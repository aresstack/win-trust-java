package com.aresstack.wintrust;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an {@link SSLSocketFactory} (and the matching {@link SSLContext} / {@link X509TrustManager})
 * whose trust anchors are chosen by a {@link CertificateTrustConfiguration}: any combination of the
 * JVM default truststore, the Windows {@code Windows-ROOT} store, and the Windows Root/Intermediate
 * CA stores.
 *
 * <p>Corporate proxies frequently terminate TLS and re-sign responses with a private CA. That CA is
 * installed in the Windows certificate store (so browsers and {@code curl} work) but is unknown to
 * the JVM's bundled {@code cacerts}. Without merging the Windows stores, every HTTPS request fails
 * during the TLS handshake with {@code PKIX path building failed ... unable to find valid
 * certification path to requested target}, even though proxy discovery succeeds.</p>
 *
 * <p>Trust is never widened beyond what Windows itself trusts: only the Windows <em>Root</em> stores
 * (and {@code Windows-ROOT}) contribute trust anchors. Certificates from the Windows
 * <em>Intermediate</em> CA stores are handed to the PKIX path builder as chain-building material
 * only, so a server chain that omits its intermediate can still be completed, but an intermediate
 * whose root is not trusted never becomes trusted by itself.</p>
 *
 * <p>This factory does not silently swallow failures: the {@link Result} records which trust sources
 * were actually loaded, how many certificates the Windows export produced, and any diagnostic
 * messages, so a connection test can show whether a PKIX failure is due to a missing trust source
 * rather than a proxy problem.</p>
 *
 * <pre>{@code
 * SystemTrustSslSocketFactory.Result trust =
 *         SystemTrustSslSocketFactory.build(CertificateTrustConfiguration.defaults());
 * HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com/").openConnection();
 * connection.setSSLSocketFactory(trust.getSocketFactory());
 * }</pre>
 */
public final class SystemTrustSslSocketFactory {

    private static final Map<CertificateTrustConfiguration, Result> CACHE =
            new HashMap<CertificateTrustConfiguration, Result>();

    private SystemTrustSslSocketFactory() {
    }

    /**
     * The outcome of assembling the trust factory: the socket factory to use plus diagnostics about
     * which sources contributed and any problems encountered.
     */
    public static final class Result {

        private final SSLSocketFactory socketFactory;
        private final SSLContext sslContext;
        private final X509TrustManager trustManager;
        private final boolean jvmDefaultTrusted;
        private final boolean windowsRootTrusted;
        private final boolean windowsCaStoresTrusted;
        private final int windowsRootAnchorCount;
        private final int windowsIntermediateCount;
        private final boolean fallbackToJvmDefault;
        private final List<String> diagnostics;

        Result(SSLSocketFactory socketFactory, SSLContext sslContext, X509TrustManager trustManager,
               boolean jvmDefaultTrusted, boolean windowsRootTrusted, boolean windowsCaStoresTrusted,
               int windowsRootAnchorCount, int windowsIntermediateCount, boolean fallbackToJvmDefault,
               List<String> diagnostics) {
            this.socketFactory = socketFactory;
            this.sslContext = sslContext;
            this.trustManager = trustManager;
            this.jvmDefaultTrusted = jvmDefaultTrusted;
            this.windowsRootTrusted = windowsRootTrusted;
            this.windowsCaStoresTrusted = windowsCaStoresTrusted;
            this.windowsRootAnchorCount = windowsRootAnchorCount;
            this.windowsIntermediateCount = windowsIntermediateCount;
            this.fallbackToJvmDefault = fallbackToJvmDefault;
            this.diagnostics = Collections.unmodifiableList(new ArrayList<String>(diagnostics));
        }

        /**
         * @return the socket factory to install on {@code HttpsURLConnection}, OkHttp, Apache
         *         HttpClient, etc.; never {@code null}
         */
        public SSLSocketFactory getSocketFactory() {
            return socketFactory;
        }

        /**
         * @return the {@link SSLContext} behind {@link #getSocketFactory()}; never {@code null}
         */
        public SSLContext getSslContext() {
            return sslContext;
        }

        /**
         * @return the combined trust manager (useful for clients such as OkHttp that need the trust
         *         manager next to the socket factory), or {@code null} when no trust manager could be
         *         built at all and the JVM default socket factory is in use
         */
        public X509TrustManager getTrustManager() {
            return trustManager;
        }

        public boolean isJvmDefaultTrusted() {
            return jvmDefaultTrusted;
        }

        public boolean isWindowsRootTrusted() {
            return windowsRootTrusted;
        }

        public boolean isWindowsCaStoresTrusted() {
            return windowsCaStoresTrusted;
        }

        /**
         * @return how many distinct certificates the Windows Root/Intermediate export produced in total
         *         ({@code 0} when that source was disabled, failed, or the platform is not Windows)
         */
        public int getWindowsExportedCertificateCount() {
            return windowsRootAnchorCount + windowsIntermediateCount;
        }

        /**
         * @return how many distinct Windows Root-store certificates serve as trust anchors
         */
        public int getWindowsRootAnchorCount() {
            return windowsRootAnchorCount;
        }

        /**
         * @return how many distinct Windows Intermediate-store certificates are available to the PKIX
         *         path builder (chain-building material only, never trust anchors)
         */
        public int getWindowsIntermediateCount() {
            return windowsIntermediateCount;
        }

        /**
         * @return {@code true} when no enabled source produced a trust manager and the result simply
         *         wraps the JVM default {@link SSLSocketFactory}
         */
        public boolean isFallbackToJvmDefault() {
            return fallbackToJvmDefault;
        }

        /**
         * @return human-readable messages describing what was loaded and what failed, in order
         */
        public List<String> getDiagnostics() {
            return diagnostics;
        }

        @Override
        public String toString() {
            return "SystemTrustSslSocketFactory.Result{jvmDefaultTrusted=" + jvmDefaultTrusted
                    + ", windowsRootTrusted=" + windowsRootTrusted
                    + ", windowsCaStoresTrusted=" + windowsCaStoresTrusted
                    + ", windowsRootAnchorCount=" + windowsRootAnchorCount
                    + ", windowsIntermediateCount=" + windowsIntermediateCount
                    + ", fallbackToJvmDefault=" + fallbackToJvmDefault
                    + ", diagnostics=" + diagnostics + '}';
        }
    }

    /**
     * Returns the cached {@link Result} for the given configuration, building it on first use.
     *
     * <p>The build is cached per configuration because reading the Windows CA stores spawns
     * PowerShell and is comparatively expensive. Use {@link #create(CertificateTrustConfiguration)}
     * for a fresh, uncached build (for example after certificates were added to the Windows store) or
     * {@link #clearCache()} to drop all cached results.</p>
     *
     * @param trust the trust sources to enable; {@code null} is treated as
     *              {@link CertificateTrustConfiguration#defaults()}
     * @return the cached result for the configuration; never {@code null}
     */
    public static Result build(CertificateTrustConfiguration trust) {
        CertificateTrustConfiguration configuration = trust == null
                ? CertificateTrustConfiguration.defaults() : trust;
        synchronized (CACHE) {
            Result cached = CACHE.get(configuration);
            if (cached != null) {
                return cached;
            }
            Result result = create(configuration);
            CACHE.put(configuration, result);
            return result;
        }
    }

    /**
     * Builds a fresh, uncached {@link Result}. This may spawn {@code powershell.exe} when the Windows
     * CA stores are enabled.
     *
     * @param trust the trust sources to enable; {@code null} is treated as
     *              {@link CertificateTrustConfiguration#defaults()}
     * @return a new result; never {@code null}
     */
    public static Result create(CertificateTrustConfiguration trust) {
        CertificateTrustConfiguration configuration = trust == null
                ? CertificateTrustConfiguration.defaults() : trust;

        List<X509TrustManager> delegates = new ArrayList<X509TrustManager>();
        List<String> diagnostics = new ArrayList<String>();
        boolean jvmDefault = false;
        boolean windowsRoot = false;
        boolean windowsCa = false;
        int rootAnchorCount = 0;
        int intermediateCount = 0;

        if (configuration.isUseJvmDefault()) {
            if (addTrustManager(delegates, null, diagnostics, "JVM default truststore")) {
                jvmDefault = true;
                diagnostics.add("JVM default truststore (cacerts) loaded.");
            } else {
                diagnostics.add("JVM default truststore (cacerts) could not be loaded.");
            }
        }

        if (configuration.isUseWindowsRoot()) {
            windowsRoot = addWindowsRootTrustManager(delegates, diagnostics);
        }

        if (configuration.isUseWindowsCaStores()) {
            WindowsCertificateStores.Result stores = WindowsCertificateStores.loadRootAndIntermediateCertificates();
            rootAnchorCount = stores.getRootCertificates().size();
            intermediateCount = stores.getIntermediateCertificates().size();
            if (stores.getError() != null) {
                diagnostics.add("Windows Root/Intermediate CA export: " + stores.getError());
            }
            windowsCa = addWindowsCaTrustManager(delegates, stores, diagnostics);
        }

        if (!configuration.isAnySourceEnabled()) {
            diagnostics.add("No trust source is enabled.");
        }

        if (delegates.isEmpty()) {
            diagnostics.add("No trust source produced a trust manager; using the JVM default SSL socket factory.");
            return fallback(jvmDefault, windowsRoot, windowsCa, rootAnchorCount, intermediateCount, diagnostics);
        }

        X509TrustManager composite = new CompositeX509TrustManager(delegates);
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{composite}, null);
            return new Result(context.getSocketFactory(), context, composite,
                    jvmDefault, windowsRoot, windowsCa, rootAnchorCount, intermediateCount, false, diagnostics);
        } catch (GeneralSecurityException ex) {
            diagnostics.add("Could not initialise the combined SSL context (" + messageOf(ex)
                    + "); using the JVM default SSL socket factory.");
            return fallback(jvmDefault, windowsRoot, windowsCa, rootAnchorCount, intermediateCount, diagnostics);
        }
    }

    /**
     * Drops every cached {@link Result}, so the next {@link #build(CertificateTrustConfiguration)}
     * re-reads all trust sources.
     */
    public static void clearCache() {
        synchronized (CACHE) {
            CACHE.clear();
        }
    }

    private static Result fallback(boolean jvmDefault, boolean windowsRoot, boolean windowsCa,
                                   int rootAnchorCount, int intermediateCount, List<String> diagnostics) {
        SSLContext context = null;
        try {
            context = SSLContext.getDefault();
        } catch (GeneralSecurityException ex) {
            diagnostics.add("JVM default SSL context unavailable: " + messageOf(ex));
        }
        SSLSocketFactory factory = context != null
                ? context.getSocketFactory() : (SSLSocketFactory) SSLSocketFactory.getDefault();
        return new Result(factory, context, defaultTrustManagerOrNull(),
                jvmDefault, windowsRoot, windowsCa, rootAnchorCount, intermediateCount, true, diagnostics);
    }

    private static X509TrustManager defaultTrustManagerOrNull() {
        List<X509TrustManager> managers = new ArrayList<X509TrustManager>();
        if (addTrustManager(managers, null, new ArrayList<String>(), "JVM default truststore")) {
            return managers.size() == 1 ? managers.get(0) : new CompositeX509TrustManager(managers);
        }
        return null;
    }

    private static boolean addWindowsRootTrustManager(List<X509TrustManager> delegates, List<String> diagnostics) {
        try {
            KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
            keyStore.load(null, null);
            if (addTrustManager(delegates, keyStore, diagnostics, "Windows-ROOT store")) {
                diagnostics.add("Windows-ROOT store loaded.");
                return true;
            }
            diagnostics.add("Windows-ROOT store produced no trust manager.");
            return false;
        } catch (Exception ex) {
            diagnostics.add("Windows-ROOT store unavailable: " + messageOf(ex));
            return false;
        }
    }

    /**
     * Adds a PKIX trust manager whose trust anchors are the certificates of the Windows <em>Root</em>
     * stores and whose path builder may use the certificates of the Windows <em>Intermediate</em> CA
     * stores (which {@code SunMSCAPI}'s {@code Windows-ROOT} keystore does not expose) to complete a
     * chain. This lets PKIX validate a TLS-intercepting proxy that omits its intermediate from the
     * handshake, which is the case {@code Windows-ROOT} alone cannot cover, while an intermediate whose
     * root is not trusted stays untrusted: the Intermediate store is a cache Windows fills from every
     * chain it sees, so its entries are never promoted to anchors.
     */
    private static boolean addWindowsCaTrustManager(List<X509TrustManager> delegates,
                                                    WindowsCertificateStores.Result stores, List<String> diagnostics) {
        List<X509Certificate> anchors = stores.getRootCertificates();
        List<X509Certificate> intermediates = stores.getIntermediateCertificates();
        if (anchors.isEmpty()) {
            diagnostics.add("Windows Root/Intermediate CA stores contributed no trust anchors"
                    + (intermediates.isEmpty() ? "." : "; " + intermediates.size()
                    + " intermediate certificate(s) ignored because there is no root to anchor them."));
            return false;
        }
        try {
            delegates.add(createPkixTrustManager(anchors, intermediates));
            diagnostics.add("Windows Root/Intermediate CA stores loaded " + anchors.size()
                    + " root anchor(s) and " + intermediates.size() + " intermediate certificate(s).");
            return true;
        } catch (Exception ex) {
            diagnostics.add("Could not assemble Windows Root/Intermediate CA trust manager: " + messageOf(ex));
            return false;
        }
    }

    /**
     * Builds a PKIX {@link X509TrustManager} with explicit trust anchors and optional intermediate
     * certificates for path building. Revocation checking follows the JSSE default
     * ({@code com.sun.net.ssl.checkRevocation}, off unless set), exactly like a trust manager built
     * from a plain {@link KeyStore}.
     *
     * @param anchors       the trust anchors; must not be empty
     * @param intermediates chain-building material that is <em>not</em> trusted by itself; may be empty
     * @return the trust manager
     * @throws GeneralSecurityException when the anchors are empty or PKIX is unavailable
     * @throws IOException              when the in-memory anchor keystore cannot be initialised
     */
    static X509TrustManager createPkixTrustManager(Collection<X509Certificate> anchors,
                                                   Collection<X509Certificate> intermediates)
            throws GeneralSecurityException, IOException {
        KeyStore anchorStore = KeyStore.getInstance(KeyStore.getDefaultType());
        anchorStore.load(null, null);
        int index = 0;
        for (X509Certificate anchor : anchors) {
            anchorStore.setCertificateEntry("win-trust-root-" + index++, anchor);
        }
        PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchorStore, new X509CertSelector());
        parameters.setRevocationEnabled(Boolean.getBoolean("com.sun.net.ssl.checkRevocation"));
        if (!intermediates.isEmpty()) {
            parameters.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(new ArrayList<X509Certificate>(intermediates))));
        }
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(new CertPathTrustManagerParameters(parameters));
        for (TrustManager trustManager : factory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }
        throw new NoSuchAlgorithmException("The PKIX TrustManagerFactory produced no X509TrustManager.");
    }

    private static boolean addTrustManager(List<X509TrustManager> delegates, KeyStore keyStore,
                                           List<String> diagnostics, String sourceName) {
        try {
            TrustManagerFactory factory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore);
            boolean added = false;
            for (TrustManager trustManager : factory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    delegates.add((X509TrustManager) trustManager);
                    added = true;
                }
            }
            return added;
        } catch (GeneralSecurityException ex) {
            diagnostics.add(sourceName + ": trust manager initialisation failed (" + messageOf(ex) + ").");
            return false;
        }
    }

    private static String messageOf(Throwable throwable) {
        if (throwable == null) {
            return "unknown error";
        }
        String message = throwable.getMessage();
        return message != null && message.trim().length() > 0 ? message : throwable.getClass().getName();
    }
}
