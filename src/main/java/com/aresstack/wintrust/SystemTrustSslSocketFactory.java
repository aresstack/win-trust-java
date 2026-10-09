package com.aresstack.wintrust;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
        private final int windowsExportedCertificateCount;
        private final boolean fallbackToJvmDefault;
        private final List<String> diagnostics;

        Result(SSLSocketFactory socketFactory, SSLContext sslContext, X509TrustManager trustManager,
               boolean jvmDefaultTrusted, boolean windowsRootTrusted, boolean windowsCaStoresTrusted,
               int windowsExportedCertificateCount, boolean fallbackToJvmDefault, List<String> diagnostics) {
            this.socketFactory = socketFactory;
            this.sslContext = sslContext;
            this.trustManager = trustManager;
            this.jvmDefaultTrusted = jvmDefaultTrusted;
            this.windowsRootTrusted = windowsRootTrusted;
            this.windowsCaStoresTrusted = windowsCaStoresTrusted;
            this.windowsExportedCertificateCount = windowsExportedCertificateCount;
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
         * @return how many distinct certificates the Windows Root/Intermediate export produced
         *         ({@code 0} when that source was disabled, failed, or the platform is not Windows)
         */
        public int getWindowsExportedCertificateCount() {
            return windowsExportedCertificateCount;
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
                    + ", windowsExportedCertificateCount=" + windowsExportedCertificateCount
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
        int exportedCount = 0;

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
            exportedCount = stores.getCertificates().size();
            if (stores.getError() != null) {
                diagnostics.add("Windows Root/Intermediate CA export: " + stores.getError());
            }
            windowsCa = addWindowsCaTrustManager(delegates, stores.getCertificates(), diagnostics);
        }

        if (!configuration.isAnySourceEnabled()) {
            diagnostics.add("No trust source is enabled.");
        }

        if (delegates.isEmpty()) {
            diagnostics.add("No trust source produced a trust manager; using the JVM default SSL socket factory.");
            return fallback(jvmDefault, windowsRoot, windowsCa, exportedCount, diagnostics);
        }

        X509TrustManager composite = new CompositeX509TrustManager(delegates);
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{composite}, null);
            return new Result(context.getSocketFactory(), context, composite,
                    jvmDefault, windowsRoot, windowsCa, exportedCount, false, diagnostics);
        } catch (GeneralSecurityException ex) {
            diagnostics.add("Could not initialise the combined SSL context (" + messageOf(ex)
                    + "); using the JVM default SSL socket factory.");
            return fallback(jvmDefault, windowsRoot, windowsCa, exportedCount, diagnostics);
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
                                   int exportedCount, List<String> diagnostics) {
        SSLContext context = null;
        try {
            context = SSLContext.getDefault();
        } catch (GeneralSecurityException ex) {
            diagnostics.add("JVM default SSL context unavailable: " + messageOf(ex));
        }
        SSLSocketFactory factory = context != null
                ? context.getSocketFactory() : (SSLSocketFactory) SSLSocketFactory.getDefault();
        return new Result(factory, context, defaultTrustManagerOrNull(),
                jvmDefault, windowsRoot, windowsCa, exportedCount, true, diagnostics);
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
     * Adds the certificates from the Windows Root <em>and</em> Intermediate Certification Authorities
     * stores (which {@code SunMSCAPI}'s {@code Windows-ROOT} keystore does not expose) as trust
     * anchors. Making the corporate intermediate CA an anchor lets PKIX build the chain even when a
     * TLS-intercepting proxy omits the intermediate from the handshake, which is the case
     * {@code Windows-ROOT} alone cannot cover.
     */
    private static boolean addWindowsCaTrustManager(List<X509TrustManager> delegates,
                                                    List<X509Certificate> certificates, List<String> diagnostics) {
        if (certificates.isEmpty()) {
            diagnostics.add("Windows Root/Intermediate CA stores contributed no certificates.");
            return false;
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            for (int i = 0; i < certificates.size(); i++) {
                keyStore.setCertificateEntry("win-trust-ca-" + i, certificates.get(i));
            }
            if (addTrustManager(delegates, keyStore, diagnostics, "Windows Root/Intermediate CA stores")) {
                diagnostics.add("Windows Root/Intermediate CA stores loaded " + certificates.size() + " certificate(s).");
                return true;
            }
            diagnostics.add("Windows Root/Intermediate CA stores produced no trust manager.");
            return false;
        } catch (Exception ex) {
            diagnostics.add("Could not assemble Windows Root/Intermediate CA anchors: " + messageOf(ex));
            return false;
        }
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
