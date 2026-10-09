package com.aresstack.wintrust;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads X.509 certificates from the Windows certificate stores that Java's {@code SunMSCAPI}
 * provider does <em>not</em> expose.
 *
 * <p>{@code SunMSCAPI} only offers {@code Windows-ROOT} (Trusted Root Certification Authorities) and
 * {@code Windows-MY} (Personal). It has <strong>no</strong> access to the Windows
 * <em>Intermediate Certification Authorities</em> store. Corporate TLS-intercepting proxies present
 * a leaf certificate signed by an intermediate CA whose root is trusted in {@code Windows-ROOT}, but
 * the intermediate itself lives in the intermediate store and is frequently <em>not</em> sent in the
 * TLS handshake. Windows/SChannel (browsers, {@code curl}) build the chain by pulling the
 * intermediate from that store, but Java's PKIX validator only has the server-sent certificates plus
 * the {@code Windows-ROOT} anchors, so path building fails with
 * {@code unable to find valid certification path to requested target}.</p>
 *
 * <p>To close that gap this helper enumerates the Root <em>and</em> Intermediate CA stores (both the
 * {@code LocalMachine} and {@code CurrentUser} scopes, which include GPO/enterprise-pushed CAs) and
 * returns their certificates <em>separately</em>: {@link Result#getRootCertificates()} are trust
 * anchors, {@link Result#getIntermediateCertificates()} are chain-building material only. The
 * distinction matters: Windows fills the Intermediate store automatically with every intermediate it
 * sees during chain building, so that store is a cache, not a trust statement. Only the Root stores
 * express trust, exactly as Windows/SChannel itself treats them.</p>
 *
 * <p>The export runs as an inline {@code powershell.exe -Command} one-liner that prints one
 * Base64-encoded DER certificate per line, prefixed with the store kind ({@code ROOT } or {@code CA }).
 * No temporary {@code .ps1} is written, so the export keeps working where GPO execution policy or
 * AppLocker block unsigned script files. Any failure (for example when PowerShell itself is blocked)
 * is reported through {@link Result#getError()} instead of being swallowed, so an application can show
 * <em>why</em> a trust source is missing.</p>
 *
 * <p>On non-Windows platforms an empty result with no error is returned and no process is started.</p>
 */
public final class WindowsCertificateStores {

    /** Default upper bound for the PowerShell export; large stores take a few seconds. */
    public static final long DEFAULT_TIMEOUT_SECONDS = 25L;

    /** The stores whose certificates are trust anchors (Trusted Root Certification Authorities). */
    static final String[] ROOT_STORE_PATHS = {
            "Cert:\\LocalMachine\\Root",
            "Cert:\\CurrentUser\\Root"
    };

    /** The stores whose certificates are path-building material only (Intermediate Certification Authorities). */
    static final String[] INTERMEDIATE_STORE_PATHS = {
            "Cert:\\LocalMachine\\CA",
            "Cert:\\CurrentUser\\CA"
    };

    /** Line prefix the export puts in front of every Root-store certificate. */
    static final String ROOT_MARKER = "ROOT ";

    /** Line prefix the export puts in front of every Intermediate-store certificate. */
    static final String INTERMEDIATE_MARKER = "CA ";

    private WindowsCertificateStores() {
    }

    /**
     * The outcome of reading the Windows Root/Intermediate CA stores: the certificates found, split
     * into trust anchors (Root stores) and intermediates (Intermediate CA stores), plus an optional
     * human-readable error describing why the export could not be (fully) performed.
     */
    public static final class Result {

        private final List<X509Certificate> rootCertificates;
        private final List<X509Certificate> intermediateCertificates;
        private final List<X509Certificate> certificates;
        private final String error;

        Result(List<X509Certificate> rootCertificates, List<X509Certificate> intermediateCertificates, String error) {
            this.rootCertificates = Collections.unmodifiableList(new ArrayList<X509Certificate>(rootCertificates));
            this.intermediateCertificates =
                    Collections.unmodifiableList(new ArrayList<X509Certificate>(intermediateCertificates));
            List<X509Certificate> all = new ArrayList<X509Certificate>(rootCertificates);
            all.addAll(intermediateCertificates);
            this.certificates = Collections.unmodifiableList(all);
            this.error = error;
        }

        /**
         * @return the de-duplicated certificates of the Windows Root stores (machine and user scope).
         *         These are the trust anchors; never {@code null}
         */
        public List<X509Certificate> getRootCertificates() {
            return rootCertificates;
        }

        /**
         * @return the de-duplicated certificates of the Windows Intermediate CA stores (machine and user
         *         scope) that are not also in a Root store. These are chain-building material only, never
         *         trust anchors; never {@code null}
         */
        public List<X509Certificate> getIntermediateCertificates() {
            return intermediateCertificates;
        }

        /**
         * @return all exported certificates, roots first, then intermediates; never {@code null}
         */
        public List<X509Certificate> getCertificates() {
            return certificates;
        }

        /**
         * @return {@code null} when the stores were read successfully (or the platform is not
         *         Windows), otherwise a message describing the failure.
         */
        public String getError() {
            return error;
        }

        /**
         * @return {@code true} when no error was recorded
         */
        public boolean isSuccessful() {
            return error == null;
        }

        @Override
        public String toString() {
            return "WindowsCertificateStores.Result{roots=" + rootCertificates.size()
                    + ", intermediates=" + intermediateCertificates.size()
                    + (error == null ? "" : ", error='" + error + '\'') + '}';
        }
    }

    /**
     * Exports the Windows Root and Intermediate CA stores with {@link #DEFAULT_TIMEOUT_SECONDS}.
     *
     * @return the certificates found plus a diagnostic error when they could not be read (for example
     *         when PowerShell is blocked). On non-Windows platforms an empty result with no error.
     */
    public static Result loadRootAndIntermediateCertificates() {
        return loadRootAndIntermediateCertificates(DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * Exports the Windows Root and Intermediate CA stores.
     *
     * @param timeoutSeconds how long to wait for {@code powershell.exe} before giving up
     * @return the certificates found plus a diagnostic error when they could not be read (for example
     *         when PowerShell is blocked). On non-Windows platforms an empty result with no error.
     */
    public static Result loadRootAndIntermediateCertificates(long timeoutSeconds) {
        if (!isWindows()) {
            return empty(null);
        }
        try {
            PowerShellRunner.Execution execution =
                    new PowerShellRunner(buildScript(), timeoutSeconds).runInlineCommand();
            Result parsed = parse(execution.getStandardOutput());
            return new Result(parsed.getRootCertificates(), parsed.getIntermediateCertificates(),
                    describeFailure(execution, parsed));
        } catch (Exception ex) {
            return empty("Windows certificate export failed: " + messageOf(ex));
        }
    }

    private static Result empty(String error) {
        return new Result(Collections.<X509Certificate>emptyList(), Collections.<X509Certificate>emptyList(), error);
    }

    private static String describeFailure(PowerShellRunner.Execution execution, Result parsed) {
        String stderr = execution.getStandardError().trim();
        if (execution.getExitCode() != 0) {
            return "PowerShell exited with code " + execution.getExitCode()
                    + (stderr.length() > 0 ? ": " + stderr : ".");
        }
        if (parsed.getCertificates().isEmpty()) {
            return "PowerShell returned no certificates" + (stderr.length() > 0 ? ": " + stderr : ".");
        }
        return null;
    }

    static boolean isWindows() {
        String osName = System.getProperty("os.name", "");
        return osName.toLowerCase().contains("win");
    }

    /**
     * The inline PowerShell one-liner: for each store, print every certificate as one line of
     * Base64-encoded DER prefixed with {@link #ROOT_MARKER} or {@link #INTERMEDIATE_MARKER}.
     * Deliberately a single line without any double quotes so it survives the Windows command-line
     * quoting applied by {@link ProcessBuilder} unchanged.
     */
    static String buildScript() {
        StringBuilder builder = new StringBuilder();
        builder.append("$ErrorActionPreference = 'SilentlyContinue'; ");
        appendStoreLoop(builder, ROOT_STORE_PATHS, ROOT_MARKER);
        builder.append("; ");
        appendStoreLoop(builder, INTERMEDIATE_STORE_PATHS, INTERMEDIATE_MARKER);
        return builder.toString();
    }

    private static void appendStoreLoop(StringBuilder builder, String[] storePaths, String marker) {
        builder.append("foreach ($store in @(");
        for (int i = 0; i < storePaths.length; i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append('\'').append(storePaths[i]).append('\'');
        }
        builder.append(")) { Get-ChildItem -Path $store | ForEach-Object { '")
                .append(marker)
                .append("' + [Convert]::ToBase64String($_.RawData) } }");
    }

    /**
     * The exact command line used for the export. Package-private so a unit test can assert that it
     * is inline ({@code -Command}) and never a temporary {@code -File}.
     */
    static List<String> buildCommand() {
        return new PowerShellRunner(buildScript(), DEFAULT_TIMEOUT_SECONDS).buildInlineCommand();
    }

    /**
     * Parses the export output: one {@code ROOT <base64>} or {@code CA <base64>} line per certificate.
     * Repeated certificates are de-duplicated (the machine and user scopes overlap heavily), a
     * certificate present in both a Root and an Intermediate store counts as root only, and lines
     * without a known prefix or without a parseable X.509 certificate (for example PowerShell
     * warnings on stdout) are skipped.
     *
     * @return a result with no error; the certificates found are split by store kind
     */
    static Result parse(String output) throws CertificateException {
        if (output == null || output.trim().length() == 0) {
            return empty(null);
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Map<String, X509Certificate> roots = new LinkedHashMap<String, X509Certificate>();
        Map<String, X509Certificate> intermediates = new LinkedHashMap<String, X509Certificate>();
        String[] lines = output.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine == null ? "" : rawLine.trim();
            Map<String, X509Certificate> target;
            String encoded;
            if (line.startsWith(ROOT_MARKER)) {
                target = roots;
                encoded = line.substring(ROOT_MARKER.length()).trim();
            } else if (line.startsWith(INTERMEDIATE_MARKER)) {
                target = intermediates;
                encoded = line.substring(INTERMEDIATE_MARKER.length()).trim();
            } else {
                continue;
            }
            if (encoded.length() == 0 || target.containsKey(encoded)) {
                continue;
            }
            X509Certificate certificate = decodeCertificate(factory, encoded);
            if (certificate != null) {
                target.put(encoded, certificate);
            }
        }
        for (String rootKey : roots.keySet()) {
            intermediates.remove(rootKey);
        }
        return new Result(new ArrayList<X509Certificate>(roots.values()),
                new ArrayList<X509Certificate>(intermediates.values()), null);
    }

    private static X509Certificate decodeCertificate(CertificateFactory factory, String encoded) {
        byte[] der;
        try {
            der = Base64.getMimeDecoder().decode(encoded);
        } catch (RuntimeException ex) {
            return null;
        }
        if (der == null || der.length == 0) {
            return null;
        }
        try {
            Object certificate = factory.generateCertificate(new ByteArrayInputStream(der));
            return certificate instanceof X509Certificate ? (X509Certificate) certificate : null;
        } catch (CertificateException ex) {
            return null;
        }
    }

    private static String messageOf(Throwable throwable) {
        if (throwable == null) {
            return "unknown error";
        }
        String message = throwable.getMessage();
        if (message == null || message.trim().length() == 0) {
            return throwable.getClass().getName();
        }
        if (throwable instanceof IOException && throwable.getCause() != null
                && throwable.getCause().getMessage() != null) {
            return message + " (" + throwable.getCause().getMessage() + ")";
        }
        return message;
    }
}
