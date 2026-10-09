package com.aresstack.wintrust;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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
 * returns their certificates. Adding those certificates as trust anchors lets PKIX build the chain
 * even when the proxy omits the intermediate. Only certificates the operating system already trusts
 * are returned, so certificate validation is not weakened.</p>
 *
 * <p>The export runs as an inline {@code powershell.exe -Command} one-liner that prints one
 * Base64-encoded DER certificate per line. No temporary {@code .ps1} is written, so the export keeps
 * working where GPO execution policy or AppLocker block unsigned script files. Any failure (for
 * example when PowerShell itself is blocked) is reported through {@link Result#getError()} instead of
 * being swallowed, so an application can show <em>why</em> a trust source is missing.</p>
 *
 * <p>On non-Windows platforms an empty result with no error is returned and no process is started.</p>
 */
public final class WindowsCertificateStores {

    /** Default upper bound for the PowerShell export; large stores take a few seconds. */
    public static final long DEFAULT_TIMEOUT_SECONDS = 25L;

    /** The certificate stores that are exported, in order. */
    static final String[] STORE_PATHS = {
            "Cert:\\LocalMachine\\CA",
            "Cert:\\CurrentUser\\CA",
            "Cert:\\LocalMachine\\Root",
            "Cert:\\CurrentUser\\Root"
    };

    private WindowsCertificateStores() {
    }

    /**
     * The outcome of reading the Windows Root/Intermediate CA stores: the certificates found plus an
     * optional human-readable error describing why the export could not be (fully) performed.
     */
    public static final class Result {

        private final List<X509Certificate> certificates;
        private final String error;

        Result(List<X509Certificate> certificates, String error) {
            this.certificates = Collections.unmodifiableList(new ArrayList<X509Certificate>(certificates));
            this.error = error;
        }

        /**
         * @return the de-duplicated certificates found in the exported stores; never {@code null}
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
            return "WindowsCertificateStores.Result{certificates=" + certificates.size()
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
            return new Result(Collections.<X509Certificate>emptyList(), null);
        }
        try {
            PowerShellRunner.Execution execution =
                    new PowerShellRunner(buildScript(), timeoutSeconds).runInlineCommand();
            List<X509Certificate> certificates = parseCertificates(execution.getStandardOutput());
            return new Result(certificates, describeFailure(execution, certificates));
        } catch (Exception ex) {
            return new Result(Collections.<X509Certificate>emptyList(),
                    "Windows certificate export failed: " + messageOf(ex));
        }
    }

    private static String describeFailure(PowerShellRunner.Execution execution, List<X509Certificate> certificates) {
        String stderr = execution.getStandardError().trim();
        if (execution.getExitCode() != 0) {
            return "PowerShell exited with code " + execution.getExitCode()
                    + (stderr.length() > 0 ? ": " + stderr : ".");
        }
        if (certificates.isEmpty()) {
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
     * Base64-encoded DER. Deliberately a single line without any double quotes so it survives the
     * Windows command-line quoting applied by {@link ProcessBuilder} unchanged.
     */
    static String buildScript() {
        StringBuilder builder = new StringBuilder();
        builder.append("$ErrorActionPreference = 'SilentlyContinue'; ");
        builder.append("foreach ($store in @(");
        for (int i = 0; i < STORE_PATHS.length; i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append('\'').append(STORE_PATHS[i]).append('\'');
        }
        builder.append(")) { Get-ChildItem -Path $store | ForEach-Object { [Convert]::ToBase64String($_.RawData) } }");
        return builder.toString();
    }

    /**
     * The exact command line used for the export. Package-private so a unit test can assert that it
     * is inline ({@code -Command}) and never a temporary {@code -File}.
     */
    static List<String> buildCommand() {
        return new PowerShellRunner(buildScript(), DEFAULT_TIMEOUT_SECONDS).buildInlineCommand();
    }

    /**
     * Parses the export output, one Base64-encoded DER certificate per line, de-duplicating repeated
     * certificates (the machine and user scopes overlap heavily) and skipping anything that is not a
     * parseable X.509 certificate (for example PowerShell warnings on stdout).
     */
    static List<X509Certificate> parseCertificates(String output) throws CertificateException {
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        if (output == null || output.trim().length() == 0) {
            return certificates;
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Set<String> seen = new LinkedHashSet<String>();
        String[] lines = output.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine == null ? "" : rawLine.trim();
            if (line.length() == 0 || !seen.add(line)) {
                continue;
            }
            byte[] der = decodeBase64(line);
            if (der == null || der.length == 0) {
                continue;
            }
            try {
                Object certificate = factory.generateCertificate(new ByteArrayInputStream(der));
                if (certificate instanceof X509Certificate) {
                    certificates.add((X509Certificate) certificate);
                }
            } catch (CertificateException ex) {
                // Not a parseable X.509 certificate; skip the line.
            }
        }
        return certificates;
    }

    private static byte[] decodeBase64(String value) {
        try {
            return Base64.getMimeDecoder().decode(value);
        } catch (RuntimeException ex) {
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
