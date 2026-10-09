package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Manual, environment-touching diagnostic that builds the trust factory from each source and
 * prints EXACTLY what was loaded, how many certificates the Windows export produced, and why a
 * source is missing.
 *
 * <p>It never fails the build (no assertions on environment state). <b>Not a normal CI test</b>:
 * it spawns {@code powershell.exe} on Windows, so it is disabled by default. Enable it with</p>
 * <pre>{@code mvn verify -Dwintrust.diagnostics=true}</pre>
 * or <pre>{@code ./gradlew test -Dwintrust.diagnostics=true}</pre>
 */
@EnabledIfSystemProperty(named = "wintrust.diagnostics", matches = "true")
class SystemTrustDiagnosticTest {

    @Test
    void diagnoseAllTrustSources() {
        System.out.println("==================================================================");
        System.out.println(" win-trust-java trust source diagnostic");
        System.out.println(" os.name=" + System.getProperty("os.name") + ", java.version=" + System.getProperty("java.version"));
        System.out.println("==================================================================");

        report("defaults (JVM + Windows-ROOT + Windows CA stores)", CertificateTrustConfiguration.defaults());
        report("JVM default only", CertificateTrustConfiguration.jvmDefaultOnly());
        report("Windows-ROOT only", new CertificateTrustConfiguration(false, true, false));
        report("Windows CA stores only", new CertificateTrustConfiguration(false, false, true));

        System.out.println("==================================================================");
    }

    private void report(String label, CertificateTrustConfiguration configuration) {
        try {
            SystemTrustSslSocketFactory.Result result = SystemTrustSslSocketFactory.create(configuration);
            System.out.println("[" + label + "]");
            System.out.println("  jvmDefaultTrusted      = " + result.isJvmDefaultTrusted());
            System.out.println("  windowsRootTrusted     = " + result.isWindowsRootTrusted());
            System.out.println("  windowsCaStoresTrusted = " + result.isWindowsCaStoresTrusted()
                    + " (" + result.getWindowsExportedCertificateCount() + " exported certificate(s))");
            System.out.println("  fallbackToJvmDefault   = " + result.isFallbackToJvmDefault());
            System.out.println("  acceptedIssuers        = "
                    + (result.getTrustManager() == null ? "n/a" : result.getTrustManager().getAcceptedIssuers().length));
            for (String line : result.getDiagnostics()) {
                System.out.println("  - " + line);
            }
        } catch (Throwable t) {
            System.out.println("[" + label + "] THREW: " + t);
            t.printStackTrace(System.out);
        }
    }
}
