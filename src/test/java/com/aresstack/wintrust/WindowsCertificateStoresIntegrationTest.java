package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-environment test: exports the certificate stores of the Windows machine the tests run on
 * through the actual inline {@code powershell.exe -Command} and asserts that it works.
 *
 * <p>Opt-in, because it depends on the machine (PowerShell must be allowed to run). CI enables it on
 * the Windows runner; locally:</p>
 * <pre>{@code mvn verify -Dwintrust.integration=true}</pre>
 */
@EnabledOnOs(OS.WINDOWS)
@EnabledIfSystemProperty(named = "wintrust.integration", matches = "true")
class WindowsCertificateStoresIntegrationTest {

    @Test
    void exportsRootAndIntermediateStoresOfThisMachine() {
        WindowsCertificateStores.Result stores = WindowsCertificateStores.loadRootAndIntermediateCertificates();

        System.out.println("[win-trust-java] Windows export: " + stores);
        assertNull(stores.getError(), "the inline PowerShell export must succeed on this machine");
        assertFalse(stores.getRootCertificates().isEmpty(), "a Windows machine always has root certificates");
        assertFalse(stores.getIntermediateCertificates().isEmpty(), "a Windows machine always has intermediate certificates");
    }

    /**
     * Runs the real export with the session locked down to PowerShell's Constrained Language Mode first
     * (the mode AppLocker/WDAC enforce on hardened machines, where {@code [Convert]::ToBase64String}
     * is not callable) and asserts the {@code ConvertTo-Json} branch produces the same certificates.
     */
    @Test
    void exportStillWorksInConstrainedLanguageMode() throws Exception {
        String script = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; "
                + WindowsCertificateStores.buildScript();

        PowerShellRunner.Execution execution = new PowerShellRunner(script, 120L).runInlineCommand();
        WindowsCertificateStores.Result constrained = WindowsCertificateStores.parse(execution.getStandardOutput());
        WindowsCertificateStores.Result normal = WindowsCertificateStores.loadRootAndIntermediateCertificates();

        System.out.println("[win-trust-java] Constrained Language Mode export: " + constrained
                + " (exit code " + execution.getExitCode() + ", stderr: " + execution.getStandardError().trim() + ")");
        assertEquals(0, execution.getExitCode(), execution.getStandardError());
        assertTrue(execution.getStandardOutput().contains(WindowsCertificateStores.ROOT_MARKER + "["),
                "the JSON byte-array branch must have been taken");
        assertFalse(execution.getStandardOutput().contains(WindowsCertificateStores.ERROR_MARKER),
                "no store may fail in Constrained Language Mode");
        assertNull(constrained.getError());
        assertEquals(normal.getRootCertificates().size(), constrained.getRootCertificates().size());
        assertEquals(normal.getIntermediateCertificates().size(), constrained.getIntermediateCertificates().size());
    }

    @Test
    void defaultsTrustEveryWindowsSourceOnThisMachine() {
        SystemTrustSslSocketFactory.Result result =
                SystemTrustSslSocketFactory.create(CertificateTrustConfiguration.defaults());

        System.out.println("[win-trust-java] " + result);
        assertTrue(result.isJvmDefaultTrusted());
        assertTrue(result.isWindowsRootTrusted(), "SunMSCAPI Windows-ROOT must load on Windows");
        assertTrue(result.isWindowsCaStoresTrusted());
        assertTrue(result.getWindowsRootAnchorCount() > 0);
        assertTrue(result.getWindowsIntermediateCount() > 0);
        assertTrue(result.getWindowsExportedCertificateCount()
                == result.getWindowsRootAnchorCount() + result.getWindowsIntermediateCount());
        assertFalse(result.isFallbackToJvmDefault());
        assertTrue(result.getTrustManager().getAcceptedIssuers().length > 0);
    }
}
