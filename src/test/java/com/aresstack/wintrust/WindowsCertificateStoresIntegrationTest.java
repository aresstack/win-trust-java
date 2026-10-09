package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

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
