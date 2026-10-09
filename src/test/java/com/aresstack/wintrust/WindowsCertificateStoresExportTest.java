package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link WindowsCertificateStores#export(PowerShellRunner)} with {@link FakePowerShell} so every
 * branch of the failure description, the library's whole diagnostic story, is asserted on every platform.
 */
class WindowsCertificateStoresExportTest {

    private static final String ROOT_LINE = WindowsCertificateStores.ROOT_MARKER + TestCertificates.ROOT_BASE64.replaceAll("\\s+", "");
    private static final String CA_LINE = WindowsCertificateStores.INTERMEDIATE_MARKER + TestCertificates.INTERMEDIATE_BASE64.replaceAll("\\s+", "");

    private static WindowsCertificateStores.Result export(String script) {
        return WindowsCertificateStores.export(new PowerShellRunner(FakePowerShell.commandPrefix(), script, 60L));
    }

    @Test
    void successfulExportHasNoError() {
        WindowsCertificateStores.Result result = export("stdout:" + ROOT_LINE + "|stdout:" + CA_LINE + "|exit:0");

        assertNull(result.getError(), String.valueOf(result.getError()));
        assertTrue(result.isSuccessful());
        assertEquals(1, result.getRootCertificates().size());
        assertEquals(1, result.getIntermediateCertificates().size());
    }

    @Test
    void nonZeroExitCodeWithCertificatesIsReportedButCertificatesAreKept() {
        WindowsCertificateStores.Result result = export("stdout:" + ROOT_LINE + "|stderr:access denied|exit:1");

        assertEquals(1, result.getRootCertificates().size());
        assertTrue(result.getError().startsWith("PowerShell exited with code 1 although 1 certificate(s) were exported: "),
                result.getError());
        assertTrue(result.getError().contains("access denied"), result.getError());
    }

    // The child JVM may print banners such as "Picked up JAVA_TOOL_OPTIONS" to stderr, which the
    // export faithfully appends to its messages; the assertions below therefore check the prefix.

    @Test
    void nonZeroExitCodeWithoutCertificatesIsReported() {
        WindowsCertificateStores.Result result = export("exit:2");

        assertTrue(result.getCertificates().isEmpty());
        assertTrue(result.getError().startsWith("PowerShell exited with code 2"), result.getError());
        assertFalse(result.getError().contains("although"), result.getError());
    }

    @Test
    void noCertificatesIsAnErrorEvenWithExitCodeZero() {
        String withoutStderr = export("stdout:nothing useful|exit:0").getError();
        String withStderr = export("stderr:provider missing|exit:0").getError();

        assertTrue(withoutStderr.startsWith("PowerShell returned no certificates"), withoutStderr);
        assertTrue(withStderr.startsWith("PowerShell returned no certificates: "), withStderr);
        assertTrue(withStderr.contains("provider missing"), withStderr);
    }

    @Test
    void unreadableStoresAreNamedWhenNothingWasExported() {
        WindowsCertificateStores.Result result = export(
                "stdout:" + WindowsCertificateStores.ERROR_MARKER + "Cert:\\LocalMachine\\Root: denied|exit:0");

        assertTrue(result.getError().startsWith("PowerShell returned no certificates (Certificate store(s) could not be read: "
                + "Cert:\\LocalMachine\\Root: denied)"), result.getError());
    }

    @Test
    void unreadableStoreNextToExportedCertificatesIsAPartialExport() {
        WindowsCertificateStores.Result result = export("stdout:" + ROOT_LINE
                + "|stdout:" + WindowsCertificateStores.ERROR_MARKER + "Cert:\\CurrentUser\\CA: denied|exit:0");

        assertEquals(1, result.getRootCertificates().size());
        assertFalse(result.isSuccessful());
        assertEquals("Certificate store(s) could not be read: Cert:\\CurrentUser\\CA: denied", result.getError());
    }

    @Test
    void aProcessThatCannotStartIsReportedAsExportFailure() {
        WindowsCertificateStores.Result result = WindowsCertificateStores.export(new PowerShellRunner(
                Collections.singletonList("win-trust-java-no-such-executable"), "stdout:x", 5L));

        assertTrue(result.getCertificates().isEmpty());
        assertTrue(result.getError().startsWith("Windows certificate export failed: "), result.getError());
        assertTrue(result.getError().contains("win-trust-java-no-such-executable"), result.getError());
        assertEquals(1, result.getError().split("win-trust-java-no-such-executable", -1).length - 1,
                "the cause text is not repeated: " + result.getError());
    }

    @Test
    void timeoutIsReportedAsExportFailure() {
        WindowsCertificateStores.Result result = WindowsCertificateStores.export(
                new PowerShellRunner(FakePowerShell.commandPrefix(), "sleep:60000|exit:0", 1L));

        assertTrue(result.getError().startsWith("Windows certificate export failed: PowerShell did not finish within 1 seconds."),
                result.getError());
    }
}
