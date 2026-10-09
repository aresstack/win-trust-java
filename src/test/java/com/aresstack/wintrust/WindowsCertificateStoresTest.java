package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Deterministic tests for the Windows certificate export: output parsing and the hardening
 * guarantee that the export runs inline ({@code powershell.exe -Command}) and never through a
 * temporary {@code .ps1}. No real {@code powershell.exe} is started.
 */
class WindowsCertificateStoresTest {

    // ── parsing ──

    @Test
    void parsesOneBase64DerCertificatePerLine() throws Exception {
        List<X509Certificate> certificates =
                WindowsCertificateStores.parseCertificates(TestCertificates.TEST_CA_BASE64 + "\r\n");

        assertEquals(1, certificates.size());
        assertTrue(certificates.get(0).getSubjectX500Principal().getName()
                .contains("CN=" + TestCertificates.TEST_CA_SUBJECT_CN));
    }

    @Test
    void deduplicatesCertificatesAndSkipsNoise() throws Exception {
        String output = "\r\n"
                + TestCertificates.TEST_CA_BASE64 + "\r\n"
                + "WARNING: something PowerShell printed to stdout\r\n"
                + "   " + TestCertificates.TEST_CA_BASE64 + "   \n"
                + "bm90IGEgY2VydGlmaWNhdGU=\n"            // valid Base64, not a certificate
                + "!!! not base64 at all !!!\n"
                + TestCertificates.TEST_CA_BASE64;         // no trailing newline

        List<X509Certificate> certificates = WindowsCertificateStores.parseCertificates(output);

        assertEquals(1, certificates.size(), "machine and user scopes overlap; duplicates collapse");
    }

    @Test
    void parsesNothingFromEmptyOrNullOutput() throws Exception {
        assertTrue(WindowsCertificateStores.parseCertificates(null).isEmpty());
        assertTrue(WindowsCertificateStores.parseCertificates("").isEmpty());
        assertTrue(WindowsCertificateStores.parseCertificates("  \r\n \n").isEmpty());
    }

    // ── hardening: inline -Command, never a temp .ps1 ──

    @Test
    void exportRunsInlineAndNeverWritesTempFile() {
        List<String> command = WindowsCertificateStores.buildCommand();

        assertEquals("powershell.exe", command.get(0));
        assertTrue(command.contains("-NoProfile"));
        assertTrue(command.contains("-NonInteractive"));
        assertTrue(command.contains("-Command"), "export must use -Command");
        assertFalse(command.contains("-File"), "export must never use -File (no temp .ps1)");
        assertFalse(command.contains("-EncodedCommand"));
        // The script is passed inline as the last argument, not as a file path.
        assertEquals(WindowsCertificateStores.buildScript(), command.get(command.size() - 1));
        assertEquals(command.indexOf("-Command") + 1, command.size() - 1);
    }

    @Test
    void scriptIsASingleLineWithoutDoubleQuotesOrFiles() {
        String script = WindowsCertificateStores.buildScript();

        assertFalse(script.contains("\n"), "inline -Command script must be a single line");
        assertFalse(script.contains("\r"));
        assertFalse(script.contains("\""), "no double quotes: ProcessBuilder's Windows quoting must not alter it");
        assertFalse(script.toLowerCase().contains(".ps1"));
        assertFalse(script.toLowerCase().contains("out-file"));
        assertFalse(script.toLowerCase().contains("writealllines"));
        assertTrue(script.contains("[Convert]::ToBase64String($_.RawData)"), script);
    }

    @Test
    void scriptExportsRootAndIntermediateStoresInMachineAndUserScope() {
        String script = WindowsCertificateStores.buildScript();

        assertTrue(script.contains("'Cert:\\LocalMachine\\CA'"), script);
        assertTrue(script.contains("'Cert:\\CurrentUser\\CA'"), script);
        assertTrue(script.contains("'Cert:\\LocalMachine\\Root'"), script);
        assertTrue(script.contains("'Cert:\\CurrentUser\\Root'"), script);
        assertTrue(script.startsWith("$ErrorActionPreference = 'SilentlyContinue';"),
                "a missing store must not abort the whole export");
    }

    // ── non-Windows ──

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void nonWindowsReturnsEmptyResultWithoutErrorAndWithoutStartingAProcess() {
        WindowsCertificateStores.Result result = WindowsCertificateStores.loadRootAndIntermediateCertificates();

        assertTrue(result.getCertificates().isEmpty());
        assertNull(result.getError());
        assertTrue(result.isSuccessful());
        assertFalse(WindowsCertificateStores.isWindows());
    }

    @Test
    void resultIsUnmodifiable() throws Exception {
        WindowsCertificateStores.Result result = new WindowsCertificateStores.Result(
                WindowsCertificateStores.parseCertificates(TestCertificates.TEST_CA_BASE64), "boom");

        assertEquals(1, result.getCertificates().size());
        assertFalse(result.isSuccessful());
        assertEquals("boom", result.getError());
        assertTrue(result.toString().contains("certificates=1"), result.toString());
        assertTrue(result.toString().contains("boom"), result.toString());
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> result.getCertificates().clear());
    }
}
