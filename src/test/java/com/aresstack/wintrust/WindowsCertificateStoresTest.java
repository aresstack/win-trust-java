package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Deterministic tests for the Windows certificate export: output parsing and the hardening
 * guarantee that the export runs inline ({@code powershell.exe -Command}) and never through a
 * temporary {@code .ps1}. No real {@code powershell.exe} is started.
 */
class WindowsCertificateStoresTest {

    private static final String ROOT_LINE = WindowsCertificateStores.ROOT_MARKER + TestCertificates.ROOT_BASE64;
    private static final String CA_LINE = WindowsCertificateStores.INTERMEDIATE_MARKER + TestCertificates.INTERMEDIATE_BASE64;

    // ── parsing ──

    @Test
    void parsesRootAndIntermediateLinesIntoSeparateLists() throws Exception {
        WindowsCertificateStores.Result result = WindowsCertificateStores.parse(ROOT_LINE + "\r\n" + CA_LINE + "\r\n");

        assertEquals(1, result.getRootCertificates().size());
        assertEquals(1, result.getIntermediateCertificates().size());
        assertEquals(2, result.getCertificates().size());
        assertTrue(result.getRootCertificates().get(0).getSubjectX500Principal().getName().contains("test root"));
        assertTrue(result.getIntermediateCertificates().get(0).getSubjectX500Principal().getName().contains("test intermediate"));
        assertNull(result.getError());
    }

    @Test
    void deduplicatesCertificatesAndSkipsNoise() throws Exception {
        String output = "\r\n"
                + ROOT_LINE + "\r\n"
                + "WARNING: something PowerShell printed to stdout\r\n"
                + "   " + ROOT_LINE + "   \n"                                            // machine + user scope overlap
                + WindowsCertificateStores.INTERMEDIATE_MARKER + "bm90IGEgY2VydGlmaWNhdGU=\n"  // valid Base64, not a certificate
                + WindowsCertificateStores.ROOT_MARKER + "!!! not base64 at all !!!\n"
                + TestCertificates.INTERMEDIATE_BASE64 + "\n"                             // no marker: ignored
                + CA_LINE + "\n"
                + CA_LINE;                                                                  // no trailing newline

        WindowsCertificateStores.Result result = WindowsCertificateStores.parse(output);

        assertEquals(1, result.getRootCertificates().size(), "duplicates collapse");
        assertEquals(1, result.getIntermediateCertificates().size(), "duplicates collapse, unmarked lines are ignored");
    }

    @Test
    void aCertificateInBothStoresCountsAsRootOnly() throws Exception {
        String output = WindowsCertificateStores.INTERMEDIATE_MARKER + TestCertificates.ROOT_BASE64 + "\n"
                + ROOT_LINE + "\n";

        WindowsCertificateStores.Result result = WindowsCertificateStores.parse(output);

        assertEquals(1, result.getRootCertificates().size());
        assertTrue(result.getIntermediateCertificates().isEmpty(), "a root is never listed as intermediate as well");
    }

    @Test
    void parsesNothingFromEmptyOrNullOutput() throws Exception {
        assertTrue(WindowsCertificateStores.parse(null).getCertificates().isEmpty());
        assertTrue(WindowsCertificateStores.parse("").getCertificates().isEmpty());
        assertTrue(WindowsCertificateStores.parse("  \r\n \n").getCertificates().isEmpty());
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
    void scriptExportsRootStoresAsAnchorsAndIntermediateStoresAsMaterial() {
        String script = WindowsCertificateStores.buildScript();

        assertTrue(script.contains("@('Cert:\\LocalMachine\\Root','Cert:\\CurrentUser\\Root')"), script);
        assertTrue(script.contains("@('Cert:\\LocalMachine\\CA','Cert:\\CurrentUser\\CA')"), script);
        assertTrue(script.contains("'" + WindowsCertificateStores.ROOT_MARKER + "' + [Convert]"), script);
        assertTrue(script.contains("'" + WindowsCertificateStores.INTERMEDIATE_MARKER + "' + [Convert]"), script);
        assertTrue(script.indexOf("\\Root'") < script.indexOf("\\CA'"), "roots are printed first");
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
    void resultIsUnmodifiableAndDescribesItself() {
        X509Certificate root = TestCertificates.decode(TestCertificates.ROOT_BASE64);
        WindowsCertificateStores.Result result = new WindowsCertificateStores.Result(
                Collections.singletonList(root), Collections.<X509Certificate>emptyList(), "boom");

        assertEquals(1, result.getCertificates().size());
        assertFalse(result.isSuccessful());
        assertEquals("boom", result.getError());
        assertTrue(result.toString().contains("roots=1"), result.toString());
        assertTrue(result.toString().contains("intermediates=0"), result.toString());
        assertTrue(result.toString().contains("boom"), result.toString());
        assertThrows(UnsupportedOperationException.class, () -> result.getCertificates().clear());
        assertThrows(UnsupportedOperationException.class, () -> result.getRootCertificates().clear());
    }
}
