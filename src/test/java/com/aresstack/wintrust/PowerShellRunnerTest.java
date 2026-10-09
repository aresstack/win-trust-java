package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PowerShellRunnerTest {

    @Test
    void inlineCommandUsesCommandSwitchAndHardeningFlags() {
        List<String> command = new PowerShellRunner("Write-Output 'x'", 5L).buildInlineCommand();

        assertTrue(command.get(0).endsWith("powershell.exe"), command.get(0));
        assertEquals("-NoProfile", command.get(1));
        assertEquals("-NonInteractive", command.get(2));
        assertEquals("-Command", command.get(3));
        assertEquals("Write-Output 'x'", command.get(4));
        assertEquals(5, command.size());
        assertFalse(command.contains("-File"));
        assertFalse(command.contains("-ExecutionPolicy"),
                "the execution policy does not apply to -Command; the Bypass flag is only an EDR indicator");
    }

    @Test
    void powerShellIsAddressedByItsFixedInstallLocationWhenSystemRootIsKnown() {
        String executable = PowerShellRunner.resolvePowerShellExecutable();
        String systemRoot = System.getenv("SystemRoot");

        if (systemRoot != null && new java.io.File(systemRoot, "System32\\WindowsPowerShell\\v1.0\\powershell.exe").isFile()) {
            assertTrue(new java.io.File(executable).isAbsolute(), executable);
            assertTrue(executable.toLowerCase().endsWith("\\system32\\windowspowershell\\v1.0\\powershell.exe"), executable);
        } else {
            assertEquals("powershell.exe", executable);
        }
    }

    @Test
    void streamReaderNeverRetainsMoreThanTheLimitEvenForOneHugeLine() throws Exception {
        StringBuilder hugeLine = new StringBuilder();
        for (int i = 0; i < 10_000; i++) {
            hugeLine.append('x');
        }
        String captured = read(hugeLine + "\nsecond line\n", 100);

        assertEquals(100, captured.length(), "a single over-long line must be cut at the cap");
        assertFalse(captured.contains("second"), "nothing after the cap is retained");
    }

    @Test
    void streamReaderKeepsWholeLinesBelowTheLimitAndCutsAtTheLimit() throws Exception {
        String captured = read("one\ntwo\nthree\nfour\n", 9);

        assertEquals("one\ntwo\nt", captured, "whole lines fit, the next one is cut exactly at the cap");
        assertEquals("one\ntwo\n", read("one\ntwo\n", 1_000), "an unlimited-enough cap keeps everything");
    }

    @Test
    void streamReaderDrainsTheWholeStreamAfterTheCap() throws Exception {
        final int[] bytesRead = {0};
        byte[] payload = "aaaa\nbbbb\ncccc\n".getBytes(StandardCharsets.UTF_8);
        InputStream counting = new ByteArrayInputStream(payload) {
            @Override
            public synchronized int read(byte[] buffer, int off, int len) {
                int n = super.read(buffer, off, len);
                if (n > 0) {
                    bytesRead[0] += n;
                }
                return n;
            }
        };

        String captured = new PowerShellRunner.StreamReader(counting, 3).call();

        assertEquals("aaa", captured);
        assertEquals(payload.length, bytesRead[0], "the stream is drained to EOF so the process cannot block");
    }

    private static String read(String content, int limit) throws Exception {
        InputStream stream = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        return new PowerShellRunner.StreamReader(stream, limit).call();
    }

    @Test
    void executionNormalisesNullStreams() {
        PowerShellRunner.Execution execution = new PowerShellRunner.Execution(3, null, null);

        assertEquals(3, execution.getExitCode());
        assertEquals("", execution.getStandardOutput());
        assertEquals("", execution.getStandardError());
        assertTrue(new PowerShellRunner.Execution(0, "out", "err").getStandardError().equals("err"));
    }
}
