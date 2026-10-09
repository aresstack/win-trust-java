package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PowerShellRunnerTest {

    @Test
    void inlineCommandUsesCommandSwitchAndHardeningFlags() {
        List<String> command = new PowerShellRunner("Write-Output 'x'", 5L).buildInlineCommand();

        assertEquals("powershell.exe", command.get(0));
        assertEquals("-NoProfile", command.get(1));
        assertEquals("-NonInteractive", command.get(2));
        assertEquals("-ExecutionPolicy", command.get(3));
        assertEquals("Bypass", command.get(4));
        assertEquals("-Command", command.get(5));
        assertEquals("Write-Output 'x'", command.get(6));
        assertEquals(7, command.size());
        assertFalse(command.contains("-File"));
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
