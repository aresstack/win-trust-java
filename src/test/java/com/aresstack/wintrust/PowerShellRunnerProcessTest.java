package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the real process lifecycle of {@link PowerShellRunner} (start, concurrent draining, exit
 * code, stderr cap, timeout, start failure) on every platform by running {@link FakePowerShell} in a
 * child JVM instead of {@code powershell.exe}.
 */
class PowerShellRunnerProcessTest {

    private static PowerShellRunner.Execution run(String script, long timeoutSeconds) throws IOException {
        return new PowerShellRunner(FakePowerShell.commandPrefix(), script, timeoutSeconds).runInlineCommand();
    }

    /** JVM banners such as "Picked up JAVA_TOOL_OPTIONS" are not the fake's output. */
    private static String withoutJvmNoise(String stderr) {
        StringBuilder builder = new StringBuilder();
        for (String line : stderr.split("\\r?\\n")) {
            if (!line.startsWith("Picked up ") && line.length() > 0) {
                builder.append(line).append('\n');
            }
        }
        return builder.toString();
    }

    @Test
    void capturesExitCodeStdoutAndStderr() throws Exception {
        PowerShellRunner.Execution execution = run("stdout:ROOT abc|stdout:CA def|stderr:warning|exit:3", 30L);

        assertEquals(3, execution.getExitCode());
        assertEquals("ROOT abc\nCA def\n", execution.getStandardOutput());
        assertEquals("warning\n", withoutJvmNoise(execution.getStandardError()));
    }

    @Test
    void drainsMegabytesOfStdoutWithoutDeadlock() throws Exception {
        PowerShellRunner.Execution execution = run("stdout-lines:30000|exit:0", 60L);

        assertEquals(0, execution.getExitCode());
        assertEquals(30000 * 101, execution.getStandardOutput().length(), "every line (100 chars + newline) arrived");
    }

    @Test
    void capsStderrButDrainsIt() throws Exception {
        PowerShellRunner.Execution execution = run("stderr-chars:20000|stdout:still here|exit:0", 60L);

        assertEquals(0, execution.getExitCode());
        assertEquals("still here\n", execution.getStandardOutput());
        assertTrue(execution.getStandardError().length() <= 4000, "stderr is capped at 4000 characters");
        assertTrue(execution.getStandardError().contains("eeeeeeeeee"));
    }

    @Test
    void killsTheProcessWhenItExceedsTheTimeout() {
        long start = System.nanoTime();
        IOException failure = assertThrows(IOException.class, () -> run("sleep:60000|exit:0", 2L));
        long elapsedSeconds = (System.nanoTime() - start) / 1_000_000_000L;

        assertTrue(failure.getMessage().contains("did not finish within 2 seconds"), failure.getMessage());
        assertTrue(elapsedSeconds < 30, "the child was killed instead of being waited for: " + elapsedSeconds + " s");
    }

    @Test
    void reportsAnExecutableThatCannotBeStarted() {
        PowerShellRunner runner = new PowerShellRunner(
                Collections.singletonList("win-trust-java-no-such-executable"), "stdout:x", 5L);

        IOException failure = assertThrows(IOException.class, runner::runInlineCommand);
        assertTrue(failure.getMessage().contains("win-trust-java-no-such-executable"), failure.getMessage());
    }
}
