package com.aresstack.wintrust;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Runs a PowerShell script <em>inline</em> via {@code powershell.exe -Command}.
 *
 * <p>No temporary {@code .ps1} file is ever written. That matters on hardened machines: an unsigned
 * script file in {@code %TEMP%} is blocked by GPO execution policy or AppLocker, while an inline
 * {@code -Command} is still allowed. This mirrors the PAC-URL discovery in
 * {@code com.aresstack:win-proxy-java}.</p>
 *
 * <p>stdout and stderr are drained concurrently on their own threads, so a large export (hundreds of
 * certificates) cannot fill the pipe buffer and deadlock the child process.</p>
 */
final class PowerShellRunner {

    /** Upper bound for the captured stderr; only used for diagnostics. */
    private static final int MAX_STDERR_CHARS = 4000;

    private final String script;
    private final long timeoutSeconds;

    PowerShellRunner(String script, long timeoutSeconds) {
        this.script = script;
        this.timeoutSeconds = timeoutSeconds;
    }

    /**
     * Builds the exact command line used by {@link #runInlineCommand()}:
     * {@code powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <script>}.
     * Package-private so a unit test can assert it without spawning a process.
     */
    List<String> buildInlineCommand() {
        List<String> command = new ArrayList<String>();
        command.add("powershell.exe");
        command.add("-NoProfile");
        command.add("-NonInteractive");
        command.add("-ExecutionPolicy");
        command.add("Bypass");
        command.add("-Command");
        command.add(script);
        return command;
    }

    /**
     * Executes the script inline and waits at most {@code timeoutSeconds} for it to finish.
     *
     * @return exit code, stdout and (truncated) stderr of the process
     * @throws IOException when PowerShell cannot be started, times out or is interrupted
     */
    Execution runInlineCommand() throws IOException {
        Process process = null;
        ExecutorService executor = Executors.newFixedThreadPool(2, new DaemonThreadFactory());
        try {
            process = new ProcessBuilder(buildInlineCommand()).start();

            Future<String> stdout = executor.submit(new StreamReader(process.getInputStream(), Integer.MAX_VALUE));
            Future<String> stderr = executor.submit(new StreamReader(process.getErrorStream(), MAX_STDERR_CHARS));

            int exitCode = waitFor(process);
            String output = await(stdout, "stdout");
            String error = await(stderr, "stderr");
            return new Execution(exitCode, output, error);
        } finally {
            executor.shutdownNow();
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private int waitFor(Process process) throws IOException {
        try {
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException("PowerShell did not finish within " + timeoutSeconds + " seconds.");
            }
            return process.exitValue();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException("Waiting for PowerShell was interrupted.", ex);
        }
    }

    private String await(Future<String> future, String streamName) throws IOException {
        try {
            // The process has exited, so the readers only need to flush what is already buffered.
            return future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IOException("Reading PowerShell " + streamName + " was interrupted.", ex);
        } catch (ExecutionException ex) {
            throw new IOException("Could not read PowerShell " + streamName + ".", ex.getCause());
        } catch (TimeoutException ex) {
            throw new IOException("PowerShell " + streamName + " reader did not finish.", ex);
        }
    }

    /** Exit code, stdout and stderr of one PowerShell run. */
    static final class Execution {

        private final int exitCode;
        private final String standardOutput;
        private final String standardError;

        Execution(int exitCode, String standardOutput, String standardError) {
            this.exitCode = exitCode;
            this.standardOutput = standardOutput == null ? "" : standardOutput;
            this.standardError = standardError == null ? "" : standardError;
        }

        int getExitCode() {
            return exitCode;
        }

        String getStandardOutput() {
            return standardOutput;
        }

        String getStandardError() {
            return standardError;
        }
    }

    /** Reads a stream to the end (always draining it) and keeps at most {@code limit} characters. */
    private static final class StreamReader implements Callable<String> {

        private final InputStream stream;
        private final int limit;

        StreamReader(InputStream stream, int limit) {
            this.stream = stream;
            this.limit = limit;
        }

        @Override
        public String call() throws IOException {
            StringBuilder builder = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (builder.length() < limit) {
                        builder.append(line).append('\n');
                    }
                }
                return builder.toString();
            } finally {
                reader.close();
            }
        }
    }

    private static final class DaemonThreadFactory implements java.util.concurrent.ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "win-trust-java-powershell");
            thread.setDaemon(true);
            return thread;
        }
    }
}
