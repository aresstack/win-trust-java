package com.aresstack.wintrust;

import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Stand-in for {@code powershell.exe} so the process handling of {@link PowerShellRunner} can run on
 * every platform. It is started as {@code java -cp <test-classes> FakePowerShell -NoProfile
 * -NonInteractive -Command <script>} and interprets the script as {@code |}-separated directives:
 * {@code stdout:<text>}, {@code stderr:<text>}, {@code stdout-lines:<n>} (n lines of 100 characters),
 * {@code stderr-chars:<n>} (one line of n characters), {@code sleep:<millis>}, {@code exit:<code>}.
 */
public final class FakePowerShell {

    private FakePowerShell() {
    }

    public static void main(String[] args) throws Exception {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8.name());
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8.name());
        String script = args.length == 0 ? "" : args[args.length - 1];
        int exitCode = 0;
        for (String directive : script.split("\\|")) {
            int colon = directive.indexOf(':');
            String key = colon < 0 ? directive : directive.substring(0, colon);
            String value = colon < 0 ? "" : directive.substring(colon + 1);
            if ("stdout".equals(key)) {
                out.println(value);
            } else if ("stderr".equals(key)) {
                err.println(value);
            } else if ("stdout-lines".equals(key)) {
                String line = repeat('x', 100);
                for (int i = 0, n = Integer.parseInt(value); i < n; i++) {
                    out.println(line);
                }
            } else if ("stderr-chars".equals(key)) {
                err.println(repeat('e', Integer.parseInt(value)));
            } else if ("sleep".equals(key)) {
                Thread.sleep(Long.parseLong(value));
            } else if ("exit".equals(key)) {
                exitCode = Integer.parseInt(value);
            }
        }
        out.flush();
        err.flush();
        System.exit(exitCode);
    }

    private static String repeat(char c, int count) {
        StringBuilder builder = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            builder.append(c);
        }
        return builder.toString();
    }

    /** The command prefix that starts this class in a child JVM, for {@link PowerShellRunner}. */
    static List<String> commandPrefix() {
        String javaExecutable = new File(System.getProperty("java.home"), "bin" + File.separator + "java").getPath();
        String classes = new File(FakePowerShell.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getPath();
        return Arrays.asList(javaExecutable, "-cp", classes, FakePowerShell.class.getName());
    }
}
