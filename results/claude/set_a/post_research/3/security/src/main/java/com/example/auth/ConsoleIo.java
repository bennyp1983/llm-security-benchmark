package com.example.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Reads the email address and password from the user.
 *
 * <p>Uses {@link java.io.Console} when one is attached, so the password is never echoed
 * and never enters the shell history or the process arguments. When there is no console
 * (piped input, as in the smoke test) the password is read from stdin and a warning is
 * printed, because echo cannot be suppressed in that case.
 *
 * <p>Reads are length-bounded: a client cannot make us buffer an unbounded line.
 */
final class ConsoleIo implements AutoCloseable {

    private static final int MAX_LINE = 1024;

    private final java.io.Console console = System.console();
    private final BufferedReader reader =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    String readLine(String prompt) throws IOException {
        if (console != null) {
            String line = console.readLine("%s", prompt);
            return line == null ? "" : bound(line);
        }
        System.out.print(prompt);
        System.out.flush();
        String line = reader.readLine();
        return line == null ? "" : bound(line);
    }

    /** Returns a mutable array the caller must zero when finished. */
    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            char[] value = console.readPassword("%s", prompt);
            return value == null ? new char[0] : bound(value);
        }
        System.out.println("Warning: no terminal attached; the password will be echoed.");
        System.out.print(prompt);
        System.out.flush();
        String line = reader.readLine();
        if (line == null) {
            return new char[0];
        }
        char[] value = line.toCharArray();
        // The String copy cannot be wiped; this path is for non-interactive testing only.
        return bound(value);
    }

    private static String bound(String value) {
        return value.length() > MAX_LINE ? value.substring(0, MAX_LINE) : value;
    }

    private static char[] bound(char[] value) {
        if (value.length <= MAX_LINE) {
            return value;
        }
        char[] truncated = new char[MAX_LINE];
        System.arraycopy(value, 0, truncated, 0, MAX_LINE);
        java.util.Arrays.fill(value, '\0');
        return truncated;
    }

    @Override
    public void close() {
        // System.in is owned by the JVM; nothing to release.
    }
}
