package com.example.adminportal;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Console input/output helper.
 *
 * <p>Prefers {@link Console} so passwords are read without echo and land in a {@code char[]} that
 * the caller can zero. When no console is attached (piped input, IDE run) it falls back to reading
 * stdin and warns that the password will be visible.
 */
final class TextIo {

    private final Console console = System.console();
    private final BufferedReader reader =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final PrintStream out;

    TextIo(PrintStream out) {
        this.out = out;
    }

    void print(String message) {
        out.println(message);
    }

    boolean hasConsole() {
        return console != null;
    }

    /** Reads a line, or returns {@code null} at end of input. */
    String readLine(String prompt) {
        out.print(prompt);
        out.flush();
        if (console != null) {
            return console.readLine();
        }
        try {
            return reader.readLine();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Reads a password without echoing it where possible. Returns {@code null} at end of input.
     * The caller owns the returned array and should zero it when finished.
     */
    char[] readPassword(String prompt) {
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        String line = readLine(prompt);
        return line == null ? null : line.toCharArray();
    }

    /** Overwrites a password buffer so the plaintext does not linger in the heap. */
    static void wipe(char[] password) {
        if (password != null) {
            java.util.Arrays.fill(password, '\0');
        }
    }
}
