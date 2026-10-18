package portal.cli;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Terminal reader. Uses {@link Console#readPassword()} whenever a real terminal is
 * attached, because that keeps the password out of the echo, out of the shell history and
 * out of {@code argv}. Falls back to piped stdin with a visible warning for non-interactive
 * runs (tests, containers with redirected input).
 */
public final class TerminalReader implements InteractiveReader {

    private final java.io.PrintStream out;
    private final Console console;
    private BufferedReader pipe;
    private boolean warnedAboutEcho;

    public TerminalReader(java.io.PrintStream out) {
        this.out = out;
        this.console = System.console();
    }

    @Override
    public boolean supportsSecretEntry() {
        return console != null;
    }

    @Override
    public String readLine(String prompt) {
        out.print(prompt);
        out.flush();
        if (console != null) {
            return console.readLine();
        }
        return readFromPipe();
    }

    @Override
    public char[] readSecret(String prompt) {
        if (console != null) {
            char[] secret = console.readPassword(prompt);
            return secret == null ? new char[0] : secret;
        }
        if (!warnedAboutEcho) {
            out.println("WARNING: no controlling terminal, so input will be echoed. "
                    + "For provisioning, prefer ADMIN_PORTAL_PASSWORD_FILE pointing at a "
                    + "file only the service account can read.");
            warnedAboutEcho = true;
        }
        out.print(prompt);
        out.flush();
        String line = readFromPipe();
        return line == null ? new char[0] : line.toCharArray();
    }

    /** Erases the line we are about to echo back is impossible here, hence the warning above. */
    private String readFromPipe() {
        try {
            if (pipe == null) {
                pipe = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            }
            return pipe.readLine();
        } catch (IOException e) {
            return null;
        }
    }

    static void erase(char[] value) {
        if (value != null) {
            Arrays.fill(value, '\0');
        }
    }
}
