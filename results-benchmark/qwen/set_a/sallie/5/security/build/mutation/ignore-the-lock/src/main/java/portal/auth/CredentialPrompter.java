package portal.auth;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/** Reading a username (visible) and a password (hidden) from wherever the portal is running. */
public interface CredentialPrompter {

    /** @return the next line, or null at end of input */
    String readLine(String prompt) throws IOException;

    /** @return the typed characters without a trailing newline, or null at end of input */
    char[] readSecret(String prompt) throws IOException;

    /** False when the password cannot be hidden, which the caller should warn about once. */
    boolean hidesSecret();

    /** The terminal this process is attached to, or a plain stdin reader when there is none. */
    static CredentialPrompter system() {
        Console console = System.console();
        return console == null ? new LinePrompter() : new ConsolePrompter(console);
    }

    /** Real terminal: {@link Console#readPassword(String, Object...)} keeps the password off screen. */
    final class ConsolePrompter implements CredentialPrompter {

        private final Console console;

        ConsolePrompter(Console console) {
            this.console = console;
        }

        @Override
        public String readLine(String prompt) {
            return console.readLine("%s", prompt);
        }

        @Override
        public char[] readSecret(String prompt) {
            return console.readPassword("%s", prompt);
        }

        @Override
        public boolean hidesSecret() {
            return true;
        }
    }

    /**
     * Piped or redirected input (a script, a container without a tty). The password is read as an
     * ordinary line, which is why the portal says out loud that it cannot hide it.
     */
    final class LinePrompter implements CredentialPrompter {

        private final BufferedReader in =
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        @Override
        public String readLine(String prompt) throws IOException {
            System.out.println(prompt);
            return in.readLine();
        }

        @Override
        public char[] readSecret(String prompt) throws IOException {
            System.out.println(prompt);
            String line = in.readLine();
            return line == null ? null : line.toCharArray();
        }

        @Override
        public boolean hidesSecret() {
            return false;
        }
    }
}
