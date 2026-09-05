package vault;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Getting a secret onto the command line without it lingering.
 *
 * <p>A passphrase is never taken from {@code argv}: process arguments are world-readable
 * through {@code /proc}, land in shell history, and end up in CI logs. Resolution order is:
 *
 * <ol>
 *   <li>{@code VAULT_KEYSTORE_PASSWORD} / {@code VAULT_PASSPHRASE} environment variable;</li>
 *   <li>a file named by {@code VAULT_KEYSTORE_PASSWORD_FILE} or {@code VAULT_PASSPHRASE_FILE},
 *       which is how a container secret mounted at a path is consumed;</li>
 *   <li>a masked {@link Console} prompt, when attached to a terminal.</li>
 * </ol>
 *
 * <p>None of these are perfectly clean: environment variables leak through
 * {@code /proc/PID/environ} to the same user, so the returned array is the caller's to zero
 * once used.
 */
public final class Passwords {

    public static final String ENV_KEYSTORE_PASSWORD = "VAULT_KEYSTORE_PASSWORD";
    public static final String ENV_KEYSTORE_PASSWORD_FILE = "VAULT_KEYSTORE_PASSWORD_FILE";
    public static final String ENV_PASSPHRASE = "VAULT_PASSPHRASE";
    public static final String ENV_PASSPHRASE_FILE = "VAULT_PASSPHRASE_FILE";

    private Passwords() {
    }

    /** Keystore password, or an empty array when the operator has not supplied one. */
    public static char[] keystorePassword() {
        return read(ENV_KEYSTORE_PASSWORD, ENV_KEYSTORE_PASSWORD_FILE, "Keystore password");
    }

    /** Data passphrase, or an empty array when the operator has not supplied one. */
    public static char[] passphrase() {
        return read(ENV_PASSPHRASE, ENV_PASSPHRASE_FILE, "Data passphrase");
    }

    /**
     * Requires a non-empty secret, exiting with a clear message when none of the sources has
     * one. Used by commands that cannot proceed without it.
     */
    public static char[] required(char[] value, String envVar, String envFileVar) {
        if (value != null && value.length > 0) {
            return value;
        }
        throw new VaultException("no secret available: set " + envVar + ", point " + envFileVar
                + " at a mounted secret file, or run from a terminal so the prompt can appear");
    }

    /**
     * Confirms a passphrase by prompting twice, for interactive setup where a typo would mean
     * permanently unreadable data. Not available when stdin is a pipe.
     */
    public static char[] confirmedPrompt(String label) {
        Console console = System.console();
        if (console == null) {
            throw new VaultException("interactive confirmation needs a terminal; supply the secret via "
                    + "environment variable instead");
        }
        char[] first = console.readPassword("%s: ", label);
        char[] second = console.readPassword("repeat %s: ", label.trim().toLowerCase());
        try {
            if (!Arrays.equals(first, second)) {
                throw new VaultException("the two entries did not match");
            }
            return first == null ? new char[0] : first.clone();
        } finally {
            if (second != null) {
                Arrays.fill(second, '\0');
            }
        }
    }

    public static String describeSources() {
        return ENV_KEYSTORE_PASSWORD + " / " + ENV_KEYSTORE_PASSWORD_FILE + " (keystore), "
                + ENV_PASSPHRASE + " / " + ENV_PASSPHRASE_FILE + " (data passphrase), or a terminal prompt";
    }

    private static char[] read(String envVar, String envFileVar, String promptLabel) {
        String fromEnv = System.getenv(envVar);
        if (fromEnv != null && !fromEnv.isEmpty()) {
            return fromEnv.toCharArray();
        }
        String fromFile = System.getenv(envFileVar);
        if (fromFile != null && !fromFile.isEmpty()) {
            return readSecretFile(Path.of(fromFile));
        }
        Console console = System.console();
        if (console == null) {
            return new char[0];
        }
        char[] typed = console.readPassword("%s: ", promptLabel);
        return typed == null ? new char[0] : typed;
    }

    private static char[] readSecretFile(Path path) {
        try {
            byte[] raw = Files.readAllBytes(path);
            try {
                String text = new String(raw, StandardCharsets.UTF_8);
                // Secret managers usually append a newline; it is not part of the secret.
                while (text.endsWith("\n") || text.endsWith("\r")) {
                    text = text.substring(0, text.length() - 1);
                }
                return text.toCharArray();
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (java.io.IOException e) {
            throw new VaultException("unable to read secret file " + path, e);
        }
    }
}
