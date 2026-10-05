package com.example.crypto;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Logging funnel for the component.
 *
 * <p>Everything this component logs passes through here so that the rule
 * "secrets and plaintext are never logged" can be enforced and reviewed in one
 * place. Callers of these methods pass only non-secret metadata: key
 * identifiers, byte lengths, and fixed English strings. Key material,
 * passphrases, plaintext and ciphertext are never arguments.
 *
 * <p>Diagnostics are emitted at {@link Level#FINE} (disabled by default) and the
 * only {@link Level#WARNING} messages describe configuration problems, never
 * data.
 */
final class CryptoLog {

    private static final Logger LOG = Logger.getLogger("com.example.crypto");

    private CryptoLog() {
    }

    /** Logs non-secret diagnostic detail about a failure. */
    static void detail(String message) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine(message);
        }
    }

    /** Logs a non-secret configuration problem. */
    static void configProblem(String message) {
        LOG.warning(message);
    }

    /**
     * Renders a sensitive value for logs as a non-reversible placeholder: its
     * length only. Used so that log lines can still be correlated without ever
     * containing the value itself.
     */
    static String masked(byte[] sensitive) {
        return sensitive == null ? "absent" : ("[redacted " + sensitive.length + " bytes]");
    }

    /** Masks a configuration/environment value that may contain a secret. */
    static String masked(String sensitive) {
        return sensitive == null ? "absent" : ("[redacted " + sensitive.length() + " chars]");
    }
}
