package com.security.crypto;

/**
 * Generic cryptographic exception thrown for all encryption, decryption,
 * key handling, and validation failures.
 * <p>
 * Security Design:
 * <ul>
 *   <li>Rule 6 (Failure behavior): To prevent oracle attacks, key-enumeration,
 *       and side-channel information leaks, caller-facing error messages are strictly
 *       uniform and generic. Callers receive only high-level generic descriptions
 *       (e.g., "Decryption failed"), regardless of whether the root cause was a
 *       malformed payload, invalid tag, unknown key, or tampering.</li>
 *   <li>Internal error details and stack traces are withheld from client responses
 *       and routed solely to secure server-side logging.</li>
 * </ul>
 */
public class CryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new CryptoException with a generic, safe message.
     *
     * @param safeMessage A sanitized, high-level message safe to display to users.
     */
    public CryptoException(String safeMessage) {
        super(safeMessage);
    }

    /**
     * Constructs a new CryptoException with a generic safe message and an internal cause.
     * The internal cause is preserved for server-side logging and diagnostic inspection,
     * but will not leak sensitive information to external callers.
     *
     * @param safeMessage A sanitized, high-level message safe to display to users.
     * @param cause       The internal technical cause (retained for server-side logging).
     */
    public CryptoException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
