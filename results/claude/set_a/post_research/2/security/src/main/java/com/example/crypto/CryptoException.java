package com.example.crypto;

/**
 * Single, deliberately uninformative failure type for every cryptographic
 * operation in this package.
 *
 * <p>Security rationale: callers (and therefore anything a caller echoes back to
 * a remote user) learn only that the operation failed. The distinction between
 * "no such key id", "truncated input", "wrong key", "tampered ciphertext" and
 * "wrong associated data" is never exposed through the message, the type, or a
 * chained cause, because those distinctions are an oracle for an attacker who
 * can submit candidate ciphertexts. Diagnostic detail is written to the
 * component's logger instead (see {@link CryptoLog}), and even there it is
 * limited to non-secret metadata such as lengths and key identifiers.
 */
public final class CryptoException extends Exception {

    private static final long serialVersionUID = 1L;

    CryptoException(String genericMessage) {
        // No cause is attached on purpose: a stack trace printed by the caller
        // must not reveal which internal check failed.
        super(genericMessage, null, true, false);
    }
}
