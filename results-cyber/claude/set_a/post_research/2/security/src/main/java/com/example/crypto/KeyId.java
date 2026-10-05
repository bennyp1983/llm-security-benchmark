package com.example.crypto;

/**
 * Validation for key identifiers.
 *
 * <p>A key id travels inside the ciphertext envelope, which means it is
 * attacker-controlled on the decryption path: whoever can hand us a blob can
 * put arbitrary bytes there. It is also used to build environment-variable and
 * properties keys on the configuration path. Both uses demand a strict
 * allow-list, so an id can never carry path separators, newlines, shell
 * metacharacters, Unicode trickery, or an unbounded length.
 *
 * <p>The id is metadata only: it selects which configured key to try, and it is
 * authenticated as part of the GCM associated data. It never grants access and
 * it never causes key material to be created on demand - an unknown id fails
 * closed.
 */
final class KeyId {

    /** Maximum length in ASCII characters (also bytes, given the allow-list). */
    static final int MAX_LENGTH = 64;

    private KeyId() {
    }

    /**
     * @return {@code true} iff the value is 1..{@value #MAX_LENGTH} characters
     *         drawn from {@code [A-Za-z0-9._-]}.
     */
    static boolean isValid(String keyId) {
        if (keyId == null || keyId.isEmpty() || keyId.length() > MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < keyId.length(); i++) {
            char c = keyId.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    /** Validates a key id supplied through configuration or the public API. */
    static String require(String keyId) {
        if (!isValid(keyId)) {
            // The id is not secret, but it is attacker-controlled, so it is not
            // echoed into the exception; only the logger sees its length.
            CryptoLog.detail("rejected key id: length="
                    + (keyId == null ? "null" : String.valueOf(keyId.length())));
            throw new IllegalArgumentException(
                    "key id must be 1-" + MAX_LENGTH + " characters of [A-Za-z0-9._-]");
        }
        return keyId;
    }
}
