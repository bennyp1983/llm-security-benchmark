package com.example.auth;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validates all inputs crossing trust boundaries.
 * Enforces strict typing, length bounds, allowed character sets, and canonicalization.
 * Prevents ReDoS, injection attacks, and resource exhaustion.
 */
public final class InputValidator {

    // RFC 5321 specifies 254 octets max for an email address path.
    public static final int MIN_EMAIL_LENGTH = 3;
    public static final int MAX_EMAIL_LENGTH = 254;

    // Minimum password length for new registrations.
    public static final int MIN_PASSWORD_LENGTH = 8;
    // Bounded maximum password length prevents PBKDF2 CPU/memory exhaustion DoS attacks.
    public static final int MAX_PASSWORD_LENGTH = 128;

    // Bounded source/client identifier length.
    public static final int MAX_SOURCE_ID_LENGTH = 64;

    // Safe linear-time email pattern without catastrophic backtracking (ReDoS safe).
    // Domain labels must be separated by dots and end with a 2-63 letter TLD.
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,63}$"
    );

    // Source identifier pattern: alphanumeric, IPv4, IPv6, colons, dots, dashes, underscores.
    private static final Pattern SOURCE_ID_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9.:_\\-]{1,64}$"
    );

    // Safe iteration limits for PBKDF2.
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;

    private InputValidator() {
        // Utility class
    }

    /**
     * Validates whether an email address conforms to length, character, and format constraints.
     *
     * @param email The raw email string.
     * @return true if valid; false otherwise.
     */
    public static boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }

        String trimmed = email.trim();
        if (trimmed.length() < MIN_EMAIL_LENGTH || trimmed.length() > MAX_EMAIL_LENGTH) {
            return false;
        }

        // Check for disallowed control characters or whitespace
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c <= 0x1F || c == 0x7F || Character.isWhitespace(c)) {
                return false;
            }
        }

        return EMAIL_PATTERN.matcher(trimmed).matches();
    }

    /**
     * Canonicalizes an email address by trimming and converting to lowercase using ROOT locale.
     *
     * @param email The validated email string.
     * @return Canonical email string.
     */
    public static String canonicalizeEmail(String email) {
        if (email == null) {
            return "";
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Validates candidate password length for authentication attempts.
     * Bound checking prevents CPU DoS during password hashing.
     *
     * @param password Password character array.
     * @return true if valid length for verification; false otherwise.
     */
    public static boolean isValidPasswordForAuth(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= 1 && password.length <= MAX_PASSWORD_LENGTH;
    }

    /**
     * Validates password strength for registration / account creation.
     * Requires minimum length and bounds maximum length.
     *
     * @param password Password character array.
     * @return true if valid for creation; false otherwise.
     */
    public static boolean isValidPasswordForCreation(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= MIN_PASSWORD_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
    }

    /**
     * Validates and sanitizes a source identifier (e.g. IP address or client ID).
     *
     * @param sourceId Raw source identifier.
     * @return Sanitized source identifier string.
     */
    public static String sanitizeSourceId(String sourceId) {
        if (sourceId == null || sourceId.isBlank()) {
            return "unknown-source";
        }
        String trimmed = sourceId.trim();
        if (trimmed.length() > MAX_SOURCE_ID_LENGTH) {
            trimmed = trimmed.substring(0, MAX_SOURCE_ID_LENGTH);
        }
        if (SOURCE_ID_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        // Fall back to a safe placeholder if invalid characters are present
        return "invalid-source-format";
    }

    /**
     * Validates stored PBKDF2 parameters retrieved from the database to ensure
     * untrusted database values do not cause algorithm degradation or memory exhaustion.
     *
     * @param algorithm  Algorithm name.
     * @param iterations Iteration count.
     * @param saltBytes  Decoded salt bytes.
     * @param hashBytes  Decoded hash bytes.
     * @return true if database parameters are valid and secure; false otherwise.
     */
    public static boolean isValidDatabaseHashParameters(String algorithm, int iterations,
                                                        byte[] saltBytes, byte[] hashBytes) {
        if (algorithm == null || !algorithm.equals(PasswordHasher.ALGORITHM)) {
            return false;
        }
        if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
            return false;
        }
        if (saltBytes == null || saltBytes.length < 16 || saltBytes.length > 64) {
            return false;
        }
        if (hashBytes == null || hashBytes.length != 32) { // 256 bits = 32 bytes
            return false;
        }
        return true;
    }
}
