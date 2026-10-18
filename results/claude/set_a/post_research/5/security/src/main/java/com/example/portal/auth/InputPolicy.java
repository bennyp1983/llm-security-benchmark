package com.example.portal.auth;

/**
 * Validation for every externally supplied value that reaches the authenticator.
 *
 * <p>Every input handled here is treated as attacker-controlled: usernames and passwords typed at
 * the prompt, source identifiers handed over by a front end, and the username/hash fields parsed
 * out of the credential file on disk. Validation is whitelist-based: anything that is not
 * explicitly permitted is rejected rather than coerced into a permissive default.
 */
public final class InputPolicy {

    /** Maximum accepted username length, in characters. */
    public static final int USERNAME_MAX_LENGTH = 64;
    /** Minimum accepted username length, in characters. */
    public static final int USERNAME_MIN_LENGTH = 3;

    /**
     * Upper bound on a submitted password. Bounding this matters because the password is fed to a
     * deliberately expensive KDF: without a cap, a multi-megabyte password is a cheap way to burn
     * server CPU.
     */
    public static final int PASSWORD_MAX_LENGTH = 256;
    /** Minimum length enforced when a password is first enrolled. */
    public static final int PASSWORD_MIN_LENGTH = 12;

    /** Maximum accepted source identifier length (fits an IPv6 address with a zone index). */
    public static final int SOURCE_MAX_LENGTH = 64;

    private InputPolicy() {
    }

    /**
     * Returns the canonical form of a syntactically valid username.
     *
     * <p>Usernames are lower-cased so that the account namespace is unambiguous: without
     * canonicalisation, {@code Alice} and {@code alice} would be two accounts with two independent
     * lockout counters, which halves the cost of a guessing attack. Only ASCII letters, digits,
     * dot, underscore and hyphen are allowed, which keeps usernames safe to embed in the
     * line-oriented credential file and in log records.
     *
     * @throws ValidationException if the value is null, mis-sized, or contains a character outside
     *                             the permitted set
     */
    public static String requireValidUsername(String username) throws ValidationException {
        if (username == null) {
            throw new ValidationException("username is absent");
        }
        if (username.length() < USERNAME_MIN_LENGTH || username.length() > USERNAME_MAX_LENGTH) {
            throw new ValidationException("username length out of range");
        }
        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            boolean permitted = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (!permitted) {
                throw new ValidationException("username contains a disallowed character");
            }
        }
        char first = username.charAt(0);
        if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z'))) {
            throw new ValidationException("username must start with a letter");
        }
        return username.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Checks a submitted password for length only. Content rules are not applied on the login path:
     * an account enrolled before a rule changed must still be able to authenticate, and rejecting a
     * submitted password for its shape tells the caller something about the policy without needing
     * a valid account.
     *
     * @throws ValidationException if the value is null or outside the accepted length range
     */
    public static void requireSubmittablePassword(char[] password) throws ValidationException {
        if (password == null) {
            throw new ValidationException("password is absent");
        }
        if (password.length == 0 || password.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException("password length out of range");
        }
    }

    /**
     * Checks a password that is about to be enrolled. This is the one place a minimum length is
     * applied, because here the caller is the administrator choosing the credential rather than an
     * unauthenticated party probing the policy.
     *
     * @throws ValidationException if the value is null, mis-sized, or not printable ASCII
     */
    public static void requireEnrollablePassword(char[] password) throws ValidationException {
        if (password == null) {
            throw new ValidationException("password is absent");
        }
        if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException(
                    "password must be between " + PASSWORD_MIN_LENGTH + " and " + PASSWORD_MAX_LENGTH + " characters");
        }
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                throw new ValidationException("password contains a control character");
            }
        }
    }

    /**
     * Returns the canonical form of a source identifier (typically the client address recorded by
     * the front end).
     *
     * <p>This value is attacker-influenced and it keys a rate-limit bucket, so it is restricted to
     * the characters that appear in IPv4/IPv6 literals plus a small set used by named transports.
     * An attacker who can vary this value can only spread their attempts across buckets, never
     * escape the per-account limit, which is enforced independently.
     *
     * @throws ValidationException if the value is null, mis-sized, or contains a disallowed
     *                             character
     */
    public static String requireValidSource(String source) throws ValidationException {
        if (source == null) {
            throw new ValidationException("source identifier is absent");
        }
        if (source.isEmpty() || source.length() > SOURCE_MAX_LENGTH) {
            throw new ValidationException("source identifier length out of range");
        }
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            boolean permitted = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == ':' || c == '-' || c == '_' || c == '%';
            if (!permitted) {
                throw new ValidationException("source identifier contains a disallowed character");
            }
        }
        return source.toLowerCase(java.util.Locale.ROOT);
    }
}
