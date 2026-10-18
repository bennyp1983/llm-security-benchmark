package com.example.auth;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Validation for every value that reaches this component from outside: the email and
 * password typed by the user, the source identifier, and values read back out of the
 * database. Nothing is normalised into a permissive default - input that does not
 * match is rejected.
 */
public final class InputValidator {

    /** RFC-5321 limits: 64-char local part, 254-char address. */
    public static final int MAX_EMAIL_LENGTH = 254;
    /** Sanity bound for a submitted password; the policy minimum for a *new* password
     *  is {@link #MIN_NEW_PASSWORD_LENGTH}. Rejecting short submissions at login would
     *  permanently lock out any account whose password predates the current policy. */
    public static final int MIN_PASSWORD_LENGTH = 8;
    /** Minimum length accepted when a password is set or changed. */
    public static final int MIN_NEW_PASSWORD_LENGTH = 12;
    /** Upper bound so an attacker cannot make us hash a megabyte-long "password". */
    public static final int MAX_PASSWORD_LENGTH = 256;

    private static final Pattern EMAIL = Pattern.compile(
            "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
          + "@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
          + "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$");

    private static final Pattern SOURCE_ID = Pattern.compile("^[A-Za-z0-9.:_-]{1,64}$");

    private InputValidator() {
    }

    /**
     * Validates and canonicalises an email address.
     *
     * @return the lower-cased address, or empty if the input is not a usable address
     */
    public static Optional<String> normalizeEmail(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String trimmed = raw.strip();
        if (trimmed.length() < 3 || trimmed.length() > MAX_EMAIL_LENGTH) {
            return Optional.empty();
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c < 0x21 || c > 0x7E) { // printable ASCII only: no controls, spaces or NUL
                return Optional.empty();
            }
        }
        int at = trimmed.indexOf('@');
        if (at < 1 || at != trimmed.lastIndexOf('@')) {
            return Optional.empty();
        }
        if (at > 64 || trimmed.length() - at - 1 > 255) {
            return Optional.empty();
        }
        if (!EMAIL.matcher(trimmed).matches()) {
            return Optional.empty();
        }
        return Optional.of(trimmed.toLowerCase(Locale.ROOT));
    }

    /**
     * Checks the supplied password for length and for characters that cannot have come
     * from a terminal (controls). The content is never logged or echoed.
     */
    public static boolean isAcceptablePassword(char[] password) {
        if (password == null
                || password.length < MIN_PASSWORD_LENGTH
                || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidSourceId(String sourceId) {
        return sourceId != null && SOURCE_ID.matcher(sourceId).matches();
    }
}
