package com.example.portal.auth;

import java.util.Locale;
import java.util.Set;

/**
 * Minimum rules for new credentials. Applied when an account is created or a password
 * is reset, never during sign-in, where an existing password must be accepted as-is.
 */
public final class PasswordPolicy {

    public static final int MIN_PASSWORD_LENGTH = 12;
    public static final int MAX_PASSWORD_LENGTH = 128;

    /** A short deny-list; a real deployment should check a breached-password corpus. */
    private static final Set<String> FORBIDDEN = Set.of(
            "password", "passw0rd", "letmein", "welcome", "changeme",
            "qwerty", "123456", "employee", "portal");

    private PasswordPolicy() {
    }

    /** @throws IllegalArgumentException if the username or password is unacceptable */
    public static void validate(String username, char[] password) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username must not be blank.");
        }
        if (username.contains("\t") || username.contains("\n")) {
            throw new IllegalArgumentException("Username must not contain tabs or newlines.");
        }
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters.");
        }
        String lower = new String(password).toLowerCase(Locale.ROOT);
        if (FORBIDDEN.contains(lower)) {
            throw new IllegalArgumentException("That password is too common. Choose another.");
        }
        if (lower.contains(username.trim().toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Password must not contain the username.");
        }
    }
}
