package com.example.adminportal;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Minimum strength rules applied when a password is chosen.
 *
 * Length is weighted far above composition rules, and passwords are screened
 * against a small list of well-known weak choices plus the account name itself.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 256;

    private static final Set<String> COMMON = loadCommonPasswords();

    private PasswordPolicy() {
    }

    /** Throws {@link IllegalArgumentException} describing the first unmet rule. */
    public static void requireAcceptable(String username, char[] password) {
        if (password == null || password.length < MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_LENGTH + " characters");
        }
        if (password.length > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_LENGTH + " characters");
        }

        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean other = false;
        for (char c : password) {
            if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                other = true;
            }
        }
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
        if (classes < 3) {
            throw new IllegalArgumentException(
                    "Password must combine at least three of: lowercase, uppercase, digits, symbols");
        }

        String lowered = new String(password).toLowerCase(Locale.ROOT);
        if (COMMON.contains(lowered)) {
            throw new IllegalArgumentException("Password is among commonly used passwords");
        }
        if (username != null && !username.isBlank()
                && lowered.contains(username.trim().toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Password must not contain the username");
        }
        if (hasLongRun(password)) {
            throw new IllegalArgumentException("Password must not repeat a character four or more times");
        }
    }

    private static boolean hasLongRun(char[] password) {
        int run = 1;
        for (int i = 1; i < password.length; i++) {
            run = password[i] == password[i - 1] ? run + 1 : 1;
            if (run >= 4) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> loadCommonPasswords() {
        Set<String> set = new HashSet<>(Arrays.asList(
                "password", "password1", "password123", "administrator", "admin123",
                "letmein", "welcome1", "qwerty123456", "changeme123", "iloveyou",
                "123456789012", "adminadmin", "passw0rd123", "superadmin1"));
        // An operator-supplied deny list, when present on the classpath, extends the built-in set.
        try (InputStream in = PasswordPolicy.class.getResourceAsStream("/weak-passwords.txt")) {
            if (in != null) {
                new java.io.BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))
                        .lines()
                        .map(line -> line.trim().toLowerCase(Locale.ROOT))
                        .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                        .forEach(set::add);
            }
        } catch (IOException e) {
            // Optional resource; the built-in list still applies.
        }
        return Set.copyOf(set);
    }
}
