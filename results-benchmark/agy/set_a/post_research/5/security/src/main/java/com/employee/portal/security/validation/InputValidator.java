package com.employee.portal.security.validation;

import com.employee.portal.security.config.SecurityConfig;

import java.util.regex.Pattern;

/**
 * Validates and sanitizes all untrusted inputs across trust boundaries.
 * Treats every client, file, and network input as attacker-controlled.
 */
public final class InputValidator {

    // Whitelist regex patterns
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]{3,32}$");
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
    );
    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|" +
        "^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    );
    private static final Pattern SESSION_TOKEN_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{43,64}$");

    private InputValidator() {
        // Utility class
    }

    /**
     * Validates employee username against strict whitelist rules.
     * Allowed: 3-32 characters, alphanumeric plus '.', '_', '-'.
     */
    public static boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }
        int len = username.length();
        if (len < SecurityConfig.MIN_USERNAME_LENGTH || len > SecurityConfig.MAX_USERNAME_LENGTH) {
            return false;
        }
        // Disallow path traversal sequences such as '..'
        if (username.contains("..")) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username).matches();
    }

    /**
     * Validates password length.
     * Bound length between 8 and 128 chars to prevent PBKDF2 CPU exhaustion attacks.
     */
    public static boolean isValidPassword(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= SecurityConfig.MIN_PASSWORD_LENGTH &&
               password.length <= SecurityConfig.MAX_PASSWORD_LENGTH;
    }

    /**
     * Validates client source IP / address identifier.
     */
    public static boolean isValidSourceIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return false;
        }
        String trimmed = sourceIp.trim();
        if (trimmed.length() > SecurityConfig.MAX_SOURCE_IP_LENGTH) {
            return false;
        }
        if ("localhost".equalsIgnoreCase(trimmed) || "127.0.0.1".equals(trimmed) || "::1".equals(trimmed)) {
            return true;
        }
        return IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches();
    }

    /**
     * Validates session token format (cryptographically random URL-safe Base64).
     */
    public static boolean isValidSessionToken(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        return SESSION_TOKEN_PATTERN.matcher(token).matches();
    }

    /**
     * Sanitizes strings for audit logging to prevent Log Injection / Log Forging (CWE-117).
     * Replaces newlines, carriage returns, and control characters.
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(Math.min(input.length(), 80));
        for (int i = 0; i < input.length() && i < 80; i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (c < 32 || c == 127) {
                sb.append('?');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Basic HTML escaping to prevent XSS (CWE-79) in web responses.
     */
    public static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.max(16, text.length()));
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#x27;");
                default -> {
                    if (c < 32 && c != '\t' && c != '\n' && c != '\r') {
                        out.append('?');
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
