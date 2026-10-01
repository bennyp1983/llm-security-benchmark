package com.security.auth.validation;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Strict whitelist validator for all external client and environment inputs.
 * Enforces Rule 1 (Trust Boundaries), Rule 5 (Bounded Storage), and Rule 6 (Reject Unknown/Invalid).
 */
public final class InputValidator {

    // RFC 5321 specifies max path/email length is 254 octets
    public static final int EMAIL_MAX_LENGTH = 254;
    public static final int EMAIL_MIN_LENGTH = 5;

    public static final int USERNAME_MIN_LENGTH = 3;
    public static final int USERNAME_MAX_LENGTH = 32;

    public static final int PASSWORD_MIN_LENGTH = 12;
    public static final int PASSWORD_MAX_LENGTH = 128; // Strict upper bound prevents Hash DoS attacks

    // Linear regex pattern with zero backtracking risk (ReDoS safe)
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@([A-Za-z0-9]+(-[A-Za-z0-9]+)*\\.)+[A-Za-z]{2,63}$"
    );

    // Whitelist: strictly alphanumeric, hyphen, underscore
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,32}$");

    // Standard IPv4 and IPv6 format patterns
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)$"
    );
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:)+:[0-9a-fA-F]{1,4}$"
    );

    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrator", "root", "system", "sysadmin", "guest", "anonymous",
            "support", "null", "undefined", "operator", "daemon", "service"
    );

    private InputValidator() {
        // Utility class
    }

    /**
     * Validates an email address against strict length, character, and structure rules.
     *
     * @param email input email
     * @return normalized (lowercased) email if valid
     * @throws IllegalArgumentException if invalid
     */
    public static String validateAndNormalizeEmail(String email) {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }
        String trimmed = email.trim();
        if (trimmed.length() < EMAIL_MIN_LENGTH || trimmed.length() > EMAIL_MAX_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Email length must be between %d and %d characters", EMAIL_MIN_LENGTH, EMAIL_MAX_LENGTH)
            );
        }
        // Reject any null bytes or ASCII control characters
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c < 32 || c > 126) {
                throw new IllegalArgumentException("Email contains illegal control or non-ASCII characters");
            }
        }
        // Disallow consecutive dots, or leading/trailing dots in local/domain
        if (trimmed.startsWith(".") || trimmed.endsWith(".") || trimmed.contains("..")) {
            throw new IllegalArgumentException("Email cannot contain consecutive dots or start/end with dot");
        }
        int atIndex = trimmed.indexOf('@');
        if (atIndex <= 0 || atIndex != trimmed.lastIndexOf('@') || atIndex == trimmed.length() - 1) {
            throw new IllegalArgumentException("Email must contain exactly one '@' character not at start or end");
        }
        String localPart = trimmed.substring(0, atIndex);
        if (localPart.startsWith(".") || localPart.endsWith(".")) {
            throw new IllegalArgumentException("Email local part cannot start or end with a dot");
        }
        if (!EMAIL_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("Email does not conform to valid email format");
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }

    /**
     * Validates a username against whitelist characters and reserved names.
     *
     * @param username input username
     * @return validated username
     * @throws IllegalArgumentException if invalid
     */
    public static String validateUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("Username cannot be null");
        }
        String trimmed = username.trim();
        if (trimmed.length() < USERNAME_MIN_LENGTH || trimmed.length() > USERNAME_MAX_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Username length must be between %d and %d characters", USERNAME_MIN_LENGTH, USERNAME_MAX_LENGTH)
            );
        }
        if (!USERNAME_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("Username must contain only alphanumeric characters, underscores, and hyphens");
        }
        if (RESERVED_USERNAMES.contains(trimmed.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Username is reserved and cannot be registered");
        }
        return trimmed;
    }

    /**
     * Validates password length and complexity.
     * Does NOT convert password to a String to protect memory security.
     *
     * @param password sensitive password characters
     * @throws IllegalArgumentException if complexity rules are not met
     */
    public static void validatePassword(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Password length must be between %d and %d characters", PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)
            );
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password) {
            if (c < 32 || c > 126) {
                throw new IllegalArgumentException("Password contains illegal control characters");
            }
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }

        if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
            throw new IllegalArgumentException(
                    "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
            );
        }
    }

    /**
     * Validates a client source identifier or IP address.
     *
     * @param sourceIp client source IP
     * @return validated sanitized IP string
     */
    public static String validateSourceIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return "127.0.0.1"; // Default safe localhost source
        }
        String trimmed = sourceIp.trim();
        if (trimmed.length() > 45) {
            throw new IllegalArgumentException("Source IP exceeds maximum allowable length");
        }
        if ("localhost".equalsIgnoreCase(trimmed) || "127.0.0.1".equals(trimmed) || "::1".equals(trimmed)) {
            return trimmed;
        }
        if (IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        throw new IllegalArgumentException("Invalid client source IP format");
    }

    /**
     * Validates a UUID identifier format.
     */
    public static void validateUuid(String uuid) {
        if (uuid == null || uuid.length() != 36) {
            throw new IllegalArgumentException("Invalid identifier format");
        }
        Pattern uuidPattern = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        if (!uuidPattern.matcher(uuid).matches()) {
            throw new IllegalArgumentException("Identifier must be a valid UUID");
        }
    }
}
