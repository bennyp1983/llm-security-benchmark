package com.security.auth.validation;

import java.util.regex.Pattern;

/**
 * Validates untrusted input across the trust boundary (Rule 1).
 * Strictly checks type, length, character set, and range.
 */
public final class InputValidator {

    // Username: 3 to 64 chars, alphanumeric plus safe characters: ., _, -, @
    // Rejects CRLF, tabs, spaces, null bytes, quotes, semicolons, and path characters
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.@-]{3,64}$");

    // IPv4: 4 octets between 0 and 255 without leading zeros
    private static final String IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])";
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^" + IPV4_OCTET + "\\." + IPV4_OCTET + "\\." + IPV4_OCTET + "\\." + IPV4_OCTET + "$"
    );

    // IPv6: standard and compressed hexadecimal notation (7 colons max, hex digits, optional ::)
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
            "([0-9a-fA-F]{1,4}:){1,7}:|" +
            "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
            "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" +
            "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|" +
            "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" +
            "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" +
            "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" +
            ":((:[0-9a-fA-F]{1,4}){1,7}|:))$"
    );

    public static final int MIN_USERNAME_LENGTH = 3;
    public static final int MAX_USERNAME_LENGTH = 64;

    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 128;

    private InputValidator() {
        // Utility class
    }

    /**
     * Validates client-supplied username.
     *
     * @param username the username to validate
     * @return the trimmed, validated username
     * @throws ValidationException if the username is null, out of length bounds, or contains disallowed characters
     */
    public static String validateUsername(String username) throws ValidationException {
        if (username == null) {
            throw new ValidationException("Username cannot be null.");
        }
        if (username.length() < MIN_USERNAME_LENGTH || username.length() > MAX_USERNAME_LENGTH) {
            throw new ValidationException("Username length must be between " + MIN_USERNAME_LENGTH + " and " + MAX_USERNAME_LENGTH + " characters.");
        }
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new ValidationException("Username contains illegal characters.");
        }
        return username;
    }

    /**
     * Validates client-supplied password char array without converting it to a String (Rule 5).
     *
     * @param password the password characters
     * @throws ValidationException if the password is null or out of length bounds
     */
    public static void validatePassword(char[] password) throws ValidationException {
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            throw new ValidationException("Password length must be between " + MIN_PASSWORD_LENGTH + " and " + MAX_PASSWORD_LENGTH + " characters.");
        }
    }

    /**
     * Validates client IP address as a valid IPv4 or IPv6 address.
     * Guarantees no DNS resolution occurs, preventing DNS rebinding or network hang attacks.
     *
     * @param clientIp client IP string
     * @return validated client IP string
     * @throws ValidationException if the IP address is null, malformed, or contains invalid characters
     */
    public static String validateClientIp(String clientIp) throws ValidationException {
        if (clientIp == null) {
            throw new ValidationException("Client IP address cannot be null.");
        }
        if (clientIp.length() < 3 || clientIp.length() > 45) {
            throw new ValidationException("Client IP address length is invalid.");
        }
        if (IPV4_PATTERN.matcher(clientIp).matches() || IPV6_PATTERN.matcher(clientIp).matches()) {
            return clientIp;
        }
        throw new ValidationException("Invalid IP address format.");
    }
}
