package com.security.auth;

import java.util.Arrays;

/**
 * Encapsulates client authentication credentials across the trust boundary (Rule 1).
 * Credentials are kept in a mutable char array and explicitly zeroized after processing (Rule 5).
 * Implements AutoCloseable to enable try-with-resources zeroization.
 */
public final class AuthenticationRequest implements AutoCloseable {

    private final String rawUsername;
    private final char[] password;
    private final String clientIp;
    private boolean cleared = false;

    public AuthenticationRequest(String rawUsername, char[] password, String clientIp) {
        this.rawUsername = rawUsername;
        this.password = (password != null) ? Arrays.copyOf(password, password.length) : null;
        this.clientIp = clientIp;
    }

    public String getRawUsername() {
        return rawUsername;
    }

    public char[] getPassword() {
        if (cleared) {
            throw new IllegalStateException("Credentials have already been cleared from memory.");
        }
        return password;
    }

    public String getClientIp() {
        return clientIp;
    }

    /**
     * Overwrites credential memory with null characters to prevent sensitive data remanence (Rule 5).
     */
    public void clearCredentials() {
        if (!cleared) {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            cleared = true;
        }
    }

    @Override
    public void close() {
        clearCredentials();
    }

    @Override
    public String toString() {
        // Redact secrets in toString to prevent accidental logging (Rule 2 & Rule 5)
        return "AuthenticationRequest{username='" + (rawUsername != null ? "[SUPPLIED]" : "[NULL]") +
                "', clientIp='" + (clientIp != null ? "[SUPPLIED]" : "[NULL]") +
                "', password=[PROTECTED]}";
    }
}
