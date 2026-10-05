package com.security.auth.model;

import com.security.auth.config.SecurityConfig;
import com.security.auth.crypto.CryptoUtils;

/**
 * Encapsulates input parameters for a user registration attempt.
 * Stores sensitive password as a mutable char array and implements
 * AutoCloseable to ensure memory clearing per Rule 5.
 */
public final class RegistrationRequest implements AutoCloseable {

    private final String email;
    private final String username;
    private final char[] password;

    public RegistrationRequest(String email, String username, char[] password) {
        this.email = email;
        this.username = username;
        this.password = (password != null) ? password.clone() : null;
    }

    public String getEmail() {
        return email;
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        return password;
    }

    /**
     * Explicitly wipes sensitive password characters from memory.
     */
    public void wipe() {
        CryptoUtils.wipe(password);
    }

    @Override
    public void close() {
        wipe();
    }

    @Override
    public String toString() {
        return "RegistrationRequest{" +
                "email='" + SecurityConfig.maskIdentifier(email) + '\'' +
                ", username='" + SecurityConfig.maskIdentifier(username) + '\'' +
                ", password=[PROTECTED]" +
                '}';
    }
}
