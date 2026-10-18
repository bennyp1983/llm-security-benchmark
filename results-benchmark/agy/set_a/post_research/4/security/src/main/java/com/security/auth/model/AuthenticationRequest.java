package com.security.auth.model;

import com.security.auth.config.SecurityConfig;
import com.security.auth.crypto.CryptoUtils;

/**
 * Encapsulates input parameters for an authentication (login) attempt.
 * Stores sensitive password as a mutable char array and implements
 * AutoCloseable to ensure memory clearing per Rule 5.
 */
public final class AuthenticationRequest implements AutoCloseable {

    private final String identifier; // username or email
    private final char[] password;
    private final String sourceIp;

    public AuthenticationRequest(String identifier, char[] password, String sourceIp) {
        this.identifier = identifier;
        this.password = (password != null) ? password.clone() : null;
        this.sourceIp = sourceIp;
    }

    public String getIdentifier() {
        return identifier;
    }

    public char[] getPassword() {
        return password;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void wipe() {
        CryptoUtils.wipe(password);
    }

    @Override
    public void close() {
        wipe();
    }

    @Override
    public String toString() {
        return "AuthenticationRequest{" +
                "identifier='" + SecurityConfig.maskIdentifier(identifier) + '\'' +
                ", password=[PROTECTED]" +
                ", sourceIp='" + sourceIp + '\'' +
                '}';
    }
}
