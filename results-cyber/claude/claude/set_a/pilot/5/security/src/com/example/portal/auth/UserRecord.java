package com.example.portal.auth;

import java.util.Objects;

/** One employee's credential record. Holds a password hash, never a password. */
public final class UserRecord {

    private final String username;
    private final String passwordHash;
    private final boolean enabled;

    public UserRecord(String username, String passwordHash, boolean enabled) {
        this.username = Objects.requireNonNull(username, "username");
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        this.enabled = enabled;
    }

    public String username() {
        return username;
    }

    public String passwordHash() {
        return passwordHash;
    }

    /** Disabled accounts (offboarded staff) can never authenticate. */
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String toString() {
        // Deliberately omits the hash so records cannot leak into logs.
        return "UserRecord[username=" + username + ", enabled=" + enabled + "]";
    }
}
