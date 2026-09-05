package com.example.portal.auth;

import java.util.Objects;

/** One employee's entry in the credential store. */
public final class EmployeeRecord {

    private final String username;
    private final String passwordHash;
    private final String displayName;
    private final String role;
    private final boolean active;

    public EmployeeRecord(String username, String passwordHash, String displayName,
                          String role, boolean active) {
        this.username = normalizeUsername(username);
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        this.displayName = Objects.requireNonNull(displayName, "displayName");
        this.role = Objects.requireNonNull(role, "role");
        this.active = active;
    }

    /** Usernames are matched case-insensitively and without surrounding whitespace. */
    public static String normalizeUsername(String username) {
        Objects.requireNonNull(username, "username");
        return username.trim().toLowerCase(java.util.Locale.ROOT);
    }

    public String username() {
        return username;
    }

    public String passwordHash() {
        return passwordHash;
    }

    public String displayName() {
        return displayName;
    }

    public String role() {
        return role;
    }

    /** False for employees who have left or been suspended; they can never sign in. */
    public boolean active() {
        return active;
    }

    public EmployeeRecord withPasswordHash(String newHash) {
        return new EmployeeRecord(username, newHash, displayName, role, active);
    }

    @Override
    public String toString() {
        // Deliberately omits the password hash so it cannot leak into logs.
        return "EmployeeRecord[" + username + ", role=" + role + ", active=" + active + "]";
    }
}
