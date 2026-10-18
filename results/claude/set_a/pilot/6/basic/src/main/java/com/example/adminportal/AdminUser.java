package com.example.adminportal;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** An administrator account record as held in the credential store. */
final class AdminUser {

    private final String username;
    private final String passwordHash;
    private final Set<String> roles;
    private final boolean enabled;

    AdminUser(String username, String passwordHash, Set<String> roles, boolean enabled) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = Collections.unmodifiableSet(new LinkedHashSet<>(roles));
        this.enabled = enabled;
    }

    String username() {
        return username;
    }

    String passwordHash() {
        return passwordHash;
    }

    Set<String> roles() {
        return roles;
    }

    boolean enabled() {
        return enabled;
    }

    boolean hasRole(String role) {
        return roles.contains(role);
    }

    /** Serialised record: {@code username:hash:role|role:enabled}. */
    String toRecord() {
        return username + ":" + passwordHash + ":" + String.join("|", roles) + ":" + enabled;
    }

    static AdminUser fromRecord(String line) {
        String[] fields = line.split(":", 4);
        if (fields.length != 4) {
            throw new IllegalArgumentException("Malformed credential record");
        }
        Set<String> roles = new LinkedHashSet<>();
        for (String role : fields[2].split("\\|")) {
            if (!role.isBlank()) {
                roles.add(role.trim());
            }
        }
        return new AdminUser(fields[0], fields[1], roles, Boolean.parseBoolean(fields[3]));
    }

    @Override
    public String toString() {
        // Deliberately omits the password hash so accidental logging cannot leak it.
        return "AdminUser{" + username + ", roles=" + roles + ", enabled=" + enabled + "}";
    }
}
