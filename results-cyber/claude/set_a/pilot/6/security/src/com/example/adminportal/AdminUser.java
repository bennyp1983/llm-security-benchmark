package com.example.adminportal;

import java.util.Set;

/** An administrator account record. The password hash never leaves this class. */
public final class AdminUser {

    /** Privilege levels available in the portal. */
    public enum Role {
        /** Day-to-day administration. */
        ADMIN(Set.of(Permission.VIEW_STATUS, Permission.MANAGE_ACCOUNTS)),
        /** Administration plus access to the audit trail. */
        SUPER_ADMIN(Set.of(Permission.VIEW_STATUS, Permission.MANAGE_ACCOUNTS, Permission.VIEW_AUDIT_LOG)),
        /** Read-only oversight: may review the audit trail but change nothing. */
        AUDITOR(Set.of(Permission.VIEW_STATUS, Permission.VIEW_AUDIT_LOG));

        private final Set<Permission> permissions;

        Role(Set<Permission> permissions) {
            this.permissions = permissions;
        }

        public boolean grants(Permission permission) {
            return permissions.contains(permission);
        }
    }

    /** Individual capabilities guarded by the portal. */
    public enum Permission {
        VIEW_STATUS,
        MANAGE_ACCOUNTS,
        VIEW_AUDIT_LOG
    }

    private final String username;
    private final String passwordHash;
    private final Role role;
    private final boolean enabled;

    public AdminUser(String username, String passwordHash, Role role, boolean enabled) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.enabled = enabled;
    }

    public String username() {
        return username;
    }

    public Role role() {
        return role;
    }

    public boolean enabled() {
        return enabled;
    }

    String passwordHash() {
        return passwordHash;
    }
}
