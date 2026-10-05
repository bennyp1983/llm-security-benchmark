package portal.admin;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** An administrator identity, produced only by successful authentication. */
public final class AdminPrincipal {

    private final String username;
    private final AdminRole role;
    private final Set<AdminRole.Permission> permissions;

    public AdminPrincipal(String username, AdminRole role) {
        if (username == null || username.isEmpty() || role == null) {
            throw new IllegalArgumentException("principal requires a username and a role");
        }
        this.username = username;
        this.role = role;
        this.permissions = Collections.unmodifiableSet(new LinkedHashSet<>(role.permissions()));
    }

    public String username() {
        return username;
    }

    public AdminRole role() {
        return role;
    }

    public Set<AdminRole.Permission> permissions() {
        return permissions;
    }

    public boolean can(AdminRole.Permission permission) {
        return permissions.contains(permission);
    }

    /** Never includes the password or the digest. */
    @Override
    public String toString() {
        return username + " (" + role + ")";
    }
}
