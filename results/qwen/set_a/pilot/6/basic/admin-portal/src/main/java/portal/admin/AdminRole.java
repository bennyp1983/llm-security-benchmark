package portal.admin;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Coarse-grained roles. Portal features check a {@link Permission}, never a role name,
 * so widening a role is a data change in one place rather than an edit at every call site.
 */
public enum AdminRole {

    SUPER_ADMIN(Permission.USER_READ, Permission.USER_MANAGE, Permission.POLICY_WRITE,
            Permission.AUDIT_READ, Permission.SESSION_TERMINATE, Permission.SYSTEM_CONFIG),

    SECURITY_ADMIN(Permission.USER_READ, Permission.USER_MANAGE, Permission.POLICY_WRITE,
            Permission.SESSION_TERMINATE),

    HELPDESK(Permission.USER_READ),

    /** Read-only: can read the audit trail but change nothing. */
    AUDITOR(Permission.AUDIT_READ);

    public static final Set<AdminRole> ALL =
            Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(values())));

    private final Set<Permission> permissions;

    AdminRole(Permission... granted) {
        this.permissions = Collections.unmodifiableSet(
                granted.length == 0 ? EnumSet.noneOf(Permission.class) : EnumSet.copyOf(Arrays.asList(granted)));
    }

    public Set<Permission> permissions() {
        return permissions;
    }

    public boolean grants(Permission permission) {
        return permissions.contains(permission);
    }

    /** Named permissions, so the console can list what a role may do. */
    public enum Permission {
        USER_READ("read administrator accounts"),
        USER_MANAGE("create, disable and reset administrator accounts"),
        POLICY_WRITE("change authentication policy"),
        AUDIT_READ("read the security audit trail"),
        SESSION_TERMINATE("revoke other administrators' sessions"),
        SYSTEM_CONFIG("change system configuration");

        private final String description;

        Permission(String description) {
            this.description = description;
        }

        public String description() {
            return description;
        }
    }
}
