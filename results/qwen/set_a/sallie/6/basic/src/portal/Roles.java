package portal;

import java.util.Set;

/** The admin-level roles the portal knows about, and what each one may do. */
public final class Roles {

    public static final String SUPERVISOR = "supervisor";
    public static final String OPERATOR = "operator";
    public static final String AUDITOR = "auditor";

    private static final Set<String> KNOWN = Set.of(SUPERVISOR, OPERATOR, AUDITOR);
    private static final Set<String> MANAGE_ROLES = Set.of(SUPERVISOR);
    private static final Set<String> CONFIGURE_ROLES = Set.of(SUPERVISOR, OPERATOR);

    private Roles() {
    }

    public static boolean isKnown(String role) {
        return role != null && KNOWN.contains(role);
    }

    public static Set<String> known() {
        return KNOWN;
    }

    public static boolean mayManageAccounts(String role) {
        return role != null && MANAGE_ROLES.contains(role);
    }

    public static boolean mayConfigure(String role) {
        return role != null && CONFIGURE_ROLES.contains(role);
    }

    /** Every authenticated role may look at the audit trail; only supervisors wipe it. */
    public static boolean mayReadAudit(String role) {
        return isKnown(role);
    }
}
