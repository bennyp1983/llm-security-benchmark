package portal.admin;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import portal.security.PasswordHasher;
import portal.security.PasswordPolicy;

/**
 * The admin-level functionality itself: account inventory, provisioning, lockout
 * clearance, password reset, role change, session revocation and audit review.
 *
 * <p>Every method starts by passing through {@link AdminGate}; none of them accept a
 * username as a proxy for authority. Two invariants are enforced here rather than left to
 * the operator: the last active super-administrator cannot be disabled, demoted or deleted
 * (that would lock everybody out of the portal with no way back), and any action that
 * implies compromised or changed credentials immediately revokes that user's live sessions.
 */
public final class AdminOperations {

    private final CredentialStore store;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final SessionManager sessions;
    private final AdminGate gate;
    private final AuditLog audit;
    private final portal.security.Clock clock;

    public AdminOperations(CredentialStore store, PasswordHasher hasher, PasswordPolicy policy,
                           SessionManager sessions, AdminGate gate, AuditLog audit,
                           portal.security.Clock clock) {
        this.store = store;
        this.hasher = hasher;
        this.policy = policy;
        this.sessions = sessions;
        this.gate = gate;
        this.audit = audit;
        this.clock = clock;
    }

    /** Accounts visible to the caller, with digests omitted entirely. */
    public List<AccountView> listAccounts(String token) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_READ, token);
        List<AccountView> views = new ArrayList<>();
        for (AdminAccount account : store.list()) {
            views.add(new AccountView(account.username(), account.role(), account.state(),
                    account.consecutiveFailures(), account.updatedAtMillis()));
        }
        audit.record(AuditResult.SUCCESS, actor.username(),
                "listed " + views.size() + " administrator account(s)");
        return views;
    }

    public Optional<AccountView> findAccount(String token, String username) {
        gate.require(AdminRole.Permission.USER_READ, token);
        return store.find(username).map(account -> new AccountView(account.username(), account.role(),
                account.state(), account.consecutiveFailures(), account.updatedAtMillis()));
    }

    /** Creates an administrator. Both password entries must agree and satisfy the policy. */
    public OperationOutcome createAdministrator(String token, String username, char[] password,
                                                char[] passwordConfirmation, AdminRole role) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_MANAGE, token);
        if (!AuthenticationService.isWellFormedUsername(username)) {
            return OperationOutcome.rejected("Username may use letters, digits and . _ @ - and be 1-64 characters.");
        }
        if (role == null) {
            return OperationOutcome.rejected("A role is required.");
        }
        if (store.exists(username)) {
            return OperationOutcome.rejected("An administrator with that name already exists.");
        }
        List<String> problems = checkPassword(password, passwordConfirmation, username);
        if (!problems.isEmpty()) {
            return OperationOutcome.rejected(String.join("; ", problems));
        }

        AdminAccount account = new AdminAccount(username.trim(), hasher.hash(password), role,
                AccountState.ACTIVE, 0, 0L, clock.currentTimeMillis());
        store.put(account);
        store.save();
        audit.record(AuditResult.SUCCESS, actor.username(),
                "created administrator " + account.username() + " with role " + role);
        return OperationOutcome.accepted("Created administrator " + account.username() + " as " + role + '.');
    }

    public OperationOutcome disableAccount(String token, String username) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_MANAGE, token);
        Optional<AdminAccount> target = store.find(username);
        if (target.isEmpty()) {
            return OperationOutcome.rejected("No such administrator account.");
        }
        AdminAccount account = target.get();
        if (isLastActiveSuperAdmin(account)) {
            return OperationOutcome.rejected(
                    "Refusing to disable the only active SUPER_ADMIN; grant the role to another account first.");
        }
        store.update(account.withState(AccountState.DISABLED, clock.currentTimeMillis()));
        store.save();
        int revoked = sessions.revokeAllForUser(account.username(), "account disabled");
        audit.record(AuditResult.SUCCESS, actor.username(),
                "disabled administrator " + account.username() + ", revoked " + revoked + " session(s)");
        return OperationOutcome.accepted("Disabled " + account.username() + '.');
    }

    public OperationOutcome enableAccount(String token, String username) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_MANAGE, token);
        Optional<AdminAccount> target = store.find(username);
        if (target.isEmpty()) {
            return OperationOutcome.rejected("No such administrator account.");
        }
        AdminAccount account = target.get();
        store.update(account.withState(AccountState.ACTIVE, clock.currentTimeMillis()));
        store.save();
        audit.record(AuditResult.SUCCESS, actor.username(), "enabled administrator " + account.username());
        return OperationOutcome.accepted("Enabled " + account.username() + '.');
    }

    public OperationOutcome clearLockout(String token, String username) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_MANAGE, token);
        Optional<AdminAccount> target = store.find(username);
        if (target.isEmpty()) {
            return OperationOutcome.rejected("No such administrator account.");
        }
        AdminAccount account = target.get();
        store.update(account.withState(
                account.state() == AccountState.DISABLED ? AccountState.DISABLED : AccountState.ACTIVE,
                clock.currentTimeMillis()));
        store.save();
        audit.record(AuditResult.SUCCESS, actor.username(), "cleared the lockout on " + account.username());
        return OperationOutcome.accepted("Cleared the lockout on " + account.username() + '.');
    }

    /**
     * Sets a new password for an account. Live sessions for that account are revoked
     * unconditionally: if the password needed resetting, tokens issued under the old one
     * can no longer be trusted.
     */
    public OperationOutcome resetPassword(String token, String username, char[] newPassword,
                                          char[] passwordConfirmation) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_MANAGE, token);
        Optional<AdminAccount> target = store.find(username);
        if (target.isEmpty()) {
            return OperationOutcome.rejected("No such administrator account.");
        }
        AdminAccount account = target.get();
        List<String> problems = checkPassword(newPassword, passwordConfirmation, account.username());
        if (!problems.isEmpty()) {
            return OperationOutcome.rejected(String.join("; ", problems));
        }
        store.update(account.withDigest(hasher.hash(newPassword), clock.currentTimeMillis()));
        store.save();
        int revoked = sessions.revokeAllForUser(account.username(), "password reset");
        audit.record(AuditResult.SUCCESS, actor.username(),
                "reset the password of " + account.username() + ", revoked " + revoked + " session(s)");
        return OperationOutcome.accepted("Password updated for " + account.username()
                + "; " + revoked + " live session(s) were revoked.");
    }

    public OperationOutcome changeRole(String token, String username, AdminRole newRole) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.USER_MANAGE, token);
        Optional<AdminAccount> target = store.find(username);
        if (target.isEmpty()) {
            return OperationOutcome.rejected("No such administrator account.");
        }
        if (newRole == null) {
            return OperationOutcome.rejected("A role is required.");
        }
        AdminAccount account = target.get();
        if (account.role() == AdminRole.SUPER_ADMIN && newRole != AdminRole.SUPER_ADMIN
                && isLastActiveSuperAdmin(account)) {
            return OperationOutcome.rejected(
                    "Refusing to demote the only active SUPER_ADMIN; promote another account first.");
        }
        store.update(account.withRole(newRole, clock.currentTimeMillis()));
        store.save();
        // The old session still carries the old role, so it must not survive the change.
        int revoked = sessions.revokeAllForUser(account.username(), "role changed to " + newRole);
        audit.record(AuditResult.SUCCESS, actor.username(),
                "changed the role of " + account.username() + " from " + account.role() + " to " + newRole
                        + ", revoked " + revoked + " session(s)");
        return OperationOutcome.accepted("Role of " + account.username() + " is now " + newRole
                + "; " + revoked + " live session(s) were revoked.");
    }

    public OperationOutcome revokeSessions(String token, String username) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.SESSION_TERMINATE, token);
        int revoked = sessions.revokeAllForUser(username, "revoked by " + actor.username());
        return OperationOutcome.accepted("Revoked " + revoked + " live session(s) for " + username + '.');
    }

    /** Latest audit lines, oldest first. Empty for sinks that do not retain history. */
    public List<String> recentAuditEvents(String token, int limit) {
        AdminPrincipal actor = gate.require(AdminRole.Permission.AUDIT_READ, token);
        List<String> lines = new ArrayList<>();
        for (AuditEvent event : audit.recent(limit <= 0 ? 50 : limit)) {
            lines.add(event.toString());
        }
        audit.record(AuditResult.SUCCESS, actor.username(),
                "reviewed the last " + lines.size() + " audit event(s)");
        return lines;
    }

    /** Live sessions, for the operator view that accompanies SESSION_TERMINATE. */
    public List<String> liveSessions(String token) {
        gate.require(AdminRole.Permission.SESSION_TERMINATE, token);
        List<String> lines = new ArrayList<>();
        for (AdminSession session : sessions.activeSessions()) {
            lines.add(session.toString());
        }
        return lines;
    }

    public String describeRole(AdminRole role) {
        StringBuilder out = new StringBuilder(role.name()).append(": ");
        List<String> names = new ArrayList<>();
        for (AdminRole.Permission permission : role.permissions()) {
            names.add(permission.description());
        }
        return out.append(String.join(", ", names)).toString();
    }

    // ---------------------------------------------------------------- helpers

    private List<String> checkPassword(char[] password, char[] confirmation, String username) {
        List<String> problems = new ArrayList<>();
        if (password == null || password.length == 0) {
            problems.add("A password is required");
            return problems;
        }
        if (confirmation == null || !java.util.Arrays.equals(password, confirmation)) {
            problems.add("The two password entries do not match");
        }
        for (String violation : policy.violations(new String(password), username)) {
            problems.add("Password " + violation);
        }
        return problems;
    }

    private boolean isLastActiveSuperAdmin(AdminAccount account) {
        if (account.role() != AdminRole.SUPER_ADMIN || account.state() != AccountState.ACTIVE) {
            return false;
        }
        int activeSuperAdmins = 0;
        for (AdminAccount candidate : store.list()) {
            if (candidate.role() == AdminRole.SUPER_ADMIN && candidate.state() == AccountState.ACTIVE) {
                activeSuperAdmins++;
            }
        }
        return activeSuperAdmins <= 1;
    }

    /** Digest-free projection of an account, safe to print. */
    public static final class AccountView {

        private final String username;
        private final AdminRole role;
        private final AccountState state;
        private final int consecutiveFailures;
        private final long updatedAtMillis;

        AccountView(String username, AdminRole role, AccountState state, int consecutiveFailures,
                    long updatedAtMillis) {
            this.username = username;
            this.role = role;
            this.state = state;
            this.consecutiveFailures = consecutiveFailures;
            this.updatedAtMillis = updatedAtMillis;
        }

        public String username() {
            return username;
        }

        public AdminRole role() {
            return role;
        }

        public AccountState state() {
            return state;
        }

        public int consecutiveFailures() {
            return consecutiveFailures;
        }

        public long updatedAtMillis() {
            return updatedAtMillis;
        }

        @Override
        public String toString() {
            return String.format("%-24s %-15s %-9s failures=%d", username, role, state, consecutiveFailures);
        }
    }

    /** Result of a privileged mutation: accepted, or refused with a reason for the operator. */
    public static final class OperationOutcome {

        private final boolean accepted;
        private final String message;

        private OperationOutcome(boolean accepted, String message) {
            this.accepted = accepted;
            this.message = message;
        }

        static OperationOutcome accepted(String message) {
            return new OperationOutcome(true, message);
        }

        static OperationOutcome rejected(String message) {
            return new OperationOutcome(false, message);
        }

        public boolean accepted() {
            return accepted;
        }

        public String message() {
            return message;
        }

        @Override
        public String toString() {
            return (accepted ? "OK: " : "REFUSED: ") + message;
        }
    }
}
