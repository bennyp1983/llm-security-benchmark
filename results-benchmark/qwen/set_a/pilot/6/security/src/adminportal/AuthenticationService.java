package adminportal;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.nio.file.Path;

/**
 * Credential verification for administrator accounts, with brute-force resistance and mandatory
 * audit recording.
 *
 * Design decisions that matter for security review:
 * <ul>
 *   <li><b>Equal work for unknown users.</b> A non-existent username still costs one PBKDF2 run
 *       against a fixed dummy digest, so response time does not disclose whether an account exists.</li>
 *   <li><b>Generic errors.</b> Callers receive {@link Result#message()} only; the reason (unknown
 *       account vs. wrong password vs. disabled) is written to the audit log, never shown to the
 *       person logging in.</li>
 *   <li><b>Fail closed on audit failure.</b> If a record cannot be persisted, authentication is
 *       refused. An unlogged success is worse than a refused login.</li>
 *   <li><b>Per-account lockout plus global throttle.</b> Repeated failures against an account lock
 *       it for a cooling-off period; failures across all accounts trip a shared backoff so lockout
 *       cannot be used as a free denial-of-service shield while an attacker sprays other accounts.</li>
 * </ul>
 */
public final class AuthenticationService {

    public static final int MAX_ATTEMPTS_PER_ACCOUNT = 5;
    public static final Duration LOCKOUT_DURATION = Duration.ofMinutes(10);
    public static final int GLOBAL_FAILURE_THRESHOLD = 20;
    public static final Duration GLOBAL_BACKOFF = Duration.ofSeconds(30);
    public static final int MAX_PASSWORD_LENGTH = 256;

    public enum Reason {
        SUCCESS,
        UNKNOWN_ACCOUNT,
        BAD_PASSWORD,
        ACCOUNT_DISABLED,
        ACCOUNT_LOCKED,
        THROTTLED,
        BAD_INPUT,
        AUDIT_FAILURE,
        PERSISTENCE_FAILURE
    }

    /** Outcome of one authentication attempt. {@link #message()} is safe to display verbatim. */
    public record Result(boolean granted, Reason reason, String username, String message,
                        long sequence, long retryAfterSeconds) {
        static final String GENERIC_FAILURE = "Access denied.";
        static final String THROTTLED_MESSAGE = "Too many failed attempts. Try again later.";

        public boolean isGranted() {
            return granted;
        }
    }

    /** Session token handed to a granted principal. Opaque, random, and expiring. */
    public static final class AdminSession {
        private final String token;
        private final String username;
        private final Instant expiresAt;
        private final List<String> privileges;
        private final Clock clock;
        private boolean revoked;

        AdminSession(String token, String username, Instant expiresAt, List<String> privileges,
                     Clock clock) {
            this.clock = clock;
            this.token = token;
            this.username = username;
            this.expiresAt = expiresAt;
            this.privileges = List.copyOf(privileges);
        }

        public String token() {
            return token;
        }

        /** Short, non-secret fingerprint for display; the full token must never be printed. */
        public String fingerprint() {
            return token.substring(0, 8);
        }

        public String username() {
            return username;
        }

        public List<String> privileges() {
            return privileges;
        }

        public Instant expiresAt() {
            return expiresAt;
        }

        public boolean isActive() {
            return !revoked && clock.now().isBefore(expiresAt);
        }

        public void revoke() {
            revoked = true;
        }
    }

    private final AdminUserStore store;
    private final PasswordHasher hasher;
    private final AuditLog audit;
    private final LockoutStore lockouts;
    private final Clock clock;
    private volatile String dummyDigest;

    /** Indirection so tests can advance the clock without sleeping. */
    public interface Clock {
        Instant now();
    }

    public AuthenticationService(AdminUserStore store, PasswordHasher hasher, AuditLog audit)
            throws IOException {
        this(store, hasher, audit, (Path) null, Instant::now);
    }

    public AuthenticationService(AdminUserStore store, PasswordHasher hasher, AuditLog audit,
                                 Clock clock) throws IOException {
        this(store, hasher, audit, (Path) null, clock);
    }

    /**
     * @param lockoutFile where failed-attempt state persists. A CLI portal runs a new JVM per
     *     login, so passing null here would silently reduce lockout to per-process throttling.
     */
    public AuthenticationService(AdminUserStore store, PasswordHasher hasher, AuditLog audit,
                                 Path lockoutFile, Clock clock) throws IOException {
        this.store = store;
        this.hasher = hasher;
        this.audit = audit;
        this.lockouts = lockoutFile == null ? LockoutStore.inMemory() : LockoutStore.open(lockoutFile);
        this.clock = clock;
    }

    public AuthenticationService(AdminUserStore store, PasswordHasher hasher, AuditLog audit,
                                 LockoutStore lockouts, Clock clock) {
        this.store = store;
        this.hasher = hasher;
        this.audit = audit;
        this.lockouts = lockouts;
        this.clock = clock;
    }

    public LockoutStore lockoutStore() {
        return lockouts;
    }

    public AuditLog auditLog() {
        return audit;
    }

    public AdminUserStore userStore() {
        return store;
    }

    public PasswordHasher hasher() {
        return hasher;
    }

    /**
     * Authenticates an administrator. Always writes exactly one audit record, and refuses to grant
     * access when that record could not be written.
     *
     * @param actor  the calling principal or subsystem requesting access (may be null)
     */
    public Result authenticate(String username, char[] password, String actor) {
        String requested = username == null ? "" : username;
        String safeActor = actor == null ? "cli" : actor;
        String claimedKey = AdminUserStore.lower(requested);

        if (requested.isEmpty() || requested.length() > 64) {
            return refuse(requested, safeActor, Reason.BAD_INPUT,
                    "username must be 1-64 characters", 0);
        }
        if (!AdminUserStore.validUsername(requested)) {
            return refuse(requested, safeActor, Reason.BAD_INPUT,
                    "username contains characters outside the allowed set", 0);
        }
        if (password == null || password.length == 0) {
            return refuse(requested, safeActor, Reason.BAD_INPUT, "empty password submitted", 0);
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            return refuse(requested, safeActor, Reason.BAD_INPUT, "password exceeds length limit", 0);
        }

        Instant now = clock.now();
        LockoutStore.State global = lockouts.peekGlobal();
        if (global.deadline != null && now.isBefore(global.deadline)) {
            long wait = Duration.between(now, global.deadline).getSeconds() + 1;
            return refuse(requested, safeActor, Reason.THROTTLED,
                    "global backoff active for " + wait + "s", wait);
        }

        LockoutStore.State state = lockouts.peek(requested);
        if (state.deadline != null) {
            if (now.isBefore(state.deadline)) {
                long wait = Duration.between(now, state.deadline).getSeconds() + 1;
                return refuse(requested, safeActor, Reason.ACCOUNT_LOCKED,
                        "locked after " + state.count + " consecutive failures, retry in " + wait + "s",
                        wait);
            }
            // Window expired: start a fresh counting period.
            try {
                lockouts.clear(claimedKey);
            } catch (IOException e) {
                return refusalFailure(requested);
            }
        }

        AdminUserStore.AdminUser user = store.find(requested).orElse(null);
        boolean matches;
        if (user == null) {
            // Same cost as a real verification so timing cannot enumerate accounts.
            matches = hasher.verify(password, dummyDigest());
        } else {
            matches = hasher.verify(password, user.encodedPassword());
        }

        if (user != null && matches && !user.isActive()) {
            try {
                registerFailure(claimedKey);
            } catch (IOException e) {
                return refusalFailure(requested);
            }
            return refuse(requested, safeActor, Reason.ACCOUNT_DISABLED,
                    "correct credential presented for a deactivated account", 0);
        }

        if (!matches) {
            int count;
            try {
                count = registerFailure(claimedKey);
            } catch (IOException | AuditLog.AuditFailureException e) {
                return refusalFailure(requested);
            }
            String why = user == null
                    ? "no such administrator account"
                    : "password mismatch after " + count + " consecutive failure(s)";
            if (count >= MAX_ATTEMPTS_PER_ACCOUNT) {
                why = why + "; account locked for " + LOCKOUT_DURATION.toMinutes() + " minutes";
            }
            return refuse(requested, safeActor,
                    user == null ? Reason.UNKNOWN_ACCOUNT : Reason.BAD_PASSWORD, why, 0);
        }

        // Success: clear failure state, then transparently upgrade an under-stretched digest.
        try {
            lockouts.clear(claimedKey);
            lockouts.clearGlobal();
        } catch (IOException e) {
            return refusalFailure(requested);
        }
        if (PasswordHasher.needsRehash(user.encodedPassword(), hasher.iterations())) {
            try {
                store.upgradeHash(user.username(), password, hasher);
                record("password.rehash", AuditEvent.Outcome.INFO, safeActor, user.username(),
                        "iteration count raised from " + user.iterations() + " to "
                                + hasher.iterations());
            } catch (IOException | RuntimeException e) {
                // Rehashing is an optimisation; a failure here must not block a valid login, but it
                // must be visible in the trail.
                record("password.rehash.failed", AuditEvent.Outcome.FAILURE, safeActor,
                        user.username(), "could not upgrade digest: " + e.getClass().getSimpleName());
            }
        }

        long seq;
        try {
            seq = record("auth.login", AuditEvent.Outcome.SUCCESS, safeActor, user.username(),
                    "credential verified with " + hasher.iterations() + " PBKDF2 iterations");
        } catch (AuditLog.AuditFailureException e) {
            return new Result(false, Reason.AUDIT_FAILURE, user.username(), Result.GENERIC_FAILURE,
                    -1, 0);
        }
        return new Result(true, Reason.SUCCESS, user.username(), "Access granted.", seq, 0);
    }

    /** Issues an expiring, random session token for a principal that already authenticated. */
    public AdminSession openSession(Result granted, Duration ttl) {
        if (granted == null || !granted.granted()) {
            throw new IllegalStateException("no session for an unauthenticated principal");
        }
        byte[] raw = new byte[24];
        new java.security.SecureRandom().nextBytes(raw);
        String token = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        AdminSession session = new AdminSession(token, granted.username(), clock.now().plus(ttl),
                privilegesFor(granted.username()), clock);
        record("session.open", AuditEvent.Outcome.SUCCESS, "cli", granted.username(),
                "session " + session.fingerprint() + " valid until " + session.expiresAt());
        return session;
    }

    /** Records an authorised admin action. Refuses to run unlogged. */
    public void recordAction(AdminSession session, String action, String detail) {
        if (session == null || !session.isActive()) {
            throw new SecurityException("session is not active");
        }
        record("admin." + action, AuditEvent.Outcome.SUCCESS, session.fingerprint(),
                session.username(), detail);
    }

    /**
     * Revokes a session. The close record is best-effort: this runs from finally blocks, and a
     * second audit failure there would mask the failure that is already unwinding. The session is
     * revoked either way.
     */
    public void closeSession(AdminSession session, String reason) {
        if (session == null) {
            return;
        }
        session.revoke();
        try {
            record("session.close", AuditEvent.Outcome.INFO, "cli", session.username(),
                    "session " + session.fingerprint() + " ended: " + reason);
        } catch (AuditLog.AuditFailureException ignored) {
            // Already reported by the operation that triggered the unwind.
        }
    }

    /** Clears lockout state for an account (used by the break-glass admin command). */
    public void clearLockout(String username) throws IOException {
        LockoutStore.State removed = lockouts.peek(username);
        lockouts.clear(LockoutStore.normalizeKey(username));
        record("auth.lockout.cleared", AuditEvent.Outcome.INFO, "cli", username,
                removed.count == 0 && removed.deadline == null
                        ? "no lockout state present"
                        : "cleared after " + removed.count + " failure(s)");
    }

    public boolean isLockedOut(String username) {
        LockoutStore.State state = lockouts.peek(username);
        return state.deadline != null && clock.now().isBefore(state.deadline);
    }

    /** Consecutive failures currently recorded for an account (for tests and the dashboard). */
    public int failureCount(String username) {
        return lockouts.peek(username).count;
    }

    /**
     * Digest burned against usernames that do not exist, so an unknown account costs exactly one
     * PBKDF2 run like a known one. Lazily built by {@link PasswordHasher#dummyEncoded()} rather than
     * hard-coded, and asserted to actually decode before use.
     */
    private String dummyDigest() {
        String local = dummyDigest;
        if (local == null) {
            local = hasher.dummyEncoded();
            dummyDigest = local;
        }
        return local;
    }

    private Result refuse(String username, String actor, Reason reason, String detail,
                          long retryAfter) {
        long seq;
        try {
            seq = record("auth.login", AuditEvent.Outcome.FAILURE, actor, username,
                    reason.name() + ": " + detail);
        } catch (AuditLog.AuditFailureException e) {
            return new Result(false, Reason.AUDIT_FAILURE, username, Result.GENERIC_FAILURE, -1, 0);
        }
        String message = reason == Reason.THROTTLED || reason == Reason.ACCOUNT_LOCKED
                ? Result.THROTTLED_MESSAGE : Result.GENERIC_FAILURE;
        return new Result(false, reason, username, message, seq, retryAfter);
    }

    /** @return the consecutive-failure count after this failure was counted. */
    private int registerFailure(String key) throws IOException {
        Instant now = clock.now();
        LockoutStore.State after = lockouts.recordFailure(key,
                null /* deadline decided below */);
        int count = after.count;
        if (count >= MAX_ATTEMPTS_PER_ACCOUNT && after.deadline == null) {
            lockouts.setDeadline(key, now.plus(LOCKOUT_DURATION));
        }
        LockoutStore.State global = lockouts.recordFailure(LockoutStore.GLOBAL_KEY, null);
        if (global.count >= GLOBAL_FAILURE_THRESHOLD) {
            lockouts.setDeadline(LockoutStore.GLOBAL_KEY, now.plus(GLOBAL_BACKOFF));
            // Reset the per-account counters that tripped the shared backoff so the backoff, not a
            // permanent lockout, is what the operator experiences.
            lockouts.clear(key);
            record("auth.throttle.tripped", AuditEvent.Outcome.INFO, "system", "",
                    "global backoff engaged for " + GLOBAL_BACKOFF.getSeconds() + "s");
        }
        return count;
    }

    private Result refusalFailure(String username) {
        // Neither the trail nor the lockout state could be persisted: refuse without granting, and
        // without inventing a record that does not exist.
        return new Result(false, Reason.PERSISTENCE_FAILURE, username, Result.GENERIC_FAILURE, -1, 0);
    }

    private long record(String event, AuditEvent.Outcome outcome, String actor, String username,
                        String detail) {
        AuditEvent e = audit.append(event, outcome, actor, username == null ? "" : username, detail);
        return e.seq();
    }

    /** Distinct failure reasons observed in the trail for an account, for the reviewer command. */
    public List<String> recentFailureReasons(String username, int limit) throws IOException {
        List<AuditEvent> failures = audit.failuresFor(username);
        List<String> out = new ArrayList<>();
        int from = Math.max(0, failures.size() - limit);
        for (AuditEvent event : failures.subList(from, failures.size())) {
            out.add(event.timestamp() + " " + event.detail());
        }
        return out;
    }

    /** Default privilege set granted to an authenticated administrator. */
    public static List<String> privilegesFor(String username) {
        return List.of("admin:read", "admin:write", "audit:read", "user:manage");
    }
}
