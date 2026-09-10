package portal.admin;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

import portal.security.PasswordHasher;

/**
 * Verifies administrator credentials and turns a successful verification into an
 * {@link AdminPrincipal}. This is the only place that is allowed to answer "yes" to a
 * login, so the controls that matter for a privileged portal live here:
 *
 * <ul>
 *   <li><b>No plaintext, ever.</b> The password is compared by re-deriving the stored
 *       digest; it is never stored, logged, returned, or written to the audit trail.</li>
 *   <li><b>No user enumeration.</b> Every non-success outcome shows the same message, and
 *       every path performs one real key derivation, so neither the response text nor the
 *       response time reveals whether a username exists.</li>
 *   <li><b>Bounded attempts.</b> Repeated failures lock an account for a fixed window and
 *       are recorded; a sliding global window additionally throttles credential stuffing
 *       across many usernames.</li>
 *   <li><b>Fail closed.</b> An unprovisioned store, a corrupt digest or a disabled account
 *       can never authenticate.</li>
 * </ul>
 */
public final class AuthenticationService {

    /** Deliberately narrow: blocks injection payloads and control bytes at the boundary. */
    private static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9._@\\-]{1,64}");

    private final CredentialStore store;
    private final PasswordHasher hasher;
    private final AuthenticationConfig config;
    private final AuditLog audit;
    private final portal.security.Clock clock;
    private final boolean persistStateChanges;

    private final Deque<Long> recentFailures = new ArrayDeque<>();
    private long lastFailureMillis;

    public AuthenticationService(CredentialStore store, PasswordHasher hasher, AuthenticationConfig config,
                                 AuditLog audit, portal.security.Clock clock) {
        this(store, hasher, config, audit, clock, true);
    }

    public AuthenticationService(CredentialStore store, PasswordHasher hasher, AuthenticationConfig config,
                                 AuditLog audit, portal.security.Clock clock, boolean persistStateChanges) {
        if (store == null || hasher == null || config == null || audit == null || clock == null) {
            throw new IllegalArgumentException("authentication service requires all collaborators");
        }
        this.store = store;
        this.hasher = hasher;
        this.config = config;
        this.audit = audit;
        this.clock = clock;
        this.persistStateChanges = persistStateChanges;
    }

    public AuthenticationConfig config() {
        return config;
    }

    public long lastFailureMillis() {
        return lastFailureMillis;
    }

    public synchronized int failuresInWindow() {
        pruneFailures(clock.currentTimeMillis());
        return recentFailures.size();
    }

    /**
     * Verifies credentials.
     *
     * @param username account name, matched case-insensitively
     * @param password caller-owned copy; this method does not retain it but the caller
     *                 should still erase it when finished
     * @return the outcome; {@link AuthResult#granted()} is true only for a real match on
     *         an active account
     */
    public synchronized AuthResult authenticate(String username, char[] password) {
        long now = clock.currentTimeMillis();

        if (!isWellFormedUsername(username) || password == null || password.length == 0) {
            // Equal work, same message: a malformed name must not be cheaper or louder
            // than a wrong password.
            hasher.spendSameWork(password);
            audit.record(AuditResult.FAILURE, username, "rejected malformed login input");
            return AuthResult.of(AuthResult.Status.INVALID_INPUT, AuthResult.GENERIC_FAILURE);
        }

        if (isThrottled(now)) {
            long wait = secondsUntil(throttleEndsAt(now), now);
            audit.record(AuditResult.WARNING, username,
                    "attempt refused, " + recentFailures.size() + " failures inside the throttle window");
            return AuthResult.retryLater(AuthResult.Status.THROTTLED,
                    "Too many recent sign-in attempts. Try again in " + wait + " seconds.", wait);
        }

        if (store.isEmpty()) {
            audit.record(AuditResult.WARNING, username, "no administrator accounts are provisioned");
            return AuthResult.of(AuthResult.Status.NOT_CONFIGURED,
                    "No administrator accounts are configured yet. Run with --bootstrap-first-admin to create one.");
        }

        String name = username.trim();
        Optional<AdminAccount> found = store.find(name);
        if (found.isEmpty()) {
            hasher.spendSameWork(password);
            registerFailure(now);
            audit.record(AuditResult.FAILURE, name, "no such administrator account");
            return AuthResult.of(AuthResult.Status.INVALID_CREDENTIALS, AuthResult.GENERIC_FAILURE);
        }

        AdminAccount account = found.get();

        if (account.state() == AccountState.DISABLED) {
            hasher.spendSameWork(password);
            audit.record(AuditResult.DENIED, name, "account is disabled");
            return AuthResult.of(AuthResult.Status.DISABLED, AuthResult.GENERIC_FAILURE);
        }

        if (account.state() == AccountState.LOCKED) {
            if (account.lockedUntilMillis() > now) {
                hasher.spendSameWork(password);
                long wait = secondsUntil(account.lockedUntilMillis(), now);
                audit.record(AuditResult.LOCKED, name, "locked for another " + wait + " seconds");
                return AuthResult.retryLater(AuthResult.Status.LOCKED, AuthResult.GENERIC_FAILURE, wait);
            }
            account = account.withState(AccountState.ACTIVE, now);
            store.update(account);
            persist();
            audit.record(AuditResult.SUCCESS, name, "temporary lock expired");
        }

        boolean matches = hasher.verify(password, account.passwordDigest());
        if (matches) {
            AdminAccount cleared = account.withSuccessfulAttempt(now);
            store.update(cleared);
            persist();
            recentFailures.clear();
            AdminPrincipal principal = new AdminPrincipal(cleared.username(), cleared.role());
            audit.record(AuditResult.SUCCESS, name, "credentials verified for role " + cleared.role());
            return AuthResult.success(principal);
        }

        int failures = account.consecutiveFailures() + 1;
        long lockedUntil = 0L;
        if (failures >= config.maxFailedAttempts()) {
            lockedUntil = now + config.lockDurationMillis();
        }
        store.update(account.withFailedAttempt(failures, lockedUntil, now));
        persist();
        registerFailure(now);

        if (lockedUntil > 0) {
            audit.record(AuditResult.LOCKED, name, "locked after " + failures + " consecutive failures");
        } else {
            audit.record(AuditResult.FAILURE, name,
                    "bad credentials (" + failures + "/" + config.maxFailedAttempts() + ")");
        }
        return AuthResult.of(AuthResult.Status.INVALID_CREDENTIALS, AuthResult.GENERIC_FAILURE);
    }

    /** Clears a temporary lock. Callers must already have performed an authorization check. */
    public synchronized AuthResult unlock(String username) {
        return store.find(username).map(account -> {
            store.update(account.withState(AccountState.ACTIVE, clock.currentTimeMillis()));
            persist();
            audit.record(AuditResult.SUCCESS, account.username(), "lock cleared by an operator");
            return AuthResult.of(AuthResult.Status.SUCCESS, "Account unlocked.");
        }).orElseGet(() -> AuthResult.of(AuthResult.Status.INVALID_CREDENTIALS,
                "No such administrator account."));
    }

    /** Removes a session-limiting side effect: forgets recorded failures (test and ops aid). */
    public synchronized void clearFailureHistory() {
        recentFailures.clear();
        lastFailureMillis = 0L;
    }

    // ---------------------------------------------------------------- internals

    private boolean isThrottled(long now) {
        pruneFailures(now);
        return recentFailures.size() >= config.globalThrottleThreshold();
    }

    private long throttleEndsAt(long now) {
        Long oldest = recentFailures.peekFirst();
        return (oldest == null ? now : oldest) + config.throttleWindowMillis();
    }

    private void registerFailure(long now) {
        lastFailureMillis = now;
        recentFailures.addLast(now);
        pruneFailures(now);
    }

    private void pruneFailures(long now) {
        long cutoff = now - config.throttleWindowMillis();
        while (!recentFailures.isEmpty() && recentFailures.peekFirst() <= cutoff) {
            recentFailures.pollFirst();
        }
    }

    private static long secondsUntil(long deadlineMillis, long nowMillis) {
        long delta = deadlineMillis - nowMillis;
        return Math.max(1L, (delta + 999L) / 1000L);
    }

    private void persist() {
        if (persistStateChanges) {
            store.save();
        }
    }

    public static boolean isWellFormedUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username.trim()).matches();
    }

    static String canonical(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
