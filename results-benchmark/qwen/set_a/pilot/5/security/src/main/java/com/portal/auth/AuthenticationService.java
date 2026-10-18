package com.portal.auth;

import java.util.Optional;

/**
 * Checks employee credentials against the records store and refuses repeated guessing.
 *
 * <p>The order of the checks below <em>is</em> the security design, so it is written as one straight
 * line rather than spread across helpers:
 *
 * <ol>
 *   <li>Ask the {@link LoginAttemptTracker} whether the account is currently throttled. If it is,
 *       refuse immediately <b>without hashing the candidate password</b>. Guessing therefore stops
 *       being free for the attacker the moment the threshold is hit, and the response stops carrying
 *       any information about the password.
 *   <li>Look the username up. For an unknown name, spend a full key-derivation anyway
 *       ({@link PasswordHasher#burnEquivalentWork(char[])}) and count the failure, so neither timing
 *       nor the number of attempts reveals whether the account exists.
 *   <li>Refuse non-{@link UserStatus#ACTIVE} records before comparing any password.
 *   <li>Only then verify the digest, and record the outcome either way.
 * </ol>
 *
 * <p>This class holds no plaintext password at any point beyond the caller's own array, and wipes it
 * on the way out.
 */
public final class AuthenticationService {

    private final CredentialStore store;
    private final PasswordHasher hasher;
    private final LoginAttemptTracker tracker;
    private final AuditLog audit;

    public AuthenticationService(CredentialStore store, PasswordHasher hasher,
                                 LoginAttemptTracker tracker, AuditLog audit) {
        this.store = store;
        this.hasher = hasher;
        this.tracker = tracker;
        this.audit = audit == null ? AuditLog.none() : audit;
    }

    /** Convenience for callers that already hold a String; the copy this makes is wiped. */
    public LoginResult authenticate(String username, String password) {
        char[] chars = PasswordHasher.toChars(password);
        try {
            return authenticate(username, chars);
        } finally {
            PasswordHasher.wipe(chars);
        }
    }

    /**
     * @param username as typed; surrounding whitespace is trimmed, matching how records are stored
     * @param password candidate, owned by the caller and overwritten by this method before returning
     */
    public LoginResult authenticate(String username, char[] password) {
        try {
            return check(username, password);
        } finally {
            PasswordHasher.wipe(password);
        }
    }

    private LoginResult check(String username, char[] password) {
        String name = username == null ? "" : username.trim();

        if (name.isEmpty() || password == null || password.length == 0) {
            /* Nothing can match, and counting it would let an attacker fill the tracker with
               junk keys for no benefit. Same generic wording as a wrong password. */
            audit.record(AuditEvent.of(AuditEvent.Type.LOGIN_FAILURE, name, "blank-input"));
            return new LoginResult.InvalidCredentials(name, policy().maxFailedAttempts(), false);
        }

        LoginAttemptTracker.AttemptState before = tracker.state(name);
        if (before.locked()) {
            audit.record(AuditEvent.of(AuditEvent.Type.LOGIN_REFUSED_LOCKED, name,
                    "failures=" + before.failedAttempts()));
            return new LoginResult.Locked(name, before.lockedUntil(), before.retryAfter(),
                    before.requiresAdminUnlock());
        }

        Optional<Credential> found = store.findByUsername(name);
        if (found.isEmpty()) {
            hasher.burnEquivalentWork(password);
            LoginAttemptTracker.AttemptState after = tracker.registerFailure(name);
            audit.record(AuditEvent.of(AuditEvent.Type.LOGIN_FAILURE, name,
                    "unknown-user failures=" + after.failedAttempts()));
            return describe(name, after, false);
        }

        Credential credential = found.get();
        if (credential.status() != UserStatus.ACTIVE) {
            /* Burn the same work as the active path: a disabled account should not answer faster
               than a live one. No failure is counted - there is no password left to guess. */
            hasher.burnEquivalentWork(password);
            audit.record(AuditEvent.of(AuditEvent.Type.LOGIN_REFUSED_STATUS, name,
                    "status=" + credential.status()));
            if (credential.status() == UserStatus.LOCKED) {
                return new LoginResult.Locked(name, null, null, true);
            }
            return new LoginResult.AccountUnavailable(name, credential.status());
        }

        boolean verified = hasher.verify(password, credential.passwordDigest());
        if (verified) {
            tracker.registerSuccess(name);
            audit.record(AuditEvent.of(AuditEvent.Type.LOGIN_SUCCESS, name, null));
            return new LoginResult.Authenticated(name, displayName(credential));
        }

        LoginAttemptTracker.AttemptState after = tracker.registerFailure(name);
        audit.record(AuditEvent.of(AuditEvent.Type.LOGIN_FAILURE, name,
                "failures=" + after.failedAttempts() + " of " + policy().maxFailedAttempts()));
        if (after.justLocked()) {
            audit.record(AuditEvent.of(AuditEvent.Type.ACCOUNT_LOCKED, name,
                    "after=" + after.failedAttempts() + " locksTaken=" + after.locksTaken()));
            if (after.requiresAdminUnlock()) {
                store.save(credential.withStatus(UserStatus.LOCKED));
            }
        }
        return describe(name, after, true);
    }

    /**
     * Turns post-failure tracker state into a result. The same method serves known and unknown
     * accounts, which is what keeps the two indistinguishable from outside: both report a generic
     * failure for attempts 1..n-1 and the same lockout message from attempt n onwards.
     */
    private LoginResult describe(String name, LoginAttemptTracker.AttemptState after, boolean accountExists) {
        if (after.locked()) {
            return new LoginResult.Locked(name, after.lockedUntil(), after.retryAfter(),
                    after.requiresAdminUnlock());
        }
        int remaining = Math.max(0, policy().maxFailedAttempts() - after.failedAttempts());
        return new LoginResult.InvalidCredentials(name, remaining, accountExists);
    }

    private static String displayName(Credential credential) {
        return credential.displayName() == null || credential.displayName().isBlank()
                ? credential.username()
                : credential.displayName();
    }

    private LoginPolicy policy() {
        return tracker.policy();
    }
}
