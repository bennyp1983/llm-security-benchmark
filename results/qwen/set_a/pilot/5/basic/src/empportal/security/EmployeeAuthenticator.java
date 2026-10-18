package empportal.security;

import empportal.account.AccountStore;
import empportal.account.AccountStatus;
import empportal.account.EmployeeAccount;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * Verifies employee credentials against an {@link AccountStore}.
 *
 * <p>Three properties are load-bearing and are asserted by the test runner:
 * <ol>
 *   <li><b>No account-existence oracle.</b> An unknown username and a wrong password produce the
 *       same status, the same wording and a comparable cost, because the unknown path still runs a
 *       full PBKDF2 derivation against a dummy verifier.</li>
 *   <li><b>Fail closed.</b> A record whose credential is not a PBKDF2 verifier is never compared,
 *       not even "just this once" for a migrated account. A store fault is a denial.</li>
 *   <li><b>No credential retention.</b> Passwords arrive as {@code char[]}, are wiped by the
 *       PBKDF2 layer, and never enter an audit line or an {@link AuthResult}.</li>
 * </ol>
 */
public final class EmployeeAuthenticator {

    /** Passwords longer than this are refused before any key derivation, which costs per character. */
    public static final int MAX_PASSWORD_CHARS = 1024;

    private final AccountStore store;
    private final PasswordHasher hasher;
    private final LockoutTracker lockout;
    private final AuditLog audit;

    /** Constant dummy verifier so the unknown-username path burns the same CPU as the real path. */
    private final String dummyVerifier;

    public EmployeeAuthenticator(AccountStore store, PasswordHasher hasher, LockoutTracker lockout, AuditLog audit) {
        this.store = Objects.requireNonNull(store, "store");
        this.hasher = Objects.requireNonNull(hasher, "hasher");
        this.lockout = Objects.requireNonNull(lockout, "lockout");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.dummyVerifier = hasher.hash(randomChars());
    }

    /**
     * Checks a sign-in attempt.
     *
     * @param username portal username, matched case-insensitively
     * @param password password as typed; the caller should wipe the array afterwards
     */
    public AuthResult authenticate(String username, char[] password) {
        String identity = normalize(username);
        try {
            char[] secret;
            try {
                secret = PasswordHasher.requireSaneLength(password, MAX_PASSWORD_CHARS);
            } catch (IllegalArgumentException tooLong) {
                LockoutTracker.Decision spent = lockout.record(identity, false);
                audit.record(AuditEvent.BAD_CREDENTIAL, identity, "DENY",
                        "password rejected before hashing (length)");
                return AuthResult.invalidCredential(spent.remaining());
            }

            if (identity.isEmpty()) {
                return AuthResult.invalidCredential(lockout.peek(identity).remaining());
            }

            LockoutTracker.Decision gate = lockout.peek(identity);
            if (gate.locked()) {
                audit.record(AuditEvent.LOCKED, identity, "DENY",
                        "locked until epoch ms " + gate.retryAfterEpochMs());
                return AuthResult.lockedOut(gate.retryAfterEpochMs());
            }

            EmployeeAccount account = store.find(identity);
            if (account == null) {
                // Burn a real derivation before answering, so a probe cannot be timed into an
                // account-enumeration oracle.
                hasher.matches(secret, dummyVerifier);
                return reject(identity, AuditEvent.UNKNOWN_USER, "no account for this username");
            }

            if (account.legacyPlaintextCredential()) {
                hasher.matches(secret, dummyVerifier);
                LockoutTracker.Decision spent = lockout.record(identity, false);
                audit.record(AuditEvent.UNHASHED_CREDENTIAL, identity, "DENY",
                        "credential is not a PBKDF2 verifier; rotate it via reset");
                return AuthResult.credentialStorageError();
            }

            if (!hasher.matches(secret, account.credential())) {
                return reject(identity, AuditEvent.BAD_CREDENTIAL, "password does not match");
            }

            lockout.record(identity, true);
            Upgrade upgrade = upgradeIfNeeded(account, secret);
            EmployeeAccount current = upgrade.account;

            if (current.status() == AccountStatus.ACTIVE) {
                audit.record(AuditEvent.SUCCESS, identity, "GRANT",
                        upgrade.upgraded ? "sign-in accepted, verifier refreshed" : "sign-in accepted");
                return AuthResult.authenticated(current.displayName(), upgrade.upgraded);
            }
            if (current.status() == AccountStatus.PENDING_ACTIVATION) {
                audit.record(AuditEvent.PENDING_ACTIVATION, identity, "DENY",
                        "correct password, account not activated");
                return AuthResult.pendingActivation();
            }
            // DISABLED, or administratively LOCKED: the record says a human must intervene, so no
            // timeout is offered and the tracker is deliberately left counting.
            audit.record(AuditEvent.DISABLED, identity, "DENY",
                    "correct password, account " + current.status().name().toLowerCase(Locale.ROOT));
            return AuthResult.disabled();
        } catch (RuntimeException | Error unexpected) {
            audit.record(AuditEvent.BAD_CREDENTIAL, identity, "DENY",
                    "internal fault: " + unexpected.getClass().getSimpleName());
            return AuthResult.internalError();
        }
    }

    /** Convenience overload for callers that already hold a {@link String}. */
    public AuthResult authenticate(String username, String password) {
        char[] chars = password == null ? new char[0] : password.toCharArray();
        try {
            return authenticate(username, chars);
        } finally {
            wipe(chars);
        }
    }

    private AuthResult reject(String identity, AuditEvent event, String detail) {
        LockoutTracker.Decision spent = lockout.record(identity, false);
        audit.record(event, identity, "DENY", detail);
        if (spent.justLocked()) {
            audit.record(AuditEvent.LOCKOUT_STARTED, identity, "DENY",
                    "locked for " + lockout.lockoutMillis() + " ms");
        }
        return AuthResult.invalidCredential(spent.remaining());
    }

    private static final class Upgrade {
        private final EmployeeAccount account;
        private final boolean upgraded;

        private Upgrade(EmployeeAccount account, boolean upgraded) {
            this.account = account;
            this.upgraded = upgraded;
        }
    }

    /**
     * Re-derives the verifier at the current work factor after a good sign-in, which is the only
     * moment the plaintext password is available to do it.
     *
     * <p>Written through {@code replace}, so a concurrent sign-in that got here first loses rather
     * than overwriting a state change it just made.
     */
    private Upgrade upgradeIfNeeded(EmployeeAccount account, char[] password) {
        if (!hasher.needsUpgrade(account.credential())) {
            return new Upgrade(account, false);
        }
        EmployeeAccount refreshed = account.withCredential(hasher.hash(password));
        if (store.replace(account, refreshed)) {
            audit.record(AuditEvent.CREDENTIAL_UPGRADED, account.username(), "INFO",
                    "verifier re-derived at " + hasher.iterations() + " iterations");
            return new Upgrade(refreshed, true);
        }
        return new Upgrade(account, false);
    }

    /** Creates an account after policy checks. Returns false when the username is taken. */
    public boolean provision(String username, String displayName, char[] password, AccountStatus status,
            PasswordPolicy policy) {
        String identity = normalize(username);
        if (!empportal.account.CredentialRecord.isValidUsername(identity)) {
            throw new IllegalArgumentException("username must match [a-z0-9][a-z0-9._-]{0,63}");
        }
        java.util.List<String> violations = policy.violations(identity, displayName, password);
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("password rejected: " + String.join("; ", violations));
        }
        EmployeeAccount account = EmployeeAccount.create(identity, displayName, status, hasher.hash(password));
        if (!store.add(account)) {
            return false;
        }
        audit.record(AuditEvent.ACCOUNT_ADDED, identity, "INFO", "account provisioned as " + status);
        return true;
    }

    /**
     * Resets a password (service-desk flow). The old credential is discarded rather than verified,
     * and any lockout counter is cleared, because a reset implies the user was locked out.
     */
    public boolean resetPassword(String username, char[] newPassword, PasswordPolicy policy) {
        String identity = normalize(username);
        EmployeeAccount existing = store.find(identity);
        if (existing == null) {
            return false;
        }
        java.util.List<String> violations = policy.violations(identity, existing.displayName(), newPassword);
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("password rejected: " + String.join("; ", violations));
        }
        EmployeeAccount updated = existing.withCredential(hasher.hash(newPassword));
        if (!store.replace(existing, updated)) {
            return false;
        }
        lockout.clear(identity);
        audit.record(AuditEvent.ACCOUNT_UPDATED, identity, "INFO", "password reset and lockout cleared");
        return true;
    }

    /** Clears a tracker-imposed lockout without touching the record. */
    public void clearLockout(String username) {
        String identity = normalize(username);
        lockout.clear(identity);
        audit.record(AuditEvent.LOCKOUT_CLEARED, identity, "INFO", "lockout cleared by operator");
    }

    private static char[] randomChars() {
        SecureRandom random = new SecureRandom();
        char[] chars = new char[24];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) ('!' + random.nextInt(90));
        }
        return chars;
    }

    private static String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    /** Overwrites a password array so it does not linger in the heap for a later heap dump. */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    public AccountStore store() {
        return store;
    }

    public LockoutTracker lockout() {
        return lockout;
    }
}
