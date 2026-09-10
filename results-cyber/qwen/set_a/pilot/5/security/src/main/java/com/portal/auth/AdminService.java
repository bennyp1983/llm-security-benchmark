package com.portal.auth;

import java.time.Instant;
import java.util.Optional;

/**
 * Operator-side account management: unlocking a throttled account, disabling one, setting a new
 * password.
 *
 * <p>Every method takes the operator's identity because "who released this lockout" is the single
 * most useful fact in a brute-force incident record. Callers are expected to have already
 * authenticated and authorised the operator at the portal's admin boundary; this class does not
 * invent an authorisation model.
 */
public final class AdminService {

    private final CredentialStore store;
    private final PasswordHasher hasher;
    private final LoginAttemptTracker tracker;
    private final AuditLog audit;

    public AdminService(CredentialStore store, PasswordHasher hasher,
                        LoginAttemptTracker tracker, AuditLog audit) {
        this.store = store;
        this.hasher = hasher;
        this.tracker = tracker;
        this.audit = audit == null ? AuditLog.none() : audit;
    }

    /** Lifts a temporary lock or an admin freeze and clears the failure history. */
    public boolean unlock(String username, String operator) {
        Optional<Credential> found = store.findByUsername(username);
        if (found.isEmpty()) {
            return false;
        }
        tracker.reset(username);
        if (found.get().status() == UserStatus.LOCKED) {
            store.save(found.get().withStatus(UserStatus.ACTIVE));
        }
        audit.record(AuditEvent.of(AuditEvent.Type.ACCOUNT_UNLOCKED, username,
                "operator=" + AuditEvent.safe(operator)));
        return true;
    }

    public boolean setStatus(String username, UserStatus status, String operator) {
        Optional<Credential> found = store.findByUsername(username);
        if (found.isEmpty()) {
            return false;
        }
        store.save(found.get().withStatus(status));
        if (status == UserStatus.ACTIVE) {
            tracker.reset(username);
        }
        audit.record(AuditEvent.of(AuditEvent.Type.ACCOUNT_STATUS_CHANGED, username,
                "status=" + status + " operator=" + AuditEvent.safe(operator)));
        return true;
    }

    /**
     * Installs a new password digest and returns the account to {@link UserStatus#ACTIVE}, which is
     * the normal resolution for a lockout the employee cannot wait out.
     */
    public boolean setPassword(String username, char[] newPassword, String operator) {
        Optional<Credential> found = store.findByUsername(username);
        if (found.isEmpty() || newPassword == null || newPassword.length == 0) {
            PasswordHasher.wipe(newPassword);
            return false;
        }
        try {
            String digest = hasher.hash(newPassword);
            store.save(found.get().withPassword(digest, Instant.now()));
            tracker.reset(username);
            audit.record(AuditEvent.of(AuditEvent.Type.PASSWORD_RESET, username,
                    "operator=" + AuditEvent.safe(operator)));
            return true;
        } finally {
            PasswordHasher.wipe(newPassword);
        }
    }

    /** Registers an employee. Refuses to overwrite an existing record. */
    public boolean create(String username, String displayName, char[] password) {
        if (username == null || username.isBlank() || store.exists(username)
                || password == null || password.length == 0) {
            PasswordHasher.wipe(password);
            return false;
        }
        try {
            store.save(new Credential(username, displayName, hasher.hash(password), UserStatus.ACTIVE, Instant.now()));
            audit.record(AuditEvent.of(AuditEvent.Type.ACCOUNT_CREATED, username, null));
            return true;
        } finally {
            PasswordHasher.wipe(password);
        }
    }
}
