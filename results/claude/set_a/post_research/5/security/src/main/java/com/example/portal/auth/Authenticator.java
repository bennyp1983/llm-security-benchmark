package com.example.portal.auth;

import java.util.Optional;

/**
 * Verifies employee credentials against the stored records and grants or denies access.
 *
 * <p>The sequence is fixed, and each step is there to close a specific attack:
 *
 * <ol>
 *   <li><b>Validate every input.</b> Username, password length and source identifier are checked
 *       against a whitelist before anything else happens. Invalid input is refused outright, never
 *       repaired into something acceptable.</li>
 *   <li><b>Reserve an attempt slot.</b> The per-source and per-account budgets are drawn down
 *       <em>before</em> the password is checked, atomically, so concurrent requests cannot slip past
 *       the limit together.</li>
 *   <li><b>Look up the record server-side.</b> The credential store is the only authority on whether
 *       an account exists and what its password is. No value from the caller contributes.</li>
 *   <li><b>Verify with a constant-time comparison.</b></li>
 *   <li><b>Grant only on an explicit pass.</b> Every other path -- unknown account, malformed
 *       record, restriction in force, tracking capacity exhausted, unexpected exception -- falls
 *       through to the same denial. There is no branch that reaches a grant by default.</li>
 * </ol>
 *
 * <p>Every path past input validation performs exactly one PBKDF2 derivation, real or decoy, and
 * returns the same message. An attempt against a non-existent employee therefore costs the same and
 * looks the same as an attempt against a real one, which is what stops the login form being used to
 * enumerate staff.
 *
 * <p>The caller owns the password array and must clear it; this class does not retain a reference to
 * it beyond the call.
 *
 * <p>Thread-safe: all mutable state lives in {@link AttemptLimiter} and {@link SessionManager}, both
 * of which serialise their own updates.
 */
public final class Authenticator {

    private final CredentialStore store;
    private final PasswordHasher hasher;
    private final AttemptLimiter limiter;
    private final SessionManager sessions;
    private final AuditLog audit;

    public Authenticator(CredentialStore store,
                         PasswordHasher hasher,
                         AttemptLimiter limiter,
                         SessionManager sessions,
                         AuditLog audit) {
        this.store = store;
        this.hasher = hasher;
        this.limiter = limiter;
        this.sessions = sessions;
        this.audit = audit;
    }

    /**
     * Authenticates one attempt.
     *
     * @param rawUsername username as supplied by the caller; untrusted
     * @param password    password as supplied by the caller; untrusted, not retained, not cleared
     *                    here
     * @param rawSource   identifier for where the attempt came from, as recorded by the front end;
     *                    untrusted, used only to key a rate-limit bucket
     * @return a granted result carrying a fresh session, or an indistinguishable denial
     */
    public AuthResult authenticate(String rawUsername, char[] password, String rawSource) {
        String username;
        String source;
        try {
            source = InputPolicy.requireValidSource(rawSource);
            username = InputPolicy.requireValidUsername(rawUsername);
            InputPolicy.requireSubmittablePassword(password);
        } catch (ValidationException e) {
            // Rejected before any budget is touched, so malformed input cannot be used to burn a
            // legitimate employee's attempt allowance.
            audit.warn("authentication input rejected: " + e.getMessage(),
                    "account=" + AuditLog.maskAccount(rawUsername) + " source=" + AuditLog.maskSource(rawSource));
            return AuthResult.denied();
        }

        AttemptLimiter.Reservation reservation;
        try {
            reservation = limiter.tryReserve(username, source);
        } catch (RuntimeException e) {
            // An attempt that could not be counted is refused. The alternative -- proceeding
            // uncounted -- would mean breaking the limiter is a way to get unlimited guesses.
            hasher.performDecoyWork();
            audit.warn("attempt limiter failed: " + e.getClass().getSimpleName() + ": " + e.getMessage(),
                    "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source));
            return AuthResult.denied();
        }
        if (!reservation.permitted()) {
            // Still pay the KDF cost: a restricted account must not answer faster than a live one.
            hasher.performDecoyWork();
            audit.security("authentication refused: " + reservation.decision(),
                    "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source));
            return AuthResult.denied();
        }

        try {
            Optional<PasswordHasher.StoredHash> stored = store.find(username);
            if (stored.isEmpty()) {
                hasher.performDecoyWork();
                limiter.recordFailure(reservation);
                audit.security("authentication failed: no such account",
                        "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source));
                return AuthResult.denied();
            }

            if (!hasher.verify(password, stored.get())) {
                limiter.recordFailure(reservation);
                audit.security("authentication failed: credential mismatch",
                        "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source));
                return AuthResult.denied();
            }

            SessionManager.Issued issued = sessions.create(username);
            limiter.recordSuccess(reservation);
            audit.security("authentication succeeded",
                    "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source)
                            + " session=" + issued.session().reference());
            return AuthResult.granted(issued);
        } catch (RuntimeException e) {
            // Fail closed. An exception anywhere above -- a broken crypto provider, an exhausted
            // session table -- denies access; it never falls through to a grant. The detail goes to
            // the log, and the attempt stays counted as a failure.
            limiter.recordFailure(reservation);
            audit.warn("authentication aborted: " + e.getClass().getSimpleName() + ": " + e.getMessage(),
                    "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source));
            return AuthResult.denied();
        }
    }
}
