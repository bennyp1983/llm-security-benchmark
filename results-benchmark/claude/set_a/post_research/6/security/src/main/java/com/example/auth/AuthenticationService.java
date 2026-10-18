package com.example.auth;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Processes username/password login attempts and records every attempt in the
 * application's authentication log.
 *
 * <p>Scope is authentication and authentication-event logging only: there is no
 * registration, password change, account lock-out management, enumeration of
 * sessions or users, and no administrative or reporting surface.</p>
 *
 * <h2>Decision order</h2>
 * <ol>
 *   <li>validate every input - anything that fails is rejected, never defaulted;</li>
 *   <li>consult the throttle atomically, per source and per account;</li>
 *   <li>look the account up in server-side state;</li>
 *   <li>derive and compare the key in constant time, doing equivalent work for an
 *       unknown account as for a known one;</li>
 *   <li>mint a fresh session identifier, retain the event, and only then report
 *       success. Any failure anywhere in the chain - including a failure to retain
 *       the event - denies the attempt.</li>
 * </ol>
 *
 * <p>The instance is safe for concurrent use; all mutable state lives in the
 * throttle and the session registry, which serialise their own check-then-act
 * steps.</p>
 */
public final class AuthenticationService {

    private final CredentialStore credentialStore;
    private final PasswordHasher hasher;
    private final LoginThrottle throttle;
    private final SessionRegistry sessions;
    private final AuthEventLog eventLog;
    private final Supplier<Instant> clock;

    public AuthenticationService(CredentialStore credentialStore,
                                 PasswordHasher hasher,
                                 LoginThrottle throttle,
                                 SessionRegistry sessions,
                                 AuthEventLog eventLog,
                                 Supplier<Instant> clock) {
        this.credentialStore = Objects.requireNonNull(credentialStore, "credentialStore");
        this.hasher = Objects.requireNonNull(hasher, "hasher");
        this.throttle = Objects.requireNonNull(throttle, "throttle");
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Attempts to authenticate a login.
     *
     * <p>This method takes ownership of {@code password} and zeroes it before
     * returning, on every path including exceptions. Callers must pass a
     * {@code char[]} they are willing to lose - never a {@code String}, which
     * cannot be cleared and would linger in the heap until collected.</p>
     *
     * @param username   client-supplied username
     * @param password   client-supplied password; cleared by this method
     * @param source     the remote address of the attempt, taken from the transport
     *                   layer by the caller - not from a client-settable header
     *                   unless a trusted proxy guarantees it
     * @return a success result carrying a fresh session identifier, or the single
     *         generic failure result
     */
    public AuthenticationResult authenticate(String username, char[] password, String source) {
        try {
            Optional<String> canonicalUsername = InputPolicy.canonicalUsername(username);
            Optional<String> canonicalSource = InputPolicy.canonicalSource(source);
            if (canonicalUsername.isEmpty() || canonicalSource.isEmpty()
                    || !InputPolicy.isAcceptablePassword(password)) {
                // Nothing here depends on whether the account exists, so rejecting
                // early leaks nothing - and it keeps unvalidated values out of the
                // store lookup, the throttle key space and the log.
                audit(AuthEvent.Outcome.INVALID_INPUT, canonicalUsername.orElse(null),
                        canonicalSource.orElse(null), "input rejected by policy");
                return AuthenticationResult.failure();
            }
            return attempt(canonicalUsername.get(), password, canonicalSource.get());
        } catch (RuntimeException e) {
            // Fail closed on anything unexpected, and keep the detail out of the response.
            audit(AuthEvent.Outcome.ERROR, null, null, "unexpected error: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private AuthenticationResult attempt(String user, char[] password, String source) {
        Optional<LoginThrottle.Block> block = throttle.admit(user, source);
        if (block.isPresent()) {
            // No key derivation here: doing the work would turn the throttle into
            // a CPU amplifier. The decision depends on failure counts, not on
            // whether the account exists, so it is not an existence oracle.
            audit(AuthEvent.Outcome.THROTTLED, user, source, "blocked by throttle: " + block.get().name());
            return AuthenticationResult.failure();
        }

        Optional<CredentialRecord> record;
        try {
            record = credentialStore.find(user);
        } catch (CredentialStore.CredentialStoreException | RuntimeException e) {
            audit(AuthEvent.Outcome.ERROR, user, source, "credential store unavailable: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        }

        boolean verified;
        try {
            if (record.isEmpty()) {
                // Equivalent work for an unknown account, so response time does
                // not disclose which usernames exist.
                hasher.verifyAgainstDecoy(password);
                verified = false;
            } else {
                verified = hasher.verify(password, record.get());
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            audit(AuthEvent.Outcome.ERROR, user, source, "verification failed: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        }

        if (!verified) {
            throttle.recordFailure(user, source);
            audit(record.isEmpty() ? AuthEvent.Outcome.UNKNOWN_ACCOUNT : AuthEvent.Outcome.BAD_CREDENTIALS,
                    user, source, "credentials did not match");
            return AuthenticationResult.failure();
        }

        String sessionId;
        try {
            sessionId = sessions.issue(user, source);
        } catch (RuntimeException e) {
            audit(AuthEvent.Outcome.ERROR, user, source, "session could not be issued: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        }

        try {
            recordEvent(AuthEvent.Outcome.SUCCESS, user, source, "authenticated");
        } catch (AuthEventLog.AuditException e) {
            // An authentication that cannot be recorded is not granted: drop the
            // session again and fail closed.
            sessions.invalidate(sessionId);
            return AuthenticationResult.failure();
        }
        throttle.recordSuccess(user, source);
        return AuthenticationResult.success(user, sessionId);
    }

    /**
     * Validates a client-presented session identifier against server-side state.
     *
     * <p>Shape is not proof: only a match in the registry grants anything, and a
     * missing, unknown, malformed or expired identifier yields empty.</p>
     */
    public Optional<Session> resumeSession(String presentedSessionId) {
        return sessions.validate(presentedSessionId);
    }

    /** Ends a session. Safe to call with an unknown or malformed identifier. */
    public void signOut(String presentedSessionId) {
        sessions.invalidate(presentedSessionId);
    }

    /** Records an event, swallowing audit failure on paths that already deny the attempt. */
    private void audit(AuthEvent.Outcome outcome, String user, String source, String detail) {
        try {
            recordEvent(outcome, user, source, detail);
        } catch (AuthEventLog.AuditException e) {
            // The attempt is being denied regardless, so there is no decision left
            // to fail closed on, and the detail must not reach the user.
        }
    }

    private void recordEvent(AuthEvent.Outcome outcome, String user, String source, String detail)
            throws AuthEventLog.AuditException {
        String correlationId = user == null ? "-" : eventLog.correlationId(user);
        eventLog.record(new AuthEvent(clock.get(), outcome,
                LogSanitizer.maskUsername(user), correlationId, LogSanitizer.maskSource(source), detail));
    }
}
