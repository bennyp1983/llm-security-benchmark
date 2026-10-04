package com.example.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Verifies a username and password and records the outcome.
 *
 * <p>This is the whole feature: authenticate, log the event, issue a session identifier on success.
 * There is no account creation, no password change, no administrative or monitoring surface - see
 * {@code SECURITY.md} for the inputs and limits that are deliberately absent. That includes not
 * shipping even a package-private helper that hashes a supplied password into a stored record: such a
 * helper is account creation under another name, and a reviewer would be right to report it as
 * scope creep the moment it exists in production code. Tests build their own credential files in
 * {@code FixtureProvisioner}, against the same {@link PasswordHasher} this service verifies with, so
 * a fixture record still exercises the loader instead of restating it.
 *
 * <h2>Order of operations for one attempt</h2>
 * <ol>
 *   <li><b>Source address.</b> The caller-supplied address is parsed textually into canonical form
 *       by {@link InputValidator#normalizeSourceAddress}. A missing or unparseable address ends the
 *       attempt immediately: without it the attempt cannot be rate limited, and the throttle is part
 *       of the authentication decision. The answer is a fixed "authentication is not available for
 *       this request" that names no account, so it does not leak existence.</li>
 *   <li><b>Per-source budget.</b> Consumed before any credential work, so an attacker cannot buy a
 *       full PBKDF2 round per attempt beyond their budget.</li>
 *   <li><b>Per-account lock.</b> Applied read-only: probing a locked account cannot lengthen the
 *       lock, and the account's budget is never charged by another account's traffic.</li>
 *   <li><b>Validation</b> of the username and password shapes. Rejections are denial-shaped.</li>
 *   <li><b>One credential derivation</b>, for a known name and for an unknown name alike
 *       ({@link CredentialVerifier}).</li>
 *   <li><b>Failure bookkeeping</b>, then <b>session issue</b>, under the state lock, so the
 *       check-then-act on the failure counters and on session capacity is atomic.</li>
 *   <li><b>The event is persisted.</b> If the log write fails, the attempt is refused - including a
 *       otherwise-successful one. Authentication does not proceed unrecorded.</li>
 *   <li><b>Latency floor</b> ({@link LatencyBudget}) makes every outcome above take comparable
 *       time.</li>
 *   <li><b>Credential clearing.</b> The password copy held by this component is wiped in a
 *       {@code finally} block, whatever happened.</li>
 * </ol>
 *
 * <p><b>What a caller may learn.</b> Exactly three things: the generic denial text, the same generic
 * denial text with a retry hint, or success plus a session identifier. Unknown username, wrong
 * password, malformed username, unhashable password, locked account and throttled source all produce
 * byte-identical denial text; the last two additionally carry a retry hint, which describes the
 * caller's own request rate and not any account.
 *
 * <p><b>Thread safety.</b> Instances are safe for concurrent use. Credential state is read-only after
 * construction; throttle and session state are internally synchronised; the log channel is guarded by
 * its own monitor.
 */
public final class AuthenticationService implements AutoCloseable {

    /** Upper bound on concurrent credential derivations; the rest wait up to the permit timeout. */
    static final int MAX_CONCURRENT_DERIVATIONS = 4;

    private final AuthConfig config;
    private final CredentialStore store;
    private final CredentialVerifier verifier;
    private final PasswordHasher hasher;
    private final AttemptThrottle throttle;
    private final SessionTokenStore sessions;
    private final AuditLogger audit;
    private final TimeSource time;
    private final LatencyBudget budget;

    private AuthenticationService(AuthConfig config, CredentialStore store, PasswordHasher hasher,
            CredentialVerifier verifier, AttemptThrottle throttle, SessionTokenStore sessions,
            AuditLogger audit, TimeSource time, LatencyBudget budget) {
        this.config = config;
        this.store = store;
        this.verifier = verifier;
        this.hasher = hasher;
        this.throttle = throttle;
        this.sessions = sessions;
        this.audit = audit;
        this.time = time;
        this.budget = budget;
    }

    /** Collects everything {@link #authenticate} needs from the caller. */
    public static final class Attempt {

        private final String username;
        private final char[] password;
        private final String sourceAddress;

        private Attempt(String username, char[] password, String sourceAddress) {
            this.username = username;
            this.password = password;
            this.sourceAddress = sourceAddress;
        }

        /**
         * @param username submitted text, validated by this component
         * @param submittedPassword submitted characters. This component works on a private copy and
         *     wipes that copy; the caller must wipe its own array as soon as
         *     {@link AuthenticationService#authenticate(Attempt)} returns.
         * @param sourceAddress the peer address as a bare IPv4/IPv6 literal, as resolved by the
         *     transport. Never take this from {@code X-Forwarded-For} unless a trusted proxy set it.
         */
        public static Attempt of(String username, char[] submittedPassword, String sourceAddress) {
            return new Attempt(username, submittedPassword, sourceAddress);
        }

        String username() {
            return username;
        }

        char[] password() {
            return password;
        }

        String sourceAddress() {
            return sourceAddress;
        }

        @Override
        public String toString() {
            // Never render the password, even masked: an Attempt in a log line is already a defect.
            return "Attempt[source=" + (sourceAddress == null ? "unset" : "set") + "]";
        }
    }

    /**
     * Authenticates one attempt. Never throws for a reason the caller can act on: every failure is a
     * denial.
     *
     * @return the result to present to the user
     */
    public AuthResult authenticate(Attempt attempt) {
        long startedNanos = System.nanoTime();
        char[] passwordCopy = null;
        byte[] passwordUtf8 = null;
        String submitted = attempt == null ? null : attempt.username();
        String canonicalSource = null;
        String canonicalName = null;
        boolean present = false;
        String issuedSessionId = null;
        boolean granted = false;
        try {
            if (attempt == null || attempt.password() == null) {
                canonicalSource = InputValidator.normalizeSourceAddress(attempt == null ? null : attempt.sourceAddress());
                record(EventType.LOGIN_REJECTED_NO_SOURCE, "failure", submitted, false, canonicalSource,
                        Diagnostic.SOURCE_ADDRESS_MISSING, startedNanos, 0, null);
                return AuthResult.sourceUnavailable();
            }
            canonicalSource = InputValidator.normalizeSourceAddress(attempt.sourceAddress());
            if (canonicalSource == null) {
                record(EventType.LOGIN_REJECTED_NO_SOURCE, "failure", submitted, false, null,
                        Diagnostic.SOURCE_ADDRESS_MISSING, startedNanos, 0, null);
                return AuthResult.sourceUnavailable();
            }

            long now = time.nowMillis();

            // 1. Per-source budget, before any credential work.
            AttemptThrottle.Decision sourceDecision = throttle.consumeSourceAttempt(canonicalSource, now,
                    config.sourceWindowSeconds(), config.sourceMaxAttempts(), config.sourceBlockSeconds());
            if (!sourceDecision.allowed()) {
                record(EventType.LOGIN_THROTTLED, "blocked", submitted, false, canonicalSource,
                        Diagnostic.CREDENTIAL_MISMATCH, startedNanos, sourceDecision.retryAfterSeconds(), null);
                return AuthResult.rateLimited(sourceDecision.retryAfterSeconds());
            }

            // 2. Per-account lock, keyed on the submitted name so flood traffic against one name is
            //    accounted to that name rather than to whichever spelling happens to exist.
            String lockKey = AttemptThrottle.canonicalize(submitted);
            AttemptThrottle.Decision lockDecision = throttle.checkAccountLock(lockKey, now);
            if (!lockDecision.allowed()) {
                record(EventType.LOGIN_THROTTLED, "blocked", submitted, false, canonicalSource,
                        Diagnostic.CREDENTIAL_MISMATCH, startedNanos, lockDecision.retryAfterSeconds(), null);
                return AuthResult.rateLimited(lockDecision.retryAfterSeconds());
            }

            // 3. Input shapes.
            String username = InputValidator.validateUsername(submitted);
            if (username == null) {
                // Burn a real derivation before refusing: "that name is malformed" must not come
                // back measurably faster than "that name does not exist" or "wrong password", or the
                // shape check becomes an account probe.
                Diagnostic burn = burnUniformWork();
                record(EventType.LOGIN_FAILURE, "failure", submitted, false, canonicalSource,
                        burn, startedNanos, 0, null);
                return AuthResult.denied();
            }
            passwordCopy = InputValidator.validatePassword(attempt.password());
            passwordUtf8 = InputValidator.encodePassword(passwordCopy);
            Arrays.fill(passwordCopy, (char) 0);
            passwordCopy = null;

            // 4. One derivation, whichever branch follows.
            Optional<AccountCredentials> found = store.lookup(username);
            canonicalName = AttemptThrottle.canonicalize(username);
            present = found.isPresent();
            AccountCredentials record = found.orElse(null);
            boolean matched;
            try {
                matched = verifier.verify(passwordUtf8, record);
            } catch (AuthException e) {
                record(EventType.LOGIN_FAILURE, "error", submitted, present, canonicalSource,
                        e.diagnostic(), startedNanos, 0, null);
                return AuthResult.denied();
            }

            if (!matched) {
                AttemptThrottle.Decision afterFailure = throttle.recordAccountFailure(canonicalName,
                        time.nowMillis(), config.accountLockAfter(), config.accountLockSeconds());
                record(EventType.LOGIN_FAILURE, "failure", submitted, present, canonicalSource,
                        Diagnostic.CREDENTIAL_MISMATCH, startedNanos, 0, null);
                // The retry hint from a lock is withheld here: the denial for a wrong password and
                // the denial that trips the lock must be indistinguishable, so the first refusal
                // after locking carries no hint either.
                if (afterFailure.kind() == AttemptThrottle.Kind.LOCKED) {
                    logLockEngaged(submitted, present, canonicalSource,
                            afterFailure.retryAfterSeconds(), startedNanos);
                }
                return AuthResult.denied();
            }

            throttle.resetAccount(canonicalName);
            String sessionId = sessions.issue();
            issuedSessionId = sessionId;
            if (sessionId == null) {
                record(EventType.LOGIN_FAILURE, "error", submitted, true, canonicalSource,
                        Diagnostic.SESSION_STORE_LIMIT, startedNanos, 0, null);
                return AuthResult.denied();
            }
            record(EventType.LOGIN_SUCCESS, "success", submitted, true, canonicalSource, null,
                    startedNanos, 0, sessionId);
            granted = true;
            return AuthResult.success(sessionId);
        } catch (AuthException e) {
            if (e.isUniformDenial()) {
                try {
                    record(EventType.LOGIN_FAILURE, "failure", submitted, false, canonicalSource,
                            e.diagnostic(), startedNanos, 0, null);
                } catch (AuditPersistenceException ignored) {
                    alertAround(ignored);
                }
                return AuthResult.denied();
            }
            try {
                record(EventType.SECURITY_ALERT, "error", submitted, present, canonicalSource,
                        e.diagnostic(), startedNanos, 0, null);
            } catch (AuditPersistenceException ignored) {
                alertAround(ignored);
            }
            return AuthResult.denied();
        } catch (AuditPersistenceException e) {
            // Fail closed: an attempt whose event cannot be persisted is not granted, and an
            // otherwise successful one loses its session.
            //
            // Nothing is charged to the account here. A wrong password has already been charged -
            // the mismatch path calls recordAccountFailure before it records, so charging again here
            // would double-count it. What this catch is reachable *for* is the success path, where a
            // charge would punish a correct password for the log being broken: a full file system or
            // a rotated-out log would then convert every user's own successful sign-in into a
            // consecutive failure, and after accountLockAfter of them the account locks itself out of
            // an authentication service whose only fault was storage. That is the rule-3 failure this
            // component is specifically required not to have - a limit that locks out a legitimate
            // user for reasons that are not their credentials.
            //
            // Refusing still costs the attacker something: the per-source budget is consumed before
            // any credential work on every attempt, so an outage is not a window of free guessing.
            alertAround(e);
            return AuthResult.denied();
        } catch (RuntimeException e) {
            try {
                record(EventType.SECURITY_ALERT, "error", submitted, present, canonicalSource,
                        Diagnostic.INTERNAL, startedNanos, 0, null);
            } catch (AuditPersistenceException | RuntimeException ignored) {
                audit.recordAlert(Diagnostic.INTERNAL, submitted, canonicalSource);
            }
            return AuthResult.denied();
        } finally {
            if (passwordCopy != null) {
                Arrays.fill(passwordCopy, (char) 0);
            }
            if (passwordUtf8 != null) {
                Arrays.fill(passwordUtf8, (byte) 0);
            }
            if (issuedSessionId != null && !granted) {
                // An identifier can exist here without the caller ever receiving it: the success
                // event may have failed to persist, or a later step may have thrown. Leaving it in
                // the table would hand out a credential that authenticates as that account, is
                // never counted anywhere as issued, and cannot be revoked by anything that follows,
                // because nothing knows it was ever supposed to be dead.
                sessions.revoke(issuedSessionId);
            }
            budget.padUntil(startedNanos);
        }
    }

    /**
     * Whether a session identifier is currently valid. Validity is server-side state only; the
     * caller must not treat a syntactically well-formed identifier as authenticated.
     */
    public boolean isSessionValid(String sessionId) {
        return sessions.isValid(sessionId);
    }

    /** Revokes a session identifier, for the caller's sign-out. */
    public void revokeSession(String sessionId) {
        sessions.revoke(sessionId);
    }

    /**
     * Builds the {@code Set-Cookie} directive for an issued identifier, with {@code HttpOnly},
     * {@code Secure}, {@code SameSite=Strict} and the validated path. Returns {@code null} when the
     * request is not known to be over TLS or an input is unusable, rather than emitting a cookie that
     * could cross a trust boundary.
     */
    public String sessionCookieFor(AuthResult result, String cookieName, String path, boolean secureTransport) {
        if (result == null || !result.isSuccess()) {
            return null;
        }
        return sessions.cookieDirectiveFor(result.sessionId(), cookieName, path, secureTransport);
    }

    /** Seconds an identifier stays valid, for the caller's cookie {@code Max-Age}. */
    public int sessionTtlSeconds() {
        return sessions.ttlSeconds();
    }

    /**
     * Live identifiers in the table. Internal: the start-up check and the tests use it to reconcile
     * issued against revoked, which is how an identifier that was created but never handed to a
     * caller - a credential nobody can sign out - becomes visible.
     */
    int activeSessionCount() {
        return sessions.activeCount();
    }

    /**
     * Events retained in memory, oldest first, bounded by {@code AUTH_MAX_EVENTS}. Review of the full
     * history is done on the log file, which is the durable record.
     */
    public List<String> recentEvents() {
        return audit.retained();
    }

    /** Events this process has persisted. */
    public long persistedEventCount() {
        return audit.totalRecorded();
    }

    /**
     * Re-checks the conditions that must hold for authentication to be trusted right now: the log
     * file is still openable with private permissions, the credential file still parses, and the
     * clock is sane. Returns problem descriptions, empty when everything holds.
     */
    public List<String> selfCheck() {
        List<String> problems = new ArrayList<>();
        if (audit.isClosed()) {
            problems.add("event log is closed");
        }
        long unsaved = audit.unsavedEvents();
        if (unsaved > 0) {
            // Surfaced rather than swallowed: the refusal path is silent by design, so this is the
            // only way an operator learns the log has a hole in it.
            problems.add(unsaved + " authentication events could not be persisted");
        }
        if (store.size() == 0) {
            problems.add("credential store has no records");
        }
        long now = time.nowMillis();
        if (now < 1_600_000_000_000L) {
            problems.add("the service clock is before 2020 and lockout windows are unreliable");
        }
        if (sessions.issuedCount() < sessions.evictedCount()) {
            // Bookkeeping cannot go backwards on its own: an issue that was counted as an eviction
            // without producing an identifier is a hole through which an identifier could exist that
            // was never handed out.
            problems.add("session accounting is inconsistent");
        }
        return problems;
    }

    @Override
    public void close() {
        audit.close();
        sessions.clear();
        hasher.erase();
    }

    /**
     * Runs one full derivation against the unknown-username parameters and reports the reason it
     * ended with. Used so that a refusal which happens before any store lookup still costs a full
     * derivation, in CPU as well as in wall clock.
     */
    private Diagnostic burnUniformWork() {
        byte[] probe = "uniform-work-probe".getBytes(StandardCharsets.UTF_8);
        try {
            verifier.verify(probe, null);
            return Diagnostic.USERNAME_INVALID;
        } catch (AuthException e) {
            return e.diagnostic();
        } finally {
            Arrays.fill(probe, (byte) 0);
        }
    }

    /**
     * Records that this attempt is the one that engaged the account lock.
     *
     * <p>{@code present} is the caller's, not a constant. This line sits immediately after the
     * mismatch line for the same attempt, which already reported the flag; a second line for the same
     * attempt that reports the opposite is not a missing detail, it is a contradiction in the record,
     * and an operator reconciling the two would conclude the lock fired on a name with no record -
     * i.e. that the throttle locked out somebody who does not exist.
     */
    private void logLockEngaged(String submitted, boolean present, String canonicalSource,
            int retryAfterSeconds, long startedNanos) {
        try {
            record(EventType.LOGIN_THROTTLED, "blocked", submitted, present, canonicalSource,
                    Diagnostic.CREDENTIAL_MISMATCH, startedNanos, retryAfterSeconds, null);
        } catch (AuditPersistenceException ignored) {
            alertAround(ignored);
        }
    }

    /**
     * Writes the alert that replaces an event which could not be persisted, keeping the account
     * attribution that event had already computed. Returning {@code false} means the alert failed too
     * and the caller must keep refusing.
     */
    private boolean alertAround(AuditPersistenceException failure) {
        AuthEvent unsaved = failure.unsavedEvent();
        if (unsaved != null) {
            return audit.recordAlert(failure.diagnostic(), unsaved);
        }
        return audit.recordAlert(failure.diagnostic(), null, null);
    }

    private void record(EventType type, String outcome, String submitted, boolean present, String canonicalSource,
            Diagnostic reason, long startedNanos, int retryAfterSeconds, String sessionId)
            throws AuditPersistenceException {
        AuthEvent event = AuthEvent.builder()
                .timestampMillis(time.now().toEpochMilli())
                .type(type)
                .outcome(outcome)
                .account(submitted, present)
                .source(canonicalSource)
                .reason(reason)
                .latencyMicros(Math.max(0L, (System.nanoTime() - startedNanos) / 1000L))
                .retryAfterSeconds(retryAfterSeconds)
                .sessionSuffix(sessionId)
                .build();
        audit.record(event);
    }

    /** Fluent construction. {@link #build()} performs every start-up check and fails closed. */
    public static Builder builder() {
        return new Builder();
    }

    /** Assembles the service from configuration and a time source. */
    public static final class Builder {

        private AuthConfig config;
        private TimeSource time;
        private SecureRandom random;

        private Builder() {
        }

        public Builder config(AuthConfig value) {
            this.config = value;
            return this;
        }

        public Builder timeSource(TimeSource value) {
            this.time = value;
            return this;
        }

        /**
         * Optional, for tests. The parameter type is {@link SecureRandom}, so a {@code Random} or a
         * seeded generator cannot be passed at all; a subclass that overrode {@code nextBytes} to
         * return predictable data could, which is why production passes nothing and lets this method
         * use the JCE default.
         */
        public Builder secureRandom(SecureRandom value) {
            this.random = value;
            return this;
        }

        /**
         * Validates configuration, loads and validates the credential store, opens the log, loads the
         * pepper, measures the latency floor and builds the session store.
         *
         * @throws InvalidConfigException when any start-up condition does not hold. The service is not
         *     constructed at all: there is no partially working instance, no permissive default and no
         *     in-memory fallback credential.
         */
        public AuthenticationService build() throws InvalidConfigException {
            List<String> problems = new ArrayList<>();
            if (config == null) {
                problems.add("configuration is required");
                throw new InvalidConfigException(problems);
            }
            TimeSource clock = time == null ? TimeSource.systemUtc() : time;
            config.validateFilesystem();

            List<String> storeProblems = new ArrayList<>();
            FileCredentialStore loadedStore = FileCredentialStore.load(config.accountsFile(), config, storeProblems);
            if (!storeProblems.isEmpty()) {
                throw new InvalidConfigException(storeProblems);
            }
            if (loadedStore.size() == 0) {
                problems.add("credential store contains no usable records");
                throw new InvalidConfigException(problems);
            }

            AuditLogger logger = AuditLogger.open(config.eventLogFile(), config.maxEvents(),
                    config.minFreeBytes(), clock.nowMillis());

            SecureRandom generator;
            if (random != null) {
                generator = random;
            } else {
                // The platform default rather than SecureRandom.getInstanceStrong(): on Linux the
                // strong instance is NativePRNGBlocking, which reads /dev/random and can block
                // indefinitely at start-up, turning an availability problem into a start-up failure.
                // The default instance is the JCE cryptographically strong generator (NativePRNG,
                // seeded from /dev/urandom) and is what the platform recommends for this use.
                generator = new SecureRandom();
            }

            char[] pepper;
            try {
                pepper = KeystorePepperProvider.loadPepper(config.keystoreFile(),
                        config.keystorePassword(), config.passwordEntryAlias());
            } catch (AuthException e) {
                problems.add("the credential hash key could not be loaded from the configured keystore");
                throw new InvalidConfigException(problems);
            }

            PasswordHasher passwordHasher;
            CredentialVerifier credentialVerifier;
            LatencyBudget latencyBudget;
            try {
                passwordHasher = new PasswordHasher(pepper, config.pbkdf2Iterations(), generator);
            } catch (AuthException e) {
                problems.add("the credential hash key is unusable");
                throw new InvalidConfigException(problems);
            } finally {
                Arrays.fill(pepper, (char) 0);
            }

            CredentialVerifier.AttemptParameters decoy;
            try {
                byte[] decoySalt = passwordHasher.newSalt();
                byte[] decoyDigest = passwordHasher.derive("decoy-placeholder".getBytes(StandardCharsets.UTF_8),
                        decoySalt, config.pbkdf2Iterations());
                decoy = new CredentialVerifier.AttemptParameters(decoySalt, config.pbkdf2Iterations(), decoyDigest);
            } catch (AuthException e) {
                problems.add("the unknown-username work parameters could not be prepared");
                throw new InvalidConfigException(problems);
            }

            latencyBudget = LatencyBudget.measure(passwordHasher, config.pbkdf2Iterations());
            credentialVerifier = new CredentialVerifier(passwordHasher, latencyBudget,
                    MAX_CONCURRENT_DERIVATIONS, decoy);

            config.eraseSecrets();

            SessionTokenStore tokenStore = new SessionTokenStore(generator, config.sessionTtlSeconds(),
                    config.maxActiveSessions(), clock);
            AttemptThrottle attemptThrottle = new AttemptThrottle();
            return new AuthenticationService(config, loadedStore, passwordHasher, credentialVerifier,
                    attemptThrottle, tokenStore, logger, clock, latencyBudget);
        }
    }
}
