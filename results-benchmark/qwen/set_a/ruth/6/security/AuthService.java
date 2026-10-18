/*
 * AuthService.java -- password authentication with a security-aware audit log.
 *
 * Java 17, JDK only (no third-party dependencies).
 *
 * Types in this file (one public type, the rest package-private collaborators):
 *
 *   AuthService                  the login service: verify credentials, apply lockout policy, audit
 *   LoginRequest / LoginResult   caller in/out values; password material is char[] and copied in
 *   PasswordHasher               PBKDF2-HMAC-SHA256 encode / verify, equal-cost verification
 *   PasswordRules                which candidate passwords may be handed to the KDF at all
 *   Username                     normalisation and syntax gate
 *   AccountRecord / AccountStatus / AccountStore / InMemoryAccountStore
 *   InMemoryFailureTracker       consecutive-failure counting and time-boxed lockout
 *   AuthAuditLogger / LoginContext / LogValue / IsoLogFormatter / StackTraceText
 *   AuthenticationDataException  a credential-store failure, which must never look like a bad password
 *   AuthenticationDemo           runnable main() -- see README.md
 *
 * Security properties this implementation is built around, each one checked by AuthServiceTest:
 *
 *   1. Plaintext passwords are never stored, never logged and never echoed. Passwords travel as
 *      char[] rather than String, are defensively copied, and the copy is zeroed when the attempt
 *      ends.
 *   2. Every attempt performs exactly one full key derivation -- known account, unknown account,
 *      disabled account, locked account, malformed username, unusable candidate password, corrupt
 *      stored record. Refusal latency therefore carries no information about whether a username is
 *      real. See the single verify() call site in login().
 *   3. A rejected subject always receives the same sentence, whatever the reason. The real reason
 *      goes to the audit log, which is an internal artifact.
 *   4. Stored credentials are salted PBKDF2-HMAC-SHA256 digests carrying a per-record iteration
 *      count, compared over fixed-length digests with MessageDigest.isEqual.
 *   5. Consecutive failures lock an account for a bounded period. The threshold crossing, the
 *      refusal of a correct password during the lockout, and any administrative unlock are logged.
 *   6. Audit records are structured key=value lines. Free-text values are escaped so that a
 *      username or a user-agent string cannot forge an extra log line or smuggle control characters
 *      into a log collector.
 */

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.text.Normalizer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Verifies user-supplied credentials against stored accounts and records the outcome in an audit
 * log that is detailed enough to reconstruct what happened.
 */
public final class AuthService {

    /**
     * The only sentence a rejected subject is ever shown. "Account locked" and "no such user" are
     * deliberately not disclosed: each one confirms that the username is real, which is precisely
     * what an enumeration attempt is looking for. The precise reason goes to the audit log instead,
     * and is available to the caller through {@link LoginResult#internalReason()} for server-side
     * counters and alerting only.
     */
    public static final String GENERIC_FAILURE_MESSAGE =
            "Authentication failed. The username and password provided could not be verified.";

    /** Shown on success. */
    public static final String SUCCESS_MESSAGE = "Authenticated.";

    private final AccountStore accounts;
    private final PasswordHasher hasher;
    private final InMemoryFailureTracker failures;
    private final AuthAuditLogger audit;
    private final Clock clock;
    private final SecureRandom ids = new SecureRandom();

    public AuthService(AccountStore accounts,
                       PasswordHasher hasher,
                       InMemoryFailureTracker failures,
                       AuthAuditLogger audit,
                       Clock clock) {
        this.accounts = Objects.requireNonNull(accounts, "accounts");
        this.hasher = Objects.requireNonNull(hasher, "hasher");
        this.failures = Objects.requireNonNull(failures, "failures");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    // --------------------------------------------------------------------------------------------
    // Login
    // --------------------------------------------------------------------------------------------

    /**
     * Verifies one set of credentials.
     *
     * <p>Control flow is deliberately linear: normalise, look up, <em>one</em> derivation, then the
     * decision cascade. No return happens before {@link PasswordHasher#verify} has run, because a
     * cheap early return is a timing oracle that tells the caller whether the username exists.
     *
     * <p>Never throws because of a wrong password. {@link AuthenticationDataException} means the
     * credential store itself is unhealthy and the attempt could not be judged at all.
     */
    public LoginResult login(LoginRequest request) {
        Objects.requireNonNull(request, "request");

        final long startedAtNanos = System.nanoTime();
        final String attemptId = newHexId(6);
        final LoginContext ctx =
                new LoginContext(attemptId, request.sourceIp(), request.sessionId(), request.userAgent());

        // Our own copy of the secret, so we can erase it without corrupting the caller's buffer.
        final char[] candidate = request.passwordCopy();
        try {
            final Username name = Username.of(request.rawUsername());
            ctx.subject(name.valueForLog(), name.stateForLog());

            final Optional<String> unusable = PasswordRules.rejectCandidate(candidate);
            final Optional<AccountRecord> account =
                    name.isValid() ? accounts.find(name.normalized()) : Optional.<AccountRecord>empty();
            ctx.account(account.orElse(null));

            // One and only one full derivation per attempt, on every path. An unknown account is
            // charged against a real digest that no login can ever match, so it costs exactly what
            // a genuine verification costs. A candidate that may not be hashed is swapped for a
            // random password that belongs to no account, inside verify().
            final String chargedDigest =
                    account.map(AccountRecord::passwordHash).orElseGet(hasher::dummyEncoded);
            final PasswordHasher.Verification verification = hasher.verify(candidate, chargedDigest);
            ctx.policy(hasher.policyLabel(verification));

            // Read the counter and the last-good login as soon as the account is identified, so
            // that EVERY line about a known account carries them -- including the refusals that
            // never reach the credential check.
            final InMemoryFailureTracker.State beforeAttempt = account
                    .map(record -> failures.state(record.accountId(), clock.instant()))
                    .orElse(null);
            account.ifPresent(record -> {
                ctx.previousSuccess(record.lastSuccessAt(), record.lastSuccessIp());
                ctx.consecutiveFailures(beforeAttempt.consecutiveFailures());
            });

            if (verification.storedRecordError() != null) {
                // A corrupt stored credential is an operator problem, not a credential problem. It
                // must not be answered with "wrong password", because the account cannot be judged
                // and silently refusing it would hide a broken import or a tampered row.
                ctx.detail("recordError", verification.storedRecordError());
                audit.credentialRecordCorrupt(ctx, elapsedMs(startedAtNanos));
                throw new AuthenticationDataException("stored credential for attempt " + attemptId
                        + " could not be parsed: " + verification.storedRecordError());
            }

            if (!name.isValid()) {
                // Its own reason, deliberately not folded into "unknown-account": whoever reads the
                // log must be able to tell a garbage or traversal-shaped username -- which is probe
                // traffic -- from a correctly spelled name that simply has no account.
                return refuse(ctx, "username-" + name.invalidReason(), startedAtNanos);
            }
            if (unusable.isPresent()) {
                return refuse(ctx, unusable.get(), startedAtNanos);
            }
            if (account.isEmpty()) {
                return refuse(ctx, "unknown-account", startedAtNanos);
            }

            final AccountRecord record = account.get();

            if (record.status() != AccountStatus.ACTIVE) {
                return refuse(ctx, "account-" + record.status().logToken(), startedAtNanos);
            }

            if (beforeAttempt.locked()) {
                ctx.lockedUntil(beforeAttempt.lockedUntil());
                return refuse(ctx, "account-locked", startedAtNanos);
            }

            if (!verification.matched()) {
                InMemoryFailureTracker.State afterFailure =
                        failures.registerFailure(record.accountId(), clock.instant());
                ctx.consecutiveFailures(afterFailure.consecutiveFailures());
                if (afterFailure.locked()) {
                    ctx.lockedUntil(afterFailure.lockedUntil());
                    // One record per attempt: the same AUTH_FAILURE line, escalated to WARNING and
                    // carrying lockedUntil, so a dashboard counts attempts and not log lines.
                    audit.accountLocked(ctx, elapsedMs(startedAtNanos));
                    return new LoginResult(LoginStatus.REJECTED, GENERIC_FAILURE_MESSAGE,
                            ctx.attemptId(), null, "password-mismatch-locking");
                }
                return refuse(ctx, "password-mismatch", startedAtNanos);
            }

            // ---- success ------------------------------------------------------------------------
            InMemoryFailureTracker.State cleared =
                    failures.registerSuccess(record.accountId(), clock.instant());
            ctx.consecutiveFailures(cleared.consecutiveFailures());
            accounts.store(record.withSuccessfulLogin(clock.instant(), request.sourceIp()));

            audit.authSuccess(ctx, elapsedMs(startedAtNanos));
            return new LoginResult(LoginStatus.AUTHENTICATED, SUCCESS_MESSAGE, attemptId,
                    record.accountId(), "authenticated");
        } finally {
            Arrays.fill(candidate, '\0');
        }
    }

    private LoginResult refuse(LoginContext ctx, String internalReason, long startedAtNanos) {
        audit.authFailure(ctx, internalReason, elapsedMs(startedAtNanos));
        // No account id on a refusal: nothing was authenticated. The investigator still gets it on
        // the audit line, where it belongs.
        return new LoginResult(LoginStatus.REJECTED, GENERIC_FAILURE_MESSAGE, ctx.attemptId(),
                null, internalReason);
    }

    private static long elapsedMs(long startedAtNanos) {
        return Math.max(0L, (System.nanoTime() - startedAtNanos) / 1_000_000L);
    }

    private String newHexId(int bytes) {
        byte[] id = new byte[bytes];
        ids.nextBytes(id);
        return HexFormat.of().formatHex(id);
    }

    // --------------------------------------------------------------------------------------------
    // Account administration -- an account's audit trail should not start at its first login
    // --------------------------------------------------------------------------------------------

    /**
     * Creates an account. This is an administrative path, so failures are reported precisely rather
     * than generically: the operator has to be able to tell "too short" from "already exists".
     */
    public AccountRecord register(String rawUsername, char[] password) {
        return register(rawUsername, password, null);
    }

    /** As above, recording the address the registration came from on the audit line. */
    public AccountRecord register(String rawUsername, char[] password, String sourceIp) {
        Objects.requireNonNull(password, "password");
        Username name = Username.of(rawUsername);
        if (!name.isValid()) {
            throw new IllegalArgumentException("invalid username: " + name.invalidReason());
        }
        PasswordRules.rejectForEnrolment(password)
                .ifPresent(reason -> { throw new IllegalArgumentException("invalid password: " + reason); });

        String encoded = hasher.encode(password);
        AccountRecord record = new AccountRecord("acct-" + newHexId(5), name.normalized(), encoded,
                AccountStatus.ACTIVE, clock.instant(), null, null);
        if (!accounts.putIfAbsent(record)) {
            throw new IllegalArgumentException("account already exists (concurrent registration)");
        }
        audit.accountCreated(record, hasher.policyLabelOf(encoded), sourceIp, clock.instant());
        return record;
    }

    /** Changes an account's status, audited. */
    public void setStatus(String rawUsername, AccountStatus status, String operator) {
        AccountRecord record = requireAccount(rawUsername);
        accounts.store(record.withStatus(status));
        if (status != AccountStatus.ACTIVE) {
            failures.clear(record.accountId());
        }
        audit.accountStatusChanged(record.accountId(), record.status(), status,
                LogValue.escape(operator, 64), clock.instant());
    }

    /** Administrative unlock, audited: it is the event that explains a sudden drop in failures. */
    public void unlock(String rawUsername, String operator) {
        AccountRecord record = requireAccount(rawUsername);
        InMemoryFailureTracker.State before = failures.state(record.accountId(), clock.instant());
        failures.clear(record.accountId());
        audit.accountUnlocked(record.accountId(), LogValue.escape(operator, 64), before, clock.instant());
    }

    private AccountRecord requireAccount(String rawUsername) {
        Username name = Username.of(rawUsername);
        return name.isValid()
                ? accounts.find(name.normalized()).orElseThrow(() -> new IllegalArgumentException("no such account"))
                : throwNoSuchAccount();
    }

    private static AccountRecord throwNoSuchAccount() {
        throw new IllegalArgumentException("no such account");
    }

    // ============================================================================================
    // Request / result
    // ============================================================================================

    /** One authentication attempt as presented by the caller. Immutable. */
    public static final class LoginRequest {

        private final String rawUsername;
        private final char[] password;
        private final String sourceIp;
        private final String sessionId;
        private final String userAgent;

        /** Preferred form: the caller keeps a char[] it can erase, and copies the one we store. */
        public LoginRequest(String rawUsername, char[] password, String sourceIp,
                            String sessionId, String userAgent) {
            this.rawUsername = rawUsername;
            this.password = password == null ? new char[0] : password.clone();
            this.sourceIp = sourceIp;
            this.sessionId = sessionId;
            this.userAgent = userAgent;
        }

        /** Convenience overload. A String password cannot be erased from the heap; prefer char[]. */
        public LoginRequest(String rawUsername, String password, String sourceIp,
                            String sessionId, String userAgent) {
            this(rawUsername, password == null ? new char[0] : password.toCharArray(),
                    sourceIp, sessionId, userAgent);
        }

        public String rawUsername() {
            return rawUsername;
        }

        /** A fresh copy of the secret; the caller should erase it as soon as it is done with it. */
        public char[] passwordCopy() {
            return password.clone();
        }

        /**
         * Zeroes the credential this request retained, so the secret does not have to wait for the
         * garbage collector. After this the request can no longer authenticate -- it reports an
         * absent credential rather than silently presenting whatever is left in memory.
         */
        public void destroy() {
            Arrays.fill(password, '\0');
        }

        public String sourceIp() {
            return sourceIp;
        }

        public String sessionId() {
            return sessionId;
        }

        public String userAgent() {
            return userAgent;
        }

        @Override
        public String toString() {
            return "LoginRequest[username=" + rawUsername + ", credential=<redacted>]";
        }
    }

    /** Login status, safe to branch on internally. */
    public enum LoginStatus {
        /** Credentials verified; a session may now be issued. */
        AUTHENTICATED,
        /** Credentials not verified. {@link LoginResult#message()} is the only public detail. */
        REJECTED
    }

    /** Outcome of one authentication attempt. */
    public static final class LoginResult {

        private final LoginStatus status;
        private final String message;
        private final String attemptId;
        private final String accountId;
        private final String internalReason;

        LoginResult(LoginStatus status, String message, String attemptId,
                    String accountId, String internalReason) {
            this.status = status;
            this.message = message;
            this.attemptId = attemptId;
            this.accountId = accountId;
            this.internalReason = internalReason;
        }

        public boolean authenticated() {
            return status == LoginStatus.AUTHENTICATED;
        }

        public LoginStatus status() {
            return status;
        }

        /** Sentence for the subject: identical for every refusal reason. */
        public String message() {
            return message;
        }

        /** Correlation id; the same value appears as {@code attempt=} on the audit line. */
        public String attemptId() {
            return attemptId;
        }

        /** Authenticated account id, or {@code null} when nothing was authenticated. */
        public String accountId() {
            return accountId;
        }

        /**
         * Machine-readable reason, for server-side metrics and alerting.
         *
         * <p>Must never be rendered to the subject: it distinguishes an unknown account from a
         * wrong password, which is the enumeration signal the public sentence exists to hide.
         */
        public String internalReason() {
            return internalReason;
        }

        @Override
        public String toString() {
            return "LoginResult[" + status + ", attempt=" + attemptId + "]";
        }
    }

    // ============================================================================================
    // Password hashing
    // ============================================================================================

    /**
     * Salted PBKDF2-HMAC-SHA256, encoded as
     * {@code pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>}.
     *
     * <p>The iteration count is stored per record so it can be raised later without a flag day:
     * existing records keep verifying at their own cost while new registrations use the new cost.
     */
    public static final class PasswordHasher {

        static final String KDF = "PBKDF2WithHmacSHA256";
        static final String PREFIX = "pbkdf2-sha256";
        static final int SALT_BYTES = 16;
        static final int DIGEST_BYTES = 32;
        static final int DEFAULT_ITERATIONS = 310_000;
        static final int MIN_ITERATIONS = 1_000;
        static final int MAX_ITERATIONS = 20_000_000;

        private final SecureRandom random = new SecureRandom();
        private final int iterations;
        private final char[] dummyPassword;
        private final String dummyEncoded;
        private final byte[] dummySalt;

        public PasswordHasher() {
            this(DEFAULT_ITERATIONS);
        }

        public PasswordHasher(int iterations) {
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException(
                        "iterations must be in [" + MIN_ITERATIONS + ", " + MAX_ITERATIONS + "]");
            }
            this.iterations = iterations;

            // The digest charged for unknown accounts has to be the product of a real derivation
            // over a password no account can hold. A hand-written constant is the classic failure
            // mode: if it does not parse, verify() takes the corrupt-record branch and the
            // unknown-account path becomes free -- the very leak the constant was meant to close,
            // with no functional test able to notice. So derive it, then assert it parses.
            this.dummyPassword = randomChars(24);
            this.dummyEncoded = deriveEncoded(this.dummyPassword, newSalt(), iterations);
            StoredDigest parsed = StoredDigest.parse(this.dummyEncoded);
            if (parsed == null) {
                throw new IllegalStateException("internal error: generated dummy digest does not parse");
            }
            this.dummySalt = parsed.salt;
        }

        /** Real digest belonging to no account; charged for unknown accounts. */
        public String dummyEncoded() {
            return dummyEncoded;
        }

        /**
         * Hashes and encodes. The strength floor is deliberately NOT enforced here: it belongs to
         * the enrolment flow ({@link #register}), so that a migration or cost-raise rehash can still
         * encode a credential that an existing account legitimately holds.
         */
        public String encode(char[] password) {
            Objects.requireNonNull(password, "password");
            PasswordRules.rejectCandidate(password).ifPresent(reason -> {
                throw new IllegalArgumentException("cannot store this password: " + reason);
            });
            return deriveEncoded(password, newSalt(), iterations);
        }

        /**
         * Derives once and compares. Always costs one full derivation, whatever the state of the
         * inputs: an unparsable stored digest is charged against the dummy parameters, and a
         * candidate that may not be hashed is replaced by {@code dummyPassword}.
         */
        public Verification verify(char[] candidate, String storedDigest) {
            StoredDigest stored = StoredDigest.parse(storedDigest);
            boolean candidateUsable = PasswordRules.rejectCandidate(candidate).isEmpty();

            char[] effective = candidateUsable ? candidate : dummyPassword;
            byte[] salt = stored != null ? stored.salt : dummySalt;
            int rounds = stored != null ? stored.iterations : iterations;

            byte[] derived = derive(effective, salt, rounds);
            try {
                // Both operands are always DIGEST_BYTES long, so the comparison leaks nothing about
                // the stored value beyond "equal" or "not equal".
                boolean matched = candidateUsable && stored != null
                        && MessageDigest.isEqual(stored.digest, derived);
                String error = stored != null ? null : StoredDigest.lastParseError();
                return new Verification(matched, error, rounds);
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
        }

        public String policyLabel(Verification verification) {
            return PREFIX + "$" + verification.iterationsUsed();
        }

        public String policyLabelOf(String encodedDigest) {
            StoredDigest parsed = StoredDigest.parse(encodedDigest);
            return PREFIX + "$" + (parsed == null ? -1 : parsed.iterations);
        }

        private byte[] newSalt() {
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            return salt;
        }

        private String deriveEncoded(char[] password, byte[] salt, int rounds) {
            byte[] digest = derive(password, salt, rounds);
            try {
                return PREFIX + "$" + rounds
                        + "$" + Base64.getEncoder().encodeToString(salt)
                        + "$" + Base64.getEncoder().encodeToString(digest);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
        }

        private char[] randomChars(int count) {
            final String alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#*+-";
            char[] out = new char[count];
            for (int i = 0; i < count; i++) {
                out[i] = alphabet.charAt(random.nextInt(alphabet.length()));
            }
            return out;
        }

        private static byte[] derive(char[] password, byte[] salt, int rounds) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, rounds, DIGEST_BYTES * 8);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new AuthenticationDataException("password hashing unavailable (" + KDF + ")", e);
            } finally {
                spec.clearPassword();
            }
        }

        /** Result of one verification. */
        public static final class Verification {

            private final boolean matched;
            private final String storedRecordError;
            private final int iterationsUsed;

            Verification(boolean matched, String storedRecordError, int iterationsUsed) {
                this.matched = matched;
                this.storedRecordError = storedRecordError;
                this.iterationsUsed = iterationsUsed;
            }

            public boolean matched() {
                return matched;
            }

            /** {@code null} when the stored record was well formed, otherwise a short code. */
            public String storedRecordError() {
                return storedRecordError;
            }

            public int iterationsUsed() {
                return iterationsUsed;
            }
        }
    }

    /**
     * Which candidate passwords may be handed to the KDF at all.
     *
     * <p>The trailing-NUL and unpaired-surrogate rules are not tidiness. {@code PBEKeySpec} converts
     * the char[] with a UTF-8 encoder that is not injective over the whole char[] domain: it drops
     * trailing NULs and maps every unpaired surrogate to '?'. Without these rules "correcthorse"
     * and "correcthorse\0" produce the same digest, so whoever registered one could be logged in by
     * anyone presenting the other. Rejecting is the right response; trimming would silently change
     * the secret the user actually typed.
     */
    static final class PasswordRules {

        static final int MIN_ENROLMENT_CHARS = 12;
        static final int MAX_CHARS = 1024;

        private PasswordRules() {
        }

        /** Rules that apply to any submitted candidate, at login as well as at enrolment. */
        static Optional<String> rejectCandidate(char[] candidate) {
            if (candidate == null || candidate.length == 0) {
                return Optional.of("no-password-submitted");
            }
            if (candidate.length > MAX_CHARS) {
                return Optional.of("password-too-long");
            }
            if (candidate[candidate.length - 1] == '\0') {
                return Optional.of("password-ends-in-nul");
            }
            for (int i = 0; i < candidate.length; i++) {
                char c = candidate[i];
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 < candidate.length && Character.isLowSurrogate(candidate[i + 1])) {
                        i++;
                    } else {
                        return Optional.of("password-has-unpaired-surrogate");
                    }
                } else if (Character.isLowSurrogate(c)) {
                    return Optional.of("password-has-unpaired-surrogate");
                }
            }
            return Optional.empty();
        }

        /**
         * Adds the strength floor, which is an enrolment rule only. A legacy account may legitimately
         * hold a shorter password, and refusing to hash it at login would turn policy into an
         * enumeration channel.
         */
        static Optional<String> rejectForEnrolment(char[] password) {
            Optional<String> base = rejectCandidate(password);
            if (base.isPresent()) {
                return base;
            }
            if (password.length < MIN_ENROLMENT_CHARS) {
                return Optional.of("password-shorter-than-" + MIN_ENROLMENT_CHARS + "-characters");
            }
            return Optional.empty();
        }
    }

    /**
     * Parsed {@code pbkdf2-sha256$...} record. Parsing is strict and reports a short code only --
     * never an echo of the offending value, because the caller writes the code into the log.
     */
    public static final class StoredDigest {

        private static final Base64.Decoder STRICT_BASE64 = Base64.getDecoder();
        private static final ThreadLocal<String> LAST_PARSE_ERROR = new ThreadLocal<>();

        final int iterations;
        final byte[] salt;
        final byte[] digest;

        private StoredDigest(int iterations, byte[] salt, byte[] digest) {
            this.iterations = iterations;
            this.salt = salt;
            this.digest = digest;
        }

        public static String lastParseError() {
            String error = LAST_PARSE_ERROR.get();
            return error == null ? "unparsable-record" : error;
        }

        public static StoredDigest parse(String encoded) {
            if (encoded == null) {
                return fail("absent-record");
            }
            String[] parts = encoded.split("\\$", -1);
            if (parts.length != 4) {
                return fail("wrong-field-count-" + parts.length);
            }
            if (!PasswordHasher.PREFIX.equals(parts[0])) {
                return fail("unknown-kdf");
            }
            int rounds;
            try {
                rounds = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                return fail("non-numeric-iterations");
            }
            if (rounds < PasswordHasher.MIN_ITERATIONS || rounds > PasswordHasher.MAX_ITERATIONS) {
                return fail("iterations-out-of-range");
            }
            byte[] salt;
            byte[] digest;
            try {
                salt = STRICT_BASE64.decode(parts[2]);
                digest = STRICT_BASE64.decode(parts[3]);
            } catch (IllegalArgumentException e) {
                return fail("non-base64-material");
            }
            if (salt.length < 8 || salt.length > 128) {
                return fail("salt-length-" + salt.length);
            }
            if (digest.length != PasswordHasher.DIGEST_BYTES) {
                return fail("digest-length-" + digest.length);
            }
            LAST_PARSE_ERROR.remove();
            return new StoredDigest(rounds, salt, digest);
        }

        private static StoredDigest fail(String code) {
            LAST_PARSE_ERROR.set(code);
            return null;
        }
    }

    // ============================================================================================
    // Usernames
    // ============================================================================================

    /**
     * Normalisation and syntax gate.
     *
     * <p>NFKC before lowercasing, so compatibility variants of one name (full-width letters and the
     * like) cannot become two different accounts; {@code Locale.ROOT}, so the result does not depend
     * on the server locale (the Turkish-I case-folding bug); and an explicit allow-list, so control
     * characters, spaces and separators never reach the log or a store key.
     */
    static final class Username {

        private static final Pattern ALLOWED = Pattern.compile("[a-z0-9._+\\-]{1,64}");
        private static final int MAX_INPUT_CHARS = 256;

        private final String normalized;
        private final String invalidReason;
        private final String rawForLog;

        private Username(String normalized, String invalidReason, String rawForLog) {
            this.normalized = normalized;
            this.invalidReason = invalidReason;
            this.rawForLog = rawForLog;
        }

        static Username of(String raw) {
            if (raw == null) {
                return new Username(null, "absent", null);
            }
            String stripped = raw.strip();
            if (stripped.isEmpty()) {
                return new Username(null, "empty", raw);
            }
            if (stripped.length() > MAX_INPUT_CHARS) {
                return new Username(null, "longer-than-" + MAX_INPUT_CHARS + "-characters", raw);
            }
            if (hasUnpairedSurrogate(stripped)) {
                return new Username(null, "malformed-unicode", raw);
            }
            String normalized = Normalizer.normalize(stripped, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
            if (!ALLOWED.matcher(normalized).matches()) {
                return new Username(null, "unsupported-characters", raw);
            }
            return new Username(normalized, null, null);
        }

        private static boolean hasUnpairedSurrogate(String s) {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                        i++;
                    } else {
                        return true;
                    }
                } else if (Character.isLowSurrogate(c)) {
                    return true;
                }
            }
            return false;
        }

        boolean isValid() {
            return normalized != null;
        }

        String normalized() {
            return normalized;
        }

        String invalidReason() {
            return invalidReason;
        }

        /** Normalised name when valid; otherwise the raw input, escaped by the log layer. */
        String valueForLog() {
            return isValid() ? normalized : rawForLog;
        }

        String stateForLog() {
            return isValid() ? "resolved" : "malformed(" + invalidReason + ")";
        }
    }

    // ============================================================================================
    // Accounts
    // ============================================================================================

    public enum AccountStatus {
        ACTIVE,
        DISABLED,
        LOCKED_BY_ADMIN;

        public String logToken() {
            return name().toLowerCase(Locale.ROOT).replace('_', '-');
        }
    }

    /** Immutable stored account. {@link #toString()} never exposes the credential. */
    public static final class AccountRecord {

        private final String accountId;
        private final String username;
        private final String passwordHash;
        private final AccountStatus status;
        private final Instant createdAt;
        private final Instant lastSuccessAt;
        private final String lastSuccessIp;

        public AccountRecord(String accountId, String username, String passwordHash, AccountStatus status,
                      Instant createdAt, Instant lastSuccessAt, String lastSuccessIp) {
            this.accountId = Objects.requireNonNull(accountId, "accountId");
            this.username = Objects.requireNonNull(username, "username");
            this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
            this.status = Objects.requireNonNull(status, "status");
            this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
            this.lastSuccessAt = lastSuccessAt;
            this.lastSuccessIp = lastSuccessIp;
        }

        public String accountId() {
            return accountId;
        }

        public String username() {
            return username;
        }

        public String passwordHash() {
            return passwordHash;
        }

        public AccountStatus status() {
            return status;
        }

        public Instant createdAt() {
            return createdAt;
        }

        public Instant lastSuccessAt() {
            return lastSuccessAt;
        }

        public String lastSuccessIp() {
            return lastSuccessIp;
        }

        public AccountRecord withSuccessfulLogin(Instant when, String ip) {
            return new AccountRecord(accountId, username, passwordHash, status, createdAt, when, ip);
        }

        public AccountRecord withStatus(AccountStatus newStatus) {
            return new AccountRecord(accountId, username, passwordHash, newStatus, createdAt,
                    lastSuccessAt, lastSuccessIp);
        }

        @Override
        public String toString() {
            return "AccountRecord[" + accountId + ", " + username + ", " + status + ", credential=<redacted>]";
        }
    }

    /** Where accounts live. In memory here; a real deployment swaps in a JDBC or directory store. */
    public interface AccountStore {

        Optional<AccountRecord> find(String normalisedUsername);

        boolean exists(String normalisedUsername);

        /** Insert only. Returns false if the username is taken. */
        boolean putIfAbsent(AccountRecord account);

        /** Unconditional replace; used to record successful-login context and status changes. */
        void store(AccountRecord account);

        /**
         * The record exactly as stored, or {@code null}. Reads are needed by anything that has to
         * replace a credential (a rehash on a cost change, a password reset) without racing another
         * writer into oblivion.
         */
        AccountRecord recordFor(String normalisedUsername);
    }

    /** Process-local store, adequate for the demo and the tests. */
    public static final class InMemoryAccountStore implements AccountStore {

        private final Map<String, AccountRecord> byUsername = new ConcurrentHashMap<>();

        @Override
        public Optional<AccountRecord> find(String normalisedUsername) {
            return Optional.ofNullable(byUsername.get(normalisedUsername));
        }

        @Override
        public boolean exists(String normalisedUsername) {
            return byUsername.containsKey(normalisedUsername);
        }

        @Override
        public boolean putIfAbsent(AccountRecord account) {
            return byUsername.putIfAbsent(account.username(), account) == null;
        }

        @Override
        public void store(AccountRecord account) {
            byUsername.put(account.username(), account);
        }

        @Override
        public AccountRecord recordFor(String normalisedUsername) {
            return byUsername.get(normalisedUsername);
        }

        @Override
        public String toString() {
            return "InMemoryAccountStore" + byUsername.keySet();
        }
    }

    // ============================================================================================
    // Lockout
    // ============================================================================================

    /**
     * Counts consecutive failures per account id and applies a time-boxed lockout.
     *
     * <p>Keyed by account id rather than username, so no spelling variant can split the counter.
     * The count is never reset by another failure -- only by a success, an administrative unlock, or
     * the lockout expiring.
     */
    public static final class InMemoryFailureTracker {

        private static final class Entry {
            int consecutiveFailures;
            Instant lockedUntil;
        }

        /** Immutable view of counter state. */
        public static final class State {

            private final int consecutiveFailures;
            private final Instant lockedUntil;
            private final boolean expiredLockWasCleared;

            State(int consecutiveFailures, Instant lockedUntil, boolean expiredLockWasCleared) {
                this.consecutiveFailures = consecutiveFailures;
                this.lockedUntil = lockedUntil;
                this.expiredLockWasCleared = expiredLockWasCleared;
            }

            public int consecutiveFailures() {
                return consecutiveFailures;
            }

            /** When the lockout ends, or {@code null} when the account is not locked. */
            public Instant lockedUntil() {
                return lockedUntil;
            }

            public boolean locked() {
                return lockedUntil != null;
            }

            /** True when this read cleared a lockout that had already expired. */
            public boolean expiredLockWasCleared() {
                return expiredLockWasCleared;
            }
        }

        private final Map<String, Entry> byAccountId = new ConcurrentHashMap<>();
        private final int maxConsecutiveFailures;
        private final Duration lockout;

        public InMemoryFailureTracker(int maxConsecutiveFailures, Duration lockout) {
            if (maxConsecutiveFailures < 1) {
                throw new IllegalArgumentException("maxConsecutiveFailures must be >= 1");
            }
            if (lockout == null || lockout.isNegative() || lockout.isZero()) {
                throw new IllegalArgumentException("lockout must be a positive duration");
            }
            this.maxConsecutiveFailures = maxConsecutiveFailures;
            this.lockout = lockout;
        }

        public int maxConsecutiveFailures() {
            return maxConsecutiveFailures;
        }

        public Duration lockout() {
            return lockout;
        }

        /**
         * Current state. Reading may clear an expired lockout, which is why the caller supplies the
         * instant instead of caching the result.
         */
        public synchronized State state(String accountId, Instant now) {
            Entry entry = byAccountId.get(accountId);
            if (entry == null) {
                return new State(0, null, false);
            }
            if (entry.lockedUntil != null && !entry.lockedUntil.isAfter(now)) {
                byAccountId.remove(accountId);
                return new State(0, null, true);
            }
            return new State(entry.consecutiveFailures, entry.lockedUntil, false);
        }

        public synchronized State registerFailure(String accountId, Instant now) {
            Entry entry = byAccountId.computeIfAbsent(accountId, key -> new Entry());
            if (entry.lockedUntil != null && !entry.lockedUntil.isAfter(now)) {
                entry.consecutiveFailures = 0;
                entry.lockedUntil = null;
            }
            entry.consecutiveFailures++;
            if (entry.lockedUntil == null && entry.consecutiveFailures >= maxConsecutiveFailures) {
                entry.lockedUntil = now.plus(lockout);
            }
            return new State(entry.consecutiveFailures, entry.lockedUntil, false);
        }

        public synchronized State registerSuccess(String accountId, Instant now) {
            byAccountId.remove(accountId);
            return new State(0, null, false);
        }

        public synchronized State clear(String accountId) {
            Entry removed = byAccountId.remove(accountId);
            return removed == null
                    ? new State(0, null, false)
                    : new State(removed.consecutiveFailures, removed.lockedUntil, false);
        }
    }

    // ============================================================================================
    // Audit log
    // ============================================================================================

    /** Everything known about one attempt, assembled as the attempt proceeds, rendered once at the end. */
    static final class LoginContext {

        private final String attemptId;
        private final String sourceIp;
        private final String sessionId;
        private final String userAgent;
        private String subject;
        private String subjectState = "unresolved";
        private AccountRecord account;
        private Integer consecutiveFailures;
        private Instant lockedUntil;
        private Instant previousSuccessAt;
        private String previousSuccessIp;
        private String policy;
        private final Map<String, String> details = new LinkedHashMap<>();

        LoginContext(String attemptId, String sourceIp, String sessionId, String userAgent) {
            this.attemptId = attemptId;
            this.sourceIp = sourceIp;
            this.sessionId = sessionId;
            this.userAgent = userAgent;
        }

        String attemptId() {
            return attemptId;
        }

        String accountId() {
            return account == null ? null : account.accountId();
        }

        void subject(String value, String state) {
            this.subject = value;
            this.subjectState = state;
        }

        void account(AccountRecord record) {
            this.account = record;
        }

        void consecutiveFailures(int value) {
            this.consecutiveFailures = value;
        }

        void lockedUntil(Instant value) {
            this.lockedUntil = value;
        }

        void previousSuccess(Instant when, String ip) {
            this.previousSuccessAt = when;
            this.previousSuccessIp = ip;
        }

        void policy(String value) {
            this.policy = value;
        }

        void detail(String key, String value) {
            this.details.put(key, value);
        }

        /** Already-escaped fields, in the column order documented in README.md. */
        List<String[]> fields() {
            List<String[]> out = new ArrayList<>(16);
            out.add(field("attempt", attemptId, 32));
            out.add(field("subject", subject, 128));
            out.add(field("subjectState", subjectState, 64));
            out.add(field("account", account == null ? null : account.accountId(), 64));
            out.add(field("accountState", account == null ? "no-such-account" : account.status().logToken(), 32));
            out.add(field("ip", sourceIp, 64));
            out.add(field("session", sessionId, 128));
            out.add(field("agent", userAgent, 256));
            out.add(field("failures", consecutiveFailures == null ? null : consecutiveFailures.toString(), 16));
            out.add(field("lockedUntil", lockedUntil == null ? null : lockedUntil.toString(), 40));
            out.add(field("previousSuccess", previousSuccessAt == null ? null : previousSuccessAt.toString(), 40));
            out.add(field("previousSuccessIp", previousSuccessIp, 64));
            out.add(field("policy", policy, 40));
            for (Map.Entry<String, String> detail : details.entrySet()) {
                out.add(field(detail.getKey(), detail.getValue(), 128));
            }
            return out;
        }

        static String[] field(String key, String value, int maxValueChars) {
            return new String[] { key, value == null ? "-" : LogValue.escape(value, maxValueChars) };
        }
    }

    /**
     * Writes authentication events as ordered {@code key=value} pairs.
     *
     * <p>The log is what an investigator reads at 3am, so a single record answers: what happened
     * ({@code event}, {@code outcome}); why ({@code reason}, internal only); who was named
     * ({@code subject}, {@code account}, {@code accountState}); from where ({@code ip},
     * {@code session}, {@code agent}); against what policy ({@code failures}, {@code lockedUntil},
     * {@code policy}); whether it is new behaviour ({@code previousSuccess},
     * {@code previousSuccessIp}); and how long it took ({@code elapsedMs}, which is also the
     * evidence that the equal-cost derivation really ran). {@code attempt} ties the line to the id
     * the subject was shown, so a support ticket resolves without guessing.
     *
     * <p>Level policy, so a collector can filter on level instead of matching strings: INFO for
     * ordinary successes and refusals, WARNING when an account locks, SEVERE when the credential
     * store itself is broken.
     */
    public static final class AuthAuditLogger {

        public static final String LOGGER_NAME = "auth.audit";

        private final Logger logger;

        public AuthAuditLogger() {
            this(Logger.getLogger(LOGGER_NAME));
        }

        public AuthAuditLogger(Logger logger) {
            this.logger = Objects.requireNonNull(logger, "logger");
        }

        public Logger logger() {
            return logger;
        }

        void authSuccess(LoginContext ctx, long elapsedMs) {
            emit("AUTH_SUCCESS", "SUCCESS", "authenticated", Level.INFO, ctx.fields(), elapsedMs);
        }

        void authFailure(LoginContext ctx, String internalReason, long elapsedMs) {
            emit("AUTH_FAILURE", "FAILURE", internalReason, Level.INFO, ctx.fields(), elapsedMs);
        }

        /**
         * The attempt that crossed the lockout threshold. Same event and shape as any other refusal
         * -- one record per attempt -- escalated to WARNING and carrying {@code lockedUntil}, so a
         * collector alerts on level and reason without double-counting the attempt.
         */
        void accountLocked(LoginContext ctx, long elapsedMs) {
            emit("AUTH_FAILURE", "FAILURE", "password-mismatch-locking", Level.WARNING,
                    ctx.fields(), elapsedMs);
        }

        void credentialRecordCorrupt(LoginContext ctx, long elapsedMs) {
            emit("CREDENTIAL_RECORD_CORRUPT", "FAILURE", "stored-credential-unparsable",
                    Level.SEVERE, ctx.fields(), elapsedMs);
        }

        void accountCreated(AccountRecord record, String policy, String sourceIp, Instant now) {
            List<String[]> fields = adminFields(now);
            fields.add(LoginContext.field("subject", record.username(), 128));
            fields.add(LoginContext.field("ip", sourceIp, 64));
            fields.add(LoginContext.field("account", record.accountId(), 64));
            fields.add(LoginContext.field("accountState", record.status().logToken(), 32));
            fields.add(LoginContext.field("createdAt", record.createdAt().toString(), 40));
            fields.add(LoginContext.field("policy", policy, 40));
            emit("ACCOUNT_CREATED", "INFO", "account-registered", Level.INFO, fields, 0L);
        }

        void accountStatusChanged(String accountId, AccountStatus from, AccountStatus to,
                                 String operator, Instant now) {
            List<String[]> fields = adminFields(now);
            fields.add(LoginContext.field("account", accountId, 64));
            fields.add(LoginContext.field("fromState", from.logToken(), 32));
            fields.add(LoginContext.field("toState", to.logToken(), 32));
            fields.add(LoginContext.field("operator", operator, 64));
            emit("ACCOUNT_STATUS_CHANGED", "INFO", "administrator-action", Level.INFO, fields, 0L);
        }

        void accountUnlocked(String accountId, String operator, InMemoryFailureTracker.State before,
                             Instant now) {
            List<String[]> fields = adminFields(now);
            fields.add(LoginContext.field("account", accountId, 64));
            fields.add(LoginContext.field("failures", String.valueOf(before.consecutiveFailures()), 16));
            fields.add(LoginContext.field("lockedUntil",
                    before.lockedUntil() == null ? null : before.lockedUntil().toString(), 40));
            fields.add(LoginContext.field("operator", operator, 64));
            emit("ACCOUNT_UNLOCKED", "INFO", "administrator-unlock", Level.INFO, fields, 0L);
        }

        private static List<String[]> adminFields(Instant now) {
            List<String[]> fields = new ArrayList<>(8);
            fields.add(LoginContext.field("attempt", "admin-" + now.getEpochSecond() + "-"
                    + (now.getNano() / 1000), 32));
            return fields;
        }

        private void emit(String event, String outcome, String reason, Level level,
                          List<String[]> fields, long elapsedMs) {
            if (!logger.isLoggable(level)) {
                return;
            }
            StringBuilder line = new StringBuilder(320);
            line.append("event=").append(event)
                    .append(" outcome=").append(outcome)
                    .append(" reason=").append(LogValue.escape(reason, 64));
            for (String[] field : fields) {
                line.append(' ').append(field[0]).append('=').append(field[1]);
            }
            line.append(" elapsedMs=").append(elapsedMs);
            logger.log(level, line.toString());
        }
    }

    /**
     * Renders a value so that one input can never become two log lines, and can never smuggle a
     * control character into a collector.
     *
     * <p>Rules, in order, applied to at most {@code maxChars} characters of the input:
     * <ul>
     *   <li>{@code %}, {@code "} and {@code \} are percent-encoded, so the escape language itself
     *       cannot be forged;</li>
     *   <li>every byte of every non-ASCII code point is percent-encoded via UTF-8, which keeps the
     *       line pure ASCII (it survives any console or importer) and keeps a look-alike Unicode
     *       username exactly reproducible. This covers the C1 controls, U+0085 and U+00A0 along with
     *       every look-alike space and U+2028/U+2029;</li>
     *   <li>the remaining invisible ASCII characters -- the C0 controls (including CR and LF) and
     *       DEL -- are percent-encoded too, so no control character ever reaches a collector.</li>
     * </ul>
     * What remains is printable ASCII; if it still contains whitespace the whole value is quoted.
     * Input beyond {@code maxChars} is dropped and the value is suffixed {@code (+truncated)}.
     */
    static final class LogValue {

        private LogValue() {
        }

        static String escape(String raw, int maxChars) {
            if (raw == null) {
                return "-";
            }
            int limit = Math.min(raw.length(), Math.max(0, maxChars));
            StringBuilder out = new StringBuilder(limit + 16);
            int i = 0;
            while (i < limit) {
                int cp = raw.codePointAt(i);
                int width = Character.charCount(cp);
                if (i + width > limit) {
                    break;
                }
                i += width;
                if (cp == '%') {
                    out.append("%25");
                } else if (cp == '"') {
                    out.append("%22");
                } else if (cp == '\\') {
                    out.append("%5C");
                } else if (cp >= 0x20 && cp <= 0x7E) {
                    out.append((char) cp);
                } else if (cp < 0x80) {
                    appendPercentEncoded(out, new byte[] { (byte) cp });
                } else {
                    // Everything at or above 0x80 is percent-encoded via UTF-8 regardless of category,
                    // so the emitted line is pure ASCII. U+0085, U+00A0 and U+2028/U+2029 are the
                    // characters in that range that specifically break line-based log parsing or are
                    // invisible in a renderer, but no non-ASCII byte is ever emitted raw.
                    appendPercentEncoded(out, new String(Character.toChars(cp))
                            .getBytes(StandardCharsets.UTF_8));
                }
            }
            if (limit < raw.length()) {
                out.append("(+truncated)");
            }
            String escaped = out.toString();
            boolean needsQuoting = escaped.chars().anyMatch(Character::isWhitespace);
            return needsQuoting ? '"' + escaped + '"' : escaped;
        }

        private static void appendPercentEncoded(StringBuilder out, byte[] bytes) {
            for (byte b : bytes) {
                out.append('%').append(String.format("%02X", b & 0xFF));
            }
        }
    }

    /** One UTC-timestamped line: {@code 2026-09-12T01:02:03.456Z INFO  auth.audit event=...}. */
    public static final class IsoLogFormatter extends Formatter {

        private static final DateTimeFormatter TIMESTAMP =
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

        @Override
        public String format(LogRecord record) {
            StringBuilder sb = new StringBuilder(256);
            sb.append(TIMESTAMP.format(record.getInstant())).append(' ');
            String levelName = record.getLevel().getName();
            sb.append(levelName);
            for (int pad = levelName.length(); pad < 7; pad++) {
                sb.append(' ');
            }
            sb.append(' ').append(record.getLoggerName()).append(' ').append(formatMessage(record));
            sb.append(System.lineSeparator());
            if (record.getThrown() != null) {
                sb.append(StackTraceText.of(record.getThrown()));
            }
            return sb.toString();
        }
    }

    /** Minimal throwable rendering, so a SEVERE record is diagnosable from the log alone. */
    static final class StackTraceText {

        private StackTraceText() {
        }

        static String of(Throwable thrown) {
            StringBuilder sb = new StringBuilder(256);
            sb.append("    thrown: ").append(thrown.getClass().getName());
            if (thrown.getMessage() != null) {
                sb.append(": ").append(LogValue.escape(thrown.getMessage(), 256));
            }
            sb.append(System.lineSeparator());
            StackTraceElement[] trace = thrown.getStackTrace();
            for (int i = 0; i < Math.min(5, trace.length); i++) {
                sb.append("        at ").append(trace[i]).append(System.lineSeparator());
            }
            if (thrown.getCause() != null) {
                sb.append("    caused by: ").append(thrown.getCause().getClass().getName())
                        .append(System.lineSeparator());
            }
            return sb.toString();
        }
    }

    /** Raised when the credential store cannot be trusted. Never raised for a wrong password. */
    public static final class AuthenticationDataException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        AuthenticationDataException(String message) {
            super(message);
        }

        AuthenticationDataException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // ============================================================================================
    // Runnable demo
    // ============================================================================================

    /** Convenience entry point so that {@code java AuthService} runs the scripted scenario. */
    public static void main(String[] args) throws Exception {
        AuthenticationDemo.main(args);
    }

    /**
     * Drives a scripted scenario against an in-memory store and shows the resulting audit log.
     *
     * <p>{@code java AuthenticationDemo} runs the script;
     * {@code java AuthenticationDemo login} prompts for one set of credentials on a terminal.
     */
    public static final class AuthenticationDemo {

        private static final String DEMO_PASSWORD = "correct-horse-battery";
        private static final int DEMO_ITERATIONS = 60_000;
        private static final int LOCK_AFTER = 5;
        private static final Duration LOCK_FOR = Duration.ofMinutes(15);

        private AuthenticationDemo() {
        }

        public static void main(String[] args) throws Exception {
            Logger auditLogger = configureLogging();
            InMemoryAccountStore store = new InMemoryAccountStore();
            AuthService service = new AuthService(store, new PasswordHasher(DEMO_ITERATIONS),
                    new InMemoryFailureTracker(LOCK_AFTER, LOCK_FOR),
                    new AuthAuditLogger(auditLogger), Clock.systemUTC());

            service.register("alice", DEMO_PASSWORD.toCharArray());
            service.register("bob", "stubborn-wrench-42".toCharArray());
            service.register("carol", "quiet-lantern-77".toCharArray());
            service.setStatus("carol", AccountStatus.DISABLED, "admin@example");

            if (args.length > 0 && args[0].equals("login")) {
                interactiveLogin(service);
            } else {
                runScenario(service);
            }
            flush(auditLogger);
            System.out.println();
            System.out.println("Audit log: ./auth.log (same lines echoed on stdout). See README.md for the field legend.");
        }

        private static void runScenario(AuthService service) {
            System.out.println("Scenario: iterations=" + DEMO_ITERATIONS
                    + ", lock after " + LOCK_AFTER + " consecutive failures for " + LOCK_FOR
                    + ", enrolment minimum " + PasswordRules.MIN_ENROLMENT_CHARS + " characters.");
            System.out.println("The audit lines below are the real output of the service.\n");

            int step = 0;
            attempt(service, ++step, "correct password for a known account",
                    "alice", DEMO_PASSWORD, "203.0.113.10");
            attempt(service, ++step, "wrong password", "alice", "wrong-password-here", "203.0.113.10");
            attempt(service, ++step, "repeated wrong password (1/4)", "alice", "guess-one", "198.51.100.7");
            attempt(service, ++step, "repeated wrong password (2/4)", "alice", "guess-two", "198.51.100.7");
            attempt(service, ++step, "repeated wrong password (3/4)", "alice", "guess-three", "198.51.100.7");
            attempt(service, ++step, "repeated wrong password (4/4) -- crosses the threshold",
                    "alice", "guess-four", "198.51.100.7");
            attempt(service, ++step, "correct password while locked -- still refused",
                    "alice", DEMO_PASSWORD, "198.51.100.7");
            attempt(service, ++step, "username that does not exist",
                    "nobody", DEMO_PASSWORD, "198.51.100.7");
            attempt(service, ++step, "correct password for a disabled account",
                    "carol", "quiet-lantern-77", "203.0.113.21");
            attempt(service, ++step, "username carrying a newline and forged fields (log injection)",
                    "alice\n2026-01-01 00:00:00 INFO auth.audit event=AUTH_SUCCESS outcome=SUCCESS",
                    DEMO_PASSWORD, "198.51.100.7");
            attempt(service, ++step, "correct password with a trailing NUL (would collide without the rule)",
                    "alice", DEMO_PASSWORD + (char) 0, "203.0.113.10");
            attempt(service, ++step, "empty password", "alice", "", "203.0.113.10");

            System.out.println("\n-- administrative unlock, then logins that were blocked before --");
            service.unlock("alice", "admin@example");
            attempt(service, ++step, "correct password after the unlock", "alice", DEMO_PASSWORD, "203.0.113.11");
            attempt(service, ++step, "mixed-case and padded username resolves to the same account",
                    "  ALICE  ", DEMO_PASSWORD, "203.0.113.11");
        }

        private static void attempt(AuthService service, int step, String label,
                                    String username, String password, String ip) {
            System.out.printf("--%2d  %s%n", step, label);
            AuthService.LoginResult result = service.login(new AuthService.LoginRequest(
                    username, password.toCharArray(), ip, "sess-" + step,
                    "DemoClient/1.0 (scenario runner)"));
            System.out.printf("     you see : %s%n", result.message());
            System.out.printf("     server  : status=%s internalReason=%s attempt=%s%n%n",
                    result.status(), result.internalReason(), result.attemptId());
        }

        private static void interactiveLogin(AuthService service) {
            Console console = System.console();
            if (console == null) {
                System.out.println("No terminal available (input is not a tty); running the scripted scenario instead.");
                runScenario(service);
                return;
            }
            String username = console.readLine("username: ");
            char[] password = console.readPassword("password: ");
            AuthService.LoginRequest request = new AuthService.LoginRequest(
                    username, password, "127.0.0.1", "sess-interactive", "Terminal");
            try {
                AuthService.LoginResult result = service.login(request);
                System.out.println(result.message() + " (attempt " + result.attemptId() + ")");
            } finally {
                Arrays.fill(password, '\0');
                request.destroy();
            }
        }

        private static Logger configureLogging() throws java.io.IOException {
            Logger logger = Logger.getLogger(AuthAuditLogger.LOGGER_NAME);
            logger.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
            for (Handler handler : logger.getHandlers()) {
                logger.removeHandler(handler);
            }
            IsoLogFormatter formatter = new IsoLogFormatter();

            ConsoleHandler console = new ConsoleHandler();
            console.setLevel(Level.INFO);
            console.setFormatter(formatter);
            logger.addHandler(console);

            // append=true: an audit log that restarts the process must not lose its history.
            FileHandler file = new FileHandler("auth.log", true);
            file.setLevel(Level.ALL);
            file.setFormatter(formatter);
            logger.addHandler(file);
            return logger;
        }

        private static void flush(Logger logger) {
            for (Handler handler : logger.getHandlers()) {
                handler.flush();
            }
        }
    }
}
