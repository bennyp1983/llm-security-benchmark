package com.portal.auth;

import java.util.Optional;

/**
 * The one place that decides whether a request is authenticated. Everything else in this
 * program is plumbing around it.
 *
 * <h2>The one-digest invariant</h2>
 * Every outcome of {@link #authenticate} executes <b>exactly one</b> PBKDF2 derivation of
 * the presented password at the configured cost, and no more:
 * <ul>
 *   <li>malformed username / malformed password -&gt; one decoy derivation</li>
 *   <li>budget spent -&gt; one decoy derivation (the roster is never read here)</li>
 *   <li>unknown username -&gt; one decoy derivation</li>
 *   <li>known username -&gt; one real verification</li>
 * </ul>
 * CPU work per request is therefore independent of the outcome, and every refusal is
 * additionally padded to a single shared latency floor. "Account does not exist",
 * "wrong password", "bad input" and "you are rate-limited" are not distinguishable by
 * timing, and are not distinguishable at all in the response the caller receives.
 *
 * <h2>What a caller may learn</h2>
 * Exactly one bit: success (with a freshly minted session id) or denial.
 * {@link Result#reasonForInternalUseOnly()} exists so the audit log and the test suite can
 * tell branches apart; it is never rendered into a response body, status code, header,
 * cookie, or byte count that a client can observe.
 *
 * <h2>Username folding</h2>
 * {@code ALICE} and {@code alice} are the same employee. The fold is a 26-letter ASCII
 * table applied <em>before</em> validation -- not {@code toLowerCase()} (locale hazard: the
 * Turkish dotted/dotless i) and not Unicode case folding or NFKC (identity hazard:
 * {@code Kelvin} folds onto {@code Kelin}, and a full-width character folds onto a
 * different name). Because the accepted alphabet is {@code [a-z0-9._-]}, this fold is
 * injective over distinct accepted identities: no two real accounts can ever be folded
 * together, so the convenience costs nothing in identity strength.
 */
public final class Authenticator {

    /**
     * Refused-input decoy reference. Not hex, so it can never collide with a real idRef.
     * Package-visible because {@link AuditLog} recognises it as one of the two non-digest
     * tokens the subject field accepts.
     */
    static final String INVALID_REF = "invalid";

    public enum Outcome {
        SUCCESS, DENIED
    }

    /** Machine-readable internal reason. Never surfaced to a client. */
    public enum Reason {
        CREDENTIALS_OK, BAD_CREDENTIALS, INPUT_INVALID, THROTTLED, KDF_UNAVAILABLE
    }

    public static final class Result {
        private final Outcome outcome;
        private final Reason reason;
        private final String sessionId;
        private final String username;

        Result(Outcome outcome, Reason reason, String sessionId, String username) {
            this.outcome = outcome;
            this.reason = reason;
            this.sessionId = sessionId;
            this.username = username;
        }

        public boolean isSuccess() {
            return outcome == Outcome.SUCCESS;
        }

        public Outcome outcome() {
            return outcome;
        }

        /** Non-null only on success. */
        public String sessionId() {
            return sessionId;
        }

        /** Non-null only on success. */
        public String username() {
            return username;
        }

        public String reasonForInternalUseOnly() {
            return reason.name();
        }
    }

    private final EmployeeStore store;
    private final PasswordHasher hasher;
    private final ThrottleManager throttle;
    private final SessionManager sessions;
    private final AuditLog audit;

    public Authenticator(EmployeeStore store, PasswordHasher hasher, ThrottleManager throttle,
                         SessionManager sessions, AuditLog audit) {
        this.store = store;
        this.hasher = hasher;
        this.throttle = throttle;
        this.sessions = sessions;
        this.audit = audit;
    }

    /** CLI entry point: the password arrives as the {@code char[]} Console gave us. */
    public Result authenticate(char[] username, char[] password, String sourceLabel) {
        char[] folded = username == null ? new char[0] : Authenticator.foldAsciiCase(username);
        String presented;
        try {
            presented = new String(folded);
        } finally {
            Crypto.wipe(username);
            Crypto.wipe(folded);
        }
        return authenticate(presented, password, sourceLabel);
    }

    /**
     * @param presentedUsername attacker-controlled; folded and validated below
     * @param password          attacker-controlled {@code char[]}; <b>cleared by this
     *                          method</b> on every path, including success
     * @param sourceLabel       already-reduced source reference (see {@link SourceRef})
     */
    public Result authenticate(String presentedUsername, char[] password, String sourceLabel) {
        long startedAt = System.nanoTime();
        try {
            return decide(presentedUsername, password, sourceLabel, startedAt);
        } finally {
            // Single exit point for clearing, so no branch can forget it.
            Crypto.wipe(password);
        }
    }

    private Result decide(String presentedUsername, char[] password, String sourceLabel,
                          long startedAt) {
        // Adopt another process's roster change before deciding anything. This is the first
        // statement of the decision so that the cost is the same on every path -- including
        // the two malformed-input paths and the throttled path, which never look at a record
        // and must not be distinguishable by a cost the other paths do not pay. The check is
        // a stat of the roster file, so it is a function of the file, not of the presented
        // name, and can therefore never answer "does this account exist?".
        store.refreshIfChanged();

        String sourceHex = SourceRef.normalizeForLedger(sourceLabel);
        String username = presentedUsername == null ? "" : foldAsciiCase(presentedUsername);

        // Each branch below performs exactly one key derivation before calling deny();
        // that is the invariant stated in the class note, and it is why the derivations
        // are spelled out at every call site instead of being hidden inside deny().
        if (!InputPolicy.isUsername(username)) {
            hasher.burnOneDigest(password, INVALID_REF);
            throttle.consumeSourceBudget(sourceHex);
            deny(password, INVALID_REF, sourceHex, Reason.INPUT_INVALID, startedAt);
            return denial(Reason.INPUT_INVALID);
        }

        String accountRef = Crypto.idRef(username);

        if (!InputPolicy.isWellFormedSecret(password)) {
            // Counted against the source budget and padded like every other refusal, so
            // a malformed password is not a cheap probe of the boundary.
            hasher.burnOneDigest(password, accountRef);
            throttle.consumeSourceBudget(sourceHex);
            deny(password, accountRef, sourceHex, Reason.INPUT_INVALID, startedAt);
            return denial(Reason.INPUT_INVALID);
        }

        // The slot is reserved (counter incremented) before the password is looked at, so
        // a concurrent burst cannot all observe the same headroom and then all verify.
        ThrottleManager.Kind reserved = throttle.beginAttempt(accountRef, sourceHex);
        if (reserved == ThrottleManager.Kind.THROTTLED) {
            // The roster is deliberately not consulted here: reading it would make the
            // throttle response differ in timing between an existing and an unknown name.
            // The secret is well-formed at this point, so the real decoy path is safe.
            hasher.verifyAgainstDecoy(password, accountRef);
            deny(password, accountRef, sourceHex, Reason.THROTTLED, startedAt);
            return denial(Reason.THROTTLED);
        }

        Optional<String> record = store.recordFor(username);
        if (record.isEmpty()) {
            hasher.verifyAgainstDecoy(password, accountRef);
            // Counted exactly like a wrong password, so neither the counter behaviour nor
            // the cost distinguishes an unknown name from a known one.
            throttle.recordFailure(accountRef, sourceHex);
            deny(password, accountRef, sourceHex, Reason.BAD_CREDENTIALS, startedAt);
            return denial(Reason.BAD_CREDENTIALS);
        }

        boolean matches;
        try {
            matches = hasher.verify(password, record.get(), accountRef);
        } catch (RuntimeException kdfUnavailable) {
            // A KDF that cannot run must not read as "wrong password" (that would let an
            // outage lock every account out) nor as "success". Fail closed and say so in
            // the log; the client sees the same generic denial as everybody else.
            audit.systemFailure("login", accountRef, sourceHex, kdfUnavailable);
            try {
                hasher.burnOneDigest(password, accountRef);
            } catch (RuntimeException kdfStillBroken) {
                // Nothing left to equalise with; the denial stands either way.
            }
            deny(password, accountRef, sourceHex, Reason.KDF_UNAVAILABLE, startedAt);
            return denial(Reason.KDF_UNAVAILABLE);
        }

        if (!matches) {
            throttle.recordFailure(accountRef, sourceHex);
            deny(password, accountRef, sourceHex, Reason.BAD_CREDENTIALS, startedAt);
            return denial(Reason.BAD_CREDENTIALS);
        }

        // Verified against server-side state. Upgrade the record when the stored KDF cost
        // is below policy -- reachable only by someone who already knows the password, so
        // it cannot be used to make the store more expensive for others.
        if (hasher.needsRehash(record.get())) {
            try {
                store.rotateSecret(username, password);
                audit.event("login", accountRef, sourceHex, "ok", "granted-rotated");
            } catch (RuntimeException rotationFailed) {
                // Authentication succeeded; a failed write is an operational problem and
                // must not retroactively change the outcome.
                audit.systemFailure("rotate", accountRef, sourceHex, rotationFailed);
            }
        } else {
            audit.event("login", accountRef, sourceHex, "ok", "granted");
        }

        throttle.recordSuccess(accountRef, sourceHex);
        String session = sessions.issue(username);
        // Success is padded on the same floor as the refusals, so an observer measuring
        // latency cannot tell a granted login from a denied one.
        throttle.padToFloor(startedAt);
        throttle.observeLatency(System.nanoTime() - startedAt);
        return new Result(Outcome.SUCCESS, Reason.CREDENTIALS_OK, session, username);
    }

    /**
     * Record the refusal, then pad. Note the order: the audit write is charged
     * <em>before</em> the padding so the padding covers it, and the padding never decides
     * anything -- it only equalises.
     */
    private void deny(char[] password, String subjectRef, String sourceHex, Reason reason,
                      long startedAt) {
        audit.event("login", subjectRef, sourceHex, "denied", auditDetail(reason));
        throttle.padToFloor(startedAt);
        throttle.observeLatency(System.nanoTime() - startedAt);
    }

    private static String auditDetail(Reason reason) {
        return switch (reason) {
            case BAD_CREDENTIALS -> "bad-credentials";
            case INPUT_INVALID -> "input-invalid";
            case THROTTLED -> "throttled";
            case KDF_UNAVAILABLE -> "kdf-unavailable";
            case CREDENTIALS_OK -> "granted";
        };
    }

    private static Result denial(Reason reason) {
        return new Result(Outcome.DENIED, reason, null, null);
    }

    /** Locale-free ASCII A-Z -&gt; a-z. Touches nothing else. See the class note. */
    static String foldAsciiCase(String in) {
        return new String(foldAsciiCase(in.toCharArray()));
    }

    static char[] foldAsciiCase(char[] in) {
        char[] out = in.clone();
        for (int i = 0; i < out.length; i++) {
            if (out[i] >= 'A' && out[i] <= 'Z') {
                out[i] = (char) (out[i] + 32);
            }
        }
        return out;
    }
}
