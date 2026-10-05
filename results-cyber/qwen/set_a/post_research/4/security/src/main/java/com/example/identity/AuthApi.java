package com.example.identity;

import java.security.SecureRandom;

/**
 * Registration and authentication, as an API. Everything the CLI does, a front end would do through
 * here - which is the point: one place makes the security decisions, so a second transport cannot
 * accidentally skip a check.
 *
 * <h2>The order of checks in {@link #signIn} <em>is</em> the security property</h2>
 * <ol>
 *   <li><b>Concurrency bound</b> first ({@link DecisionGuard}). One decision per identifier form, at
 *     most {@link #MAX_IN_FLIGHT_DERIVATIONS} in the process. Without it, K parallel connections all
 *     pass the penalty check during each other's ~850 ms derivation and the limits hand over
 *     {@code limit + K} guesses - and unbounded parallel PBKDF2 is free CPU.</li>
 *   <li><b>Source label</b> next. An unusable label aborts the request before any lookup or
 *     derivation, so it is never a way to get work done for free and never a bucket to hide
 *     behind.</li>
 *   <li><b>The source penalty</b> second, keyed by the caller's own canonical origin. This is the
 *     <em>only</em> refusal before the account is known. Rule 3's "so an attacker cannot use your own
 *     limit to lock a legitimate user out" is what forbids an account-keyed pre-check: it would
 *     refuse the attacker's guesses <em>and</em> the owner's correct password with one cheap early
 *     return, and whoever is guessing chooses when that happens.</li>
 *   <li><b>Password policy</b> third. A candidate we refuse to hash is rejected <em>at a
 *     derivation's cost</em>, never cheaply - otherwise "is this password long enough" becomes an
 *     unauthenticated oracle - and it still charges the source, so it is not a free way to spend our
 *     CPU either.</li>
 *   <li><b>Account lookup</b> fourth.</li>
 *   <li><b>The per-account penalty</b> fifth, after the lookup. Rule 3 does ask for a per-account
 *     limit, so it is enforced on every failed attempt and it does refuse further attempts - but only
 *     from here, once the row is known. Two consequences: its key is the row's primary key (see
 *     {@link #accountBucketKey}), and it can never stand between the owner and a password that was
 *     never verified. The caller who arrives during a penalty is charged against <em>its own</em>
 *     source budget, which is what stops one source parking a lockout on somebody else's account for
 *     free. A caller that trips it cannot deepen it either: the check precedes the charge.</li>
 *   <li><b>Password verification</b> sixth.</li>
 *   <li><b>Account status</b> <em>after</em> verification. Reading {@code status} first would let an
 *     unauthenticated caller learn which accounts are administratively disabled - from the message
 *     and from the timing of the early return.</li>
 *   <li><b>Session issue</b> last.</li>
 * </ol>
 *
 * <h2>Equal work on every refusal (Rule 6)</h2>
 * Every branch that could separate "this identifier exists" from "it does not" pays roughly one
 * PBKDF2 derivation: unknown account, corrupt row, wrong password, and a candidate that fails
 * policy all do. {@link PasswordHasher#chargeDummy()} spends the work where there is nothing real to
 * verify. The throttled branch is the one deliberate exception, and it is not an oracle: the same
 * cheap refusal is reachable whether or not the identifier exists, since the bucket was created by
 * the earlier attempts either way. Charging the derivation there would defeat a limiter whose whole
 * purpose is to bound that cost. Each branch is timed separately in {@code EqualWorkTest}.
 *
 * <h2>What this class never does</h2>
 * It never logs, returns, or stores the plaintext password, the stored hash, the salt, or the
 * iteration count. It never echoes caller bytes back: every string it returns was re-read from the
 * database and re-validated. It never decides an outcome from a caller-supplied token, identifier
 * mapping, or role.
 */
public final class AuthApi implements AutoCloseable {

    /**
     * Concurrent verifications this process allows in total. Sized from the measured cost of one
     * derivation (~850 ms at the accepted iteration floor): eight of them saturate eight cores for
     * almost a second, which is already more CPU an unauthenticated caller can force than a
     * legitimate load should be sharing, and the refusal under contention is cheap and immediate.
     * Deliberately not configuration: it is a safety bound, and a knob an operator can raise is a
     * knob a compromised config can raise.
     */
    static final int MAX_IN_FLIGHT_DERIVATIONS = 8;

    private final SqlIdentityStore store;
    private final PasswordHasher hasher;
    private final AuditLog audit;
    private final Config config;
    private final TimeSource time;
    private final DecisionGuard guard = new DecisionGuard(MAX_IN_FLIGHT_DERIVATIONS);
    private final SecureRandom random = new SecureRandom();

    public AuthApi(SqlIdentityStore store, PasswordHasher hasher, AuditLog audit, Config config,
                   TimeSource time) {
        this.store = store;
        this.hasher = hasher;
        this.audit = audit;
        this.config = config;
        this.time = time;
    }

    // ------------------------------------------------------------------ registration

    /**
     * Registers an account.
     *
     * @param passwordChars consumed and erased on every path, including the rejected ones
     * @param sourceLabel   asserted origin; see {@link SourceId} for why it is treated as hostile
     */
    public AuthResult register(String emailRaw, String usernameRaw, char[] passwordChars, String sourceLabel)
            throws IdentityStoreException {
        // Validation first, before any secret is touched. These outcomes are about the caller's own
        // input and may be specific, because none of them says whether an account exists.
        SourceId source = SourceId.parse(sourceLabel);
        if (source == null) {
            Password.erase(passwordChars);
            audit.record(Reason.INVALID_REQUEST, null);
            return AuthResult.of(Reason.INVALID_REQUEST);
        }
        Identity email = Identity.parseClientEmail(emailRaw);
        if (email == null) {
            Password.erase(passwordChars);
            audit.record(Reason.INVALID_EMAIL, null);
            return AuthResult.of(Reason.INVALID_EMAIL);
        }
        Identity username = Identity.parseClientUsername(usernameRaw);
        if (username == null) {
            Password.erase(passwordChars);
            audit.record(Reason.INVALID_USERNAME, null);
            return AuthResult.of(Reason.INVALID_USERNAME);
        }
        Password password = Password.adopt(passwordChars); // erases the array if it is rejected
        if (password == null) {
            audit.record(Reason.INVALID_PASSWORD, username);
            return AuthResult.of(Reason.INVALID_PASSWORD);
        }

        try {
            String hash = hasher.hash(password); // closes the password
            // Budgets and the account cap are enforced inside the store's transaction, behind the
            // serialisation row, so neither can be raced.
            SqlIdentityStore.Outcome outcome =
                    store.register(username.canonical(), username, email, email.canonical(), hash, source);
            // Committed: the account exists and the registration budget is spent, whatever the log
            // now says. A throwing append here used to turn that into "The service is unavailable."
            // - the program denying an effect it had just performed, and the retry then answering as
            // a duplicate. The audit still gets the store's specific fact; the caller still gets the
            // collapsed one.
            audit.record(outcome.reason(), username);
            return AuthResult.of(outcome.callerReason());
        } catch (IdentityStoreException e) {
            password.close();
            // The operation failed, so the caller is still refused - with <em>this</em> reason, not
            // with whatever the second failure happens to say. Appending here used to be able to
            // throw, and the AUDIT_FAILURE that escaped replaced the storage reason being reported.
            audit.record(e.reason(), username);
            throw e;
        }
    }

    // ------------------------------------------------------------------ sign-in

    /**
     * Verifies a credential and, on success, issues a session.
     *
     * @param passwordChars consumed and erased on every path
     */
    public AuthResult signIn(String identifierRaw, char[] passwordChars, String sourceLabel)
            throws IdentityStoreException {
        long now = time.nowEpochSeconds();

        SourceId source = SourceId.parse(sourceLabel);
        if (source == null) {
            Password.erase(passwordChars);
            audit.record(Reason.INVALID_REQUEST, null);
            return AuthResult.of(Reason.INVALID_REQUEST);
        }

        Identity identifier = parseIdentifier(identifierRaw);
        Password password = Password.adopt(passwordChars);
        // One decision at a time per identifier form and at most MAX_IN_FLIGHT_DERIVATIONS at a
        // time in total. Taken before any derivation, so it bounds the work and not just the
        // bookkeeping; released in the finally below, so a thrown store error cannot leak a slot.
        String guardKey = identifier == null ? null : "i:" + identifier.canonical();
        String rowKey = null;
        boolean rowClaimed = false;
        if (!guard.tryBegin(guardKey)) {
            if (password != null) {
                password.close();
            }
            // The same cheap refusal an active source penalty produces, and for the same reason: it
            // is reachable whether or not the identifier exists, so shedding is not an oracle.
            audit.record(Reason.THROTTLED, identifier);
            return AuthResult.of(Reason.BAD_CREDENTIAL);
        }
        try {
            // (2) The source penalty, ahead of every branch that would spend work or write a
            // counter. Keyed by the caller's own canonical origin, never by the account: see the
            // class header for why an account-keyed pre-check is what Rule 3's parenthetical
            // forbids. An already-blocked source is charged nothing here, so it cannot extend its
            // own penalty by continuing to knock.
            if (store.isPenaltyActive(SqlIdentityStore.bucketKindSource(), source.canonical(), now)) {
                audit.record(Reason.THROTTLED, identifier);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // (3) Policy. Refused at verification cost, so password policy is not an oracle - and
            // charged to the source, so a candidate we decline to hash is not a way to make us
            // derive for free with no counter anywhere recording it.
            //
            // Every audit call below is the non-throwing form. Each one sits after a decision that
            // database state already fixed - a charged counter, a verified credential, a refusal
            // reached by lookup - so a full or blocked log must not reach the user as "The service is
            // unavailable." while their budget really was spent or their session really was created.
            // Rule 6's "identical messages" is broken by the log, not by the decision, and the log is
            // filled at a rate an unauthenticated attacker chooses.
            if (password == null) {
                chargeEqualWork();
                chargeSource(source, now);
                audit.record(Reason.INVALID_PASSWORD, identifier);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // A malformed identifier never reaches the database. Equal cost, same message, and the
            // source is still charged: an unchargeable identifier is exactly the shape an attacker
            // would pick to spend our CPU for free forever.
            if (identifier == null) {
                chargeEqualWork();
                chargeSource(source, now);
                audit.record(Reason.BAD_CREDENTIAL, null);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // (4) Lookup. A row that fails strict re-validation is a storage fact, not a user fact:
            // it becomes the same outcome as "no such account".
            SqlIdentityStore.Account account;
            try {
                account = store.findByCanonicalIdentity(identifier);
            } catch (IdentityStoreException corrupt) {
                chargeEqualWork();
                audit.recordEvent(AuditEvent.ROW_REJECTED_AS_ABSENT);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // The per-account penalty, checked here rather than before the lookup because its key is
            // the row's primary key: see accountBucketKey. Reading the row is not a decision - the
            // caller still gets one generic sentence and, below, the same cheap refusal whether or
            // not an account exists, because a bucket is created for unknown identifiers too.
            String accountKey = accountBucketKey(identifier, account);
            if (account != null) {
                // Second claim, now that the account is known: it excludes a concurrent attempt
                // against the same account typed the other way, which the form-key claim above
                // cannot see.
                rowKey = accountKey;
                rowClaimed = guard.tryBegin(rowKey);
                if (!rowClaimed) {
                    audit.record(Reason.THROTTLED, identifier);
                    return AuthResult.of(Reason.BAD_CREDENTIAL);
                }
            }
            if (store.isPenaltyActive(SqlIdentityStore.bucketKindAccount(), accountKey, now)) {
                // The account's budget is spent, so this attempt is refused without a derivation -
                // and the caller who made it is still charged against its own source budget. That
                // charge is the answer to the one thing a per-account limit is always open to: an
                // attacker parking a lockout on somebody else's account. Without it, sustaining
                // Alice's lockout is free and a single source can hold it open forever, one guess
                // per penalty expiry; with it, the attacker burns its own per-source allowance at
                // full rate and its source limit trips, after which it can do nothing at all. A
                // distributed attacker that rotates sources still pays that cost per source, which
                // is the same trade every rate limiter makes and README "Limitations" names.
                //
                // What is deliberately NOT charged here is the account bucket itself: chargeFailure
                // recomputes the deadline from the post-increment counter, so charging a bucket that
                // is already in penalty would let the blocked caller deepen its own lockout - the
                // property the check-before-charge ordering exists to prevent.
                chargeSource(source, now);
                audit.record(Reason.THROTTLED, identifier);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            if (account == null) {
                chargeEqualWork();
                chargeBothBuckets(source, accountKey, now);
                audit.record(Reason.ABSENT_ACCOUNT, identifier);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // (5) Verify. A stored credential that fails strict decoding is the same user-visible
            // outcome as "no such account": matchesStored already charged the equal-work dummy
            // before throwing, so this branch also costs a derivation. Only a genuine cryptographic
            // failure propagates - there the service truly cannot decide, and it must not guess.
            boolean ok;
            try {
                ok = hasher.matchesStored(password.chars(), account.passwordHash());
            } catch (IdentityStoreException corrupt) {
                if (corrupt.reason() != Reason.CORRUPT_RECORD) {
                    throw corrupt;
                }
                chargeBothBuckets(source, accountKey, now);
                audit.recordEvent(AuditEvent.ROW_REJECTED_AS_ABSENT);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }
            if (!ok) {
                chargeBothBuckets(source, accountKey, now);
                audit.record(Reason.BAD_CREDENTIAL, identifier);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // (6) Status, only now that the credential is proven.
            if (!"active".equals(account.status())) {
                store.clearBucket(SqlIdentityStore.bucketKindAccount(), accountKey);
                // The audit gets the specific fact; the caller's AuthResult carries the same reason
                // every other sign-in refusal carries. Handing back ACCOUNT_DISABLED here would make
                // the audit log uniform while leaving the distinction one getter call away from a
                // front end - and a front end that shows, returns in a header, or branches on it
                // reopens the exact oracle this ordering exists to close.
                audit.record(Reason.ACCOUNT_DISABLED, identifier);
                return AuthResult.of(Reason.BAD_CREDENTIAL);
            }

            // Verified: reset the per-account counter. The per-source counter is deliberately left
            // alone - clearing it on success would let an attacker who knows one real credential
            // keep their source bucket permanently empty by alternating a correct login with a
            // thousand guesses.
            store.clearBucket(SqlIdentityStore.bucketKindAccount(), accountKey);

            // (7) Transparent cost upgrade, while the candidate is still in hand. Re-encoding is a
            // credential change, so outstanding sessions are revoked with it: a token stolen before
            // the upgrade cannot outlive it.
            if (hasher.needsRehash(account.passwordHash())) {
                try {
                    Password forRehash = Password.copyOf(password.chars());
                    if (forRehash != null) {
                        store.replacePasswordHash(account.id(), hasher.hash(forRehash));
                        store.revokeAllSessions(account.id());
                        audit.recordEvent(AuditEvent.CREDENTIAL_REENCODED);
                    }
                } catch (IdentityStoreException e) {
                    // The user did authenticate. Failing the upgrade must not refuse them - the old
                    // parameters still verify - so the reason is logged and sign-in proceeds.
                    audit.record(e.reason(), identifier);
                }
            }

            SessionToken token = SessionToken.generate(random);
            store.createSession(account.id(), token, now);
            store.deleteExpiredSessions(now);
            audit.record(Reason.AUTHENTICATED, identifier);
            return AuthResult.success(Reason.AUTHENTICATED, token, account.username().canonical());
        } finally {
            if (password != null) {
                password.close();
            }
            if (rowClaimed) {
                guard.end(rowKey);
            }
            guard.end(guardKey);
        }
    }

    // ------------------------------------------------------------------ sessions

    /**
     * Resolves a submitted token against server-side state. Rule 3: a token is a lookup key, not
     * proof. The account's live status is re-read from the row every call, so disabling an account
     * takes effect immediately rather than at the token's next expiry.
     */
    public AuthResult checkSession(String tokenRaw) throws IdentityStoreException {
        long now = time.nowEpochSeconds();
        SessionToken token = SessionToken.parse(tokenRaw);
        if (token == null) {
            // Wrong shape: refuse without a query, so junk cannot be used to probe and costs
            // nothing. Same message as an unknown token, so the shape check is not an oracle.
            audit.record(Reason.MALFORMED_TOKEN, null);
            return AuthResult.of(Reason.INVALID_SESSION);
        }
        SqlIdentityStore.SessionRow row;
        try {
            row = store.resolveSession(token, now);
        } catch (IdentityStoreException corrupt) {
            audit.record(corrupt.reason(), null);
            return AuthResult.of(Reason.INVALID_SESSION);
        }
        if (row == null || !row.live()) {
            audit.record(Reason.INVALID_SESSION, null);
            return AuthResult.of(Reason.INVALID_SESSION);
        }
        if (!"active".equals(row.status())) {
            store.revokeSession(token);
            audit.record(Reason.INVALID_SESSION, row.username());
            return AuthResult.of(Reason.INVALID_SESSION);
        }
        return AuthResult.success(Reason.AUTHENTICATED, null, row.username().canonical());
    }

    /**
     * Revokes one session. The user-visible message is identical whether or not the token was live,
     * so this is not a token-existence oracle; the distinction is kept for the operator.
     */
    public AuthResult revokeSession(String tokenRaw) throws IdentityStoreException {
        SessionToken token = SessionToken.parse(tokenRaw);
        if (token == null) {
            audit.record(Reason.MALFORMED_TOKEN, null);
            return AuthResult.of(Reason.SESSION_REVOKED);
        }
        int removed = store.revokeSession(token);
        audit.record(removed > 0 ? Reason.SESSION_REVOKED : Reason.ALREADY_REVOKED, null);
        return AuthResult.of(Reason.SESSION_REVOKED);
    }

    // ------------------------------------------------------------------ administration

    /**
     * Changes an account's administrative status and revokes its sessions when disabling. Reachable
     * only in-process: no unauthenticated path exposes it, and {@link #signIn} will not tell a
     * caller it happened.
     */
    public AuthResult setAccountStatus(Identity username, String status) throws IdentityStoreException {
        SqlIdentityStore.Account account = store.findByCanonicalIdentity(username);
        if (account == null) {
            return AuthResult.of(Reason.ABSENT_ACCOUNT);
        }
        store.setStatus(account.id(), status);
        if (!"active".equals(status)) {
            store.revokeAllSessions(account.id());
        }
        audit.recordEvent(AuditEvent.STATUS_CHANGED);
        return AuthResult.of(Reason.ACCOUNT_CREATED);
    }

    // ------------------------------------------------------------------ operational reads

    public int liveSessionCount() throws IdentityStoreException {
        store.deleteExpiredSessions(time.nowEpochSeconds());
        return store.countSessions();
    }

    public int accountCount() throws IdentityStoreException {
        return store.countAccounts();
    }

    public int throttleRowCount() throws IdentityStoreException {
        return store.countThrottleRows();
    }

    /**
     * Security events that could not be written because the audit log was unwritable at a point where
     * the operation's outcome was already fixed. Surfaced by {@code status} so a full or blocked log is
     * operator-visible rather than a silently empty trail; always zero on a healthy filesystem.
     */
    public long unrecordedAuditEvents() {
        return audit.unrecordedEvents();
    }

    public java.util.List<String> startupWarnings() {
        return store.startupWarnings();
    }

    /** For tests: the validated config in force. Never contains a user secret. */
    public Config config() {
        return config;
    }

    // ------------------------------------------------------------------ helpers

    /** An identifier may be either form. Whichever parses, parses; never a merge of the two. */
    private static Identity parseIdentifier(String raw) {
        Identity byEmail = Identity.parseClientEmail(raw);
        if (byEmail != null) {
            return byEmail;
        }
        return Identity.parseClientUsername(raw);
    }

    /**
     * The per-account bucket key.
     *
     * <p>Keyed by the row's primary key whenever a row was found, and only by the submitted
     * identifier's canonical form when there is none. Keying it on the canonical form <em>always</em>
     * was the earlier shape, and it gave one account two independent budgets - the username spelling
     * and the email spelling are different strings - so an attacker could hold one blocked while
     * guessing the other, and a verified sign-in cleared whichever form the user happened to type
     * rather than the one that was under attack. The primary key is one per account by construction,
     * and the account cannot change its own bucket key the way it can change the email on its own
     * account.
     *
     * <p>For an identifier with no account the key is the canonical form, which is the only thing
     * available and is stable, so a spray of the same non-existent address still accumulates one
     * counter instead of none.
     */
    private static String accountBucketKey(Identity identifier, SqlIdentityStore.Account account) {
        if (account != null) {
            return "id:" + account.id();
        }
        return identifier.kind() + ":" + identifier.canonical();
    }

    private void chargeEqualWork() throws IdentityStoreException {
        // Propagates rather than swallowing: if the JCE lost PBKDF2 the equal-work guarantee is
        // gone, and a refusal must not quietly become a success path.
        hasher.chargeDummy();
    }

    /**
     * Charges the caller's own origin. Used on the two branches that never reach an account bucket -
     * a candidate that fails policy and a malformed identifier - so that neither is a way to spend
     * this process's CPU with no counter anywhere recording it. Both still cost a derivation, so
     * without this charge the source limit is bypassable by sending only malformed identifiers.
     */
    private void chargeSource(SourceId source, long now) throws IdentityStoreException {
        SqlIdentityStore.Throttle charge =
                store.chargeFailure(SqlIdentityStore.bucketKindSource(), source.canonical(), now);
        if (charge.blocked()) {
            audit.recordEvent(AuditEvent.THROTTLE_ENGAGED);
        }
    }

    /**
     * Charges source then account. The account leg is keyed by {@link #accountBucketKey}, the source
     * leg by the canonical origin, so the pair is stable across identifier spellings and sources.
     */
    private void chargeBothBuckets(SourceId source, String accountKey, long now)
            throws IdentityStoreException {
        SqlIdentityStore.Throttle sourceCharge =
                store.chargeFailure(SqlIdentityStore.bucketKindSource(), source.canonical(), now);
        SqlIdentityStore.Throttle accountCharge =
                store.chargeFailure(SqlIdentityStore.bucketKindAccount(), accountKey, now);
        if (sourceCharge.blocked() || accountCharge.blocked()) {
            // Recorded so an operator can see a lockout engage, without recording who.
            audit.recordEvent(AuditEvent.THROTTLE_ENGAGED);
        }
    }

    @Override
    public void close() {
        store.close();
        audit.close();
    }
}
