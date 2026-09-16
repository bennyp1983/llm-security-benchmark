# Security Review: AuthService (Java 17 password authentication + audit log)

## 1. Executive Summary

`AuthService.java` is a self-contained, dependency-free Java 17 authentication module: it accepts a
username and password, verifies the credential against a stored `pbkdf2-sha256$<iters>$<salt>$<digest>`
record, enforces a consecutive-failure lockout, and writes exactly one machine-readable audit record
per attempt through `java.util.logging`. It also exposes administrative operations (`register`,
`setStatus`, `unlock`) and a runnable demo (`AuthService.main`). `AuthServiceTest.java` is a
framework-free verification suite (242 checks) that pins most of the documented security properties,
including equal-cost refusal and log-injection resistance.

This is unusually well-built code for its size: the credential handling, the escaping of
attacker-controlled log fields, the KDF usage, and the anti-enumeration design all hold up under
review, and several properties that are normally only asserted in prose are actually tested.

The most important findings are:

1. **SEC-01 (High)** — a successful login writes back a *stale whole-record snapshot* that it read
   before an ~85 ms key derivation, using an unconditional `put`. A `DISABLED` / `LOCKED_BY_ADMIN`
   status change (or a deletion) performed while the derivation runs is silently reverted to `ACTIVE`,
   so containment can be undone by the victim's own next correct login. The class has an explicit
   helper (`recordFor`) whose own javadoc warns about "racing another writer into oblivion", but the
   success path does not use it.
2. **SEC-02 (High)** — `register`, `setStatus` and `unlock` carry **no authorization check**. The
   source comment calls register "an administrative path", and `operator` is a free-text string the
   caller types, so anyone holding the service reference can create accounts, disable real ones, or
   lift a lockout — and can pick the name recorded as the actor in the audit trail.
3. **SEC-03 / SEC-05 (Medium)** — brute-force defence is *only* a per-account lockout held in
   process-local memory: there is no per-source or per-session budget (password spraying across many
   usernames is unimpeded), the same counter lets an attacker lock a known user out with five wrong
   guesses, and every attempt is charged the *stored* record's iteration count up to 20,000,000 with
   no concurrency cap, which turns unauthenticated logins into a CPU-amplification primitive.
4. **SEC-04 (Medium)** — the shipped cost policy is weak for a PBKDF2 deployment: 310,000 iterations
   as the default and 60,000 in the runnable path (`DEMO_ITERATIONS`, used by `AuthService.main` and
   the README example), against OWASP's current 600,000 floor for PBKDF2-HMAC-SHA256, and there is no
   rehash-on-login despite the format carrying a per-record cost.

Also reported: the public `String`-password overload that admits un-erasable secrets into the heap
(SEC-06), an unbounded relative-path audit file (SEC-07), internal detail escaping through an
unchecked exception (SEC-08), silently droppable audit records (SEC-09), hard-coded demo credentials
(SEC-10), and predictable administrative audit ids (SEC-11).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `AuthService.java` (1557 lines) | Authentication service: `login`, `register`, `setStatus`, `unlock`; `PasswordHasher` (PBKDF2-HMAC-SHA256), `StoredDigest` (record format), `PasswordRules`, `Username`, `AccountRecord`/`AccountStore`/`InMemoryAccountStore`, `InMemoryFailureTracker`, `AuthAuditLogger`/`IsoLogFormatter`/`LogValue`, plus the `AuthenticationDemo` runnable from `main`. | Credential verification, password storage/KDF parameters, account lockout, account state transitions, audit-log construction and escaping, in-memory state, secret erasure, hard-coded demo credentials, log-file path. |
| `AuthServiceTest.java` (1297 lines) | Framework-free verification suite, 242 checks (`java -cp out AuthServiceTest`). | No production behaviour. Confirms equal-cost timing (line 870, `TIMED_ITERATIONS = 60_000` at line 49), log escaping, secret wipes via reflection (lines 748, 762). Reviewed for claims that are *not* covered — see SEC-04/SEC-05. |
| `README.md` | Design documentation: log field legend, security-property table, mutation-test battery, known limitations. | No code. Used to check documented intent against the implementation; its "Known limitations" list already anticipates SEC-03 and part of SEC-04/SEC-07. |
| `prompt.txt`, `prompt_hash.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` | Task/run metadata for how this module was generated. | Not code; no executable content; out of scope for vulnerability analysis. |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher` (`encode`, `verify`,
  `derive`, `deriveEncoded`, `newSalt`, `digestHex`), `StoredDigest.parse`, and the KDF constants at
  `AuthService.java:451-457` — primitive choice, mode, salt/IV entropy, hard-coded keys, weak KDF
  parameters, comparison method. Produced SEC-04 and SEC-05; the primitive/salt/digest/comparison
  checks are clean (§6).
- `testing-api-authentication-weaknesses`: applied to the `login()`/`register()` surface — password
  policy (`AuthService.java:621-622`, `658-666`), the account-enumeration channels (subject-facing
  message, per-attempt timing, `LoginResult.internalReason()`), and credential/session handling
  (`LoginRequest`). Produced SEC-04, SEC-06, SEC-08.
- `exploiting-broken-function-level-authorization`: applied as administrative-endpoint discovery plus
  role-based function testing over `register` (`:253`, `:258`), `setStatus` (`:278`) and `unlock`
  (`:289`) — the class's own javadoc labels register "an administrative path" while nothing enforces
  it. Produced SEC-02.
- `implementing-api-rate-limiting-and-throttling`: applied to the anti-brute-force posture around
  `login()` — per-user/per-IP/per-endpoint budgets, and to the cost of a single unauthenticated
  request. Produced SEC-03 and SEC-05.
- `performing-hash-cracking-with-hashcat`: applied to the stored format
  `pbkdf2-sha256$<iters>$<b64salt>$<b64digest>` (hashcat `-m 10000`) to size the offline cost of the
  60,000 and 310,000 iteration settings actually shipped. Supported SEC-04.
- `testing-for-email-header-injection`: used as the CRLF/header-injection analogue against the audit
  sink — `AuthAuditLogger.emit` and `LogValue.escape` (`:1264-1277`, `:1299-1350`). No finding: the
  escaping is complete and provably so (§6).

Any behaviour reviewed against general OWASP Top 10 / CWE knowledge because no skill matched.
Specifically: the read-modify-write race on account state (SEC-01), plaintext secret retention in an
insecure-by-construction API (SEC-06), audit-file path/size and resource exhaustion (SEC-07),
information disclosure through exception messages (SEC-08), silently suppressed audit records
(SEC-09), hard-coded credentials in a demo entry point (SEC-10), and predictable correlation
identifiers (SEC-11).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Successful login resurrects an account an administrator disabled mid-attempt | High | CWE-367 | `AuthService.java:217` |
| SEC-02 | No authorization check on `register`, `setStatus` or `unlock` | High | CWE-862 | `AuthService.java:278` |
| SEC-03 | Only per-account lockout: no per-source budget, and lockout is a free account DoS | Medium | CWE-307 | `AuthService.java:1048` |
| SEC-04 | KDF cost below current guidance, with no rehash-on-login | Medium | CWE-916 | `AuthService.java:455` |
| SEC-05 | A stored record can demand 20M iterations per unauthenticated login | Medium | CWE-400 | `AuthService.java:519` |
| SEC-06 | Public `String`-password overload admits un-erasable secrets to the heap | Medium | CWE-316 | `AuthService.java:330` |
| SEC-07 | Audit log written to an unbounded relative file | Medium | CWE-770 | `AuthService.java:1543` |
| SEC-08 | Internal parse details escape `login()` in an unchecked exception message | Low | CWE-209 | `AuthService.java:170` |
| SEC-09 | Audit records are silently dropped when the logger level filters them | Low | CWE-778 | `AuthService.java:1266` |
| SEC-10 | Hard-coded password in the same source file as the library, used by `main` | Low | CWE-798 | `AuthService.java:1432` |
| SEC-11 | Predictable `attempt` id on administrative audit records | Low | CWE-340 | `AuthService.java:1259` |

## 5. Detailed Findings

### SEC-01: Successful login resurrects an account an administrator disabled mid-attempt

- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `AuthService.java:187,213-217` (with `:888-890` and `:913,945-947`)
- **Vulnerable code:**

```java
// AuthService.java:213-217
            // ---- success ------------------------------------------------------------------------
            InMemoryFailureTracker.State cleared =
                    failures.registerSuccess(record.accountId(), clock.instant());
            ctx.consecutiveFailures(cleared.consecutiveFailures());
            accounts.store(record.withSuccessfulLogin(clock.instant(), request.sourceIp()));
```

- **Why it is a problem:** `record` is a snapshot taken at line 187, *before* the key derivation at
  line 150, which costs roughly 85 ms at the demo's iteration count and hundreds of milliseconds at
  the production default. `withSuccessfulLogin` (`:888-890`) builds a new record that carries
  `status` and `passwordHash` **from that stale snapshot**, and `AccountStore.store` is documented as
  an "Unconditional replace" (`:913`, implemented as a plain `byUsername.put` at `:945-947`). So if an
  administrator calls `setStatus("mallory", DISABLED, ...)` (or a deprovisioning job removes the
  account) during that window — precisely the window in which a real containment action is likely,
  because the same user is being investigated — the derivation finishes and the success path writes
  the pre-derivation record back: `status` reverts to `ACTIVE`, and the disable is erased with no
  audit trace of its own. On a JDBC or directory store behind the same interface the same lost update
  applies (`UPDATE ... SET status=?, ...` with no `WHERE status='ACTIVE'` guard). The code already
  knows this is the hazard: `AccountStore.recordFor` exists so a writer can act on "the record exactly
  as stored ... without racing another writer into oblivion" (`:915-919`), but `login()` never uses
  it. `setStatus` itself (`:279-280`) is subject to the mirror-image race: a concurrent success can
  be clobbered, or the status change can be lost.
- **Fix:** stop writing whole records from a stale snapshot. Give the store a column-scoped,
  compare-and-set operation for the login context, and treat "the row is no longer usable" as a
  refusal:

```java
// AuthService.java: AccountStore gains a conditional, column-scoped update (replacing store()).
/** Update only the last-success columns, and only if the row still exists with this id and is ACTIVE. */
boolean recordSuccessfulLogin(AccountRecord expected, Instant when, String ip);
```

```java
// AuthService.java: InMemoryAccountStore implementation. A JDBC store writes the equivalent
// UPDATE account SET last_success_at=?, last_success_ip=?
//  WHERE username=? AND account_id=? AND status='ACTIVE'
// and treats 0 affected rows as false.
@Override
public synchronized boolean recordSuccessfulLogin(AccountRecord expected, Instant when, String ip) {
    AccountRecord current = byUsername.get(expected.username());
    if (current == null
            || !current.accountId().equals(expected.accountId())
            || current.status() != AccountStatus.ACTIVE) {
        return false;                     // disabled, deleted or re-keyed while the KDF ran
    }
    byUsername.put(current.username(), current.withSuccessfulLogin(when, ip));
    return true;
}
```

```java
// AuthService.java: login() success path replaces line 217. The derivation has already run, so this
// costs nothing extra and does not disturb the equal-timing property.
if (!accounts.recordSuccessfulLogin(record, clock.instant(), request.sourceIp())) {
    // SEVERE audit record: an operator revoked this account during the attempt.
    audit.accountStateChangedDuringAttempt(ctx, elapsedMs(startedAtNanos));
    return refuse(ctx, "account-state-changed-mid-attempt", startedAtNanos);
}
```

`setStatus` should be reworked the same way: read with `recordFor`, then swap only the status column
(`replaceStatus(expected, newStatus)`), so it neither loses nor resurrects concurrent writes.

### SEC-02: No authorization check on `register`, `setStatus` or `unlock`

- **Severity:** High
- **CWE:** CWE-862: Missing Authorization
- **Location:** `AuthService.java:277-293` (also `:249-251`, `:253`, `:258`)
- **Vulnerable code:**

```java
// AuthService.java:277-293
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
```

- **Why it is a problem:** these are the three operations that decide who has an account and who is
  locked out, and none of them asks whether the caller is allowed to do it. They are `public` on the
  same object an unprivileged web handler calls `login()` on, so any code path that can reach the
  service — a support screen, an internal script, a handler that was only meant to authenticate — can
  mint an `ACTIVE` account (`register`, whose javadoc at `:249-251` merely *declares* it "an
  administrative path"), disable anyone, or clear a lockout that a defender just applied. Because
  `unlock` clears the failure counter, an attacker with valid-but-lockable credentials can keep their
  own guessing loop running indefinitely. The `operator` parameter makes it worse for forensics: it is
  a caller-supplied string, so the `ACCOUNT_STATUS_CHANGED`/`ACCOUNT_UNLOCKED` records attribute the
  action to whatever name the caller typed — the audit trail is non-repudiable only in the direction
  that favours the attacker. This is the OWASP API Top 10 "broken function level authorization"
  pattern: the sensitive function exists, and access control was left to the caller's politeness.
- **Fix:** take an authenticated principal rather than a name, check the capability before acting,
  and audit the principal the platform authenticated:

```java
// AuthService.java: actor is built by the caller from an authenticated session/Subject,
// never from a request parameter.
public void setStatus(AdminPrincipal actor, String rawUsername, AccountStatus status) {
    Objects.requireNonNull(actor, "actor");
    if (!actor.hasCapability(Capability.ACCOUNT_STATUS_CHANGE)) {
        audit.administrationDenied(actor.authenticatedName(), "setStatus", rawUsername, clock.instant());
        throw new SecurityException("actor is not permitted to change account status");
    }
    AccountRecord record = requireAccount(rawUsername);
    if (!accounts.replaceStatus(record, status)) {            // see SEC-01
        throw new IllegalStateException("account changed concurrently, status not applied");
    }
    if (status != AccountStatus.ACTIVE) {
        failures.clear(record.accountId());
    }
    audit.accountStatusChanged(record.accountId(), record.status(), status,
            LogValue.escape(actor.authenticatedName(), 64), clock.instant());
}
```

Apply the same gate to `register` (`Capability.ACCOUNT_CREATE`) and `unlock`
(`Capability.ACCOUNT_UNLOCK`), and delete the `String operator` overloads so the unauthenticated name
cannot be recorded as the actor.

### SEC-03: Only per-account lockout: no per-source budget, and lockout is a free account DoS

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AuthService.java:1048-1058` (charged from `:156-158`, `:198-201`)
- **Vulnerable code:**

```java
// AuthService.java:1048-1058
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
```

- **Why it is a problem:** the only attempt-counting state is keyed by `accountId`. There is no
  counter for the source address or session anywhere in the authentication path, so a password spray
  — one guess per account across thousands of usernames from one host — never accumulates enough
  failures on any single account to trip anything. `README.md` states this as a deliberate boundary
  ("**No rate limiting per source address or per session** — only per-account lockout. A slow
  credential-stuffing run spread across many usernames is not impeded"), which makes it a documented
  limitation of the *library*, but the code as shipped has no hook for the compensating control, and
  every unthrottled attempt still costs a full PBKDF2 derivation (SEC-05). The same control is
  attacker-triggerable in the other direction: `maxConsecutiveFailures` (5 in the demo) wrong guesses
  for a *known username* denies that user access for the whole `lockout` window, repeatedly — an
  account-lockout denial of service that also hides an intrusion, because the victim's real login is
  refused as `account-locked`. Finally, `byAccountId` is process-local
  (`ConcurrentHashMap`, `:1010`): restarting the service or adding a second instance clears every
  lockout, so the control is advisory in any deployment that is not single-process.
- **Fix:** put a per-source budget in front of the KDF, keep the public message identical, and move
  the counters to shared state with a TTL. Charge the throttled path the dummy derivation so the new
  fast-fail does not become a new timing class:

```java
// AuthService.java: sliding-window budget per source address, checked before any derivation.
public LoginResult login(LoginRequest request) {
    final Instant now = clock.instant();
    if (!sourceBudget.allow(request.sourceIp(), now)) {          // e.g. 30 attempts / 10 minutes
        char[] probe = request.passwordCopy();
        try {
            hasher.verify(probe, hasher.dummyEncoded());          // keep the cost uniform (see README)
        } finally {
            Arrays.fill(probe, '\0');
        }
        LoginContext ctx = new LoginContext(newHexId(6), request.sourceIp(),
                request.sessionId(), request.userAgent());
        return refuse(ctx, "source-throttled", System.nanoTime());
    }
    return authenticate(request);
}
```

```java
// SourceBudget: shared (Redis/JDBC) in a real deployment so a restart or a second node cannot
// reset it, with a TTL on each key.
static final class SourceBudget {
    private final Map<String, Deque<Instant>> hits = new ConcurrentHashMap<>();
    private final int maxAttempts;
    private final Duration window;

    boolean allow(String ip, Instant now) {
        if (ip == null) {
            return false;                       // unknown transport address: fail closed
        }
        Deque<Instant> q = hits.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && q.peekFirst().isBefore(now.minus(window))) {
                q.removeFirst();
            }
            if (q.size() >= maxAttempts) {
                return false;
            }
            q.addLast(now);
            return true;
        }
    }
}
```

Prefer progressive backoff per source over a hard account lock (or require an administrative unlock
plus a source budget) so that lockout stops being a cheap way to silence a known user.

### SEC-04: KDF cost below current guidance, with no rehash-on-login

- **Severity:** Medium
- **CWE:** CWE-916: Password Hashing with Insufficient Work Factor
- **Location:** `AuthService.java:455` (demo value at `:1433`, `:1443`)
- **Vulnerable code:**

```java
// AuthService.java:451-457
        static final String KDF = "PBKDF2WithHmacSHA256";
        static final String PREFIX = "pbkdf2-sha256";
        static final int SALT_BYTES = 16;
        static final int DIGEST_BYTES = 32;
        static final int DEFAULT_ITERATIONS = 310_000;
        static final int MIN_ITERATIONS = 1_000;
        static final int MAX_ITERATIONS = 20_000_000;
```

- **Why it is a problem:** the only barrier between a stolen record store and offline recovery is the
  iteration count. OWASP's current password-storage guidance puts PBKDF2-HMAC-SHA256 at a minimum of
  600,000 iterations (and recommends Argon2id or scrypt instead), so `DEFAULT_ITERATIONS = 310_000`
  is roughly half the advised floor. The runnable path is much worse: `DEMO_ITERATIONS = 60_000`
  (`:1433`) is what `AuthService.main` wires up (`:1443`) and what the README's copy-paste example
  shows, i.e. the value a reader is most likely to inherit. At 60,000 iterations a single modern GPU
  (`hashcat -m 10000`) tests PBKDF2-SHA256 at millions of guesses per second, which makes the
  12-character enrolment minimum (SEC-06 of `PasswordRules`, `:621`) the only remaining defence — and
  a 12-character passphrase from a breached-wordlist corpus is well inside that budget. Two structural
  gaps make the exposure persistent rather than one-time: nothing ever rehashes a record whose stored
  cost is below today's policy even though the format carries a per-record cost and `login()` holds
  the plaintext candidate at that exact moment, and `MIN_ITERATIONS = 1_000` accepts a record 600×
  cheaper than the default without a word (the README claims this constant "guards against a record
  importing a cost that is too cheap to accept" — at 1,000 iterations it does not).
- **Fix:** raise the policy floor to current guidance and rehash upward on the next successful login,
  using the CAS write from SEC-01:

```java
// AuthService.java:455-457
        static final int DEFAULT_ITERATIONS = 600_000;   // OWASP floor for PBKDF2-HMAC-SHA256
        static final int MIN_ITERATIONS = 1_000;         // parse-compatibility for legacy rows only
        static final int MAX_ITERATIONS = 1_200_000;     // a single attempt may not cost more
        static final int MIN_ACCEPTED_ITERATIONS = 600_000;  // never *authenticate* below this
```

```java
// AuthService.java: in login(), immediately after the successful match and before the finally wipe.
if (verification.matched() && verification.iterationsUsed() < PasswordHasher.MIN_ACCEPTED_ITERATIONS) {
    AccountRecord upgraded = record.withPasswordHash(hasher.encode(candidate));   // candidate still live
    if (!accounts.replaceCredential(record, upgraded)) {
        ctx.detail("kdfUpgrade", "skipped-race");        // retried on the next login; never fatal
    } else {
        ctx.detail("kdfUpgrade", verification.iterationsUsed() + "->" + hasher.policyIterations());
    }
}
```

Set `DEMO_ITERATIONS = 600_000` (`:1433`) so the runnable path is not the weak example, and use the
`policy=` field the audit line already carries to spot rows that are still below policy. The correct
long-term fix is to move `KDF` to Argon2id behind the existing `kdf` field, which the format already
supports.

### SEC-05: A stored record can demand 20M iterations per unauthenticated login

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `AuthService.java:519` (bound at `:457`, accepted by `:710-712`)
- **Vulnerable code:**

```java
// AuthService.java:513-521
        public Verification verify(char[] candidate, String storedDigest) {
            StoredDigest stored = StoredDigest.parse(storedDigest);
            boolean candidateUsable = PasswordRules.rejectCandidate(candidate).isEmpty();

            char[] effective = candidateUsable ? candidate : dummyPassword;
            byte[] salt = stored != null ? stored.salt : dummySalt;
            int rounds = stored != null ? stored.iterations : iterations;

            byte[] derived = derive(effective, salt, rounds);
```

- **Why it is a problem:** the work factor charged for an authentication attempt is taken from the
  *stored record*, and `StoredDigest.parse` accepts anything up to `MAX_ITERATIONS = 20_000_000`
  (`:710-712`). The service therefore has no upper bound on the CPU cost of a single unauthenticated
  request: 20M PBKDF2-HMAC-SHA256 iterations is on the order of five seconds of one core, versus
  ~85 ms for the demo cost — a ~60× amplification factor per request. There is no semaphore, queue
  bound, or timeout around `derive`, and (per SEC-03) no request budget, so N concurrent attempts for
  a high-cost account pin N cores and take the whole service down; `elapsedMs` on the audit line shows
  the attempt simply being slow. Who can raise a record's cost? Any write path into the store — a
  bulk import, a migration, a directory sync, an operator hand-editing a row, or an attacker who has
  already obtained write access and wants to blind the service — and because `store()` accepts whole
  records unconditionally (SEC-01), nothing re-validates the cost against service policy on the way
  in. `register()` adds a second, self-inflicted instance of the same amplification: `hasher.encode`
  runs at the full policy cost *before* the duplicate-name check at `:270`, so with SEC-02 left
  unfixed an unauthenticated caller can burn `DEFAULT_ITERATIONS` of CPU per rejected registration
  attempt.
- **Fix:** decouple the cost charged at authentication time from the cost a record claims, and bound
  concurrency. Records above the ceiling are refused and must be re-enrolled, not honoured:

```java
// AuthService.java: verify() — never charge more than the service's own ceiling.
int claimed = stored != null ? stored.iterations : iterations;
int rounds = Math.min(claimed, PasswordHasher.MAX_CHARGED_ITERATIONS);
if (claimed > PasswordHasher.MAX_CHARGED_ITERATIONS) {
    // Refuse rather than honour: the row is unauthenticated-by-policy, not merely expensive.
    return new Verification(false, "iterations-above-policy", rounds);
}
```

```java
// AuthService.java: bound concurrent derivations so slow rows cannot occupy every worker.
private final Semaphore derivationSlots =
        new Semaphore(Runtime.getRuntime().availableProcessors() * 2, true);

// ... in login(), around line 150:
if (!acquireSlot(derivationSlots, Duration.ofSeconds(2))) {
    return refuse(ctx, "server-busy", startedAtNanos);   // same GENERIC_FAILURE_MESSAGE
}
try {
    verification = hasher.verify(candidate, chargedDigest);
} finally {
    derivationSlots.release();
}
```

Also move the uniqueness check before the derivation in `register()`: `if (accounts.exists(name.normalized())) { throw new IllegalArgumentException("account already exists"); }` ahead of `hasher.encode(password)` at `:267`, keeping `putIfAbsent` at `:270` as the race-free final word.

### SEC-06: Public `String`-password overload admits un-erasable secrets to the heap

- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in a Memory Region
- **Location:** `AuthService.java:330-334`
- **Vulnerable code:**

```java
// AuthService.java:330-334
        /** Convenience overload. A String password cannot be erased from the heap; prefer char[]. */
        public LoginRequest(String rawUsername, String password, String sourceIp,
                            String sessionId, String userAgent) {
            this(rawUsername, password == null ? new char[0] : password.toCharArray(),
                    sourceIp, sessionId, userAgent);
        }
```

- **Why it is a problem:** the module's first documented property is that passwords travel as
  `char[]` so they can be erased instead of waiting for the garbage collector, and the whole design is
  built around that (defensive copies at `:321-327`, `passwordCopy()` at `:341`, `destroy()` at `:351`,
  the `finally` wipe at `:223`, the redacted `toString()`s). This `public` overload quietly voids that
  property for any caller who uses it: the secret is already an immutable `String` in the caller's
  frame — interned or not, unreachable-but-not-zeroed, and visible in heap dumps, crash dumps and
  thread/serialisation traces — and no amount of downstream `Arrays.fill` can recover it. The javadoc
  warns about it, but a warning is not a control: the overload is `public`, discoverable, and used by
  the module's own demo (`:1470`, `:1478`, `:1487`), which is the code most readers will copy. In
  practice it turns a memory-forensics-hardened design back into the ordinary "password lives in a
  `String` until the GC feels like it" design, one autocomplete away.
- **Fix:** delete the overload from the public API; the pattern the caller needs is a convert-and-wipe
  at *their* boundary, which `LoginRequest`'s defensive copy already permits:

```java
// AuthService.java: the overload is removed. Callers that only hold a String convert once and
// erase their own array immediately, because the request keeps its own copy.
char[] secret = password.toCharArray();
try {
    LoginRequest request = new LoginRequest(rawUsername, secret, sourceIp, sessionId, userAgent);
    return service.login(request);
} finally {
    Arrays.fill(secret, '\0');       // caller-owned: safe to wipe as soon as the copy exists
}
```

If a migration period requires keeping it, mark it `@Deprecated(forRemoval = true)` and
`@ApiStatus.Internal`-style documented as test-only, and stop using it in `AuthenticationDemo`.

### SEC-07: Audit log written to an unbounded relative file

- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `AuthService.java:1543` (fallback behaviour at `:1276-1277`, `:1293-1295`)
- **Vulnerable code:**

```java
// AuthService.java:1542-1546
            // append=true: an audit log that restarts the process must not lose its history.
            FileHandler file = new FileHandler("auth.log", true);
            file.setLevel(Level.ALL);
            file.setFormatter(formatter);
            logger.addHandler(file);
```

- **Why it is a problem:** the audit sink is the module's security control — every authentication
  decision, lockout, and admin action lands here — and it is configured with the two-argument
  `FileHandler` constructor: a *relative* path resolved against the process working directory, in
  append mode, with **no size limit and no file count**. Every rejected login appends a line, and per
  SEC-03 nothing limits rejected logins, so an unauthenticated attacker grows the file at will until
  the filesystem is full; the same `FileHandler` also writes on `ACCOUNT_CREATED`/status records, so
  an attacker who can reach `register()` (SEC-02) can grow it faster. When the disk fills or the
  directory becomes un writable, `FileHandler.publish` throws `IOException`, which `AuthAuditLogger.emit`
  swallows by falling back to `LOG.log(...)` on the *application* logger (`:1293-1295`) — the audit
  trail then silently continues in a different file, in a different format, without the `IsoLogFormatter`
  fields that the collector and the README's field legend depend on. Separately, a
  service-relative `auth.log` in an attacker-influenced working directory is a symlink/overwrite
  target, and a security log that lives only on the compromised host is erased by whoever has the
  least interest in it being read.
- **Fix:** take the path from trusted configuration, bound the file set, and fail loudly instead of
  quietly changing sinks:

```java
// AuthService.java: absolute, configured path with a bounded rotating file set.
String path = System.getProperty("auth.audit.file", "/var/log/auth-service/audit.log");
// 24 files x 32 MB, append: a failed-login flood costs a bounded 768 MB and rolls over.
FileHandler file = new FileHandler(path + ".%g", 32 * 1024 * 1024, 24, true);
file.setLevel(Level.ALL);
file.setFormatter(formatter);
logger.addHandler(file);
// Ship it off-host so local tampering cannot delete the evidence:
//   SocketHandler / rsyslog forwarder / sidecar tailing the rotated set.
```

```java
// AuthService.java: emit() must not degrade the audit record silently.
private void emit(String event, String outcome, String reason, Level level,
                  List<String[]> fields, long elapsedMs) {
    ...
    try {
        logger.log(level, line.toString());
    } catch (RuntimeException auditSinkFailed) {
        // An authentication decision that cannot be recorded is an availability event for the
        // security control itself: alarm, and let the operator decide whether logins may continue.
        ALARM.log(Level.SEVERE, "audit record not written: " + event, auditSinkFailed);
    }
}
```

### SEC-08: Internal parse details escape `login()` in an unchecked exception message

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `AuthService.java:164-171` (same pattern at `:575`)
- **Vulnerable code:**

```java
// AuthService.java:164-171
            if (verification.storedRecordError() != null) {
                // A corrupt stored credential is an operator problem, not a credential problem. It
                // must not be answered with "wrong password", because the account cannot be judged
                // and silently refusing it would hide a broken import or a tampered row.
                ctx.detail("recordError", verification.storedRecordError());
                audit.credentialRecordCorrupt(ctx, elapsedMs(startedAtNanos));
                throw new AuthenticationDataException("stored credential for attempt " + attemptId
                        + " could not be parsed: " + verification.storedRecordError());
            }
```

- **Why it is a problem:** the intent is right — a broken row must not look like a wrong password —
  but the mechanism puts operator-internal detail into an unchecked exception that escapes the
  authentication API. `AuthenticationDataException extends RuntimeException`, and `login()` is the
  method a transport layer calls directly; any servlet/Spring/JAX-RS handler without an explicit
  mapper for it renders the message (or a stack trace containing it) to the subject. The message
  carries the specific parse failure code produced by `StoredDigest.parse` (`unknown-kdf`,
  `digest-length-20`, `non-base64-material`, `iterations-out-of-range`, …), which tells a caller that
  the account exists *and* how its credential record is malformed — the enumeration signal the whole
  `GENERIC_FAILURE_MESSAGE` design exists to suppress, reintroduced through the exception channel.
  The same class is thrown from `PasswordHasher.derive` as
  `"password hashing unavailable (" + KDF + ")"` (`:575`), so a JDK-level fault also surfaces as an
  unwrapped runtime exception from `login()`, breaking its "one of exactly two sentences" contract.
  Note that the audit record is already written before the throw, so nothing is lost operationally by
  returning instead of throwing.
- **Fix:** keep the detail on the audit line, where it is useful, and hand the subject the generic
  sentence; if the caller must distinguish the fault, use a status, not a message string:

```java
// AuthService.java:164-171 becomes:
if (verification.storedRecordError() != null) {
    ctx.detail("recordError", verification.storedRecordError());   // SEVERE line carries the detail
    audit.credentialRecordCorrupt(ctx, elapsedMs(startedAtNanos));
    // Same GENERIC_FAILURE_MESSAGE and the same one-derivation cost as every other refusal:
    // no parse code, no attempt id, nothing enumerable.
    return refuse(ctx, "stored-credential-unparsable", startedAtNanos);
}
```

```java
// AuthService.java: LoginStatus gains the third value, so a caller that needs to alarm on a broken
// import can branch without parsing an exception message:
public enum LoginStatus {
    AUTHENTICATED,
    REJECTED,
    /** The credential could not be evaluated at all; alert on it, never render it. */
    SERVICE_FAULT
}
```

### SEC-09: Audit records are silently dropped when the logger level filters them

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `AuthService.java:1264-1268`
- **Vulnerable code:**

```java
// AuthService.java:1264-1268
        private void emit(String event, String outcome, String reason, Level level,
                          List<String[]> fields, long elapsedMs) {
            if (!logger.isLoggable(level)) {
                return;
            }
```

- **Why it is a problem:** `AuthAuditLogger` is the record of every authentication decision, and the
  very first thing it does is ask an ambient, globally mutable configuration object whether the record
  is wanted. `Logger.isLoggable` consults the effective level of the `auth.audit` logger, which is
  inherited from the root logger and influenced by `logging.properties`, `-Djava.util.logging.config.file`,
  `LogManager.readConfiguration()` calls, and anything in the host application that raises the JUL
  level to reduce noise. The demo's `configureLogging` sets `Level.ALL` on the named logger, so the
  tests and the shipped scenario never show it, but a deployment that configures JUL *after* the
  service is constructed — or that simply sets the root level to `WARNING` — makes every INFO
  `AUTH_SUCCESS`/`AUTH_FAILURE` record vanish with no error, no counter and no trace, which is exactly
  the failure mode an intruder wants and indistinguishable from "nobody logged in".
- **Fix:** the level belongs to the handler, not to the decision to produce a record. Remove the
  guard, pin the named logger so it cannot inherit a silencing level, and alarm if no handler can
  accept records:

```java
// AuthService.java: emit() always builds and hands the record over; handlers filter, not the logger.
private void emit(String event, String outcome, String reason, Level level,
                  List<String[]> fields, long elapsedMs) {
    StringBuilder line = new StringBuilder(320);
    ...
    logger.log(level, line.toString());
}

// ... and where the logger is constructed, make the level non-inheritable:
Logger audit = Logger.getLogger("auth.audit");
audit.setLevel(Level.ALL);
audit.setUseParentHandlers(false);      // a host application's root level can no longer mute it
if (!audit.isLoggable(Level.INFO) || audit.getHandlers().length == 0) {
    throw new IllegalStateException("audit sink is not usable: refusing to authenticate unlogged");
}
```

### SEC-10: Hard-coded password in the same source file as the library, used by `main`

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AuthService.java:1432` (consumed at `:1443`, `:1447`, `:1470`, `:1492`)
- **Vulnerable code:**

```java
// AuthService.java:1432-1434
        private static final String DEMO_PASSWORD = "correct-horse-battery";
        private static final int DEMO_ITERATIONS = 60_000;
        private static final int LOCK_AFTER = 5;
```

- **Why it is a problem:** `alice` is created with `DEMO_PASSWORD` (`:1447`) and every scenario login
  replays the same literal, so the credential is permanent, shared, and printed in `README.md`. Because
  `AuthenticationDemo` is a nested class inside `AuthService.java`, the constant travels with the
  library: anyone who copies this file into a service inherits a `main()` that provisions an
  `ACTIVE` account with a known password and a known weak iteration count (SEC-04), and secret scanners
  — correctly — flag the repository. It is also a `String` constant, which means the password sits in
  the class's constant pool, in the compiled `.class` file, and indefinitely in the heap, in direct
  contradiction of the `char[]`-only property the same file documents (SEC-06). No finding here is
  reachable from a library-only deployment, which is why this is Low rather than Medium — but the
  fix costs nothing and removes the "known default credential" class of finding entirely.
- **Fix:** supply the demo credential from the environment or generate it per run, and keep the demo
  out of the shipped file:

```java
// AuthService.java: AuthenticationDemo — no literal, and a cost that matches the library default.
private static final int DEMO_ITERATIONS = PasswordHasher.DEFAULT_ITERATIONS;
private static final int LOCK_AFTER = 5;

/** From the environment if provided, else a fresh random secret printed once for the operator. */
private static char[] demoPassword() {
    String fromEnv = System.getenv("AUTH_DEMO_PASSWORD");
    if (fromEnv != null && !fromEnv.isEmpty()) {
        return fromEnv.toCharArray();
    }
    char[] generated = PasswordHasher.randomChars(24);
    System.out.println("generated demo password: " + new String(generated));
    return generated;                        // used once, then only the derived hash survives
}
```

```java
// AuthService.java:1447 becomes, so the demo's own strings never hold the credential:
try (AutoCloseable ignored = null) {
    char[] secret = demoPassword();
    try {
        service.register("alice", secret.clone());
        attempt(service, ++step, "correct password", "alice", secret, "203.0.113.10");
    } finally {
        Arrays.fill(secret, '\0');
    }
}
```

### SEC-11: Predictable `attempt` id on administrative audit records

- **Severity:** Low
- **CWE:** CWE-340: Generation of Predictable Numbers or Identifiers
- **Location:** `AuthService.java:1257-1262`
- **Vulnerable code:**

```java
// AuthService.java:1257-1262
        private static List<String[]> adminFields(Instant now) {
            List<String[]> fields = new ArrayList<>(8);
            fields.add(LoginContext.field("attempt", "admin-" + now.getEpochSecond() + "-"
                    + (now.getNano() / 1000), 32));
            return fields;
        }
```

- **Why it is a problem:** authentication attempts get a 12-hex id from `SecureRandom` (`:129`,
  `:239-245`), but the administrative records — `ACCOUNT_CREATED`, `ACCOUNT_STATUS_CHANGED`,
  `ACCOUNT_UNLOCKED`, the events that matter most in an intrusion review — derive their correlation id
  from the wall clock at microsecond resolution. Two consequences: ids collide whenever two admin
  actions land in the same microsecond (plausible in a scripted bulk-remediation, and `Instant.now()`
  resolution on Linux is often coarser than a microsecond, which makes collisions routine rather than
  theoretical), and ids are trivially predictable, so `attempt=` cannot be used as a
  tamper-evident/correlation handle when the log is merged with another system's. The README documents
  the format as an interface (`Administrative records use an admin-<epoch>-<micros> id`), so the
  weakness is baked into the contract rather than being an accident of one line.
- **Fix:** reuse the generator that the authentication path already trusts:

```java
// AuthService.java:1257-1262 — keep the readable prefix, take the entropy from SecureRandom.
private List<String[]> adminFields(Instant now) {
    List<String[]> fields = new ArrayList<>(8);
    fields.add(LoginContext.field("attempt", "admin-" + newHexId(6), 32));
    fields.add(LoginContext.field("at", now.toString(), 32));   // timestamp stays queryable, not an id
    return fields;
}
```

## 6. Verified Controls and Checks With No Finding

- **KDF choice and parameters:** PBKDF2-HMAC-SHA256 via `SecretKeyFactory` (`:451`), 32-byte output
  (`:454`), no MD5/SHA-1, no block-cipher mode anywhere, no hard-coded key or IV; the only SHA-1/ECB
  classes are absent from the file. Cost policy itself is SEC-04/SEC-05.
- **Per-record salt from a CSPRNG:** `newSalt()` (`:543-547`) draws 16 fresh bytes from `SecureRandom`
  for every `encode`, so identical passwords get different digests and one precomputed table cannot
  cover the store.
- **Constant-time comparison:** `MessageDigest.isEqual(stored.digest, derived)` over two
  `DIGEST_BYTES`-long arrays (`:525-526`), with both operands always the same length, so no
  early-exit or length signal.
- **Strict parsing of stored records:** `StoredDigest.parse` (`:694-731`) requires exactly four
  `$`-separated fields, the `pbkdf2-sha256` prefix match, an iteration count inside the declared
  range, strict (non-MIME, non-lenient) Base64 for both operands, salt length 8..128 and digest length
  exactly 32. A tampered or truncated row cannot smuggle a shorter digest or a different KDF.
- **Equal-cost refusal (timing enumeration):** exactly one derivation per attempt on every path
  (`:148-150`), an unknown account charged against a *derived* `dummyEncoded` digest whose parseability
  is asserted in the `PasswordHasher` constructor (`:479-487`), and an unusable candidate swapped for
  `dummyPassword` inside `verify` (`:517`). Verified by
  `AuthServiceTest.everyRefusalShapeCostsTheSameWork` (`AuthServiceTest.java:870`) with a ratio window
  and an absolute floor.
- **No enumeration by response text:** every refusal returns the same `GENERIC_FAILURE_MESSAGE`
  constant through the single `refuse(...)` helper (`:86`, `:227-233`), including the lockout-crossing
  path that bypasses `refuse` (`:207-208`); the reason is only in `internalReason()` (`:428`) and the
  audit line. `internalReason()` is documented as server-side only, which is a convention rather than
  a control, but it is not reachable from any rendering path in this file.
- **Password-collision defence:** `PasswordRules.rejectCandidate` (`:628-645`) rejects trailing NULs
  and unpaired surrogates because `PBEKeySpec` is not injective over `char[]`, so `"pw"` and `"pw\0"`
  can never hash to the same digest. Verified: the demo exercises the NUL case at `:1487`.
- **Username canonicalisation:** NFKC then `toLowerCase(Locale.ROOT)` then the allow-list
  `[a-z0-9._+\-]{1,64}` with a 256-character input cap (`:752-753`, `:773-781`), which closes
  look-alike/rename confusion (`ａｌｉｃｅ` → `alice`, NBSP refused) and keeps traversal-shaped input in
  the log as distinguishable probe traffic rather than a resolved account.
- **Audit-log injection resistance:** `LogValue.escape` (`:1299-1350`) percent-encodes `%`, `"` and
  `\`, percent-encodes every byte of every non-ASCII code point via UTF-8, encodes C0 controls
  (CR/LF included) and DEL, quotes values that still contain whitespace, and truncates with an
  explicit `(+truncated)` marker. Verified against the header-injection analogue: a username carrying
  `\n` plus a forged `event=AUTH_SUCCESS outcome=SUCCESS` payload yields one record with the real
  field values (`AuthServiceTest.logInjectionCannotForgeASecondLine`), and no throwable is attached to
  any record, so no stack trace can spill into the file.
- **One record per attempt, with escalation:** the attempt that crosses the lockout threshold is the
  same `AUTH_FAILURE` record escalated to `WARNING` and carrying `lockedUntil` (`:202-208`), so
  record counts equal attempt counts; `failures` is not incremented and the deadline does not slide
  while an account is locked (`:193-196`).
- **Secret hygiene in memory:** the request defensively copies the caller's array (`:321-327`),
  `login()` wipes its working copy in a `finally` (`:223`), `PasswordHasher.verify` wipes the derived
  key (`:529-531`), `destroy()` zeroes the retained copy (`:351-353`), and `LoginRequest.toString()` /
  `AccountRecord.toString()` redact the credential and the digest (`:368-371`, `:898-900`). Verified
  reflectively by the suite (`AuthServiceTest.java:748`, `:762`).
- **Lockout accounting under concurrency:** every `InMemoryFailureTracker` mutator is `synchronized`
  on one monitor (`:1037-1069`) and audit emission happens outside it; expired lockouts clear on read
  (`:1037-1044`). The suite drives 16 threads and checks for lost increments.
- **Duplicate-account prevention:** `AccountStore.putIfAbsent` (`:940-942`) is the insert path used by
  `register` (`:270`), on a `ConcurrentHashMap` (`:911`), so a concurrent registration cannot create
  two records for one normalised username.
- **Attempt correlation ids for the authentication path:** `newHexId(6)` from `SecureRandom`
  (`:129`, `:239-245`), 12 hex characters, shared between the subject-facing result and `attempt=`.
- **No injection-prone surface:** no SQL/shell/LDAP/template construction, no deserialisation
  (`ObjectInputStream` absent), no JNDI lookup, no reflection over user input, no `eval`-equivalent;
  the only I/O is `java.util.logging`'s handlers, and the only transforms are
  `SecretKeyFactory`/`MessageDigest`, `java.text.Normalizer`, `java.util.Base64` and `HexFormat`.
  The `testing-for-email-header-injection` and `exploiting-insecure-deserialization` checklists were
  therefore run against the log sink (finding none) and found no applicable target respectively.
- **`AuthServiceTest.java` as a whole:** no production behaviour, no network or filesystem writes
  beyond the JVM's own, and its `setAccessible(true)` calls target only its own inner classes; its
  hardcoded passwords are fixtures. Its one gap is relevance rather than correctness — the timing test
  uses uniformly-costed accounts, so it cannot detect the cost divergence in SEC-05.
