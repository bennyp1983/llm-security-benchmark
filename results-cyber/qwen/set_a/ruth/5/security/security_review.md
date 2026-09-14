# Security Review: LoginService

## 1. Executive Summary

`LoginService.java` is a single-file authentication component: credential verification, PBKDF2
password storage, per-account lockout, an account store, and an audit hook. The implementation is
unusually careful about several classic mistakes — the constant-time key comparison, the timing
equalisation on every refusal branch, the fail-closed record parser, the `PBEKeySpec` collision
refusal, and the per-username `ConcurrentHashMap.compute` serialisation all hold up under
inspection and are confirmed in section 6.

Twelve findings are reported: two High, four Medium, six Low.

The two High findings are that the throttling control is keyed on the username alone, so the
stated defence against "repeated failed attempts" is bypassed by spraying one password across many
usernames or by rotating across app nodes (SEC-01), and that the password-hash cost is materially
below the current published baseline for the algorithm in use and is not memory-hard (SEC-02). The
Medium findings cover an accepted hash-cost floor of 1,000 iterations with no rehash-on-login
upgrade (SEC-03), unbounded and attacker-influenceable CPU cost per unauthenticated request
(SEC-04), lockout state that exists only inside one JVM (SEC-05), and a credential-replacement API
that authenticates nobody and audits nothing (SEC-06).

`README.md` already names several of these as deliberate out-of-scope gaps ("there is no rate
limiting per IP … the tracker must be shared across instances (Redis or similar) or an attacker
simply rotates between app nodes … a real deployment would migrate `PasswordHasher` to a
memory-hard KDF such as Argon2id"). That documentation is accurate and is credited, but the shipped
code is the artefact under review, so each such gap is still reported with a severity that reflects
the risk of deploying the file as written.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `LoginService.java` (764 lines) | The whole component: `login()` flow, `PasswordHasher` (PBKDF2 record encode/verify), `LoginAttemptTracker` (rolling-window lockout), `AccountStore`/`InMemoryAccountStore`, `AuditSink`, `main` demo and `--interactive` prompt. | Authentication decision, credential verification, KDF choice and cost, username/password input validation, account-lockout policy and its storage, audit-record contents and destination, credential registration and replacement, demo credentials. |
| `LoginServiceTest.java` (1010 lines) | Dependency-free suite (288 checks, 24 sections) covering the happy path, wrong-password matrix, unknown-user indistinguishability, malformed-input matrix, corrupt records, lockout lifecycle against a deterministic clock, two concurrency races, audit contents, and six timed cost ratios. | No production behaviour. Does embed the same literal passwords as `main` (e.g. `LoginServiceTest.java:75-76`) and asserts that audit lines contain no credential material. Its timed-ratio assertions (0.75-1.35) are the test evidence for the timing controls credited in section 6. |
| `README.md` | Design narrative, build/run instructions, threat model, integration notes. | Documents the intended security properties and, in "Integrating it", self-declares the missing controls that underpin SEC-01, SEC-02, SEC-03 and SEC-05. |
| `out/*.class`, `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Compiled output and task-harness files. | Not source; no independent behaviour reviewed. `out/LoginService*.class` is stale build output of the file under review. |

## 3. Skills Applied

- **`review-code-for-security-vulnerabilities`** (the entry skill) — drove the workflow: establish what the code does, select library skills by name, apply each and cite `file:line`.
- **`performing-cryptographic-audit-of-application`** — applied to `PasswordHasher` (`LoginService.java:228-410`): primitive and mode review, salt generation and length, derived-key length, KDF work factor against the published baseline, `SecureRandom` usage, constant-time comparison, and the stored-record cost-migration scheme. Source of SEC-02, SEC-03 and part of SEC-04.
- **`testing-api-authentication-weaknesses`** — applied to `login()` (`LoginService.java:150-215`): token/credential handling, the five refusal branches, response-wording and cost parity, the account-enumeration oracle, and the absence of credential-strength controls. Source of SEC-07, SEC-11 and part of SEC-10.
- **`implementing-api-abuse-detection-with-rate-limiting`** — applied to the throttle design (`LoginService.java:412-620`): which key the limiter is indexed by, whether a per-source/token-bucket budget exists, and whether the endpoint's per-request cost is bounded. Source of SEC-01 and SEC-04.
- **`hunting-credential-stuffing-attacks`** — applied to `LoginAttemptTracker` state accumulation for both existing and non-existent usernames (`LoginService.java:470-498`, `LoginService.java:175-182`): whether one password spread over many accounts ever trips a threshold. Source of SEC-01.
- **`detecting-anomalous-authentication-patterns`** — applied to what the telemetry can and cannot answer (`LoginService.java:157-160`, `LoginService.java:206-210`): attribution of refused attempts and the signals available to a detector. Source of SEC-12.
- **`testing-for-broken-access-control`** — applied to `InMemoryAccountStore.register` / `changePassword` (`LoginService.java:638-666`): whether a critical state change authenticates its caller and whether one key can overwrite another's secret. Source of SEC-06.
- **`testing-for-sensitive-data-exposure`** — applied to `AuditSink` and the demo paths (`LoginService.java:106-118`, `LoginService.java:694`) and to in-memory credential residue (`LoginService.java:150-155`, `LoginService.java:337-347`). Source of SEC-09, SEC-10 and part of SEC-12.
- **`implementing-secret-scanning-with-gitleaks`** — applied to the whole file for literal credentials in source; matched `LoginService.java:686-688` and `LoginService.java:744`. Source of SEC-08.
- **General OWASP Top 10 / CWE review, no library skill matched** — the following behaviours were checked against general knowledge because no skill in the library covers them: thread-safety of `LoginAttemptTracker`'s sweep against its `compute` mutators and the publication of `lastPurgeMillis` (SEC-04 note, plus section 6); Java-specific `PBEKeySpec` zeroisation semantics on an exception path (SEC-10); the availability consequence of deliberately paying KDF work per unauthenticated request (SEC-04); and the durability/sharing requirements of anti-brute-force state in a multi-instance deployment (SEC-05).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Lockout is keyed on username only, so password spraying never trips it | High | CWE-307 | `LoginService.java:420` |
| SEC-02 | PBKDF2 work factor below the published baseline and not memory-hard | High | CWE-916 | `LoginService.java:238-239` |
| SEC-03 | Cost floor of 1,000 iterations accepted; no rehash-on-login upgrade | Medium | CWE-916 | `LoginService.java:235-236`, `LoginService.java:363-365` |
| SEC-04 | Unbounded, attacker-influenceable CPU cost per unauthenticated request | Medium | CWE-400 | `LoginService.java:237`, `LoginService.java:156-160` |
| SEC-05 | Lockout state lives in one JVM and is lost on restart or node rotation | Medium | CWE-307 | `LoginService.java:420` |
| SEC-06 | Credential replacement requires no authentication and emits no audit event | Medium | CWE-306 | `LoginService.java:652-665` |
| SEC-07 | `ACCOUNT_LOCKED` plus `retryInSeconds` confirms account existence | Low | CWE-204 | `LoginService.java:49`, `LoginService.java:162-166` |
| SEC-08 | Hard-coded credentials in `main` and `interactive` | Low | CWE-798 | `LoginService.java:686-688` |
| SEC-09 | Password hash and audit lines written to standard output | Low | CWE-532 | `LoginService.java:694`, `LoginService.java:115-116` |
| SEC-10 | Cleartext password copies survive the derivation, including on the error path | Low | CWE-316 | `LoginService.java:337-347` |
| SEC-11 | No password-strength or breached-password policy at registration | Low | CWE-521 | `LoginService.java:642-651` |
| SEC-12 | Malformed-name attempts are logged with `username=null` and are unattributable | Low | CWE-778 | `LoginService.java:157-160` |

## 5. Detailed Findings

### SEC-01: Lockout is keyed on username only, so password spraying never trips it

- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginService.java:420` (also `LoginService.java:470-498`, `LoginService.java:175-182`)

**Vulnerable code:**

```java
// LoginService.java:419-420, 470-473  (LoginAttemptTracker)
        /** Per-username policy state. */
        private final ConcurrentHashMap<String, State> states = new ConcurrentHashMap<>();
// ...
        public boolean recordFailure(String username) {
            requireKey(username);
            purgeIfNeeded();
            boolean[] tripped = new boolean[1];
```

**Why it is a problem:** The only key in the throttle is the account name. `maxFailures` failures
*for one name* suspend that name, so an attacker who tries one common password against ten
thousand usernames records exactly one failure per key and is never throttled by anything in this
file — the classic credential-stuffing and spray pattern. The tracker does accumulate state for
names that do not exist (`LoginService.java:175-182`), which is necessary and correct, but a
counter that is per-name cannot detect "one source, many names" because it has no source
dimension at all. `README.md` states the gap plainly: *"there is no rate limiting per IP, no
CAPTCHA …"*. The consequence for the control this file exists to provide is that the lockout stops
typo storms and single-account guessing but does not stop the attack class that actually breaks
password authentication at scale.

**Fix:** Throttle the request source in addition to the account, and enforce it before any KDF
work. Apply the same generic refusal wording so no new oracle is introduced, and prefer to shed
the request at the edge (gateway/WAF) so the application never pays for it.

```java
// Corrected: two independent throttle keys, both checked before any derivation.
public LoginOutcome login(String username, char[] password, String sourceKey) {
    // Per-source budget: N failures across ANY username inside the window stops the source.
    // Existing accounts, unknown accounts and malformed names all charge it.
    if (!tracker.sourceBudgetAvailable(sourceKey)) {
        tracker.recordSourceFailure(sourceKey);       // charge even when refusing early
        hasher.burnWork();                            // keep cost parity with a real check
        return refuse(null, LoginStatus.INVALID_CREDENTIALS, 0L);
    }
    if (!isWellFormedUsername(username)) {
        tracker.recordSourceFailure(sourceKey);
        hasher.burnWork();
        return refuse(null, LoginStatus.INVALID_CREDENTIALS, 0L);
    }
    // ... existing per-account path unchanged, plus:
    //     tracker.recordSourceFailure(sourceKey);   on every refusal branch
    //     tracker.recordSourceSuccess(sourceKey);   on SUCCESS
}
```

### SEC-02: PBKDF2 work factor below the published baseline and not memory-hard

- **Severity:** High
- **CWE:** CWE-916: Password Hash with Insufficient Computational Effort
- **Location:** `LoginService.java:238-239` (also `LoginService.java:229-230`)

**Vulnerable code:**

```java
// LoginService.java:229-230, 238-239
        private static final String PREFIX = "pbkdf2";
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
// ...
        /** Cost of a new password; about 0.3s per derivation on a 2026-class x86 core. */
        public static final int DEFAULT_ITERATIONS = 210_000;
```

**Why it is a problem:** The OWASP Password Storage Cheat Sheet recommends **600,000** iterations
for PBKDF2-HMAC-SHA256; 210,000 is roughly a third of that, i.e. every stored password is
crackable about three times cheaper than the current baseline assumes. Separately, PBKDF2 is
CPU-bound by design and therefore GPU- and ASIC-friendly: its cost does not scale with memory, so
a hashcat rig divides the work factor far more effectively than it can divide a memory-hard KDF's.
The file is structurally well prepared for the fix — the cost factor is stored per record and
honoured at verification (`LoginService.java:363-365`, `LoginService.java:325`), and `README.md`
already says a real deployment "would migrate `PasswordHasher` to a memory-hard KDF such as
Argon2id" — but as shipped every new password is enrolled at the weak cost, and this is the
parameter an offline attacker spends their budget against.

**Fix:** Raise the default to at least the OWASP figure, and move to Argon2id via a vetted library
while keeping the existing record-prefix migration so old PBKDF2 records keep verifying.

```java
// Corrected: meet the published PBKDF2-HMAC-SHA256 baseline.
public static final int DEFAULT_ITERATIONS = 600_000;   // OWASP Password Storage Cheat Sheet floor

// Preferred: add a memory-hard prefix alongside "pbkdf2" and let the existing
// record parser dispatch on it, so old records verify while new ones enrol strong.
//   Argon2id: m=19456 (19 MiB), t=2, p=1   (OWASP-recommended parameters)
//   private static final String PHC_PREFIX = "argon2id";
//   $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
```

### SEC-03: Cost floor of 1,000 iterations accepted; no rehash-on-login upgrade

- **Severity:** Medium
- **CWE:** CWE-916: Password Hash with Insufficient Computational Effort
- **Location:** `LoginService.java:235-236` (band check `LoginService.java:363-365`; missed upgrade `LoginService.java:184-187`)

**Vulnerable code:**

```java
// LoginService.java:235-236
        /** Stored iteration counts outside this range are treated as a corrupt record. */
        public static final int MIN_ITERATIONS = 1_000;
```

**Why it is a problem:** `parse()` accepts any stored cost from 1,000 upward as a valid record, so
a record enrolled at 1,000 iterations is **210×** cheaper to brute-force than a current one and is
verified forever without complaint. Nothing in the success path re-enrols it: `login()` returns
`SUCCESS` after `hasher.matches(...)` (`LoginService.java:184-187`) and never compares the
record's cost against the current policy, so a weak record can only be strengthened by an explicit
`changePassword`. In practice the cost factor is also data an attacker with any write access to
the account row controls downward, and a migration from an older, weaker hash (the README's
"cost-factor migration" story) lands records at whatever the legacy value was. The floor is a
policy floor, and 1,000 is not a policy — it is a "this is probably not garbage" sentinel used for
two different purposes at once.

**Fix:** Split the two meanings: keep a low *syntactic* acceptance bound for parsing, add a
separate *policy* floor, and transparently re-enrol any record that verifies below it.

```java
// Corrected: parse tolerance and security floor are different numbers.
public static final int MIN_ITERATIONS = 1_000;          // syntactic: reject obvious garbage
public static final int POLICY_MIN_ITERATIONS = 310_000; // security: weaker than this must migrate

/** True when a record verifies but is weaker or a different algorithm than policy. */
public static boolean needsRehash(String stored) {
    Record r = parse(stored);
    return r != null && (r.iterations < POLICY_MIN_ITERATIONS || !ALGORITHM.equals(prefixOf(stored)));
}
```

```java
// LoginService.java:184-187 corrected — upgrade on a verified login, never on a failed one.
if (hasher.matches(password, found.get().hashedPassword())) {
    if (PasswordHasher.needsRehash(found.get().hashedPassword())) {
        accounts.replace(username, hasher.hash(password));  // re-encode at DEFAULT_ITERATIONS
    }
    tracker.recordSuccess(username);
    audit.record(username, LoginStatus.SUCCESS, 0L);
    return new LoginOutcome(LoginStatus.SUCCESS, "Access granted.", 0L);
}
```

Do not raise `MIN_ITERATIONS` to the policy floor without a migration sweep first: that would
lock every legacy account out, because a record below the floor parses as corrupt and fails closed.

### SEC-04: Unbounded, attacker-influenceable CPU cost per unauthenticated request

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginService.java:237` (also `LoginService.java:156-160`, `LoginService.java:325`)

**Vulnerable code:**

```java
// LoginService.java:236-237
        public static final int MIN_ITERATIONS = 1_000;
        public static final int MAX_ITERATIONS = 5_000_000;
```

**Why it is a problem:** Two effects compound. First, every unauthenticated `login()` call is
guaranteed to pay a full ~300 ms derivation — including a call with a malformed username or a
non-existent account, which is deliberate and correct for timing parity
(`LoginService.java:156-160`, `LoginService.java:329-332`) — but there is no cap on how many such
calls one caller may have in flight, no semaphore sized to the cores available, and no cheap
pre-check. A handful of concurrent requests converts a login endpoint into a CPU-exhaustion
amplifier, which is the availability half of SEC-01 and is not fixed by per-account throttling
because malformed names charge nothing at all. Second, `matches()` honours the cost factor found
*in the stored record* (`LoginService.java:325`), and `parse()` accepts up to 5,000,000
(`LoginService.java:363-365`) — roughly 24× the intended per-login budget, i.e. ~7 seconds of CPU
per attempt against one account. That is reachable by anyone who can write an account row (a
second-order injection, a partial DB compromise, a mis-scoped admin API such as the one in
SEC-06), and no rehash-on-login path exists to retire it.

**Fix:** Bound concurrent KDF work and shed load with the same generic refusal, and cap the cost
factor the service is willing to pay for somebody else's record.

```java
// Corrected: never pay more than the service's own budget for a stored record,
// and never let derivations queue beyond what the machine can absorb.
private static final int HONOURED_MAX_ITERATIONS = 1_000_000;  // policy budget, not a storage limit
private static final Semaphore KDF_SLOTS =
        new Semaphore(2 * Runtime.getRuntime().availableProcessors(), true);

public boolean matches(char[] password, String stored) {
    Record record = parse(stored);
    if (record == null || record.iterations > HONOURED_MAX_ITERATIONS || !isHashable(password)) {
        burnWork();                       // still charged, so the cap is not a timing oracle
        return false;                     // record is quarantined for re-enrolment, not trusted
    }
    if (!KDF_SLOTS.tryAcquire()) {
        throw new OverloadedException();  // caller maps this to the generic refusal / HTTP 429
    }
    try {
        byte[] candidate = derive(password, record.salt, record.iterations);
        return MessageDigest.isEqual(record.key, candidate);
    } finally {
        KDF_SLOTS.release();
    }
}
```

### SEC-05: Lockout state lives in one JVM and is lost on restart or node rotation

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts (same weakness as SEC-01, different root cause and different remediation)
- **Location:** `LoginService.java:420` (also `LoginService.java:564-567`)

**Vulnerable code:**

```java
// LoginService.java:420
        private final ConcurrentHashMap<String, State> states = new ConcurrentHashMap<>();
```

**Why it is a problem:** The entire anti-brute-force policy — failure counts, rolling windows,
escalating lock durations — is process memory. Behind a load balancer an attacker gets one failure
budget *per node* simply by letting the balancer rotate them, and a deploy, an autoscale event, an
OOM restart or a `kubectl rollout restart` resets every counter and lifts every lock without any
action on the attacker's part. `README.md` states the requirement: *"in production the tracker must
be shared across instances (Redis or similar) or an attacker simply rotates between app nodes."*
The class is otherwise production-shaped (`AccountStore` is a clean seam, the clock is injectable),
so the in-memory map is the one piece that silently degrades the control rather than failing
loudly: everything keeps returning correct `LoginStatus` values while the policy stops applying.
Note this also silently disables `clear(username)` (`LoginService.java:564-567`) as an operator
override in a multi-node deployment, since it clears only the local map.

**Fix:** Keep the interface, move the state. The policy is small enough to express as two keys per
subject with TTLs, which maps directly onto Redis and preserves the existing semantics.

```java
// Corrected: same contract, shared and durable backing.
public interface AttemptStore {
    /** Atomic: INCR failures:{key} with EXPIRE window, then SET lock:{key} PX if count >= max. */
    LockOutcome chargeFailure(String key, Duration window, Duration lock);
    long remainingLockMillis(String key);          // TTL of lock:{key}
    void clear(String key);                        // DEL failures:{key} lock:{key}
}

public final class RedisLoginAttemptTracker implements LoginAttemptTracker {
    private final UnifiedJedis redis;              // every app instance shares this state
    // recordFailure -> chargeFailure(username) AND chargeFailure("src:" + sourceKey)
}
```

### SEC-06: Credential replacement requires no authentication and emits no audit event

- **Severity:** Medium
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `LoginService.java:652-665` (also `LoginService.java:642-651`)

**Vulnerable code:**

```java
// LoginService.java:652-665
        /**
         * Replaces a password. The caller must also lift any lockout with
         * {@link LoginAttemptTracker#clear(String)}, otherwise a locked account stays
         * locked after a password reset.
         */
        public Account changePassword(String username, char[] password) {
            Account existing = accounts.get(username);
            if (existing == null) {
                throw new IllegalArgumentException("no such account: " + username);
            }
            return register(username, password, existing.enabled());
        }
```

**Why it is a problem:** `changePassword` overwrites the stored secret with no proof of the old
password, no identity of the actor, and — unlike every path in `login()` — no `audit.record` call
at all. `register` (`LoginService.java:642-651`) is the same via a different door: it
`accounts.put`s unconditionally, so calling it for a name that already exists silently takes over
that account rather than failing. Both are public methods on a shipped class, so whether the
control exists at all is delegated to every caller remembering to add an authorisation check in
front of each one; the javadoc documents the *lockout* footgun but is silent on the fact that this
method is an unauthenticated account-takeover primitive. A password change is exactly the event a
defender most needs in the audit trail — it is how persistence after account takeover looks — and
here it is invisible: `AuditSink` sees only login attempts.

**Fix:** Require the old credential (or an authenticated actor principal), refuse silent
overwrite on registration, and make the credential change itself an audited event that also clears
the lockout it is meant to resolve.

```java
// Corrected: verify, authorise, audit, and do not leave the account locked.
public Account changePassword(String actor, String username, char[] oldPassword, char[] newPassword) {
    Account existing = accounts.get(username);
    if (existing == null) {
        throw new IllegalArgumentException("no such account: " + username);
    }
    if (!authorizer.canChangePassword(actor, username)
            || !hasher.matches(oldPassword, existing.hashedPassword())) {
        audit.record(username, LoginStatus.INVALID_CREDENTIALS, 0L);   // failed change is visible
        throw new SecurityException("password change not authorised for " + actor);
    }
    Account account = new Account(username, hasher.hash(newPassword), existing.enabled());
    accounts.put(username, account);
    tracker.clear(username);                                            // reset the reset
    audit.record(username, LoginStatus.SUCCESS, 0L);                    // credential change audited
    return account;
}

// register(): create only, never overwrite an existing secret.
Account previous = accounts.putIfAbsent(username, account);
if (previous != null) {
    throw new IllegalStateException("account already exists: " + username);
}
```

### SEC-07: `ACCOUNT_LOCKED` plus `retryInSeconds` confirms account existence

- **Severity:** Low
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `LoginService.java:49` (also `LoginService.java:162-166`, `LoginService.java:213-215`)

**Vulnerable code:**

```java
// LoginService.java:162-166
        long lockedFor = tracker.remainingLockMillis(username);
        if (lockedFor > 0L) {
            // Refusing early would make the lock state readable by stopwatch.
            hasher.burnWork();
            return refuse(username, LoginStatus.ACCOUNT_LOCKED, secondsUp(lockedFor));
        }
```

**Why it is a problem:** Every other refusal is deliberately indistinguishable, so this is the one
observable that answers "does this username exist, and is it currently locked?" — a valid status
code, distinct wording, and a numeric seconds-to-retry that additionally discloses the configured
lock duration. Because the lock is reachable without knowing the password (five failures on a real
account, `LoginService.java:175-182`), the same response doubles as a low-cost denial-of-service
primitive against a named user: an attacker can keep a chosen account locked indefinitely and can
use the response to confirm which candidate names are real before spending a spray on them. The
timing leak is correctly closed with `burnWork()`; what remains is the *content* leak, which the
code comments acknowledge as a deliberate trade-off. It is reported at Low because the trade-off is
defensible for a user-facing login, but it is a real enumeration oracle and the mitigation is
cheap.

**Fix:** Only disclose the lock to someone who has already proven the password. Refuse everyone
else with the generic outcome, so the response no longer distinguishes a real account from a
hypothetical one.

```java
// Corrected: the lock is disclosed to the rightful owner, not to a prober.
long lockedFor = tracker.remainingLockMillis(username);
if (lockedFor > 0L) {
    boolean passwordOk = hasher.matches(password, found.orElse(dummyRecordFor(username)));
    if (!passwordOk) {
        tracker.recordFailure(username);
        return refuse(username, LoginStatus.INVALID_CREDENTIALS, 0L);  // generic, same cost
    }
    // Correct password but suspended: still refused, now safe to say when to return.
    return refuse(username, LoginStatus.ACCOUNT_LOCKED, secondsUp(lockedFor));
}
```

If the deployment would rather not disclose it at all, return `INVALID_CREDENTIALS` for the locked
case unconditionally and surface lock status only through an authenticated recovery flow.

### SEC-08: Hard-coded credentials in `main` and `interactive`

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginService.java:686-688` (also `LoginService.java:744`)

**Vulnerable code:**

```java
// LoginService.java:684-688
        PasswordHasher hasher = new PasswordHasher();
        InMemoryAccountStore store = new InMemoryAccountStore(hasher);
        store.register("alice", "Corr3ct-Horse-Battery".toCharArray());
        store.register("bob", "hunter2-hunter2!".toCharArray());
        store.register("svc-batch", "d1sabled-s3cret-pw".toCharArray(), false);
```

**Why it is a problem:** These are demo fixtures, and severity reflects that. They still trip the
hard-coded-credential check for real reasons: the strings are in the shipped `.class` files under
`out/`, `LoginServiceTest.java:75-76` and the "Integrating it" snippet reuse the same literal
`alice` / `Corr3ct-Horse-Battery` pair, so a developer pasting the README example into an
integration brings the password along — and `hunter2-hunter2!` is precisely the shape a real user
picks. A further hazard is that one of them is named `svc-batch`, i.e. reads as a service account.

**Fix:** Generate the demo secret at runtime (or read it from the environment) so no literal
password is ever compiled into the artefact.

```java
// Corrected: demo credentials exist only for this process, in memory, and are wiped.
private static char[] demoSecret(String seed) {
    byte[] b = new byte[24];
    new SecureRandom().nextBytes(b);
    return ("demo-" + Base64.getUrlEncoder().withoutPadding().encodeToString(b)).toCharArray();
}
// ...
char[] aliceSecret = demoSecret("alice");
store.register("alice", aliceSecret);
try {
    // ... scripted walkthrough uses aliceSecret ...
} finally {
    java.util.Arrays.fill(aliceSecret, '\0');
}
// For real configuration: System.getenv("DEMO_ALICE_PASSWORD"), never a literal.
```

### SEC-09: Password hash and audit lines written to standard output

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `LoginService.java:694` (also `LoginService.java:115-116`)

**Vulnerable code:**

```java
// LoginService.java:694
        System.out.println("Stored record for alice: " + store.find("alice").orElseThrow().hashedPassword());
```

**Why it is a problem:** The demo prints a full encoded credential record — salt plus derived key —
to stdout. Anyone with read access to the console transcript, the container log, or CI job output
holds an offline-crackable target, which is exactly the asset the KDF cost in SEC-02/SEC-03 protects.
The same channel carries the shipped audit sink: `AuditSink.println()` (`LoginService.java:113-117`)
writes security-relevant authentication events to `System.out`, which is typically unrotated,
unfiltered and shipped to places security logs should not go. The contents of those two lines are
themselves fine — usernames and statuses only, never a credential, which is asserted by the test
suite — the problem is the destination and the printed credential record.

**Fix:** Never print a stored record; if the demo must show the format, show a redacted or
obviously-fake example. Send audit events to a logger configured for a security channel.

```java
// Corrected: show the shape, not the secret.
String record = store.find("alice").orElseThrow().hashedPassword();
System.out.println("Stored record for alice: " + record.replaceAll("\\$[^$]{6,}\\$", "$<redacted>$"));

// Corrected audit destination: a real logger, not stdout.
static AuditSink logger() {
    Logger log = Logger.getLogger("auth.audit");
    return (username, status, retryInSeconds) ->
            log.info("auth event", Map.of("username", String.valueOf(username),
                                          "status", status.name(),
                                          "retryInSeconds", retryInSeconds)); // structured, one line, no newlines in values
}
```

### SEC-10: Cleartext password copies survive the derivation, including on the error path

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `LoginService.java:337-347` (also `LoginService.java:150-155`, `LoginService.java:252`)

**Vulnerable code:**

```java
// LoginService.java:337-347
        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
                byte[] key = factory.generateSecret(spec).getEncoded();
                spec.clearPassword();
                return key;
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(ALGORITHM + " unavailable", e);
            }
        }
```

**Why it is a problem:** `spec.clearPassword()` is on the happy path only. `PBEKeySpec`'s
constructor copies the `char[]` into its own internal array, so on the `GeneralSecurityException`
path the copy inside `spec` is never zeroed and stays reachable on the heap until `spec` is
collected — the one path where wiping matters most is the one that skips it. Two adjacent
residues compound it: `login()` intentionally leaves the caller's array intact (`LoginService.java:150-155`)
— correct as an API choice, but it means the plaintext lifetime equals however long the caller's
frame lives unless the caller remembers to wipe, which `README.md` has to remind people to do), and
`dummyPassword` (`LoginService.java:252`) is a real `char[]` derived from random bytes that is
retained for the process lifetime as a field of a long-lived object. None of this is remotely
exploitable on its own; it is the standard "reduce the window in which a heap dump or a core file
yields a password" hygiene finding, and the file is already using `char[]` rather than `String`
specifically to support it — which is why the missing `finally` is worth fixing.

**Fix:** Clear in a `finally`, and wipe the tracker's own copy when it is no longer needed.

```java
// Corrected: the copy is cleared whatever happens to the derivation.
private static byte[] derive(char[] password, byte[] salt, int iterations) {
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        return factory.generateSecret(spec).getEncoded();
    } catch (GeneralSecurityException e) {
        throw new IllegalStateException(ALGORITHM + " unavailable", e);
    } finally {
        spec.clearPassword();
    }
}

// And at the call site, in the same spirit the javadoc already asks of callers:
char[] password = readCredential();
try {
    outcome = service.login(username, password);
} finally {
    java.util.Arrays.fill(password, '\0');
}
```

### SEC-11: No password-strength or breached-password policy at registration

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `LoginService.java:642-651`

**Vulnerable code:**

```java
// LoginService.java:642-651
        public Account register(String username, char[] password, boolean enabled) {
            if (!isWellFormedUsername(username)) {
                throw new IllegalArgumentException("username cannot name an account: " + username);
            }
            if (!PasswordHasher.isHashable(password)) {
                throw new IllegalArgumentException("password cannot be hashed safely");
            }
            Account account = new Account(username, hasher.hash(password), enabled);
            accounts.put(username, account);
            return account;
        }
```

**Why it is a problem:** The only password gate is `isHashable`, which tests whether the JCE can
encode the value losslessly and caps it at 1024 characters — it says nothing about strength. A
one-character secret or `123456` enrols happily, and the file's own fixture `hunter2-hunter2!`
(`LoginService.java:687`) is the kind of pattern that appears in every breach corpus. Because SEC-02
already weakens the cost per guess, weak enrolment and a cheap hash compound: the KDF budget is
what makes a low-entropy secret survivable, and it is set below baseline. `README.md` lists "no
password-strength policy, no breached-password check" as out of scope; it is still the reason the
lockout work in this file is load-bearing rather than belt-and-braces.

**Fix:** Enforce NIST SP 800-63B-style enrolment rules — length over composition, and a breach
list — at the same boundary that already validates the username.

```java
// Corrected: check entropy where the secret is still in hand, before it becomes a hash.
if (!PasswordHasher.isHashable(password)) {
    throw new IllegalArgumentException("password cannot be hashed safely");
}
if (password.length < 12) {                                  // length first, no composition rules
    throw new IllegalArgumentException("password too short");
}
if (breachedPasswords.contains(password)) {                  // k-anonymised Pwned Passwords range query
    throw new IllegalArgumentException("password appears in a known breach");
}
if (usernameContainsPassword(username, password)) {          // no trivial personalisation
    throw new IllegalArgumentException("password must not contain the username");
}
```

### SEC-12: Malformed-name attempts are logged with `username=null` and are unattributable

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `LoginService.java:157-160` (also `LoginService.java:206-210`)

**Vulnerable code:**

```java
// LoginService.java:157-160
        if (!isWellFormedUsername(username)) {
            hasher.burnWork();
            return refuse(null, LoginStatus.INVALID_CREDENTIALS, 0L);
        }
```

**Why it is a problem:** Passing `null` through `refuse` → `audit.record(username, …)`
(`LoginService.java:206-209`) means the shipped sink emits `username=null` for an entire class of
rejections, so the record carries no key, no length, no hash — nothing to correlate. That is
precisely the traffic a detector most wants: scanner and injection-probing payloads (the test
suite feeds it `' OR '1'='1` and `<script>…` strings), tooling that mangles names, and the
attacker-controlled input behind the SEC-01 spray. The analyst sees "somebody was refused" and
cannot answer who or with what. Note the security reasoning for not logging the raw value is sound
and the code should keep it — the fix is a non-reversible locator, not the original string. The
line-format sink at `LoginService.java:115-116` compounds the ambiguity because a `null` username
and an empty username render identically. Input validation here is otherwise excellent and does
block CR/LF log forging (see section 6), so the residual issue is completeness, not injection.

**Fix:** Log a derived, non-reversible locator for rejected identifiers and keep it distinct from a
genuine empty value.

```java
// Corrected: attribute the attempt without storing the attacker's string.
if (!isWellFormedUsername(username)) {
    hasher.burnWork();
    // 8 hex chars of SHA-256: correlatable across attempts, non-reversible, cannot forge log lines.
    audit.record("malformed:" + sha256Prefix(username), LoginStatus.INVALID_CREDENTIALS, 0L);
    return refuse(null, LoginStatus.INVALID_CREDENTIALS, 0L);
}

private static String sha256Prefix(String raw) {
    if (raw == null) {
        return "absent";
    }
    byte[] d = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(d).substring(0, 8);
}
```

## 6. Verified Controls and Checks With No Finding

The following were actively tested against the source (and, where noted, against assertions in
`LoginServiceTest.java`) and are correct as implemented:

- **Constant-time credential comparison.** `MessageDigest.isEqual(record.key, candidate)`
  (`LoginService.java:326`) rather than `Arrays.equals`/`String.equals`, so no byte-at-a-time leak
  about the stored key.
- **Timing parity across every refusal shape.** All five early-return branches call
  `hasher.burnWork()` — malformed name (`157-159`), locked (`162-166`), unhashable password
  (`169-172`), unknown or disabled account (`175-181`), and corrupt record inside `matches`
  (`321-323`) — so none of them is cheap relative to a real check. `burnWork()` verifies a
  genuinely runtime-derived record (`330-332`, `251-267`), which is why the equaliser cannot
  silently degrade into a no-op. The suite's 0.75-1.35 ratio gate is the empirical proof.
- **Corrupt and tampered records fail closed and cost the normal amount.** `parse`
  (`LoginService.java:349-378`) rejects a null input, a wrong field count, a wrong prefix, a
  non-numeric or out-of-band cost factor, undecodable base64, a zero or oversized salt, and a key
  of the wrong length — returning `null` and never throwing, so a damaged row is neither
  distinguishable by stopwatch nor probeable by error message, and can never authenticate.
- **`PBEKeySpec` collision class is refused, not normalised.** `isHashable`
  (`LoginService.java:279-300`) rejects null/empty, >1024 characters, a trailing NUL and any
  unpaired surrogate, which closes the real collision where `secret` and `secret\0` would derive
  the same key. The 1024-character cap also bounds KDF input cost.
- **Salt and digest strength.** Fresh 16-byte `SecureRandom` salt per hash (`LoginService.java:301-310`),
  256-bit derived key, and `Account` stores only the encoded record (`LoginService.java:104`).
- **No injection or log-forging surface from identifiers.** The exact-match allowlist
  `Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")` (`LoginService.java:57`), applied before the
  store is consulted and with no trimming or case folding, means no CR/LF, quote, `<` or space can
  ever become a tracker key, a store key, or a substring of an audit line. Exact matching also
  prevents the trailing-normalisation account confusion.
- **Lockout cannot be lifted by guessing the password.** `recordSuccess`
  (`LoginService.java:502-514`) forgets the failure count but returns the state unchanged while
  `lockedUntilMillis > now`; only the timer or the explicit operator `clear` ends a suspension.
- **Failures during a suspension are inert.** `recordFailure` returns early when
  `lockedUntilMillis > now` (`LoginService.java:479-481`), so an attacker inside the window can
  neither double-count nor extend the deadline.
- **Per-username serialisation of policy transitions.** `recordFailure`, `recordSuccess`,
  `remainingLockMillis` and `failureCount` all run their read-modify-write inside
  `ConcurrentHashMap.compute`, so the counter/lock state machine cannot interleave for a given key
  (the suite pins "exactly one thread reports the trip" with 32 concurrent failures).
- **Tracker state cannot be grown without bound.** Unknown usernames accumulate state, but
  `purgeIfNeeded`/`purgeExpired` (`LoginService.java:575-591`, `601-605`) sweep keys idle beyond a
  retention window (≈40 minutes with the shipped 15-minute lock / 10-minute window defaults,
  `LoginService.java:425-427`), on a cadence capped at one sweep per 15 seconds
  (`LoginService.java:461`), so random-name churn does not create unbounded memory or unbounded
  sweep cost.
- **Sweep and mutator do not race, and the purge watermark is safely published.**
  `entrySet().removeIf` (`LoginService.java:578-586`) synchronises on each hash bucket exactly as
  `compute` does, so an idle verdict cannot be taken from a torn snapshot of a `State` another
  thread is updating, and the documented invariant at `LoginService.java:613` holds.
  `lastPurgeMillis` is declared `volatile` (`LoginService.java:422`) and is only ever written
  inside `synchronized (purgeLock)` (`587-589`), so the unlocked read in `purgeIfNeeded` (`602`) is
  not a data race — concurrent duplicate sweeps are possible and harmless.
- **Configuration errors fail loudly.** Both `PasswordHasher` and `LoginAttemptTracker`
  constructors reject out-of-range cost factors, non-positive durations, a `backoffFactor` below
  1.0, a `maxLockDuration` that does not cover `lockDuration`, and a null clock (`258-260`,
  `433-452`) rather than defaulting to something permissive.
- **The audit hook never receives a credential.** `AuditSink.record` takes only username, status
  and retry seconds (`LoginService.java:106-111`); no call site passes a password or a hash.
- **Unknown-account lookup is indistinguishable from a wrong password.** `AccountStore.find`
  returning `Optional.empty()` takes the same derived-key path and the same generic wording
  (`LoginService.java:175-182`), and the `AccountStore` javadoc (`90-98`) tells implementers to
  surface genuine absence only, never an error — so a DB outage cannot be turned into an oracle or
  an open door.
- **No session, cookie, token, redirect, template, SQL or deserialisation surface** exists in this
  file, so the corresponding OWASP Top 10 classes are not applicable here; note that
  `login()` is an authentication primitive only and grants no session, which `README.md` states.
