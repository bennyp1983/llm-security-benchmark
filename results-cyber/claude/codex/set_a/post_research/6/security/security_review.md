# Security Review: Java Username/Password Authentication Component (`example.security.auth`)

## 1. Executive Summary

The component under review is a self-contained Java 17 username/password authentication module.
`AuthenticationService.authenticate` validates a username and `char[]` password, registers the
attempt with a rate limiter, verifies the password against a `CredentialStore` (PBKDF2-HMAC-SHA-256),
creates a server-side session keyed by a SHA-256 digest of a 256-bit CSPRNG token, returns a
`__Host-`prefixed `Secure; HttpOnly; SameSite=Strict` cookie, and appends a pseudonymised event to an
owner-private rolling audit log.

The cryptographic core is genuinely strong: PBKDF2-HMAC-SHA-256 with 600,000 iterations and a
128-bit random salt, constant-time digest comparison (`MessageDigest.isEqual`), CSPRNG-generated
session tokens that are stored only as digests, HMAC-SHA-256 domain-separated correlation
pseudonyms instead of raw usernames/IPs in logs, a generic identical failure message on every
failure path, and 0700/0600-enforced audit files. No hardcoded working secret exists.

The important findings are not in the crypto but in the enforcement and availability logic:

- **The rate limiter never actually blocks anything** (SEC-01). A `THROTTLED` decision is computed,
  logged, and then discarded: the full password verification still runs and a correct password still
  produces a session. The caller cannot even see that the attempt was throttled, so the "apply a
  delay at the HTTP edge" mitigation the README relies on is not implementable. Brute force and
  credential stuffing are unrestricted, and each unrestricted attempt costs a 600,000-iteration KDF.
- **The limiter's own capacity guard converts into a login outage** (SEC-02). An attacker who sends
  ~100,000 attempts with distinct syntactically-valid usernames fills the account map; after that,
  every login for an account not already tracked throws and fails closed.
- **Failure, throttle and internal-error events are best-effort only** (SEC-03): `logFailure`
  swallows every audit exception, so an attacker who can break audit I/O brute-forces with no record.

Two lower-severity issues round out the report: an account-existence timing oracle when stored
records use a work factor above the dummy record's fixed 600,000 iterations (SEC-04), a silent
`Instant.EPOCH` substitution when the clock is unavailable or out of range (SEC-05), and a
correlation-key collision between all invalid usernames and a real account literally named
`invalid` (SEC-06).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/example/security/auth/AuthenticationService.java` | Orchestrates one login attempt: validate, throttle, verify, create session, audit. | Input validation, rate-limit decision handling, session token generation, cookie attributes, generic failure messages, credential zeroisation, HMAC pseudonymisation, clock handling. |
| `src/main/java/example/security/auth/PasswordVerifier.java` | PBKDF2-HMAC-SHA-256 derivation and verification. | KDF algorithm/work factor, salt use, constant-time comparison, password length/charset bounds, buffer clearing. |
| `src/main/java/example/security/auth/PasswordRecord.java` | Validated stored-credential value object. | Salt/hash length and iteration-count range validation, redacted `toString()`, defensive copies. |
| `src/main/java/example/security/auth/CredentialStore.java` | Interface for server-side credential state. | Documents the atomic-check and equal-work contract for adapters. |
| `src/main/java/example/security/auth/InMemoryCredentialStore.java` | Immutable in-process credential map. | Username canonicalisation/duplicate rejection, dummy-KDF path for unknown accounts (timing), map size bound. |
| `src/main/java/example/security/auth/LoginRateLimiter.java` | Limiter contract (`ALLOW` / `THROTTLED`). | Defines per-source and per-account attempt registration as atomic. |
| `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java` | Synchronized fixed-window limiter. | Counter atomicity, window expiry, `MAX_KEYS` capacity guard that throws, success-path counter reset. |
| `src/main/java/example/security/auth/SessionStore.java` | Session storage contract. | States that only the SHA-256 token digest is stored, never the bearer token. |
| `src/main/java/example/security/auth/InMemorySessionStore.java` | Bounded in-process session table. | Digest length validation, account-id allow-list, expiry clamping to 24 h, capacity bound, atomic `putIfAbsent`. |
| `src/main/java/example/security/auth/AuditSink.java` | Audit append contract. | States the event must be durably retained or an exception thrown. |
| `src/main/java/example/security/auth/AuthenticationEvent.java` | Immutable audit event record. | Enforces that every correlation value is a 64-hex digest and that outcome/reason/session are consistent; carries no password, username, IP or token. |
| `src/main/java/example/security/auth/PrivateRollingFileAuditSink.java` | Owner-private rolling audit log writer. | 0700 directory / 0600 file permission enforcement, symlink and regular-file checks, `NOFOLLOW_LINKS` open, file lock, `force(true)`, bounded record size and rotation. |
| `src/test/java/.../AuthenticationServiceTest.java`, `PrivateRollingFileAuditSinkTest.java` | Unit tests. | Assert generic failures, cookie attributes, password clearing, redacted `toString()`, log file mode; reviewed for coverage gaps only, not a finding source. |
| `pom.xml` | Build definition. | Pinned plugin and JUnit 5.11.4 versions, no runtime third-party dependency. |
| `README.md` | Design/threat documentation. | Documents trust boundaries and deployment obligations; reviewed against actual code behaviour. |

Not reviewed as source: prebuilt artefacts under `target/` (compiled `.class`/`.jar` output of the
same sources) and `prompt.txt` / `result.md` / `return.txt` / `prompt_hash.txt` (harness metadata).
Nothing in the tree was executed, built or imported.

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordVerifier`, `PasswordRecord`,
  the HMAC correlation function and token generation in `AuthenticationService` — checked for
  deprecated hashes, weak KDF parameters, salt reuse, hardcoded keys, entropy source and
  non-constant-time comparison. No crypto-primitive weakness found (see section 6).
- `testing-api-authentication-weaknesses`: applied to `AuthenticationService.authenticate`,
  `InMemoryCredentialStore.verify` and `InMemorySessionStore` — checked token entropy and
  predictability, token leakage into logs, account enumeration by response body and by response
  time, credential-stuffing resistance and session handling. Produced SEC-01 and SEC-04.
- `implementing-api-rate-limiting-and-throttling`: applied to `InMemoryLoginRateLimiter` and its
  call site — checked that an exceeded limit actually denies the request, that per-IP and per-account
  limits are both enforced, and that limiter state is bounded. Produced SEC-01 and SEC-02.
- `performing-api-rate-limiting-bypass`: applied to the throttle decision path — checked whether the
  limit can be bypassed via the identity the limiter keys on (source supplied by the adapter) and
  whether exceeding the limit changes the outcome. Confirmed SEC-01; the keying itself is sound
  because the source must be the socket peer, not a client header.
- `exploiting-race-condition-vulnerabilities`: applied to `InMemoryLoginRateLimiter.registerAttempt`,
  `InMemorySessionStore.create` and `PrivateRollingFileAuditSink.append` — checked check-then-act
  atomicity under parallel login attempts. No TOCTOU finding (see section 6).
- `testing-for-sensitive-data-exposure`: applied to `AuthenticationEvent`,
  `PrivateRollingFileAuditSink.format`, `Result.toString()`, `PasswordRecord.toString()` and the
  password `char[]` lifecycle — checked for credentials, tokens, raw usernames or IPs reaching logs,
  messages or world-readable files. No exposure finding; contributed SEC-03 and SEC-06 on log
  integrity rather than confidentiality.
- `performing-security-headers-audit`: applied to the `Set-Cookie` string built at
  `AuthenticationService.java:120-122` — checked `Secure`, `HttpOnly`, `SameSite`, `Path`, `Domain`
  and the `__Host-` prefix constraints. No finding.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:
  the `Instant.EPOCH` clock-failure substitution and other fail-open/fail-closed exception handling
  (CWE-754, SEC-05); audit-write durability and loss semantics (CWE-778, SEC-03); unbounded in-memory
  state growth in the limiter and session store (CWE-770, SEC-02); filesystem permission and symlink
  handling in `PrivateRollingFileAuditSink` (CWE-59/CWE-732); and log-record attribution ambiguity
  (SEC-06). There is no SQL, OS command execution, deserialization, XML/XXE, template rendering,
  HTML output or outbound network call anywhere in the component, so the corresponding injection,
  SSRF and XSS skills were deliberately not selected.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate-limit decision is computed but never enforced; brute force and credential stuffing proceed unrestricted | High | CWE-307 | `src/main/java/example/security/auth/AuthenticationService.java:73-127` |
| SEC-02 | Limiter capacity guard lets attacker-chosen usernames deny logins for all untracked accounts | Medium | CWE-770 | `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java:40-43` |
| SEC-03 | Failure, throttle and internal-error audit events are silently discarded on audit I/O error | Medium | CWE-778 | `src/main/java/example/security/auth/AuthenticationService.java:154-160` |
| SEC-04 | Account-existence timing oracle: dummy KDF work factor is fixed while stored records may use up to 2,000,000 iterations | Low | CWE-208 | `src/main/java/example/security/auth/InMemoryCredentialStore.java:43-51` |
| SEC-05 | Clock failure or out-of-range time silently substitutes `Instant.EPOCH`, corrupting audit timestamps and wedging the limiter window | Low | CWE-754 | `src/main/java/example/security/auth/AuthenticationService.java:175-181` |
| SEC-06 | All invalid usernames share the correlation key of a real account named `invalid`, producing misattributed audit records | Low | CWE-117 | `src/main/java/example/security/auth/AuthenticationService.java:71` |

## 5. Detailed Findings

### SEC-01: Rate-limit decision is computed but never enforced; brute force and credential stuffing proceed unrestricted
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/example/security/auth/AuthenticationService.java:73-127` (decision captured at 78-79, ignored at 86-90 and 96-123, only logged at 125-126); result type without a throttle signal at `src/main/java/example/security/auth/AuthenticationService.java:217-229`

**Vulnerable code:**
```java
// src/main/java/example/security/auth/AuthenticationService.java:73-96
        boolean throttled = false;
        byte[] token = null;
        byte[] tokenDigest = null;
        try {
            try {
                throttled = limiter.registerAttempt(sourceKey, subjectKey, now)
                        == LoginRateLimiter.Decision.THROTTLED;
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            Optional<CredentialStore.AuthenticatedPrincipal> principal = Optional.empty();
            try {
                if (canonical != null && validPassword) {
                    principal = credentials.verify(canonical, password);
                } else {
                    PasswordVerifier.verify(INVALID_PASSWORD.clone(), dummyRecord);
                }
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            // Correct credentials bypass a hostile account-induced throttle; failed attempts do not.
            if (principal.isPresent()) {
```

```java
// src/main/java/example/security/auth/AuthenticationService.java:125-127
            logFailure(now, subjectKey, sourceKey, throttled
                    ? AuthenticationEvent.Reason.THROTTLED : AuthenticationEvent.Reason.REJECTED);
            return Result.failure();
```

**Why it is a problem:** `throttled` never changes control flow. Once the limit is exceeded the code
still performs the full PBKDF2 verification and, on a correct password, still mints a session
(`96-123`); on a wrong password it returns exactly the same `Result.failure()` it would have returned
without any limiter at all. The limiter is therefore purely advisory — it only decorates the audit
record with `Reason.THROTTLED`. Consequences:

1. **Unrestricted online guessing.** An attacker can send an unbounded number of attempts against one
   account from one source; attempt *n* is treated identically to attempt 1. Credential stuffing
   across many accounts is equally unimpeded. The comment at line 95 justifies letting a *correct*
   password through to avoid third-party lockout, but the code also lets every *incorrect* password
   through to verification and to the same answer, which is the part that defeats the control.
2. **CPU resource exhaustion (CWE-400 amplification).** Every attempt — throttled or not, valid
   username or not — runs at least one 600,000-iteration PBKDF2 derivation
   (`PasswordVerifier.java:53-62`, `PasswordRecord.MIN_ITERATIONS`). A rate limiter that never
   short-circuits means a few hundred requests per second cost the server several CPU-seconds each,
   so the deliberately expensive KDF becomes an attacker amplifier.
3. **The documented compensating control cannot be implemented.** `README.md` instructs the HTTP edge
   to "apply a bounded delay/queue to `THROTTLED` events", but `Result` exposes only
   `authenticated`, a fixed `message`, and `setCookieHeader` (`217-229`). The throttle decision never
   leaves the component, so no caller can act on it. The mitigation is unavailable in practice.

**Fix:** make the limiter authoritative for *failed* attempts while keeping the anti-lockout property.
Verify the password (so a legitimate user holding the correct secret is never locked out by a third
party), but when the attempt is throttled *and* verification failed, stop doing attacker-controlled
work and tell the caller to back off — and surface the decision so the edge can delay or return 429.
Also bound verification work per source so a throttled source cannot keep buying KDF cycles.

```java
// Result gains a retry-after signal; message and cookie semantics are unchanged.
public record Result(boolean authenticated, String message, String setCookieHeader,
        boolean throttled, long retryAfterSeconds) {
    public Result {
        if (message == null || message.length() > 64) throw new IllegalArgumentException("Invalid result");
        if (authenticated != (setCookieHeader != null)) throw new IllegalArgumentException("Invalid result");
        if (retryAfterSeconds < 0 || retryAfterSeconds > 3_600) throw new IllegalArgumentException("Invalid result");
    }
    static Result success(String cookie) { return new Result(true, "Authenticated.", cookie, false, 0); }
    static Result failure() { return new Result(false, GENERIC_FAILURE, null, false, 0); }
    static Result throttledFailure(long retryAfterSeconds) {
        // Identical message and no account-existence detail: only the transport-level hint differs.
        return new Result(false, GENERIC_FAILURE, null, true, retryAfterSeconds);
    }
    @Override public String toString() {
        return "Result[authenticated=" + authenticated + ", message=" + message
                + ", setCookieHeader=" + (setCookieHeader == null ? "null" : "REDACTED") + "]";
    }
}

// In authenticate(), replace lines 73-127 behaviour:
LoginRateLimiter.Decision decision;
try {
    decision = limiter.registerAttempt(sourceKey, subjectKey, now);
} catch (RuntimeException e) {
    return internalFailure(now, subjectKey, sourceKey);
}
boolean throttled = decision == LoginRateLimiter.Decision.THROTTLED;

// Hard ceiling: beyond it, do no attacker-funded KDF work at all for this source.
if (throttled && limiter.sourceAttempts(sourceKey, now) > HARD_SOURCE_LIMIT) {
    logFailure(now, subjectKey, sourceKey, AuthenticationEvent.Reason.THROTTLED);
    return Result.throttledFailure(limiter.windowSeconds());
}

Optional<CredentialStore.AuthenticatedPrincipal> principal = Optional.empty();
try {
    if (canonical != null && validPassword) {
        principal = credentials.verify(canonical, password);
    } else {
        PasswordVerifier.verify(INVALID_PASSWORD.clone(), dummyRecord);
    }
} catch (RuntimeException e) {
    return internalFailure(now, subjectKey, sourceKey);
}

if (principal.isPresent()) {
    // Unchanged: a correct proof is honoured even while throttled, so no third party can
    // lock a legitimate user out by burning the account counter.
    ... existing session-creation and success-audit block ...
}

// A failed attempt while throttled is now denied as throttled, not merely recorded as such.
if (throttled) {
    logFailure(now, subjectKey, sourceKey, AuthenticationEvent.Reason.THROTTLED);
    return Result.throttledFailure(limiter.windowSeconds());
}
logFailure(now, subjectKey, sourceKey, AuthenticationEvent.Reason.REJECTED);
return Result.failure();
```

### SEC-02: Limiter capacity guard lets attacker-chosen usernames deny logins for all untracked accounts
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (fail-closed denial of service)
- **Location:** `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java:40-43`, reached from `src/main/java/example/security/auth/AuthenticationService.java:77-82`

**Vulnerable code:**
```java
// src/main/java/example/security/auth/InMemoryLoginRateLimiter.java:37-46
        boolean throttled = count(sources, sourceKey, now) >= perSource
                || count(accounts, accountKey, now) >= perAccount;
        // Capacity is checked for both maps before either is mutated.
        if ((!sources.containsKey(sourceKey) && sources.size() >= MAX_KEYS)
                || (!accounts.containsKey(accountKey) && accounts.size() >= MAX_KEYS)) {
            throw new IllegalStateException("Rate-limit capacity exhausted");
        }
        increment(sources, sourceKey, now);
        increment(accounts, accountKey, now);
        return throttled ? Decision.THROTTLED : Decision.ALLOW;
```

```java
// src/main/java/example/security/auth/AuthenticationService.java:77-82
            try {
                throttled = limiter.registerAttempt(sourceKey, subjectKey, now)
                        == LoginRateLimiter.Decision.THROTTLED;
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }
```

**Why it is a problem:** the account key is derived from the attacker-supplied username
(`AuthenticationService.java:71`), and any string matching `[a-z0-9][a-z0-9._@-]{0,63}` yields a
distinct key. An attacker sends ~100,000 login attempts with distinct random usernames
(`u0000001`, `u0000002`, …) inside one rate-limit window — which SEC-01 guarantees nothing will slow
down. `accounts` now holds `MAX_KEYS` entries. From that moment, any login for an account whose key
is *not already in the map* — i.e. every legitimate user who has not just tried to log in — hits the
`IllegalStateException`, which the service converts to `internalFailure` and a generic failure.
Authentication fails closed for the whole user population until the window (up to one hour,
`InMemoryLoginRateLimiter.java:22-23`) rolls the entries out, and the attacker can refresh the fill
indefinitely. Secondarily, `expire(now)` walks both maps on every single attempt
(`InMemoryLoginRateLimiter.java:69-77`), so a 100,000-entry map adds an O(n) scan inside the global
lock on each login, compounding the slowdown.

**Fix:** never let limiter bookkeeping decide a legitimate user's outcome. Evict the oldest/least
relevant counter instead of throwing, and keep a separate, small reserved headroom so new keys always
fit. If capacity really is exhausted, degrade to source-only limiting rather than denying the login.

```java
private static final int MAX_KEYS = 100_000;
// LinkedHashMap in access order gives O(1) eviction of the stalest counter.
private final Map<String, Counter> sources = new LinkedHashMap<>(16, 0.75f, true);
private final Map<String, Counter> accounts = new LinkedHashMap<>(16, 0.75f, true);

@Override public synchronized Decision registerAttempt(String sourceKey, String accountKey, Instant now) {
    validateKey(sourceKey); validateKey(accountKey); validateTime(now);
    expire(now);
    boolean throttled = count(sources, sourceKey, now) >= perSource
            || count(accounts, accountKey, now) >= perAccount;
    // Capacity pressure must degrade the limiter, never deny authentication.
    evictOldestIfFull(sources, sourceKey);
    evictOldestIfFull(accounts, accountKey);
    increment(sources, sourceKey, now);
    increment(accounts, accountKey, now);
    return throttled ? Decision.THROTTLED : Decision.ALLOW;
}

private static void evictOldestIfFull(Map<String, Counter> map, String key) {
    if (map.containsKey(key)) return;
    Iterator<Map.Entry<String, Counter>> it = map.entrySet().iterator();
    while (map.size() >= MAX_KEYS && it.hasNext()) { it.next(); it.remove(); }
}
```

### SEC-03: Failure, throttle and internal-error audit events are silently discarded on audit I/O error
- **Severity:** Medium
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/example/security/auth/AuthenticationService.java:154-160`

**Vulnerable code:**
```java
// src/main/java/example/security/auth/AuthenticationService.java:154-160
    private void logFailure(Instant now, String subject, String source, AuthenticationEvent.Reason reason) {
        try {
            audit.append(event(now, AuthenticationEvent.Outcome.FAILURE, reason, subject, source, null));
        } catch (Exception ignored) {
            // Authentication still fails closed. The host must treat audit I/O failure as unhealthy.
        }
    }
```

**Why it is a problem:** `AuditSink` explicitly contracts that "`append` must durably retain the event
or throw; it must never silently discard it" (`AuditSink.java:3`), and the task this component was
built for requires that unsuccessful login attempts be retained for later review. Every failure path
— rejected password, throttled attempt, limiter failure, session-store failure — funnels through
`logFailure`, which swallows `Exception` without any signal to the caller, no counter, and no
rethrow. An attacker who can make audit writes fail removes exactly the evidence of their own brute
force while authentication keeps answering normally: fill the filesystem containing the audit
directory, or trip one of `PrivateRollingFileAuditSink`'s own safety checks
(`PrivateRollingFileAuditSink.java:54`, `:71`, `:85` all throw), and failed-login records stop being
written. The code comment delegates detection to "the host", but nothing is exposed for the host to
observe — unlike the success path, which correctly revokes the session and fails closed when the
audit append throws (`AuthenticationService.java:115-118`).

**Fix:** keep failing closed for the user, but make audit loss observable and non-silent: count the
drops, surface them through a health signal the host can read, and preserve the underlying exception
for the application's own error log (not for the user-visible message).

```java
    private final java.util.concurrent.atomic.AtomicLong droppedAuditEvents =
            new java.util.concurrent.atomic.AtomicLong();

    /** Non-zero means authentication events have been lost; the host must alarm on any increase. */
    public long droppedAuditEventCount() { return droppedAuditEvents.get(); }

    private void logFailure(Instant now, String subject, String source, AuthenticationEvent.Reason reason) {
        try {
            audit.append(event(now, AuthenticationEvent.Outcome.FAILURE, reason, subject, source, null));
        } catch (Exception e) {
            // Authentication still fails closed, but the loss is counted and reported, never silent.
            droppedAuditEvents.incrementAndGet();
            auditFailureListener.onAuditWriteFailure(e); // no credential, token or raw identifier
        }
    }
```

### SEC-04: Account-existence timing oracle: dummy KDF work factor is fixed while stored records may use up to 2,000,000 iterations
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/example/security/auth/InMemoryCredentialStore.java:43-51`; work factor read at `src/main/java/example/security/auth/PasswordVerifier.java:31-33`; range allowed at `src/main/java/example/security/auth/PasswordRecord.java:10-11,23-25`

**Vulnerable code:**
```java
// src/main/java/example/security/auth/InMemoryCredentialStore.java:43-51
    @Override public Optional<AuthenticatedPrincipal> verify(String canonicalUsername, char[] password) {
        Entry entry = entries.get(canonicalUsername);
        if (entry == null) {
            PasswordVerifier.verify(password, dummyRecord);
            return Optional.empty();
        }
        return PasswordVerifier.verify(password, entry.password())
                ? Optional.of(entry.principal()) : Optional.empty();
    }
```

```java
// src/main/java/example/security/auth/PasswordVerifier.java:31-33
    static boolean verify(char[] password, PasswordRecord record) {
        byte[] candidate = derive(password, record.salt(), record.iterations());
```

**Why it is a problem:** the unknown-account path always derives with `dummyRecord`, which
`hashForStorage` pins to `PasswordRecord.MIN_ITERATIONS` (600,000, `PasswordVerifier.java:22-24`).
The known-account path derives with that account's own `record.iterations()`, which `PasswordRecord`
permits to be anything up to `MAX_ITERATIONS` = 2,000,000. As soon as any account is stored with a
raised work factor — the obvious reason the range exists, and what happens naturally as a deployment
ages its parameters — a login against that account takes up to ~3.3× longer than a login against a
non-existent one. The response body is correctly identical (`GENERIC_FAILURE` everywhere), but the
latency difference is large, stable and remotely measurable, so an attacker can enumerate valid
usernames and then concentrate the unthrottled guessing of SEC-01 on real accounts. The equal-work
promise in `CredentialStore.java:11-13` and in `README.md` is therefore not met by this adapter.

**Fix:** make the dummy derivation use the same work factor the real records use, by deriving the
dummy record's iteration count from the store's actual contents (the maximum in use) rather than
from the floor constant.

```java
    private final PasswordRecord dummyRecord;

    public InMemoryCredentialStore(Map<String, Entry> serverEntries) {
        // ... existing validation and copy ...
        this.entries = Map.copyOf(copy);
        // Equal work for unknown accounts: match the highest work factor any real record uses.
        int dummyIterations = this.entries.values().stream()
                .mapToInt(e -> e.password().iterations())
                .max().orElse(PasswordRecord.MIN_ITERATIONS);
        char[] dummy = new char[32];
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < dummy.length; i++) dummy[i] = (char) ('!' + random.nextInt(90));
        try {
            this.dummyRecord = PasswordVerifier.hashForStorage(dummy, random, dummyIterations);
        } finally {
            Arrays.fill(dummy, '\0');
        }
    }
```
```java
// PasswordVerifier: allow an explicit work factor instead of always using the floor.
    public static PasswordRecord hashForStorage(char[] password, SecureRandom random, int iterations) {
        validatePassword(password);
        if (random == null) throw new IllegalArgumentException("SecureRandom is required");
        byte[] salt = new byte[PasswordRecord.SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, iterations);   // PasswordRecord validates the range
        try {
            return new PasswordRecord(salt, hash, iterations);
        } finally {
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    public static PasswordRecord hashForStorage(char[] password, SecureRandom random) {
        return hashForStorage(password, random, PasswordRecord.MIN_ITERATIONS);
    }
```

### SEC-05: Clock failure or out-of-range time silently substitutes `Instant.EPOCH`, corrupting audit timestamps and wedging the limiter window
- **Severity:** Low
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `src/main/java/example/security/auth/AuthenticationService.java:175-181`, consumed at `:78`, `:102`, `:112` and `:156`

**Vulnerable code:**
```java
// src/main/java/example/security/auth/AuthenticationService.java:175-181
    private Instant safeNow() {
        Instant now;
        try { now = clock.instant(); } catch (RuntimeException e) { return Instant.EPOCH; }
        Instant lower = Instant.parse("2020-01-01T00:00:00Z");
        Instant upper = Instant.parse("2200-01-01T00:00:00Z");
        return now.isBefore(lower) || !now.isBefore(upper) ? Instant.EPOCH : now;
    }
```

**Why it is a problem:** rule 6 of the component's own brief says to reject invalid input rather than
substitute a permissive default, yet a broken or skewed clock is replaced with a *valid-looking*
timestamp that then flows into three security decisions:

- **Audit integrity.** Every event written while the clock is bad is stamped
  `1970-01-01T00:00:00Z` (`PrivateRollingFileAuditSink.java:94`). `AuthenticationEvent` accepts it
  because it only null-checks `occurredAt` (`AuthenticationEvent.java:14`). A reviewer reconstructing
  an attack timeline sees a block of epoch-dated records with no indication the time was never known.
- **Limiter window.** `Counter.started` becomes `EPOCH` and `expired()` compares
  `!now.isBefore(started.plus(window))` with `now == EPOCH` (`InMemoryLoginRateLimiter.java:79`), so
  counters created in this state never expire while it persists — they accumulate until SEC-02's
  capacity limit, turning a transient clock fault into a lasting limiter malfunction.
- **Session creation.** `expires = EPOCH.plus(sessionTtl)` is in the past, so
  `InMemorySessionStore.create` rejects it against its own clock
  (`InMemorySessionStore.java:25-29`) and every correct login becomes an `INTERNAL_ERROR`. That part
  at least fails closed, but the user-visible effect is a full authentication outage whose cause is
  recorded only as epoch-dated internal errors.

**Fix:** treat an unusable clock as the exceptional condition it is — refuse the attempt without
fabricating a time, and keep the user-visible result generic.

```java
    /** @throws IllegalStateException if the platform clock cannot be trusted for a security decision. */
    private Instant trustedNow() {
        Instant now;
        try {
            now = clock.instant();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Trusted time source unavailable", e);
        }
        if (now.isBefore(CLOCK_LOWER_BOUND) || !now.isBefore(CLOCK_UPPER_BOUND)) {
            throw new IllegalStateException("Trusted time source out of range");
        }
        return now;
    }

    public Result authenticate(String username, char[] password, InetAddress source) {
        final Instant now;
        try {
            now = trustedNow();
        } catch (IllegalStateException e) {
            // No timestamp means no auditable decision: fail closed, generic message, no audit forgery.
            unauditableFailures.incrementAndGet();
            if (password != null) Arrays.fill(password, '\0');
            return Result.failure();
        }
        // ... unchanged remainder of authenticate() ...
    }
```

### SEC-06: All invalid usernames share the correlation key of a real account named `invalid`, producing misattributed audit records
- **Severity:** Low
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `src/main/java/example/security/auth/AuthenticationService.java:71`

**Vulnerable code:**
```java
// src/main/java/example/security/auth/AuthenticationService.java:71
        String subjectKey = correlate("account", canonical == null ? "invalid" : canonical);
```

**Why it is a problem:** the sentinel `"invalid"` is placed in the *same* HMAC domain
(`"account"`) as real canonical usernames, and `"invalid"` itself satisfies the username grammar
`[a-z0-9][a-z0-9._@-]{0,63}` — `AuthenticationService.canonicalUsername("invalid")` succeeds. So
`correlate("account", "invalid")` for a malformed submission is byte-identical to the subject key of a
genuine account named `invalid`. Two consequences: (a) an attacker can flood the audit log with
malformed-username attempts that an analyst will attribute to that real account, muddying or
discrediting the evidence trail — the pseudonymisation that makes the log privacy-safe also makes the
collision impossible to untangle after the fact; and (b) the same key is used as the limiter's account
key (`:78`), so unrelated garbage traffic shares a counter with that account. Domain separation is
done correctly between `account`, `source` and `session`, but not between *real* and *sentinel*
subjects inside the account domain.

**Fix:** give the sentinel its own HMAC domain, so no real username can ever collide with it.

```java
        String subjectKey = canonical == null
                ? correlate("account-invalid", "")   // separate domain: cannot collide with any username
                : correlate("account", canonical);
```

## 6. Verified Controls and Checks With No Finding

- **Password hashing algorithm and work factor:** `PasswordVerifier.java:13,53-56` uses
  `PBKDF2WithHmacSHA256` with a 256-bit output; `PasswordRecord.java:10` enforces a minimum of
  600,000 iterations, matching the OWASP Password Storage guidance for PBKDF2-HMAC-SHA-256. No MD5,
  SHA-1, unsalted hash, or home-made KDF anywhere in the tree.
- **Salting:** a fresh 128-bit salt per record from the injected `SecureRandom`
  (`PasswordVerifier.java:20-22`); `PasswordRecord.java:20-22` rejects any record whose salt or hash
  length is wrong, so a poisoned credential row cannot shrink the salt.
- **Constant-time credential comparison:** `MessageDigest.isEqual` at `PasswordVerifier.java:35`,
  not `Arrays.equals` or `String.equals`.
- **Session token generation and storage:** 32 bytes (256 bits) from the injected `SecureRandom`
  (`AuthenticationService.java:99-100`); only the SHA-256 digest is persisted
  (`:101`, `InMemorySessionStore.java:30-31`), so a session-store compromise does not yield usable
  bearer tokens. Tokens are never accepted from, nor derivable by, the caller.
- **Event-ID generation:** RFC 4122 v4 layout filled from the same CSPRNG
  (`AuthenticationService.java:164-171`), not `UUID.randomUUID()` on an unspecified source and not a
  counter or timestamp.
- **Cookie attributes:** `AuthenticationService.java:120-122` emits
  `__Host-session=…; Path=/; Max-Age=<bounded>; Secure; HttpOnly; SameSite=Strict` with no `Domain`,
  which satisfies every `__Host-` prefix requirement; the TTL is range-checked to 1 minute–24 hours at
  `:47-50`. The cookie value is Base64url, so it cannot inject CR/LF into the response header.
- **Hardcoded secrets:** none. The correlation key is injected and length-checked
  (`AuthenticationService.java:51-55`), defensively cloned, and used only as an HMAC key.
  `INVALID_PASSWORD` (`:26`) is a fixed dummy input to a dummy KDF, not a credential that
  authenticates anything; `hashForStorage` creates random dummy passwords (`:56-62`,
  `InMemoryCredentialStore.java:33-40`). No key, password or token appears in `pom.xml`, `README.md`
  or any source file.
- **Secrets and tokens kept out of logs and messages:** `AuthenticationEvent` structurally forbids
  anything but 64-hex keyed digests (`AuthenticationEvent.java:25-29`); the log line
  (`PrivateRollingFileAuditSink.java:93-97`) contains only enums, a UUID and those digests;
  `Result.toString()` redacts the cookie (`AuthenticationService.java:225-228`) and
  `PasswordRecord.toString()` redacts credential material (`PasswordRecord.java:47`). No
  `printStackTrace`, `System.out`/`err`, or exception message carrying user input exists.
- **Credential zeroisation:** the caller's `char[]` is cleared on every return path
  (`AuthenticationService.java:128-133`), as are the token, token digest, derived candidate/expected
  hashes (`PasswordVerifier.java:36-39`), the salt and hash in `hashForStorage` (`:25-28`), and the
  `PBEKeySpec` via `clearPassword()` (`:60`). The password is never converted to a `String`.
- **Generic, non-enumerating failure responses:** every failure returns the identical
  `Result.failure()` with the single message `"Invalid username or password."`
  (`AuthenticationService.java:23,223`), whether the username is malformed, the account is unknown,
  the password is wrong, the attempt is throttled, or an internal error occurred. The dummy KDF on the
  invalid-input path (`:88-90`) keeps the work comparable; the residual timing gap is SEC-04.
- **Fail-closed error handling:** every `catch` in `authenticate` returns a failure, never a success
  (`:80-82`, `:91-93`, `:106-109`, `:115-118`); a `false` from `sessions.create` is treated as failure
  (`:103-105`); and when the success audit write throws, the just-created session is revoked before
  returning (`:116-117`). No path grants authentication on a missing or failed check.
- **Input validation / trust boundaries:** username is allow-listed to
  `[a-z0-9][a-z0-9._@-]{0,63}` with explicit length bound and `Locale.ROOT` canonicalisation
  (`:24,136-141,199-202`) — `Locale.ROOT` avoids the Turkish-dotless-I style canonicalisation
  mismatch; password is bounded to 1–128 chars with NUL and surrogates rejected
  (`PasswordVerifier.java:42-51`); the source address must be a real 4- or 16-byte `InetAddress`
  (`AuthenticationService.java:207-215`) and is used only as a keyed pseudonym, never as proof of
  identity. Server-side `accountId` values coming back from the store are themselves re-validated
  against `[A-Za-z0-9_-]{1,64}` (`CredentialStore.java:18`, `InMemorySessionStore.java:24`). The
  limiter re-validates its keys as 64-hex (`InMemoryLoginRateLimiter.java:80-82`). All configuration
  values (session TTL, capacities, window, counts, retention bounds) have explicit min/max ranges with
  no permissive default.
- **Rate-limit keying cannot be spoofed by the client:** the limiter keys on the `InetAddress` passed
  by the adapter, and `AuthenticationService.java:65` plus `README.md` require that to be the socket
  peer rather than a `Forwarded`/`X-Forwarded-For` header — this closes the usual header-spoofing
  rate-limit bypass. Both a per-source *and* a per-account counter are maintained
  (`InMemoryLoginRateLimiter.java:37-46`), and `recordSuccess` deliberately clears only the account
  counter, never the source counter (`:49-53`), so an attacker cannot reset their own source limit by
  authenticating to an account they control. The anti-lockout property is real; what is missing is
  enforcement (SEC-01). A missing or invalid source collapses to a single shared bucket
  (`AuthenticationService.java:208,211`), which is documented in `README.md` and does not grant
  privilege.
- **Concurrency / TOCTOU:** `InMemoryLoginRateLimiter.registerAttempt` and `recordSuccess` are
  `synchronized`, and the capacity check for both maps happens before either is mutated, so count-then-
  allow is atomic (`:34-47`). `InMemorySessionStore.create` is `synchronized` and finishes with an
  atomic `putIfAbsent` on a `ConcurrentHashMap`, so a digest collision cannot overwrite an existing
  session (`:22-32`). `PrivateRollingFileAuditSink.append` is `synchronized` and additionally takes an
  OS-level `FileLock` around the write (`:51-64`). The credential map is immutable
  (`Map.copyOf`, `InMemoryCredentialStore.java:32`). The session is created server-side *before* the
  token is released to the caller. No check-then-act gap was found that an attacker can widen.
- **Audit file confidentiality and symlink safety:** the directory must be an existing real directory
  with mode exactly `0700` and must not be a symlink (`PrivateRollingFileAuditSink.java:31-41`); the
  log file is created with mode `0600` via `PosixFilePermissions.asFileAttribute` — atomically at
  creation, not chmod-after-create (`:75`); before every write the file is re-verified to be a
  non-symlink regular file with exactly `0600` (`:68-73`), the channel is opened with
  `LinkOption.NOFOLLOW_LINKS` (`:57-58`), and rotation applies the same checks to each archive and
  uses an atomic `Files.move` (`:78-91`). The path is absolutised and normalised (`:31`) and the file
  name is a constant, so no caller-controlled path traversal is possible. `channel.force(true)` gives
  durability before `append` returns.
- **Bounded storage everywhere:** audit record ≤1024 bytes (`:54`), file size and archive count
  bounded (`:42-44`), credential map ≤100,000 entries (`InMemoryCredentialStore.java:24`), session
  table ≤1,000,000 with expired entries purged on each create
  (`InMemorySessionStore.java:17,26-27`), limiter counters capped at `Integer.MAX_VALUE` to prevent
  overflow (`InMemoryLoginRateLimiter.java:64-66`), and session lifetime clamped to 24 hours in the
  store independently of the service (`InMemorySessionStore.java:27`). The limiter's cap handling is
  the exception and is reported as SEC-02.
- **Injection classes not applicable — verified by inspection:** there is no SQL or other query
  construction, no OS command or process execution, no reflection on caller-supplied names, no Java
  or other deserialization (`ObjectInputStream`, YAML, XML), no XML/XXE parsing, no template
  rendering, no HTML/JSON output of user data, and no outbound HTTP or DNS call anywhere in
  `src/main`. Consequently CWE-89, CWE-78, CWE-502, CWE-611, CWE-79 and CWE-918 have no reachable sink
  in this component.
- **Dependencies:** `pom.xml` declares no runtime third-party dependency; JUnit is pinned to 5.11.4
  at `test` scope and the compiler/surefire plugins are pinned to exact versions, so no floating or
  snapshot version is resolved at build time. The production code relies only on JDK-required
  algorithms.
