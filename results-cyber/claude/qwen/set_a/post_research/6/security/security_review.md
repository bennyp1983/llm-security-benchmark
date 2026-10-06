# Security Review: `com.example.auth` username/password authentication component

## 1. Executive Summary

The component under review is a dependency-free Java 17 username/password authentication library:
it loads credential records from an operator-supplied file, verifies a submitted password against a
peppered PBKDF2-HMAC-SHA256 digest, applies per-account lockout and per-source rate limiting, issues
an opaque server-side session identifier, and appends a structured event to a fail-closed audit log.

The code is defensively written and gets the hard parts right: parameterless credential lookup (no
SQL at all), PBKDF2-HMAC-SHA256 with an HMAC pepper held in a keystore rather than in source,
`MessageDigest.isEqual` for digest comparison, `SecureRandom` salts and 128-bit opaque session
identifiers, byte-identical denial text for every credential failure, equal PBKDF2 work on the
known/unknown-username paths plus a latency floor, strict allow-list validation of usernames,
passwords and peer addresses, owner-only permission checks on every credential file, and an audit
record format with no free-text field (so log injection is structurally impossible).

The findings are therefore not in the cryptography but in the resource and concurrency behaviour of
the throttle, the audit log and the global work budget:

* **SEC-01 (High)** — every throttled attempt still writes an audit line. Because the service refuses
  all authentication once the log reaches its 64 MiB ceiling, a single unauthenticated address can
  write the log full with near-zero CPU cost and take authentication down globally.
* **SEC-02 (Medium)** — when the per-source table is at its 20 000-key cap, buckets are evicted on
  idle time alone, ignoring an active block, so a source block shorter-lived than the configured
  window can be cleared and the per-source budget reset.
* **SEC-03 (Medium)** — `ConcurrentHashMap.compute()` remapping functions mutate the *same* map
  (`removeIf` over its entry set), which the JDK explicitly forbids and which can deadlock two
  concurrent attempts.
* **SEC-04 (Medium)** — the latency floor is applied while the caller still holds one of only four
  global derivation permits, so the effective login throughput is ~4 / floor and the service is cheap
  to saturate into blanket `WORK_UNAVAILABLE` denials.
* Plus lower-severity items: a PBKDF2 iteration floor below current OWASP guidance, an
  indefinitely-sliding session with no absolute lifetime, unsalted account identifiers in the log, a
  session table whose saturation logs other users out, and a timing oracle that reappears when the
  configured work factor exceeds the latency-floor clamp.

No SQL injection, command injection, deserialization, XSS, SSRF, hardcoded-secret or path-traversal
issue was found; see section 6 for what was verified.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/AuthenticationService.java` | Orchestrates one attempt: throttle, validate, verify, log, issue session | Decision ordering, uniform denials, audit-on-every-path, password wiping, session revoke on failure |
| `src/main/java/com/example/auth/CredentialVerifier.java` | Performs exactly one PBKDF2 derivation per attempt | Global semaphore work budget, decoy derivation for unknown users, latency padding |
| `src/main/java/com/example/auth/PasswordHasher.java` | `HMAC-SHA256(pepper, salt ‖ PBKDF2(password,salt,c))` | KDF choice and parameters, constant-time compare, canonical Base64 decode, key material wiping |
| `src/main/java/com/example/auth/KeystorePepperProvider.java` | Loads the HMAC pepper from a JCEKS/PKCS12/JKS keystore | Keystore path/type/alias validation, entry-type and key-length checks, password wiping, no exception propagation |
| `src/main/java/com/example/auth/InputValidator.java` | Validates username, password and peer address | Allow-list validation, no Unicode folding, exact UTF-8 encodability, textual-only IP literal parsing |
| `src/main/java/com/example/auth/AttemptThrottle.java` | Per-account lockout and per-source sliding window | Atomic check-and-act, bounded key tables, eviction policy, fail-closed verdicts |
| `src/main/java/com/example/auth/SessionTokenStore.java` | Issues/validates/revokes opaque session ids | 128-bit `SecureRandom` ids, server-side validity only, sliding TTL, bounded table, `Set-Cookie` builder |
| `src/main/java/com/example/auth/AuditLogger.java` | Append-only fail-closed event log | 0600 mode and inode-identity re-checks, torn-tail repair, free-space and size ceilings, write verification |
| `src/main/java/com/example/auth/AuthEvent.java` | Renders one audit line | Fixed field set, no free text, newline/control-character rejection, session-suffix truncation |
| `src/main/java/com/example/auth/AccountField.java` | Renders the account identity field of a log line | SHA-256 of the lower-cased submitted username instead of the name itself |
| `src/main/java/com/example/auth/AuthConfig.java` | Parses and bounds all configuration | Required-value policy, bounded integers, cross-field rules, file permission checks, secret erasure |
| `src/main/java/com/example/auth/FileCredentialStore.java` | Loads and validates credential records | NOFOLLOW regular-file check, size/record/line caps, canonical Base64, iteration-count bounds, case-collision refusal |
| `src/main/java/com/example/auth/PosixMode.java` | Single place that reads POSIX file modes | Fails closed when a mode cannot be read; NOFOLLOW checks |
| `src/main/java/com/example/auth/LatencyBudget.java` | Equalises response time across outcomes | Measured floor with margin, clamped upper bound |
| `src/main/java/com/example/auth/AuthResult.java`, `AuthOutcome.java`, `Diagnostic.java`, `AuthException.java`, `AuditPersistenceException.java`, `InvalidConfigException.java` | Result and error types | Generic user-facing text, fixed diagnostic categories, suppressed causes, redacted `toString()` |
| `src/main/java/com/example/auth/AccountCredentials.java`, `CredentialStore.java`, `EventType.java`, `TimeSource.java`, `ConfigSource.java` | Records, interfaces and clock/config abstraction | Defensive array cloning, no credential serialiser, snapshotted config, injected clock |
| `src/test/java/com/example/auth/*.java` (11 files) | Validation, behaviour, latency, durability and concurrency suites plus fixtures | Reviewed for production reachability only; `FixtureProvisioner` is the only code that writes credential records, and it is test-tree-only |
| `README.md`, `SECURITY.md`, `tools/*.sh`, `build-logs/*`, `out/**/*.class` | Documentation, mutation-test helpers, build output | Not production code; compiled classes and logs were not executed or decompiled |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`, `KeystorePepperProvider`,
  `AccountField`, `SessionTokenStore` and `AuthConfig` — checked for deprecated hashes, insecure
  modes, hardcoded secrets, KDF parameters, RNG quality and key handling. Produced SEC-05 (KDF
  iteration floor) and SEC-07 (unsalted hash of an identifier).
- `testing-api-authentication-weaknesses`: applied to `AuthenticationService`, `SessionTokenStore`,
  `AuthResult` and `InputValidator` — token entropy, token revocation, token leakage in logs/URLs,
  token lifecycle, password policy and account-enumeration-by-message/timing. Produced SEC-06
  (no absolute session lifetime) and SEC-09 (timing oracle at high work factors).
- `implementing-api-rate-limiting-and-throttling`: applied to `AttemptThrottle` and the
  `AuthConfig` bounds — window algorithm, per-IP vs per-account keys, `Retry-After` values, counter
  state bounds. Produced SEC-02.
- `performing-api-rate-limiting-bypass`: applied to the per-source budget — key derivation from the
  peer address, `X-Forwarded-For` trust, IPv4/IPv6 spelling normalisation, and state-eviction
  bypasses. Confirmed the address-spelling defences; produced SEC-02.
- `hunting-credential-stuffing-attacks`: applied to `AttemptThrottle` and `AuditLogger`/`AuthEvent` —
  whether the emitted events support velocity, spray and account-diversity analysis, and whether the
  attacker controls log volume. Produced SEC-01.
- `exploiting-race-condition-vulnerabilities`: applied to `AttemptThrottle.compute()` blocks,
  `SessionTokenStore`'s synchronised methods, `AuditLogger`'s monitor, and the file-permission
  check-then-open sequences. Produced SEC-03.
- `testing-for-sensitive-data-exposure`: applied to every `toString()`, every `Diagnostic` string,
  `InvalidConfigException.problems()`, `AuthEvent.render` and the `char[]`/`byte[]` wiping paths.
  No finding; see section 6.
- Behaviour reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:
  the audit-log file handling in `AuditLogger` and `PosixMode` (symlink/TOCTOU/privilege exposure,
  CWE-59/CWE-367/CWE-732), the credential-file parser in `FileCredentialStore` (CWE-20/CWE-400),
  the configuration parser in `AuthConfig` (CWE-20/CWE-1188), log-record forgery in `AuthEvent`
  (CWE-117), and the fail-closed availability trade-offs in `AuditLogger` and `SessionTokenStore`
  (CWE-400/CWE-770), which produced SEC-01, SEC-04 and SEC-08.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Throttled attempts still write audit lines, so an unauthenticated client can fill the 64 MiB log ceiling and stop all authentication | High | CWE-779 | `src/main/java/com/example/auth/AuthenticationService.java:166` |
| SEC-02 | Per-source block is discarded when the source table is full, resetting the rate-limit budget | Medium | CWE-307 | `src/main/java/com/example/auth/AttemptThrottle.java:314` |
| SEC-03 | `ConcurrentHashMap.compute()` remapping functions mutate the same map, risking deadlock of the throttle | Medium | CWE-833 | `src/main/java/com/example/auth/AttemptThrottle.java:145` |
| SEC-04 | Latency padding is performed while holding one of only four global work permits | Medium | CWE-400 | `src/main/java/com/example/auth/CredentialVerifier.java:93` |
| SEC-05 | PBKDF2-HMAC-SHA256 iteration floor of 120 000 is below current guidance | Low | CWE-916 | `src/main/java/com/example/auth/AuthConfig.java:59` |
| SEC-06 | Session lifetime slides indefinitely with no absolute expiry | Low | CWE-613 | `src/main/java/com/example/auth/SessionTokenStore.java:117` |
| SEC-07 | Account identifier in the audit log is an unsalted, unkeyed SHA-256 of the username | Low | CWE-759 | `src/main/java/com/example/auth/AccountField.java:50` |
| SEC-08 | Saturating the session table evicts other users' live sessions | Low | CWE-770 | `src/main/java/com/example/auth/SessionTokenStore.java:82` |
| SEC-09 | Latency floor clamp lets per-record iteration counts become an account-existence oracle | Low | CWE-208 | `src/main/java/com/example/auth/LatencyBudget.java:64` |

## 5. Detailed Findings

### SEC-01: Throttled attempts still write audit lines, so an unauthenticated client can fill the 64 MiB log ceiling and stop all authentication

- **Severity:** High
- **CWE:** CWE-779: Logging of Excessive Data
- **Location:** `src/main/java/com/example/auth/AuthenticationService.java:162-179`, with the ceiling at `src/main/java/com/example/auth/AuditLogger.java:65` and the refusal at `src/main/java/com/example/auth/AuditLogger.java:493-495`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthenticationService.java:162-169
            // 1. Per-source budget, before any credential work.
            AttemptThrottle.Decision sourceDecision = throttle.consumeSourceAttempt(canonicalSource, now,
                    config.sourceWindowSeconds(), config.sourceMaxAttempts(), config.sourceBlockSeconds());
            if (!sourceDecision.allowed()) {
                record(EventType.LOGIN_THROTTLED, "blocked", submitted, false, canonicalSource,
                        Diagnostic.CREDENTIAL_MISMATCH, startedNanos, sourceDecision.retryAfterSeconds(), null);
                return AuthResult.rateLimited(sourceDecision.retryAfterSeconds());
            }
```
```java
// src/main/java/com/example/auth/AuditLogger.java:493-495
        if (size >= maxLogBytes) {
            return Diagnostic.LOG_FILE_LIMIT;
        }
```

**Why it is a problem:** The per-source throttle stops credential *work*, but it does not stop the
attempt from producing a durable audit record. Once a source is blocked, every further request from
it still reaches `record(...)` and appends one ~200-byte line to the event log, at essentially zero
CPU cost to the server and with no remaining budget to consume. The log has a hard 64 MiB ceiling
(`AuditLogger.MAX_LOG_BYTES`), and reaching it makes `storageProblem()` return `LOG_FILE_LIMIT` for
every subsequent write; because the service is deliberately fail-closed on audit failure
(`AuthenticationService.authenticate` catches `AuditPersistenceException` and returns
`AuthResult.denied()`), *all* authentication — including correct credentials from legitimate users —
is refused until an operator rotates the file out of band. Roughly 3.4 × 10^5 requests (64 MiB /
~200 bytes) from one address are enough: minutes of traffic from a single host, with no credentials
and no account knowledge, converts into a complete authentication outage. The same lines also drown
the records a responder needs: the credential-stuffing detection pattern (velocity and account
diversity per source) is exactly what gets buried under millions of identical `login_throttled`
lines. Nothing in the component rotates, rate-limits or summarises log output, and
`AUTH_MAX_EVENTS` bounds only the in-memory ring, not the file.

**Fix:** Do not emit one durable record per already-blocked attempt. Record the transition into the
blocked state once and then coalesce: keep a per-source counter of suppressed attempts in the
throttle bucket and emit a single summary event when the block expires (or at most one event per
window). Independently, make the size ceiling recoverable without an operator by rotating the log
file in place rather than refusing authentication forever.

```java
// src/main/java/com/example/auth/AuthenticationService.java — coalesce repeated block records
            // 1. Per-source budget, before any credential work.
            AttemptThrottle.Decision sourceDecision = throttle.consumeSourceAttempt(canonicalSource, now,
                    config.sourceWindowSeconds(), config.sourceMaxAttempts(), config.sourceBlockSeconds());
            if (!sourceDecision.allowed()) {
                // Only the attempt that engages the block, and at most one summary per window, is
                // durable. Later attempts against a live block are counted in the bucket and
                // reported once when the block lapses, so a blocked client cannot choose how many
                // bytes the audit log grows by.
                if (sourceDecision.isFirstRefusalOfBlock()) {
                    record(EventType.LOGIN_THROTTLED, "blocked", submitted, false, canonicalSource,
                            Diagnostic.CREDENTIAL_MISMATCH, startedNanos, sourceDecision.retryAfterSeconds(), null);
                }
                return AuthResult.rateLimited(sourceDecision.retryAfterSeconds());
            }
```
```java
// src/main/java/com/example/auth/AuditLogger.java — rotate instead of refusing forever
        if (size >= maxLogBytes) {
            if (!rotateLocked()) {   // rename to file + ".1" (0600) and reopen with CREATE_NEW
                return Diagnostic.LOG_FILE_LIMIT;
            }
        }
```

### SEC-02: Per-source block is discarded when the source table is full, resetting the rate-limit budget

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/AttemptThrottle.java:314-323`, reached from `src/main/java/com/example/auth/AttemptThrottle.java:143-148`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AttemptThrottle.java:143-148
            long horizon = nowMillis - windowSeconds * 1000L;
            if (bucket == null) {
                if (sources.size() >= MAX_SOURCE_KEYS && !evictIdleSources(horizon)) {
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return null;
                }
```
```java
// src/main/java/com/example/auth/AttemptThrottle.java:314-323
    private boolean evictIdleSources(long horizon) {
        int before = sources.size();
        sources.entrySet().removeIf(entry -> {
            SourceBucket bucket = entry.getValue();
            synchronized (bucket) {
                return bucket.lastTouchedMillis < horizon;
            }
        });
        return sources.size() < before;
    }
```

**Why it is a problem:** `evictIdleSources` decides eligibility from `lastTouchedMillis` alone. It
does not consult `blockedUntilMillis`, unlike the periodic sweep at
`AttemptThrottle.java:277-290`, which correctly requires `bucket.blockedUntilMillis <= nowMillis`.
The horizon handed in is `now - sourceWindowSeconds * 1000`, and the configuration bounds allow a
block that outlives that window (`AUTH_SOURCE_BLOCK_SECONDS` up to 1800 while
`AUTH_SOURCE_WINDOW_SECONDS` may be as low as 60, `AuthConfig.java:68-75`). So with, say,
`window=60` and `block=1800`, a source blocked 61 seconds ago is "idle" and is deleted together with
its `blockedUntilMillis` and its entire `attempts` deque — 29 minutes of its block silently vanish
and its budget starts again from zero. The attacker controls when this fires: the eviction path is
only taken when the table holds `MAX_SOURCE_KEYS` (20 000) entries, and filling it is just 20 000
attempts from distinct addresses, which is trivial for anyone holding an IPv6 /64. The net effect is
that the per-source brute-force budget can be reset on demand, which is the control the component
relies on to stop credential stuffing before any PBKDF2 work is bought.

**Fix:** Make eviction eligibility match the sweep: a bucket with a live block, or with stamps that
a verdict could still count, must never be evicted. Prefer refusing the new key (fail-closed, which
the code already does when nothing can be evicted) over discarding enforcement state.

```java
    private boolean evictIdleSources(long horizon, long nowMillis) {
        int before = sources.size();
        sources.entrySet().removeIf(entry -> {
            SourceBucket bucket = entry.getValue();
            synchronized (bucket) {
                // A live block is enforcement state, not idle state: dropping it hands the source a
                // fresh budget. Only buckets with no live block and no countable stamps may go.
                if (bucket.blockedUntilMillis > nowMillis) {
                    return false;
                }
                bucket.pruneStampsBefore(horizon);
                return bucket.attempts.isEmpty() && bucket.lastTouchedMillis < horizon;
            }
        });
        return sources.size() < before;
    }
```

### SEC-03: `ConcurrentHashMap.compute()` remapping functions mutate the same map, risking deadlock of the throttle

- **Severity:** Medium
- **CWE:** CWE-833: Deadlock
- **Location:** `src/main/java/com/example/auth/AttemptThrottle.java:141-150` and `src/main/java/com/example/auth/AttemptThrottle.java:201-209`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AttemptThrottle.java:141-150
        sources.compute(canonicalSource, (key, existing) -> {
            SourceBucket bucket = existing;
            long horizon = nowMillis - windowSeconds * 1000L;
            if (bucket == null) {
                if (sources.size() >= MAX_SOURCE_KEYS && !evictIdleSources(horizon)) {
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return null;
                }
                bucket = new SourceBucket();
            }
```

**Why it is a problem:** `evictIdleSources` runs `sources.entrySet().removeIf(...)` from inside the
remapping function of `sources.compute(...)`. `ConcurrentHashMap`'s contract is explicit that the
remapping function "must not attempt to update any other mappings of this map"; `compute` holds the
bin lock for the computed key while the function runs, and the nested `removeIf` walks the whole
table acquiring other bins' locks. Two concurrent attempts whose keys hash to different bins can
therefore take the locks in opposite orders — thread A holds bin 1 and waits for bin 2 while thread B
holds bin 2 and waits for bin 1 — and both block permanently inside the throttle. Because every
authentication attempt begins with `consumeSourceAttempt` and the deadlocked threads never release,
the result is a wedged authentication service that only a restart recovers; the same construct exists
on the account path (`accounts.compute` → `evictIdleAccounts`, lines 201-209). The window is the same
table-full condition an attacker can create at will (see SEC-02), so this is reachable rather than
theoretical, and the JDK may alternatively throw an unchecked recursive-update error, which lands in
the `catch (RuntimeException e)` arm of `authenticate` and denies the attempt.

**Fix:** Keep the `compute` body short and side-effect-free with respect to the map. Perform capacity
eviction *before* entering `compute`, then re-check capacity inside it and fail closed if the table
is still full.

```java
    Decision consumeSourceAttempt(String canonicalSource, long nowMillis, int windowSeconds, int maxAttempts,
            int blockSeconds) {
        sweepIfDue(nowMillis);
        long horizon = nowMillis - windowSeconds * 1000L;
        // Eviction happens outside compute(): the remapping function must not touch other mappings
        // of the same map, or two attempts on different bins can deadlock each other.
        if (!sources.containsKey(canonicalSource) && sources.size() >= MAX_SOURCE_KEYS) {
            evictIdleSources(horizon, nowMillis);
        }
        List<Decision> observed = new ArrayList<>(1);
        sources.compute(canonicalSource, (key, existing) -> {
            SourceBucket bucket = existing;
            if (bucket == null) {
                if (sources.size() >= MAX_SOURCE_KEYS) {
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return null;
                }
                bucket = new SourceBucket();
            }
            // ... unchanged verdict logic ...
            return bucket;
        });
        return observed.isEmpty() ? blockedForever() : observed.get(0);
    }
```

### SEC-04: Latency padding is performed while holding one of only four global work permits

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/CredentialVerifier.java:82-97`, with the second (correct) pad at `src/main/java/com/example/auth/AuthenticationService.java:296`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/CredentialVerifier.java:82-97
        long started = System.nanoTime();
        try {
            final boolean matched;
            if (record == null) {
                // Discarded deliberately: the purpose is that an unknown username costs exactly what
                // a known one costs.
                hasher.matches(passwordUtf8, decoy.salt(), decoy.iterations(), decoy.digest());
                matched = false;
            } else {
                matched = hasher.matches(passwordUtf8, record.salt(), record.iterations(), record.digest());
            }
            budget.padUntil(started);
            return matched;
        } finally {
            workPermits.release();
        }
```

**Why it is a problem:** `budget.padUntil(started)` sleeps until the latency floor has elapsed — and
it does so *before* `workPermits.release()`, so the thread occupies one of only
`MAX_CONCURRENT_DERIVATIONS = 4` process-wide permits (`AuthenticationService.java:31`) for the full
floor rather than for the derivation alone. The floor is sized at 1.35 × the measured derivation
cost (`LatencyBudget.java:63`), so roughly 35% of every permit-hold is pure sleeping, and global
login capacity is about `4 / floor` ≈ 20 sign-ins per second with the default 120 000-iteration
setting. A client that merely exceeds that rate pushes everyone else past the 2-second
`PERMIT_TIMEOUT_MILLIS` and every concurrent attempt — including correct credentials — is denied with
`WORK_UNAVAILABLE`. The per-source budget does not contain this: `AUTH_SOURCE_MAX_ATTEMPTS` may be
up to 1000 per window, and a handful of source addresses saturates the budget outright. The padding
here is also redundant: `authenticate` already pads in its own `finally`
(`AuthenticationService.java:296`), which equalises the whole attempt without consuming a permit, so
the inner pad buys no additional timing protection for the cost it imposes.

**Fix:** Release the permit as soon as the derivation is done and let the caller's own `finally`
perform the padding, which is where the floor belongs. Make the concurrency cap configurable and
sized from the host rather than fixed at four.

```java
        long started = System.nanoTime();
        final boolean matched;
        try {
            if (record == null) {
                hasher.matches(passwordUtf8, decoy.salt(), decoy.iterations(), decoy.digest());
                matched = false;
            } else {
                matched = hasher.matches(passwordUtf8, record.salt(), record.iterations(), record.digest());
            }
        } finally {
            // Released before any padding: a permit is the scarce CPU budget, and holding one while
            // sleeping cuts global login capacity for no timing benefit. The caller's finally block
            // pads the whole attempt against the same floor.
            workPermits.release();
        }
        budget.padUntil(started);
        return matched;
```

### SEC-05: PBKDF2-HMAC-SHA256 iteration floor of 120 000 is below current guidance

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:59`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:59
    public static final int MIN_PBKDF2_ITERATIONS = 120_000;
```

**Why it is a problem:** The component correctly refuses to run below a compiled-in floor, uses
PBKDF2-HMAC-SHA256 rather than a bare digest, and adds a keystore-held HMAC pepper — all of which
materially raise the cost of an offline attack on a stolen credential file. The floor itself,
however, is roughly one fifth of the OWASP Password Storage guidance for PBKDF2-HMAC-SHA256
(600 000 iterations), and `AuthConfig.Builder` starts at exactly that floor
(`AuthConfig.java:623`), so an embedded deployment that never calls `pbkdf2Iterations(...)` ships at
the weakest value the component permits. PBKDF2 is also the memory-hard-free option: it parallelises
cheaply on GPUs, which is why its recommended iteration count is high. The pepper limits the damage
to attackers who steal only the credential file, but an attacker who obtains both the file and the
keystore (one host compromise) is left with a 120 000-iteration PBKDF2 to grind.

**Fix:** Raise the compiled-in floor to the current guidance and start the builder above it. Where
the deployment can add a dependency, prefer Argon2id (m=19 MiB, t=2, p=1) or scrypt over PBKDF2; the
per-record iteration count already stored in each line gives a migration path.

```java
    /**
     * Absolute floor on PBKDF2-SHA-256 iterations. Set to the OWASP Password Storage guidance for
     * PBKDF2-HMAC-SHA256 rather than to the lowest value that still feels fast: the floor is the
     * value every deployment that does not tune anything will actually run.
     */
    public static final int MIN_PBKDF2_ITERATIONS = 600_000;
```

### SEC-06: Session lifetime slides indefinitely with no absolute expiry

- **Severity:** Low
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/SessionTokenStore.java:104-119`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionTokenStore.java:113-118
        Long expiry = expiresAtMillis.get(candidate);
        if (expiry == null || expiry <= now) {
            return false;
        }
        expiresAtMillis.put(candidate, now + ttlSeconds * 1000L);
        return true;
```

**Why it is a problem:** Every successful validation pushes the expiry a further `ttlSeconds` into
the future, and nothing records when the session was first issued. A session that is polled more
often than its TTL therefore never expires, so a stolen identifier remains valid for as long as the
thief keeps using it — the idle timeout is the only timeout there is. That removes the natural
backstop for credential theft (heap dump, client-side exposure, logged identifier) that an absolute
lifetime provides, and it means the `Max-Age` the cookie helper emits
(`SessionTokenStore.java:206`) understates how long the server will honour the value. There is also
no re-authentication boundary, so the identifier issued at sign-in is the only credential the holder
ever needs.

**Fix:** Store the issue time alongside the sliding expiry and refuse validation past a fixed
absolute lifetime, independently of activity.

```java
    private static final class Entry {
        final long issuedAtMillis;
        long expiresAtMillis;
        Entry(long issuedAtMillis, long expiresAtMillis) {
            this.issuedAtMillis = issuedAtMillis;
            this.expiresAtMillis = expiresAtMillis;
        }
    }

    synchronized boolean isValid(String candidate) {
        if (candidate == null || candidate.length() != TOKEN_HEX_LENGTH || !isHex(candidate)) {
            return false;
        }
        long now = time.nowMillis();
        dropExpiredLocked(now);
        Entry entry = sessions.get(candidate);
        if (entry == null || entry.expiresAtMillis <= now) {
            return false;
        }
        // Absolute cap: activity may slide the idle timeout, but it must not be able to keep a
        // stolen identifier alive indefinitely.
        if (now - entry.issuedAtMillis >= absoluteLifetimeMillis) {
            sessions.remove(candidate);
            return false;
        }
        entry.expiresAtMillis = now + ttlSeconds * 1000L;
        return true;
    }
```

### SEC-07: Account identifier in the audit log is an unsalted, unkeyed SHA-256 of the username

- **Severity:** Low
- **CWE:** CWE-759: Use of a One-Way Hash without a Salt
- **Location:** `src/main/java/com/example/auth/AccountField.java:43-63`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AccountField.java:47-50
        byte[] canonical = lowerAscii(username).getBytes(StandardCharsets.UTF_8);
        final byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(canonical);
```

**Why it is a problem:** Writing a hash instead of the username is the right instinct, and the
component is explicit that it knows the hash is unkeyed. The consequence is still real: usernames
have very low entropy (dictionary names, email addresses, employee ids), so anyone who reads the
audit log can hash a candidate list and recover the plaintext of every `account_id` it contains at
negligible cost — recovering the exact information the field exists to avoid storing. The log is
0600, so this matters on log shipping, backups, and any ticket or paste where a line is quoted; the
`account_present=true|false` flag next to the recovered name additionally confirms which guessed
names are real accounts. A keyed MAC gives identical searchability with none of this exposure.

**Fix:** Derive the field with HMAC-SHA256 under a dedicated log key (a second keystore entry,
rotated on its own schedule), so the identifier is still stable and searchable within a deployment
but useless to anyone who does not hold the key.

```java
    /**
     * Keyed so the identifier cannot be reversed by hashing a dictionary of candidate names. The key
     * is a keystore entry distinct from the credential pepper and is never written to the log.
     */
    static String accountId(String username, byte[] logKey) {
        if (username == null) {
            return repeat('0', 64);
        }
        byte[] canonical = lowerAscii(username).getBytes(StandardCharsets.UTF_8);
        final byte[] digest;
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(logKey, "HmacSHA256"));
            digest = mac.doFinal(canonical);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        java.util.Arrays.fill(canonical, (byte) 0);
        return hex(digest);
    }
```

### SEC-08: Saturating the session table evicts other users' live sessions

- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/SessionTokenStore.java:78-91` and `src/main/java/com/example/auth/SessionTokenStore.java:274-298`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionTokenStore.java:81-88
        if (expiresAtMillis.size() >= maxActiveSessions) {
            if (!evictOldestExpiringLocked(now)) {
                return null;
            }
            evictedCount++;
        }
```

**Why it is a problem:** When the table is full, a new sign-in silently deletes the entry that
expires soonest — which, under a sliding TTL, is simply the least recently active real user. So any
party that can authenticate (one valid credential pair is enough, or a pool of low-privilege
accounts) can repeatedly sign in and evict one other user's live session per issue, logging people
out on demand and forcing re-authentication storms. The class comment at lines 280-283 identifies
exactly this failure mode for a mis-derived age calculation, but the chosen policy has the same
effect by design: the only protection is the 1-second `MIN_EVICTION_GRACE_MILLIS` window, which
protects a session issued in the last second and nothing else. With `AUTH_MAX_ACTIVE_SESSIONS` as
low as 16 (`AuthConfig.java:78`) the table is trivially saturated.

**Fix:** Do not evict live sessions to make room. Drop only entries that are already expired, and
refuse to issue when the table is genuinely full — refusing one new sign-in is strictly less harmful
than terminating an established one. If capacity pressure is a real concern, cap sessions per account
so one principal cannot consume the table.

```java
    synchronized String issue(String accountKey) {
        long now = time.nowMillis();
        dropExpiredLocked(now);
        if (expiresAtMillis.size() >= maxActiveSessions) {
            // Never evict a live session to admit a new one: that converts capacity pressure into a
            // way to sign other users out. Refusing this issue is the fail-closed answer.
            return null;
        }
        if (countForAccountLocked(accountKey) >= maxSessionsPerAccount) {
            return null;
        }
        String token = newToken();
        expiresAtMillis.put(token, now + ttlSeconds * 1000L);
        issuedCount++;
        return token;
    }
```

### SEC-09: Latency floor clamp lets per-record iteration counts become an account-existence oracle

- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/auth/LatencyBudget.java:62-71`, interacting with `src/main/java/com/example/auth/CredentialVerifier.java:88-91`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LatencyBudget.java:62-71
        } else {
            double withMargin = micros * MARGIN;
            if (withMargin > MAX_FLOOR_MICROS) {
                floor = MAX_FLOOR_MICROS;
            } else if (withMargin < FALLBACK_FLOOR_MICROS) {
                floor = FALLBACK_FLOOR_MICROS;
            } else {
                floor = (long) withMargin;
            }
        }
```

**Why it is a problem:** The uniform-work design rests on the floor being at least as long as the
most expensive derivation an attempt can perform. The floor is clamped at
`MAX_FLOOR_MICROS = 4_000_000` µs (4 s), while `AUTH_PBKDF2_ITERATIONS` may be configured as high as
5 000 000 (`AuthConfig.java:61`) — about 8 s of PBKDF2 on the component's own reference figure of
200 ms per 120 000 iterations. Above roughly 1.8 M iterations the clamp binds, every attempt
overshoots the floor, and the padding stops equalising anything. At that point the derivation cost
itself becomes observable, and it is *not* uniform: the decoy used for an unknown username always
runs at `config.pbkdf2Iterations()` (`AuthenticationService.java:560-562`), whereas a real record
runs at its own stored count, which may be as low as `AUTH_MIN_ACCEPTED_ITERATIONS`
(`FileCredentialStore.java:147`). A response that is measurably faster than the decoy therefore means
"this username exists and its record was hashed with fewer iterations", reintroducing both the
account-existence oracle and a read of each account's work factor.

**Fix:** Tie the clamp to the configured cost instead of a fixed constant, and refuse at start-up any
configuration whose work factor cannot be covered by the floor. Equally, derive the decoy at the
lowest acceptable count so a real record can never be cheaper than the decoy.

```java
    static LatencyBudget measure(PasswordHasher hasher, int iterations) throws InvalidConfigException {
        long nanos = hasher.measureDerivationNanos(iterations,
                "latency-probe-value".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        long micros = nanos < 0 ? -1L : Math.max(1L, nanos / 1000L);
        if (micros <= 0) {
            return new LatencyBudget(FALLBACK_FLOOR_MICROS * 1000L, 0L);
        }
        double withMargin = micros * MARGIN;
        if (withMargin > MAX_FLOOR_MICROS) {
            // A floor shorter than the work it is meant to hide equalises nothing: refuse the
            // configuration rather than ship a service whose timing leaks which accounts exist.
            throw new InvalidConfigException(List.of(
                    AuthConfig.KEY_PBKDF2_ITERATIONS + " costs more than the latency floor can absorb"));
        }
        long floor = (long) Math.max(withMargin, FALLBACK_FLOOR_MICROS);
        return new LatencyBudget(floor * 1000L, micros);
    }
```

## 6. Verified Controls and Checks With No Finding

- **SQL / query injection (CWE-89):** no database, JDBC, ORM or query string exists anywhere in the
  tree. Credential lookup is a `Map` probe over an unmodifiable map built at start-up
  (`FileCredentialStore.java:187`, `FileCredentialStore.java:199`).
- **OS command execution and deserialization (CWE-78, CWE-502):** no `ProcessBuilder`, `Runtime.exec`,
  `ObjectInputStream`, `readObject`, reflection or dynamic class loading in `src/main`. The only
  external data readers are `Files.readAllLines` for the credential file and the JDK `KeyStore` API.
- **Hardcoded secrets (CWE-798):** no key, password or salt is embedded. The pepper is read from a
  password-protected keystore entry (`KeystorePepperProvider.java:82-95`), the keystore password
  comes from configuration and is wiped (`AuthConfig.java:315-319`), and the only literal byte
  strings are non-secret probes (`AuthenticationService.java:398`, `AuthenticationService.java:560`,
  `LatencyBudget.java:57`).
- **Password storage construction:** PBKDF2-HMAC-SHA256 with a 16-byte `SecureRandom` per-account
  salt and an HMAC pepper used as a MAC key rather than concatenated, which avoids the
  pepper/password boundary collision (`PasswordHasher.java:103-139`). The record's iteration count
  is bounded above by the deployment's own policy both at load (`FileCredentialStore.java:147`) and
  at derivation (`PasswordHasher.java:107-109`), so a credential file cannot order unbounded work.
- **Timing-safe comparison (CWE-208):** digest comparison is `MessageDigest.isEqual`
  (`PasswordHasher.java:155`); session validation is a hash probe with no byte-wise compare
  (`SessionTokenStore.java:113`); unknown usernames perform a full decoy derivation
  (`CredentialVerifier.java:88`). Only the clamp interaction in SEC-09 was found to break this.
- **Account enumeration via responses (CWE-204):** unknown username, wrong password, malformed
  username, unencodable password, locked account and throttled source all return the identical
  `DENIAL_MESSAGE` with no distinguishing field (`AuthResult.java:14`, `AuthResult.java:39-45`), and
  the retry hint is deliberately withheld on the attempt that trips the account lock
  (`AuthenticationService.java:216-222`).
- **Session identifier quality and handling (CWE-330, CWE-384, CWE-539):** 128 bits from
  `SecureRandom`, generated server-side and never derived from input
  (`SessionTokenStore.java:248-257`); validity is server-side table presence only, so a well-formed
  identifier cannot be forged; the `Set-Cookie` helper always emits `HttpOnly`, `SameSite=Strict`
  and `Secure`, and returns `null` rather than a cookie on a non-TLS request
  (`SessionTokenStore.java:188-208`); only a 6-hex-character prefix reaches the log
  (`AuthEvent.java:255-272`); an identifier issued on a path that then failed is revoked in the
  `finally` block so it can never be live but unreachable (`AuthenticationService.java:288-295`).
- **Log injection and record forgery (CWE-117):** the audit line has no free-text field; the account
  identity is a hex digest, the source is re-validated against `normalizeSourceAddress`, the reason
  is an enum name, and the rendered line is rejected outright if it exceeds 320 characters or
  contains CR, LF, any C0 character or DEL (`AuthEvent.java:128-173`). Exception messages are never
  logged (`AuthException.java:17`, `AuditPersistenceException.java:32`).
- **Sensitive data in error paths and `toString()` (CWE-209, CWE-532):** `AuthResult.toString`,
  `Attempt.toString`, `AccountCredentials.toString`, `AuthConfig.toString`, `AuthEvent.toString` and
  `SnapshotConfigSource.toString` all omit secrets; `InvalidConfigException` problem strings name
  keys and fixed reasons only, and an environment-supplied key name is filtered to `[A-Z0-9_]`
  before being printed (`InvalidConfigException.java:51-63`).
- **Credential material in memory (CWE-316):** passwords are handled as `char[]`/`byte[]` and wiped
  in `finally` blocks (`AuthenticationService.java:281-287`), `encodePassword` encodes straight out
  of the array through a reporting `CharsetEncoder` so no immutable `String` copy is created
  (`InputValidator.java:345-388`), the derived key and candidate digest are zeroed
  (`PasswordHasher.java:133`, `PasswordHasher.java:157`), and the pepper is erased on `close()`
  (`PasswordHasher.java:213-215`).
- **Input validation (CWE-20):** usernames are allow-listed by code point with combining marks,
  format characters, private-use and unassigned code points excluded, and with no case folding or
  Unicode normalisation that could fold two names onto one account
  (`InputValidator.java:235-261`, `InputValidator.java:414-431`); passwords reject anything below
  `U+0021` before the length test, so a zero-filled buffer cannot pass on size alone
  (`InputValidator.java:293-297`); peer addresses are parsed purely textually, rejecting hostnames,
  zone identifiers, bracketed forms, CIDR and short-form IPv4 so a client cannot rotate its throttle
  bucket by spelling (`InputValidator.java:100-170`, `InputValidator.java:433-466`).
- **Credential-file parsing (CWE-400, CWE-59):** NOFOLLOW regular-file check, 8 MiB file cap, 20 000
  record cap, 512-character line cap, canonical-Base64-only decoding with exact length, and refusal
  of duplicate or ASCII-case-colliding usernames; any single problem discards the whole store and
  start-up fails (`FileCredentialStore.java:64-124`, `PasswordHasher.java:171-188`).
- **File permissions and symlink handling (CWE-59, CWE-732):** all mode reads go through `PosixMode`,
  which returns "exposed" when a mode cannot be read at all (`PosixMode.java:45-100`); the accounts
  file and keystore must be owner-only, the event-log directory must not be group/other-writable,
  and a new log file is created with `CREATE_NEW` plus owner-only attributes so a pre-planted
  symlink fails the open rather than being adopted (`AuditLogger.java:137-173`,
  `AuthConfig.java:551-597`).
- **Audit-log integrity (CWE-778):** every write re-checks that the path still names the same inode
  and is still 0600 before appending (`AuditLogger.java:547-572`), short writes are never retried
  against the same channel, a torn trailing record is truncated before anything is appended and the
  repair is itself logged (`AuditLogger.java:601-621`, `AuditLogger.java:193-200`), unpersisted
  events are counted and surfaced through `selfCheck()` (`AuthenticationService.java:363-368`), and
  an attempt whose event cannot be persisted is denied rather than silently granted.
- **Configuration handling (CWE-1188, CWE-453):** every key is required with no permissive fallback,
  every integer is range-checked, an unknown `AUTH_`-prefixed key is a start-up error, cross-field
  rules (`sourceMaxAttempts >= accountLockAfter`, `pbkdf2Iterations >= minAcceptedIterations`) are
  enforced in `build()` so the environment path cannot skip them, and `fromEnvironment` additionally
  runs the filesystem checks before returning (`AuthConfig.java:141-211`,
  `AuthConfig.java:774-807`).
- **Lockout fairness (CWE-645):** the per-account lock is read-only at check time, so probing cannot
  extend another party's lock (`AttemptThrottle.java:180-191`); a verified sign-in clears the failure
  streak so an attacker cannot hold an account locked indefinitely
  (`AttemptThrottle.java:237-245`); and an audit-log failure deliberately charges nothing to the
  account, so a storage outage cannot lock a legitimate user out
  (`AuthenticationService.java:255-272`).
- **Concurrency (CWE-362):** throttle verdicts are produced inside a single atomic `compute` per key,
  session issue/validate/revoke/capacity bookkeeping all run under one monitor, and the log channel
  is guarded by the logger's monitor. The only concurrency defect found is the nested same-map
  mutation in SEC-03.
- **Scope discipline:** no account-creation, password-change, admin or metrics surface exists in
  `src/main`, and there is deliberately no credential-record serialiser
  (`AccountCredentials.java:40-47`); the only code that writes credential lines is
  `src/test/java/com/example/auth/FixtureProvisioner.java`, which is not on any production path.
- **Not executed:** per the review constraints, nothing in the source tree was compiled, run or
  imported; the prebuilt `out/**/*.class` artefacts and `build-logs/*` were treated as untrusted
  output and not executed or decompiled.
