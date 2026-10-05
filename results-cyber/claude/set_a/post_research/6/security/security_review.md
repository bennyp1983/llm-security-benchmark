# Security Review: `com.example.auth` username/password authentication component

## 1. Executive Summary

The component under review is a self-contained Java 17 authentication library
(`src/main/java/com/example/auth`, 15 classes, no third-party dependencies). It verifies
username/password logins against a server-side credential store, rate-limits attempts per
source address and per account, issues and validates random session identifiers, renders a
hardened `Set-Cookie` header, and appends masked authentication-activity records to an
owner-only log file.

The security fundamentals are in good shape and are clearly deliberate: PBKDF2-HMAC-SHA512
with a per-record random salt and a constant-time digest comparison
(`PasswordHasher.java:59-66`), one single generic failure result for every failure mode
(`AuthenticationResult.java:361-367`), 256-bit `SecureRandom` session identifiers stored only
as SHA-256 digests (`SessionRegistry.java:77-81`), a fresh identifier on every login so there is
no session fixation, allow-list input validation (`InputPolicy.java:47-69`), log-injection
escaping and field masking (`LogSanitizer.java:222-242`), `0600`/`0700` + `NOFOLLOW_LINKS`
log file handling (`FileAuthEventLog.java:105-157`), no hardcoded credentials anywhere in the
tree, and a fail-closed decision chain in which even an unrecordable success is refused
(`AuthenticationService.java:146-153`). No injection, deserialization, XSS, SSRF, weak-crypto
or secret-exposure defect was found.

The findings that remain are all in the availability and rate-limiting layer rather than in the
credential path. The most important is that `LoginThrottle`'s fixed-size tracking tables fail
closed for *unseen* keys, so an attacker who saturates the per-account table with 50 000
arbitrary usernames denies login to every account not currently tracked (SEC-01). That is made
materially cheaper by `InputPolicy.canonicalSource` returning the source string unchanged, so
case- and format-variants of one IPv6 address count as distinct throttle keys and multiply the
per-source failure budget (SEC-02). Separately, the invalid-input rejection path writes an audit
record without consulting the throttle at all, giving an unauthenticated attacker an unbounded
write channel into a log that keeps only one rotated generation, which can evict genuine
evidence (SEC-03). Four lower-severity issues follow: an indefinitely renewable per-account
cool-off (SEC-04), an account-existence timing oracle when stored records use a non-default
iteration count (SEC-05), an accepted PBKDF2 iteration floor below the one the class itself
cites (SEC-06), and a log writer that is left permanently closed after a failed rotation,
which converts a transient I/O fault into a permanent authentication outage (SEC-07).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/AuthenticationService.java` | Orchestrates a login attempt end to end | Decision ordering, fail-closed error handling, password zeroing, throttle/store/session/log sequencing, audit on every path |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2 verification and derivation | KDF algorithm/iterations/salt/key length, constant-time compare, decoy derivation for unknown accounts, `SecureRandom` |
| `src/main/java/com/example/auth/CredentialRecord.java` | Stored verifier (salt, hash, iterations) | Validates untrusted store records, clones arrays, redacts `toString` |
| `src/main/java/com/example/auth/CredentialStore.java` | Read-only credential lookup interface | Declares the failure mode the caller must fail closed on |
| `src/main/java/com/example/auth/InMemoryCredentialStore.java` | In-memory `CredentialStore` | No pre-seeded credentials; canonicalises usernames on insert |
| `src/main/java/com/example/auth/LoginThrottle.java` | Per-source and per-account rate limiting | Atomic check-then-act, failure budgets, cool-off windows, bounded key tables, capacity fail-closed |
| `src/main/java/com/example/auth/SessionRegistry.java` | Issues/validates/invalidates sessions | 256-bit `SecureRandom` identifiers, SHA-256 at-rest digest, atomic expiry+refresh, idle/absolute timeouts, capacity cap |
| `src/main/java/com/example/auth/Session.java` | Server-side session state | Expiry computation, no identifier material retained, masked `toString` |
| `src/main/java/com/example/auth/SessionCookie.java` | Renders `Set-Cookie` | `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, shape check preventing header injection |
| `src/main/java/com/example/auth/InputPolicy.java` | Trust-boundary validation | Username allow-list + canonicalisation, password length bounds, IP-literal validation, session-id shape, config range checks |
| `src/main/java/com/example/auth/LogSanitizer.java` | Makes values log-safe | Control-character/newline neutralisation, quote escaping, field truncation, username and address masking |
| `src/main/java/com/example/auth/AuthEvent.java` | One audit record | Type-level guarantee that no password, key or session id can be logged |
| `src/main/java/com/example/auth/AuthEventLog.java` | Audit sink interface | `AuditException` is the contract that makes audit failure deny the attempt |
| `src/main/java/com/example/auth/FileAuthEventLog.java` | File-backed audit sink | `0600`/`0700` creation, permission verification, `NOFOLLOW_LINKS`, size-bounded rotation, serialised flushed writes, HMAC-SHA256 account correlation id |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Caller-visible outcome | Single generic failure message, session id only on success, redacted `toString` |
| `src/test/java/com/example/auth/AuthenticationSelfCheck.java` | Executable self-checks | Runtime-generated test password (no credential in source), asserts enumeration resistance, log hygiene, buffer zeroing, concurrency bounds |
| `pom.xml` | Build descriptor | Zero third-party dependencies; pinned plugin version; JDK-only crypto |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`, `CredentialRecord`, `SessionRegistry.digest`, and `FileAuthEventLog.buildMac` — checked for deprecated hashes, cipher mode/padding, key size, RNG quality, KDF parameters, and hardcoded key material. Produced SEC-06.
- `testing-api-authentication-weaknesses`: applied to `AuthenticationService`, `SessionRegistry`, `Session`, `SessionCookie`, and `AuthenticationResult` — checked token entropy, server-side revocation on sign-out, token lifetime, token leakage into logs/URLs, password policy, and account enumeration via response or timing differences. Produced SEC-05.
- `performing-api-rate-limiting-bypass`: applied to `LoginThrottle` and `InputPolicy.canonicalSource` — checked source-identifier spoofing/variation, per-account key rotation, and burst/concurrency bypass of the budget. Produced SEC-01 and SEC-02.
- `implementing-api-rate-limiting-and-throttling`: applied to `LoginThrottle` as the defender-side counterpart — checked window algorithm, per-key state bounds, cool-off behaviour, and the failure mode when counter storage is exhausted. Produced SEC-01 and SEC-04.
- `testing-for-sensitive-data-exposure`: applied to `LogSanitizer`, `FileAuthEventLog`, `AuthEvent`, and every `toString` — checked for credentials, session identifiers, PII and internal error detail in logs, error messages and rendered objects. Produced SEC-03.
- `testing-for-broken-access-control`: applied to `AuthenticationService.resumeSession`/`signOut` and `SessionRegistry.validate` — checked that identifier shape alone grants nothing and that only server-side state authorises.
- `testing-for-business-logic-vulnerabilities`: applied to the `admit` → verify → `recordFailure`/`recordSuccess` state machine — checked ordering, counter-reset logic and multi-step bypass.
- `implementing-secret-scanning-with-gitleaks`: applied as a knowledge-based secret scan over `src/` and `pom.xml` — no hardcoded password, key, token or API key present.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched: the POSIX file-permission and symlink-resistance logic in `FileAuthEventLog` (CWE-59, CWE-276, CWE-367), the log-rotation failure path (CWE-703, producing SEC-07), the `Set-Cookie` header construction in `SessionCookie` (CWE-113, CWE-1004, CWE-614), the IPv4/IPv6 literal parsers in `InputPolicy` (CWE-20), in-memory secret lifetime for `char[]`/`byte[]` buffers (CWE-226), and the `ConcurrentHashMap.compute` concurrency contract in `LoginThrottle` and `SessionRegistry` (CWE-367, CWE-362). There is no SQL, ORM, template, deserialization, XML, command execution, HTML rendering or outbound network call anywhere in the component, so the corresponding skills were not applicable.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Saturating the throttle's fixed-size tracking tables denies authentication to all untracked accounts | Medium | CWE-770 | `src/main/java/com/example/auth/LoginThrottle.java:95` |
| SEC-02 | `canonicalSource` does not canonicalise, so format-variants of one address multiply the per-source failure budget | Medium | CWE-307 | `src/main/java/com/example/auth/InputPolicy.java:108` |
| SEC-03 | Invalid-input rejection path writes an audit record without consulting the throttle, allowing unauthenticated log flooding and evidence eviction | Medium | CWE-779 | `src/main/java/com/example/auth/AuthenticationService.java:77` |
| SEC-04 | Per-account cool-off is indefinitely renewable because the counter window is never reset | Low | CWE-645 | `src/main/java/com/example/auth/LoginThrottle.java:199` |
| SEC-05 | Decoy derivation uses the hasher's iteration count instead of matching the record's, leaking account existence by timing | Low | CWE-208 | `src/main/java/com/example/auth/PasswordHasher.java:73` |
| SEC-06 | Accepted PBKDF2 iteration floor (100 000) is below the OWASP figure the class itself cites | Low | CWE-916 | `src/main/java/com/example/auth/PasswordHasher.java:25` |
| SEC-07 | A failed log rotation leaves the audit sink permanently closed, turning a transient I/O fault into a permanent authentication outage | Low | CWE-703 | `src/main/java/com/example/auth/FileAuthEventLog.java:184` |

## 5. Detailed Findings

### SEC-01: Saturating the throttle's fixed-size tracking tables denies authentication to all untracked accounts
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/LoginThrottle.java:95-97` and `src/main/java/com/example/auth/LoginThrottle.java:142-157`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginThrottle.java:95-97
        if (atCapacity(bySource, source, now) || atCapacity(byAccount, canonicalUsername, now)) {
            return java.util.Optional.of(Block.CAPACITY);
        }
```
```java
// src/main/java/com/example/auth/LoginThrottle.java:142-148
    private boolean atCapacity(Map<String, Counter> table, String key, Instant now) {
        if (table.size() < MAX_TRACKED_KEYS || table.containsKey(key)) {
            return false;
        }
        purgeExpired(table, now);
        return table.size() >= MAX_TRACKED_KEYS && !table.containsKey(key);
    }
```

**Why it is a problem:** The memory bound is enforced by refusing attempts for keys that are not
already in the table. `penalise` (line 159) inserts a `byAccount` entry for *any* syntactically
valid username, including usernames with no account, and entries stay live for the whole
`window` (15 minutes by default). An attacker who drives 50 000 (`MAX_TRACKED_KEYS`) distinct
failed attempts with distinct usernames inside one window fills `byAccount`; from then on every
login for an account that is not already tracked returns `Block.CAPACITY`, which
`AuthenticationService.attempt` (line 100-106) turns into the generic failure. The same applies
to `bySource` against every client address not already tracked. The per-source budget does not
prevent this — it only sets the cost, 10 failures per address per window, so roughly 5 000
source addresses (trivial within a single routed IPv6 allocation, and cheaper still given
SEC-02) suffice. The result is a complete, attacker-sustained authentication outage for
legitimate users, and because `purgeExpired` walks the full table on every capacity-pressured
call, each attempt in the saturated state also costs an O(50 000) scan under the caller's
thread, amplifying the load.

Failure scenario: an attacker sends 50 000 logins with unique random usernames (`u00001`,
`u00002`, …) spread over ~5 000 source addresses within 15 minutes. Victim `alice`, whose
`byAccount` entry has expired because she has not failed recently, then submits her correct
password; `admit` returns `Block.CAPACITY`, no credential work happens, and she receives
"We could not sign you in." Every untracked account is locked out for as long as the attacker
keeps refreshing the table.

**Fix:** Do not let a full counter table deny service to new keys. Bound the tables by evicting
the least-recently-used entry instead of refusing admission, and back that with a single global
failure budget so eviction cannot itself be used to erase an attacker's own counters. Reserve
fail-closed behaviour for the global budget, which is not attacker-partitionable, rather than
for per-key capacity.

```java
    /**
     * Capacity handling. A full table evicts its oldest entry rather than refusing
     * the attempt: refusing would let an attacker who fills the table with
     * arbitrary keys deny login to every key that is not already tracked. Eviction
     * cannot be used to clear an attacker's own counter either, because the global
     * budget below is not partitioned by key.
     */
    private void makeRoom(Map<String, Counter> table, String key, Instant now) {
        if (table.size() < MAX_TRACKED_KEYS || table.containsKey(key)) {
            return;
        }
        purgeExpired(table, now);
        while (table.size() >= MAX_TRACKED_KEYS) {
            Iterator<Map.Entry<String, Counter>> it = table.entrySet().iterator();
            Map.Entry<String, Counter> oldest = null;
            while (it.hasNext()) {
                Map.Entry<String, Counter> candidate = it.next();
                if (oldest == null || candidate.getValue().windowStart.isBefore(oldest.getValue().windowStart)) {
                    oldest = candidate;
                }
            }
            if (oldest == null) {
                return;
            }
            table.remove(oldest.getKey(), oldest.getValue());
        }
    }

    public java.util.Optional<Block> admit(String canonicalUsername, String source) {
        Instant now = clock.get();
        if (isBlocked(bySource, source, now)) {
            return java.util.Optional.of(Block.SOURCE);
        }
        if (isBlocked(byAccount, canonicalUsername, now)) {
            return java.util.Optional.of(Block.ACCOUNT);
        }
        // Global, un-partitionable backstop: this is the only dimension an
        // attacker cannot multiply by choosing new keys, so it is the only one
        // that may fail closed.
        if (globalFailures.isBlocked(now)) {
            return java.util.Optional.of(Block.CAPACITY);
        }
        makeRoom(bySource, source, now);
        makeRoom(byAccount, canonicalUsername, now);
        return java.util.Optional.empty();
    }
```

### SEC-02: `canonicalSource` does not canonicalise, so format-variants of one address multiply the per-source failure budget
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts (via CWE-178: Improper Handling of Case Sensitivity)
- **Location:** `src/main/java/com/example/auth/InputPolicy.java:92-109`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/InputPolicy.java:103-108
        boolean v6 = raw.indexOf(':') >= 0;
        boolean v4 = raw.indexOf('.') >= 0;
        if (v6 == v4) {
            return Optional.empty();
        }
        return (v4 ? isIpv4(raw) : isIpv6(raw)) ? Optional.of(raw) : Optional.empty();
```

**Why it is a problem:** The method is named `canonicalSource` and its return value is used
directly as the `bySource` throttle key (`AuthenticationService.java:86` →
`LoginThrottle.admit`/`recordFailure`), but it validates the string and returns it *unchanged*.
One IPv6 address has many accepted textual forms that differ as `String` keys: hex-digit case
(`2001:DB8::1` vs `2001:db8::1`), zero padding (`2001:0db8::1`), and zero-group expansion
(`2001:db8:0:0:0:0:0:1`). Each form gets its own `Counter` and therefore its own full
`sourceFailureBudget`. The per-source budget is the component's primary brute-force control, and
multiplying it also lowers the cost of SEC-01. IPv4 literals are less affected but still admit
nothing to normalise them. The component's javadoc explicitly contemplates the value arriving
from a trusted proxy header (`AuthenticationService.java:67-69`), which is precisely the path
where an attacker can influence the representation rather than just the address.

Failure scenario: an attacker at `2001:db8::1` spends its 10-failure budget, then continues
guessing as `2001:DB8::1`, `2001:0db8::1`, `2001:db8:0:0:0:0:0:1`, `2001:DB8:0:0:0:0:0:0001`
and so on. Each spelling is accepted by `canonicalSource`, keys a fresh counter, and yields 10
more guesses — hundreds of attempts per window from a single address, with the log also showing
them as unrelated sources because `LogSanitizer.maskSource` masks the raw string too.

**Fix:** Parse the validated literal into an `InetAddress` and re-render it, so every spelling of
one address collapses to one key. `InetAddress.getByName` performs no name resolution for an IP
literal, and the literal has already passed the allow-list above, so no hostname can reach it.

```java
        if (!(v4 ? isIpv4(raw) : isIpv6(raw))) {
            return Optional.empty();
        }
        try {
            // Re-render through InetAddress so that every textual spelling of one
            // address (hex case, zero padding, group compression) collapses to a
            // single throttle key. No DNS lookup happens: raw has already been
            // validated as an IP literal by the checks above.
            return Optional.of(java.net.InetAddress.getByName(raw).getHostAddress());
        } catch (java.net.UnknownHostException e) {
            return Optional.empty();
        }
```

### SEC-03: Invalid-input rejection path writes an audit record without consulting the throttle, allowing unauthenticated log flooding and evidence eviction
- **Severity:** Medium
- **CWE:** CWE-779: Logging of Excessive Data
- **Location:** `src/main/java/com/example/auth/AuthenticationService.java:77-85`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthenticationService.java:77-85
            if (canonicalUsername.isEmpty() || canonicalSource.isEmpty()
                    || !InputPolicy.isAcceptablePassword(password)) {
                // Nothing here depends on whether the account exists, so rejecting
                // early leaks nothing - and it keeps unvalidated values out of the
                // store lookup, the throttle key space and the log.
                audit(AuthEvent.Outcome.INVALID_INPUT, canonicalUsername.orElse(null),
                        canonicalSource.orElse(null), "input rejected by policy");
                return AuthenticationResult.failure();
            }
```

**Why it is a problem:** This branch returns before `attempt` is reached, so `throttle.admit` is
never consulted and `throttle.recordFailure` is never called — yet it performs a synchronous,
flushed disk write through `FileAuthEventLog.record`. The path is reachable by any
unauthenticated client with a trivially malformed request (an 11-character password is enough,
since `PASSWORD_MIN_LENGTH` is 12), it is not rate-limited in any way, and it remains open even
to a source that the throttle has already blocked. `FileAuthEventLog` keeps exactly one rotated
generation (`rotate()`, line 180-193), so an attacker can push roughly 2 × `maxBytes` of
INVALID_INPUT records through the file and permanently evict the genuine records of a real
attack — destroying exactly the evidence the component is built to retain. It is also an
unthrottled `fsync`-rate I/O amplifier against the host.

Failure scenario: an attacker first brute-forces `alice` until blocked, leaving the real
BAD_CREDENTIALS and THROTTLED records in the log. It then issues ~90 000 requests with an
11-character password (each ~190 bytes of log) against the default 8 MiB ceiling. The log
rotates twice; both the current file and the `.1` generation now contain only INVALID_INPUT
noise, and no record of the brute-force attempt survives. The throttle never saw any of the
90 000 requests.

**Fix:** Apply the throttle before writing anything on this path. When the source canonicalises,
charge the invalid attempt against the source budget and skip the record if that source is
already blocked; when the source itself is malformed, emit a periodic aggregate rather than one
record per request.

```java
            if (canonicalUsername.isEmpty() || canonicalSource.isEmpty()
                    || !InputPolicy.isAcceptablePassword(password)) {
                // Rate-limited like any other failed attempt: this path performs a
                // synchronous log write, so leaving it unthrottled would let an
                // unauthenticated client flood the audit file and rotate genuine
                // records out of it.
                if (canonicalSource.isPresent()) {
                    String src = canonicalSource.get();
                    if (throttle.admit(null, src).isEmpty()) {
                        audit(AuthEvent.Outcome.INVALID_INPUT, canonicalUsername.orElse(null),
                                src, "input rejected by policy");
                    }
                    throttle.recordSourceFailure(src);
                } else {
                    // The source is unusable as a throttle key, so record a counted
                    // aggregate instead of one line per request.
                    unkeyedInvalidInput.recordAndMaybeAudit(this::audit, clock.get());
                }
                return AuthenticationResult.failure();
            }
```

### SEC-04: Per-account cool-off is indefinitely renewable because the counter window is never reset
- **Severity:** Low
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/example/auth/LoginThrottle.java:195-203`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginThrottle.java:195-203
        boolean isExpired(Instant now, Duration window) {
            return !isBlocked(now) && windowStart.plus(window).isBefore(now);
        }

        Counter withFailure(Instant now, int budget, Duration coolOff) {
            int next = failures == Integer.MAX_VALUE ? failures : failures + 1;
            Instant until = next >= budget ? now.plus(coolOff) : blockedUntil;
            return new Counter(windowStart, next, until);
        }
```

**Why it is a problem:** `withFailure` carries `windowStart` forward unchanged and never resets
`failures`, so once a counter reaches `budget` it stays at or above it for its whole life. Each
subsequent failure therefore sets `blockedUntil = now + coolOff` again, and because `isExpired`
requires `!isBlocked(now)`, the counter is never garbage-collected while the attacker keeps
feeding it. The class documents the opposite property — "when exhausted it only imposes a
bounded cool-off that expires on its own - there is no sticky lockout" (lines 18-22) — but the
cool-off is renewable at a cost of one failed attempt per `accountCoolOff`, which is well within
a single source's budget. Only `recordSuccess` (line 119-121) clears it, and the legitimate user
must win a race against the attacker's next failure to get there.

Failure scenario: with defaults (`accountFailureBudget` 50, `accountCoolOff` 5 min,
`sourceFailureBudget` 10 per 15 min) an attacker spends `alice`'s 50-failure budget, then sends
one wrong password for `alice` every 5 minutes — 12 failures per hour, inside the 40 per hour
one source address is permitted. `alice`'s counter never expires and she is limited to the
narrow instants between cool-offs indefinitely, from a single IP address.

**Fix:** Reset the window and the failure count when a cool-off has fully elapsed, so an expired
penalty restores a full budget instead of leaving the counter one failure away from the next
block.

```java
        Counter withFailure(Instant now, int budget, Duration coolOff) {
            // A cool-off that has already elapsed must restore a full budget.
            // Carrying `failures` past the end of the penalty would let an attacker
            // renew the block indefinitely at one failed attempt per cool-off.
            boolean penaltyServed = !blockedUntil.equals(Instant.EPOCH) && !isBlocked(now);
            Instant start = penaltyServed ? now : windowStart;
            int previous = penaltyServed ? 0 : failures;
            int next = previous == Integer.MAX_VALUE ? previous : previous + 1;
            Instant until = next >= budget ? now.plus(coolOff) : (penaltyServed ? Instant.EPOCH : blockedUntil);
            return new Counter(start, next, until);
        }
```

### SEC-05: Decoy derivation uses the hasher's iteration count instead of matching the record's, leaking account existence by timing
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:73-79` (decoy built at lines 34-51), consumed at `src/main/java/com/example/auth/AuthenticationService.java:118-125`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/PasswordHasher.java:73-79
    public void verifyAgainstDecoy(char[] password) throws GeneralSecurityException {
        boolean ignored = verify(password, decoyRecord);
        if (ignored) {
            // Unreachable for any realistic input; kept so the branch is not elided.
            throw new GeneralSecurityException("decoy collision");
        }
    }
```

**Why it is a problem:** The decoy record is derived once in the constructor with
`this.iterations` (line 45), whereas a real verification uses the iteration count stored in the
record, `record.iterations()` (line 60). `CredentialRecord` deliberately accepts any count in
`[MIN_ITERATIONS, MAX_ITERATIONS]` — a 100× range — so any deployment whose stored records were
written with a count other than the hasher's configured one gives unknown accounts a measurably
different PBKDF2 cost from known accounts. PBKDF2 runtime is linear in the iteration count, so
the gap is large and stable rather than a few microseconds of noise, which defeats the
equal-work property that this method exists to provide and re-opens the username enumeration
that `AuthenticationResult`'s single generic failure was designed to close.

Failure scenario: a deployment loads a legacy store written at 100 000 iterations while the
service runs `PasswordHasher` with the 210 000 default. A login for an existing user takes
~100 ms; a login for a non-existent user takes ~210 ms. An attacker times one request per
candidate username and reads the account list straight off the response latency, without ever
needing a valid password.

**Fix:** Derive the decoy at the same iteration count as the record that would have been used.
Since no record exists, mirror the cost by deriving against a decoy whose iteration count is
taken from the store's prevailing value, and cache one decoy per observed count.

```java
    /**
     * Performs the same key derivation against a process-local decoy record so
     * that an attempt on an unknown username costs what an attempt on a known
     * username costs. The iteration count must match what a real record would
     * have used, because PBKDF2 cost is linear in it and a mismatch is an
     * observable account-existence oracle. The result is deliberately discarded.
     */
    public void verifyAgainstDecoy(char[] password, int recordIterations) throws GeneralSecurityException {
        CredentialRecord decoy = decoysByIterations.computeIfAbsent(
                InputPolicy.requireInRange("recordIterations", recordIterations, MIN_ITERATIONS, MAX_ITERATIONS),
                count -> newDecoy(count));
        boolean ignored = verify(password, decoy);
        if (ignored) {
            // Unreachable for any realistic input; kept so the branch is not elided.
            throw new GeneralSecurityException("decoy collision");
        }
    }
```

### SEC-06: Accepted PBKDF2 iteration floor (100 000) is below the OWASP figure the class itself cites
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:22-28`, enforced at `src/main/java/com/example/auth/PasswordHasher.java:35` and `src/main/java/com/example/auth/CredentialRecord.java:25-26`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/PasswordHasher.java:23-26
    /** OWASP's 2023 floor for PBKDF2-HMAC-SHA512 is 210 000 iterations. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 10_000_000;
```

**Why it is a problem:** The comment names 210 000 as the floor, and `DEFAULT_ITERATIONS`
honours it, but `MIN_ITERATIONS` is the value actually enforced — by the constructor
(line 35) and by every record loaded from the store (`CredentialRecord.java:25-26`). It permits
configurations and stored verifiers at less than half the stated floor, so a deployment that
passes `MIN_ITERATIONS`, or a store migrated from an older scheme, silently halves offline
cracking cost for every password in it. `CredentialRecord`'s own javadoc identifies the
iteration count as attacker-relevant and the floor as the defence, which makes the floor itself
the control worth getting right.

Failure scenario: an operator constructs `new PasswordHasher(PasswordHasher.MIN_ITERATIONS)`
(as `AuthenticationSelfCheck.java:38` does) or loads a store of records stamped at 100 000. The
store later leaks. An attacker's GPU rig recovers roughly twice as many passwords per unit time
as the documented posture implies, and nothing in the component flagged the shortfall.

**Fix:** Raise the enforced floor to the cited figure so the documented and the enforced value
agree, and keep a deliberately named, separately gated migration constant if legacy records must
still be readable.

```java
    /** OWASP's 2023 floor for PBKDF2-HMAC-SHA512 is 210 000 iterations. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    /**
     * The enforced floor equals the documented floor: a lower value halves offline
     * cracking cost for every verifier it covers, and it is enforced on records
     * loaded from the store as well as on this class's own configuration.
     */
    static final int MIN_ITERATIONS = 210_000;
    static final int MAX_ITERATIONS = 10_000_000;
```

### SEC-07: A failed log rotation leaves the audit sink permanently closed, turning a transient I/O fault into a permanent authentication outage
- **Severity:** Low
- **CWE:** CWE-703: Improper Check or Handling of Exceptional Conditions
- **Location:** `src/main/java/com/example/auth/FileAuthEventLog.java:181-193`, observed at `src/main/java/com/example/auth/FileAuthEventLog.java:165-166`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/FileAuthEventLog.java:181-193
    private void rotate() throws IOException {
        out.flush();
        out.close();
        out = null;
        Path previous = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, previous, StandardCopyOption.REPLACE_EXISTING);
        PosixFileAttributeView view = Files.getFileAttributeView(previous, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view != null) {
            view.setPermissions(FILE_MODE);
        }
        openForAppend();
    }
```

**Why it is a problem:** `out` is set to `null` before the move, and nothing restores it if any
step after that throws. The exception propagates to `record`'s handler (line 174-176) as a single
`AuditException`, but the object is now permanently wedged: every later `record` call hits
`if (out == null) throw new IOException("log is closed")` at line 165-166 and throws again, with
no reopen attempt ever made. Because the component correctly refuses to authenticate an attempt
it cannot record (`AuthenticationService.java:146-153`), one transient failure in `Files.move` or
`openForAppend` — a full volume at `createFile` time, a directory whose permissions changed, a
brief filesystem error — permanently denies *all* logins for the lifetime of the process, and the
condition is self-inflicted rather than detected. Rotation is triggered by request volume, so an
attacker can choose when the component is at its most fragile.

Failure scenario: the log volume fills exactly as the 8 MiB ceiling is crossed. `rotate` closes
and nulls `out`, `Files.move` succeeds, `openForAppend`'s `Files.createFile` fails with
`ENOSPC`. The `IOException` becomes an `AuditException` and the current login is correctly
denied. An operator frees disk space a minute later, but every subsequent authentication still
fails with "We could not sign you in." until the process is restarted, because `out` is still
`null` and `openForAppend` is never called again.

**Fix:** Make rotation recoverable: never discard a working stream before the replacement is in
place, and let a later `record` retry the open rather than latching the closed state.

```java
    /** Keeps exactly one previous generation, so total log footprint stays under 2x maxBytes. */
    private void rotate() throws IOException {
        OutputStream current = out;
        out = null;
        try {
            current.flush();
        } finally {
            current.close();
        }
        Path previous = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, previous, StandardCopyOption.REPLACE_EXISTING);
        PosixFileAttributeView view = Files.getFileAttributeView(previous, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view != null) {
            view.setPermissions(FILE_MODE);
        }
        openForAppend();
    }

    @Override
    public void record(AuthEvent event) throws AuditException {
        String line = render(event);
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        synchronized (writeLock) {
            try {
                if (closed) {
                    throw new IOException("log is closed");
                }
                if (out == null) {
                    // A previous rotation failed part-way. Retry the open here so a
                    // transient I/O fault cannot permanently deny every subsequent
                    // authentication; a still-failing open denies this attempt only.
                    openForAppend();
                }
                if (written + bytes.length > maxBytes) {
                    rotate();
                }
                out.write(bytes);
                out.flush();
                written += bytes.length;
            } catch (IOException e) {
                throw new AuditException("authentication event could not be retained", e);
            }
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **Password storage algorithm and parameters:** `PasswordHasher.java:22-28` uses
  `PBKDF2WithHmacSHA512` via the JDK `SecretKeyFactory`, 512-bit output, 16-byte salt,
  210 000 default iterations. No MD5, SHA-1, unsalted digest, or hand-rolled KDF anywhere in the
  tree. (Only the accepted *floor* is low — SEC-06.)
- **Per-password salt from a CSPRNG:** a fresh 16-byte salt is drawn from `SecureRandom` for every
  derivation (`PasswordHasher.java:86-87`); no shared, static or time-seeded salt exists.
- **Constant-time verifier comparison:** `MessageDigest.isEqual` at `PasswordHasher.java:62`,
  not `Arrays.equals` or `==`; the derived key is zeroed in a `finally` at line 64.
- **Equal work for unknown accounts:** `AuthenticationService.java:118-125` performs a full
  PBKDF2 derivation against a decoy record when no account exists, rather than returning early.
  (Correct in structure; the iteration count is the gap — SEC-05.)
- **Single generic failure response:** one shared immutable `FAILURE` instance and one message
  for malformed input, unknown account, wrong password, throttling and store outage
  (`AuthenticationResult.java:361-367`, `AuthenticationService.java:84, 105, 113, 128, 135, 143, 152`).
  No status, field, message or exception detail distinguishes them.
- **No credential or session material in logs:** `AuthEvent` has no field for a password, derived
  key or session id by construction (`AuthEvent.java:14-19`); `FileAuthEventLog.render`
  (lines 195-204) writes only timestamp, outcome, masked username, keyed correlation id, masked
  source and a detail string that carries exception *class* names only
  (`AuthenticationService.java:89, 112, 127, 142`). `AuthenticationSelfCheck.java:121` asserts the
  password never appears in the log.
- **Log injection / record forging:** `LogSanitizer.escape` (lines 222-242) maps every character
  below `0x20` or above `0x7e` — including CR and LF — to `.`, escapes `"` and `\`, and truncates
  to 64 characters, so one record cannot become two and no downstream parser can be broken.
  `InputPolicy.canonicalUsername` independently rejects control characters before that.
- **Input validation is allow-list, not sanitise-and-continue:** `InputPolicy.canonicalUsername`
  (lines 47-69) permits only ASCII alphanumerics plus `. _ - @ +`, requires alphanumeric first
  and last characters, bounds the length, and rejects rather than rewrites. Wildcards, quotes,
  backslashes, NUL, Unicode confusables and directory/SQL metacharacters cannot reach the store,
  the throttle key space or the log.
- **Locale-safe case folding:** `toLowerCase(Locale.ROOT)` at `InputPolicy.java:68`, which avoids
  the Turkish dotless-i class of bug where two distinct usernames fold together; it runs on an
  already ASCII-restricted string.
- **Username canonicalisation defeats per-account throttle-key rotation:** `Alice`, `ALICE` and
  `alice` all canonicalise to one key before `throttle.admit`
  (`AuthenticationService.java:75, 86`), so the account-rotation bypass from
  `performing-api-rate-limiting-bypass` Step 5 does not apply; whitespace- and
  percent-encoded variants are rejected outright.
- **Password length bounds:** `InputPolicy.java:21-27, 75-79` enforces a 12-character minimum and
  a 256-character maximum, the latter specifically to cap PBKDF2 cost. Content/complexity rules
  are deliberately out of scope (registration), which is a documented scope decision rather than
  a gap in this component.
- **Session identifier entropy and unpredictability:** 32 bytes from `SecureRandom` per session,
  base64url-encoded to 43 characters (`SessionRegistry.java:32, 77-79`). No counter, timestamp,
  username, hash of user data, or `java.util.Random` contribution; the raw buffer is zeroed at
  line 80.
- **Session identifiers are not stored in recoverable form:** only `SHA-256(identifier)` is kept
  as the map key (`SessionRegistry.java:81, 131-138`); `Session` holds no identifier material
  (`Session.java:7-8, 12-15`). A heap dump or leaked diagnostic yields no replayable session.
  The unkeyed digest is appropriate here because the input is 256 uniform random bits.
- **Session fixation:** a client-supplied identifier can never be promoted. `issue` always mints a
  fresh value and never reads any caller input into it (`SessionRegistry.java:69-83`), and
  `validate` only ever looks identifiers up (lines 95-110).
- **Server-side revocation on sign-out:** `AuthenticationService.signOut` →
  `SessionRegistry.invalidate` removes the server-side entry (lines 113-117), so a presented
  identifier is dead immediately afterwards — not merely expired client-side.
- **Session expiry is enforced server-side and atomically:** both the 30-minute idle and the
  8-hour absolute deadline are checked inside one `ConcurrentHashMap.compute`
  (`SessionRegistry.java:101-108`, `Session.java:41-44`), so a concurrent request cannot revive
  an expired session by racing the check, and the refresh cannot extend past the absolute cap.
- **Shape is never treated as proof:** `InputPolicy.isWellFormedSessionId` (lines 173-186) is only
  a pre-filter; authorisation comes solely from the registry lookup
  (`AuthenticationService.java:164-166`). A well-formed but unknown identifier yields empty.
- **Cookie hardening:** `SessionCookie.java:35-38` emits `Secure`, `HttpOnly`,
  `SameSite=Strict`, an explicit narrow `Path`, no `Domain`, and the `__Host-` name prefix; the
  attributes are compile-time constants so no deployment can weaken them.
- **Cookie header injection (CWE-113):** `setCookieHeader` refuses any identifier that is not
  exactly 43 base64url characters (lines 27-31) and bounds `Max-Age` (lines 32-34), so no CR, LF,
  `;` or `=` can be smuggled into the response header.
- **Password buffer lifetime:** `authenticate` zeroes the caller's `char[]` in a `finally` on every
  path including exceptions (`AuthenticationService.java:91-95`); `derive` calls
  `spec.clearPassword()` in a `finally` (`PasswordHasher.java:95-98`); the decoy secret is zeroed
  at construction (lines 48-50). `AuthenticationSelfCheck.java:183` asserts this. The only
  residue is the `byte[]` returned by `derive` inside `hash()` (`PasswordHasher.java:88`), which
  is cloned into the record and left uncleared — not reported, since the verifier is already
  persisted in the store by design.
- **Untrusted store records are validated:** `CredentialRecord`'s constructor rejects null arrays,
  wrong salt length, wrong key length and out-of-range iteration counts
  (`CredentialRecord.java:15-29`), specifically closing the "tampered record claiming one
  iteration" downgrade. Arrays are cloned on both construction and accessor
  (lines 27-28, 31-39).
- **No sensitive data in `toString`:** `CredentialRecord.toString` redacts salt and hash
  (line 44), `AuthenticationResult.toString` omits the session id and masks the username
  (lines 412-416), `Session.toString` renders no identifier (lines 51-54).
- **Fail-closed on every error path:** store outage, PBKDF2 failure, session-capacity exhaustion
  and unexpected `RuntimeException` all deny the attempt and log only an exception class name
  (`AuthenticationService.java:87-90, 111-114, 126-129, 141-144`). No stack trace or internal
  message reaches the caller.
- **An unrecordable success is refused:** `AuthenticationService.java:146-153` invalidates the
  freshly issued session and returns failure if the SUCCESS record cannot be retained, so no
  authentication is granted unobserved.
- **Audit-log file permissions and symlink resistance:** the directory is created `0700` and the
  file `0600` with explicit `PosixFilePermissions` rather than relying on umask; both are
  re-verified after creation and the component refuses to write if either is reachable by other
  users (`FileAuthEventLog.java:105-153`). Every stat and open uses `LinkOption.NOFOLLOW_LINKS`
  and the target must be a regular file (lines 109, 118, 122, 134, 143, 147, 155-156), so a
  pre-planted symlink cannot redirect the writes. `FileAlreadyExistsException` is tolerated and
  re-validated, closing the create/check race.
- **Log size is bounded:** `maxBytes` is range-checked (lines 69-71) and rotation keeps exactly one
  previous generation, capping the footprint at 2 × `maxBytes` so the log cannot fill the volume.
  (The *eviction* consequence of that cap is SEC-03; the rotation *failure* path is SEC-07.)
- **Concurrent writes cannot interleave within a record:** all writes are inside
  `synchronized (writeLock)` and flushed (`FileAuthEventLog.java:163-177`); the `Mac` instance is
  guarded by its own monitor and reset before each use (lines 217-220), avoiding the classic
  shared-`Mac` state-corruption bug.
- **Account correlation is keyed, not plain:** HMAC-SHA256 with a deployment-supplied key of at
  least 16 bytes, or a process-local random key, truncated to 72 bits
  (`FileAuthEventLog.java:83-103, 211-222`). A plain digest of a short username space would be
  enumerable offline; this is not. The key is never logged or echoed.
- **Address and username masking in the log:** `LogSanitizer.maskUsername` keeps only the first and
  last character, and `maskSource` drops the last IPv4 octet or everything below the IPv6 /48
  (lines 248-279), so the log does not become an account and address directory.
- **No hardcoded secrets:** a knowledge-based secret scan over `src/` and `pom.xml` found no
  password, key, token or API key. `InMemoryCredentialStore` is explicitly unseeded
  (lines 326-328) and `AuthenticationSelfCheck` generates its test password from `SecureRandom`
  at runtime (lines 231-238), so nothing in the tree grants access to any deployment.
- **Atomic check-then-act in the throttle:** every read and state change happens inside a single
  `ConcurrentHashMap.compute` (`LoginThrottle.java:123-135, 167-171`), so a burst of parallel
  requests cannot slip past the budget; `AuthenticationSelfCheck.java:205-225` exercises this
  concurrently.
- **Throttle counter arithmetic is overflow-safe:** `withFailure` saturates at
  `Integer.MAX_VALUE` (`LoginThrottle.java:200`) rather than wrapping to a negative count that
  would silently clear the block.
- **Per-source counter is not reset by a successful login:** `recordSuccess` clears only the
  account counter (`LoginThrottle.java:119-121`), so an attacker holding one valid account of
  their own cannot reset the per-source budget and guess indefinitely from the same address. The
  documented trade-off is correct and was verified, not assumed.
- **Configuration is rejected rather than clamped:** `InputPolicy.requireInRange` throws
  (lines 189-195) and is used for iteration counts, failure budgets and `maxBytes`; durations are
  bounded and `absoluteTimeout >= idleTimeout` is enforced (`SessionRegistry.java:42-61`,
  `LoginThrottle.java:51-70`). No out-of-range value is silently normalised into a weaker setting.
- **Session table is bounded:** `MAX_SESSIONS` with an expiry purge before refusing
  (`SessionRegistry.java:71-76`), and the resulting `IllegalStateException` is caught and failed
  closed by the caller (`AuthenticationService.java:139-144`). Unlike SEC-01 this cap is not
  reachable by unauthenticated input, since only a successful login creates an entry.
- **Injection classes not present:** there is no SQL/JPA/JDBC call, no ORM, no NoSQL query, no
  LDAP filter, no template engine, no HTML or JSON rendering, no `ObjectInputStream` or other
  deserialization, no XML parsing, no `Runtime.exec`/`ProcessBuilder`, no reflection on
  caller-supplied names, no client-controlled file path (the only path is the configured log
  file, normalised at `FileAuthEventLog.java:68`), and no outbound HTTP/URL/socket call. SQL
  injection, XXE, SSRF, XSS, command injection, path traversal and insecure deserialization are
  therefore not reachable in this component.
- **Dependency supply chain:** `pom.xml` declares zero third-party dependencies and one pinned
  Apache plugin version, so there is no vulnerable-component or dependency-confusion exposure.
- **Session-to-address binding (reviewed, not reported):** `Session` records the originating
  `source` (`Session.java:13, 28-31`) but `validate` does not compare it on resumption. This is a
  defensible design choice — IP pinning breaks mobile and CGNAT clients and is weak against an
  attacker on the same network — and the field is documented as audit-only, so it is noted rather
  than raised as a finding.
- **IPv6 literal parser leniency (reviewed, not reported):** `InputPolicy.isIpv6` (lines 135-164)
  accepts some malformed-but-harmless forms. The impact is confined to the throttle key space and
  the log, both of which are already bounded by the 45-character limit and the hex/`.`/`:`
  character allow-list, so no finding is raised; the exploitable consequence of not *normalising*
  the value is reported separately as SEC-02.
