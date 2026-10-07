# Security Review: authentication-component

## 1. Executive Summary

This review covers a standalone Java 17 authentication component (Maven artifact `authentication-component`) that implements username/password login, credential verification with PBKDF2, in-memory sessions, a login rate limiter, and a private rolling-file audit sink. The review was performed statically — the code was never executed, built, or imported — following the dispatcher workflow of the `review-code-for-security-vulnerabilities` skill and the specialised skills listed in §3.

The cryptographic core is strong. Password hashing uses PBKDF2-HMAC-SHA-256 at OWASP-recommended iteration counts with per-password 128-bit salts, hash comparison is constant-time, session tokens are 256-bit CSPRNG values persisted only as SHA-256 digests, the session cookie uses `__Host-` prefix attributes, secrets held in `char[]`/`byte[]` are zeroized, audit records carry only HMAC-pseudonymous hex digests, and several error paths fail closed. No hardcoded credentials, weak algorithms, or injection sinks were found.

Three issues are reported:

1. **SEC-01 (Medium, CWE-307):** the rate limiter's `THROTTLED` decision never blocks anything. The only consumer of the flag in `AuthenticationService.authenticate()` is the audit-log reason, and the public `Result` API gives callers no way to learn that an attempt was throttled — so the component's advertised brute-force limit exerts zero backpressure and cannot even be enforced by an HTTP edge that trusts it.
2. **SEC-02 (Medium, CWE-400):** `InMemoryLoginRateLimiter` performs a full scan of both of its up-to-100,000-entry maps on every single login attempt (under a global monitor), and throws `IllegalStateException` once a key map is full — an attacker who sprays unique source addresses can both amplify per-request CPU cost and wedge every login in the service into a permanent fail-closed state.
3. **SEC-03 (Low, CWE-226):** two `correlate()` calls run *before* the `try`/`finally` that zeroizes the caller's password array; if the HMAC primitive is unavailable, the exception escapes and the plaintext password is left uncleared.

None of the findings expose credentials or forge sessions directly; SEC-01 and SEC-02 degrade the brute-force and availability guarantees the component's own documentation claims. §6 lists the controls that were checked and verified.

## 2. Scope

All paths are relative to the read-only source folder `/data/results/codex/set_a/post_research/6/security/`. The `target/` build-output tree was excluded; `pom.xml`, `README.md`, and `prompt.txt` were read as context.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition | Java 17; only test-scoped JUnit 5 — no runtime dependencies; no shaded/vendored code |
| `src/main/java/example/security/auth/AuthenticationService.java` | Core login orchestration | Rate-limit call, credential verify, session/token creation, cookie emission, secret zeroization, fail-closed error paths, clock clamping |
| `src/main/java/example/security/auth/PasswordVerifier.java` | PBKDF2 hashing/verification | KDF parameters, constant-time compare, `char[]` and `PBEKeySpec` zeroization, password validation |
| `src/main/java/example/security/auth/PasswordRecord.java` | Stored hash record | Enforces 600k–2M iteration bounds, 16-byte salt / 32-byte hash sizes, clone-on-get, redacted `toString()` |
| `src/main/java/example/security/auth/InMemoryCredentialStore.java` | In-memory user store | Atomic verify contract, unknown-user dummy-KDF timing equalization, 100k entry cap |
| `src/main/java/example/security/auth/InMemorySessionStore.java` | Session registry | Stores only SHA-256 token digests, expiry purge, TTL ≤ 24 h cap, capacity cap, key-format validation |
| `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java` | Fixed-window throttle | Dual source/account counters, `MAX_KEYS` cap, expiry sweep, capacity-exhaustion exception |
| `src/main/java/example/security/auth/PrivateRollingFileAuditSink.java` | Durable audit log | Directory/file permission enforcement (0700/0600), `NOFOLLOW_LINKS`, file lock, `force(true)` fsync, atomic rotation, size caps |
| `src/main/java/example/security/auth/AuthenticationEvent.java` | Audit record | Enforces `[0-9a-f]{64}` digests for subject/source/session keys, SUCCESS↔sessionKey consistency |
| `src/main/java/example/security/auth/CredentialStore.java` | Credential-store SPI | Documents atomic verify; `AuthenticatedPrincipal` account-id regex |
| `src/main/java/example/security/auth/SessionStore.java` | Session-store SPI | Digest-only token contract |
| `src/main/java/example/security/auth/LoginRateLimiter.java` | Rate-limiter SPI | Atomic `registerAttempt` contract, `Decision` enum |
| `src/main/java/example/security/auth/AuditSink.java` | Audit SPI | Durable-or-throw append contract |
| `src/test/java/example/security/auth/AuthenticationServiceTest.java` | Tests | Encodes expected security behaviour, incl. throttle anti-lockout semantics |
| `src/test/java/example/security/auth/PrivateRollingFileAuditSinkTest.java` | Tests | Audit-file hardening expectations |

## 3. Skills Applied

Sibling skills from the security-skill library whose guidance was applied to this code:

- **performing-cryptographic-audit-of-application** — audited KDF choice and parameters (PBKDF2-HMAC-SHA-256, iteration bounds, salt size), CSPRNG use for tokens/dummies, constant-time comparison, and digest-only at-rest token storage against the skill's weakness checklist (weak KDF, weak entropy source, hardcoded keys). Drove the §6 verification items 1–4 and confirmed no crypto finding.
- **testing-api-authentication-weaknesses** — reviewed the login flow for token generation/validation lifecycle, cookie attributes, generic failure messages, and user-enumeration timing (dummy-KDF parity). Framed SEC-01 (brute-force exposure) and §6 items 3–6.
- **implementing-api-rate-limiting-and-throttling** — evaluated the limiter's window design, keying (source vs. account), in-memory single-instance state, and — critically — whether the throttle decision is *enforced* rather than advisory. Primary source of SEC-01; its fixed-window-boundary pitfall is noted in §6.
- **performing-api-rate-limiting-bypass** — used the skill's bypass catalogue (distributed sources, key-selection weaknesses, header-IP spoofing) to stress the limiter. Distributed-source flooding against the `MAX_KEYS` cap produced SEC-02; X-Forwarded-For spoofing was checked and ruled out (§6 item 16).
- **testing-for-sensitive-data-exposure** — traced plaintext passwords, tokens, and cookies through memory, return values, `toString()`, and the audit path; verified zeroization discipline. Produced SEC-03 (zeroization bypass on an early-throw path) and §6 items 5–8, 12.
- **testing-for-broken-access-control** — checked session creation/consumption boundaries, account-id and key validation, and whether any input lets a caller act on another principal. No finding; informed §6 items 4, 14.
- **implementing-secret-scanning-with-gitleaks** — manual equivalent sweep of all files for committed credentials/API keys. No finding; §6 item 12.

**Behaviours covered by general OWASP/CWE knowledge instead:** the skill library has no specialised skill for local audit-file hardening (POSIX permission enforcement, symlink/`NOFOLLOW_LINKS` handling, rotation atomicity, TOCTOU between `ensureFile()` and channel open), for fail-closed clock handling (`safeNow` epoch clamping), or for log-injection resistance of the audit record format. These were assessed against the OWASP Logging, Authentication, and Cryptography Cheat Sheets and CWE-117/CWE-367 general knowledge, and are reported in §6 items 8–11.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate-limit decision is advisory only — throttling never blocks or delays an attempt | Medium | CWE-307 | `src/main/java/example/security/auth/AuthenticationService.java:78-79, 95-96, 125-127` |
| SEC-02 | Rate limiter allows attacker-amplified CPU cost and a global fail-closed login outage via key-map exhaustion | Medium | CWE-400 | `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java:34-47, 69-77` |
| SEC-03 | Plaintext password not zeroized when `correlate()` throws before the `try`/`finally` | Low | CWE-226 | `src/main/java/example/security/auth/AuthenticationService.java:71-72, 128-133` |

## 5. Detailed Findings

### SEC-01: Rate-limit decision is advisory only — throttling never blocks or delays an attempt

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/example/security/auth/AuthenticationService.java:78-79`, `src/main/java/example/security/auth/AuthenticationService.java:95-96`, `src/main/java/example/security/auth/AuthenticationService.java:125-127`

**Vulnerable code:**

```java
// AuthenticationService.java:78-79
                throttled = limiter.registerAttempt(sourceKey, subjectKey, now)
                        == LoginRateLimiter.Decision.THROTTLED;
```

```java
// AuthenticationService.java:125-127
            logFailure(now, subjectKey, sourceKey, throttled
                    ? AuthenticationEvent.Reason.THROTTLED : AuthenticationEvent.Reason.REJECTED);
            return Result.failure();
```

**Why it is a problem:**

`throttled` is assigned at line 78-79 and read in exactly one place: line 126, to pick the audit-log reason string. No code path in the component ever refuses, delays, or cheapens an attempt because it was throttled. When the limiter says `THROTTLED`, `authenticate()` proceeds to run the full 600,000-iteration PBKDF2 verification (line 87, `credentials.verify(canonical, password)`) and, on a correct password, still creates a session and returns a valid cookie (the success branch at line 96 is gated only on `principal.isPresent()`, never on `throttled`; the comment at line 95 confirms this is deliberate for the *account* counter). For the *source* counter this means an online brute-force or password-spray from a single peer receives exactly the same service — full KDF work and an authoritative accept/reject signal — on attempt 1 and attempt 10,000. The per-source limit reduces attacker work by nothing; it only changes a log label.

The component's README argues throttling is delegated to "an HTTP edge [that] applies a bounded delay/queue to `THROTTLED` events," but the public API makes that impossible to honour: the `Decision` is consumed internally and the returned `Result` record (`AuthenticationService.java:217-229`) exposes only `authenticated`, `message`, and `setCookieHeader` — an integrator has no signal that a given attempt was throttled and would have to duplicate the entire counter implementation to enforce it. The `THROTTLED` audit reason also only appears on *failed* attempts, so an operator watching logs sees throttles only for guesses that were wrong anyway.

Note that the account-keyed half of this design is a *deliberate, documented* anti-lockout measure (test `accountThrottleDoesNotLetAnAttackerLockOutCorrectCredentials`) and is not itself the defect; the defect is that the source-keyed half — the half whose entire purpose is limiting an attacker — is never enforced and never surfaced.

**Fix:**

Make the limiter report *which* limit tripped, refuse source-limited attempts before performing real verification (while burning equivalent KDF work so the throttled path is timing-indistinguishable from a wrong-password attempt), and keep the account counter advisory for anti-lockout:

```java
// LoginRateLimiter.java — distinguish which counter tripped instead of a single verdict.
record Decision(boolean sourceLimited, boolean accountLimited) {
    static final Decision ALLOW = new Decision(false, false);
}
```

```java
// InMemoryLoginRateLimiter.java — return the detailed decision.
boolean sourceLimited = count(sources, sourceKey, now) >= perSource;
boolean accountLimited = count(accounts, accountKey, now) >= perAccount;
// ... increment both counters as before ...
return (sourceLimited || accountLimited) ? new Decision(sourceLimited, accountLimited) : Decision.ALLOW;
```

```java
// AuthenticationService.java — enforce the source limit inside authenticate().
Decision decision;
try {
    decision = limiter.registerAttempt(sourceKey, subjectKey, now);
} catch (RuntimeException e) {
    return internalFailure(now, subjectKey, sourceKey);
}
if (decision.sourceLimited()) {
    // Equal cost to a real wrong-password attempt so throttling is not a faster path.
    PasswordVerifier.verify(INVALID_PASSWORD.clone(), dummyRecord);
    logFailure(now, subjectKey, sourceKey, AuthenticationEvent.Reason.THROTTLED);
    return Result.failure();
}
// Account-side pressure stays advisory: correct credentials must not be lockable out.
```

If the API contract must stay `boolean`-free, at minimum add the throttle state to `Result` (or a dedicated field) so the HTTP edge can apply its documented delay/queue — but enforcement inside the component is the safer default, since every integrator otherwise inherits an inert control.

### SEC-02: Rate limiter allows attacker-amplified CPU cost and a global fail-closed login outage via key-map exhaustion

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java:34-47`, `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java:69-77`

**Vulnerable code:**

```java
// InMemoryLoginRateLimiter.java:34-47
    @Override public synchronized Decision registerAttempt(String sourceKey, String accountKey, Instant now) {
        validateKey(sourceKey); validateKey(accountKey); validateTime(now);
        expire(now);
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
    }
```

```java
// InMemoryLoginRateLimiter.java:69-77
    private void expire(Instant now) {
        removeExpired(sources, now);
        removeExpired(accounts, now);
    }

    private void removeExpired(Map<String, Counter> map, Instant now) {
        Iterator<Counter> it = map.values().iterator();
        while (it.hasNext()) if (expired(it.next(), now)) it.remove();
    }
```

**Why it is a problem:**

Two attacker-reachable availability defects compound in this class, both stemming from cost and capacity being driven by data the attacker controls (distinct source keys — trivially produced from an IPv6 host, a proxy fleet, or a botnet; the key is just an HMAC of the peer address, so every new peer IP is a new map entry):

1. **O(n) cost amplification per attempt (CWE-407 in the small).** `expire()` at line 36 walks *both* maps on *every* login attempt, and the whole method holds the class monitor (`synchronized`). Nothing bounds the map size within a window other than `MAX_KEYS = 100_000`, so once an attacker has seeded tens of thousands of live source entries, every authentication — including legitimate ones — pays a full scan of up to 200,000 entries, serialized behind one global lock. A few dozen unique source IPs per second permanently degrades the login path; the attacker's own requests are the ones causing victims' logins to queue.
2. **Global fail-closed wedge via capacity exhaustion.** When `sources.size()` reaches `MAX_KEYS`, line 42 throws `IllegalStateException` for *every new* key — and because `expire()` can only evict counters whose window has passed, an attacker who keeps the working set of unique sources at/over the cap keeps throwing. `AuthenticationService` catches the `RuntimeException` (line 80-81) and routes to `internalFailure()`, which returns the generic failure for *every* login, including correct credentials from innocent users. Result: a permanent, unauthenticated, unbounded-lifetime denial of the entire authentication service, caused by the defender's own fail-closed choice. The state self-heals only when the attack stops and counters expire, so a low-and-slow trickle of unique sources is enough to stay at the cap.

Memory itself is bounded (that part of the design is sound); the uncontrolled resources are CPU under a global lock and the availability of login for everyone else.

**Fix:**

Remove the full-map sweep and the throw. `count()` and `increment()` already treat expired counters as absent/fresh on access, so expiry can be lazy, and an access-order LRU cap bounds memory without ever refusing service:

```java
// InMemoryLoginRateLimiter.java — O(1) attempts, lazy expiry, bounded eviction instead of throwing.
private final Map<String, Counter> sources = new LinkedHashMap<>(64, 0.75f, true) {
    @Override protected boolean removeEldestEntry(Map.Entry<String, Counter> eldest) {
        return size() > MAX_KEYS;
    }
};
// accounts map is constructed identically.

@Override public synchronized Decision registerAttempt(String sourceKey, String accountKey, Instant now) {
    validateKey(sourceKey); validateKey(accountKey); validateTime(now);
    boolean throttled = count(sources, sourceKey, now) >= perSource
            || count(accounts, accountKey, now) >= perAccount;
    increment(sources, sourceKey, now);   // expired counters are replaced in place by increment()
    increment(accounts, accountKey, now);
    return throttled ? Decision.THROTTLED : Decision.ALLOW;
}
```

Now a unique-source flood costs the defender O(1) per request and can at worst evict the least-recently-seen counters (weakening limits for a *third party's* old key, not blocking anyone's login), rather than converting each login into a 200,000-entry scan or switching authentication off globally.

### SEC-03: Plaintext password not zeroized when `correlate()` throws before the `try`/`finally`

- **Severity:** Low
- **CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- **Location:** `src/main/java/example/security/auth/AuthenticationService.java:71-72`, `src/main/java/example/security/auth/AuthenticationService.java:128-133`

**Vulnerable code:**

```java
// AuthenticationService.java:67-76
        Instant now = safeNow();
        String canonical = validUsername(username) ? canonicalUsername(username) : null;
        boolean validPassword = validPassword(password);
        byte[] sourceBytes = validatedSourceBytes(source);
        String subjectKey = correlate("account", canonical == null ? "invalid" : canonical);
        String sourceKey = correlate("source", HexFormat.of().formatHex(sourceBytes));
        boolean throttled = false;
        byte[] token = null;
        byte[] tokenDigest = null;
        try {
```

```java
// AuthenticationService.java:128-133
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (token != null) Arrays.fill(token, (byte) 0);
            if (tokenDigest != null) Arrays.fill(tokenDigest, (byte) 0);
            Arrays.fill(sourceBytes, (byte) 0);
        }
```

**Why it is a problem:**

The method's own contract (Javadoc at line 65: "Consumes and clears `password` on every path") is enforced by the `finally` block at lines 128-133 — but the two `correlate()` calls at lines 71-72 sit *outside and before* the `try`. `correlate()` (lines 183-193) rethrows any failure as `IllegalStateException("Required correlation primitive unavailable")`. If `HmacSHA256` is unavailable or unusable — e.g. a FIPS-restricted or broken JCE provider configuration — the exception escapes `authenticate()` from line 71, the `finally` block is never entered, and the caller's plaintext password `char[]` survives in memory unscrubbed, defeating the exact hardening discipline (zeroize secrets on every path, cf. `PasswordVerifier` clearing `PBEKeySpec` at line 60 and derived copies at lines 26-27, 37) that the rest of the component carefully maintains. The likelihood is low because `HmacSHA256` is a mandatory JDK-algorithm, but the impact class (residual plaintext credentials in heap memory, exposed to heap dumps and later array reuse) matches the control the code otherwise guarantees, and the fix is free.

**Fix:**

Move the key derivation inside the `try` so the zeroization block covers it (declare the keys for later use in the method body):

```java
        Instant now = safeNow();
        String canonical = validUsername(username) ? canonicalUsername(username) : null;
        boolean validPassword = validPassword(password);
        byte[] sourceBytes = validatedSourceBytes(source);
        boolean throttled = false;
        byte[] token = null;
        byte[] tokenDigest = null;
        String subjectKey;
        String sourceKey;
        try {
            subjectKey = correlate("account", canonical == null ? "invalid" : canonical);
            sourceKey = correlate("source", HexFormat.of().formatHex(sourceBytes));
            try {
                throttled = limiter.registerAttempt(sourceKey, subjectKey, now)
                        == LoginRateLimiter.Decision.THROTTLED;
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }
            // ... remainder of the method unchanged ...
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (token != null) Arrays.fill(token, (byte) 0);
            if (tokenDigest != null) Arrays.fill(tokenDigest, (byte) 0);
            Arrays.fill(sourceBytes, (byte) 0);
        }
```

## 6. Verified Controls and Checks With No Finding

The following controls were exercised by the applied skills and general OWASP/CWE review and are confirmed present and correct; no finding is raised on them.

1. **Password hashing strength.** PBKDF2-HMAC-SHA-256 with bounds of 600,000–2,000,000 iterations (`PasswordRecord.java:10-11`, enforced at `:23`), a fresh 16-byte `SecureRandom` salt per hash, and a 32-byte derived key (`PasswordVerifier.java:17-29`, derive at `:50-60`) — meets the OWASP Password Storage minimum (600k for PBKDF2-SHA-256).
2. **Constant-time verification.** Hash comparison uses `MessageDigest.isEqual` (`PasswordVerifier.java:35`), preventing timing side-channels on the hash check itself.
3. **User-enumeration / timing parity for unknown accounts.** Unknown usernames still run a full dummy KDF (`InMemoryCredentialStore.java:44-46`; invalid-input path `AuthenticationService.java:86-89`), and the dummy record is generated at construction (`AuthenticationService.java` constructor) so login timing does not distinguish "no such user" from "wrong password."
4. **Session token strength and storage.** Tokens are 32 bytes from the injected `SecureRandom` CSPRNG, stored server-side only as SHA-256 digests, with creation rejecting non-future expiry, TTL > 86,400 s, and capacity overflow (`AuthenticationService.java:99-103`; `InMemorySessionStore.java:22-31`, purge/expiry checks at `:26-27`). A store dump therefore yields no usable bearer tokens.
5. **Cookie hardening.** Session cookie uses the `__Host-` name prefix with `Path=/`, `Max-Age`, `Secure`, `HttpOnly`, `SameSite=Strict`, no `Domain` attribute (`AuthenticationService.java:119-122`).
6. **No credential leakage in API surface.** Failures return a single generic message (`AuthenticationService.java:23`); `Result.toString()` redacts the bearer cookie (`AuthenticationService.java:225-227`) and the record rejects `authenticated`/cookie inconsistencies (`Result` validation, `AuthenticationService.java:217-224`).
7. **Secret zeroization.** Caller's `char[]` cleared in `finally` (`AuthenticationService.java:129`); derived bytes and salts zeroed after use (`PasswordVerifier.java:26-27, 37`); `PBEKeySpec.clearPassword()` in a `finally` (`PasswordVerifier.java:60`); token/digest/source buffers cleared (`AuthenticationService.java:130-132`). (See SEC-03 for the one pre-`try` path that bypasses this.)
8. **Log injection / PII resistance in the audit trail.** `AuthenticationEvent` enforces `[0-9a-f]{64}` digests for subject, source, and session keys (`AuthenticationEvent.java:17-19, 25`) — HMAC-SHA-256 pseudonyms with domain separation (`AuthenticationService.java:71-72, 183-193`) — and the sink serializes only bounded ASCII `key=value` fields whose values are UUIDs, instants, enums, or those digests, so raw usernames, IPs, tokens, and newline injection cannot reach the log (`PrivateRollingFileAuditSink.java:51-65, 93-99`).
9. **Audit file and directory hardening.** Constructor requires an absolute, non-symlinked, real directory with permissions exactly `0700` (`PrivateRollingFileAuditSink.java:28-48`, check at `:36`); every append/rotation re-verifies the file is a regular, non-symlink file with permissions exactly `0600` (`ensureFile` `:67-75`, check at `:70`; `rotate` `:78-91`, check at `:84`); writes open with `NOFOLLOW_LINKS`, take an exclusive `FileChannel.lock()`, and `force(true)` (durable-or-throw per the `AuditSink` contract) (`:51-65`). The `ensureFile()`-vs-open race is mitigated because the open itself refuses to follow symlinks.
10. **Fail-closed clock handling.** `safeNow()` maps clock exceptions or out-of-range (pre-2020/post-2200) times to `Instant.EPOCH` (`AuthenticationService.java:175-181`); a session then expires at `EPOCH + TTL` (1970s), which `InMemorySessionStore.create` — comparing against its own clock — rejects via `!expiresAt.isAfter(now)` (`InMemorySessionStore.java:27`), so a broken clock cannot mint long-lived sessions.
11. **Fail-closed audit coupling.** If the audit append fails on the success path, the freshly created session is revoked and a generic failure is returned — no session is issued without its durable audit record (`AuthenticationService.java:113-118`); failure-path audit errors also never turn into successes (`logFailure` swallows and fails closed).
12. **No hardcoded secrets.** A full manual sweep (gitleaks-equivalent) of all sources, tests, and `pom.xml` found no credentials, keys, or tokens. The only secret-shaped string is `INVALID_PASSWORD = "invalid-input-placeholder"` (`AuthenticationService.java:26`), a dummy KDF input used only via `.clone()` (`:89`) so the shared array is never mutated by verification-time zeroization — not a credential.
13. **Anti-lockout counter design.** `recordSuccess` clears only the account counter and deliberately never the source counter, so an attacker cannot reset its own per-IP limit by logging into an account it controls (`InMemoryLoginRateLimiter.java:49-53`). (The separate enforcement gap is SEC-01.)
14. **Input validation at boundaries.** Username regex `[a-z0-9][a-z0-9._@-]{0,63}` with lowercase canonicalization (`AuthenticationService.java:24, 135-140`); password length 1–128 with NUL and surrogate rejection (`PasswordVerifier.java:41-49`); limiter keys must be 64-hex digests before any map access (`InMemoryLoginRateLimiter.java:80-83`); account ids constrained by `CredentialStore.AuthenticatedPrincipal` and re-validated in `InMemorySessionStore.create` (`:22-31`). No injection or traversal sink was found in any file.
15. **Server-side source binding (no XFF trust).** `authenticate()` takes the source as a `java.net.InetAddress` and its contract states "Source must be the socket peer, not a header" (`AuthenticationService.java:65, 207-215`), eliminating the `X-Forwarded-For` spoofing bypass from the rate-limiting-bypass catalogue at this layer.
16. **Fixed-window boundary burst (accepted design).** As documented in the class Javadoc (`InMemoryLoginRateLimiter.java:8-11`) the limiter is a fixed window (`expired()` at `:80`), which admits up to ~2× `perSource` attempts straddling a window boundary — a known property of the chosen design (flagged as a pitfall by `implementing-api-rate-limiting-and-throttling`), not a deviation from stated intent, and moot until SEC-01's enforcement gap is fixed. Noted, not filed.
