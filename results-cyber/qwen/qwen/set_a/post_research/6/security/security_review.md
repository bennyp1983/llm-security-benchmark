# Security Review: com.example.auth sign-in and audit component

## 1. Executive Summary

This review covers the 25 Java 17 source files of `com.example.auth`, a JDK-only username/password sign-in service with an append-only audit log. The code is unusually defensive for its size: constant-time digest comparison, a server-side pepper (keyed HMAC over PBKDF2 output), uniform-denial timing with decoy derivations, dual throttling that cannot be extended by probing, fail-closed audit persistence, fail-closed POSIX file-mode checks, and cross-validated configuration bounds. Most suspicious-looking spots were traced to deliberate, correctly implemented mitigations, and §6 lists what was checked and found sound.

Three defects were confirmed, none High-severity:

- **SEC-01 (Medium, CWE-400)** — `SessionTokenStore.isValid()` runs a full-table expiry sweep on *every* session validation while holding the store's monitor. The method's own javadoc claims the shape pre-check keeps the sweep away from attacker traffic, but the check accepts any 32-character lower-case hex string, which an unauthenticated caller can generate trivially. Repeated cheap probes therefore cost O(active sessions) — up to the configured cap of 100 000 — and serialize every other session operation behind the same lock. The sweep is not needed for correctness (validity re-checks expiry anyway), which makes it cheap to fix.
- **SEC-02 (Low, CWE-916)** — stored credential records may carry a KDF work factor as low as 10 000 iterations (default acceptance floor 50 000) while the policy floor for fresh hashes is 120 000, and there is no upgrade-on-login path, so legacy accounts remain 2.4×–12× weaker against offline cracking indefinitely.
- **SEC-03 (Informational, CWE-1188)** — throttle bucket fields default `lastTouchedMillis` to `System.currentTimeMillis()` even though the sweep's javadoc explicitly warns that mixing the wall clock with the injected clock deletes lockout state. The value is always overwritten before the bucket becomes visible, so it is latent today, but it sits one refactor away from silently disabling both throttles.

The component's README advertises eight security rules and "800 checks, zero failures." Every rule was independently checked against the implementation; none was found violated outright. SEC-01 is the one place where the implementation contradicts its own documented threat model: it names the exact attack (turning the expiry sweep into cost scaled by the session cap) and then gates it with a filter that provides no protection.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthenticationService.java` | Facade orchestrating `authenticate()` and wiring via builder | Attempt-ordering policy, uniform-denial paths, decoy derivation on unknown users, session issue/revoke in `finally`, RNG choice for session tokens, secret wiping |
| `CredentialVerifier.java` | Concurrency-capped digest verification | FIFO semaphore (fairness), decoy derivation for unknown accounts, latency floor padding, digest length validation |
| `AttemptThrottle.java` | Per-source sliding-window limiter + per-account lockout | Key-count caps, idle-bucket eviction sweeps, no lockout extension while blocked, fail-closed on overflow, injected-clock invariant |
| `InputValidator.java` | Validation/normalisation of source address, username, password | Strict IP literal parsing (no hostname resolution path), homoglyph non-folding username charset rules, control-char and surrogate checks, collision-free password encoding |
| `PasswordHasher.java` | Peppered PBKDF2-HMAC-SHA-256 → HMAC-SHA-256(pepper, salt‖DK) | 16-byte salt, 256-bit key, per-record iteration ceiling, canonical Base64 round-trip checks, key-material clearing |
| `FileCredentialStore.java` | Loads the account file at startup | Strict 4-field grammar, iteration bounds vs config, duplicate/case-collision refusal, any problem ⇒ refuse to start |
| `SessionTokenStore.java` | Server-side opaque session table | 128-bit token generation, sliding TTL, expiry sweep call sites, capacity eviction, cookie directive generation (fail-closed `Secure`), single global monitor |
| `AuthConfig.java` | Configuration parsing and policy | Hard floors (120 000 PBKDF2 iterations), acceptance floor for stored records, cross-field rules, unknown-key rejection, keystore-password hygiene, filesystem validation |
| `AuditLogger.java` | Append-only audit log | Torn-tail repair, file identity/owner-mode re-validation per write, fsync before counters, fail-closed on write failure, `renderOrReject` line grammar (log-injection defence), account-ID redaction |
| `AuthEvent.java` | Immutable audit event record | Carries only redacted/non-secret fields |
| `EventType.java` | Enum of auditable event kinds | Defines what is recorded |
| `AuthOutcome.java` | Enum of terminal outcomes | Uniform denial vocabulary |
| `AuthResult.java` | Result object returned to callers | Withholds retry/lock detail that would aid enumeration |
| `Diagnostic.java` | Enum of non-sensitive diagnostic codes | Distinguishes operator-facing causes without leaking account existence |
| `AuthException.java` | Sign-failure exception | Carries no credential material |
| `AuditPersistenceException.java` | Audit-write failure signal | Drives fail-closed session revocation |
| `InvalidConfigException.java` | Configuration failure signal | Fail-fast at startup |
| `AccountCredentials.java` | Immutable credential holder | `toString()` omits salt and digest; no serialisation |
| `AccountField.java` | Typed account-field names for events | Constrains what field labels can appear in audit lines |
| `CredentialStore.java` | Store interface | Lookup by canonical name only |
| `KeystorePepperProvider.java` | Loads pepper `SecretKeyEntry` from JCEKS/PKCS12/JKS | Keystore file-mode checks, length/charset validation of the pepper, password-char handling |
| `LatencyBudget.java` | Measured uniform-latency floor | Padding target used by verifier and service |
| `PosixMode.java` | POSIX permission checks | Owner-only requirement, fail-closed on attribute errors |
| `TimeSource.java` | Injectable clock abstraction | Single-clock invariant for throttle/session decisions |
| `ConfigSource.java` | Config key source abstraction | Bounds where configuration values enter |

Out of scope: `README.md`, `SECURITY.md`, prompt/result notes, `build-logs/`, `tools/mutation-*.sh`, compiled classes under `out/`, and `src/test/` (including `FixtureProvisioner`, which handles test-only keys). All code was reviewed statically by reading; nothing was built, executed, or imported.

## 3. Skills Applied

- **performing-cryptographic-audit-of-application** — drove the primitive/KDF audit: PBKDF2-HMAC-SHA-256 parameters and floors, keyed-HMAC pepper construction, salt generation and length, constant-time comparison, `SecureRandom` usage, canonical Base64 decoding, and key-material lifecycle (pepper zeroing, `PBEKeySpec` clearing, config `eraseSecrets()`, password-array wiping in `finally`). Anchored SEC-02.
- **testing-api-authentication-weaknesses** — drove the credential-check, token-entropy, and session-management review: 128-bit hex session ids, presence-only validity, sliding TTL, capacity eviction math, revoke-on-failure in `finally`, cookie attribute generation, and uniform-denial/anti-enumeration behaviour. Anchored SEC-01.
- **implementing-api-rate-limiting-and-throttling** — drove review of the dual throttle: sliding-window semantics, pre-credential consumption, per-account consecutive-failure lockout, the no-extend-while-blocked rule, key-count caps with idle eviction, and fail-closed `blockedForever` behaviour. Anchored SEC-03.
- **testing-for-sensitive-data-exposure** — drove review of secret handling at rest and in logs: keystore file-mode guards, absence of hardcoded secrets in main sources, `toString()` hygiene, audit redaction (`sha256(lowercased name)`, an unkeyed hash whose residual risk the code itself documents), and secret wiping after startup.

Additional areas reviewed against **general OWASP/CWE knowledge only**, with no matching skill in the library: denial-of-service via data-structure cost on an unauthenticated path (SEC-01's class of bug), POSIX file-permission hardening, audit-log line-grammar injection resistance, and the single-clock consistency invariant of the throttle sweeps. Four further skills surfaced during discovery (`testing-api-security-with-owasp-top-10`, `testing-for-business-logic-vulnerabilities`, `implementing-secrets-management-with-vault`, `implementing-api-rate-limiting-and-throttling`'s Redis/gateway playbook) are dynamic-testing or infrastructure-deployment playbooks that do not apply to a static, JDK-only in-process library and were not applied.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unauthenticated probes force a full session-table sweep under the store lock on every validation | Medium | CWE-400 | `SessionTokenStore.java:104` |
| SEC-02 | Stored KDF work factor accepted far below the policy floor, with no upgrade path | Low | CWE-916 | `AuthConfig.java:624` |
| SEC-03 | Throttle buckets default their last-touch time to the wall clock, contradicting the sweep's single-clock invariant | Informational | CWE-1188 | `AttemptThrottle.java:350` |

## 5. Detailed Findings

### SEC-01: Unauthenticated probes force a full session-table sweep under the store lock on every validation

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SessionTokenStore.java:104`

**Vulnerable code:**

```java
// SessionTokenStore.java:93-109
    /**
     * Validates an identifier and slides its expiry on success. Validity is presence in this table
     * and nothing else.
     *
     * <p>The shape check runs <em>first</em>, outside the lock. Everything a caller can send arrives
     * unauthenticated, and a table scan on the far side of that check would let anyone holding a
     * keyboard convert the expiry sweep into a cost that scales with the deployment's session cap
     * (100&nbsp;000 entries) rather than with the traffic they can actually generate. The sweep is
     * therefore reached only by a string that is already the right shape - i.e. one that is far more
     * likely to be a real identifier than an attacker's first probe.
     */
    synchronized boolean isValid(String candidate) {
        if (candidate == null || candidate.length() != TOKEN_HEX_LENGTH || !isHex(candidate)) {
            return false;
        }
        long now = time.nowMillis();
        dropExpiredLocked(now);

// SessionTokenStore.java:259-266
    private void dropExpiredLocked(long now) {
        Iterator<Map.Entry<String, Long>> it = expiresAtMillis.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() <= now) {
                it.remove();
            }
        }
    }
```

**Why it is a problem:**

The javadoc's own threat statement is correct — a table scan reachable from unauthenticated traffic lets "anyone holding a keyboard" impose cost scaled by the session cap — but the defence it describes does not exist. The shape pre-check accepts *any* 32-character lower-case hexadecimal string, which is trivially generated (`openssl rand -hex 16`); the claim that a well-shaped string is "far more likely to be a real identifier than an attacker's first probe" is simply false, so the check gates nothing. Every validation therefore iterates the entire `LinkedHashMap` while holding the store's single monitor. At the configured default (`maxActiveSessions` 10 000; ceiling 100 000 per `AuthConfig` bounds), each unauthenticated probe costs up to 100 000 map iterations, and because `isValid`, `issue`, and `revoke` are all `synchronized` on the same monitor, a handful of concurrent probe streams serialise the whole sign-in path — real validations and new logins queue behind attacker-triggered scans. The throttle protects `authenticate()` but does not run on session-validation traffic, so there is nothing upstream limiting probe rate at this layer.

The sweep is also redundant for correctness in this call site: `isValid` re-checks `expiry <= now` after the sweep and returns `false` for expired entries anyway (`SessionTokenStore.java:113-115`), so validity is presence *and* unexpired timestamp regardless of whether the sweep ran. The sweep exists here only for memory reclamation, which `issue()` (line 80) and capacity eviction already provide — meaning the per-request full scan buys nothing the attacker isn't already paying for.

**Fix:**

Amortize the reclamation sweep by time instead of running it per validation. Correctness is unchanged because the post-sweep expiry check stays:

```java
// SessionTokenStore.java (patch)
    /** Bound on how often a validation pass may scan the whole table. */
    private static final long VALIDATE_SWEEP_INTERVAL_MILLIS = 1_000L;

    private long nextSweepMillis;

    synchronized boolean isValid(String candidate) {
        if (candidate == null || candidate.length() != TOKEN_HEX_LENGTH || !isHex(candidate)) {
            return false;
        }
        long now = time.nowMillis();
        if (now >= nextSweepMillis) {
            dropExpiredLocked(now);
            nextSweepMillis = now + VALIDATE_SWEEP_INTERVAL_MILLIS;
        }
        Long expiry = expiresAtMillis.get(candidate);
        if (expiry == null || expiry <= now) {
            return false;
        }
        expiresAtMillis.put(candidate, now + ttlSeconds * 1000L);
        return true;
    }
```

This keeps per-request cost at O(1) hash probe plus a per-`put` slide, and bounds sweep work to one scan per interval regardless of who is calling. (Alternative: drop the sweep from `isValid()` entirely and rely on the existing sweep in `issue()` plus capacity eviction, or maintain a TTL-ordered structure for O(log n) reclamation.) The misleading javadoc should be corrected either way — an invalid claimed mitigation is worse than none, because it discourages the reviewer from looking further.

### SEC-02: Stored KDF work factor accepted far below the policy floor, with no upgrade path

- **Severity:** Low
- **CWE:** CWE-916: Password Hash with Insufficient Computational Effort
- **Location:** `AuthConfig.java:624`

**Vulnerable code:**

```java
// AuthConfig.java:59-63
    public static final int MIN_PBKDF2_ITERATIONS = 120_000;

    private static final int MAX_ITERATIONS = 5_000_000;
    private static final int MIN_STORED_ITERATIONS = 10_000;
    private static final int MAX_STORED_ITERATIONS = 10_000_000;

// AuthConfig.java:623-624
        private int pbkdf2Iterations = MIN_PBKDF2_ITERATIONS;
        private int minAcceptedIterations = 50_000;

// AuthConfig.java:169
        int minAccepted = positiveInt(source, KEY_MIN_ACCEPTED_ITERATIONS, problems, MIN_STORED_ITERATIONS, MAX_STORED_ITERATIONS);

// FileCredentialStore.java:147
        if (iterations < config.minAcceptedIterations() || iterations > config.pbkdf2Iterations()) {
```

**Why it is a problem:**

Three different iteration floors coexist. Fresh hashes are forced to ≥ 120 000 iterations (`MIN_PBKDF2_ITERATIONS`, enforced in both `AuthConfig.java:164-167` and `build()` at :791). But stored records are accepted at the *minimum accepted* floor, whose built-in default is 50 000 (`AuthConfig.java:624`) and which an operator can configure down to 10 000 via `KEY_MIN_ACCEPTED_ITERATIONS` (`MIN_STORED_ITERATIONS`, :62; parse range at :169). The `build()` cross-check (:794) only requires `pbkdf2Iterations >= minAcceptedIterations`, so 120 000-with-accepting-10 000 is a valid configuration. `FileCredentialStore.java:147` then admits those records, and nothing in the sign-in flow re-derives or rewrites a record after a successful verification (the component treats the account file as read-only by design). Net effect: a legacy or misprovisioned account with 10 000 iterations stays valid forever while costing an attacker 12× less work to crack offline than the policy floor implies — the exact scenario the "absolute floor … so a misconfigured or deliberately weakened environment cannot turn credential hashing into a no-op" comment at :54-57 says the design defends against, but that floor governs only *fresh* hashing. The per-record upper-bound check (records cannot force extra work) is correctly handled; this is purely the lower bound.

Severity is Low because reaching the weakness requires an attacker to already have obtained the credential file (which is owner-only-mode enforced) or to be an operator choosing the weak floor — but once there, the gap is silent and permanent.

**Fix:**

Minimal: make the default acceptance floor equal the policy floor, so weak records block startup (consistent with the store's existing fail-closed behaviour) rather than being silently accepted:

```java
// AuthConfig.java (patch)
        private int pbkdf2Iterations = MIN_PBKDF2_ITERATIONS;
        private int minAcceptedIterations = MIN_PBKDF2_ITERATIONS;
```

and pin the configurable floor accordingly (`private static final int MIN_STORED_ITERATIONS = MIN_PBKDF2_ITERATIONS;`), keeping the lower value only as a named migration escape hatch that logs loudly. The durable fix is upgrade-on-login: after a successful `verifier.verify(...)`, re-derive with the current `pbkdf2Iterations` and atomically rewrite the record — this requires making the store writable, so it is a design change rather than a patch, but it is the only mitigation that lets the floor rise over time without a forced password reset.

### SEC-03: Throttle buckets default their last-touch time to the wall clock, contradicting the sweep's single-clock invariant

- **Severity:** Informational
- **CWE:** CWE-1188: Insecure Default Initialization of Resource
- **Location:** `AttemptThrottle.java:350`

**Vulnerable code:**

```java
// AttemptThrottle.java:256-263
    /**
     * Drops keys idle longer than the sweep horizon.
     *
     * <p>The clock passed in is the same one every verdict is computed from. Reading
     * {@link System#currentTimeMillis()} here instead would compare the injected timeline against
     * the wall clock: wherever the two differ - a test clock, or a deployment whose clock was stepped
     * after buckets were created - the sweep would see every bucket as idle and delete the lockout
     * state while authentication kept reporting healthy limits.
     */

// AttemptThrottle.java:346-361
    private static final class AccountBucket {

        private int consecutiveFailures;
        private long blockedUntilMillis;
        private long lastTouchedMillis = System.currentTimeMillis();

        private AccountBucket() {
        }
    }

    private static final class SourceBucket {

        private final ArrayDeque<Long> attempts = new ArrayDeque<>();
        private long blockedUntilMillis;
        private long lastTouchedMillis = System.currentTimeMillis();
```

**Why it is a problem:**

The sweep's javadoc states the invariant precisely — every bucket timestamp must come from the injected `TimeSource` clock, because mixing in `System.currentTimeMillis()` makes the sweep "see every bucket as idle and delete the lockout state while authentication kept reporting healthy limits" (i.e., both throttles silently stop working under a stepped clock or injected test clock). Yet both bucket classes violate the invariant *at construction*: their field initializers read the wall clock directly, exactly as the warning forbids. Today the defect is unobservable: every creation site is inside the same `ConcurrentHashMap.compute` lambda that publishes the bucket, and the touch sites immediately overwrite the field with the injected clock value (`bucket.lastTouchedMillis = nowMillis` at `AttemptThrottle.java:152` for sources and :211 for accounts) before any sweep can observe the bucket. It is therefore latent — but it is a live footgun: any new bucket creation path, or a refactor that moves initialization out of the compute lambda, reintroduces the precise failure mode the code documents, with no compiler or test barrier between the two states.

**Fix:**

Make the wall clock unreachable from the buckets by requiring the touch time at construction, so a bucket cannot exist without a correct-clock timestamp:

```java
// AttemptThrottle.java (patch)
    private static final class AccountBucket {

        private int consecutiveFailures;
        private long blockedUntilMillis;
        private long lastTouchedMillis;

        private AccountBucket(long nowMillis) {
            this.lastTouchedMillis = nowMillis;
        }
    }

    private static final class SourceBucket {

        private final ArrayDeque<Long> attempts = new ArrayDeque<>();
        private long blockedUntilMillis;
        private long lastTouchedMillis;

        private SourceBucket(long nowMillis) {
            this.lastTouchedMillis = nowMillis;
        }
    }
```

and change each creation site (inside the existing `compute` lambdas, which already hold `nowMillis`) to `new AccountBucket(nowMillis)` / `new SourceBucket(nowMillis)`.

## 6. Verified Controls and Checks With No Finding

The following were examined line-by-line and found correctly implemented (claim-vs-implementation, since the README asserts each as a security rule):

- **Credential comparison** — `MessageDigest.isEqual` over the full 32-byte digest in `CredentialVerifier`; unknown accounts run a decoy derivation of identical cost and the result is discarded; store-side digest length validated before comparison. No account-existence timing or response divergence.
- **Digest construction (pepper)** — `HMAC-SHA-256(pepper, salt ‖ PBKDF2-HMAC-SHA-256(pw, salt, c))`; 16-byte `SecureRandom` salt; 256-bit derived key; pepper loaded only as a keystore `SecretKeyEntry` (JCEKS/PKCS12/JKS) with file-mode and length checks, and zeroed after `Mac` initialization. No hardcoded secrets anywhere in main sources.
- **Per-record iteration cost** — records cannot order more work than policy (`FileCredentialStore.java:147` upper bound plus `PasswordHasher.derive`'s `saltIterations > maxSaltIterations` rejection at :107), closing the KDF-cost oracle/DoS through the account file.
- **Throttle semantics** — pre-credential per-source sliding window (probing cannot bypass it by varying usernames); per-account consecutive-failure lockout that probing cannot extend while blocked; `sourceMaxAttempts ≥ accountLockAfter` cross-check prevents one account burning a shared NAT's budget (`AuthConfig.java:797` ff.); key-count caps (20 000) with idle eviction and fail-closed `blockedForever` on pathological growth; sweep horizon sized above the longest lockout.
- **Session management** — 128-bit hex ids from a CSPRNG; validity is presence-only with sliding TTL; successful issue after lock trip resets the account; any session minted but not granted is revoked in the `finally` block (`AuthenticationService.java`); capacity eviction picks the soonest-expiring entry with a 1-second grace so fresh logins are not instantly evicted. Note (documentation mismatch, not a finding): the class javadoc at `SessionTokenStore.java:11-12` says ids come from `SecureRandom.getStrongInstance()`, while `AuthenticationService.java:533` deliberately uses `new SecureRandom()` with a documented rationale (the strong instance is `NativePRNGBlocking` and can block startup). Both are cryptographically strong CSPRNGs, so entropy is adequate; only the comment is wrong.
- **Audit log** — append-only with fsync before success counters; torn-tail repair bounded to one malformed trailing line; file identity (inode via `fileKey`), owner, and POSIX mode re-validated on every write, fail-closed; write failure revokes the just-issued session and raises `AuditPersistenceException` *without* charging the account's failure counter (so log-outage cannot lock users out) while still alerting; `renderOrReject` enforces the line grammar so unvalidated strings cannot forge or split audit lines; account names are never logged — only `sha256(lowercased name)`, an unkeyed hash the code itself labels as residual risk (dictionary-expandable for common names; acceptable given no salt/pepper is mixed in — flagged here rather than as a finding because the design accepts and documents it).
- **Input handling** — source addresses are strict IPv4/IPv6 *literals* only (leading-zero, CIDR, zone-id, userinfo, `%`/`@`, and hostname forms rejected by textual pre-check before `InetAddress.getByName`, so no name resolution or SSRF-adjacent DNS path exists); IPv4-mapped IPv6 unwrapped so one host cannot split its throttle bucket; usernames restricted to a non-folding ASCII+letter/digit set with positional first/last rules and `..` rejection (deliberate no-normalization design prevents homoglyph account collisions); passwords reject NUL/control/DEL and lone surrogates before length checks, and are encoded with a `REPORT`-mode `CharsetEncoder` so no two distinct inputs map to the same byte string.
- **Configuration** — unknown keys rejected; hard PBKDF2 floor of 120 000 for fresh hashing; keystore password rejects control characters and is erased after load (`eraseSecrets()`); account-file, event-log, and keystore paths validated owner-only (POSIX, fail-closed on attribute errors).
- **Uniformity/anti-enumeration** — `LatencyBudget` floor padding on every terminal path (`authenticate()` `finally` and each `verify`); identical denial result and diagnostic codes whether the account is unknown, locked-then-failed, or simply wrong-password; the "you are locked, retry in N" hint is withheld on the request that trips the lock to avoid a confirmation oracle.
- **Secret hygiene** — password `char[]`/UTF-8 copies wiped in `finally` on all paths; `AccountCredentials.toString()` omits salt/digest; no `Serializable` on credential types; builder wipes config secrets after wiring; pepper copy zeroed post-`Mac.init`; `PBEKeySpec` cleared after PBKDF2.
- **Concurrency** — throttle state mutated only inside `ConcurrentHashMap.compute` (per-key atomicity); session table operations under one monitor; verifier bounded by a fair FIFO `Semaphore` with release in `finally` and a 2-second acquire timeout that fails closed as `SECURITY_ALERT`, not as an authentication answer.
- **RNG usage** — all salts and session ids from one injected/constructed `SecureRandom`; no `java.util.Random`, `Math.random`, or time-seeded material anywhere in main sources; test seams (`Builder.secureRandom`, `TimeSource`) are explicit and default to production values.

Reviewed but excluded from scope by task framing: `src/test/**` (including `FixtureProvisioner`, which embeds test-only pepper keys — appropriate for fixtures, and not shipped in `src/main`), `tools/mutation-*.sh`, and compiled output under `out/`.
