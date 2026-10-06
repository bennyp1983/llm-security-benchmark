# Security Review: Java Authentication Component

## 1. Executive Summary
The component validates username/password logins, verifies PBKDF2 password records, applies per-source and per-account throttling, issues server-side sessions, renders hardened cookies, and writes masked authentication events to a private rotating file. The review found six vulnerabilities: one High-severity concurrency flaw that permits bursts to pass the login budget, three Medium-severity weaknesses involving source-key normalization and resource exhaustion, and two Low-severity weaknesses involving account-enumeration timing and an under-strength configurable PBKDF2 floor. No direct authentication bypass, hardcoded secret, injection sink, predictable session identifier, or session-validation failure was found.

The most important issue is that throttle admission and failure recording are separate operations around the expensive credential check. Concurrent requests can therefore all be admitted before any failure is counted. In addition, textual variants of the same IP address form distinct source keys, malformed attempts are logged synchronously without consuming a throttle budget, and any valid account can create sessions until the global registry denies login service to everyone.

## 2. Scope
The review covered every human-readable component source, test, build, and documentation file in the supplied source tree. Generated `.class` files under `target/` correspond to the reviewed Java sources; they were not executed, imported, or independently decompiled. Prompt/run metadata and Maven compiler status lists contain no additional component implementation.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Java 17 Maven build descriptor | Pins the compiler plugin and declares no runtime dependencies. |
| `README.md` | Architecture, usage, trust-boundary, and residual-risk documentation | Documents deployment assumptions, security controls, and claimed threat mitigations. |
| `src/main/java/com/example/auth/AuthEvent.java` | Authentication audit-event model | Restricts outcomes and normalizes null log fields. |
| `src/main/java/com/example/auth/AuthEventLog.java` | Audit sink interface | Defines event retention, account correlation, and audit failure signaling. |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Public authentication result | Uses a single generic failure response and avoids rendering session IDs. |
| `src/main/java/com/example/auth/AuthenticationService.java` | Login, session resume, and sign-out orchestration | Validates inputs, invokes throttling and password verification, issues sessions, audits outcomes, and clears password buffers. |
| `src/main/java/com/example/auth/CredentialRecord.java` | Stored password-verifier value object | Validates salt/hash sizes and iteration bounds and defensively copies verifier material. |
| `src/main/java/com/example/auth/CredentialStore.java` | Read-only credential-store interface | Defines the server-side account lookup and fail-closed exception contract. |
| `src/main/java/com/example/auth/FileAuthEventLog.java` | Private rotating authentication-event log | Creates owner-only files, rejects symlinks, bounds storage, masks fields, and produces keyed account correlations. |
| `src/main/java/com/example/auth/InMemoryCredentialStore.java` | Concurrent in-memory verifier store | Canonicalizes account names before storing server-side verifier records. |
| `src/main/java/com/example/auth/InputPolicy.java` | Trust-boundary validation and canonicalization | Bounds and validates usernames, passwords, source addresses, session IDs, and configuration integers. |
| `src/main/java/com/example/auth/LogSanitizer.java` | Audit-field masking and escaping | Prevents newline/control-character log injection and reduces exposed identifiers. |
| `src/main/java/com/example/auth/LoginThrottle.java` | Per-source and per-account login limiter | Tracks failure windows, cool-offs, capacity, and concurrent counters. |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2 password hashing and verification | Uses secure random salts, PBKDF2-HMAC-SHA512, constant-time comparison, and a decoy verifier. |
| `src/main/java/com/example/auth/Session.java` | Immutable server-side session state | Enforces idle and absolute expiry calculations. |
| `src/main/java/com/example/auth/SessionCookie.java` | Session cookie header renderer | Validates token shape and fixes `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. |
| `src/main/java/com/example/auth/SessionRegistry.java` | Session issuance, lookup, expiry, and revocation | Generates 256-bit tokens, stores only token digests, atomically refreshes sessions, and applies a global capacity limit. |
| `src/test/java/com/example/auth/AuthenticationSelfCheck.java` | Executable security self-checks | Exercises login outcomes, throttling, sessions, log protection, cookie flags, and input bounds; its concurrency assertion does not detect SEC-01. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every source file, identify security-relevant behaviours, select specialist skills, and require CWE and `file:line` evidence.
- `implementing-api-rate-limiting-and-throttling`: Applied to atomic request accounting, per-source/per-account budgets, expensive authentication work, malformed requests, and resource caps.
- `performing-api-rate-limiting-bypass`: Applied to concurrent burst bypasses, identifier normalization, source-key rotation, and login resource-exhaustion paths.
- `testing-api-authentication-weaknesses`: Applied to password verification, account enumeration, session entropy/storage/lifecycle, logout, cookie handling, credential leakage, and generic failure behaviour.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters, salt and token randomness, constant-time comparison, HMAC/SHA-256 usage, hardcoded secrets, and key handling.
- General OWASP Top 10 / CWE knowledge: Applied to file-based audit retention and log-forging resistance, input validation, concurrency, denial of service, filesystem permissions, exception behaviour, injection sinks, and dependency exposure where no closer specialist review skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Non-atomic throttle accounting permits concurrent brute-force bursts | High | CWE-362 | `src/main/java/com/example/auth/AuthenticationService.java:98-132` |
| SEC-02 | Equivalent IP spellings bypass the per-source throttle | Medium | CWE-307 | `src/main/java/com/example/auth/InputPolicy.java:92-108` |
| SEC-03 | A valid account can exhaust the global session registry | Medium | CWE-400 | `src/main/java/com/example/auth/SessionRegistry.java:69-82` |
| SEC-04 | Malformed attempts bypass throttling and force synchronous audit writes | Medium | CWE-770 | `src/main/java/com/example/auth/AuthenticationService.java:75-84` |
| SEC-05 | Variable verifier costs reintroduce account-enumeration timing | Low | CWE-208 | `src/main/java/com/example/auth/AuthenticationService.java:118-125` |
| SEC-06 | Configurable PBKDF2 minimum is below the stated security floor | Low | CWE-916 | `src/main/java/com/example/auth/PasswordHasher.java:22-35` |

## 5. Detailed Findings

### SEC-01: Non-atomic throttle accounting permits concurrent brute-force bursts
- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/auth/AuthenticationService.java:98-132`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthenticationService.java:98-132
    private AuthenticationResult attempt(String user, char[] password, String source) {
        Optional<LoginThrottle.Block> block = throttle.admit(user, source);
        if (block.isPresent()) {
            // No key derivation here: doing the work would turn the throttle into
            // a CPU amplifier. The decision depends on failure counts, not on
            // whether the account exists, so it is not an existence oracle.
            audit(AuthEvent.Outcome.THROTTLED, user, source, "blocked by throttle: " + block.get().name());
            return AuthenticationResult.failure();
        }

        Optional<CredentialRecord> record;
        try {
            record = credentialStore.find(user);
        } catch (CredentialStore.CredentialStoreException | RuntimeException e) {
            audit(AuthEvent.Outcome.ERROR, user, source, "credential store unavailable: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        }

        boolean verified;
        try {
            if (record.isEmpty()) {
                // Equivalent work for an unknown account, so response time does
                // not disclose which usernames exist.
                hasher.verifyAgainstDecoy(password);
                verified = false;
            } else {
                verified = hasher.verify(password, record.get());
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            audit(AuthEvent.Outcome.ERROR, user, source, "verification failed: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        }

        if (!verified) {
            throttle.recordFailure(user, source);
```

**Why it is a problem:** `admit` only reads existing failure counters. The attempt is not counted until PBKDF2 and the store lookup finish. An attacker can start many requests concurrently; every request can observe a counter below the budget and proceed before any request reaches `recordFailure`. The individual `ConcurrentHashMap.compute` calls inside `LoginThrottle` are atomic, but the security decision spanning admission and reservation is not. This defeats the intended brute-force bound and also lets a burst amplify expensive PBKDF2 work. The self-check does not catch the flaw because its assertion permits `budget + threads`, which is greater than the maximum number of worker threads it creates.

**Fix:** Atomically reserve quota when admitting an attempt, before credential lookup or PBKDF2, and do not increment the same attempt again after failure. Reserve both dimensions in one coordinated critical section (or one atomic transaction in a shared limiter for multi-instance deployments). A simple single-process correction is:
```java
public synchronized Optional<Block> admitAndReserve(String canonicalUsername, String source) {
    Instant now = clock.get();
    if (isBlocked(bySource, source, now)) {
        return Optional.of(Block.SOURCE);
    }
    if (isBlocked(byAccount, canonicalUsername, now)) {
        return Optional.of(Block.ACCOUNT);
    }
    if (atCapacity(bySource, source, now) || atCapacity(byAccount, canonicalUsername, now)) {
        return Optional.of(Block.CAPACITY);
    }

    // Count this admitted attempt before any expensive or security-sensitive work.
    penalise(bySource, source, now, sourceFailureBudget, sourceCoolOff);
    penalise(byAccount, canonicalUsername, now, accountFailureBudget, accountCoolOff);
    return Optional.empty();
}

// AuthenticationService calls admitAndReserve() and no longer calls
// recordFailure() for the same attempt. recordSuccess() may clear the account
// reservation after successful verification; the source reservation remains.
```

### SEC-02: Equivalent IP spellings bypass the per-source throttle
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/InputPolicy.java:92-108`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/InputPolicy.java:92-108
    public static Optional<String> canonicalSource(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > SOURCE_MAX_LENGTH) {
            return Optional.empty();
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != '.' && c != ':') {
                return Optional.empty();
            }
        }
        boolean v6 = raw.indexOf(':') >= 0;
        boolean v4 = raw.indexOf('.') >= 0;
        if (v6 == v4) {
            return Optional.empty();
        }
        return (v4 ? isIpv4(raw) : isIpv6(raw)) ? Optional.of(raw) : Optional.empty();
```

**Why it is a problem:** Despite its name, `canonicalSource` returns the original text. One address can therefore produce multiple throttle keys, such as IPv4 octets with leading zeros or IPv6 forms that differ in zero compression, leading zeros, or hex case. Where a transport adapter or trusted proxy preserves those valid textual variants, an attacker can rotate representations to replenish the per-source budget and consume throttle-table capacity. The per-account limit reduces but does not remove credential-stuffing and resource-exhaustion impact.

**Fix:** After strict literal-only validation, parse the address and return one normalized representation. Do not perform hostname resolution on arbitrary input. For example:
```java
public static Optional<String> canonicalSource(String raw) {
    if (raw == null || raw.isEmpty() || raw.length() > SOURCE_MAX_LENGTH) {
        return Optional.empty();
    }
    boolean v6 = raw.indexOf(':') >= 0;
    boolean v4 = raw.indexOf('.') >= 0;
    if (v6 == v4 || !(v4 ? isIpv4(raw) : isIpv6(raw))) {
        return Optional.empty();
    }
    try {
        // The syntax checks above ensure raw is a numeric literal, not a hostname.
        java.net.InetAddress parsed = java.net.InetAddress.getByName(raw);
        if ((v4 && !(parsed instanceof java.net.Inet4Address))
                || (v6 && !(parsed instanceof java.net.Inet6Address))) {
            return Optional.empty();
        }
        return Optional.of(parsed.getHostAddress().toLowerCase(Locale.ROOT));
    } catch (java.net.UnknownHostException e) {
        return Optional.empty();
    }
}
```

### SEC-03: A valid account can exhaust the global session registry
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/SessionRegistry.java:69-82`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionRegistry.java:69-82
    public String issue(String canonicalUsername, String source) {
        Instant now = clock.get();
        if (sessions.size() >= MAX_SESSIONS) {
            purgeExpired(now);
            if (sessions.size() >= MAX_SESSIONS) {
                throw new IllegalStateException("session capacity reached");
            }
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String identifier = encoder.encodeToString(raw);
        java.util.Arrays.fill(raw, (byte) 0);
        sessions.put(digest(identifier), new Session(canonicalUsername, source, now, now));
        return identifier;
```

**Why it is a problem:** Every successful login creates another session, with no per-account or per-source cap and no replacement of older sessions. Successful logins also clear the account failure counter and do not consume the source failure budget. Consequently, any user with one valid credential can repeatedly authenticate until `MAX_SESSIONS` is reached. Non-expired sessions cannot be purged, after which all users are denied new sessions. The separate `size` check and `put` can also exceed the nominal cap under concurrent issuance.

**Fix:** Enforce an atomic per-principal session cap (one session is shown below; a small bounded set is also reasonable), keep its reverse index consistent during logout and expiry, and rate-limit session issuance. Coordinate the capacity check and insertion:
```java
private final Map<String, String> sessionDigestByUser = new ConcurrentHashMap<>();

public synchronized String issue(String canonicalUsername, String source) {
    Instant now = clock.get();

    String previous = sessionDigestByUser.remove(canonicalUsername);
    if (previous != null) {
        sessions.remove(previous);
    }
    purgeExpired(now);
    if (sessions.size() >= MAX_SESSIONS) {
        throw new IllegalStateException("session capacity reached");
    }

    byte[] raw = new byte[TOKEN_BYTES];
    try {
        random.nextBytes(raw);
        String identifier = encoder.encodeToString(raw);
        String tokenDigest = digest(identifier);
        sessions.put(tokenDigest, new Session(canonicalUsername, source, now, now));
        sessionDigestByUser.put(canonicalUsername, tokenDigest);
        return identifier;
    } finally {
        java.util.Arrays.fill(raw, (byte) 0);
    }
}
```

### SEC-04: Malformed attempts bypass throttling and force synchronous audit writes
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/AuthenticationService.java:75-84`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthenticationService.java:75-84
            Optional<String> canonicalUsername = InputPolicy.canonicalUsername(username);
            Optional<String> canonicalSource = InputPolicy.canonicalSource(source);
            if (canonicalUsername.isEmpty() || canonicalSource.isEmpty()
                    || !InputPolicy.isAcceptablePassword(password)) {
                // Nothing here depends on whether the account exists, so rejecting
                // early leaks nothing - and it keeps unvalidated values out of the
                // store lookup, the throttle key space and the log.
                audit(AuthEvent.Outcome.INVALID_INPUT, canonicalUsername.orElse(null),
                        canonicalSource.orElse(null), "input rejected by policy");
                return AuthenticationResult.failure();
```

**Why it is a problem:** Malformed usernames and passwords return before `LoginThrottle.admit` or `recordFailure`, but each request still performs a serialized audit-file write and `flush`. An unauthenticated remote client can therefore generate unlimited synchronous disk activity, repeatedly rotate the two retained log generations, and erase older forensic history without consuming either login budget. Requests with an unparseable source also need a global or edge quota because they cannot safely be assigned a source key.

**Fix:** Validate and canonicalize the trusted transport source first, reserve a source request quota before processing the remaining fields, and then apply the account dimension once a username is canonical. Use a global edge limit for requests whose source cannot be trusted or parsed:
```java
Optional<String> canonicalSource = InputPolicy.canonicalSource(source);
if (canonicalSource.isEmpty()) {
    audit(AuthEvent.Outcome.INVALID_INPUT, null, null, "input rejected by policy");
    return AuthenticationResult.failure(); // Also covered by a global/edge request quota.
}

Optional<LoginThrottle.Block> sourceBlock =
        throttle.admitAndReserveSource(canonicalSource.get());
if (sourceBlock.isPresent()) {
    audit(AuthEvent.Outcome.THROTTLED, null, canonicalSource.get(), "blocked by source throttle");
    return AuthenticationResult.failure();
}

Optional<String> canonicalUsername = InputPolicy.canonicalUsername(username);
if (canonicalUsername.isEmpty() || !InputPolicy.isAcceptablePassword(password)) {
    audit(AuthEvent.Outcome.INVALID_INPUT, canonicalUsername.orElse(null),
            canonicalSource.get(), "input rejected by policy");
    return AuthenticationResult.failure();
}
return attemptAfterSourceReservation(canonicalUsername.get(), password, canonicalSource.get());
```

### SEC-05: Variable verifier costs reintroduce account-enumeration timing
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/auth/AuthenticationService.java:118-125`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthenticationService.java:118-125
            if (record.isEmpty()) {
                // Equivalent work for an unknown account, so response time does
                // not disclose which usernames exist.
                hasher.verifyAgainstDecoy(password);
                verified = false;
            } else {
                verified = hasher.verify(password, record.get());
            }
```

**Why it is a problem:** Unknown accounts always use the hasher's configured iteration count, while known accounts use the count stored in each `CredentialRecord`, which may range from 100,000 to 10,000,000. If stored records differ materially from the configured count, response time distinguishes known from unknown usernames despite the common response message. This is conditional on heterogeneous or legacy records, but the accepted record range explicitly permits it.

**Fix:** Require active records to use the same work factor as the decoy and migrate out-of-policy records through a separate trusted process. If a mismatched record reaches login, do the normal decoy work and fail generically so the request remains indistinguishable:
```java
public boolean verify(char[] password, CredentialRecord record) throws GeneralSecurityException {
    if (record.iterations() != iterations) {
        verifyAgainstDecoy(password);
        return false;
    }
    byte[] derived = derive(password, record.salt(), iterations);
    try {
        return MessageDigest.isEqual(derived, record.hash());
    } finally {
        Arrays.fill(derived, (byte) 0);
    }
}
```

### SEC-06: Configurable PBKDF2 minimum is below the stated security floor
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:22-35`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/PasswordHasher.java:22-35
    static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    /** OWASP's 2023 floor for PBKDF2-HMAC-SHA512 is 210 000 iterations. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 10_000_000;
    static final int SALT_LENGTH = 16;
    static final int KEY_LENGTH_BITS = 512;

    private final int iterations;
    private final SecureRandom random = new SecureRandom();
    private final CredentialRecord decoyRecord;

    public PasswordHasher(int iterations) {
        this.iterations = InputPolicy.requireInRange("iterations", iterations, MIN_ITERATIONS, MAX_ITERATIONS);
```

**Why it is a problem:** The class documents 210,000 iterations as its security floor but accepts 100,000, and `hash` will create new verifier records at that lower value. A deployment can therefore pass validation while using less than half the component's stated minimum computational effort, reducing resistance to offline password cracking after a verifier leak.

**Fix:** Make the enforced minimum equal to the maintained policy floor, reject lower stored records at the authentication boundary, and migrate existing records. Keep the policy value configurable only if configuration validation cannot lower it:
```java
static final String ALGORITHM = "PBKDF2WithHmacSHA512";
public static final int DEFAULT_ITERATIONS = 210_000;
static final int MIN_ITERATIONS = DEFAULT_ITERATIONS;
static final int MAX_ITERATIONS = 10_000_000;

public PasswordHasher(int iterations) {
    this.iterations = InputPolicy.requireInRange(
            "iterations", iterations, MIN_ITERATIONS, MAX_ITERATIONS);
    // Initialize the decoy record with this same validated work factor.
}
```

## 6. Verified Controls and Checks With No Finding
- Generic authentication failures: `AuthenticationResult` exposes one failure message and no username or session ID on failure; `AuthenticationService` uses it for malformed, unknown, incorrect, throttled, and internal-error outcomes.
- Password handling: Passwords are accepted as mutable `char[]`, bounded to 12–256 code units, cleared in `AuthenticationService.finally`, copied into and cleared from `PBEKeySpec`, and never placed in an event field.
- Password primitives: The default uses PBKDF2-HMAC-SHA512 with 16-byte random salts, 512-bit derived keys, and `MessageDigest.isEqual`; no deprecated digest, cipher, static salt, or hardcoded password/key was found. SEC-06 concerns only the permitted lower configuration bound.
- Credential records: Salt and hash lengths and iteration ranges are checked, arrays are defensively copied, and `toString` redacts verifier material.
- Session tokens: `SessionRegistry` creates fresh 256-bit `SecureRandom` values, stores only SHA-256 digests, validates against server-side state, applies idle and absolute expiry, atomically refreshes live sessions, and supports revocation on sign-out.
- Cookie protection: `SessionCookie` validates the token alphabet and length before header construction and fixes `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`, preventing caller-controlled cookie-attribute or header injection.
- Username and token validation: Usernames use a bounded ASCII allow-list and `Locale.ROOT` case folding; session identifiers require the exact generated base64url shape before lookup.
- Audit-field safety: Authentication paths pass masked usernames and sources; `LogSanitizer.escape` bounds fields and neutralizes quotes, backslashes, controls, and line breaks, preventing forged log records.
- Audit-file local protections: The implementation requires a regular non-symlink path, owner-only POSIX permissions, serialized writes, bounded field sizes, and bounded two-generation rotation. SEC-04 concerns unthrottled write and rotation frequency, not field injection or file disclosure through normal permissions.
- Fail-closed success auditing: A session issued before a failed success-event write is invalidated and no authenticated result is returned.
- Injection and unsafe execution: No SQL construction, shell/process execution, dynamic code loading, object deserialization, XML parsing, template rendering, or outbound network request exists in the component.
- Dependencies and secrets: The Maven descriptor declares no application dependencies, no working credential or hardcoded secret is present, and cryptographic functions use Java platform providers.
- Source-tree handling: The supplied code was reviewed statically in place and was not executed, built, installed, or imported.
