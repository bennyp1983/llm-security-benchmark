# Security Review: Portal Authentication System (portal-auth)

## 1. Executive Summary
The target component under review is `portal-auth`, an authentication portal and administrative command-line interface implemented in Java without external runtime dependencies. The system provides HTTPS-based employee authentication, single-use double-submit CSRF protection, secure session management, flat-file credential storage with PBKDF2-HMAC-SHA256, constant-time comparisons, refusal-only security configurations, and per-account and per-source brute-force rate limiting with durable disk-backed tracking.

The security review identified six (6) distinct security vulnerabilities across the codebase:
- **SEC-01 (High):** An unbounded, monotonic latency padding ratchet in `ThrottleManager` that causes full CPU starvation and hangs the HTTP service when any single request experiences latency.
- **SEC-02 (High):** An unhandled capacity limit exception in `ThrottleManager` allowing unauthenticated attackers to trigger a complete denial of service across all users by querying arbitrary non-existent usernames.
- **SEC-03 (High):** Ineffective inter-process session revocation where administrative commands (`disable-user` and `set-password`) clear only transient CLI process state, leaving active sessions valid on the running HTTPS daemon.
- **SEC-04 (Medium):** Permanent accumulation of expired entries in `Ledger.persist` causing the durable rate-limiting ledger file to grow monotonically until hitting hard size limits, corrupting on-disk state.
- **SEC-05 (Medium):** Client IP attribution and throttling bypass via duplicate `X-Forwarded-For` header spoofing due to single-value header extraction.
- **SEC-06 (Low):** Cleartext retention of user passwords in heap memory resulting from immutable `String` conversions during HTTP form parsing.

A significant number of security controls were verified and found to be robustly designed, including cryptographic primitive selection (PBKDF2-HMAC-SHA256 with 150,000 iterations floor), constant-time comparisons, CSPRNG usage, strict POSIX filesystem permissions (0600/0700), anti-timing decoy hashing, and comprehensive HTTP security headers.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/portal/auth/Main.java` | Application entry point | Dispatches between CLI subcommands and the HTTPS listener; enforces fail-closed startup validation. |
| `src/main/java/com/portal/auth/PortalConfig.java` | System configuration loader | Loads and strictly validates configuration from environment variables, config files, and system properties; enforces path canonicalization and KDF minimums. |
| `src/main/java/com/portal/auth/PortalRuntime.java` | Runtime dependency wiring | Initializes and binds storage, throttling, sessions, authenticator, and audit logging into a single cohesive runtime. |
| `src/main/java/com/portal/auth/PrivateFiles.java` | Filesystem access abstraction | Enforces POSIX file permissions (`0600` files, `0700` directories), rejects symbolic links (`NOFOLLOW_LINKS`), performs atomic writes via fsync, and bounds read sizes. |
| `src/main/java/com/portal/auth/EmployeeStore.java` | Flat-file credential roster store | Loads and mutates `employees.dat` under exclusive `FileLock`; validates format strictness; auto-refreshes in-memory roster on inode/mtime changes. |
| `src/main/java/com/portal/auth/PasswordHasher.java` | Password derivation and verification | Computes PBKDF2-HMAC-SHA256 with iteration floors; implements decoy hashing on absent accounts or invalid inputs to prevent timing side channels. |
| `src/main/java/com/portal/auth/Crypto.java` | Cryptographic primitives wrapper | Thin wrapper for `SecureRandom`, `MessageDigest` SHA-256, constant-time `MessageDigest.isEqual`, strict Base64 encoding/decoding, and secret array wiping. |
| `src/main/java/com/portal/auth/InputPolicy.java` | Input validation boundary | Enforces strict character and length constraints on usernames, passwords, session tokens, and CSRF tokens; prevents Unicode folding attacks. |
| `src/main/java/com/portal/auth/SessionManager.java` | In-memory session and CSRF state | Generates and verifies 256-bit session tokens and 192-bit CSRF tokens; enforces idle (20m) and absolute (8h) timeouts; maintains bounded eviction maps. |
| `src/main/java/com/portal/auth/Authenticator.java` | Core authentication decision logic | Enforces the "one-digest invariant" (exactly one KDF or decoy calculation per attempt); coordinates throttling, roster lookup, and latency padding. |
| `src/main/java/com/portal/auth/ThrottleManager.java` | Dual-dimension rate limiting | Tracks failed attempts per account (5 failures, exponential back-off) and per source IP (30 failures, 8h block); provides latency floor padding. |
| `src/main/java/com/portal/auth/Ledger.java` | Durable throttle state persistence | Manages atomic read-modify-write merges of throttle counters to `throttle.log` with cross-process file locking and generation tracking. |
| `src/main/java/com/portal/auth/SourceRef.java` | Peer attribution and IP resolution | Resolves client IP literals from socket address and `X-Forwarded-For` using right-to-left traversal against trusted IPv4 CIDR proxies. |
| `src/main/java/com/portal/auth/PortalServer.java` | HTTPS HTTP handler | Implements HTTP request routing, CSRF verification, uniform 401 error responses, session cookie issuance (`SameSite=Strict; Secure; HttpOnly`), and security headers. |
| `src/main/java/com/portal/auth/CookieParser.java` | HTTP Cookie header parser | Parses `Cookie` header strictly by splitting on `;` and matching exact `name=value` tokens without leniency or case folding. |
| `src/main/java/com/portal/auth/HttpExchangeView.java` | HTTP exchange interface | Abstraction decoupler defining request and response operations for test doubles and listener implementations. |
| `src/main/java/com/portal/auth/JdkHttpsListener.java` | TLS server listener | Configures and runs JDK built-in `HttpsServer`; restricts protocols to TLSv1.2 and TLSv1.3; loads keystores securely from private files. |
| `src/main/java/com/portal/auth/AuditLog.java` | Security event logger | Appends tamper-resistant, redacted audit records to `audit.log` (mode `0600`) and an in-memory ring buffer; hashes sensitive identifiers. |
| `src/main/java/com/portal/auth/AuditClock.java` | Deterministic time abstraction | Wraps `java.time.Clock` with system UTC default and mock injection support for test suites. |
| `src/main/java/com/portal/auth/PortalCli.java` | Administrative command-line interface | Implements operator commands (`login`, `add-user`, `set-password`, `disable-user`, `status`, `version`); reads secrets via `Console.readPassword()`. |
| `build.sh` | Project build script | Compiles production Java sources using strict compiler flags (`-encoding US-ASCII -Xlint:all -Werror`). |
| `test.sh` | Test runner script | Compiles and executes adversarial regression and unit test suites. |
| `portal.cmd` | Windows batch launcher | Windows counterpart launcher script setting up Java classpath and options. |
| `tools/gen-cert.sh` | Certificate generation utility | Generates ECDSA secp384r1 self-signed TLS certificates and 0600 password files using `/dev/urandom`. |
| `tools/get-jdk.sh` | JDK download script | Downloads and cryptographically verifies OpenJDK 21 binary using Adoptium SHA-256 checksums. |
| `tools/mutate.py` | Mutation testing battery | Applies semantic security mutations across codebase to verify test suite detection sensitivity. |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to assess credential validation flows, timing enumeration resistance, session lifecycle handling, token generation, and account lockout mechanics in `Authenticator.java`, `SessionManager.java`, and `PortalServer.java`.
- `performing-cryptographic-audit-of-application`: Applied to audit PBKDF2-HMAC-SHA256 key derivation parameters, constant-time equality comparisons, random byte generation, Base64 canonicalization, and secret zeroization in `PasswordHasher.java` and `Crypto.java`.
- `implementing-api-rate-limiting-and-throttling`: Applied to evaluate rate limiting architecture, account and source counter tracking, back-off mechanisms, and durable counter storage in `ThrottleManager.java` and `Ledger.java`.
- `performing-api-rate-limiting-bypass`: Applied to assess potential bypasses of IP attribution and throttling via proxy headers, case-folding, path manipulation, and duplicate header pollution in `SourceRef.java` and `PortalServer.java`.
- `testing-for-broken-access-control`: Applied to assess authorization enforcement, administrative user disablement, password rotation, and multi-process access revocation in `EmployeeStore.java`, `PortalCli.java`, and `SessionManager.java`.
- `performing-csrf-attack-simulation`: Applied to verify CSRF token generation, double-submit cookie validation, token consumption, and SameSite cookie attributes in `PortalServer.java` and `SessionManager.java`.
- `performing-security-headers-audit`: Applied to audit HTTP response headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Cache-Control) in `PortalServer.java`.
- `configuring-tls-1-3-for-secure-communications`: Applied to verify TLS protocol restrictions (TLSv1.2, TLSv1.3), cipher suite configuration, and keystore security in `JdkHttpsListener.java` and `tools/gen-cert.sh`.
- General OWASP Top 10 / CWE knowledge (A04:2021 Insecure Design, A05:2021 Security Misconfiguration, CWE-400 / CWE-770 Resource Exhaustion, CWE-316 Cleartext Storage of Sensitive Information in Memory): Applied to audit file permission enforcement (`PrivateFiles.java`), memory safety during form parsing (`PortalServer.java`), and resource starvation / DoS vulnerabilities (`ThrottleManager.java`, `Ledger.java`).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unbounded Monotonic Latency Padding Ratchet Induces CPU Starvation and Service Hang | High | CWE-400 | `src/main/java/com/portal/auth/ThrottleManager.java:307-316` |
| SEC-02 | Authentication Denial of Service via Unbounded Throttle Subject Capacity Exhaustion | High | CWE-400 | `src/main/java/com/portal/auth/ThrottleManager.java:398-403` |
| SEC-03 | Ineffective Multi-Process Session Revocation for Administratively Disabled or Reset Accounts | High | CWE-613 | `src/main/java/com/portal/auth/PortalCli.java:238-241` |
| SEC-04 | Unbounded Monotonic On-Disk Throttle Ledger Growth Leading to State Corruption and DoS | Medium | CWE-770 | `src/main/java/com/portal/auth/Ledger.java:142-149` |
| SEC-05 | Client IP Attribution and Rate Limiting Bypass via Duplicate `X-Forwarded-For` Headers | Medium | CWE-290 | `src/main/java/com/portal/auth/PortalServer.java:336-339` |
| SEC-06 | Retention of Plaintext User Credentials in Heap Memory via Immutable String Conversions | Low | CWE-316 | `src/main/java/com/portal/auth/PortalServer.java:125-126` |

## 5. Detailed Findings

### SEC-01: Unbounded Monotonic Latency Padding Ratchet Induces CPU Starvation and Service Hang
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:307-316`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/ThrottleManager.java:307-316
    public void observeLatency(long nanos) {
        if (paddingSuppressed) {
            return;
        }
        synchronized (monitor) {
            if (nanos > latencyFloorNanos) {
                latencyFloorNanos = nanos;
            }
        }
    }
```

**Why it is a problem:**
In `ThrottleManager.java`, `observeLatency` is called after every authentication attempt (both granted and denied in `Authenticator.java` lines 236 and 249). The method tracks the maximum observed duration and assigns it to `latencyFloorNanos`. However, `latencyFloorNanos` is a monotonic ratchet that has no maximum upper ceiling and never decays over time.

In `padToFloor(long startedAtNanos)` (lines 286–304), any remaining time between the request's execution time and `latencyFloorNanos` is consumed using a busy-wait spin-loop:
```java
while (System.nanoTime() < deadline) {
    Thread.onSpinWait();
}
```
If an intermittent operational pause occurs—such as a JVM garbage collection stop-the-world pause, system thread scheduling contention, disk fsync latency while writing `throttle.log`, or slow I/O—a single request can easily take several seconds (e.g., 5–10 seconds). Once observed, `latencyFloorNanos` is permanently pinned to that duration.

Subsequently, every incoming authentication request on every worker thread will spin-wait on CPU for several seconds. Because the server allocates a small fixed thread pool (`Math.max(4, availableProcessors * 2)`), all worker threads immediately peg CPU cores at 100%, causing complete starvation of the thread pool. Furthermore, if `latencyFloorNanos` ratchets past `sun.net.httpserver.maxReqTime` (30 seconds), every subsequent request fails with an HTTP timeout, rendering the entire portal unusable.

**Fix:**
Enforce an upper sanity bound on `latencyFloorNanos` (e.g., 500 milliseconds) so that abnormal latency spikes cannot poison the floor. In addition, avoid pure busy-wait spin-loops for long durations by combining a brief spin with non-busy waiting or a capped adaptive decay.
```java
    public static final long MAX_LATENCY_FLOOR_NANOS = 500_000_000L; // 500ms ceiling

    public void observeLatency(long nanos) {
        if (paddingSuppressed) {
            return;
        }
        synchronized (monitor) {
            long clamped = Math.min(nanos, MAX_LATENCY_FLOOR_NANOS);
            if (clamped > latencyFloorNanos) {
                latencyFloorNanos = clamped;
            }
        }
    }
```

---

### SEC-02: Authentication Denial of Service via Unbounded Throttle Subject Capacity Exhaustion
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:398-403`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/ThrottleManager.java:398-403
            if (map.size() >= MAX_SUBJECTS) {
                sweep(map);
                if (map.size() >= MAX_SUBJECTS) {
                    throw new IllegalStateException("throttle-subject-capacity");
                }
            }
```

**Why it is a problem:**
When `Authenticator.authenticate` processes a login request, it calls `throttle.beginAttempt(accountRef, sourceHex)` before verifying whether the username exists in the roster (`EmployeeStore`). Inside `ThrottleManager.live`, any novel subject allocates a new `State` entry in `accounts`.

If `accounts.size()` reaches `MAX_SUBJECTS` (50,000), `live` calls `sweep(map)`:
```java
map.entrySet().removeIf(e -> now - e.getValue().windowStart > RETENTION_SECONDS
        && e.getValue().blockedUntil <= now);
```
Where `RETENTION_SECONDS` is 24 hours (86,400 seconds).

An unauthenticated remote attacker can easily submit 50,000 login requests with randomly generated valid usernames (e.g., `user00001`, `user00002`, ..., `user50000`). Because each username is distinct and well-formed, an entry is added to `accounts`. Because all entries were created within the last 24 hours, `sweep` cannot remove any entry. On the 50,001st request, line 401 throws `IllegalStateException("throttle-subject-capacity")`.

Because `Authenticator` does not catch this exception, it propagates to `PortalServer.handle`, where it is caught as an unexpected `RuntimeException`, causing the server to log a failure and respond with HTTP 500. From that point on, any login attempt for any user (including valid existing accounts not yet cached in `accounts`) triggers this unhandled exception and fails with HTTP 500, creating a persistent, complete denial of service.

**Fix:**
Instead of throwing a fatal `IllegalStateException` that terminates request processing, evict the oldest unblocked subject using an LRU eviction strategy when capacity is reached.
```java
            if (map.size() >= MAX_SUBJECTS) {
                sweep(map);
                if (map.size() >= MAX_SUBJECTS) {
                    // Evict oldest unblocked entry to preserve service availability
                    String oldestKey = null;
                    long oldestTime = Long.MAX_VALUE;
                    for (Map.Entry<String, State> entry : map.entrySet()) {
                        if (entry.getValue().blockedUntil <= now && entry.getValue().windowStart < oldestTime) {
                            oldestTime = entry.getValue().windowStart;
                            oldestKey = entry.getKey();
                        }
                    }
                    if (oldestKey != null) {
                        map.remove(oldestKey);
                    } else {
                        // All entries currently blocked; refuse addition gracefully without throwing
                        return map.values().iterator().next();
                    }
                }
            }
```

---

### SEC-03: Ineffective Multi-Process Session Revocation for Administratively Disabled or Reset Accounts
- **Severity:** High
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/portal/auth/PortalCli.java:238-241`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PortalCli.java:238-241
        runtime.store().disableAccount(name);
        runtime.sessions().revokeAllFor(name);
        out.println("ok.");
        return 0;
```

**Why it is a problem:**
`SessionManager` maintains session state strictly in an in-memory `LinkedHashMap` (`sessions`) within the running JVM process. When an administrator executes `portal disable-user --user=<name>`, a separate, short-lived CLI process is started. This process initializes its own independent `PortalRuntime` via `PortalRuntime.open(config)` with an empty in-memory `SessionManager`.

When `PortalCli` calls `runtime.sessions().revokeAllFor(name)` at line 239, it operates exclusively on its own local, empty session map. The active, long-running `portal portal` HTTPS daemon runs in an entirely separate OS process and JVM instance; it never receives any notification or IPC message regarding the revocation.

Furthermore, in `PortalServer`, incoming requests only validate sessions by checking whether the presented session cookie exists in the local map and whether its idle/absolute timeouts have lapsed (`runtime.sessions().find(presented.get())`). `SessionManager.find()` never inspects `EmployeeStore` to check if the user is disabled (`store.isDisabled()`) or if their credentials were changed. Consequently, if an administrator disables an account or resets an employee's password via CLI, the employee's existing session cookies remain valid on the server for up to 8 hours.

**Fix:**
Ensure that session validation in `SessionManager.find()` (or `PortalServer`) actively checks `EmployeeStore` to verify that the session's username is not administratively disabled and that the account still exists. In addition, record a credential version or timestamp on each account record and session to immediately invalidate sessions upon password resets or account disablement.
```java
    public Optional<Session> find(String presentedId, EmployeeStore store) {
        if (!InputPolicy.isSessionToken(presentedId)) {
            return Optional.empty();
        }
        String key = Crypto.sha256Hex(presentedId);
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            Session s = sessions.get(key);
            if (s == null) {
                return Optional.empty();
            }
            if (now - s.issuedAtEpochSecond > ABSOLUTE_TIMEOUT.getSeconds()
                    || now - s.lastUsedEpochSecond > IDLE_TIMEOUT.getSeconds()) {
                sessions.remove(key);
                expiredLookups++;
                return Optional.empty();
            }
            if (store != null && (!store.exists(s.username) || store.isDisabled(s.username))) {
                sessions.remove(key);
                return Optional.empty();
            }
            s.lastUsedEpochSecond = now;
            return Optional.of(s);
        }
    }
```

---

### SEC-04: Unbounded Monotonic On-Disk Throttle Ledger Growth Leading to State Corruption and DoS
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/portal/auth/Ledger.java:142-149`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/Ledger.java:142-149
                Map<String, Counter> merged = new HashMap<>();
                for (Map.Entry<String, Counter> e : state.entrySet()) {
                    merged.put(e.getKey(), e.getValue().copy());
                }
                for (Map.Entry<String, Counter> e : readForMerge().entrySet()) {
                    merged.merge(e.getKey(), e.getValue(), Ledger::max);
                }
                PrivateFiles.writePrivateAtomic(file, render(merged));
```

**Why it is a problem:**
When `Ledger.load()` is called on startup, it filters out expired counters whose block has lapsed and whose window start timestamp exceeds `retentionSeconds` (24 hours). However, during runtime, every state change calls `Ledger.persist()`, which invokes `readForMerge()` to merge in-memory counters with what is currently on disk.

Unlike `load()`, `readForMerge()` (lines 213–228) reads every single line in `throttle.log` without checking expiration timestamps:
```java
for (String raw : lines) {
    Counter c = parse(raw);
    if (c != null) {
        out.merge(keyOf(raw), c, Ledger::max);
    }
}
```
The merge step `merged.merge(..., Ledger::max)` combines in-memory subjects with all historical records from the file and writes the combined result back to `throttle.log`. As a result, expired subjects are never pruned from `throttle.log` during writes.

Over time or under brute-force attacks, the ledger file steadily grows until it exceeds `MAX_LINES` (50,000) or `MAX_BYTES` (4 MB). When this occurs, `readLines()` throws `IllegalStateException("ledger-too-large")` or `PrivateFiles.readPrivateBounded()` throws `IllegalStateException("file-too-large")`. On subsequent service restarts, `Ledger.load()` throws `IllegalStateException("ledger-corrupt")`, causing all throttle history to be wiped and preventing reliable restart.

**Fix:**
Apply retention filtering inside `readForMerge()` so that expired entries are discarded during merge operations, bounding the maximum size of `throttle.log`.
```java
    private Map<String, Counter> readForMerge(long nowEpochSecond, long retentionSeconds) {
        Map<String, Counter> out = new HashMap<>();
        List<String> lines;
        try {
            lines = readLines();
        } catch (RuntimeException unreadable) {
            return out;
        }
        for (String raw : lines) {
            Counter c = parse(raw);
            if (c != null) {
                boolean stillBlocked = c.blockedUntil > nowEpochSecond;
                boolean inWindow = nowEpochSecond - c.windowStart <= retentionSeconds
                        && c.windowStart <= nowEpochSecond;
                if (stillBlocked || inWindow) {
                    out.merge(keyOf(raw), c, Ledger::max);
                }
            }
        }
        return out;
    }
```

---

### SEC-05: Client IP Attribution and Rate Limiting Bypass via Duplicate `X-Forwarded-For` Headers
- **Severity:** Medium
- **CWE:** CWE-290: Authentication Bypass by Spoofing
- **Location:** `src/main/java/com/portal/auth/PortalServer.java:336-339`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PortalServer.java:336-339
    private String sourceLabelOf(HttpExchangeView ex) {
        return SourceRef.resolvePeer(ex.peerAddress(), ex.header("X-Forwarded-For"),
                trustedProxies);
    }
```

**Why it is a problem:**
`PortalServer.sourceLabelOf` queries `ex.header("X-Forwarded-For")` to obtain proxy forwarding information. In `JdkHttpsListener.java` line 129, `ex.header(name)` is implemented as:
```java
String v = exchange.getRequestHeaders().getFirst(name);
```
`getFirst()` retrieves only the first value if multiple `X-Forwarded-For` headers are sent.

In many reverse proxy architectures, intermediate proxies append client IP information as an additional header line rather than appending with a comma to an existing header line. If an attacker sends an initial spoofed header (e.g. `X-Forwarded-For: 198.51.100.1`), and the trusted reverse proxy appends a second header line with the actual client IP (e.g. `X-Forwarded-For: 203.0.113.5`), `getFirst("X-Forwarded-For")` returns only the attacker's first, spoofed header line.

Because the immediate TCP peer is recognized as a trusted proxy, `SourceRef.resolvePeer` trusts the proxy forwarding value, evaluates the single hop `198.51.100.1`, finds it untrusted, and attributes the request to `198.51.100.1`. By rotating this spoofed header value on every attempt, an attacker completely circumvents per-source rate limiting (`SOURCE_MAX_FAILURES = 30`), allowing unrestricted credential brute-forcing.

**Fix:**
Extract all `X-Forwarded-For` header entries using `ex.headers("X-Forwarded-For")`, combine them with commas into a single canonical comma-separated list, and pass the concatenated string to `SourceRef.resolvePeer`.
```java
    private String sourceLabelOf(HttpExchangeView ex) {
        List<String> xffHeaders = ex.headers("X-Forwarded-For");
        String combinedXff = (xffHeaders == null || xffHeaders.isEmpty())
                ? null
                : String.join(", ", xffHeaders);
        return SourceRef.resolvePeer(ex.peerAddress(), combinedXff, trustedProxies);
    }
```

---

### SEC-06: Retention of Plaintext User Credentials in Heap Memory via Immutable String Conversions
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/portal/auth/PortalServer.java:125-126`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PortalServer.java:125-126
        FormFields fields = FormFields.parse(new String(body, StandardCharsets.UTF_8));
        Crypto.wipe(body);
```

**Why it is a problem:**
The system adheres to a strict policy of handling credentials in mutable `char[]` and `byte[]` buffers that are promptly cleared using `Crypto.wipe` or `Arrays.fill` to avoid leaving plaintext credentials in memory.

However, in `PortalServer.route()`, the incoming HTTP POST body (which contains the URL-encoded `password` parameter) is converted into an immutable `java.lang.String` object at line 125 via `new String(body, StandardCharsets.UTF_8)`. While `Crypto.wipe(body)` wipes the underlying byte array at line 126, the newly allocated `String` object containing the plaintext password cannot be modified or cleared in Java.

Furthermore, `FormFields.parse` creates additional `String` instances through `body.split("&")` and `pair.substring(eq + 1)`. These strings reside in the JVM garbage-collected heap until collected and overwritten, leaving cleartext credentials exposed to heap dumps, core dumps, or memory inspection attacks.

**Fix:**
Parse the form fields directly from the mutable `byte[]` buffer without instantiating immutable `String` objects for the full body or the password value, and wipe intermediate byte arrays once processed.
```java
        FormFields fields = FormFields.parseBytes(body);
        Crypto.wipe(body);
```

## 6. Verified Controls and Checks With No Finding
- Password Hashing Algorithm and Parameters: Verified that `PasswordHasher.java` enforces PBKDF2-HMAC-SHA256 with a strict minimum floor of 100,000 iterations (defaulting to 150,000 iterations), 16-byte random salts generated by `SecureRandom`, and 32-byte derived keys. Legacy or weak records below the floor are refused.
- Constant-Time Comparison Implementations: Verified that `Crypto.equal`, `Crypto.equalConstantTime`, and `Crypto.equalChars` utilize `MessageDigest.isEqual` or constant-time XOR bit loops without short-circuiting on content differences, preventing timing attacks.
- Anti-Timing Decoy Derivations: Verified that `Authenticator.java` enforces the "one-digest invariant" by executing a decoy key derivation (`hasher.verifyAgainstDecoy` / `hasher.burnOneDigest`) on invalid inputs, missing accounts, and rate-limited requests to normalize CPU execution time across all authentication branches.
- Cryptographic Randomness: Verified that `Crypto.java` uses `java.security.SecureRandom` exclusively for all security-sensitive tokens, including 256-bit session IDs, 192-bit CSRF tokens, and salts.
- Cross-Site Request Forgery (CSRF) Defenses: Verified that `PortalServer.java` and `SessionManager.java` require a double-submit cookie and hidden form token pair (`portal_csrf`) on all state-changing endpoints (`POST /login`, `POST /logout`). Tokens are single-use, bounded by a 15-minute expiration, and validated in constant time.
- Cookie Security Flags: Verified that session and CSRF cookies are issued with `HttpOnly`, `Secure`, `SameSite=Strict`, and explicit `Max-Age` attributes, protecting cookies against client-side script theft and cross-site request inclusion.
- HTTP Security Headers: Verified that `PortalServer.java` injects strict browser security headers on all responses, including `Strict-Transport-Security` (up to 1 year max-age), `Content-Security-Policy: default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
- TLS Protocol and Cipher Enforcement: Verified that `JdkHttpsListener.java` explicitly removes TLSv1.0 and TLSv1.1, restricting communication to TLSv1.2 and TLSv1.3 with standard secure cipher suites; plaintext HTTP fallback is absent.
- Strict Filesystem Permissions: Verified that `PrivateFiles.java` enforces POSIX permissions `0600` on files and `0700` on directories, audits ancestor directory permissions for world-writable sticky flags, refuses symbolic links (`NOFOLLOW_LINKS`), and verifies ownership probes.
- Atomic File Operations and Concurrency: Verified that `PrivateFiles.writePrivateAtomic` writes to a temporary file in the same directory, flushes to disk using `FileChannel.force(true)`, and renames atomically via `ATOMIC_MOVE`, preventing truncated files during crashes. Cross-process writes are synchronized using exclusive `FileLock`.
- Input Validation and Unicode Normalization Invariance: Verified that `InputPolicy.java` enforces strict printable ASCII constraints on usernames (`[a-z0-9._-]{3,32}` without consecutive dots), rendering usernames NFKC-invariant and preventing Unicode homoglyph/confusable attacks.
- Audit Log Redaction: Verified that `AuditLog.java` sanitizes all logged fields, hashes account names and IP addresses to 16-hex references (`Crypto.idRef`), logs only exception class names rather than raw messages, and writes append-only to an owner-only file.
