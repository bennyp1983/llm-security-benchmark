# Security Review: Authentication Component

## 1. Executive Summary
The target component is a standalone Java SE 17 user authentication and event-logging service (`com.example.auth`). It validates username and password credentials against server-side PBKDF2-HMAC-SHA512 verifiers, enforces rate-limiting throttle budgets per source IP address and per user account, generates 256-bit cryptographically random session tokens stored server-side as SHA-256 digests, formats hardened `__Host-` session cookies, and appends audit events to an owner-restricted, size-bounded log file with HMAC-based account correlation and PII masking. The design includes strong defensive patterns such as decoy verifications for non-existent users, strict generic error messages, defensive copying of verifiers, and zeroing of plaintext password arrays.

However, static analysis identified five security vulnerabilities:
1. **SEC-01 (High):** A Time-of-Check to Time-of-Use (TOCTOU) race condition between throttle admission (`throttle.admit`) and failure recording (`throttle.recordFailure`) permits concurrent request bursts to exceed the attempt budget and amplify PBKDF2 CPU load.
2. **SEC-02 (Medium):** `InputPolicy.canonicalSource` performs format validation without canonicalizing IP representations (case sensitivity, leading zeros, zero compression), allowing attackers to bypass per-source rate limits.
3. **SEC-03 (Medium):** The throttle's fail-closed capacity guard (`Block.CAPACITY`) denies login to all un-tracked legitimate users once the table reaches 50,000 keys, creating an application-wide Denial of Service (DoS) condition.
4. **SEC-04 (Low):** `LogSanitizer.maskSource` improperly parses compressed IPv6 addresses, causing host interface identifiers to leak into audit logs instead of masking to a `/48` prefix.
5. **SEC-05 (Low):** `PasswordHasher.verify` clones the stored credential hash without zeroing the cloned byte array from memory in its `finally` block.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build descriptor | Pins Java 17 and compiler plugin with no third-party runtime dependencies. |
| `src/main/java/com/example/auth/AuthenticationService.java` | Core authentication coordinator | Coordinates validation, throttling admission, verifier lookups, decoy verifications, session issuance, and event logging. |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Authentication response model | Returns uniform generic failure messages and exposes session IDs only upon success. |
| `src/main/java/com/example/auth/InputPolicy.java` | Trust-boundary input validator | Enforces allowlists, length constraints, and syntax checks on usernames, passwords, sources, and tokens. |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2 cryptographic engine | Computes PBKDF2-HMAC-SHA512 derivations (210,000 iterations), constant-time comparisons, and decoy cost matching. |
| `src/main/java/com/example/auth/CredentialRecord.java` | Stored verifier data structure | Validates salt and hash lengths, bounds iteration counts, redacts `toString()`, and defensive-copies byte arrays. |
| `src/main/java/com/example/auth/CredentialStore.java` | Credential repository contract | Read-only interface for retrieving account verifiers. |
| `src/main/java/com/example/auth/InMemoryCredentialStore.java` | In-memory credential repository | Thread-safe in-memory store enforcing canonical username lookups. |
| `src/main/java/com/example/auth/LoginThrottle.java` | Rate limiting and attempt budgeting | Maintains per-source and per-account attempt counters, cool-off windows, and capacity limits. |
| `src/main/java/com/example/auth/SessionRegistry.java` | Server-side session management | Generates 256-bit `SecureRandom` tokens, indexes by SHA-256 digest, and enforces idle/absolute timeouts. |
| `src/main/java/com/example/auth/Session.java` | Session metadata entity | Stores username, source, creation time, and last access time without retaining token material. |
| `src/main/java/com/example/auth/SessionCookie.java` | HTTP cookie formatter | Formats `Set-Cookie` with `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. |
| `src/main/java/com/example/auth/AuthEventLog.java` | Audit sink interface | Declares event recording and HMAC account correlation contracts. |
| `src/main/java/com/example/auth/FileAuthEventLog.java` | POSIX file audit sink | Enforces POSIX 0600 file and 0700 directory permissions, `NOFOLLOW_LINKS`, single-generation rotation, and HMAC-SHA256 correlation. |
| `src/main/java/com/example/auth/AuthEvent.java` | Audit event record | Encapsulates timestamp, outcome enum, masked user, masked source, correlation ID, and detail string. |
| `src/main/java/com/example/auth/LogSanitizer.java` | Log sanitization utility | Escapes control characters and quotes, bounds string lengths, and masks usernames and IP addresses. |
| `src/test/java/com/example/auth/AuthenticationSelfCheck.java` | Executable verification suite | Runs 44 self-tests covering functionality, concurrency, logging, and security boundaries. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2-HMAC-SHA512 key derivation, iteration bounds, constant-time digest comparison, `SecureRandom` entropy, and HMAC-SHA256 correlation key handling.
- `testing-api-authentication-weaknesses`: Applied to authentication verification flows, credential validation, decoy execution, session lifecycle, token generation, fixation resistance, and account enumeration defenses.
- `hunting-credential-stuffing-attacks`: Applied to login throttling mechanisms, per-source/per-account failure budgeting, cool-off logic, and brute-force mitigations.
- `performing-security-headers-audit`: Applied to session cookie attributes (`__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`).
- `testing-for-sensitive-data-exposure`: Applied to password memory zeroing, verifier redaction in `toString()`, PII masking in logs, and POSIX file access permissions.
- General OWASP Top 10 / CWE knowledge: Applied to TOCTOU concurrency race conditions between admission and failure tracking (CWE-367), uncanonicalized alternate encodings of IP addresses (CWE-173), global denial of service via capacity saturation (CWE-400), and IPv6 address parsing bugs leading to PII disclosure (CWE-200).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | TOCTOU Race Condition Between Throttle Admission and Failure Recording | High | CWE-367 | `AuthenticationService.java:99-135` |
| SEC-02 | Per-Source Throttle Bypass via Non-Canonical IP Address Representations | Medium | CWE-173 | `InputPolicy.java:92-109` |
| SEC-03 | Global Denial of Service via Fail-Closed Throttle Capacity Exhaustion | Medium | CWE-400 | `LoginThrottle.java:95-97` |
| SEC-04 | Information Disclosure of IPv6 Host Identifiers in Audit Log | Low | CWE-200 | `LogSanitizer.java:73-80` |
| SEC-05 | Credential Verifier Hash Clone Leaked in Memory Without Zeroing | Low | CWE-316 | `PasswordHasher.java:62` |

## 5. Detailed Findings

### SEC-01: TOCTOU Race Condition Between Throttle Admission and Failure Recording
- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `AuthenticationService.java:99-135`

**Vulnerable code:**
```java
// AuthenticationService.java:99-135
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
            audit(record.isEmpty() ? AuthEvent.Outcome.UNKNOWN_ACCOUNT : AuthEvent.Outcome.BAD_CREDENTIALS,
                    user, source, "credentials did not match");
            return AuthenticationResult.failure();
        }
```

**Why it is a problem:**
`LoginThrottle.admit()` only inspects whether an IP or account is currently marked blocked; it does not reserve attempt budget, register an in-flight operation, or increment the failure counter. The failure counter is only incremented much later in `throttle.recordFailure()` after the computationally expensive PBKDF2 derivation (`hasher.verify()`, 210,000 iterations) finishes.

When an attacker issues a concurrent burst of login requests from the same source IP or targeting the same user, all requests pass `throttle.admit()` simultaneously before any single request completes verification and records a failure. This allows an attacker to:
1. Bypass the configured failure budget (e.g. 10 attempts per source) by sending concurrent batches of attempts.
2. Force the server to execute tens or hundreds of concurrent PBKDF2 derivations simultaneously, creating a severe CPU exhaustion Denial of Service (DoS)—the exact risk `admit()` was designed to prevent.

In `AuthenticationSelfCheck.java:225-226`, the test suite explicitly accommodates this race condition as "+ in-flight slack" (`admitted.get() <= budget + threads`).

**Fix:**
Atomically reserve an in-flight attempt permit or increment the failure counter optimistically during `throttle.admit()`. If authentication subsequently succeeds, clear or refund the counter in `throttle.recordSuccess()`.

```java
// LoginThrottle.java
    public synchronized Optional<Block> admitAndAcquire(String canonicalUsername, String source) {
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
        // Increment attempt count on admission to bind concurrent requests to the budget
        penalise(bySource, source, now, sourceFailureBudget, sourceCoolOff);
        penalise(byAccount, canonicalUsername, now, accountFailureBudget, accountCoolOff);
        return Optional.empty();
    }
```

---

### SEC-02: Per-Source Throttle Bypass via Non-Canonical IP Address Representations
- **Severity:** Medium
- **CWE:** CWE-173: Improper Handling of Alternate Encoding
- **Location:** `InputPolicy.java:92-109`

**Vulnerable code:**
```java
// InputPolicy.java:92-109
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
    }
```

**Why it is a problem:**
Despite its name, `InputPolicy.canonicalSource` performs syntactic validation but returns the raw string unchanged (`Optional.of(raw)`). `LoginThrottle` uses this string directly as the lookup key in `ConcurrentHashMap<String, Counter> bySource`.

IP addresses have multiple valid textual representations for the same underlying network address:
1. Hex case variations: `2001:db8::1` versus `2001:DB8::1`.
2. Leading zeroes in groups: `2001:0db8::0001` versus `2001:db8::1`.
3. Zero-compression variants: `2001:db8:0:0:0:0:0:1` versus `2001:db8::1`.
4. In IPv4, octets with leading zeroes: `198.51.100.7` versus `198.51.100.07`.

Because `bySource` relies on exact `String.equals()` matching, an attacker sending attempts from the same IP address can evade the per-source failure limit (10 failures per 15 minutes) simply by altering character case or zero-padding in the source string.

**Fix:**
Parse the address using `java.net.InetAddress` to validate syntax and produce a normalized, canonical string representation (or canonical byte array representation) before using it as a map key.

```java
// InputPolicy.java
    public static Optional<String> canonicalSource(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > SOURCE_MAX_LENGTH) {
            return Optional.empty();
        }
        try {
            java.net.InetAddress addr = java.net.InetAddress.getByName(raw);
            return Optional.of(addr.getHostAddress().toLowerCase(java.util.Locale.ROOT));
        } catch (java.net.UnknownHostException e) {
            return Optional.empty();
        }
    }
```

---

### SEC-03: Global Denial of Service via Fail-Closed Throttle Capacity Exhaustion
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginThrottle.java:95-97`

**Vulnerable code:**
```java
// LoginThrottle.java:95-97
        if (atCapacity(bySource, source, now) || atCapacity(byAccount, canonicalUsername, now)) {
            return java.util.Optional.of(Block.CAPACITY);
        }
```

**Why it is a problem:**
`LoginThrottle` caps tracked keys at 50,000 (`MAX_TRACKED_KEYS`). When `table.size() >= MAX_TRACKED_KEYS`, `atCapacity()` returns `true` for any key that does not already exist in the table. Because `admit()` fails closed on `Block.CAPACITY`, once `byAccount` or `bySource` is filled with 50,000 entries, **all legitimate users** whose accounts or source IPs are not already tracked in the failure table are denied authentication.

An attacker can easily populate 50,000 keys using distributed sources, rotated IPv6 addresses, or automated attempts across distinct unauthenticated usernames. Once saturated, no legitimate user can log in until the 15-minute window expires. Failing closed on memory-table capacity turns an anti-abuse control into an application-wide Denial-of-Service vector.

**Fix:**
Do not deny un-tracked users when the tracking table reaches capacity. Instead, implement a bounded eviction strategy (such as LRU eviction or removing the oldest non-blocked entry) when inserting new keys, or log an alert and allow the request to proceed to credential verification.

```java
// LoginThrottle.java:95-97
        // Do not deny legitimate users on capacity saturation; instead manage memory eviction
        if (isBlocked(bySource, source, now)) {
            return java.util.Optional.of(Block.SOURCE);
        }
        if (isBlocked(byAccount, canonicalUsername, now)) {
            return java.util.Optional.of(Block.ACCOUNT);
        }
        return java.util.Optional.empty();
```

---

### SEC-04: Information Disclosure of IPv6 Host Identifiers in Audit Log
- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `LogSanitizer.java:73-80`

**Vulnerable code:**
```java
// LogSanitizer.java:73-80
        if (safe.indexOf(':') >= 0) {
            String[] groups = safe.split(":", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < 3 && i < groups.length; i++) {
                out.append(groups[i]).append(':');
            }
            return out.append(":/48").toString();
        }
```

**Why it is a problem:**
`LogSanitizer.maskSource` intends to truncate IPv6 addresses to their `/48` prefix to prevent user identification in audit logs. However, it blindly splits the string on `:` and takes the first three tokens.

When an IPv6 address uses `::` zero-compression in the prefix (such as `::1`, `fe80::1`, or `2001::1`), the split array contains empty strings corresponding to the compressed zeroes. The loop consumes these empty entries and advances into the suffix of the address, capturing the host interface identifier. For example:
- For `::1`, `groups` is `["", "", "1"]`, resulting in `"::1::/48"`, which logs the host identifier `"1"`.
- For `2001::1`, `groups` is `["2001", "", "1"]`, resulting in `"2001::1::/48"`, which logs the host identifier `"1"`.
- For `2001:db8::1`, `groups[2]` is empty, producing `"2001:db8:::/48"` with an invalid triple colon.

This leaks individual host identifiers into logs, violating the design requirement to mask sensitive client network addresses.

**Fix:**
Expand the IPv6 address to its full 8-group representation or parse it into 16 bytes before extracting the first 3 groups (48 bits).

```java
// LogSanitizer.java
    public static String maskSource(String source) {
        if (source == null || source.isEmpty()) {
            return "-";
        }
        String safe = escape(source);
        if (safe.indexOf(':') >= 0) {
            try {
                byte[] bytes = java.net.InetAddress.getByName(safe).getAddress();
                if (bytes.length == 16) {
                    return String.format(java.util.Locale.ROOT, "%02x%02x:%02x%02x:%02x%02x::/48",
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
                }
            } catch (java.net.UnknownHostException ignored) {
            }
            return "***::/48";
        }
        int lastDot = safe.lastIndexOf('.');
        return lastDot < 0 ? "***" : safe.substring(0, lastDot) + ".0/24";
    }
```

---

### SEC-05: Credential Verifier Hash Clone Leaked in Memory Without Zeroing
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `PasswordHasher.java:62`

**Vulnerable code:**
```java
// PasswordHasher.java:59-65
    public boolean verify(char[] password, CredentialRecord record) throws GeneralSecurityException {
        byte[] derived = derive(password, record.salt(), record.iterations());
        try {
            return MessageDigest.isEqual(derived, record.hash());
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }
```

**Why it is a problem:**
`CredentialRecord.hash()` creates and returns a cloned copy of the stored verifier hash (`return hash.clone();` at `CredentialRecord.java:39`). In line 62, this cloned array is passed directly as a temporary parameter to `MessageDigest.isEqual(derived, record.hash())`.

While `derived` is explicitly zeroed in the `finally` block, the cloned `record.hash()` array is left unreferenced on the heap without being cleared. Until collected by the garbage collector, sensitive password verifier bytes persist in process memory and may be exposed in heap dumps or memory analysis.

**Fix:**
Assign the cloned hash array to a local variable and zero it out in the `finally` block alongside `derived`.

```java
// PasswordHasher.java
    public boolean verify(char[] password, CredentialRecord record) throws GeneralSecurityException {
        byte[] derived = derive(password, record.salt(), record.iterations());
        byte[] expected = record.hash();
        try {
            return MessageDigest.isEqual(derived, expected);
        } finally {
            Arrays.fill(derived, (byte) 0);
            Arrays.fill(expected, (byte) 0);
        }
    }
```

## 6. Verified Controls and Checks With No Finding
- **Cryptographic Key Derivation Algorithm and Cost:** Verified that `PasswordHasher` uses standard Java JCE `PBKDF2WithHmacSHA512` with a minimum of 100,000 iterations (defaulting to OWASP-recommended 210,000 iterations) and 16-byte random salts (`PasswordHasher.java:22-29, 91-98`).
- **Account Existence Timing Oracle Protection:** Verified that attempts on non-existent accounts trigger `hasher.verifyAgainstDecoy(password)`, deriving keys using a process-local decoy record with identical iteration count and algorithm parameters, preventing username enumeration via response timing (`AuthenticationService.java:118-125`, `PasswordHasher.java:73-79`).
- **Constant-Time Digest Verification:** Verified that password verification evaluates hashes using `MessageDigest.isEqual`, preventing byte-by-byte timing attacks on the hash comparison (`PasswordHasher.java:62`).
- **Generic Error Responses:** Verified that all authentication failures (syntax rejection, throttled access, unknown user, incorrect password, backend store exception) return the identical message `AuthenticationResult.GENERIC_FAILURE_MESSAGE` with no internal diagnostic details (`AuthenticationResult.java:17-23`, `AuthenticationService.java:84, 90, 105, 113, 128, 135, 143, 152`).
- **Input Allowlisting and Parameter Constraints:** Verified that usernames are constrained to 1–64 characters matching `[a-zA-Z0-9._\-@+]` and canonicalized using `Locale.ROOT`, mitigating SQL/LDAP injection, path traversal, and Unicode homoglyph collisions (`InputPolicy.java:47-69`).
- **Password Length Range Guards:** Verified that passwords shorter than 12 characters are rejected without hashing, and passwords longer than 256 characters are rejected to prevent computational CPU exhaustion attacks (`InputPolicy.java:75-79`).
- **Caller Password Buffer Sanitization:** Verified that `AuthenticationService.authenticate` accepts passwords as `char[]` and securely overwrites the buffer with `'\0'` in a `finally` block on every execution path, including unexpected runtime exceptions (`AuthenticationService.java:91-95`).
- **Internal Password Spec Cleanup:** Verified that `PasswordHasher.derive` calls `spec.clearPassword()` in a `finally` block to zero the internal character array maintained by `PBEKeySpec` (`PasswordHasher.java:95-98`).
- **Session Identifier Randomness and Entropy:** Verified that session tokens are generated from `java.security.SecureRandom` with 256 bits of cryptographic entropy (32 bytes encoded as 43 base64url characters) and are never accepted from external caller input (`SessionRegistry.java:31-36, 77-83`).
- **Session Digest Storage (Fixation and Leak Resistance):** Verified that `SessionRegistry` stores only SHA-256 digests of session identifiers, ensuring that a memory or state dump does not reveal usable session tokens, and mints new identifiers upon every successful authentication (`SessionRegistry.java:81, 131-139`).
- **Server-Side Session Timeouts:** Verified that sessions are strictly bounded by both an idle timeout (30 minutes) and an absolute timeout (8 hours), with validation and touch operations executed atomically inside `ConcurrentHashMap.compute` (`SessionRegistry.java:101-108`, `Session.java:41-44`).
- **Hardened Cookie Configuration:** Verified that session cookies are formatted with `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and an explicit positive `Max-Age` matching session lifetime (`SessionCookie.java:26-39`).
- **Audit File Access Control:** Verified that `FileAuthEventLog` explicitly creates log files with POSIX `0600` (`rw-------`) permissions and parent directories with POSIX `0700` (`rwx------`), checks `LinkOption.NOFOLLOW_LINKS`, and refuses execution if files or directories are accessible to other users (`FileAuthEventLog.java:43-44, 109-130, 134-157`).
- **Audit Log Injection Defense:** Verified that `LogSanitizer.escape` strips/escapes quotes, backslashes, and control characters (including CR and LF), and limits individual fields to 64 characters, preventing log forging and parser corruption (`LogSanitizer.java:26-46`).
- **Audit Log Volume Bounding and Rotation:** Verified that log file size is strictly bounded by a configurable ceiling (default 8 MiB) and rotated using `StandardCopyOption.REPLACE_EXISTING` with single-generation retention (`.1`), preventing disk space exhaustion (`FileAuthEventLog.java:168-193`).
- **Audit Failure Fail-Closed Policy:** Verified that if a successful authentication event cannot be written to the audit log, the newly minted session is immediately invalidated and the login attempt is denied (`AuthenticationService.java:148-153`).
- **Dependency and Supply Chain Hygiene:** Verified that `pom.xml` declares no third-party libraries and relies entirely on standard JDK SE 17 primitives, eliminating third-party supply chain risks (`pom.xml:1-34`).
