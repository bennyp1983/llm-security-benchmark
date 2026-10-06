# Security Review: com.example.auth (Authentication and Audit Logging Service)

## 1. Executive Summary
A static security assessment was conducted on the `com.example.auth` component located in `/data/results/qwen/set_a/post_research/6/security/`. The reviewed component is a zero-dependency Java 17 service implementing credential verification (username/password), brute-force defense (per-source rate limiting and per-account lockout), session identifier issuance, and append-only tamper-resistant authentication audit logging.

The codebase exhibits rigorous defensive engineering, including constant-time hash comparisons, decoy work derivation for non-existent accounts, POSIX 0600 file permission validation with symlink protection, input canonicalization, and atomic session revocation upon logging failures. However, the audit identified several vulnerabilities, including a **Critical** authentication flaw where passwords consisting entirely of 3-byte UTF-8 characters (such as CJK scripts) are corrupted and zeroed out before hashing, causing credential collisions and authentication bypass. Additionally, concurrency deadlocks during cache eviction, a rate-limiting bypass via premature source eviction, an infinite loop hazard during log tail repair, and missing absolute session timeouts were identified.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/AccountCredentials.java` | In-memory representation of stored user credentials | Holds username, salt, PBKDF2 iterations, and digest; omits plaintext passwords; defensive array cloning. |
| `src/main/java/com/example/auth/AccountField.java` | Renders anonymized account identifiers for audit logs | Computes SHA-256 hash of submitted usernames and character diversity sketches; avoids writing raw usernames to disk. |
| `src/main/java/com/example/auth/AttemptThrottle.java` | Rate limiting and account lockout engine | Tracks failed attempts per account and request volume per source IP using `ConcurrentHashMap` with memory caps. |
| `src/main/java/com/example/auth/AuditLogger.java` | Append-only audit trail logger | Enforces POSIX 0600 permissions, checks parent directory ownership, detects inode swapping, repairs torn tails, and tracks storage capacity. |
| `src/main/java/com/example/auth/AuditPersistenceException.java` | Exception raised on audit write failure | Retains unpersisted event metadata for security alert emission without leaking file paths or exception causes. |
| `src/main/java/com/example/auth/AuthConfig.java` | Central configuration validator and builder | Enforces strict floors for iterations (120,000), bounds on timeouts/windows, path security rules, and keystore entry validation. |
| `src/main/java/com/example/auth/AuthEvent.java` | Structured audit event model and serializer | Validates single-line log formatting (max 320 chars), forbids control characters/newlines, and sanitizes IP addresses and session prefixes. |
| `src/main/java/com/example/auth/AuthException.java` | Internal authentication failure exception | Encapsulates diagnostic reason codes while preventing external disclosure of account existence. |
| `src/main/java/com/example/auth/AuthOutcome.java` | Enumeration of high-level authentication outcomes | Distinguishes `SUCCESS` and `DENIED` outcomes. |
| `src/main/java/com/example/auth/AuthResult.java` | Public response returned to the caller | Exposes generic denial messages, retry-after hints, and session tokens on success; redacts internal failure diagnostics. |
| `src/main/java/com/example/auth/AuthenticationService.java` | Main orchestration façade for authentication | Coordinates rate checks, input validation, decoy derivation, credential verification, event logging, and credential memory wiping. |
| `src/main/java/com/example/auth/ConfigSource.java` | Environment and properties abstraction | Snapshots system environment variables while validating keys against the `AUTH_` namespace. |
| `src/main/java/com/example/auth/CredentialStore.java` | Interface for credential retrieval | Defines case-insensitive account lookup contract. |
| `src/main/java/com/example/auth/CredentialVerifier.java` | Work-balanced credential comparison coordinator | Enforces global concurrency permit limits (4 permits) and executes decoy PBKDF2 derivations for unknown accounts. |
| `src/main/java/com/example/auth/Diagnostic.java` | Fixed internal error categories | Standardizes log-safe diagnostic codes without reflecting user inputs. |
| `src/main/java/com/example/auth/EventType.java` | Audit log event type tokens | Defines immutable tokens for successes, failures, throttling, and security alerts. |
| `src/main/java/com/example/auth/FileCredentialStore.java` | File-backed credential repository | Parses colon-delimited records, enforces canonical Base64 encoding, bounds iteration counts, and rejects duplicate or case-colliding usernames. |
| `src/main/java/com/example/auth/InputValidator.java` | Input validation and character encoding | Validates username syntax, parses bare IPv4/IPv6 literals, checks password constraints, and converts passwords to UTF-8. |
| `src/main/java/com/example/auth/InvalidConfigException.java` | Startup configuration failure exception | Aggregates configuration problems without leaking sensitive passwords or system paths. |
| `src/main/java/com/example/auth/KeystorePepperProvider.java` | Keystore secret key extractor | Extracts symmetric HMAC keys from JCEKS/PKCS12/JKS keystores and enforces minimum 16-byte key length. |
| `src/main/java/com/example/auth/LatencyBudget.java` | Response timing equalizer | Pads execution duration to a calibrated baseline floor to mitigate side-channel timing leaks. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Cryptographic password hashing and verification | Implements `HMAC-SHA-256(pepper, salt \|\| PBKDF2-HMAC-SHA-256(password, salt, c))` with constant-time equality checks. |
| `src/main/java/com/example/auth/PosixMode.java` | File permission verification utility | Checks POSIX file modes, rejecting non-POSIX or group/world-accessible files and directories. |
| `src/main/java/com/example/auth/SessionTokenStore.java` | In-memory session identifier store | Issues 128-bit cryptographically secure random session tokens, manages sliding expiry, and formats hardened cookie directives. |
| `src/main/java/com/example/auth/TimeSource.java` | Clock abstraction | Provides UTC time for logging and lockout window evaluation. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to inspect the PBKDF2 key derivation parameters, HMAC pepper integration, secret key retrieval from Java KeyStores, constant-time digest comparisons via `MessageDigest.isEqual`, entropy properties of `SecureRandom`, and intermediate credential memory scrubbing.
- `testing-api-authentication-weaknesses`: Applied to audit the credential validation workflow, username enumeration protections, session identifier generation, cookie security flag enforcement (`HttpOnly`, `Secure`, `SameSite=Strict`), and brute-force defenses.
- `implementing-api-rate-limiting-and-throttling`: Applied to evaluate the sliding-window source IP rate limiting, consecutive failure account lockout, map sizing caps, and bucket eviction algorithms.
- `testing-for-business-logic-vulnerabilities`: Applied to analyze the order of operations in the login flow, fail-closed handling of logging errors, atomic session revocation, and race conditions between authentication checks and state updates.
- `performing-security-headers-audit`: Applied to assess the structure, attributes, and transport constraints of emitted `Set-Cookie` directives.
- General OWASP Top 10 / CWE Knowledge: Applied to audit concurrency constructs (`ConcurrentHashMap` locking semantics), low-level NIO `FileChannel` I/O operations, character encoding corner cases, and memory persistence of sensitive configuration strings.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Password Plaintext Zeroed Out for 3-Byte UTF-8 Characters Leading to Credential Collision and Authentication Bypass | Critical | CWE-287 | `src/main/java/com/example/auth/InputValidator.java:372-386` |
| SEC-02 | Concurrency Deadlock in ConcurrentHashMap Compute During Cache Eviction | High | CWE-833 | `src/main/java/com/example/auth/AttemptThrottle.java:141-150` |
| SEC-03 | Rate Limiting Bypass via Premature Eviction of Blocked IP Sources | High | CWE-307 | `src/main/java/com/example/auth/AttemptThrottle.java:314-323` |
| SEC-04 | Potential Infinite Loop and Tail Buffer Corruption in Audit Log Tail Scanning | Medium | CWE-835 | `src/main/java/com/example/auth/AuditLogger.java:634-640` |
| SEC-05 | Insufficient Session Expiration Due to Missing Absolute Session Timeout | Medium | CWE-613 | `src/main/java/com/example/auth/SessionTokenStore.java:113-118` |
| SEC-06 | Sensitive Keystore Password Maintained in Heap Memory as Immutable Strings | Low | CWE-316 | `src/main/java/com/example/auth/ConfigSource.java:30-33` |

## 5. Detailed Findings

### SEC-01: Password Plaintext Zeroed Out for 3-Byte UTF-8 Characters Leading to Credential Collision and Authentication Bypass
- **Severity:** Critical
- **CWE:** CWE-287: Improper Authentication
- **Location:** `src/main/java/com/example/auth/InputValidator.java:372-386`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/InputValidator.java:372-386
            int written = output.position();
            if (oversized.length == written) {
                encoded = oversized;
            } else {
                encoded = new byte[written];
                System.arraycopy(oversized, 0, encoded, 0, written);
            }
        } catch (RuntimeException e) {
            java.util.Arrays.fill(oversized, (byte) 0);
            throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
        }
        java.util.Arrays.fill(oversized, (byte) 0);
        if (encoded.length == 0) {
            java.util.Arrays.fill(encoded, (byte) 0);
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        return encoded;
```

**Why it is a problem:**
In `InputValidator.encodePassword(char[] raw)`, the scratch buffer `oversized` is allocated with `raw.length * 3` bytes. For any password where all code points encode to 3 bytes in UTF-8 (such as CJK ideographs in `U+4E00..U+9FFF`, Japanese Hiragana/Katakana, Korean Hangul, Devanagari, or currency symbols like `€`), the number of written bytes `written` equals `raw.length * 3`.

When `oversized.length == written`, the optimization branch executes: `encoded = oversized;`. Immediately afterward, line 382 unconditionally clears the scratch buffer: `Arrays.fill(oversized, (byte) 0);`. Because `encoded` references the exact same array as `oversized`, the contents of `encoded` are completely wiped to zeroes before being returned.

As a result:
1. Any password consisting of 3-byte UTF-8 characters is hashed as a block of zero bytes (`0x00`).
2. Two completely different passwords of equal character length consisting of 3-byte UTF-8 characters (e.g., two distinct Chinese passwords) produce identical hashes.
3. An attacker can authenticate as any user whose password uses these characters by submitting any string of 3-byte UTF-8 characters of matching length, resulting in a critical authentication bypass and credential collision.

**Fix:**
Never alias `encoded` to the mutable scratch buffer `oversized`. Always allocate a distinct array of size `written`, copy the data, and then zero out `oversized`:
```java
            int written = output.position();
            encoded = new byte[written];
            System.arraycopy(oversized, 0, encoded, 0, written);
        } catch (RuntimeException e) {
            java.util.Arrays.fill(oversized, (byte) 0);
            throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
        }
        java.util.Arrays.fill(oversized, (byte) 0);
        if (encoded.length == 0) {
            java.util.Arrays.fill(encoded, (byte) 0);
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        return encoded;
```

---

### SEC-02: Concurrency Deadlock in ConcurrentHashMap Compute During Cache Eviction
- **Severity:** High
- **CWE:** CWE-833: Deadlock
- **Location:** `src/main/java/com/example/auth/AttemptThrottle.java:141-150`

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

**Why it is a problem:**
In `AttemptThrottle.consumeSourceAttempt` (and similarly in `recordAccountFailure` at lines 201–209), the service executes `sources.compute(...)` to atomically evaluate and update attempt counts. Inside the remapping function passed to `compute()`, if the map reaches capacity (`MAX_SOURCE_KEYS`), it calls `evictIdleSources(horizon)`.

`evictIdleSources` performs `sources.entrySet().removeIf(...)`, which iterates across all buckets of the same `ConcurrentHashMap` and calls `remove(key, value)`. In Java's `ConcurrentHashMap`, `compute()` holds an exclusive lock on the hash bin head node of `canonicalSource`. Simultaneously, `remove()` requires locking the bin head node of each entry it attempts to delete.

If two threads concurrently attempt logins from two different IP addresses when the cache is full, Thread A locks Bin 1 and attempts to remove an entry in Bin 2, while Thread B locks Bin 2 and attempts to remove an entry in Bin 1. This causes a circular lock dependency and deadlocks both threads. Over time, worker threads block permanently on the map bins, creating a complete denial of service for authentication. The Javadoc for `ConcurrentHashMap.compute` explicitly prohibits this: *"The action should not attempt to update any other mappings of this map."*

**Fix:**
Evict idle keys before entering `compute()`, ensuring `compute()` performs only local modifications to its target bin:
```java
        long horizon = nowMillis - windowSeconds * 1000L;
        if (!sources.containsKey(canonicalSource) && sources.size() >= MAX_SOURCE_KEYS) {
            evictIdleSources(horizon, nowMillis);
        }
        sources.compute(canonicalSource, (key, existing) -> {
            SourceBucket bucket = existing;
            if (bucket == null) {
                if (sources.size() >= MAX_SOURCE_KEYS) {
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return null;
                }
                bucket = new SourceBucket();
            }
```

---

### SEC-03: Rate Limiting Bypass via Premature Eviction of Blocked IP Sources
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/AttemptThrottle.java:314-323`

**Vulnerable code:**
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

**Why it is a problem:**
When an IP address exceeds `sourceMaxAttempts`, it is blocked for `sourceBlockSeconds` (up to 1,800 seconds / 30 minutes) by setting `bucket.blockedUntilMillis = nowMillis + blockSeconds * 1000L`.

When `sources.size() >= MAX_SOURCE_KEYS`, `evictIdleSources(horizon)` is invoked with `horizon = nowMillis - windowSeconds * 1000L` (where `sourceWindowSeconds` can be configured down to 60 seconds). `evictIdleSources` deletes any bucket where `bucket.lastTouchedMillis < horizon`, without verifying whether the bucket is still actively blocked (`bucket.blockedUntilMillis <= nowMillis`).

An attacker blocked for 30 minutes can wait for the 60-second window to lapse, flood 20,000 requests from other IP addresses (or spoofed addresses) to force cache eviction, and trigger the removal of their own blocked IP bucket. The next request from the attacker's IP will find no existing bucket and obtain a fresh quota, bypassing the 30-minute lockout after only 1 minute.

**Fix:**
Ensure that `evictIdleSources` never evicts an address whose block has not yet expired:
```java
    private boolean evictIdleSources(long horizon, long nowMillis) {
        int before = sources.size();
        sources.entrySet().removeIf(entry -> {
            SourceBucket bucket = entry.getValue();
            synchronized (bucket) {
                return bucket.lastTouchedMillis < horizon && bucket.blockedUntilMillis <= nowMillis;
            }
        });
        return sources.size() < before;
    }
```

---

### SEC-04: Potential Infinite Loop and Tail Buffer Corruption in Audit Log Tail Scanning
- **Severity:** Medium
- **CWE:** CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')
- **Location:** `src/main/java/com/example/auth/AuditLogger.java:634-640`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuditLogger.java:634-640
            ByteBuffer buffer = ByteBuffer.wrap(chunk, 0, length);
            int guard = 0;
            while (buffer.hasRemaining()) {
                if (probe.read(buffer, start) < 0L && ++guard > 8) {
                    throw new IOException("the event log could not be read for the tail scan");
                }
            }
```

**Why it is a problem:**
In `AuditLogger.offsetAfterLastNewline`, the method reads file chunks backwards to locate the last newline boundary. In `FileChannel.read(ByteBuffer dst, long position)`, the `position` argument specifies the absolute offset in the file and does not modify or advance the channel position.

If `probe.read(buffer, start)` returns fewer bytes than `length` (a short read), `buffer.position()` advances, but `start` remains unchanged. On the next loop iteration, `probe.read(buffer, start)` reads from offset `start` again instead of `start + buffer.position()`, corrupting the buffer with duplicate data from the head of the chunk. Furthermore, if `probe.read` returns `0` (e.g., temporary lack of data), `guard` is not incremented while `buffer.hasRemaining()` remains true, trapping the thread in a 100% CPU infinite loop.

**Fix:**
Track and advance the file position by the number of bytes read on each iteration:
```java
            ByteBuffer buffer = ByteBuffer.wrap(chunk, 0, length);
            long readPos = start;
            int guard = 0;
            while (buffer.hasRemaining()) {
                int read = probe.read(buffer, readPos);
                if (read < 0 && ++guard > 8) {
                    throw new IOException("the event log could not be read for the tail scan");
                }
                if (read > 0) {
                    readPos += read;
                }
            }
```

---

### SEC-05: Insufficient Session Expiration Due to Missing Absolute Session Timeout
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/SessionTokenStore.java:113-118`

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

**Why it is a problem:**
`SessionTokenStore.isValid` renews the session expiry timestamp on every validation call (`expiresAtMillis.put(candidate, now + ttlSeconds * 1000L)`). The service maintains no record of the session's initial creation time and enforces no absolute maximum lifetime cap.

An active session can remain valid indefinitely if a client (or an attacker possessing a hijacked session token) periodically sends requests within the sliding window. Per OWASP Session Management Guidelines and CWE-613, sessions must enforce an absolute timeout after which re-authentication is mandatory regardless of ongoing activity.

**Fix:**
Maintain both an initial creation timestamp and an idle expiry timestamp for each session, enforcing an absolute maximum lifetime:
```java
        SessionEntry session = sessions.get(candidate);
        if (session == null || session.isExpired(now) || (now - session.createdAtMillis()) > maxLifetimeMillis) {
            sessions.remove(candidate);
            return false;
        }
        session.touch(now + ttlSeconds * 1000L);
        return true;
```

---

### SEC-06: Sensitive Keystore Password Maintained in Heap Memory as Immutable Strings
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/example/auth/ConfigSource.java:30-33`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/ConfigSource.java:30-33
    static ConfigSource ofEnvironment() {
        final Map<String, String> snapshot = new LinkedHashMap<>(System.getenv());
        return new SnapshotConfigSource(snapshot);
    }
```

**Why it is a problem:**
While `AuthConfig` and `AuthenticationService` make efforts to handle `char[] keystorePassword` and wipe it via `eraseSecrets()`, `ConfigSource.ofEnvironment()` imports configuration from `System.getenv()`, which represents environment variables as immutable `java.lang.String` objects. These strings are permanently retained in `SnapshotConfigSource.values` and internal JVM tables.

Immutable `String` objects cannot be cleared or zeroed out from memory. The master keystore password remains resident in cleartext on the JVM heap indefinitely, exposing it to memory scraping, heap dumps, or core dumps.

**Fix:**
Provide an ingestion path that reads the keystore password directly from a secure file descriptor or console into a mutable `char[]` buffer, rather than storing secrets in environment variables or immutable `String` instances:
```java
    // Avoid reading sensitive secrets into immutable String objects;
    // ingest credentials into mutable char[] buffers that are zeroed immediately after use.
```

## 6. Verified Controls and Checks With No Finding
- Constant-time password verification: `PasswordHasher.matches` relies on `MessageDigest.isEqual()`, mitigating timing side-channel attacks on hash comparisons (CWE-208).
- Decoy work on non-existent accounts: `CredentialVerifier.verify` executes a full PBKDF2 derivation with decoy parameters when an unknown account is supplied, preventing account enumeration via timing analysis (CWE-208 / CWE-200).
- PBKDF2 iteration floor enforcement: `AuthConfig` enforces a hardcoded floor of 120,000 iterations for PBKDF2-HMAC-SHA256 and validates that stored credential counts do not exceed the service's configured cost, preventing computational resource exhaustion.
- POSIX 0600 file permission validation: `PosixMode` and `AuthConfig.validateFilesystem` verify that credential stores, logs, and keystores are regular files owned exclusively by the service user (`rw-------`) without following symlinks (`NOFOLLOW_LINKS`), refusing startup on misconfigured permissions (CWE-732).
- Audit log injection defense: `AuthEvent.renderOrReject` enforces strict structural line formatting (maximum 320 characters), rejects all control characters (below `0x20` and `0x7F`), validates IP formatting, and hashes usernames to `account_id` digests before persisting (CWE-117).
- Cryptographically strong session generation: `SessionTokenStore` generates 128-bit session tokens (32 hex characters) using `java.security.SecureRandom`, preventing token predictability (CWE-330 / CWE-331).
- Session cookie hardening: `SessionTokenStore.cookieDirectiveFor` emits `HttpOnly`, `SameSite=Strict`, and `Secure` attributes, and returns `null` if the connection is not verified to be TLS (CWE-614 / CWE-1004).
- Plaintext password lifecycle control: `AuthenticationService` and `InputValidator` work on mutable `char[]` and `byte[]` copies and explicitly invoke `Arrays.fill(..., 0)` in `finally` blocks (CWE-244 / CWE-316).
- Atomic session revocation on logging failure: If an audit log write fails, `AuthenticationService.authenticate` catches `AuditPersistenceException`, revokes the newly issued session identifier, and returns a denial, ensuring no unlogged logins succeed (CWE-778).
- Audit file swapping detection: `AuditLogger.targetStillOurs` verifies file attributes and inode identity (`fileKey()`) before each write, preventing writes to unlinked or replaced files (CWE-59 / CWE-367).
