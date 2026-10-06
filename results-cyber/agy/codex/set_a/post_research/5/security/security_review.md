# Security Review: Internal Employee Portal Authentication

## 1. Executive Summary

This security review evaluated the internal employee portal authentication service implemented in Java 17 under `/data/results/codex/set_a/post_research/5/security/`. The application provides local console-based credential verification and administrator provisioning, utilizing PBKDF2-HMAC-SHA-256 with 600,000 iterations, strict POSIX file permissions (`0600`), constant-time hash comparisons, dummy password hashing to prevent user enumeration, and dual-layer rate limiting (per-source sliding window blocking and per-account backoff).

While cryptographic algorithms and file permission validations are implemented securely, the review identified significant vulnerabilities in the rate-limiting and concurrency architectures. Specifically, the in-memory account failure store lacks time-based eviction and sliding-window expiration, allowing an attacker to permanently exhaust the cache through username spraying and force an unrecoverable 15-minute lockout on every subsequent user typo. Furthermore, `System.nanoTime()` comparisons rely on an uninitialized `0L` timestamp, causing total service denial on systems where the monotonic clock starts negative. Additionally, read-only authentication holds an OS-level exclusive file lock across multi-second throttling sleeps and CPU-intensive PBKDF2 operations, stalling all concurrent consoles and administrative operations.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/acme/portal/Main.java` | CLI entry point and process lifecycle controller | Console input validation, password memory clearing (`Arrays.fill`), global update lock orchestration, generic error output masking. |
| `src/main/java/com/acme/portal/Authenticator.java` | Authentication orchestration and decision logic | Username canonicalization, rate limiter queries, dummy record PBKDF2 execution for absent users, synchronized decision flow. |
| `src/main/java/com/acme/portal/CredentialStore.java` | File-backed credential record storage and locking | POSIX permissions (`0600`) and parent directory checks, symlink refusal, bounded ASCII parsing, atomic file replacement, OS-level file locking. |
| `src/main/java/com/acme/portal/LoginGuard.java` | In-memory source and account rate limiting | Sliding-window source failure tracking, progressive backoff calculation, salted SHA-256 account key hashing, memory state capping. |
| `src/main/java/com/acme/portal/PasswordBlocklist.java` | Prohibited password hash filter for provisioning | SHA-256 hash list parsing, size and count bounds enforcement, immutable set lookup, password candidate digest zeroing. |
| `src/main/java/com/acme/portal/PasswordHasher.java` | PBKDF2-HMAC-SHA-256 password hashing utility | Cryptographically secure salt generation (`SecureRandom`), 600,000 PBKDF2 iterations, constant-time verification (`MessageDigest.isEqual`), buffer zeroing. |
| `src/test/java/com/acme/portal/SecurityTests.java` | Security regression test suite | Tests valid login, bad password denial, unknown user rejection, source throttling activation, and file permission enforcement. |
| `build.sh` | Build and test automation script | Shell execution under restrictive umask (`077`) and strict compiler error flags (`-Xlint:all -Werror`). |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: Applied to audit PBKDF2 iteration parameters, salt entropy, key derivation handling, constant-time comparisons, and sensitive memory zeroing in `PasswordHasher.java`, `Authenticator.java`, and `PasswordBlocklist.java`.
- `implementing-secret-scanning-with-gitleaks`: Applied to inspect the codebase and build scripts for hardcoded secrets, test credentials, or exposed tokens.
- `exploiting-race-condition-vulnerabilities`: Applied to evaluate file locking mechanisms, TOCTOU risks during file creation/replacement, and multi-process concurrency in `CredentialStore.java` and `Main.java`.
- `implementing-api-rate-limiting-and-throttling`: Applied to assess rate-limiting algorithms, state retention policies, exponential backoff, and exhaustion defenses in `LoginGuard.java` and `Authenticator.java`.
- General OWASP Top 10 / CWE knowledge (CWE-20, CWE-59, CWE-400, CWE-662, CWE-670, CWE-706, CWE-732): Applied to evaluate input validation, sentinel identifier handling, monotonic clock time arithmetic, and POSIX filesystem permission enforcement.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Permanent Lockout and Denial of Service via State Poisoning in Account Tracking | High | CWE-400 | `src/main/java/com/acme/portal/LoginGuard.java:49-55` |
| SEC-02 | Monotonic Clock Underflow Causing Permanent Startup Lockout | High | CWE-670 | `src/main/java/com/acme/portal/LoginGuard.java:30-33` |
| SEC-03 | Exclusive File Lock Held During Artificial Throttling Sleep | Medium | CWE-662 | `src/main/java/com/acme/portal/Main.java:71-76` |
| SEC-04 | Sentinel Identifier Collision and Unrecoverable Delay on Malformed Inputs | Medium | CWE-706 | `src/main/java/com/acme/portal/Authenticator.java:32` |
| SEC-05 | Account Failure Counter Escalation During Active Source Lockout | Low | CWE-307 | `src/main/java/com/acme/portal/Authenticator.java:42-48` |
| SEC-06 | Missing Parent Directory Security Validation in Password Blocklist Loader | Low | CWE-732 | `src/main/java/com/acme/portal/PasswordBlocklist.java:33-39` |

## 5. Detailed Findings

### SEC-01: Permanent Lockout and Denial of Service via State Poisoning in Account Tracking
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/acme/portal/LoginGuard.java:49-55`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/LoginGuard.java:49-55
        Key key = key(canonicalUsername);
        if (accountFailures.size() >= MAX_ACCOUNT_STATES && !accountFailures.containsKey(key)) {
            // Fail closed for account-spray storage exhaustion; the source limit still expires.
            sourceBlockedUntil = now + SOURCE_BLOCK.toNanos();
            return;
        }
        accountFailures.merge(key, 1, (oldValue, one) -> Math.min(oldValue + 1, 32));
```

**Why it is a problem:**
`accountFailures` stores failed attempt counts without timestamps, sliding windows, or time-to-live (TTL) expiration. Entries are only removed when `recordSuccess(canonicalUsername)` is invoked upon a successful authentication. If an attacker sprays 10,000 non-existent or arbitrary usernames over time, `accountFailures` reaches `MAX_ACCOUNT_STATES` (10,000). Because these usernames do not exist in the credential store, no successful login can ever occur to remove them.

Once the map reaches capacity, line 50 triggers on every subsequent failed attempt for any username not already in the set: it resets `sourceBlockedUntil` to 15 minutes into the future without adding the key. Consequently, a single mistyped password by any legitimate employee whose account is not present in the 10,000 keys immediately locks out the entire console for 15 minutes. This creates a permanent, irreversible denial of service.

**Fix:**
Track account failures with sliding-window timestamps or a bounded Least-Recently-Used (LRU) cache with time-to-live eviction, ensuring stale failures decay over time and cache saturation evicts the oldest entry rather than locking out the source:
```java
// src/main/java/com/acme/portal/LoginGuard.java
        Key key = key(canonicalUsername);
        pruneAccountFailures(now);
        if (accountFailures.size() >= MAX_ACCOUNT_STATES && !accountFailures.containsKey(key)) {
            evictOldestAccountFailure();
        }
        accountFailures.compute(key, (k, existing) -> {
            int count = (existing == null || now - existing.timestamp() >= ACCOUNT_WINDOW.toNanos())
                    ? 1 : Math.min(existing.count() + 1, 32);
            return new AccountFailureRecord(count, now);
        });
```

---

### SEC-02: Monotonic Clock Underflow Causing Permanent Startup Lockout
- **Severity:** High
- **CWE:** CWE-670: Always-Incorrect Control Flow Implementation
- **Location:** `src/main/java/com/acme/portal/LoginGuard.java:30-33`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/LoginGuard.java:30-33
    synchronized Decision beforeAttempt(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        boolean sourceAllowed = now - sourceBlockedUntil >= 0;
```

**Why it is a problem:**
The field `sourceBlockedUntil` is a `long` primitive initialized to `0L`. According to the Java SE specification for `System.nanoTime()`, the returned value represents nanoseconds since an arbitrary origin point, which may be in the future, meaning `System.nanoTime()` can legitimately return negative values.

On platforms or virtual machines where `System.nanoTime()` returns negative numbers, `now - sourceBlockedUntil` calculates `now - 0L = now < 0`. As a result, `sourceAllowed` evaluates to `false` immediately upon startup. The application will permanently reject every authentication attempt with "Access denied.", even though no failed logins have occurred.

**Fix:**
Track blocking state using an explicit boolean flag (`sourceBlocked`), or verify that `sourceBlocked` is active before comparing timestamps:
```java
// src/main/java/com/acme/portal/LoginGuard.java
    private boolean sourceBlocked = false;
    private long sourceBlockedUntil;

    synchronized Decision beforeAttempt(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        boolean sourceAllowed = !sourceBlocked || (now - sourceBlockedUntil >= 0);
        if (sourceAllowed) {
            sourceBlocked = false;
        }
```

---

### SEC-03: Exclusive File Lock Held During Artificial Throttling Sleep
- **Severity:** Medium
- **CWE:** CWE-662: Improper Synchronization
- **Location:** `src/main/java/com/acme/portal/Main.java:71-76`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:71-76
                try (CredentialStore.UpdateLock updateLock =
                        CredentialStore.lockForUpdate(STORE_PATH)) {
                    updateLock.requireHeld();
                    allowed = authenticator.authenticate(
                            CredentialStore.load(STORE_PATH), username, password);
                }
```

**Why it is a problem:**
In `Main.login`, `CredentialStore.lockForUpdate` opens the lock file with write access and acquires an exclusive OS file lock (`channel.lock()`). Inside this lock, `authenticator.authenticate` invokes `Thread.sleep(decision.accountDelayMillis())` (sleeping up to 2,000 ms) and computes PBKDF2 (600,000 iterations, requiring ~500–1,000 ms of CPU time).

Holding an exclusive write lock across artificial delay sleeps and heavy cryptography during a read-only authentication operation serializes all instances. As recommended in the documentation ("Run one supervised instance for each protected local console/source"), running multiple console verifiers causes any throttling delay on console 1 to completely stall authentication and provisioning on console 2.

**Fix:**
Acquire a shared read lock solely while loading the credential store, release the file lock before entering `Authenticator.authenticate`, and execute artificial sleep delays and cryptographic computations outside of filesystem locks:
```java
// src/main/java/com/acme/portal/Main.java
                CredentialStore store;
                try (CredentialStore.ReadLock readLock = CredentialStore.lockForRead(STORE_PATH)) {
                    readLock.requireHeld();
                    store = CredentialStore.load(STORE_PATH);
                }
                allowed = authenticator.authenticate(store, username, password);
```

---

### SEC-04: Sentinel Identifier Collision and Unrecoverable Delay on Malformed Inputs
- **Severity:** Medium
- **CWE:** CWE-706: Use of Incorrectly-Resolved Name or Reference
- **Location:** `src/main/java/com/acme/portal/Authenticator.java:32`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Authenticator.java:32
        String guardName = usernameValid ? canonical : "invalid-input";
```

**Why it is a problem:**
When a username fails validation (`canonical == null`), `Authenticator` assigns `guardName = "invalid-input"`. However, `"invalid-input"` satisfies the username regex `[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?` and represents a valid user account. If an employee with that username exists, invalid input from any user will increment the failure count for that account.

Furthermore, if `"invalid-input"` is not a provisioned user, no authentication attempt can ever succeed as `"invalid-input"`, meaning `guard.recordSuccess("invalid-input")` is never called. Once 5 invalid username attempts occur across the lifetime of the process, `"invalid-input"` accumulates the maximum 2,000 ms penalty permanently. Every subsequent malformed or empty username will trigger a 2-second sleep under the global lock, stalling the system.

**Fix:**
Do not map invalid usernames to an in-namespace string identifier. Reject invalid usernames immediately, perform the dummy verification work, and record only source-level failures without accumulating permanent account-level backoff:
```java
// src/main/java/com/acme/portal/Authenticator.java
        if (!usernameValid) {
            LoginGuard.Decision decision = guard.beforeAttempt(null);
            PasswordHasher.verify(DUMMY_PASSWORD, dummyRecord);
            guard.recordFailure(null);
            return false;
        }
        String guardName = canonical;
```

---

### SEC-05: Account Failure Counter Escalation During Active Source Lockout
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/acme/portal/Authenticator.java:42-48`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Authenticator.java:42-48
        boolean allowed = decision.sourceAllowed() && usernameValid && passwordValid
                && actual != null && passwordMatches;
        if (allowed) {
            guard.recordSuccess(canonical);
        } else {
            guard.recordFailure(guardName);
        }
```

**Why it is a problem:**
When `decision.sourceAllowed()` is `false` (the source console is currently blocked), line 42 forces `allowed = false`. When any attempt is made while blocked, line 47 calls `guard.recordFailure(guardName)`.

This causes account-level failure counts to increment even when valid credentials are submitted, or when targeted employee usernames are entered by an attacker during the 15-minute source block. An attacker can trigger a source block and then input targeted employee usernames 5+ times, escalating those employees' accounts into maximum 2,000 ms backoff delays that persist after the source block expires.

**Fix:**
Do not increment account-level failure counters when an authentication attempt is rejected solely because the source is already blocked:
```java
// src/main/java/com/acme/portal/Authenticator.java
        boolean allowed = decision.sourceAllowed() && usernameValid && passwordValid
                && actual != null && passwordMatches;
        if (allowed) {
            guard.recordSuccess(canonical);
        } else if (decision.sourceAllowed()) {
            guard.recordFailure(guardName);
        }
```

---

### SEC-06: Missing Parent Directory Security Validation in Password Blocklist Loader
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/acme/portal/PasswordBlocklist.java:33-39`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/PasswordBlocklist.java:33-39
    static PasswordBlocklist load() throws IOException {
        if (!Files.isRegularFile(PATH, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(PATH)
                || !Files.getPosixFilePermissions(PATH, LinkOption.NOFOLLOW_LINKS)
                        .equals(PosixFilePermissions.fromString("rw-------"))) {
            throw new IOException("password blocklist is unsafe");
        }
```

**Why it is a problem:**
While `CredentialStore` validates both the target file and its parent directory (`validateParent`), `PasswordBlocklist.load()` only verifies the attributes of the blocklist file itself. It fails to verify that the parent directory (`/var/lib/internal-employee-portal`) is non-symbolic and not group- or world-writable. If the parent directory has permissive permissions, an untrusted local user could unlink or substitute the blocklist file.

**Fix:**
Enforce parent directory validation prior to opening the blocklist file, ensuring consistent POSIX directory permission checks across all storage components:
```java
// src/main/java/com/acme/portal/PasswordBlocklist.java
    static PasswordBlocklist load() throws IOException {
        validateParent(PATH);
        if (!Files.isRegularFile(PATH, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(PATH)
                || !Files.getPosixFilePermissions(PATH, LinkOption.NOFOLLOW_LINKS)
                        .equals(PosixFilePermissions.fromString("rw-------"))) {
            throw new IOException("password blocklist is unsafe");
        }
```

## 6. Verified Controls and Checks With No Finding

- **Password Hashing & Derivation (`PasswordHasher.java:11-32`):** Verified usage of `PBKDF2WithHmacSHA256` with 600,000 iterations, a 16-byte cryptographically secure random salt generated via `SecureRandom`, and a 256-bit derived key, matching OWASP Password Storage guidelines.
- **Constant-Time Digest Verification (`PasswordHasher.java:38`):** Verified that candidate password hashes are compared against stored hashes using `MessageDigest.isEqual`, preventing byte-by-byte timing side channels.
- **Sensitive Memory Sanitization (`Main.java:78, 121`, `Authenticator.java:19-20`, `PasswordBlocklist.java:69-70`, `PasswordHasher.java:30, 40`):** Verified that plaintext password `char[]` arrays, derived hash byte arrays, and `PBEKeySpec` instances are wiped with `Arrays.fill` in `finally` blocks immediately after use.
- **Dummy Record Work Balancing (`Authenticator.java:16-21, 38-41`):** Verified that invalid usernames or unprovisioned accounts execute full PBKDF2 hash computations against an in-memory `dummyRecord`, equalizing response times and preventing account enumeration.
- **Atomic File Writing (`CredentialStore.java:172-204`):** Verified that updates to the credential store write to a temporary file in the same directory (`PosixFilePermissions.fromString("rw-------")`) and replace the target atomically via `StandardCopyOption.ATOMIC_MOVE`, preventing file truncation or partial reads.
- **POSIX Permission Enforcement (`CredentialStore.java:32-36, 115-117, 215-219`):** Verified that the credential store file enforces strict `0600` permissions, and its parent directory is checked to be non-symbolic and not group- or world-writable.
- **Username Syntax Allowlisting (`CredentialStore.java:31`, `Authenticator.java:52-58`):** Verified that usernames are restricted to 3–64 characters matching `^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?$`, preventing delimiter injection (`:`) or path traversal sequences.
- **Interactive Console Enforcement (`Main.java:28`):** Verified that execution requires an attached `System.console()`, failing closed if standard input is piped or redirected, preventing password leakage into shell history.
- **Absence of Hardcoded Secrets:** Verified through static pattern scanning that no plaintext passwords, hardcoded credentials, or private cryptographic keys exist in the repository.
