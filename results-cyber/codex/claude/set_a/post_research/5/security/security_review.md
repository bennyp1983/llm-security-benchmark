# Security Review: Employee Portal Authentication

## 1. Executive Summary
This Java 17 component authenticates employees against an owner-only, file-backed credential store; applies per-account and per-source attempt limits; hashes passwords with PBKDF2-HMAC-SHA256; issues server-side sessions; builds hardened session cookies; and writes a redacted audit log. The review found five vulnerabilities: a high-severity file identity race that can enable credential-store substitution, three medium-severity weaknesses involving a spoofable rate-limit key, observable KDF timing differences, and weak enrollment requirements, plus a low-severity race in session-cap enforcement. The implementation otherwise has unusually strong input validation, secret redaction, fail-closed authentication, cryptographic randomness, cookie settings, and atomic attempt accounting.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `build.sh` | Compiles main and test Java sources. | Uses only the installed JDK and downloads no dependencies; its command substitutions process repository-controlled source filenames. |
| `src/main/java/com/example/portal/auth/AttemptCounters.java` | Implements shared attempt-window and temporary-restriction rules. | Bounds tracked keys, prunes stale counters, handles clock shifts, and consumes slots before authentication. |
| `src/main/java/com/example/portal/auth/AttemptLimiter.java` | Defines account/source rate-limit contracts and defaults. | Sets attempt budgets, restriction periods, capacity limits, and fail-closed decisions. |
| `src/main/java/com/example/portal/auth/AuditLog.java` | Writes authentication audit events. | Masks identifiers, removes control characters, bounds fields, and opens an owner-only append target. |
| `src/main/java/com/example/portal/auth/AuthResult.java` | Represents public authentication outcomes. | Uses one generic denial message and redacts the bearer token from `toString()`. |
| `src/main/java/com/example/portal/auth/Authenticator.java` | Orchestrates validation, throttling, verification, and session creation. | Fails closed, performs decoy KDF work, and grants only after server-side credential verification. |
| `src/main/java/com/example/portal/auth/CredentialStore.java` | Defines authoritative credential lookup. | Keeps authentication decisions tied to server-side state. |
| `src/main/java/com/example/portal/auth/FileAttemptLimiter.java` | Persists attempt counters across CLI processes. | Uses process and file locks, validates persisted records, bounds storage, and denies when tracking is unavailable. |
| `src/main/java/com/example/portal/auth/FileCredentialStore.java` | Loads password records into an immutable map. | Checks file ownership/mode, bounds file and record sizes, validates every record, and rejects duplicate entries. |
| `src/main/java/com/example/portal/auth/InMemoryAttemptLimiter.java` | Maintains counters for one long-lived JVM. | Serializes account/source updates under one lock and caps map growth. |
| `src/main/java/com/example/portal/auth/InputPolicy.java` | Validates usernames, passwords, and source identifiers. | Applies canonicalization, allowlists, and length limits at trust boundaries. |
| `src/main/java/com/example/portal/auth/PasswordHasher.java` | Hashes and verifies passwords. | Uses salted PBKDF2-HMAC-SHA256, bounded work factors, constant-time digest comparison, and decoy work. |
| `src/main/java/com/example/portal/auth/PortalCli.java` | Provides `login` and `enroll` commands. | Reads passwords outside command-line arguments, clears buffers, chooses security-file paths, and exposes a source-ID option. |
| `src/main/java/com/example/portal/auth/PrivateFiles.java` | Creates and validates sensitive files. | Enforces regular-file, owner, and mode checks, but separates those checks from later opens. |
| `src/main/java/com/example/portal/auth/Session.java` | Carries non-secret server-side session metadata. | Omits the bearer token and redacts identity details from `toString()`. |
| `src/main/java/com/example/portal/auth/SessionCookie.java` | Constructs and clears session cookies. | Enforces token shape, `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, host-only scope, and `Path=/`. |
| `src/main/java/com/example/portal/auth/SessionManager.java` | Creates, validates, expires, and revokes sessions. | Uses 256-bit CSPRNG tokens, stores SHA-256 token digests, refreshes idle expiry atomically, and attempts to cap sessions. |
| `src/main/java/com/example/portal/auth/ValidationException.java` | Represents rejected untrusted input. | Separates detailed validation failures from generic user-facing authentication results. |
| `src/test/java/com/example/portal/auth/SelfTest.java` | Defines adversarial regression tests and fixtures. | Covers denial behavior, timing, throttling, concurrency, file modes, token handling, cookies, logs, and malformed input; it does not cover the findings below. |
| `out/classes/**/*.class`, `out/test-classes/**/*.class` | Precompiled main and self-test artifacts. | Static constant-pool inspection showed the expected source filenames, classes, methods, JDK APIs, and redacted messages; these artifacts were not loaded or executed. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: used to inventory every source file, identify trust boundaries, route the review to specialized skills, and require CWE/file-line evidence.
- `performing-cryptographic-audit-of-application`: applied to PBKDF2 parameters, salts, token hashing, constant-time comparison, hardcoded-secret checks, and random-number generation.
- `testing-api-authentication-weaknesses`: applied to credential verification, enumeration resistance, password policy, token validation, expiration, revocation, and leakage.
- `implementing-api-rate-limiting-and-throttling`: applied to account/source budgets, persistence, capacity bounds, atomic updates, and fail-closed behavior.
- `performing-api-rate-limiting-bypass`: applied to source-key spoofing, identifier rotation, account canonicalization, and concurrent limit bypasses.
- `exploiting-race-condition-vulnerabilities`: applied to attempt accounting, duplicate enrollment, file check/use sequences, and session-cap enforcement.
- `testing-for-sensitive-data-exposure`: applied to source/log scanning for secrets, token and hash exposure, masking, error detail, file permissions, and cookie storage.
- General OWASP Top 10 / CWE knowledge: applied to Java/POSIX symlink-safe file opening, local filesystem permissions, shell build behavior, log injection, resource bounds, and classes of injection/deserialization/network risk for which no closer library skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Security files are opened after a non-atomic path check | High | CWE-363 | `src/main/java/com/example/portal/auth/FileCredentialStore.java:58-67` |
| SEC-02 | Caller-controlled source identifiers bypass the source attempt budget | Medium | CWE-345 | `src/main/java/com/example/portal/auth/PortalCli.java:116` |
| SEC-03 | Variable PBKDF2 costs reintroduce account-enumeration timing | Medium | CWE-208 | `src/main/java/com/example/portal/auth/PasswordHasher.java:92-116` |
| SEC-04 | Enrollment accepts weak and breached passwords | Medium | CWE-521 | `src/main/java/com/example/portal/auth/InputPolicy.java:93-105` |
| SEC-05 | Session capacity enforcement is not atomic | Low | CWE-362 | `src/main/java/com/example/portal/auth/SessionManager.java:92-107` |

## 5. Detailed Findings

### SEC-01: Security files are opened after a non-atomic path check
- **Severity:** High
- **CWE:** CWE-363: Race Condition Enabling Link Following
- **Location:** `src/main/java/com/example/portal/auth/FileCredentialStore.java:58-67` (also `AuditLog.java:54-61`, `FileAttemptLimiter.java:155-165`, and `PortalCli.java:212-228`)

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/FileCredentialStore.java:58-67
    public static FileCredentialStore load(Path path, AuditLog audit) throws IOException, ValidationException {
        Path resolved = path.toAbsolutePath().normalize();
        PrivateFiles.requireOwnerOnly(resolved, "credential file");

        long size = Files.size(resolved);
        if (size > MAX_FILE_BYTES) {
            throw new ValidationException("credential file exceeds the maximum accepted size");
        }

        List<String> lines = Files.readAllLines(resolved, StandardCharsets.UTF_8);
```

**Why it is a problem:** `requireOwnerOnly` validates one filesystem object, but `Files.size` and `Files.readAllLines` resolve the pathname again. A local attacker who can modify the containing directory can replace the checked entry with a symlink or attacker-controlled file between those operations, causing authentication to load a different credential store. This is feasible in group-writable directories because `PrivateFiles.java:83-88` rejects only `OTHERS_WRITE`, not `GROUP_WRITE`. The same check-then-open pattern affects the audit log and attempt state; enrollment is still weaker because its append path does not call `requireOwnerOnly` after `createIfAbsent`. Consequences include authentication bypass with attacker-selected hashes, rate-limit reset or denial, disclosure of hashes, and writes to unintended files. Path normalization and `NOFOLLOW_LINKS` during the earlier check do not bind later opens to the checked inode.

**Fix:** Require the containing directory to be owned by the portal user and not writable by group or others, open every sensitive target with `NOFOLLOW_LINKS`, and perform validation/opening through one shared helper. Where the platform permits, use descriptor-relative APIs such as `SecureDirectoryStream`; otherwise fail closed rather than claiming the check is race-free. Revalidate existing stores during enrollment as well.
```java
static void requireProtectedParent(Path path, String kind)
        throws IOException, ValidationException {
    Path parent = path.toAbsolutePath().normalize().getParent();
    if (parent == null) {
        throw new ValidationException(kind + " has no parent directory");
    }
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
            parent, LinkOption.NOFOLLOW_LINKS);
    if (permissions.contains(PosixFilePermission.GROUP_WRITE)
            || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
        throw new ValidationException(kind + " sits in a directory writable by another account");
    }
    String owner = Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).getName();
    if (!owner.equals(System.getProperty("user.name"))) {
        throw new ValidationException(kind + " directory is not owned by the portal user");
    }
}

Path resolved = path.toAbsolutePath().normalize();
PrivateFiles.requireProtectedParent(resolved, "credential file");
PrivateFiles.requireOwnerOnly(resolved, "credential file");
try (FileChannel channel = FileChannel.open(
        resolved, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
    // Enforce the size limit and parse UTF-8 records from this already-open channel.
}
```

### SEC-02: Caller-controlled source identifiers bypass the source attempt budget
- **Severity:** Medium
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `src/main/java/com/example/portal/auth/PortalCli.java:116`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PortalCli.java:116
        String source = option(arguments, "--source").orElse(localSource());
```

**Why it is a problem:** An unauthenticated caller can choose a fresh syntactically valid `--source` value for every invocation. Validation in `InputPolicy` proves only shape, not origin, so rotating the value gives every password-spraying attempt a new 50-attempt source bucket. The five-attempt per-account budget still limits focused guessing, but the independent source budget advertised as the defense against spraying across the employee directory is ineffective on this CLI path. The public `Authenticator.authenticate(..., rawSource)` API creates the same integration hazard if a web front end passes a client-controlled forwarding header.

**Fix:** Remove the source override from the login CLI and derive the key from trusted transport or operating-system context. A web adapter should use the socket peer address, or accept a proxy-provided address only after the edge proxy strips inbound copies and the application authenticates that proxy.
```java
// A local console has one authoritative source bucket; do not accept --source on login.
String source = localSource();
```

### SEC-03: Variable PBKDF2 costs reintroduce account-enumeration timing
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/portal/auth/PasswordHasher.java:92-116`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PasswordHasher.java:92-116
    public boolean verify(char[] password, StoredHash stored) {
        byte[] derived = derive(password, stored.salt(), stored.iterations());
        try {
            return MessageDigest.isEqual(derived, stored.hash());
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /**
     * Runs one derivation whose result is discarded.
     *
     * <p>Called when there is no stored hash to verify against -- an unknown username, a malformed
     * record, or an account under restriction. Without it, "no such account" would return in
     * microseconds while "wrong password" took hundreds of milliseconds, and that difference alone
     * enumerates the employee directory.
     */
    public void performDecoyWork() {
        char[] decoy = new char[24];
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        for (int i = 0; i < decoy.length; i++) {
            decoy[i] = (char) ('a' + random.nextInt(26));
        }
        byte[] derived = derive(decoy, salt, iterations);
```

**Why it is a problem:** Real verification uses the work factor embedded in each record, accepted anywhere from 100,000 to 10,000,000 iterations, while an unknown or restricted account uses the hasher instance's current work factor. PBKDF2 duration is approximately proportional to that value. Legacy records after a work-factor upgrade, imported records, or high-cost records therefore respond observably faster or slower than unknown accounts. The generic response text and constant-time digest comparison do not remove this whole-request timing oracle.

**Fix:** Keep all active records at one uniform verification cost and migrate the credential store atomically before changing that cost; alternatively pad the complete authentication operation to a measured constant-time envelope. The simplest safe record policy is to reject non-current work factors at load time rather than accepting a broad range silently.
```java
int iterations = Integer.parseInt(parts[1]);
if (iterations != DEFAULT_ITERATIONS) {
    throw new ValidationException(
            "stored hash requires offline migration to the current work factor");
}

// Both genuine verification and decoy verification now use DEFAULT_ITERATIONS.
byte[] derived = derive(password, stored.salt(), DEFAULT_ITERATIONS);
```

### SEC-04: Enrollment accepts weak and breached passwords
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/example/portal/auth/InputPolicy.java:93-105`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/InputPolicy.java:93-105
    public static void requireEnrollablePassword(char[] password) throws ValidationException {
        if (password == null) {
            throw new ValidationException("password is absent");
        }
        if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException(
                    "password must be between " + PASSWORD_MIN_LENGTH + " and " + PASSWORD_MAX_LENGTH + " characters");
        }
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                throw new ValidationException("password contains a control character");
            }
        }
```

**Why it is a problem:** The component is password-only and accepts any printable 12-character value, including common or previously breached passwords such as predictable repeated or keyboard patterns. It has no compromised-password blocklist and no MFA. Current OWASP authentication guidance treats passwords shorter than 15 characters as weak when MFA is absent and recommends blocking common and breached values. PBKDF2 slows offline guesses but cannot compensate for guessable credentials.

**Fix:** Raise the no-MFA minimum to at least 15 characters and check candidates against a locally hosted, regularly refreshed breached/common-password blocklist. Keep the existing generous maximum and do not add composition rules. The blocklist interface should accept a character array so callers do not need to create an uncleared password `String`.
```java
public static final int PASSWORD_MIN_LENGTH = 15;

@FunctionalInterface
public interface PasswordBlocklist {
    boolean contains(char[] password);
}

public static void requireEnrollablePassword(
        char[] password, PasswordBlocklist blocklist) throws ValidationException {
    if (password == null
            || password.length < PASSWORD_MIN_LENGTH
            || password.length > PASSWORD_MAX_LENGTH) {
        throw new ValidationException("password length out of range");
    }
    for (char c : password) {
        if (c < 0x20 || c == 0x7F) {
            throw new ValidationException("password contains a control character");
        }
    }
    if (blocklist.contains(password)) {
        throw new ValidationException("password appears in the compromised-password blocklist");
    }
}
```

### SEC-05: Session capacity enforcement is not atomic
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/portal/auth/SessionManager.java:92-107`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/SessionManager.java:92-107
    public Issued create(String username) {
        if (sessions.size() >= MAX_SESSIONS) {
            pruneExpired();
            if (sessions.size() >= MAX_SESSIONS) {
                throw new IllegalStateException("session capacity exhausted");
            }
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        java.util.Arrays.fill(raw, (byte) 0);

        String digest = digestOf(token);
        Instant now = Instant.now();
        Entry entry = new Entry(username, now, now.plus(absoluteLifetime), now.plus(idleTimeout));
        if (sessions.putIfAbsent(digest, entry) != null) {
```

**Why it is a problem:** `ConcurrentHashMap` makes each map operation thread-safe, but it does not make `size`/prune/second-`size`/`putIfAbsent` one atomic capacity reservation. When the table is just below 20,000 entries, many simultaneous successful logins can all observe available capacity and insert, exceeding the stated memory bound. The overshoot is limited by concurrent creation volume, so this is a low-severity authenticated resource-exhaustion issue rather than an unlimited leak.

**Fix:** Serialize session creation (removals may remain concurrent because they only decrease occupancy), or reserve capacity with a semaphore/counter whose release is coupled to every removal path. Synchronizing this short path is sufficient and does not serialize password derivation, which occurs before session creation.
```java
public synchronized Issued create(String username) {
    if (sessions.size() >= MAX_SESSIONS) {
        pruneExpired();
        if (sessions.size() >= MAX_SESSIONS) {
            throw new IllegalStateException("session capacity exhausted");
        }
    }
    byte[] raw = new byte[TOKEN_BYTES];
    random.nextBytes(raw);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    java.util.Arrays.fill(raw, (byte) 0);

    String digest = digestOf(token);
    Instant now = Instant.now();
    Entry entry = new Entry(username, now, now.plus(absoluteLifetime), now.plus(idleTimeout));
    if (sessions.putIfAbsent(digest, entry) != null) {
        throw new IllegalStateException("session identifier collision");
    }
    return new Issued(token, new Session(username, referenceOf(digest), now, entry.absoluteExpiry));
}
```

## 6. Verified Controls and Checks With No Finding
- Authentication decision and fail-closed behavior: `Authenticator.java:66-131` validates first, reserves a slot before KDF work, verifies against `CredentialStore`, and grants only after an explicit match; limiter and session failures deny access.
- User-visible enumeration resistance: `AuthResult.java:19-42` returns the same message and no token for every denial; the residual KDF-cost timing exception is reported as SEC-03.
- Username and input validation: `InputPolicy.java:45-67` canonicalizes usernames into one account bucket and allowlists characters; password, source, token, file, record, and console-input sizes are bounded.
- Password storage cryptography: `PasswordHasher.java:73-99` uses a fresh 128-bit `SecureRandom` salt, PBKDF2-HMAC-SHA256 with a 600,000-iteration production default, a 256-bit result, defensive array copies, and `MessageDigest.isEqual`.
- Hardcoded secrets: no working credentials, private keys, API keys, fixed salts, default passwords, or predictable session secrets were found in source, documentation, build logic, or inspected class constants.
- Secret lifecycle and rendering: password and derived-key arrays are cleared where owned; `PasswordHasher.StoredHash`, `AuthResult`, `Session`, and `SessionManager.Issued` do not render hashes or bearer tokens.
- Session token quality and validation: `SessionManager.java:92-146` generates 256 random bits with `SecureRandom`, stores only SHA-256 digests, validates against server-side state, enforces idle and absolute expiry, refreshes atomically with `compute`, and supports revocation.
- Cookie hardening: `SessionCookie.java:50-65` validates the value and sets `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, host-only scope, `Path=/`, and bounded `Max-Age` on set and clear paths.
- Attempt accounting: `InMemoryAttemptLimiter.java:39-78` and `FileAttemptLimiter.java:81-132` serialize read/decide/update operations; the file implementation also uses an exclusive cross-process lock, persists counters, bounds keys/files, and fails closed when unavailable.
- Lockout denial-of-service controls: source slots are consumed before account slots, restrictions expire, invalid syntax does not burn an account budget, and successful authentication clears only the appropriate account attempt state.
- Audit injection and direct leakage: `AuditLog.java:80-145` bounds fields, collapses control characters, masks account/source values, and never receives passwords, hashes, or tokens from reviewed production call sites; filesystem identity risk is reported in SEC-01.
- Credential-record validation: `FileCredentialStore.java:62-106` bounds file size and record count and validates username, scheme, Base64, salt/hash sizes, and PBKDF2 work-factor range before use; duplicate records do not overwrite the first parsed credential.
- Command, query, template, and deserialization injection: no OS-command execution, SQL/database construction, template rendering, unsafe object deserialization, dynamic class loading, or outbound network operation exists in the reviewed production code.
- Build/dependency surface: `build.sh` invokes only local JDK tools, uses no package manager or network download, and introduces no third-party dependency or install hook.
- Test isolation: `SelfTest.java` contains test-only passwords and filesystem mutations in private temporary fixtures; those values are not production defaults and no test helper is referenced by main code.
