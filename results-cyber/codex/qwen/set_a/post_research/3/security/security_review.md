# Security Review: Java CLI Authentication Service

## 1. Executive Summary
The component is a Java command-line authentication service backed by an embedded H2 database. It validates email/password input, stores PBKDF2-HMAC-SHA256 password verifiers, maintains transactional per-identity and per-source attempt counters, issues hashed server-side session tokens, and writes a private audit log.

Five vulnerabilities were identified. The most important are that the source-rate-limit key comes from a caller-controlled environment variable and that successful authentication refunds only the identity counter, allowing valid logins to exhaust the shared source budget and deny all subsequent users. Password hashes may also be created with only 100,000 iterations (210,000 by default), below the current 600,000-iteration OWASP recommendation for PBKDF2-HMAC-SHA256. In addition, the audit-log size cap resets for every CLI process, and unsalted SHA-256 email identifiers can be reversed by dictionary attack after database disclosure. No SQL injection, authentication bypass, predictable session token, plaintext password storage, or log-injection issue was found.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `.probe/Probe.java` | Standalone H2 and PBKDF2 investigation utility | Exercises JDBC URL options, SQL locking, file modes, and KDF timing; it is not called by the application. |
| `src/main/java/com/example/auth/AccountSeeder.java` | Creates new credential records | Validates credentials, salts and hashes passwords, refuses duplicate accounts, and wipes derived material. |
| `src/main/java/com/example/auth/AuthService.java` | Makes login decisions | Normalizes identities, reserves rate-limit budgets, compares password hashes, issues sessions, pads response time, and hashes email identifiers. |
| `src/main/java/com/example/auth/Config.java` | Loads environment configuration | Accepts database credentials, paths, table names, rate limits, source labels, KDF cost, session TTL, and output controls. |
| `src/main/java/com/example/auth/CryptoUtils.java` | Supplies cryptographic helpers | Uses SHA-256, `SecureRandom`, hex conversion, fixed-length secret comparison, and buffer wiping. |
| `src/main/java/com/example/auth/Database.java` | Owns H2 connections and SQL | Constructs the JDBC URL, creates schema, uses prepared statements, validates credential rows, and hardens database files. |
| `src/main/java/com/example/auth/DbFiles.java` | Creates and hardens sensitive files | Creates files/directories with owner-only POSIX permissions and refuses replacement. |
| `src/main/java/com/example/auth/DbPathGuard.java` | Validates sensitive filesystem paths | Rejects symlinks, non-regular files, foreign ownership, and group/world access. |
| `src/main/java/com/example/auth/InputValidator.java` | Centralizes validation | Bounds and allowlists emails, passwords, session tokens, SQL identifiers, source labels, integers, booleans, and database paths. |
| `src/main/java/com/example/auth/LogWriter.java` | Writes the audit trail | Masks identities, rejects unsafe log characters, appends to a private file, and attempts to cap output volume. |
| `src/main/java/com/example/auth/Main.java` | Implements the CLI boundary | Reads bounded UTF-8 input, obtains secrets without argv exposure, renders generic outcomes, and controls optional session emission. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Derives password verifiers | Uses salted PBKDF2-HMAC-SHA256 with configurable iterations and validates stored hash parameters. |
| `src/main/java/com/example/auth/PosixPermissions.java` | Defines file modes | Provides the owner-only `0600` and `0700` permission sets. |
| `src/main/java/com/example/auth/SessionStore.java` | Persists sessions | Generates 256-bit tokens, stores only SHA-256 token hashes, verifies expiry, and atomically revokes sessions. |
| `src/main/java/com/example/auth/ThrottleStore.java` | Persists rate-limit state | Atomically reserves fixed-window identity/source budgets with row locks and refunds counters. |
| `src/test/java/com/example/auth/AllTests.java` | Unit and source-invariant suite | Tests input validation, cryptographic helpers, log safety, configuration, and SQL/source-code invariants. |
| `src/test/java/com/example/auth/AuthServiceTests.java` | Authentication integration suite | Tests outcomes, timing, throttling, tampered rows, sessions, failure handling, and audit content. |
| `src/test/java/com/example/auth/E2ETests.java` | Forked-JVM CLI suite | Tests observable output, hostile stdin, files, token emission, and concurrent process behavior. |
| `src/test/java/com/example/auth/T.java` | Test harness | Manages assertions, private scratch directories, cleanup, and timing statistics. |
| `out/main/**/*.class`, `out/test/**/*.class`, `.probe/Probe.class` | Compiled Java artifacts | Binary counterparts of the reviewed Java sources; no binary was executed or imported. |
| `libs/h2-2.3.232.jar` | Embedded SQL engine dependency | Third-party binary used through JDBC; it was not executed or imported. Its SHA-1 and SHA-256 match the supplied sidecars. |
| `libs/h2-2.3.232.jar.sha1`, `libs/h2-2.3.232.jar.sha256` | Dependency integrity metadata | Pin the bundled H2 JAR hashes. |
| `THREAT-MODEL.md` | Design threat model | Documents trust boundaries, intended controls, and accepted residual risks used to validate implementation intent. |
| `prompt.txt`, `prompt_hash.txt` | Generation input and integrity metadata | Describe the requested security properties; contain no runtime code. |
| `result.md`, `return.txt` | Generation-run metadata/transcript | Non-runtime material; reviewed only for scope/context and not treated as application code. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every source file, identify security-relevant behaviours, select specialized reviews, and require concrete CWE/file-line evidence.
- `testing-api-authentication-weaknesses`: Applied to password policy, account enumeration, server-side session validation, token entropy/expiry/revocation, credential leakage, and fail-closed authentication paths.
- `implementing-api-rate-limiting-and-throttling`: Applied to source/identity key selection, fixed-window semantics, shared persistent state, transaction atomicity, counter recovery, and denial-of-service properties.
- `performing-cryptographic-audit-of-application`: Applied to password KDF choice and work factor, salt/RNG quality, constant-time comparisons, hardcoded secrets, and hash use.
- `exploiting-sql-injection-vulnerabilities`: Applied statically to every SQL construction and bind site, including identifiers, values, JDBC URL injection, and second-order use of stored values; no code was executed.
- General OWASP Top 10 / CWE knowledge: Applied to filesystem/symlink handling, audit-log injection and resource exhaustion, sensitive-data minimization, configuration trust, concurrency, error disclosure, and third-party artifacts where no closer skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Caller-controlled source identifier bypasses spray limiting | Medium | CWE-807 | `Config.java:154-159`, `AuthService.java:130-135` |
| SEC-02 | Successful logins exhaust the shared source budget | Medium | CWE-400 | `AuthService.java:272-290` |
| SEC-03 | PBKDF2 work factor is below current guidance | Medium | CWE-916 | `PasswordHasher.java:29-30`, `Config.java:39` |
| SEC-04 | Audit-log byte cap resets on every process invocation | Medium | CWE-400 | `LogWriter.java:65-72`, `LogWriter.java:92-93` |
| SEC-05 | Unsalted email hashes permit offline identity recovery | Low | CWE-759 | `AuthService.java:182-185` |

## 5. Detailed Findings

### SEC-01: Caller-controlled source identifier bypasses spray limiting
- **Severity:** Medium
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `Config.java:154-159`, `AuthService.java:130-135`

**Vulnerable code:**
```java
// Config.java:154-159
        String sourceId;
        try {
            sourceId = InputValidator.requireSourceId(
                    orDefault(env.get(ENV_SOURCE_ID), DEFAULT_SOURCE_ID));
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("source_" + e.getMessage());
        }
```
```java
// AuthService.java:130-135
            List<ThrottleStore.BudgetKey> budgets =
                    ThrottleStore.attemptBudgets(identityHash, config.sourceId(), config);
            boolean slot;
            boolean budgetKnown = true;
            try {
                slot = throttles.reserve(budgets, clock.epochMillis());
```

**Why it is a problem:** `AUTH_SOURCE_ID` is an environment value and the threat model explicitly treats it as spoofable. Character validation prevents injection but does not establish provenance. A caller that can launch the CLI repeatedly can choose a fresh valid source label for every attempt, creating a fresh source budget each time. The per-identity limit still restricts guesses against one account, but the intended source-wide protection against password spraying and broad account lockout is bypassed. This contradicts the code's own rule that attacker-controlled input must not decide a security outcome without validation against trusted server-side state.

**Fix:** Do not accept the rate-limit source key from client-controlled configuration. For this local CLI, bind it to a server-owned constant. If the code is wrapped by a network service, derive the key from trusted connection state (for example, the socket peer address after validating any proxy chain) and pass that trusted value separately from request/configuration data.
```java
private static final String TRUSTED_SOURCE_ID = "local-cli";

List<ThrottleStore.BudgetKey> budgets = ThrottleStore.attemptBudgets(
        identityHash, TRUSTED_SOURCE_ID, config);
```

### SEC-02: Successful logins exhaust the shared source budget
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `AuthService.java:272-290`

**Vulnerable code:**
```java
// AuthService.java:272-290
    private String grant(long identityId, String identityHash, String masked) {
        String token;
        try {
            token = sessions.issue(identityId, config.sessionTtlSec(), config.sourceId());
        } catch (Database.StorageException e) {
            logDbFailure(e);
            return null;
        }
        try {
            throttles.refund(ThrottleStore.identityBudget(identityHash,
                    config.identityMaxFailures(), config.identityWindowSec()), clock.epochMillis());
            log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
        } catch (Database.StorageException e) {
            // The refund is a courtesy to the legitimate owner. Failing to refund must not revoke an
            // otherwise valid session, and must not be silent.
            logDbFailure(e);
        }
        log.log(LogWriter.Event.SESSION_ISSUED, masked, 0);
        return token;
    }
```

**Why it is a problem:** Every attempt reserves both the identity and source budgets, but the successful path refunds only the identity budget. With the default configuration, 120 successful logins from the shared `local-cli` source within 15 minutes consume the source quota; subsequent users are denied even with correct passwords. A user with valid credentials can deliberately trigger this global lockout, and ordinary legitimate activity can trigger it accidentally. The comments in `ThrottleStore` state that a successful login should consume no source slot, so this is an implementation defect rather than an intentional policy.

**Fix:** Refund every budget charged by the successful attempt, ideally in one transaction so the two counters cannot diverge. The source key must be the trusted key described in SEC-01.
```java
List<ThrottleStore.BudgetKey> charged = ThrottleStore.attemptBudgets(
        identityHash, TRUSTED_SOURCE_ID, config);
try {
    throttles.refundAll(charged, clock.epochMillis());
    log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
} catch (Database.StorageException e) {
    logDbFailure(e);
}
```

### SEC-03: PBKDF2 work factor is below current guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `PasswordHasher.java:29-30`, `Config.java:39`

**Vulnerable code:**
```java
// PasswordHasher.java:29-30
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 1_500_000;
```
```java
// Config.java:39
    static final int DEFAULT_ITERATIONS = 210_000;
```

**Why it is a problem:** The application permits PBKDF2-HMAC-SHA256 verifiers at 100,000 iterations and creates them at 210,000 iterations by default. The current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256. Rate limiting does not mitigate an offline attack after database disclosure, and the code acknowledges that H2 file contents may be attacked offline. The low floor also allows an operator-controlled setting to weaken every newly seeded credential.

**Fix:** Raise the accepted floor and default to at least 600,000 after benchmarking the deployment. Prefer Argon2id where FIPS-only primitives are not required, and rehash legacy records after a successful password verification.
```java
static final int MIN_ITERATIONS = 600_000;
static final int DEFAULT_ITERATIONS = 600_000;
static final int MAX_ITERATIONS = 1_500_000;
```

### SEC-04: Audit-log byte cap resets on every process invocation
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LogWriter.java:65-72`, `LogWriter.java:92-93`

**Vulnerable code:**
```java
// LogWriter.java:65-72
    private final Path file;
    private final Writer out;
    private long written;
    private boolean capNotified;

    private LogWriter(Path file, Writer out) {
        this.file = file;
        this.out = out;
    }
```
```java
// LogWriter.java:92-93
        return new LogWriter(file, Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND));
```

**Why it is a problem:** `written` always starts at zero even when an existing audit file is reopened. This is a one-command-per-process CLI, so each authentication starts a new `LogWriter` and forgets the file's existing size. The advertised 4 MiB cap therefore limits only one process, not the append-only file. Repeated denied or throttled invocations can grow the log without bound and exhaust disk space; once storage fails, the application can no longer open its audit log and refuses to start.

**Fix:** Initialize the counter from the existing file size and use locked rotation or an external log manager so concurrent processes cannot race the quota check. At minimum, preserve the accumulated byte count across reopens.
```java
private LogWriter(Path file, Writer out, long written) {
    this.file = file;
    this.out = out;
    this.written = written;
}

long existingBytes = Files.size(file);
Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
        StandardOpenOption.WRITE, StandardOpenOption.APPEND);
return new LogWriter(file, writer, existingBytes);
```

### SEC-05: Unsalted email hashes permit offline identity recovery
- **Severity:** Low
- **CWE:** CWE-759: Use of a One-Way Hash without a Salt
- **Location:** `AuthService.java:182-185`

**Vulnerable code:**
```java
// AuthService.java:182-185
    /** SHA-256 of the normalised address; the only form of the address ever sent to the database. */
    static String identityHash(String normalisedEmail) {
        return CryptoUtils.toHex(CryptoUtils.sha256(PasswordHasher.utf8(normalisedEmail)));
    }
```

**Why it is a problem:** Email addresses have low entropy and are frequently available from public or breached datasets. Because every installation computes the same unsalted SHA-256 value, an attacker who obtains the database can cheaply hash candidate addresses and recover which users have accounts. This defeats the intended data-minimization benefit and allows cross-database correlation. The threat model acknowledges this residual risk, but documenting it does not remove the exposure.

**Fix:** Use a keyed HMAC with an installation-specific secret held outside the H2 database. Version the derivation so keys can be rotated and records migrated; do not use a public salt, which does not prevent candidate testing for email addresses.
```java
static String identityHash(String normalisedEmail, javax.crypto.SecretKey identityKey)
        throws java.security.GeneralSecurityException {
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(identityKey);
    return CryptoUtils.toHex(mac.doFinal(PasswordHasher.utf8(normalisedEmail)));
}
```

## 6. Verified Controls and Checks With No Finding
- SQL injection: All runtime values in `Database.java`, `SessionStore.java`, and `ThrottleStore.java` use `PreparedStatement` bind parameters. Concatenated table identifiers pass a strict identifier allowlist and are quoted; H2 JDBC path metacharacters are rejected.
- Authentication failure handling: `AuthService.authenticate` begins denied, storage errors remain denied, and the CLI renders the same failure string for invalid email, invalid password, unknown identity, throttling, row rejection, and storage failure.
- Password handling: Passwords are read into mutable `char[]` buffers, bounded before hashing, wiped by callers, never accepted in argv, and never written to the audit log. Stored verifiers use independent 16-byte random salts.
- Session generation and lifecycle: `SessionStore` generates 256-bit `SecureRandom` tokens, stores only token hashes, validates exact token shape, checks expiry in SQL, and revokes with a single atomic `DELETE`. Cookie guidance includes `HttpOnly`, `Secure`, and `SameSite=Strict`.
- Cryptographic comparisons: Password digests are validated as fixed 32-byte values before the constant-time comparison, so the helper's length-dependent loop does not expose a variable-length password digest in the authentication path.
- Rate-limit atomicity: Reservation uses shared SQL state, sorted row-lock order, explicit transactions, rollback on refusal, and fail-closed handling on storage error. No check-then-increment race was found.
- Input and resource bounds: Email, password, token, identifier, integer, path, and stdin lengths are bounded. Invalid UTF-8, controls, unpaired surrogates, JDBC URL delimiters, and SQL identifier punctuation are rejected.
- Filesystem protection: Database and log parents must be owner-only real directories; sensitive files must be regular, owned, non-symlink files without group/world permissions. New files use create-new semantics and `0600` permissions.
- Logging safety: Log events use fixed tokens, email local parts are masked, and a final character allowlist excludes CR, LF, NUL, tabs, escapes, and non-ASCII log-injection payloads.
- Secrets and error disclosure: No production credential or key is hardcoded. Database exceptions are mapped to fixed error codes, and bearer-token output is disabled by default and explicitly labelled when enabled.
- Dependency integrity: The bundled `h2-2.3.232.jar` hashes match both supplied checksum files. The application does not start the H2 web console and does not expose configurable `INIT` or network-server options.
- Dangerous execution surfaces: Production code contains no OS-command execution, reflection-based loading, object deserialization, template rendering, outbound network request, XML parsing, or dynamic script execution path.
