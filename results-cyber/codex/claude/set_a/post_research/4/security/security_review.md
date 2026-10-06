# Security Review: secure-accounts

## 1. Executive Summary
The component is a Java 17 command-line account service backed by SQLite. It validates registration input, hashes passwords with Argon2id, rate-limits authentication, stores server-side sessions, and provides helpers for private logging and secure cookies. The review found six vulnerabilities: one High-severity race between password verification and session issuance, four Medium-severity issues involving attacker-induced account lockout, disabled-account session survival, private-storage enforcement, and an incomplete password denylist, and one Low-severity terminal-control injection path from unvalidated database values. Strong controls are present for SQL parameterization, password hashing, session-token generation, generic authentication failures, and bounded input handling, but they do not eliminate the findings below.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and dependency manifest | Pins cryptographic, SQLite, logging, test, compiler, and packaging dependencies; uses Maven Central over HTTPS with checksum failure enabled. |
| `README.md` | Component and security-design documentation | Defines the trust model, operational assumptions, residual risks, and intended authentication/session controls. |
| `src/main/java/com/example/accounts/AccountRepository.java` | Account persistence | Uses prepared statements for account creation, lookup, and hash upgrades; maps database values into authentication objects. |
| `src/main/java/com/example/accounts/AccountService.java` | Registration and authentication orchestration | Coordinates validation, throttling, password verification, hash upgrades, session issuance, logout, and generic failure behavior. |
| `src/main/java/com/example/accounts/App.java` | CLI entry point | Reads credentials, dispatches commands, writes/reads the local session token, displays account/session data, and wipes caller-owned secret arrays. |
| `src/main/java/com/example/accounts/Config.java` | Environment configuration | Validates Argon2, throttle, session, pepper, data-directory, logging, and JDBC settings; creates the data directory. |
| `src/main/java/com/example/accounts/Database.java` | SQLite setup and transactions | Opens SQLite, configures WAL and immediate transactions, creates schema constraints, and attempts to restrict database-file permissions. |
| `src/main/java/com/example/accounts/Hex.java` | Hex encoder | Encodes digests and random session references. |
| `src/main/java/com/example/accounts/InputValidator.java` | Registration-input validation | Canonicalizes email/usernames, prepares Unicode passwords, enforces length/content rules, and checks a small common-password denylist. |
| `src/main/java/com/example/accounts/Logging.java` | Application logging | Creates a nominally owner-only log file, masks multiline records, and falls back to stderr. |
| `src/main/java/com/example/accounts/Mask.java` | Log-value masking | Redacts email local parts, usernames, and JDBC URL user information/query data. |
| `src/main/java/com/example/accounts/PasswordHasher.java` | Password hashing and verification | Implements Argon2id PHC encoding, strict parameter parsing, random salts, optional peppering, rehash detection, and constant-time digest comparison. |
| `src/main/java/com/example/accounts/SessionCookie.java` | HTTP cookie helper | Produces `__Host-` session cookies with Secure, HttpOnly, SameSite, Path, and Max-Age attributes. |
| `src/main/java/com/example/accounts/SessionService.java` | Server-side session management | Generates random tokens/references, stores token digests, validates idle/absolute expiry, refreshes activity, revokes, and prunes sessions. |
| `src/main/java/com/example/accounts/ThrottleService.java` | Authentication/registration throttling | Maintains atomic per-source and per-account counters using digested identifiers. |
| `src/main/java/com/example/accounts/ValidationException.java` | Validation error type | Carries user-displayable format-policy errors. |
| `src/main/java/com/example/accounts/Wipe.java` | Secret-memory cleanup | Best-effort zeroes credential byte and character arrays. |
| `src/test/java/com/example/accounts/AccountServiceTest.java` | Account-service integration tests | Tests registration, authentication, enumeration resistance, throttling, sessions, hash upgrades, concurrency, SQL metacharacters, and POSIX modes. |
| `src/test/java/com/example/accounts/InputValidatorTest.java` | Input-validation tests | Tests canonicalization, malformed inputs, Unicode handling, size limits, and password rules. |
| `src/test/java/com/example/accounts/PasswordHasherTest.java` | Password-hasher tests | Tests salts, pepper behavior, PHC parsing, hostile parameters, verification, rehashing, and decoy hashes. |
| `src/test/java/com/example/accounts/TestSupport.java` | Test fixture support | Creates low-cost test configuration and a silent logger. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the required routing workflow to inventory all source behavior, select specialized checks, and require CWE/file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to Argon2id parameters, salts, pepper handling, SecureRandom use, SHA-256 token digests, constant-time comparisons, hardcoded-secret checks, and dependency configuration.
- `testing-api-authentication-weaknesses`: Applied statically to password policy, account enumeration, token entropy, revocation, expiration, disabled accounts, and the verify-to-session state transition.
- `implementing-api-rate-limiting-and-throttling`: Applied to per-source/per-account keys, atomic counters, window behavior, credential-stuffing resistance, and lockout abuse.
- `testing-for-sensitive-data-exposure`: Applied to password/token logging, local database/log/session storage, file permissions, masking, error output, and secret lifetime.
- `exploiting-sql-injection-vulnerabilities`: Applied only as a static checklist to every SQL construction and binding site; no untrusted code was executed and no injection was attempted.
- General OWASP Top 10 / CWE review: Applied to filesystem/path invariants, TOCTOU state changes, terminal-control output, validation of persisted data, failure behavior, and concurrency because no narrower library skill matched each of those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Authentication state is not revalidated atomically before session issuance | High | CWE-367 | `src/main/java/com/example/accounts/AccountService.java:157-208` |
| SEC-02 | Per-account hard throttling permits repeated victim lockout | Medium | CWE-645 | `src/main/java/com/example/accounts/ThrottleService.java:100-118` |
| SEC-03 | Existing sessions remain valid after an account is disabled | Medium | CWE-613 | `src/main/java/com/example/accounts/SessionService.java:39-46` |
| SEC-04 | Configurable SQLite URLs can bypass private-storage enforcement | Medium | CWE-732 | `src/main/java/com/example/accounts/Config.java:153-163` |
| SEC-05 | Tiny static denylist accepts readily guessable passwords | Medium | CWE-521 | `src/main/java/com/example/accounts/InputValidator.java:39-44` |
| SEC-06 | Unvalidated persisted display values can inject terminal control sequences | Low | CWE-150 | `src/main/java/com/example/accounts/App.java:158-165` |

## 5. Detailed Findings

### SEC-01: Authentication state is not revalidated atomically before session issuance
- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/accounts/AccountService.java:157-208`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/AccountService.java:157-166
Decisionable gate = database.inTransaction(connection -> {
    ThrottleService.Decision decision =
            throttle.tryAcquire(connection, source, lookupKey, now);
    if (!decision.allowed()) {
        return new Decisionable(decision, null);
    }
    Optional<AccountRepository.Account> account =
            lookupKey == null ? Optional.empty() : accounts.findByLogin(connection, lookupKey);
    return new Decisionable(decision, account.orElse(null));
});
```
```java
// src/main/java/com/example/accounts/AccountService.java:187-208
boolean verified;
try {
    String candidateHash = usable ? account.passwordHash() : decoyHash;
    verified = hasher.verify(prepared, candidateHash) && usable;
    if (!verified) {
        log.info(() -> "authentication failed for identifier="
                + Mask.username(lookupKey == null ? "" : lookupKey));
        return AuthResult.failure(AuthStatus.INVALID_CREDENTIALS);
    }

    final long accountId = account.id();
    final boolean rehash = hasher.needsRehash(account.passwordHash());
    final String upgraded = rehash ? hasher.hash(prepared) : null;

    // Step 2 (atomic): clear the account counter and mint the session together.
    SessionService.IssuedSession issued = database.inTransaction(connection -> {
        throttle.clearAccount(connection, lookupKey, now);
        if (upgraded != null) {
            accounts.updatePasswordHash(connection, accountId, upgraded, now);
        }
        return sessions.issue(connection, accountId, now);
    });
```

**Why it is a problem:** The account row is read in one transaction, its password is verified after that transaction releases its lock, and a session is minted in a later transaction without checking that the account is still enabled or that its stored hash is unchanged. A concurrent disable or password change can therefore occur after verification but before authorization is granted. The old password still receives a new session. If rehashing is needed, the unconditional update can also overwrite a concurrently changed password with a hash of the old password. This violates the stated atomic “verify, then grant” requirement and can undo a security administrator's state change.

**Fix:** Keep expensive Argon2 work outside the database lock, but in the session-issuance transaction re-read by immutable account ID and require both `disabled == false` and an unchanged password hash. Only then clear counters, conditionally upgrade, and issue the session. SQLite's immediate write transaction then makes the final recheck and grant atomic. Add `findById` as a prepared query.
```java
// Recheck the exact authentication state inside the transaction that grants access.
SessionService.IssuedSession issued = database.inTransaction(connection -> {
    AccountRepository.Account current = accounts.findById(connection, accountId).orElse(null);
    if (current == null || current.disabled()
            || !current.passwordHash().equals(account.passwordHash())) {
        return null;
    }
    throttle.clearAccount(connection, lookupKey, now);
    if (upgraded != null) {
        accounts.updatePasswordHash(connection, accountId, upgraded, now);
    }
    return sessions.issue(connection, accountId, now);
});
if (issued == null) {
    return AuthResult.failure(AuthStatus.INVALID_CREDENTIALS);
}
```

### SEC-02: Per-account hard throttling permits repeated victim lockout
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/example/accounts/ThrottleService.java:100-118`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/ThrottleService.java:100-118
public Decision tryAcquire(Connection connection, String sourceId, String accountIdentifier,
                           Instant now) throws SQLException {
    long cutoff = windowCutoff(now);
    String sourceKey = key(SCOPE_SOURCE, sourceId);
    if (failures(connection, SCOPE_SOURCE, sourceKey, cutoff) >= config.maxFailuresPerSource()) {
        return Decision.SOURCE_THROTTLED;
    }
    String accountKey = accountIdentifier == null ? null : key(SCOPE_ACCOUNT, accountIdentifier);
    if (accountKey != null
            && failures(connection, SCOPE_ACCOUNT, accountKey, cutoff)
                    >= config.maxFailuresPerAccount()) {
        return Decision.ACCOUNT_THROTTLED;
    }
    bump(connection, SCOPE_SOURCE, sourceKey, now, cutoff);
    if (accountKey != null) {
        bump(connection, SCOPE_ACCOUNT, accountKey, now, cutoff);
    }
    prune(connection, cutoff);
    return Decision.ALLOW;
}
```

**Why it is a problem:** Once distributed attackers produce the configured number of guesses for a victim identifier, `ACCOUNT_THROTTLED` is returned before the submitted password is checked. The legitimate user therefore cannot authenticate and clear the account counter. Although the fixed window eventually expires, an attacker can repeat the guesses each window and maintain recurring lockouts. The source limit does not prevent this because the attack can be distributed across sources.

**Fix:** Keep a hard per-source gate, but do not hard-reject an account before checking a potentially valid credential. Record account failures only after a failed verification, clear them after success, and use the account signal for alerting, progressive delay, or step-up verification rather than a pre-verification lock. The per-source gate continues to bound work from each origin.
```java
public Decision tryAcquireSource(Connection connection, String sourceId, Instant now)
        throws SQLException {
    long cutoff = windowCutoff(now);
    String sourceKey = key(SCOPE_SOURCE, sourceId);
    if (failures(connection, SCOPE_SOURCE, sourceKey, cutoff)
            >= config.maxFailuresPerSource()) {
        return Decision.SOURCE_THROTTLED;
    }
    bump(connection, SCOPE_SOURCE, sourceKey, now, cutoff);
    prune(connection, cutoff);
    return Decision.ALLOW;
}

// After password verification:
if (verified) {
    throttle.clearAccount(connection, lookupKey, now);
} else {
    throttle.recordAccountFailure(connection, lookupKey, now); // alert/delay; do not lock out
}
```

### SEC-03: Existing sessions remain valid after an account is disabled
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/accounts/SessionService.java:39-46`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/SessionService.java:39-46
private static final String SELECT_SQL = """
        SELECT session_ref, account_id, last_used_at, absolute_expires_at, revoked
        FROM auth_session WHERE token_hash = ?
        """;

private static final String TOUCH_SQL = """
        UPDATE auth_session SET last_used_at = ? WHERE token_hash = ? AND revoked = 0
        """;
```

**Why it is a problem:** Authentication refuses a disabled account, but session validation consults only `auth_session`. Any token issued before the account was disabled remains valid until logout, idle expiry, absolute expiry, or an explicit call to `revokeAllForAccount`. A disabled or compromised account can therefore continue acting through an existing session for up to the configured absolute lifetime.

**Fix:** Join the account table during every validation and require the account to remain enabled. Preserve that condition in the touch statement so the refresh also fails closed. Continue revoking all sessions as part of any disable/password-change workflow as defense in depth.
```java
private static final String SELECT_SQL = """
        SELECT s.session_ref, s.account_id, s.last_used_at,
               s.absolute_expires_at, s.revoked
        FROM auth_session s
        JOIN account a ON a.id = s.account_id
        WHERE s.token_hash = ? AND a.disabled = 0
        """;

private static final String TOUCH_SQL = """
        UPDATE auth_session
        SET last_used_at = ?
        WHERE token_hash = ? AND revoked = 0
          AND EXISTS (
              SELECT 1 FROM account a
              WHERE a.id = auth_session.account_id AND a.disabled = 0
          )
        """;
```

### SEC-04: Configurable SQLite URLs can bypass private-storage enforcement
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/accounts/Config.java:153-163`; `src/main/java/com/example/accounts/Database.java:103-123`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/Config.java:153-163
private static String resolveJdbcUrl(String configured, Path dataDir) {
    if (configured == null || configured.isBlank()) {
        return "jdbc:sqlite:" + dataDir.resolve("accounts.db");
    }
    require(configured.length() <= 2048, "ACCOUNTS_JDBC_URL is too long");
    require(configured.chars().noneMatch(c -> c < 0x20 || c == 0x7f),
            "ACCOUNTS_JDBC_URL contains control characters");
    boolean allowed = ALLOWED_JDBC_PREFIXES.stream().anyMatch(configured::startsWith);
    require(allowed, "ACCOUNTS_JDBC_URL must start with one of " + ALLOWED_JDBC_PREFIXES);
    return configured;
}
```
```java
// src/main/java/com/example/accounts/Database.java:103-123
private void restrictDatabaseFilePermissions(String url) {
    String pathPart = url.substring("jdbc:sqlite:".length());
    int q = pathPart.indexOf('?');
    if (q >= 0) {
        pathPart = pathPart.substring(0, q);
    }
    if (pathPart.isEmpty() || pathPart.startsWith(":")) {
        return; // in-memory database, nothing on disk
    }
    Path base = Paths.get(pathPart);
    for (String suffix : new String[] {"", "-wal", "-shm", "-journal"}) {
        Path p = suffix.isEmpty() ? base : Paths.get(pathPart + suffix);
        try {
            if (Files.exists(p) && !Files.isSymbolicLink(p)
                    && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (IOException | UnsupportedOperationException e) {
            log.log(Level.WARNING, "could not restrict permissions on database file", e);
        }
    }
}
```

**Why it is a problem:** Prefix validation accepts SQLite URI filenames and arbitrary paths outside the owner-only data directory. For example, a `jdbc:sqlite:file:/...?...` URL is interpreted by SQLite as a URI, while the permission routine treats `file:/...` as an ordinary Java path and may chmod the wrong object. Plain external paths also place WAL/SHM files in directories that have not been made private. On non-POSIX filesystems no equivalent ACL is applied, and permission errors are logged but startup continues. Password hashes, email addresses, attempt data, and session records can consequently be created with ambient permissions despite the component's private-storage invariant.

**Fix:** Construct the database location from the already secured data directory instead of accepting an arbitrary JDBC URL. Resolve the real parent without following an attacker-controlled final symlink, enforce owner-only permissions using POSIX permissions or platform ACLs, and fail startup if the invariant cannot be established.
```java
private static String resolveJdbcUrl(String configured, Path dataDir) {
    Path database = dataDir.resolve("accounts.db").normalize();
    String expected = "jdbc:sqlite:" + database;
    require(configured == null || configured.isBlank() || configured.equals(expected),
            "ACCOUNTS_JDBC_URL must name the private data-directory database");
    return expected;
}

private void requirePrivateDatabaseFile(Path file) throws SQLException {
    try {
        if (!file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            throw new IOException("owner-only database permissions are not supported");
        }
        Files.setPosixFilePermissions(file,
                PosixFilePermissions.fromString("rw-------"));
    } catch (IOException | UnsupportedOperationException e) {
        throw new SQLException("cannot enforce private database permissions", e);
    }
}
```

### SEC-05: Tiny static denylist accepts readily guessable passwords
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/example/accounts/InputValidator.java:39-44`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/InputValidator.java:39-44
/** A small, high-frequency blocklist; see README for wiring a full breached-password list. */
private static final Set<String> BLOCKED_PASSWORDS = Set.of(
        "123456789012", "passwordpassword", "password1234", "qwertyuiop12", "administrator",
        "iloveyou1234", "letmein12345", "welcome12345", "monkey123456", "dragon123456",
        "football1234", "baseball1234", "sunshine1234", "princess1234", "qwerty123456",
        "abc123456789", "trustno12345", "changeme1234", "secret123456", "superman1234");
```

**Why it is a problem:** The policy checks only twenty exact lowercase strings. Obvious variants such as `password123!` satisfy the 12-character minimum and distinct-character rule but remain highly guessable in online and offline attacks. Argon2 slows cracking but does not make commonly breached passwords safe, and the README itself acknowledges that the list is a stub that must be replaced before production.

**Fix:** Require a stronger minimum for single-factor passwords and check the prepared password against a comprehensive, locally maintained breached-password index without sending the password to a third party. The checker should accept `char[]`/digest input so the password is not converted to an unwipeable `String`.
```java
public static final int PASSWORD_MIN_LENGTH = 15;

public static void checkPasswordPolicy(char[] prepared, String canonicalUsername,
        String canonicalEmail, BreachedPasswordChecker breachedPasswords)
        throws ValidationException {
    if (prepared == null || prepared.length < PASSWORD_MIN_LENGTH) {
        throw new ValidationException(
                "Password must be at least " + PASSWORD_MIN_LENGTH + " characters.");
    }
    if (breachedPasswords.contains(prepared)) {
        throw new ValidationException("That password is too common. Choose a different one.");
    }
    // Retain the existing maximum-length and account-identifier similarity checks.
}
```

### SEC-06: Unvalidated persisted display values can inject terminal control sequences
- **Severity:** Low
- **CWE:** CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences
- **Location:** `src/main/java/com/example/accounts/AccountRepository.java:80-87`; `src/main/java/com/example/accounts/App.java:158-165`; `src/main/java/com/example/accounts/App.java:198-205`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/AccountRepository.java:80-87
Account account = new Account(
        rs.getLong("id"),
        rs.getString("email_canonical"),
        rs.getString("username_canonical"),
        rs.getString("username_display"),
        rs.getString("password_hash"),
        rs.getInt("disabled") != 0);
return Optional.of(account);
```
```java
// src/main/java/com/example/accounts/App.java:158-165
result = service.authenticate(identifier, password, sourceId());
switch (result.status()) {
    case AUTHENTICATED -> {
        SessionService.IssuedSession session = result.session();
        storeSessionToken(config, session.token());
        System.out.println("Signed in as " + result.usernameDisplay() + ".");
        System.out.println("Session " + session.reference() + " expires at "
                + TS.format(session.expiresAt()) + ".");
```
```java
// src/main/java/com/example/accounts/App.java:198-205
Optional<SessionService.ValidSession> session = service.resolveSession(token);
if (session.isEmpty()) {
    // Expired, revoked, unknown or malformed all look the same: fail closed.
    System.err.println("Not signed in.");
    return 1;
}
System.out.println("Signed in with session " + session.get().reference() + ".");
return 0;
```

**Why it is a problem:** Registration validates these values when first written, but later database reads trust `username_display` and `session_ref` even though the documented trust model treats database contents as attacker-controlled. A tampered row can contain ANSI escape/control sequences that are emitted to an operator's terminal on login or `whoami`, potentially forging output, changing terminal state, or creating misleading clickable content. Database length constraints do not restrict the character set.

**Fix:** Revalidate persisted values against their exact storage formats before returning them from the repository/session layer and fail closed on corruption. Display usernames should use the same normalized ASCII grammar as registration; session references must be exactly 32 lowercase hexadecimal characters.
```java
String usernameDisplay = rs.getString("username_display");
if (usernameDisplay == null
        || !usernameDisplay.matches("[A-Za-z0-9](?:[A-Za-z0-9._-]{1,30}[A-Za-z0-9])")) {
    throw new SQLException("invalid persisted username display value");
}

String reference = rs.getString("session_ref");
if (reference == null || !reference.matches("[0-9a-f]{32}")) {
    throw new SQLException("invalid persisted session reference");
}
```

## 6. Verified Controls and Checks With No Finding
- SQL injection resistance: All production SQL is fixed text executed through `PreparedStatement` with bound parameters in `AccountRepository`, `ThrottleService`, and `SessionService`; no client value is concatenated into SQL.
- Password storage cryptography: `PasswordHasher` uses Argon2id with validated minimum configuration, fresh 16-byte `SecureRandom` salts, 32-byte output, optional peppering, strict PHC parsing, bounded hostile parameters, and `MessageDigest.isEqual` for comparison.
- Hardcoded secrets: No deployable password, key, token, or pepper is embedded in production source; the optional pepper is base64-decoded from runtime configuration and omitted from log/config rendering.
- Session-token construction: Tokens contain 256 random bits from `SecureRandom`, use a fixed base64url format, are stored only as SHA-256 digests, and are not caller-selected.
- Cookie flags: `SessionCookie` emits the `__Host-` prefix, `Path=/`, Secure, HttpOnly, SameSite=Strict, no Domain attribute, and bounded server-side session expiry remains authoritative.
- Session expiration and explicit logout: Idle and absolute expiration, revocation, fixed token shape, and refresh row-count checks fail closed for otherwise enabled accounts; logout revokes the server-side row.
- Authentication enumeration resistance: Unknown identifiers, wrong passwords, corrupt hashes, and disabled accounts share a generic result, while unknown/disabled accounts perform Argon2 work using a decoy hash.
- Registration enumeration resistance: Duplicate email/username conflicts return the same public status as successful creation, and password hashing occurs before the uniqueness result is known.
- Registration input validation: Email and username inputs are bounded and allowlisted, usernames are NFKC/case canonicalized, and password inputs reject controls, malformed Unicode, and excessive length before hashing.
- Concurrency controls outside SEC-01: SQLite immediate transactions serialize throttle counter check/increment; database UNIQUE constraints arbitrate concurrent registration; session revoke/expiry checks and activity refresh occur in one transaction.
- Sensitive logging: Production paths do not log plaintext passwords or session tokens; identifiers are masked and newline-like characters are neutralized by the formatter.
- Secret cleanup: Caller-owned passwords, prepared password buffers, token buffers, digest intermediates, and pepper configuration arrays are wiped on the reviewed normal/error paths on a best-effort JVM basis.
- Resource bounds: Input lengths, PHC components and parameters, database text columns, session-token files, log size, throttle records, and expired/revoked session records are bounded or pruned.
