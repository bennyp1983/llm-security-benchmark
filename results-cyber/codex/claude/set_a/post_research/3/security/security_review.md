# Security Review: secure-auth Java authentication component

## 1. Executive Summary
The component is a Java 17 command-line authentication service backed by JDBC. It validates email/password input, hashes passwords with PBKDF2-HMAC-SHA512, applies database-backed per-source and per-account throttling, and issues server-side sessions represented by random bearer tokens. Its core SQL, password hashing, token generation, and transaction controls are generally well designed.

Six vulnerabilities were identified. Three are Medium severity: caller-visible authentication diagnostics permit account/state enumeration, password changes do not revoke existing sessions, and the cookie-path validator accepts the cookie attribute delimiter. Three Low-severity issues affect the database-password file and log privacy: check/use races around the secret file, fail-open permission validation on non-POSIX filesystems, and deterministic email fingerprints that can be reversed with a candidate list. No Critical or High-severity issue was found.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition | Pins Java 17, compiler/JAR plugins, and the runtime H2 JDBC dependency. |
| `README.md` | Architecture and deployment documentation | Documents trust boundaries, configuration, secret handling, authentication controls, and known limitations. |
| `scripts/smoke-test.sh` | End-to-end H2 smoke test | Generates a temporary password, creates a private temporary database, invokes the CLI, and checks login, throttling, injection rejection, and session-file mode. |
| `src/main/resources/schema.sql` | Authentication database schema | Defines users, password hashes, sessions, foreign keys, expiry indexes, and throttle counters. |
| `src/main/java/com/example/auth/AdminCli.java` | Schema/password administration CLI | Loads bundled DDL, validates an email, prompts twice for a new password, hashes it, and creates or updates a credential. |
| `src/main/java/com/example/auth/App.java` | Login CLI entry point | Reads credentials, calls authentication, reports the result, and optionally writes the session token to an owner-only file. |
| `src/main/java/com/example/auth/AuthConfig.java` | Environment and secret-file configuration | Validates JDBC/configuration values, reads the database password, checks POSIX permissions, and clears the password array. |
| `src/main/java/com/example/auth/AuthResult.java` | Authentication result model | Separates internal failure reasons from the two intended user-visible result strings and carries the issued token. |
| `src/main/java/com/example/auth/AuthService.java` | Authentication orchestration | Validates input, accounts for attempts, verifies credentials under a row lock, logs outcomes, issues sessions, and clears account throttles. |
| `src/main/java/com/example/auth/ConsoleIo.java` | Bounded console input | Uses no-echo terminal password input when available and bounds all lines to 1,024 characters. |
| `src/main/java/com/example/auth/CredentialRepository.java` | Credential persistence | Uses bound prepared statements and locks credential rows during authentication. |
| `src/main/java/com/example/auth/Database.java` | JDBC connection factory | Supplies database credentials via JDBC properties and opens explicit READ COMMITTED transactions. |
| `src/main/java/com/example/auth/Hashing.java` | SHA-256 utility | Hashes session/throttle lookup keys; it is not used for password storage. |
| `src/main/java/com/example/auth/InputValidator.java` | Input validation | Bounds and validates email addresses, passwords, and source identifiers. |
| `src/main/java/com/example/auth/LogMasker.java` | Log redaction | Replaces emails with a partially masked value plus an unkeyed truncated SHA-256 fingerprint and masks secrets by length. |
| `src/main/java/com/example/auth/LoggingSetup.java` | Default logging setup | Sends INFO-and-higher diagnostics to the invoking caller's stderr. |
| `src/main/java/com/example/auth/LoginThrottle.java` | Login rate limiting | Maintains hashed source/account counters using prepared statements, row locks, savepoints, and committed transactions. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Password hashing and verification | Uses PBKDF2-HMAC-SHA512, random salts, bounded encoded fields, constant-time comparison, and a decoy verification path. |
| `src/main/java/com/example/auth/SessionCookie.java` | Session cookie header builder | Validates token/path/lifetime values and emits Secure, HttpOnly, SameSite, Path, and Max-Age attributes. |
| `src/main/java/com/example/auth/SessionService.java` | Session issuance and validation | Generates 256-bit random tokens, stores only SHA-256 token hashes, and enforces active-user, revocation, and expiry state. |

Generated build outputs under `target/` duplicate the reviewed sources or are binary artifacts; prompt/result metadata files are not application code.

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory every source/build file, identify security-relevant behaviours, route the review to specialized skills, and require CWE/file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters, salts, random generation, token hashing, constant-time comparison, hardcoded-secret checks, and secret lifecycle.
- `exploiting-sql-injection-vulnerabilities`: Applied statically to every JDBC query and all user/configuration values that can reach SQL.
- `testing-api-authentication-weaknesses`: Applied to password policy, account enumeration, throttling, token entropy, validation, expiry, revocation, and password-change session lifecycle.
- `performing-security-headers-audit`: Applied to the `Set-Cookie` builder, including delimiter validation and Secure, HttpOnly, SameSite, Path, and Max-Age attributes.
- `exploiting-race-condition-vulnerabilities`: Applied to throttle counters, verify-then-issue transactions, administrative credential updates, and filesystem check/use sequences.
- General OWASP Top 10 / CWE knowledge: Applied to stderr/log information exposure, filesystem permissions and symlink handling, bounded resource use, configuration validation, shell scripting, and dependency/build configuration where no closer specialized skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Authentication diagnostics permit account and state enumeration | Medium | CWE-204 | `src/main/java/com/example/auth/AuthService.java:131-158` |
| SEC-02 | Password changes leave existing sessions valid | Medium | CWE-613 | `src/main/java/com/example/auth/AdminCli.java:112-115` |
| SEC-03 | Cookie Path accepts the attribute delimiter | Medium | CWE-116 | `src/main/java/com/example/auth/SessionCookie.java:19` |
| SEC-04 | Database-password file checks are vulnerable to a check/use race | Low | CWE-367 | `src/main/java/com/example/auth/AuthConfig.java:123-131` |
| SEC-05 | Secret-file permission validation fails open on non-POSIX filesystems | Low | CWE-732 | `src/main/java/com/example/auth/AuthConfig.java:162-167` |
| SEC-06 | Deterministic email fingerprints expose logged addresses to guessing | Low | CWE-532 | `src/main/java/com/example/auth/LogMasker.java:15-29` |

## 5. Detailed Findings

### SEC-01: Authentication diagnostics permit account and state enumeration
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `src/main/java/com/example/auth/AuthService.java:131-158`; `src/main/java/com/example/auth/LoggingSetup.java:22-29`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:131-158
                if (found.isEmpty()) {
                    hasher.verifyDecoy(password);
                    connection.commit();
                    LOG.log(Level.INFO, "Login failed for {0}", LogMasker.maskEmail(email));
                    return AuthResult.failure(AuthResult.Reason.NO_SUCH_ACCOUNT);
                }

                CredentialRepository.Credential credential = found.get();
                if (credential.passwordHash().isEmpty()) {
                    hasher.verifyDecoy(password);
                    connection.commit();
                    LOG.log(Level.WARNING, "Stored credential is unusable for {0}",
                            LogMasker.maskEmail(email));
                    return AuthResult.failure(AuthResult.Reason.UNUSABLE_STORED_CREDENTIAL);
                }

                // Always verify, even for a deactivated account, so the response time of
                // "disabled" matches "wrong password".
                boolean passwordMatches = hasher.verify(password, credential.passwordHash());

                if (!passwordMatches || !credential.active()) {
                    connection.commit();
                    AuthResult.Reason reason = passwordMatches
                            ? AuthResult.Reason.ACCOUNT_INACTIVE
                            : AuthResult.Reason.BAD_PASSWORD;
                    LOG.log(Level.INFO, "Login failed ({0}) for {1}",
                            new Object[]{reason, LogMasker.maskEmail(email)});
                    return AuthResult.failure(reason);
```

```java
// src/main/java/com/example/auth/LoggingSetup.java:22-29
        Logger root = LogManager.getLogManager().getLogger("");
        for (Handler handler : root.getHandlers()) {
            root.removeHandler(handler);
        }
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        root.addHandler(handler);
        root.setLevel(Level.INFO);
```

**Why it is a problem:** Although stdout uses a generic failure message and the unknown-account path performs comparable PBKDF2 work, the default logger writes different INFO/WARNING messages directly to the invoking caller's stderr. A wrong password for an existing account includes `BAD_PASSWORD`; a nonexistent account produces a different log line; an inactive or malformed credential produces still another result; and throttling also prints its scope. A caller can therefore distinguish account existence and security state by capturing stderr. The smoke test itself demonstrates that these supposedly internal reasons are caller-visible by searching combined stdout/stderr for `ACCOUNT_LIMIT`.

**Fix:** Emit the same caller-visible diagnostic for every authentication failure, or send detailed audit events only to a genuinely separate, access-controlled sink. Keep `AuthResult.Reason` internal for protected metrics/auditing, and do not attach detailed authentication logs to the CLI's stderr by default.
```java
private AuthResult fail(AuthResult.Reason reason, String email) {
    // Identical observable log event for every authentication failure.
    LOG.log(Level.INFO, "Authentication failed for {0}", LogMasker.maskEmail(email));
    return AuthResult.failure(reason);
}

// Use the same helper on every failure path.
if (found.isEmpty()) {
    hasher.verifyDecoy(password);
    connection.commit();
    return fail(AuthResult.Reason.NO_SUCH_ACCOUNT, email);
}

if (!passwordMatches || !credential.active()) {
    connection.commit();
    AuthResult.Reason reason = passwordMatches
            ? AuthResult.Reason.ACCOUNT_INACTIVE
            : AuthResult.Reason.BAD_PASSWORD;
    return fail(reason, email);
}
```

### SEC-02: Password changes leave existing sessions valid
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/AdminCli.java:112-115`; `src/main/java/com/example/auth/SessionService.java:34-37`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AdminCli.java:112-115
            String encoded = new PasswordHasher().hash(first);
            try (Connection connection = database.openTransaction()) {
                new CredentialRepository().saveCredential(connection, email.get(), encoded);
                connection.commit();
```

```java
// src/main/java/com/example/auth/SessionService.java:34-37
    private static final String SELECT_ACTIVE =
            "SELECT s.user_id FROM user_session s JOIN app_user u ON u.user_id = s.user_id "
            + "WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? "
            + "AND u.is_active = TRUE";
```

**Why it is a problem:** Updating a password changes only `app_user.password_hash`. Previously issued session rows remain unrevoked, and session validation has no password-version or password-change-time check. A session stolen before an operator resets a compromised password therefore remains usable until its original expiry (up to 24 hours under accepted configuration), defeating a common reason for resetting the password.

**Fix:** Revoke all of the user's sessions in the same transaction as the password update. Keeping both operations atomic prevents a login or validation window between the credential change and revocation.
```java
// SessionService.java
private static final String REVOKE_ALL_FOR_EMAIL =
        "UPDATE user_session SET revoked_at = CURRENT_TIMESTAMP "
        + "WHERE user_id = (SELECT user_id FROM app_user WHERE email = ?) "
        + "AND revoked_at IS NULL";

public void revokeAllForEmail(Connection connection, String email) throws SQLException {
    try (PreparedStatement ps = connection.prepareStatement(REVOKE_ALL_FOR_EMAIL)) {
        ps.setString(1, email);
        ps.executeUpdate();
    }
}

// AdminCli.java
try (Connection connection = database.openTransaction()) {
    new CredentialRepository().saveCredential(connection, email.get(), encoded);
    new SessionService().revokeAllForEmail(connection, email.get());
    connection.commit();
}
```

### SEC-03: Cookie Path accepts the attribute delimiter
- **Severity:** Medium
- **CWE:** CWE-116: Improper Encoding or Escaping of Output
- **Location:** `src/main/java/com/example/auth/SessionCookie.java:19`; `src/main/java/com/example/auth/SessionCookie.java:40-43`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookie.java:19
    private static final Pattern PATH = Pattern.compile("^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$");
```

```java
// src/main/java/com/example/auth/SessionCookie.java:40-43
        return COOKIE_NAME + "=" + token
                + "; Max-Age=" + seconds
                + "; Path=" + path
                + "; HttpOnly; Secure; SameSite=Strict";
```

**Why it is a problem:** The allowlist includes semicolon, which delimits cookie attributes. A caller-controlled value such as `/;Domain=example.com` passes validation and injects a `Domain` attribute into the generated header. Depending on the deployment domain and user agent, this can widen the bearer cookie's scope to sibling hosts or introduce conflicting security attributes. CR/LF are blocked, but attribute injection does not require them.

**Fix:** Reject the semicolon delimiter. Cookie Path values cannot safely escape it, so a strict allowlist should exclude it.
```java
private static final Pattern PATH =
        Pattern.compile("^/[A-Za-z0-9._~!$&'()*+,=:@%/-]{0,200}$");
```

### SEC-04: Database-password file checks are vulnerable to a check/use race
- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:123-131`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:123-131
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is not a regular file");
                }
                if (Files.size(path) > MAX_SECRET_FILE_BYTES) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is larger than "
                            + MAX_SECRET_FILE_BYTES + " bytes");
                }
                requireOwnerOnly(path);
                raw = Files.readAllBytes(path);
```

**Why it is a problem:** File type, size, and permissions are checked by separate path-based operations before `readAllBytes` reopens the path and follows links. If an attacker can replace an entry in the containing directory between those operations, the application can read a different file from the one it validated. Replacement also bypasses the 4,096-byte pre-check, allowing memory consumption from a much larger file. The risk is local and depends on an attacker-writable parent directory, hence Low severity.

**Fix:** Require a non-attacker-writable parent directory, open with `NOFOLLOW_LINKS`, and enforce the byte limit while reading from that already-open channel rather than through a separate size check.
```java
requirePrivateParent(path.getParent());
requireOwnerOnly(path);

try (java.nio.channels.SeekableByteChannel channel = Files.newByteChannel(
        path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
    java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(MAX_SECRET_FILE_BYTES + 1);
    while (buffer.hasRemaining() && channel.read(buffer) != -1) {
        // Read from the same no-follow handle, with a hard upper bound.
    }
    if (buffer.position() > MAX_SECRET_FILE_BYTES) {
        throw new ConfigException("AUTH_DB_PASSWORD_FILE is too large");
    }
    raw = Arrays.copyOf(buffer.array(), buffer.position());
}
```

### SEC-05: Secret-file permission validation fails open on non-POSIX filesystems
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:162-167`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:162-167
    private static void requireOwnerOnly(Path path) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            return; // non-POSIX file system; permissions enforced by the platform ACL
        }
```

**Why it is a problem:** The code assumes that a platform ACL enforces owner-only access but does not inspect that ACL. On filesystems without POSIX attributes, a database-password file readable by other users is accepted without any permission check. This contradicts the documented owner-only requirement and can expose the database credential on multi-user systems.

**Fix:** Inspect the platform ACL and reject broad read/write grants. If the application does not implement a correct ACL check for a filesystem, fail closed and require another secret source rather than silently accepting the file.
```java
PosixFileAttributeView view = Files.getFileAttributeView(
        path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
if (view == null) {
    throw new ConfigException(
            "Cannot verify owner-only permissions for AUTH_DB_PASSWORD_FILE on this filesystem");
}
```

### SEC-06: Deterministic email fingerprints expose logged addresses to guessing
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/example/auth/LogMasker.java:15-29`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LogMasker.java:15-29
    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "<none>";
        }
        return email.charAt(0) + "***@*** (eid:" + fingerprint(email) + ")";
    }

    /** Short, non-reversible correlation id for any sensitive string. */
    public static String fingerprint(String value) {
        byte[] digest = Hashing.sha256(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(12);
        for (int i = 0; i < 6; i++) {
            sb.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
            sb.append(Character.forDigit(digest[i] & 0xF, 16));
```

**Why it is a problem:** Email addresses have low entropy and are commonly available in candidate lists. An unkeyed SHA-256 fingerprint does not make them non-reversible: anyone who obtains the logs can hash candidate addresses offline and compare the first 48 bits, aided by the logged first character. The value is therefore pseudonymous, not safely redacted, and can disclose account identifiers from logs.

**Fix:** If correlation is unnecessary, remove all address-derived data. If correlation is required, use a keyed HMAC with a separately managed log-pseudonymization key and an appropriate rotation policy; do not use an unkeyed digest.
```java
public static String maskEmail(String email) {
    return (email == null || email.isEmpty()) ? "<none>" : "***@***";
}
```

## 6. Verified Controls and Checks With No Finding
- SQL injection: Every runtime query in `CredentialRepository.java`, `LoginThrottle.java`, and `SessionService.java` uses constant SQL with `PreparedStatement` bindings. The only plain `Statement` executes bundled `schema.sql`, not caller-provided DDL.
- Password storage: `PasswordHasher.java` uses PBKDF2-HMAC-SHA512 with 210,000 iterations, a fresh 16-byte `SecureRandom` salt, a 256-bit output, bounded parsing, and `MessageDigest.isEqual`; passwords are not stored with a general-purpose digest.
- Authentication fail-closed behaviour: `AuthService.java` grants success only after a valid credential and active account are verified; SQL/runtime errors, invalid source identifiers, malformed stored credentials, and throttle failures deny authentication.
- Online guessing resistance: `AuthService.java` and `LoginThrottle.java` account for attempts per source and per normalized account in committed transactions, use row locks for updates, retain the source counter after successful login, and avoid charging a source-blocked request to the victim account.
- Authentication timing: Missing and malformed credentials use a full PBKDF2 decoy verification, and inactive accounts still verify the submitted password before denial.
- Transaction atomicity: Credential verification, session issuance, and account-counter clearing occur in one transaction while the user row is locked; throttle updates use row locks and recover insert races with a savepoint.
- Session-token strength and storage: `SessionService.java` generates 32 random bytes with `SecureRandom`, exposes a fixed 43-character base64url token, stores only its SHA-256 lookup hash, and checks server-side revocation, expiry, and active-user state.
- Baseline cookie attributes: Apart from SEC-03, `SessionCookie.java` always adds `HttpOnly`, `Secure`, `SameSite=Strict`, an explicit path, and a bounded `Max-Age`; the token itself is restricted to the service's base64url format.
- User-visible stdout failures: `AuthResult.java` exposes one generic failure sentence and does not return internal `Reason` values through its user message.
- Input and resource bounds: `InputValidator.java`, `ConsoleIo.java`, `AuthConfig.java`, and `PasswordHasher.java` bound user input, configuration fields, source identifiers, encoded hashes, iteration counts, salts, and derived-key lengths.
- Session-file creation: `App.java` rejects an existing non-regular target and creates the replacement using `CREATE_NEW`; on POSIX filesystems it applies mode 0600 atomically at creation, preventing a planted symlink from being followed during creation.
- Secret handling: No working password, key, or session token is hardcoded. Interactive passwords use `char[]` and are cleared, derived buffers and salts are cleared, database passwords are cleared when configuration closes, and raw session tokens are not logged.
- Shell script handling: `scripts/smoke-test.sh` creates a mode-0700 temporary directory, generates its password at runtime under `umask 077`, quotes expansions used as paths/arguments, and removes the temporary tree through a trap scoped to the `mktemp` result.
- Dependency/build configuration: `pom.xml` pins dependency and plugin versions and introduces no untrusted repositories, dynamic version ranges, build-time code generators, or download-and-execute steps.
