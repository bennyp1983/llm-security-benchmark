# Security Review: secure-auth

## 1. Executive Summary
The `secure-auth` component is a Java 17 application providing command-line and service-layer authentication for users using email and password against an SQL database (PostgreSQL / H2). It includes password hashing using PBKDF2-HMAC-SHA512, database-backed rate limiting per source and per account, token-based session management storing SHA-256 digests, HTTP cookie header formatting with security attributes, input validation, and an administrative CLI for schema initialization and password management.

While the codebase exhibits strong security practices in areas such as SQL parameterization, constant-time hash comparisons, decoy derivations against timing attacks, and password hashing parameters, the static review identified four security vulnerabilities:
1. **Account Lockout Denial of Service (High):** The rate-limiting logic enforces a strict account-level limit that is lower than the source limit. An unauthenticated attacker from a single IP can exhaust any user's account attempt quota, locking legitimate users out of their accounts even when supplying correct credentials.
2. **Cookie Attribute Injection (Medium):** The path validation regular expression in `SessionCookie` allows semicolons (`;`) and equals signs (`=`), enabling injection of arbitrary cookie attributes (such as `Domain`) into the `Set-Cookie` header.
3. **Sensitive Credentials Retained in Memory (Medium):** In `App.java`, calling `System.exit()` directly from within the `try` block terminates the JVM immediately, skipping `finally` blocks and `try-with-resources` `close()` methods. As a result, plaintext password arrays and database passwords are not zeroed before process termination.
4. **Failure to Invalidate Active Sessions upon Password Change (Medium):** Setting or changing a password via `AdminCli` updates the stored hash but does not revoke existing active user sessions in `user_session`, allowing compromised or stolen sessions to remain valid.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/App.java` | Main CLI entry point for user authentication | Reads credentials from console without echo, invokes authentication service, manages process exit codes, writes session token to owner-only file, attempts memory cleanup. |
| `src/main/java/com/example/auth/AdminCli.java` | Operator CLI for schema initialization and credential provisioning | Reads bundled DDL resource to initialize schema, validates password complexity, prompts for passwords twice, hashes passwords, saves user credentials. |
| `src/main/java/com/example/auth/AuthConfig.java` | Environment configuration parser and validator | Validates JDBC URLs against allowlist patterns and forbidden sub-options, enforces 0600 POSIX permissions on secret password files, bounds configuration ranges, zeroes DB password. |
| `src/main/java/com/example/auth/AuthResult.java` | Authentication outcome model | Provides generic, uniform user-facing messages for both success and all failure modes to prevent account enumeration; retains internal diagnosis reasons for logging. |
| `src/main/java/com/example/auth/AuthService.java` | Core authentication business logic | Coordinates input normalization, attempt accounting across source and account scopes, credential verification under row locks, session issuance, and decoy password hashing. |
| `src/main/java/com/example/auth/ConsoleIo.java` | Terminal and stdin I/O abstraction | Utilizes `java.io.Console` for no-echo password input when interactive; falls back to stdin with warnings; bounds maximum input line lengths. |
| `src/main/java/com/example/auth/CredentialRepository.java` | Database repository for user credentials | Executes parameterized queries (`SELECT ... FOR UPDATE`, `UPDATE`, `INSERT`) on `app_user`; limits maximum field sizes; checks nullability and row validity. |
| `src/main/java/com/example/auth/Database.java` | JDBC connection factory | Connects via `DriverManager` using `Properties` to avoid credentials in URLs; enforces `READ_COMMITTED` transaction isolation and disables auto-commit. |
| `src/main/java/com/example/auth/Hashing.java` | Cryptographic SHA-256 helper | Generates fixed-width SHA-256 hex strings for token storage, throttle keys, and masking fingerprints. |
| `src/main/java/com/example/auth/InputValidator.java` | External input validation and normalization | Validates email syntax and RFC lengths, normalizes emails to lowercase, validates password length and ASCII bounds, validates source identifier character sets. |
| `src/main/java/com/example/auth/LoggingSetup.java` | Logging subsystem configuration | Configures `java.util.logging` root logger with a console handler directing logs to stderr; respects external configuration properties. |
| `src/main/java/com/example/auth/LoginThrottle.java` | Database-backed sliding window attempt rate limiter | Records and checks attempt counts per source and account scopes using row-level locking (`SELECT ... FOR UPDATE`); handles insert concurrency races via savepoints; periodically purges expired records. |
| `src/main/java/com/example/auth/LogMasker.java` | Log sanitization utility | Masks email addresses using the first character and SHA-256 fingerprint; masks session tokens displaying only character length. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Password hashing and verification engine | Implements PBKDF2-HMAC-SHA512 with 210,000 iterations, 16-byte random salts, constant-time `MessageDigest.isEqual` comparison, and decoy hashing for uniform timing. |
| `src/main/java/com/example/auth/SessionCookie.java` | HTTP `Set-Cookie` header constructor | Validates session token and path formats; constructs cookie headers enforcing `HttpOnly`, `Secure`, and `SameSite=Strict` attributes with bounded `Max-Age`. |
| `src/main/java/com/example/auth/SessionService.java` | Session lifecycle management | Issues cryptographically random 256-bit session tokens; persists SHA-256 token digests; resolves active sessions joined to active users; purges expired sessions. |
| `src/main/resources/schema.sql` | Database schema definition | Defines DDL for `app_user`, `user_session`, and `login_throttle` tables, foreign keys, timestamps with time zone, and indexes. |
| `pom.xml` | Maven project build descriptor | Declares Java 17 compiler release, strict compiler flags (`-Xlint:all`), and pinned runtime dependency on H2 database. |
| `scripts/smoke-test.sh` | Integration and security smoke test script | Executes end-to-end integration tests covering authentication paths, SQL injection rejection, rate limiting, and output masking in a temporary directory. |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to evaluate session token generation, token storage hashing, session lifecycle, token revocation mechanisms, rate limiting behaviors, and account enumeration resistance across `AuthService`, `SessionService`, `AdminCli`, and `LoginThrottle`.
- `performing-cryptographic-audit-of-application`: Applied to audit PBKDF2-HMAC-SHA512 parameters, iteration counts, salt generation, entropy sources (`SecureRandom`), constant-time comparisons (`MessageDigest.isEqual`), decoy derivation paths, and SHA-256 hashing across `PasswordHasher`, `Hashing`, and `SessionService`.
- `exploiting-sql-injection-vulnerabilities`: Applied to inspect database statement construction, parameter binding, schema structure, and JDBC usage across `CredentialRepository`, `LoginThrottle`, `SessionService`, `AdminCli`, and `Database`.
- `exploiting-race-condition-vulnerabilities`: Applied to analyze concurrency controls, database transactions, row-level locking (`SELECT ... FOR UPDATE`), savepoint rollback handling, and file creation operations in `LoginThrottle`, `AuthService`, and `App`.
- `performing-api-rate-limiting-bypass`: Applied to evaluate throttling scope boundaries, window reset mechanisms, key hashing, and bypass vectors in `LoginThrottle` and `AuthService`.
- General OWASP Top 10 / CWE Knowledge: Applied to review HTTP cookie header formatting and delimiter handling (CWE-113 / CWE-644 in `SessionCookie`), process lifecycle and in-memory credential sanitization (CWE-244 / CWE-226 in `App` and `AdminCli`), and file permissions.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Account Lockout Denial of Service via Unauthenticated Rate Limiting | High | CWE-307 | `src/main/java/com/example/auth/AuthService.java:75-85` |
| SEC-02 | Cookie Attribute Injection in `SessionCookie` via Permissive Path Validation | Medium | CWE-113 | `src/main/java/com/example/auth/SessionCookie.java:19` |
| SEC-03 | Plaintext Credentials Retained in Memory Due to `System.exit()` Bypassing Resource Cleanup | Medium | CWE-244 | `src/main/java/com/example/auth/App.java:48-68` |
| SEC-04 | Failure to Invalidate Active User Sessions on Password Change | Medium | CWE-613 | `src/main/java/com/example/auth/AdminCli.java:112-116` |

## 5. Detailed Findings

### SEC-01: Account Lockout Denial of Service via Unauthenticated Rate Limiting
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/AuthService.java:75-85`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:75-85
        ThrottleDecision decision = countAttempt(source, accountKey, now);
        if (decision != ThrottleDecision.ALLOWED) {
            hasher.verifyDecoy(password);
            LOG.log(Level.INFO, "Login throttled ({0}) for {1}",
                    new Object[]{decision, LogMasker.maskEmail(accountKey)});
            return AuthResult.failure(switch (decision) {
                case SOURCE_LIMIT -> AuthResult.Reason.SOURCE_THROTTLED;
                case ACCOUNT_LIMIT -> AuthResult.Reason.ACCOUNT_THROTTLED;
                default -> AuthResult.Reason.INTERNAL_ERROR;
            });
        }
```

**Why it is a problem:**
`AuthService` tracks failed attempts per network source (`maxAttemptsPerSource`, default 30) and per target account (`maxAttemptsPerAccount`, default 10). Because the account limit is lower than the source limit, an unauthenticated attacker from a single IP or client source can submit 10 failed login requests targeting any victim's email address. During these 10 attempts, the attacker's source limit is never reached (10 < 30), but the victim's account counter reaches the maximum allowed attempts.

Once the account limit is reached, `countAttempt` returns `ThrottleDecision.ACCOUNT_LIMIT`. At line 76, `AuthService` halts authentication immediately and returns failure without verifying the password. Consequently, the legitimate account owner is locked out from logging in from any location or IP address, even when providing the correct password. An attacker can persistently deny access to targeted users or administrators by submitting 10 automated requests every throttle window (default 15 minutes), weaponizing the rate limiter as a denial-of-service tool in direct violation of the design requirement to prevent account lockout abuse.

**Fix:**
Avoid a hard account-level lockout that blocks legitimate credentials across all origins. Instead, enforce attempt limits primarily on the combination of source and account (or require progressive delays / CAPTCHA / MFA). If an account-wide limit is reached, allow attempts from non-throttled sources to proceed to credential verification, and clear the account counter if the password is valid:

```java
        ThrottleDecision decision = countAttempt(source, accountKey, now);
        if (decision == ThrottleDecision.SOURCE_LIMIT || decision == ThrottleDecision.ERROR) {
            hasher.verifyDecoy(password);
            LOG.log(Level.INFO, "Login throttled ({0}) for {1}",
                    new Object[]{decision, LogMasker.maskEmail(accountKey)});
            return AuthResult.failure(decision == ThrottleDecision.SOURCE_LIMIT
                    ? AuthResult.Reason.SOURCE_THROTTLED
                    : AuthResult.Reason.INTERNAL_ERROR);
        }

        if (email.isEmpty() || !passwordAcceptable) {
            hasher.verifyDecoy(password);
            LOG.log(Level.FINE, "Login rejected: input failed validation");
            return AuthResult.failure(AuthResult.Reason.INVALID_INPUT);
        }

        AuthResult result = verifyAndIssue(email.get(), password, source, now);
        // If account-level limit was exceeded and credentials failed, report throttled
        if (decision == ThrottleDecision.ACCOUNT_LIMIT && !result.isAuthenticated()) {
            return AuthResult.failure(AuthResult.Reason.ACCOUNT_THROTTLED);
        }
        return result;
```

---

### SEC-02: Cookie Attribute Injection in `SessionCookie` via Permissive Path Validation
- **Severity:** Medium
- **CWE:** CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
- **Location:** `src/main/java/com/example/auth/SessionCookie.java:19`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookie.java:19
    private static final Pattern PATH = Pattern.compile("^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$");
```

**Why it is a problem:**
Under RFC 6265 §4.1.1, the semicolon character (`;`) serves as the attribute delimiter in HTTP `Set-Cookie` response headers (`path-value = <any CHAR except CTLs or ";">`).

The regular expression `PATH` in `SessionCookie.java` erroneously includes both semicolon (`;`) and equals (`=`) in its character set. In `SessionCookie.setCookieHeader`:
```java
return COOKIE_NAME + "=" + token
        + "; Max-Age=" + seconds
        + "; Path=" + path
        + "; HttpOnly; Secure; SameSite=Strict";
```
If a caller-controlled or redirect-derived path contains a semicolon (for example, `/app;Domain=attacker.com`), the resulting header becomes:
`Set-Cookie: sid=<token>; Max-Age=1800; Path=/app;Domain=attacker.com; HttpOnly; Secure; SameSite=Strict`

The browser parses `Domain=attacker.com` as an explicit cookie attribute, overriding the default host-only cookie scope and transmitting the session token to attacker-controlled domains or subdomains, leading to session hijacking.

**Fix:**
Disallow semicolons and equals signs in the cookie path regular expression to enforce compliance with RFC 6265:

```java
    private static final Pattern PATH = Pattern.compile("^/[A-Za-z0-9._~!$&'()*+:@%/-]{0,200}$");
```

---

### SEC-03: Plaintext Credentials Retained in Memory Due to `System.exit()` Bypassing Resource Cleanup
- **Severity:** Medium
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Memory Scavenging')
- **Location:** `src/main/java/com/example/auth/App.java:48-68`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/App.java:48-68
            if (result.isAuthenticated()) {
                Optional<String> token = result.sessionToken();
                if (token.isPresent()) {
                    reportSession(token.get(), config.sessionTokenFile());
                }
                System.exit(0);
            }
            System.exit(1);
        } catch (AuthConfig.ConfigException e) {
            // Configuration problems are an operator-facing message with no secret values.
            System.err.println("Startup failed: " + e.getMessage());
            System.exit(2);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Could not read credentials from the terminal", e);
            System.err.println("Authentication failed. Please try again later.");
            System.exit(1);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
```

**Why it is a problem:**
`App.java` collects user passwords into a `char[] password` array and defines a `finally` block (lines 64–68) intended to zero the array using `Arrays.fill(password, '\0')`. It also initializes `AuthConfig config` in a `try-with-resources` statement to invoke `config.close()`, which clears `dbPassword`.

However, inside the `try` block, `App.main` invokes `System.exit(0)` on line 53 upon successful authentication and `System.exit(1)` on line 55 on failure. According to Java Language Specification §11.1.3, calling `System.exit()` immediately terminates the Java Virtual Machine. When `System.exit()` is called, neither `finally` blocks nor `try-with-resources` `close()` methods are executed.

As a result, neither `password` nor `dbPassword` is cleared before JVM termination. Plaintext credentials remain resident in heap memory across the process lifecycle, exposing them to process core dumps, swap files, and memory inspection tools. A similar issue occurs in `AdminCli.java:42`, where calling `System.exit()` inside `try (AuthConfig config = ...)` prevents `config.close()` from clearing `dbPassword`.

**Fix:**
Store the process exit code in a local variable, allow the `try-with-resources` and `finally` blocks to complete normally to wipe credentials, and call `System.exit()` as the final statement outside the blocks:

```java
        int exitCode = 1;
        char[] password = null;
        try (AuthConfig config = AuthConfig.fromEnvironment(); ConsoleIo io = new ConsoleIo()) {
            AuthService service = new AuthService(config, new Database(config), new PasswordHasher(),
                    new CredentialRepository(), new LoginThrottle(), new SessionService());

            String email = io.readLine("Email address: ");
            password = io.readPassword("Password: ");

            AuthResult result = service.authenticate(email, password, config.sourceId());
            System.out.println(result.userMessage());

            if (result.isAuthenticated()) {
                Optional<String> token = result.sessionToken();
                if (token.isPresent()) {
                    reportSession(token.get(), config.sessionTokenFile());
                }
                exitCode = 0;
            } else {
                exitCode = 1;
            }
        } catch (AuthConfig.ConfigException e) {
            System.err.println("Startup failed: " + e.getMessage());
            exitCode = 2;
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Could not read credentials from the terminal", e);
            System.err.println("Authentication failed. Please try again later.");
            exitCode = 1;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
        System.exit(exitCode);
```

---

### SEC-04: Failure to Invalidate Active User Sessions on Password Change
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/AdminCli.java:112-116`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AdminCli.java:112-116
            String encoded = new PasswordHasher().hash(first);
            try (Connection connection = database.openTransaction()) {
                new CredentialRepository().saveCredential(connection, email.get(), encoded);
                connection.commit();
            }
```

**Why it is a problem:**
When an administrator resets or updates a user's password using `AdminCli.setPassword`, only the `app_user.password_hash` column is updated. Active sessions in the `user_session` table are neither expired nor marked as revoked (`revoked_at IS NULL`).

Furthermore, `SessionService` only provides a token-specific revocation method (`revoke(Connection, String token, Instant now)`), with no method to revoke all sessions for a user ID. `SessionService.resolveUserId` verifies session tokens by checking `s.revoked_at IS NULL AND s.expires_at > ? AND u.is_active = TRUE`, without checking whether the credential hash changed after session creation.

If a password reset is performed in response to account compromise, credential stuffing, or stolen device incidents, any session tokens previously obtained by an adversary remain active and valid until their scheduled expiration (up to 24 hours). This violates OWASP ASVS v4.0.3 §3.3.4 ("Verify that user sessions are invalidated upon password change or reset").

**Fix:**
Add a method `revokeAllForUser` to `SessionService` and invoke it within the password update transaction in `AdminCli.setPassword`:

```java
            String encoded = new PasswordHasher().hash(first);
            try (Connection connection = database.openTransaction()) {
                CredentialRepository credentials = new CredentialRepository();
                credentials.saveCredential(connection, email.get(), encoded);
                Optional<CredentialRepository.Credential> cred = credentials.findForUpdate(connection, email.get());
                if (cred.isPresent()) {
                    new SessionService().revokeAllForUser(connection, cred.get().userId(), Instant.now());
                }
                connection.commit();
            }
```

Implementation in `SessionService.java`:
```java
    private static final String REVOKE_ALL_FOR_USER =
            "UPDATE user_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL";

    public void revokeAllForUser(Connection connection, long userId, Instant now) throws SQLException {
        if (userId <= 0) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(REVOKE_ALL_FOR_USER)) {
            ps.setObject(1, OffsetDateTime.ofInstant(now, ZoneOffset.UTC));
            ps.setLong(2, userId);
            ps.executeUpdate();
        }
    }
```

## 6. Verified Controls and Checks With No Finding
- **SQL Injection Defenses:** Verified across all database operations in `CredentialRepository.java`, `LoginThrottle.java`, and `SessionService.java`. Every dynamic query uses parameterized `PreparedStatement` queries with explicit positional parameter bindings (`?`). No SQL statements are constructed through string concatenation or formatting. DDL statements in `AdminCli.java` originate exclusively from the bundled `/schema.sql` classpath resource.
- **Cryptographic Password Hashing:** Verified in `PasswordHasher.java`. Uses standard JDK `PBKDF2WithHmacSHA512` with 210,000 iterations, 16-byte random salts generated via `SecureRandom`, and 256-bit derived key lengths, matching OWASP password storage guidelines.
- **Timing Side-Channel Defenses:** Verified in `PasswordHasher.java:118` and `AuthService.java:132, 140`. Hash verification uses `java.security.MessageDigest.isEqual` for constant-time comparison. Failed lookups (non-existent accounts, unusable hashes, disabled accounts) execute a full decoy PBKDF2 calculation (`verifyDecoy`) of equal computational cost to prevent response-time account enumeration.
- **Session Token Generation & Storage:** Verified in `SessionService.java`. Tokens are 256-bit cryptographically secure random values (32 bytes from `SecureRandom`) encoded as base64url without padding. Only the SHA-256 digest of the token is stored in the database (`user_session.token_hash`), ensuring that a database breach does not reveal valid session tokens.
- **Hardcoded Secrets:** Verified across the entire repository (`pom.xml`, `schema.sql`, and all Java classes). No hardcoded passwords, private keys, API tokens, or credentials exist in source code or configuration defaults.
- **Database Connection Security:** Verified in `Database.java` and `AuthConfig.java`. Database credentials are supplied through separate JDBC driver properties rather than embedded in the connection URL. `AuthConfig` verifies that `AUTH_DB_PASSWORD_FILE` is a regular file with strictly owner-only POSIX permissions (`chmod 600`) and disallows dangerous JDBC URL parameters (`init=`, `runscript`, `socketfactory`).
- **Account Enumeration Defenses:** Verified in `AuthResult.java`. The application returns identical failure messages and exit codes (`1`) for incorrect passwords, non-existent accounts, disabled accounts, and throttled attempts, preventing attackers from distinguishing valid usernames via user-facing output.
- **Input Validation:** Verified in `InputValidator.java`. Strict RFC-5321 length limits and character boundaries are enforced on email addresses; passwords are validated against printable character ranges; source identifiers are strictly matched against `^[A-Za-z0-9.:_-]{1,64}$`.
- **Sensitive Data Masking in Telemetry:** Verified in `LogMasker.java` and `LoggingSetup.java`. Plaintext passwords and session tokens are never logged. Emails logged for operational tracking are truncated to their initial character and combined with a truncated SHA-256 fingerprint (`eid:...`). Log output is routed exclusively to stderr via a standard console handler.
- **Database Concurrency and Race Condition Safeguards:** Verified in `LoginThrottle.java` and `CredentialRepository.java`. Uses `READ_COMMITTED` transaction isolation and explicit pessimistic row locking (`SELECT ... FOR UPDATE`). Concurrency races on initial counter inserts are handled via transaction savepoints and retry under row locks.
