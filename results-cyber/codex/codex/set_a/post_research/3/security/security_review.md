# Security Review: Secure JDBC Authentication CLI

## 1. Executive Summary
This Java 17 command-line component reads an email address and masked password, validates them, retrieves a PostgreSQL credential record over a hostname-verified TLS connection, verifies a PBKDF2-HMAC-SHA-256 password hash, and records source/account authentication attempts atomically. The review found three vulnerabilities: attacker-controlled environment variables can select the database that acts as the authentication authority (High), already-throttled requests still perform the expensive credential lookup and password derivation (Medium), and minute-aligned fixed windows permit boundary bursts at twice the intended guessing rate (Low). Strong controls include parameterized SQL, bounded credential metadata, constant-time hash comparison, generic failure output, explicit secret-array clearing, serializable transactions, least-privilege grants, and a pinned pgJDBC release with a fail-closed checksum script.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Defines the Java 17 Maven build and runtime dependency. | Pins pgJDBC and build-plugin versions and selects the application entry point. |
| `database/schema.sql` | Creates credential and authentication-rate-limit tables. | Constrains password metadata and limiter state and grants the runtime role least-privilege access. |
| `scripts/verify-pgjdbc.sh` | Verifies the downloaded pgJDBC JAR. | Compares the dependency against a pinned SHA-512 digest and fails closed on absence or mismatch. |
| `src/main/java/example/security/AuthenticationService.java` | Orchestrates database-backed authentication. | Performs transactional rate limiting, parameterized credential lookup, password verification, generic failure handling, and sensitive-array clearing. |
| `src/main/java/example/security/CredentialRecord.java` | Carries credential metadata read from PostgreSQL. | Holds the algorithm, work factor, salt, hash, and enabled state consumed by verification. |
| `src/main/java/example/security/DatabaseConfig.java` | Builds JDBC connection configuration from environment variables. | Validates URL components and forces `sslmode=verify-full`, but allows untrusted configuration to select the authentication database. |
| `src/main/java/example/security/InputValidator.java` | Validates email, password, and database configuration inputs. | Applies type, length, character, structure, and range allowlists before inputs reach security-sensitive operations. |
| `src/main/java/example/security/PasswordVerifier.java` | Derives and compares password hashes. | Uses PBKDF2-HMAC-SHA-256, `SecureRandom`, fixed work factors, dummy verification, constant-time comparison, and array clearing. |
| `src/main/java/example/security/SecureAuthApplication.java` | Provides the terminal-only application entry point. | Rejects arguments and redirected input, masks password entry, emits uniform user-facing failures, avoids sensitive logging, and clears the password. |
| `src/test/java/example/security/SecuritySelfTest.java` | Exercises validators and password verification. | Checks representative injection-shaped inputs, malformed passwords, correct/incorrect hashes, unknown-account dummy work, and array clearing. |
| `README.md` | Documents operation, deployment, and the threat model. | Declares environment variables and database rows attacker-controlled and specifies TLS, identity, dependency, logging, and filesystem assumptions used in this review. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory every source/configuration file, identify security-relevant behaviours, route them to specialized skills, and require CWE and file:line evidence.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters, salt generation requirements, dummy hashing, constant-time comparison, SHA-256 bucket derivation, entropy, secret storage, and memory clearing.
- `testing-api-authentication-weaknesses`: Applied to authentication-authority trust, fail-closed behaviour, account enumeration, password handling, credential stuffing resistance, secret leakage, and the absence of sessions/tokens.
- `exploiting-sql-injection-vulnerabilities`: Applied to every SQL statement, JDBC URL construction, bound parameters, second-order database values, error disclosure, and database-role privileges.
- `implementing-api-rate-limiting-and-throttling`: Applied to source/account key selection, fixed-window behaviour, atomic updates, concurrency, brute-force limits, storage growth, and work performed after rejection.
- `configuring-tls-1-3-for-secure-communications`: Applied to the PostgreSQL transport, hostname verification, trust-store assumptions, and whether untrusted configuration can redirect the protected connection.
- `detecting-dependency-confusion`: Applied to the Maven manifest, public/private coordinate resolution, dependency pinning, and the pgJDBC integrity-check workflow.
- General OWASP Top 10 / CWE knowledge: Applied where no specialized skill matched, including environment trust boundaries, input/error handling, resource cleanup, sensitive logging, OS command and deserialization exposure, database least privilege, shell quoting, and transaction safety.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Untrusted environment selects the authentication authority | High | CWE-15 | `src/main/java/example/security/DatabaseConfig.java:7-19` |
| SEC-02 | Throttled requests still perform expensive password hashing | Medium | CWE-400 | `src/main/java/example/security/AuthenticationService.java:38-61` |
| SEC-03 | Minute-aligned windows permit burst guessing above configured limits | Low | CWE-307 | `src/main/java/example/security/AuthenticationService.java:76-88` |

## 5. Detailed Findings

### SEC-01: Untrusted environment selects the authentication authority
- **Severity:** High
- **CWE:** CWE-15: External Control of System or Configuration Setting
- **Location:** `src/main/java/example/security/DatabaseConfig.java:7-19`

**Vulnerable code:**
```java
// src/main/java/example/security/DatabaseConfig.java:7-19
    static DatabaseConfig fromEnvironment(Map<String, String> environment) {
        String host = InputValidator.requireHost(environment.get("AUTH_DB_HOST"));
        int port = InputValidator.requirePort(environment.get("AUTH_DB_PORT"));
        String database = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_NAME"));
        String user = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_USER"));

        // Values are strictly allow-listed above, so none can inject JDBC URL properties.
        String url = "jdbc:postgresql://" + host + ':' + port + '/' + database
                + "?sslmode=verify-full&connectTimeout=5&socketTimeout=10&tcpKeepAlive=true";
        Properties properties = new Properties();
        properties.setProperty("user", user);
        properties.setProperty("ApplicationName", "secure-auth-cli");
        return new DatabaseConfig(url, properties);
    }
```

**Why it is a problem:** The documented threat model says all consumed environment variables are attacker-controlled, but these four values determine which server, database, and role supply the credential record that decides authentication. Character allowlisting prevents JDBC-URL injection; it does not establish that the selected database is the intended authentication authority. Likewise, `sslmode=verify-full` proves that a certificate matches the attacker-selected hostname, not that the hostname is approved. An attacker who points the process at a PostgreSQL server they control can return an enabled credential record whose salt and hash match a password known to the attacker, causing the application to report successful authentication. Treating the host/JVM as trusted does not make mutable process configuration trustworthy under the stated model.

**Fix:** Load the endpoint and database identity from owner-controlled deployment configuration outside the stated attacker boundary, or pin/allowlist every security-sensitive value against independently trusted constants. Continue using `verify-full`; it becomes meaningful once the expected hostname is trusted. For example:
```java
private static final String EXPECTED_HOST = "db.example.internal";
private static final int EXPECTED_PORT = 5432;
private static final String EXPECTED_DATABASE = "authdb";
private static final String EXPECTED_USER = "auth_runtime";

static DatabaseConfig fromEnvironment(Map<String, String> environment) {
    String host = InputValidator.requireHost(environment.get("AUTH_DB_HOST"));
    int port = InputValidator.requirePort(environment.get("AUTH_DB_PORT"));
    String database = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_NAME"));
    String user = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_USER"));
    if (!EXPECTED_HOST.equals(host) || port != EXPECTED_PORT
            || !EXPECTED_DATABASE.equals(database) || !EXPECTED_USER.equals(user)) {
        throw new IllegalArgumentException("invalid database configuration");
    }

    String url = "jdbc:postgresql://" + EXPECTED_HOST + ':' + EXPECTED_PORT + '/'
            + EXPECTED_DATABASE
            + "?sslmode=verify-full&connectTimeout=5&socketTimeout=10&tcpKeepAlive=true";
    Properties properties = new Properties();
    properties.setProperty("user", EXPECTED_USER);
    properties.setProperty("ApplicationName", "secure-auth-cli");
    return new DatabaseConfig(url, properties);
}
```

### SEC-02: Throttled requests still perform expensive password hashing
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/example/security/AuthenticationService.java:38-61`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:38-61
                int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
                // Once the source is blocked, collapse attacker-chosen account keys and queries to
                // constants. This bounds database growth while preserving comparable failure work.
                String emailForQuery = sourceBlocked ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
                CredentialRecord record = readCredential(connection, emailForQuery);
                // Unknown accounts share one bucket. Only a server-side credential row can cause
                // a distinct persistent account key to be created.
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
                boolean passwordMatches;
                char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
                try {
                    passwordMatches = passwordVerifier.verify(boundedPassword, record);
                } finally {
                    if (boundedPassword != password) {
                        Arrays.fill(boundedPassword, '\0');
                    }
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
                boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
                boolean authenticated = inputValid && allowed && passwordMatches;
```

**Why it is a problem:** Once `sourceBlocked` is true, authentication cannot succeed, but the code still performs a credential query, another database upsert, and a 600,000-iteration PBKDF2 derivation while holding the transaction open. An attacker can therefore continue forcing the dominant CPU operation and database work without limit; the rate limiter restricts successful authentication attempts but does not restrict resource consumption. The shared source row also serializes concurrent transactions, increasing availability impact. Comparable dummy work is appropriate for ordinary unknown-account failures, but it is unnecessary after a non-secret, server-side source limit has already rejected the request.

**Fix:** Commit the source counter and reject immediately when the source limit is exceeded. Retain dummy hashing for attempts that remain within the source budget so ordinary valid/invalid-account failures remain comparable.
```java
int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
if (sourceAttempts > SOURCE_LIMIT_PER_MINUTE) {
    connection.commit();
    return false;
}

String emailForQuery = canonical.orElse(INVALID_EMAIL);
CredentialRecord record = readCredential(connection, emailForQuery);
String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
int accountAttempts = incrementBucket(connection, "account", accountBucket);
boolean passwordMatches;
char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
try {
    passwordMatches = passwordVerifier.verify(boundedPassword, record);
} finally {
    if (boundedPassword != password) {
        Arrays.fill(boundedPassword, '\0');
    }
    if (record != null) {
        clear(record.salt(), record.passwordHash());
    }
}
boolean allowed = accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
boolean authenticated = inputValid && allowed && passwordMatches;
```

### SEC-03: Minute-aligned windows permit burst guessing above configured limits
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/example/security/AuthenticationService.java:76-88`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:76-88
        String sql = """
                INSERT INTO auth_rate_limit (scope, bucket_key, window_start, attempt_count)
                VALUES (?, ?, date_trunc('minute', CURRENT_TIMESTAMP), 1)
                ON CONFLICT (scope, bucket_key)
                DO UPDATE SET
                    window_start = EXCLUDED.window_start,
                    attempt_count = CASE
                        WHEN auth_rate_limit.window_start = EXCLUDED.window_start
                        THEN LEAST(auth_rate_limit.attempt_count + 1, 1000000)
                        ELSE 1
                    END
                RETURNING attempt_count
                """;
```

**Why it is a problem:** Buckets reset on wall-clock minute boundaries rather than after a full minute has elapsed. An attacker can place the full allowance immediately before a boundary and another full allowance immediately after it. This permits up to 20 source attempts and 10 attempts against one account in a short burst, twice the configured 10/minute and 5/minute limits, weakening resistance to online guessing and increasing the work spike described in SEC-02.

**Fix:** Use a true sliding window, or at minimum anchor each fixed window to the first attempt and reset it only after 60 elapsed seconds. The following atomic upsert removes the predictable wall-clock boundary burst; an event table or Redis sorted set can provide an exact sliding window if required.
```java
String sql = """
        INSERT INTO auth_rate_limit (scope, bucket_key, window_start, attempt_count)
        VALUES (?, ?, CURRENT_TIMESTAMP, 1)
        ON CONFLICT (scope, bucket_key)
        DO UPDATE SET
            window_start = CASE
                WHEN auth_rate_limit.window_start <= EXCLUDED.window_start - INTERVAL '1 minute'
                THEN EXCLUDED.window_start
                ELSE auth_rate_limit.window_start
            END,
            attempt_count = CASE
                WHEN auth_rate_limit.window_start <= EXCLUDED.window_start - INTERVAL '1 minute'
                THEN 1
                ELSE LEAST(auth_rate_limit.attempt_count + 1, 1000000)
            END
        RETURNING attempt_count
        """;
```

## 6. Verified Controls and Checks With No Finding
- SQL injection: Both database operations use constant SQL and bind `scope`, bucket, and email through `PreparedStatement` at `AuthenticationService.java:75-112`; no attacker-controlled value is concatenated into SQL.
- JDBC URL injection: `InputValidator.java:68-90` restricts host, port, database, and user syntax, so URL delimiters and property injection are rejected. This does not cure the authentication-authority issue in SEC-01.
- Password hashing: `PasswordVerifier.java:11-14,33-55` fixes PBKDF2-HMAC-SHA-256 at 600,000 iterations with a 16-byte salt and 32-byte result, validates database-provided metadata before use, and compares with `MessageDigest.isEqual`.
- Randomness and dummy work: `PasswordVerifier.java:16-31` uses `SecureRandom` for a per-process dummy salt/password/hash, and `PasswordVerifier.java:33-46` performs the same KDF for ordinary unknown, disabled, or malformed records.
- Password and credential handling: `SecureAuthApplication.java:21-32` requires a real console and uses `readPassword`; `AuthenticationService.java:49-58`, `PasswordVerifier.java:42-45,49-61`, and `SecureAuthApplication.java:47-50` clear reachable password, salt, and hash arrays.
- Generic failures and logging: `SecureAuthApplication.java:12,17-25,33-46` emits the same user-facing failure text and logs only the exception class, not supplied values, SQL, connection details, or exception messages.
- Input bounds: `InputValidator.java:15-65` bounds and structurally validates email and password input, rejects control characters and malformed surrogate pairs, and limits password encoding work to 1,024 UTF-8 bytes.
- Credential-row validation: `AuthenticationService.java:105-129` requires at most one row and checks nullable primitive fields; `PasswordVerifier.java:33-43` rejects disabled rows and unexpected algorithm, iteration, salt, or hash values without letting hostile metadata alter KDF cost.
- Transaction and concurrency safety: `AuthenticationService.java:33-72,75-103` uses a serializable transaction, atomic PostgreSQL upserts, commit-before-success, rollback-on-failure, and try-with-resources. No check-then-update race was found.
- Database least privilege and integrity constraints: `database/schema.sql:2-26` constrains credential and limiter fields, prevents duplicate accounts, grants only credential reads and limiter reads/writes, and explicitly withholds destructive runtime access.
- TLS mode: `DatabaseConfig.java:13-18` forces pgJDBC `sslmode=verify-full` and does not expose a caller-controlled property suffix. With an independently trusted expected hostname and trust store, certificate and hostname verification are enabled.
- Secrets and tokens: No working password, private key, API key, session identifier, cookie, or bearer token is embedded or generated; the component returns only a one-time Boolean result and creates no authorization session.
- Command, path, and deserialization exposure: No application path invokes an OS command, opens an attacker-selected file, reflects a class, or deserializes an object. The dependency script quotes `jar_path` and uses fixed command arguments at `scripts/verify-pgjdbc.sh:4-16`.
- Dependency confusion and integrity: `pom.xml:15-22` contains one public Maven Central coordinate at an exact version, not a private/confusable artifact. `scripts/verify-pgjdbc.sh:4-17` fails closed if the expected JAR is absent or its SHA-512 digest differs. The local artifact was absent during this review, so its actual digest could not be reverified.
- Test coverage reviewed: `SecuritySelfTest.java:8-48` covers representative validation and password-verification cases. The existing test class could not be executed in the review environment because no Java runtime was installed; no source files or build outputs were modified to work around that limitation.
