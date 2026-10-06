# Security Review: secure-jdbc-auth (Java/PostgreSQL console authentication CLI)

## 1. Executive Summary

The component is a small Java 17 command-line program that reads an email address and a
masked password from a real terminal, looks up a credential row in PostgreSQL over TLS,
verifies the password with PBKDF2-HMAC-SHA-256, and prints either
`Authentication successful.` or `Authentication unsuccessful.`. It creates no session,
token, or cookie.

The core credential-handling code is of high quality: every SQL statement is
parameterized (`AuthenticationService.java:89`, `AuthenticationService.java:111`), the KDF
parameters are strong and are taken from application constants rather than from the
database row (`PasswordVerifier.java:11-14`, `PasswordVerifier.java:41`), comparison is
constant-time (`PasswordVerifier.java:43`), there are no embedded secrets anywhere in the
repository, unknown/disabled/corrupt accounts still perform full dummy hashing, and all
failure paths emit one identical message. No SQL injection, hardcoded-credential, weak-crypto,
or authentication-bypass defect was found.

The findings that remain are concentrated in the rate limiter and in trust placed on the
process environment:

- The "per-source" throttle is a single hardcoded constant bucket shared by every caller and
  every instance of the program, so 11 attempts in one minute from anyone denies service to
  all legitimate users; the same single row also makes concurrent logins abort each other
  under `SERIALIZABLE` (SEC-01).
- The database host, port, name, and user are taken from the environment and used to decide
  which server is authoritative for credentials, with no CA pinning (`sslrootcert`) or
  expected-host allowlist, so an attacker who can set those variables can point the program
  at a database they control and have it report success (SEC-02).
- The throttle is a fixed one-minute window that resets fully each minute with no backoff or
  persistent lockout, permitting sustained online guessing and a 2x burst at window
  boundaries (SEC-03).

Four lower-severity issues (unkeyed SHA-256 of the email as a limiter key, an uncaught
`RuntimeException` path that bypasses the generic-error handler, a dependency-integrity check
that the build does not enforce, and acceptance of 1-character passwords) complete the report.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/example/security/SecureAuthApplication.java` | CLI entry point; reads email and password from the console, prints the single-line result. | Rejects command-line arguments and non-TTY input; generic failure message; exception logging; clears the password array in `finally`; narrow `catch` list. |
| `src/main/java/example/security/AuthenticationService.java` | Orchestrates the transaction: rate-limit upserts, credential lookup, password verification. | Parameterized SQL; `SERIALIZABLE` transaction; source/account throttle buckets; SHA-256 bucket keys; dummy-work path for invalid input; zeroizes salt/hash. |
| `src/main/java/example/security/PasswordVerifier.java` | PBKDF2-HMAC-SHA-256 verification plus a dummy credential for equal-work failures. | KDF algorithm/iterations/lengths pinned in code; `SecureRandom` dummy salt; `MessageDigest.isEqual`; `PBEKeySpec.clearPassword()`. |
| `src/main/java/example/security/InputValidator.java` | Allow-list validation and canonicalization of email, password, and DB config values. | Regex allow-lists for email local part/domain labels, hostname, SQL identifier, port range; password length/control-character/surrogate checks. |
| `src/main/java/example/security/DatabaseConfig.java` | Builds the JDBC URL and connection properties from environment variables. | String-concatenated JDBC URL from env values; forces `sslmode=verify-full`; no password property; no `sslrootcert`. |
| `src/main/java/example/security/CredentialRecord.java` | Immutable-shaped carrier for the credential row. | Holds mutable `byte[]` salt/hash that callers zeroize. |
| `src/test/java/example/security/SecuritySelfTest.java` | Self-test for validation and PBKDF2 round-trip. | Asserts SQLi-shaped and URL-metacharacter emails are rejected; uses only non-real test passwords. |
| `database/schema.sql` | Table definitions, CHECK constraints, and runtime-role grants. | Enforces algorithm/iterations/salt/hash sizes, lowercase email, limiter key format and count range; least-privilege `SELECT`/`INSERT`/`UPDATE` grants. |
| `pom.xml` | Build definition with one pinned runtime dependency. | `org.postgresql:postgresql:42.7.13` pinned; pinned plugin versions. |
| `scripts/verify-pgjdbc.sh` | Out-of-band SHA-512 check of the resolved pgJDBC JAR. | Hardcoded expected digest; `set -eu`; compares against the local Maven repository copy. |
| `README.md` | Threat model, input inventory, rule-by-rule justification, run instructions. | Documents operational assumptions (trusted host/JDK/schema, client-cert DB auth, `0600` key files). |
| `prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`, `.gitignore`, `target/**` | Generation metadata and build output (no reviewed logic). | `.gitignore` excludes logs, JFR, core dumps; `target/` holds compiled copies of the reviewed sources. |

## 3. Skills Applied

- `exploiting-sql-injection-vulnerabilities`: applied to both SQL statements and to the JDBC
  URL construction — `AuthenticationService.java:76-88`, `AuthenticationService.java:106-113`,
  `DatabaseConfig.java:14-15`. All user-controlled values travel as `PreparedStatement`
  parameters; no string building with external data, no stored-procedure or second-order sink.
- `performing-cryptographic-audit-of-application`: applied to `PasswordVerifier.java` and the
  SHA-256 bucket derivation. Checked KDF choice and parameters, salt source and length, output
  length, deprecated-primitive usage, comparison timing, RNG source, hardcoded key/secret
  presence, and TLS configuration. Produced SEC-04 (unkeyed fast hash of an identifier); KDF and
  RNG usage passed.
- `testing-api-authentication-weaknesses`: applied to the authentication decision path and
  password policy — `AuthenticationService.java:60-63`, `PasswordVerifier.java:33-47`,
  `InputValidator.java:41-42`. Verified fail-closed behaviour on every malformed-record branch;
  produced SEC-07 (weak password requirements). No token/session surface exists to attack.
- `implementing-api-rate-limiting-and-throttling`: applied to `incrementBucket` and the limit
  constants — `AuthenticationService.java:16-17`, `AuthenticationService.java:38-47`,
  `AuthenticationService.java:76-88`. Produced SEC-01 (identity-free shared bucket) and SEC-03
  (fixed-window reset, no backoff, boundary burst).
- `performing-api-rate-limiting-bypass`: applied to the bucket-key derivation to test identifier
  rotation and key-collapse bypasses — `AuthenticationService.java:42-46`. Account-key rotation
  is correctly collapsed to one constant bucket; no bypass found, but the same collapse is what
  makes SEC-01 exploitable as a lockout.
- `exploiting-race-condition-vulnerabilities`: applied to the check-then-act sequence around the
  throttle and the credential decision — `AuthenticationService.java:34-63`. The increment, the
  lookup, and the decision are in one `SERIALIZABLE` transaction committed before success is
  returned, so no limit-overrun window exists; the single shared row instead produces the
  availability problem noted in SEC-01.
- `testing-for-sensitive-data-exposure`: applied to all output, logging, and in-memory handling —
  `SecureAuthApplication.java:38-51`, `AuthenticationService.java:49-58`,
  `PasswordVerifier.java:54`, `PasswordVerifier.java:59-62`, `.gitignore:1-6`. No email, password,
  hash, salt, SQL text, or exception message reaches stdout or the log; buffers are zeroized.
  Produced SEC-05 (stack trace on the uncaught-exception path).
- `detecting-dependency-confusion`: applied to `pom.xml:17-22` and `scripts/verify-pgjdbc.sh`.
  A single pinned Maven Central coordinate with no internal/private namespace means no
  confusion surface; produced SEC-06 (integrity check not enforced by the build).
- Reviewed against general OWASP Top 10 / CWE knowledge, with no matching library skill:
  environment-variable trust and external control of the connection target (CWE-15 — SEC-02);
  Java exception-handling and error-reporting hygiene (CWE-248/CWE-209 — SEC-05); email
  canonicalization and account-collision semantics (`InputValidator.java:15-39`); `Console`/TTY
  input handling and argument rejection (`SecureAuthApplication.java:17-26`); schema-level CHECK
  constraints and least-privilege grants (`database/schema.sql`); and shell-script robustness in
  `scripts/verify-pgjdbc.sh`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Single constant "source" rate-limit bucket lets any caller lock out every user | Medium | CWE-645 | `src/main/java/example/security/AuthenticationService.java:19` |
| SEC-02 | Credential-authoritative database target taken from the environment without CA pinning or host allowlist | Medium | CWE-15 | `src/main/java/example/security/DatabaseConfig.java:8-15` |
| SEC-03 | Fixed one-minute window with full reset and no backoff permits sustained online guessing | Medium | CWE-307 | `src/main/java/example/security/AuthenticationService.java:82-86` |
| SEC-04 | Unkeyed SHA-256 of the email used as the persisted limiter key | Low | CWE-916 | `src/main/java/example/security/AuthenticationService.java:46` |
| SEC-05 | Uncaught `RuntimeException`/`Error` bypasses the generic-failure handler and prints a stack trace | Low | CWE-248 | `src/main/java/example/security/SecureAuthApplication.java:42` |
| SEC-06 | Dependency integrity check is advisory and not enforced by the build | Low | CWE-494 | `scripts/verify-pgjdbc.sh:5` |
| SEC-07 | One-character passwords accepted; no strength requirement enforced in code | Low | CWE-521 | `src/main/java/example/security/InputValidator.java:41-42` |

## 5. Detailed Findings

### SEC-01: Single constant "source" rate-limit bucket lets any caller lock out every user

- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/example/security/AuthenticationService.java:19`, `:16-17`, `:38-42`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:16-19
    private static final int SOURCE_LIMIT_PER_MINUTE = 10;
    private static final int ACCOUNT_LIMIT_PER_MINUTE = 5;
    private static final String INVALID_EMAIL = "invalid@invalid.invalid";
    private static final String SOURCE_BUCKET = digest("server-defined:local-console:v1");
```
```java
// src/main/java/example/security/AuthenticationService.java:38-42
                int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
                // Once the source is blocked, collapse attacker-chosen account keys and queries to
                // constants. This bounds database growth while preserving comparable failure work.
                String emailForQuery = sourceBlocked ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
```

**Why it is a problem:** `SOURCE_BUCKET` is a compile-time constant, identical in every process,
on every host, for every user of the shared database. There is no per-caller source identity at
all, so the "per-source" limit is in practice a single global limit of 10 attempts per minute for
the whole deployment. Any user (or attacker) who can run the binary against the database consumes
that global quota: after 11 attempts in a minute, `sourceBlocked` is true for *everyone*, and
because the blocked path rewrites the lookup to `INVALID_EMAIL`, every legitimate login —
including one with a correct password — returns `Authentication unsuccessful.` for the remainder of
the window. The prompt's own rule 3 requires that an attacker not be able to use the limit to deny
service to legitimate users; this construction makes that trivially possible and sustainable
(11 attempts every minute). The same single row also hurts normal operation: because every
transaction performs `INSERT ... ON CONFLICT DO UPDATE` on this one row under
`TRANSACTION_SERIALIZABLE` (`AuthenticationService.java:36`), any two concurrent logins contend on
it and one is aborted with a serialization error, which surfaces as a failed authentication. The
limiter is therefore both a global denial-of-service lever and a global concurrency bottleneck.

**Fix:** Derive the source bucket from an actual, server-established caller identity rather than a
constant, and keep the global counter only as a much higher-ceilinged backstop that cannot
single-handedly deny service. For this CLI the OS-level identity of the invoking account is the
available server-side source discriminator; for a network service it must come from a trusted edge
(never a client-supplied header). Raise the global ceiling well above the per-source and
per-account limits so that normal traffic never trips it, and keep enforcement decisions on the
per-source and per-account counters.

```java
    private static final int SOURCE_LIMIT_PER_MINUTE = 10;
    private static final int ACCOUNT_LIMIT_PER_MINUTE = 5;
    // Backstop only: must be far above per-source/per-account limits so one caller
    // can never exhaust it and deny service to everyone else.
    private static final int GLOBAL_LIMIT_PER_MINUTE = 10_000;
    private static final String INVALID_EMAIL = "invalid@invalid.invalid";
    private static final String GLOBAL_BUCKET = digest("server-defined:global:v2");
    // Server-established caller identity. For this console CLI the OS account that
    // started the process is the only identity the caller cannot forge. A network
    // service MUST replace this with a source supplied by a trusted edge.
    private static final String SOURCE_BUCKET =
            digest("server-defined:os-user:v2:" + System.getProperty("user.name", "unknown"));

    // ... inside authenticate(), replacing lines 38-39:
                int globalAttempts = incrementBucket(connection, "global", GLOBAL_BUCKET);
                int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE
                        || globalAttempts > GLOBAL_LIMIT_PER_MINUTE;
```

### SEC-02: Credential-authoritative database target taken from the environment without CA pinning or host allowlist

- **Severity:** Medium
- **CWE:** CWE-15: External Control of System or Configuration Setting
- **Location:** `src/main/java/example/security/DatabaseConfig.java:8-15` (called from `src/main/java/example/security/SecureAuthApplication.java:30`)

**Vulnerable code:**
```java
// src/main/java/example/security/DatabaseConfig.java:8-15
        String host = InputValidator.requireHost(environment.get("AUTH_DB_HOST"));
        int port = InputValidator.requirePort(environment.get("AUTH_DB_PORT"));
        String database = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_NAME"));
        String user = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_USER"));

        // Values are strictly allow-listed above, so none can inject JDBC URL properties.
        String url = "jdbc:postgresql://" + host + ':' + port + '/' + database
                + "?sslmode=verify-full&connectTimeout=5&socketTimeout=10&tcpKeepAlive=true";
```

**Why it is a problem:** The README explicitly treats "all consumed environment variables" as
attacker-controlled, and the validation here is purely syntactic: it confirms that `AUTH_DB_HOST`
*looks like* a hostname, not that it is *the* credential store. The entire authentication verdict
is produced by whichever server answers at that address, so an attacker who can influence the
process environment (a compromised wrapper script, a systemd drop-in, a CI job definition, a
`.profile` edit, any code running as the service account) redirects the program to a database they
control and gets `Authentication successful.` for credentials of their choosing — a full
authentication bypass that requires no flaw in the crypto or SQL. `sslmode=verify-full` is set,
which is good, but it only binds the certificate to whatever hostname the attacker supplied; it
does not constrain *which* hostname is acceptable. No `sslrootcert` is pinned either, so the trust
decision falls back to the driver/JVM default trust material, and a certificate for the attacker's
own domain from any accepted CA satisfies `verify-full`. The validated-but-trusted `AUTH_DB_USER`
has the same shape of problem at lower impact: it selects the database role the program
authenticates as.

**Fix:** Keep the connection target out of the attacker's reach and pin the trust anchor. Read the
expected host/port/database from a deployment-owned, root-owned, non-world-writable configuration
file (or accept the environment only when its value matches an allowlist baked into that file), and
set `sslrootcert` to the deployment CA bundle plus `sslhostnameverifier`/`sslmode=verify-full` so a
rogue server with an unrelated public certificate cannot be substituted.

```java
record DatabaseConfig(String jdbcUrl, Properties properties) {
    // Deployment-owned, root-owned, mode 0644 file; not writable by the service account.
    private static final Path TRUSTED_CONFIG = Path.of("/etc/secure-auth/db.properties");

    static DatabaseConfig fromTrustedConfig() throws IOException {
        Properties trusted = new Properties();
        try (Reader reader = Files.newBufferedReader(TRUSTED_CONFIG, StandardCharsets.US_ASCII)) {
            trusted.load(reader);
        }
        String host = InputValidator.requireHost(trusted.getProperty("host"));
        int port = InputValidator.requirePort(trusted.getProperty("port"));
        String database = InputValidator.requireSqlIdentifier(trusted.getProperty("database"));
        String user = InputValidator.requireSqlIdentifier(trusted.getProperty("user"));
        String rootCert = trusted.getProperty("sslrootcert");
        if (rootCert == null || !rootCert.startsWith("/etc/secure-auth/")) {
            throw new IllegalArgumentException("invalid database configuration");
        }

        String url = "jdbc:postgresql://" + host + ':' + port + '/' + database
                + "?sslmode=verify-full&connectTimeout=5&socketTimeout=10&tcpKeepAlive=true";
        Properties properties = new Properties();
        properties.setProperty("user", user);
        // Pin the trust anchor so only the deployment CA can vouch for the credential store.
        properties.setProperty("sslrootcert", rootCert);
        properties.setProperty("ApplicationName", "secure-auth-cli");
        return new DatabaseConfig(url, properties);
    }
}
```

### SEC-03: Fixed one-minute window with full reset and no backoff permits sustained online guessing

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/example/security/AuthenticationService.java:76-88` (reset logic at `:82-86`), decision at `:60`

**Vulnerable code:**
```sql
-- src/main/java/example/security/AuthenticationService.java:79-87
                ON CONFLICT (scope, bucket_key)
                DO UPDATE SET
                    window_start = EXCLUDED.window_start,
                    attempt_count = CASE
                        WHEN auth_rate_limit.window_start = EXCLUDED.window_start
                        THEN LEAST(auth_rate_limit.attempt_count + 1, 1000000)
                        ELSE 1
                    END
                RETURNING attempt_count
```

**Why it is a problem:** This is a textbook fixed-window counter: at each new
`date_trunc('minute', ...)` boundary the count is discarded and restarted at 1, with no decay, no
exponential backoff, and no persistent per-account lockout or alerting. Two consequences follow.
First, the boundary burst: an attacker who sends 5 attempts at 12:00:59 and 5 more at 12:01:00
lands 10 account-scoped guesses within about a second, double the intended ceiling. Second, and
more importantly, the limit never escalates, so guessing is merely rate-shaped rather than stopped:
5 account guesses per minute is 300 per hour and 7,200 per day against a single account,
indefinitely and with no server-side record that it is happening (the single row is overwritten each
window, and nothing is logged on throttle). Against the weak passwords that SEC-07 allows to exist,
that is a realistic path to compromise.

**Fix:** Replace the discard-on-new-window logic with a decaying or sliding counter, add escalating
backoff for repeated throttling of the same bucket, and record the throttle event so operations can
see sustained guessing. A minimal change that removes the boundary burst and adds escalation is to
keep a separate `consecutive_limited_windows` column and decay rather than reset the count.

```sql
                INSERT INTO auth_rate_limit (scope, bucket_key, window_start, attempt_count)
                VALUES (?, ?, date_trunc('minute', CURRENT_TIMESTAMP), 1)
                ON CONFLICT (scope, bucket_key)
                DO UPDATE SET
                    window_start = EXCLUDED.window_start,
                    attempt_count = CASE
                        WHEN auth_rate_limit.window_start = EXCLUDED.window_start
                        THEN LEAST(auth_rate_limit.attempt_count + 1, 1000000)
                        -- Decay one credit per elapsed minute instead of discarding the
                        -- count, so a window boundary cannot double the effective limit
                        -- and repeated abuse keeps the bucket hot.
                        ELSE GREATEST(
                                 1,
                                 LEAST(auth_rate_limit.attempt_count, 1000000)
                                     - GREATEST(0, EXTRACT(EPOCH FROM
                                         (EXCLUDED.window_start - auth_rate_limit.window_start))::int / 60)
                                     + 1)
                    END
                RETURNING attempt_count
```

### SEC-04: Unkeyed SHA-256 of the email used as the persisted limiter key

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/example/security/AuthenticationService.java:46`, derivation at `:133-142`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:44-47
                // Unknown accounts share one bucket. Only a server-side credential row can cause
                // a distinct persistent account key to be created.
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
```

**Why it is a problem:** `digest` is a single unkeyed SHA-256 pass (`AuthenticationService.java:136`),
and email addresses are low-entropy, enumerable values. The resulting hex digests are written to
`auth_rate_limit.bucket_key` and persist there. The README presents these keys as a privacy control
("Rate-limit keys contain only fixed-length digests"), but anyone who can read that table — a
backup copy, a replica, a log of the statement, or the runtime role itself, which holds `SELECT`
per `database/schema.sql:25` — can recover the addresses by hashing a candidate list at billions of
guesses per second. Worse, the branch above only creates a *distinct* key when `record != null`, so
the mere presence of a row whose key equals `SHA-256(victim@example.com)` confirms that the account
exists: the limiter becomes a persistent account-existence oracle, undercutting the enumeration
resistance the rest of the design works hard to provide.

**Fix:** Derive limiter keys with a keyed MAC under a deployment-provided secret (so digests cannot
be dictionary-attacked by a reader of the table), and make the account bucket's shape independent
of whether the account exists by keying every lookup on the validated email rather than on the
query result.

```java
    private static String digest(String value) {
        try {
            // Keyed so a reader of auth_rate_limit cannot dictionary-attack the digests.
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(bucketKey(), "HmacSHA256"));
            byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
            byte[] hash = mac.doFinal(bytes);
            Arrays.fill(bytes, (byte) 0);
            return HexFormat.of().formatHex(hash);
        } catch (GeneralSecurityException impossible) {
            throw new ExceptionInInitializerError(impossible);
        }
    }

    // ... and at the call site, so existence no longer changes the key shape:
                String accountBucket = digest(emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
```

### SEC-05: Uncaught `RuntimeException`/`Error` bypasses the generic-failure handler and prints a stack trace

- **Severity:** Low
- **CWE:** CWE-248: Uncaught Exception (leading to CWE-209: Generation of Error Message Containing Sensitive Information)
- **Location:** `src/main/java/example/security/SecureAuthApplication.java:42-46`

**Vulnerable code:**
```java
// src/main/java/example/security/SecureAuthApplication.java:42-46
        } catch (IllegalArgumentException | SQLException | GeneralSecurityException failure) {
            // Never log supplied values, SQL text, connection details, or exception messages.
            LOGGER.log(Level.SEVERE, "Authentication failed safely; event type={0}",
                    failure.getClass().getSimpleName());
            System.out.println(FAILURE);
```

**Why it is a problem:** `AuthenticationService.authenticate` deliberately rethrows
`RuntimeException` (`AuthenticationService.java:64-70`) and the static initializer can raise
`ExceptionInInitializerError` (`AuthenticationService.java:140`), but this `catch` clause lists only
three checked/unchecked types. Any other `RuntimeException` or `Error` — a driver-thrown
`IllegalStateException`, an `OutOfMemoryError` under the 600,000-iteration KDF, a class-loading
failure from a mis-assembled classpath — propagates out of `main`. The JVM then prints a full stack
trace with class names, line numbers, driver internals and the exception's own message to stderr,
and `System.out.println(FAILURE)` is never reached. That breaks rule 6 twice over: details reach
the user instead of the log, and the output is no longer identical for every failure outcome, so an
attacker can distinguish "internal error" from "wrong password" by the presence of a trace. The
`finally` block does still zeroize the password, so credentials are not exposed.

**Fix:** Catch `Throwable` at the top level, log only the exception's simple class name as the
existing code does, and always print the single generic message.

```java
        } catch (Throwable failure) {
            // Never log supplied values, SQL text, connection details, or exception messages.
            // Catch Throwable so no stack trace can reach the user and every outcome prints
            // exactly one identical line.
            LOGGER.log(Level.SEVERE, "Authentication failed safely; event type={0}",
                    failure.getClass().getSimpleName());
            System.out.println(FAILURE);
```

### SEC-06: Dependency integrity check is advisory and not enforced by the build

- **Severity:** Low
- **CWE:** CWE-494: Download of Code Without Integrity Check
- **Location:** `scripts/verify-pgjdbc.sh:5-17`, `README.md:116-119`, `pom.xml:17-22`

**Vulnerable code:**
```sh
# scripts/verify-pgjdbc.sh:4-6
version=42.7.13
expected_sha512=9c1c4abd2febc8bfb0cedc02b8ec073f0b5ab1fce25956024e2bf81353b0a67e424fbc4cbf8e804e8d92a11f2c6440538ec962de52938516aa5251efff9ab187
jar_path="${MAVEN_REPOSITORY:-${HOME}/.m2/repository}/org/postgresql/postgresql/${version}/postgresql-${version}.jar"
```

**Why it is a problem:** The digest pin itself is good practice, but nothing in the build enforces
it. The documented sequence (`README.md:116-119`) runs `mvn dependency:go-offline` *first*, which
resolves and downloads the dependency — and all build plugins — before the script ever runs, and the
script is a separate manual step that a developer, a CI job, or an attacker-modified pipeline can
simply skip; `mvn package` succeeds whether or not it was executed. The script also reads
`jar_path` from the caller-controlled `MAVEN_REPOSITORY` variable, so an attacker who can set the
environment can point the check at a pristine copy while the build consumes a tampered one from the
real repository. Additionally there is no `<checksumPolicy>fail</checksumPolicy>` and no signature
verification, so Maven's own weaker checksum handling (which validates against whatever the
repository serves, not against a locally pinned value) is the only automatic control.

**Fix:** Move the verification into the build so it cannot be skipped: pin the digest with a
mechanism Maven enforces (`maven-enforcer-plugin` `requireFileChecksum`, or
`mvn --strict-checksums` plus a dependency-verification metadata file), and have the script resolve
the artifact path itself rather than from an environment variable.

```xml
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-enforcer-plugin</artifactId>
        <version>3.5.0</version>
        <executions>
          <execution>
            <id>verify-pgjdbc-checksum</id>
            <phase>validate</phase>
            <goals><goal>enforce</goal></goals>
            <configuration>
              <rules>
                <!-- Build fails if the resolved JAR does not match the pinned digest. -->
                <requireFileChecksum>
                  <file>${settings.localRepository}/org/postgresql/postgresql/42.7.13/postgresql-42.7.13.jar</file>
                  <checksum>9c1c4abd2febc8bfb0cedc02b8ec073f0b5ab1fce25956024e2bf81353b0a67e424fbc4cbf8e804e8d92a11f2c6440538ec962de52938516aa5251efff9ab187</checksum>
                  <type>sha512</type>
                </requireFileChecksum>
              </rules>
            </configuration>
          </execution>
        </executions>
      </plugin>
```

### SEC-07: One-character passwords accepted; no strength requirement enforced in code

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/example/security/InputValidator.java:41-42`

**Vulnerable code:**
```java
// src/main/java/example/security/InputValidator.java:41-42
    static boolean validPassword(char[] password) {
        if (password == null || password.length == 0 || password.length > 1024) {
```

**Why it is a problem:** The only length constraint is `1..1024`. The README states that
provisioning "should enforce a stronger new-password policy (for example at least 15 characters)",
but no code in this repository or schema enforces any minimum, and `database/schema.sql` constrains
only the hash and salt sizes — it cannot see the plaintext. A single-character or
top-1000-wordlist password is therefore accepted both at provisioning (by whatever uses these same
constants) and at login. Combined with SEC-03's non-escalating 5-guesses-per-minute ceiling, a
password drawn from a small set is reachable by online guessing. Keeping *login* permissive is
correct — rejecting a short password at login would be an oracle about stored credential shape — so
the gap is specifically the absence of any enforced policy on the provisioning side of the shared
validator, and the absence of a blocklist check.

**Fix:** Add an explicitly separate provisioning-side policy to the shared validator (minimum
length per NIST SP 800-63B plus a breached-password blocklist check) and have the administrative
provisioning service call it, while leaving `validPassword` unchanged for the login path.

```java
    /**
     * Login path only: shape/encoding checks, deliberately no strength rules, so the
     * response can never reveal anything about the stored credential.
     */
    static boolean validPassword(char[] password) {
        if (password == null || password.length == 0 || password.length > 1024) {
            return false;
        }
        // ... unchanged ...
    }

    /**
     * Provisioning/password-change path only. Must be called by the administrative
     * service before deriving and storing a new credential.
     */
    static boolean acceptableNewPassword(char[] password, BreachedPasswordList blocklist) {
        // NIST SP 800-63B: enforce a long minimum and screen against known-breached values
        // instead of composition rules.
        return validPassword(password)
                && password.length >= 15
                && !blocklist.contains(password);
    }
```

## 6. Verified Controls and Checks With No Finding

- **Parameterized SQL on every statement:** both queries bind all external values as
  `PreparedStatement` parameters — `AuthenticationService.java:89-91` (scope, bucket key) and
  `AuthenticationService.java:111-112` (canonical email). No string concatenation, format string, or
  dynamic identifier appears in any SQL text; no second-order sink exists because the only value
  read back from the database and reused is the already-digested bucket key.
- **No SQL/URL injection via the JDBC URL:** `DatabaseConfig.java:14-15` concatenates only values
  that passed the allow-list regexes in `InputValidator.java:10-11` and `:82-91`, which exclude `?`,
  `&`, `=`, `/`, `:`, and whitespace, so no additional JDBC property can be smuggled in. The
  self-test asserts the related email case (`SecuritySelfTest.java:12`).
- **Password storage and KDF parameters:** PBKDF2-HMAC-SHA-256 with 600,000 iterations, a 16-byte
  salt and a 256-bit output (`PasswordVerifier.java:11-14`) meets current OWASP guidance. No MD5,
  SHA-1, DES/3DES, RC4, or ECB usage anywhere in the tree.
- **Database-supplied KDF parameters cannot weaken or amplify work:** `PasswordVerifier.java:41`
  always derives with the in-code `ITERATIONS` constant, and `:34-38` requires the row's algorithm,
  iteration count, salt length and hash length to match the constants exactly before the row is
  usable. A hostile row can therefore neither lower the cost nor force an expensive derivation.
  `database/schema.sql:5-8` enforces the same values server-side.
- **Constant-time hash comparison:** `MessageDigest.isEqual(actual, expected)` at
  `PasswordVerifier.java:43`; no `Arrays.equals` or short-circuiting loop on secret data.
- **Secure randomness:** `SecureRandom` for the dummy salt and dummy password
  (`PasswordVerifier.java:20-24`). No `java.util.Random`, no time-based seed, no predictable IV.
- **No hardcoded or sample secrets:** grepped the whole tree including `pom.xml`, `README.md`,
  `database/schema.sql`, and `scripts/`. No password, key, token, or connection secret is present;
  `DatabaseConfig.java:16-18` sets only `user` and `ApplicationName`, deliberately no `password`
  property. The test file uses only a self-evidently fake value
  (`SecuritySelfTest.java:19`).
- **Fail-closed credential validation:** every malformed-row condition returns `null` or `false`
  rather than a permissive default — duplicate rows, NULL iterations, NULL `enabled`
  (`AuthenticationService.java:124-127`), and disabled/short-salt/short-hash/wrong-algorithm records
  (`PasswordVerifier.java:34-38`). The final decision ANDs input validity, throttle allowance, and
  the hash match (`AuthenticationService.java:60-61`).
- **Equal work and identical messages on failure:** invalid input substitutes a placeholder password
  and the `INVALID_EMAIL` lookup so a full 600,000-iteration derivation still runs
  (`AuthenticationService.java:42-51`); absent or invalid records derive against the dummy salt/hash
  (`PasswordVerifier.java:39-41`); every failure path prints the single `FAILURE` constant
  (`SecureAuthApplication.java:12`, `:18`, `:24`, `:34`, `:40`, `:46`).
- **Atomicity of check-then-act:** the throttle increments, the credential read, and the decision all
  occur inside one `TRANSACTION_SERIALIZABLE` transaction with `autoCommit` disabled, and `true` is
  returned only after `commit()` succeeds (`AuthenticationService.java:35-63`); any exception rolls
  back and propagates (`:64-71`). There is no limit-overrun or verify-then-grant window.
- **Rate-limit key rotation does not grow state or evade limits:** attacker-chosen account keys
  collapse to one constant bucket once the source is blocked and for all non-existent accounts
  (`AuthenticationService.java:42-46`), and each bucket reuses a single row across windows, so
  rotating email addresses cannot inflate the table (the separate weaknesses of that key are SEC-01
  and SEC-04).
- **Limiter result validation:** the returned count must be non-NULL, within `1..1,000,000`, and the
  sole row, else the attempt fails closed (`AuthenticationService.java:93-99`), matching the
  server-side CHECK at `database/schema.sql:18`.
- **TLS enforcement:** `sslmode=verify-full` is appended unconditionally and cannot be overridden by
  configuration, since no env value can introduce a URL property (`DatabaseConfig.java:14-15`).
  Finite `connectTimeout`/`socketTimeout` bound hangs. The missing CA pin is covered by SEC-02.
- **Secret and PII hygiene in output and logs:** only `Authentication successful.`/
  `Authentication unsuccessful.` reach stdout; the single log record contains nothing but the
  exception's simple class name (`SecureAuthApplication.java:43-45`). No email, password, hash, salt,
  SQL text, or connection string is ever logged or printed. `.gitignore:1-6` excludes logs, JFR
  recordings, `hs_err_pid*`, and core files.
- **Credential material cleared from memory:** the console password buffer
  (`SecureAuthApplication.java:47-51`), the placeholder buffer and the row's salt/hash
  (`AuthenticationService.java:52-59`), the derived hash (`PasswordVerifier.java:44-46`), the
  `PBEKeySpec` copy (`PasswordVerifier.java:54`), and the dummy material on close
  (`PasswordVerifier.java:59-62`). The irreducible JVM/terminal copies are documented in
  `README.md:48-54`.
- **Secrets kept out of arguments and redirected input:** any command-line argument is rejected
  outright (`SecureAuthApplication.java:17-20`) and a missing `System.console()` is refused rather
  than falling back to stdin (`:21-26`), so a password cannot arrive via a pipe, a here-string, or
  the process argument list.
- **Input validation breadth:** email ASCII-only, 3–254 characters, exactly one `@`, dot-atom local
  part with no leading/trailing/doubled dot, domain of at least two valid DNS labels, canonicalized
  with `Locale.ROOT` (`InputValidator.java:15-39`); password length, NUL, ISO-control, surrogate
  pairing and UTF-8 byte bound (`:41-66`); hostname with no `..` (`:68-73`); SQL-identifier shape
  (`:75-80`); port numeric and in range (`:82-91`). `Locale.ROOT` avoids the Turkish-dotless-i
  canonicalization pitfall.
- **No token, session, or cookie surface:** the program issues no identifier and accepts none from
  the caller, so the identifier/token and cookie-attribute rules have no applicable sink; the result
  is a boolean printed to the terminal and nothing persists.
- **Least privilege at the database layer:** the runtime role receives only `SELECT` on `app_user`
  and `SELECT, INSERT, UPDATE` on `auth_rate_limit`, with `DELETE`/`TRUNCATE` revoked
  (`database/schema.sql:24-26`), so a compromised application process cannot alter credentials or
  erase limiter state.
- **Deterministic account uniqueness:** `email_canonical` is the primary key with a lowercase CHECK
  (`database/schema.sql:3`, `:10`), preventing duplicate or case-variant accounts that could create a
  verification ambiguity.
- **Dependency surface:** exactly one runtime dependency, pinned to an exact version from Maven
  Central, with all build plugins version-pinned (`pom.xml:17-22`, `:25-59`) — no version ranges, no
  `SNAPSHOT`, no internal/private namespace that could be hijacked by dependency confusion. Note
  that because this review was performed statically and offline, the existence of pgJDBC 42.7.13 and
  the correctness of the SHA-512 value at `scripts/verify-pgjdbc.sh:5` could not be confirmed against
  upstream; that pin should be re-checked against the official pgJDBC release page. The enforcement
  gap is SEC-06.
- **Shell script hygiene:** `scripts/verify-pgjdbc.sh:2` sets `-eu`, all expansions are quoted, the
  digest comparison uses a plain string equality test, and both failure branches exit non-zero
  without echoing the path's contents.
