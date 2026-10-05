# Security Review: secure-auth (Java CLI email/password authentication component)

## 1. Executive Summary

`secure-auth` is a Java 17 command-line component that authenticates an email address and
password against an SQL database (PostgreSQL or H2), rate-limits attempts in server-side
database counters, and issues a 256-bit random session token whose SHA-256 is the only
value stored. A separate operator CLI (`AdminCli`) creates the schema and sets passwords.

The code is unusually well hardened for its size. The high-risk classics are genuinely
absent: every SQL statement is a `PreparedStatement` with bound parameters (no string
concatenation anywhere), passwords are stored as PBKDF2-HMAC-SHA512 with 210,000
iterations and a per-user 16-byte `SecureRandom` salt, hash comparison uses
`MessageDigest.isEqual`, session tokens come only from `SecureRandom` and are never
caller-influenced, there are no hardcoded credentials in source, schema or test script,
authentication failure returns a single generic message for every reason, and failure
paths spend an equivalent "decoy" KDF cost so account existence is not disclosed by
timing. No Critical or High finding was identified.

The ten findings are design and defence-in-depth gaps rather than direct authentication
bypasses. The most important are: **existing sessions are not revoked when a password is
changed** (SEC-01), so a credential reset after a compromise does not evict the attacker;
**database transport security is never required** (SEC-02), so the validated JDBC URL may
legitimately be a cleartext connection carrying the DB password and all credential hashes;
the JDBC URL hardening uses an **incomplete denylist of dangerous driver options**
(SEC-03) that misses class-loading parameters such as PostgreSQL's
`sslhostnameverifier`/`authenticationPluginClassName`; and the per-source attempt counter
is keyed on a **single process-wide source identifier that is never cleared on success**
(SEC-04), which turns the rate limiter into a deployment-wide lockout. The remaining six
are Low: a password reset silently re-activating a deactivated account, unsalted SHA-256
used to pseudonymise email addresses, sensitive values copied into immutable `String`s
(with cleanup bypassed by `System.exit` inside try-with-resources), the non-TTY password
echo path, a silent empty-DB-password fallback for remote URLs, and a check-then-read race
on the DB password file.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/App.java` | Login CLI entry point | Reads credentials from the terminal, zeroes the password array, writes the session token to a 0600 file created with `CREATE_NEW`; `System.exit` inside try-with-resources |
| `src/main/java/com/example/auth/AdminCli.java` | Operator CLI: `init-schema`, `set-password` | Executes bundled DDL, enforces new-password policy, writes password hashes; no authentication of the operator beyond OS access |
| `src/main/java/com/example/auth/AuthService.java` | Authentication orchestration | Validation order, attempt accounting in its own committed transaction, verify-and-issue under a row lock, uniform failure results, masked logging |
| `src/main/java/com/example/auth/AuthConfig.java` | Environment configuration | JDBC URL allowlist regex + option denylist, DB password from file (POSIX permission check) or env, path normalisation, bounded integers |
| `src/main/java/com/example/auth/PasswordHasher.java` | Password hashing/verification | PBKDF2-HMAC-SHA512 210k, 16-byte random salt, strict parse of stored hash, constant-time compare, decoy hashing for timing uniformity |
| `src/main/java/com/example/auth/SessionService.java` | Session issue/resolve/revoke/purge | 256-bit `SecureRandom` tokens, only SHA-256(token) stored, format check before DB access, expiry/revocation/active-user join |
| `src/main/java/com/example/auth/CredentialRepository.java` | Credential row read/write | Parameterised `SELECT ... FOR UPDATE`, `setMaxFieldSize`, range checks on returned columns, update-then-insert upsert |
| `src/main/java/com/example/auth/LoginThrottle.java` | Windowed attempt counters | Row-locked read-modify-write, savepoint around insert race, SHA-256 scope keys, sampled purge of expired rows |
| `src/main/java/com/example/auth/InputValidator.java` | Input validation | Email canonicalisation (ASCII-only, length and shape), password length/control-character bounds, source-id charset |
| `src/main/java/com/example/auth/SessionCookie.java` | `Set-Cookie` builder for HTTP front ends | Mandatory `HttpOnly; Secure; SameSite=Strict`, token and path format validation, bounded `Max-Age` |
| `src/main/java/com/example/auth/Database.java` | JDBC connection factory | Credentials passed as driver properties, auto-commit off, READ COMMITTED isolation; DB password copied into a `String` |
| `src/main/java/com/example/auth/LogMasker.java` | Log redaction | Email masked to first char + truncated SHA-256 fingerprint; secrets reduced to length only |
| `src/main/java/com/example/auth/Hashing.java` | SHA-256 helpers | Digest used for session-token and throttle lookup keys (explicitly not for passwords) |
| `src/main/java/com/example/auth/LoggingSetup.java` | JUL configuration | Diagnostics to stderr at INFO; operator-supplied config wins |
| `src/main/java/com/example/auth/AuthResult.java` | Authentication outcome | Two user-visible messages only; detailed `Reason` kept internal |
| `src/main/java/com/example/auth/ConsoleIo.java` | Terminal input | `Console.readPassword` when a TTY exists; echoing fallback and `String` copy when not; 1024-char line bound |
| `src/main/resources/schema.sql` | Database schema | Unique email, `VARCHAR(256)` hash, session table keyed by token hash with FK cascade, throttle table keyed by `(scope, scope_key)` |
| `scripts/smoke-test.sh` | End-to-end test | Generates a run-time password into a `umask 077` file, pipes secrets on stdin, asserts generic failure messages and 0600 session file |
| `pom.xml` | Build definition | Pinned H2 2.3.232 (runtime scope), JDK-only crypto, no extra dependencies |
| `README.md`, `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Documentation and generation artifacts | Reviewed for embedded credentials only; none present |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`, `Hashing`,
  `SessionService`, `LogMasker` and `AuthConfig` — KDF choice and parameters, salt
  generation and length, RNG source, constant-time comparison, deprecated-algorithm use,
  hardcoded secrets, key/secret lifetime in memory, and transport (TLS) configuration.
  Produced SEC-02, SEC-06 and SEC-07; confirmed the password-storage controls in section 6.
- `testing-api-authentication-weaknesses`: applied to `AuthService`, `SessionService`,
  `AuthResult`, `LoginThrottle` and `AdminCli` — token entropy and format validation,
  token lifecycle (revocation on logout and on password change), account enumeration via
  differing messages or response times, credential-stuffing resistance, and password
  policy. Produced SEC-01 and SEC-04.
- `exploiting-sql-injection-vulnerabilities` and `performing-second-order-sql-injection`:
  applied to every SQL site (`CredentialRepository`, `SessionService`, `LoginThrottle`,
  `AdminCli.initSchema`) — checked both first-order injection (query construction) and
  second-order injection (values read back out of the database and reused). No finding;
  see section 6.
- `testing-for-sensitive-data-exposure`: applied to `LogMasker`, `AuthResult`, `App`,
  `AuthConfig`, `ConsoleIo`, `schema.sql` and `scripts/smoke-test.sh` — secrets in source
  and test fixtures, data in transit, data at rest, log masking and redaction, error-message
  leakage, and on-disk artifact permissions. Produced SEC-08 and SEC-09, and contributed to
  SEC-02 and SEC-06.
- `testing-for-broken-access-control`: applied to `SessionService.resolveUserId`,
  `CredentialRepository` and the `AdminCli` privileged commands — who may read or write a
  credential row, whether a deactivated account can authenticate or hold a live session.
  Produced SEC-05.
- `implementing-secrets-management-with-vault`: used as the reference model for how the
  database password should be supplied and rotated; applied to `AuthConfig.readDbPassword`
  and `Database.openTransaction`. Contributed to SEC-07 and SEC-09.
- `testing-for-business-logic-vulnerabilities`: applied to the throttle state machine in
  `LoginThrottle.registerAttempt`/`incrementExisting` and the attempt-accounting ordering
  in `AuthService.countAttempt` — window reset, counter clearing, and whether a failure can
  be used to reset or evade a limit. Produced SEC-04.
- Behaviour reviewed against general OWASP Top 10 / CWE knowledge because no library skill
  matched: JDBC driver-URL parameter abuse and the denylist used to contain it
  (CWE-184/CWE-1286, SEC-03); file-system check-then-use races and symlink handling in
  `AuthConfig.requireOwnerOnly` and `App.writeOwnerOnly` (CWE-367/CWE-59, SEC-10); naive
  DDL statement splitting in `AdminCli.splitStatements`; `Set-Cookie` attribute
  construction in `SessionCookie`; `java.util.logging` configuration in `LoggingSetup`;
  shell quoting and temp-file handling in `scripts/smoke-test.sh`; and dependency pinning /
  supply-chain posture in `pom.xml`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Password change does not revoke existing sessions | Medium | CWE-613 | `src/main/java/com/example/auth/CredentialRepository.java:60` |
| SEC-02 | Database connection never requires TLS; cleartext JDBC URLs are accepted | Medium | CWE-319 | `src/main/java/com/example/auth/AuthConfig.java:28` |
| SEC-03 | Dangerous JDBC URL options contained by an incomplete denylist | Medium | CWE-184 | `src/main/java/com/example/auth/AuthConfig.java:36` |
| SEC-04 | Per-source counter is process-wide and never cleared, producing a deployment-wide lockout | Medium | CWE-645 | `src/main/java/com/example/auth/AuthService.java:165` |
| SEC-05 | Setting a password silently re-activates a deactivated account | Low | CWE-284 | `src/main/java/com/example/auth/CredentialRepository.java:19` |
| SEC-06 | Unsalted SHA-256 used to pseudonymise email addresses in the throttle table and logs | Low | CWE-328 | `src/main/java/com/example/auth/LoginThrottle.java:63` |
| SEC-07 | Database password copied into an immutable `String`, and cleanup bypassed by `System.exit` | Low | CWE-316 | `src/main/java/com/example/auth/Database.java:28` |
| SEC-08 | Non-TTY fallback echoes the password and leaves it in an unwipeable `String` | Low | CWE-549 | `src/main/java/com/example/auth/ConsoleIo.java:43` |
| SEC-09 | Silent empty-password fallback for any JDBC URL, including remote databases | Low | CWE-258 | `src/main/java/com/example/auth/AuthConfig.java:151` |
| SEC-10 | Permission check and read of the DB password file are not on the same file object | Low | CWE-367 | `src/main/java/com/example/auth/AuthConfig.java:123` |

## 5. Detailed Findings

### SEC-01: Password change does not revoke existing sessions
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/CredentialRepository.java:60-74` (caller: `src/main/java/com/example/auth/AdminCli.java:112-116`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/CredentialRepository.java:60-74
    public void saveCredential(Connection connection, String email, String encodedHash)
            throws SQLException {
        try (PreparedStatement update = connection.prepareStatement(UPSERT)) {
            update.setString(1, encodedHash);
            update.setString(2, email);
            if (update.executeUpdate() > 0) {
                return;
            }
        }
        try (PreparedStatement insert = connection.prepareStatement(INSERT)) {
            insert.setString(1, email);
            insert.setString(2, encodedHash);
            insert.executeUpdate();
        }
    }
```

**Why it is a problem:** Sessions are server-side rows in `user_session` and are only
invalidated by expiry (`expires_at`), explicit `SessionService.revoke`, or the account
becoming inactive. Changing a password writes a new `password_hash` and nothing else, so
every session issued under the old password stays valid for the rest of its TTL (up to
`AUTH_SESSION_TTL_SECONDS`, bounded at 86,400 s). A password reset is the standard response
to a credential compromise, and here it does not evict the attacker: a stolen token
continues to resolve to the user via `SessionService.resolveUserId`. Nothing else in the
code closes this gap — `SessionService.revoke` exists but is never called from the
credential-write path (and is not wired into `App` at all).

**Fix:** Revoke the user's sessions in the same transaction that writes the new hash, so
the change and the eviction are atomic. Capture the affected `user_id` and mark its
sessions revoked (or delete them).

```java
    private static final String REVOKE_ALL_FOR_EMAIL =
            "UPDATE user_session SET revoked_at = CURRENT_TIMESTAMP "
            + "WHERE revoked_at IS NULL AND user_id = "
            + "(SELECT user_id FROM app_user WHERE email = ?)";

    /**
     * Creates or replaces a user's password hash and revokes every session that was
     * issued under the previous password, in the caller's transaction.
     */
    public void saveCredential(Connection connection, String email, String encodedHash)
            throws SQLException {
        boolean updated;
        try (PreparedStatement update = connection.prepareStatement(UPSERT)) {
            update.setString(1, encodedHash);
            update.setString(2, email);
            updated = update.executeUpdate() > 0;
        }
        if (!updated) {
            try (PreparedStatement insert = connection.prepareStatement(INSERT)) {
                insert.setString(1, email);
                insert.setString(2, encodedHash);
                insert.executeUpdate();
            }
            return; // a new account has no prior sessions
        }
        try (PreparedStatement revoke = connection.prepareStatement(REVOKE_ALL_FOR_EMAIL)) {
            revoke.setString(1, email);
            revoke.executeUpdate();
        }
    }
```

### SEC-02: Database connection never requires TLS; cleartext JDBC URLs are accepted
- **Severity:** Medium
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:28-29`, used at `src/main/java/com/example/auth/Database.java:30`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:28-29
    private static final Pattern JDBC_URL =
            Pattern.compile("^jdbc:(postgresql|h2):[A-Za-z0-9_:;,.=&/?@\\-]{1,480}$");
```

**Why it is a problem:** The URL allowlist happily matches a remote, unencrypted
connection such as `jdbc:postgresql://db.internal:5432/auth`, and neither `AuthConfig` nor
`Database.openTransaction` (`Database.java:30`) sets or requires `sslmode=verify-full`.
The PostgreSQL JDBC driver's default `sslmode` is `prefer`, which silently falls back to
plaintext and performs no certificate verification even when TLS is negotiated. Everything
this component sends over that link is sensitive: the database password supplied as a
driver property (`Database.java:26-29`), the normalised email addresses used as query
parameters, the stored PBKDF2 hashes returned by `SELECT ... FOR UPDATE`, and the SHA-256
session-token hashes written by `SessionService.issue` — a token hash observed on the wire
is directly usable to look up or revoke that session, and the password hashes are offline
crackable. The component validates this value carefully for shape but never for the one
property that protects it in transit.

**Fix:** Require transport security for any non-embedded URL: reject a remote PostgreSQL
URL that does not carry `sslmode=verify-full` (and restrict the plaintext exemption to
embedded H2 `mem:`/`file:` URLs), or set the property explicitly in `Database` so the
driver cannot fall back.

```java
    private static final Pattern JDBC_URL =
            Pattern.compile("^jdbc:(postgresql|h2):[A-Za-z0-9_:;,.=&/?@\\-]{1,480}$");

    /** Embedded H2 is local-only; anything else crosses a network and must be encrypted. */
    private static final Pattern LOCAL_EMBEDDED_URL =
            Pattern.compile("^jdbc:h2:(mem|file):[A-Za-z0-9_:;,.=&/?@\\-]{1,470}$");

    private static void requireEncryptedTransport(String url, String lowered) {
        if (LOCAL_EMBEDDED_URL.matcher(url).matches()) {
            return;
        }
        if (!lowered.contains("sslmode=verify-full")) {
            throw new ConfigException(
                    "AUTH_DB_URL must specify sslmode=verify-full for a networked database");
        }
    }
```

### SEC-03: Dangerous JDBC URL options contained by an incomplete denylist
- **Severity:** Medium
- **CWE:** CWE-184: Incomplete List of Disallowed Inputs
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:36-39`, enforced at `src/main/java/com/example/auth/AuthConfig.java:72-77`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:36-39
    private static final String[] FORBIDDEN_URL_TOKENS = {
            "init=", "runscript", "trace_level", "script_", "shutdown",
            "allowothersettings", "socketfactory", "loggerfile", "sslfactory",
    };
```

**Why it is a problem:** The comment above this array states the goal correctly — "a single
mis-set variable should not turn into code execution" — but the control is a denylist of
nine substrings, so it only stops the parameters the author happened to think of. The
allowing regex at line 29 permits arbitrary `;key=value` and `?key=value` sub-options, and
several equally dangerous ones are not listed. On PostgreSQL JDBC,
`sslhostnameverifier=<class>` and `authenticationPluginClassName=<class>` both cause the
driver to load and instantiate a named class from the classpath, and
`sslpassword`/`sslkey`/`sslcert` redirect which key material is used; on H2,
`ACCESS_MODE_DATA` and `IFEXISTS` change file handling. A denylist also fails the moment a
driver is upgraded and gains a new parameter, which is exactly the maintenance trap that
makes CWE-184 a design flaw rather than a typo. Because only trusted configuration reaches
here, impact is limited — but the control is presented as a containment boundary and does
not hold as one.

**Fix:** Invert the control: parse the URL's sub-options and accept only an explicit
allowlist of parameter names, rejecting anything unrecognised. The denylist can stay as a
redundant second check.

```java
    /** The only JDBC sub-options this component accepts; anything else is refused. */
    private static final Set<String> ALLOWED_URL_PARAMETERS = Set.of(
            "sslmode", "sslrootcert", "connecttimeout", "sockettimeout",
            "applicationname", "db_close_delay", "mode");

    private static void requireAllowedUrlOptions(String url) {
        int firstOption = url.indexOf(';') < 0 ? url.indexOf('?') : url.indexOf(';');
        if (firstOption < 0) {
            return; // no sub-options at all
        }
        for (String option : url.substring(firstOption + 1).split("[;&?]")) {
            if (option.isBlank()) {
                continue;
            }
            int eq = option.indexOf('=');
            String name = (eq < 0 ? option : option.substring(0, eq))
                    .trim().toLowerCase(Locale.ROOT);
            if (!ALLOWED_URL_PARAMETERS.contains(name)) {
                throw new ConfigException("AUTH_DB_URL contains an unsupported option");
            }
        }
    }
```

### SEC-04: Per-source counter is process-wide and never cleared, producing a deployment-wide lockout
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/example/auth/AuthService.java:165-168` (source value from `src/main/java/com/example/auth/AuthConfig.java:88` via `src/main/java/com/example/auth/App.java:45`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:165-168
                // Only the account counter is cleared. The source counter deliberately
                // survives a success, so holding one valid account cannot be used to
                // reset a spraying quota.
                throttle.clear(connection, LoginThrottle.Scope.ACCOUNT, email);
```

**Why it is a problem:** The source counter surviving a success is a sound anti-spraying
choice *only* if the source identifier is per-caller. It is not: `AUTH_SOURCE_ID` is a
single environment variable read once at startup (`AuthConfig.java:88`, default
`"local-cli"`) and `App` passes that one constant for every login
(`App.java:45`). All logins served by a deployment therefore share one `SOURCE` bucket of
`AUTH_MAX_ATTEMPTS_PER_SOURCE` attempts (default 30) per window (default 900 s). Once any
30 attempts in the window fail — which any unauthenticated party can cause —
`LoginThrottle.registerAttempt` returns false for every subsequent login from that
deployment, including ones with correct credentials, as the project's own smoke test
demonstrates for the account scope (`scripts/smoke-test.sh:63-72`). The rate limiter thus
becomes a cheap, remotely triggerable denial of service against all users, which is
precisely the outcome `LoginThrottle`'s own class comment says it set out to avoid
("cannot use our own limit as a denial-of-service tool") for the account scope.

**Fix:** Require the source identifier to be the actual per-request caller (the remote
address or client id) rather than a process-wide constant, and refuse to start when a
multi-user deployment is configured with the shared default. Keep the "not cleared on
success" semantics, which are correct once the key is per-caller.

```java
    /**
     * @param rawSource identifier of THIS request's origin (remote network address or
     *                  client id). It must vary per caller: a process-wide constant would
     *                  make the per-source limit a deployment-wide lockout.
     */
    public AuthResult authenticate(String rawEmail, char[] password, String rawSource) {
        if (rawSource != null && rawSource.equals(config.sourceId())
                && !config.singleUserCli()) {
            // Fail closed rather than meter every user through one shared bucket.
            hasher.verifyDecoy(password);
            LOG.severe("Login rejected: AUTH_SOURCE_ID is shared by all callers; "
                    + "pass the per-request source identifier instead");
            return AuthResult.failure(AuthResult.Reason.INVALID_INPUT);
        }
        // ... unchanged ...
    }
```

### SEC-05: Setting a password silently re-activates a deactivated account
- **Severity:** Low
- **CWE:** CWE-284: Improper Access Control
- **Location:** `src/main/java/com/example/auth/CredentialRepository.java:19-20`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/CredentialRepository.java:19-20
    private static final String UPSERT =
            "UPDATE app_user SET password_hash = ?, is_active = TRUE WHERE email = ?";
```

**Why it is a problem:** `is_active = FALSE` is the component's only account-disable
control: it is what stops authentication (`AuthService.java:151`) and what invalidates
existing sessions (`SessionService.SELECT_ACTIVE` requires `u.is_active = TRUE`). This
statement, reached from `AdminCli set-password`, resets that flag to `TRUE` as an
undocumented side effect of a password change. An operator rotating the password of an
account that was deliberately suspended — a common step while investigating a compromised
account — silently un-suspends it and restores login and session capability. The two
operations (set a credential, change an account's state) should not be coupled, and the
coupling is in the direction that grants access.

**Fix:** Change only the credential; make reactivation a separate, explicit operation.

```java
    private static final String UPSERT =
            "UPDATE app_user SET password_hash = ? WHERE email = ?";
```

### SEC-06: Unsalted SHA-256 used to pseudonymise email addresses in the throttle table and logs
- **Severity:** Low
- **CWE:** CWE-328: Use of Weak Hash
- **Location:** `src/main/java/com/example/auth/LoginThrottle.java:63` and `:153`; `src/main/java/com/example/auth/LogMasker.java:23-31`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginThrottle.java:63
        String key = Hashing.sha256Hex(scope.name() + ':' + rawKey);
```

**Why it is a problem:** `LoginThrottle`'s class comment claims "the table holds no
addresses or email addresses", and `README.md:139` claims the log fingerprint is "not
enough to recover the address". Neither holds: the input is a low-entropy value from a
small, guessable domain (an email address or an IP address) hashed with a single unsalted,
unkeyed SHA-256. Anyone who reads the `login_throttle` table or the logs — a DBA, a
log-aggregation tenant, or an attacker with read-only database access obtained through
SEC-02 — can confirm whether a specific address has been attempted, or recover addresses
wholesale by hashing a candidate list at billions of guesses per second.
`LogMasker.fingerprint` is worse: it truncates to 48 bits, so it is both reversible by
dictionary and subject to collisions. This is a privacy/claim-accuracy gap, not an
authentication bypass.

**Fix:** Use a keyed hash (HMAC-SHA-256 under a secret pepper from the same configuration
path as the DB password) so the mapping cannot be recomputed without the key, and keep the
full width for the correlation id.

```java
// Hashing.java - add a keyed variant and use it for all pseudonymisation
    static String hmacSha256Hex(byte[] key, String input) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return toHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 is required by the platform", e);
        }
    }

// LoginThrottle.java:63
        String key = Hashing.hmacSha256Hex(pepper, scope.name() + ':' + rawKey);
```

### SEC-07: Database password copied into an immutable `String`, and cleanup bypassed by `System.exit`
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/example/auth/Database.java:26-31` (cleanup bypassed at `src/main/java/com/example/auth/App.java:53` and `:55`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Database.java:26-31
        char[] password = config.dbPassword();
        if (password.length > 0) {
            props.setProperty("password", new String(password));
        }
        Connection connection = DriverManager.getConnection(config.jdbcUrl(), props);
        props.clear();
```

**Why it is a problem:** The component goes to real lengths to keep secrets in `char[]` so
they can be zeroed (`AuthConfig.close`, `App`'s `finally`, `PBEKeySpec.clearPassword`), and
this line discards that for the database password: `new String(password)` creates an
immutable copy that cannot be wiped and that `props.clear()` does not erase — it only drops
the reference. The copy is created on every `openTransaction()` call, so a long-running
process accumulates unwiped copies on the heap until GC, where a heap dump or core file
discloses them. The same class of gap exists in `App`: `System.exit(0)`/`System.exit(1)` at
`App.java:53` and `App.java:55` are inside the try-with-resources, so neither
`AuthConfig.close()` (which zeroes the DB password) nor the `finally` block at
`App.java:64-68` (which zeroes the user's password array) ever runs on the normal exit
paths.

**Fix:** Build the property value without an extra copy where the driver allows it, and set
exit status through a variable so the resource and `finally` cleanup actually executes.

```java
// Database.java - no retained String copy
        char[] password = config.dbPassword();
        if (password.length > 0) {
            // Properties.put accepts the char[] the JDBC drivers also accept, so no
            // immutable copy of the secret is created.
            props.put("password", password.clone());
        }
        Connection connection = DriverManager.getConnection(config.jdbcUrl(), props);
        Object stored = props.remove("password");
        if (stored instanceof char[] copy) {
            java.util.Arrays.fill(copy, '\0');
        }

// App.java - let try-with-resources and finally run before exiting
        int status = 2;
        try (AuthConfig config = AuthConfig.fromEnvironment(); ConsoleIo io = new ConsoleIo()) {
            // ... unchanged ...
            status = result.isAuthenticated() ? 0 : 1;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
        System.exit(status);
```

### SEC-08: Non-TTY fallback echoes the password and leaves it in an unwipeable `String`
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `src/main/java/com/example/auth/ConsoleIo.java:43-52`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/ConsoleIo.java:43-52
        System.out.println("Warning: no terminal attached; the password will be echoed.");
        System.out.print(prompt);
        System.out.flush();
        String line = reader.readLine();
        if (line == null) {
            return new char[0];
        }
        char[] value = line.toCharArray();
        // The String copy cannot be wiped; this path is for non-interactive testing only.
        return bound(value);
```

**Why it is a problem:** When `System.console()` returns null the password is read through a
`BufferedReader` into a `String`, so it is echoed (if the input is a terminal that the JVM
simply did not detect, e.g. under some CI and container runtimes) and lands in an immutable
object that the careful `Arrays.fill` cleanup elsewhere cannot reach; the `BufferedReader`'s
internal buffer retains it too. The code documents the limitation and the smoke test needs
this path, but nothing restricts it to testing: the same build will silently take this
branch in production when no console is attached, which is the normal case for a service or
a cron job. A deployment that pipes a password into `App` is a supported-looking mode that
quietly loses the protection.

**Fix:** Require an explicit opt-in for the unmasked path so it cannot be entered by
accident in production, and read it without an intermediate `String`.

```java
    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            char[] value = console.readPassword("%s", prompt);
            return value == null ? new char[0] : bound(value);
        }
        if (!Boolean.getBoolean("auth.allowUnmaskedPasswordInput")) {
            throw new IOException("no terminal is attached; refusing to read the password "
                    + "unmasked (set -Dauth.allowUnmaskedPasswordInput=true for tests)");
        }
        System.out.println("Warning: no terminal attached; the password will be echoed.");
        System.out.print(prompt);
        System.out.flush();
        char[] buffer = new char[MAX_LINE];
        int n = 0;
        for (int c = reader.read(); c >= 0 && c != '\n' && c != '\r'; c = reader.read()) {
            if (n < buffer.length) {
                buffer[n++] = (char) c;
            }
        }
        char[] value = java.util.Arrays.copyOf(buffer, n);
        java.util.Arrays.fill(buffer, '\0');
        return value;
    }
```

### SEC-09: Silent empty-password fallback for any JDBC URL, including remote databases
- **Severity:** Low
- **CWE:** CWE-258: Empty Password in Configuration File
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:151-159`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:151-159
        String env = System.getenv("AUTH_DB_PASSWORD");
        if (env != null) {
            if (env.length() > MAX_SECRET_FILE_BYTES) {
                throw new ConfigException("AUTH_DB_PASSWORD is too long");
            }
            return env.toCharArray();
        }
        // Embedded in-memory H2 (demo only) legitimately has no password.
        return new char[0];
```

**Why it is a problem:** The class contract one screen above states "no permissive
fallbacks: a missing or malformed value is a hard startup failure", and this is a
permissive fallback. The empty password is returned for *any* accepted URL, not just the
embedded H2 case the comment describes, so a deployment that sets `AUTH_DB_URL` to a remote
PostgreSQL instance but mis-spells `AUTH_DB_PASSWORD_FILE` (or whose secret-injection
sidecar has not populated it yet) starts up and connects with no password rather than
failing. If that database accepts `trust` or `peer`-style authentication, or the empty
password happens to match, the component runs against it with no credential at all and
nothing in the logs says so. The same branch also returns the password from an environment
variable, which is visible in `/proc/<pid>/environ` and in container inspection output —
acceptable as a documented fallback, but it should not be the silent default.

**Fix:** Allow the empty password only for an embedded H2 URL, and require an explicit
acknowledgement otherwise.

```java
    private static char[] readDbPassword(String jdbcUrl) {
        // ... file and AUTH_DB_PASSWORD branches unchanged ...
        if (LOCAL_EMBEDDED_URL.matcher(jdbcUrl).matches()) {
            return new char[0]; // embedded H2 legitimately has no password
        }
        throw new ConfigException(
                "AUTH_DB_PASSWORD_FILE or AUTH_DB_PASSWORD is required for a networked database");
    }
```

### SEC-10: Permission check and read of the DB password file are not on the same file object
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

**Why it is a problem:** Four separate path-based syscalls are performed against the same
name: the type check, the size check and the permission check are `NOFOLLOW_LINKS`, but
`Files.readAllBytes(path)` resolves the name again and *does* follow symlinks. If anything
can modify the containing directory between the check and the read — a co-tenant process,
a secret-injection sidecar, or an operator script with a wider umask — the bytes actually
read may come from a different, symlinked, group-readable, or oversized file than the one
that passed validation. The consequence here is limited (the component would use a wrong
value as the database password and fail to connect, or read a file the validation would
have rejected), but the control as written does not establish the property it claims.

**Fix:** Open the file once and perform every check on that open handle, so the checked
object and the read object are identical.

```java
            try (java.nio.channels.SeekableByteChannel channel = Files.newByteChannel(
                    path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
                PosixFileAttributes attrs = Files.readAttributes(
                        path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!attrs.isRegularFile()) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is not a regular file");
                }
                if (channel.size() > MAX_SECRET_FILE_BYTES) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is larger than "
                            + MAX_SECRET_FILE_BYTES + " bytes");
                }
                requirePermissions(attrs.permissions());
                java.nio.ByteBuffer buffer =
                        java.nio.ByteBuffer.allocate((int) channel.size());
                while (buffer.hasRemaining() && channel.read(buffer) > 0) {
                    // read from the same open handle that was validated
                }
                raw = buffer.array();
            }
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (first-order), CWE-89:** every statement in the component is a constant
  `String` passed to `prepareStatement` with bound parameters, and no SQL text is built from
  input anywhere — `CredentialRepository.java:16-24` with `setString` at `:41`, `:63-64`,
  `:70-71`; `SessionService.java:31-41` with `setString`/`setLong`/`setObject` at `:60-63`,
  `:82-83`, `:100-101`, `:109`; `LoginThrottle.java:37-49` with binds at `:69-70`, `:85-87`,
  `:116-117`, `:141-144`, `:152-153`, `:168`. Verified by grep that no `Statement.execute`
  takes a concatenated string: the only `createStatement()` use is
  `AdminCli.java:80-83`, which executes the DDL bundled in the artifact's own
  `/schema.sql` resource (`AdminCli.java:73`) and takes no caller-supplied path.
  The smoke test exercises two injection payloads and asserts the table survives
  (`scripts/smoke-test.sh:56-61`).
- **Second-order SQL injection, CWE-89:** values read back out of the database are never
  re-inserted into SQL text. The stored hash is parsed and used only as data
  (`PasswordHasher.java:83-115`), `user_id` is handled as a `long`
  (`CredentialRepository.java:47`, `SessionService.java:88`), and the throttle key is a
  fixed 64-hex digest (`LoginThrottle.java:63`). Returned-column width is additionally
  bounded with `setMaxFieldSize(512)` at `CredentialRepository.java:42`.
- **Password storage, CWE-916/CWE-759/CWE-760:** PBKDF2WithHmacSHA512, 210,000 iterations,
  256-bit output, fresh 16-byte `SecureRandom` salt per hash
  (`PasswordHasher.java:25-34`, `:56-67`). Salts are per-user, not global; iterations are
  recorded in the encoded value with a scheme prefix so re-hashing is possible
  (`PasswordHasher.java:62-63`). No MD5, SHA-1, DES, RC4 or ECB appears anywhere in the
  tree.
- **Hash comparison, CWE-208:** verification uses the platform's constant-time
  `MessageDigest.isEqual` rather than `Arrays.equals` or `String.equals`
  (`PasswordHasher.java:118`).
- **Hostile stored-hash handling, CWE-20:** the encoded value from the database is parsed
  strictly — length ≤ 256, exactly four fields, known scheme id, iterations within
  100,000…5,000,000, salt 8…64 bytes, hash 16…64 bytes — and every failure path performs a
  decoy derivation and returns `false` rather than short-circuiting to success
  (`PasswordHasher.java:77-114`). A KDF that cannot run throws instead of returning a pass
  (`PasswordHasher.java:145-148`).
- **Account enumeration and timing side channels, CWE-203/CWE-204:** a single failure
  message covers every reason (`AuthResult.java:28-30`, `:65-67`), and the no-such-account,
  unusable-hash, invalid-input, unusable-source and throttled paths all spend an equivalent
  PBKDF2 cost via `hasher.verifyDecoy` (`AuthService.java:66`, `:77`, `:88`, `:132`, `:141`);
  a deactivated account is still verified so "disabled" and "wrong password" take the same
  time (`AuthService.java:149-151`). The smoke test asserts the known-account and
  unknown-account outputs are byte-identical (`scripts/smoke-test.sh:52-54`).
- **Session token generation, CWE-330/CWE-338:** 32 bytes (256 bits) from `SecureRandom`,
  base64url-encoded, never derived from or influenced by caller input
  (`SessionService.java:43`, `:54-56`); the raw bytes are zeroed immediately
  (`SessionService.java:57`). No `java.util.Random` is used for any security value — the
  only `ThreadLocalRandom` use is purge sampling (`LoginThrottle.java:164`).
- **Session storage and validation, CWE-384/CWE-613 (partial):** only `SHA-256(token)` is
  persisted (`SessionService.java:60`, `:114-116`), so a database read does not yield usable
  tokens; validation is always a server-side lookup requiring an unrevoked, unexpired row
  joined to an active user (`SessionService.java:34-37`), the token format is checked before
  any database access (`SessionService.java:78-80`, `:96-98`), and a non-positive `user_id`
  is rejected (`SessionService.java:88-89`). TTL is bounded to 60…86,400 s
  (`AuthConfig.java:97`) and expired rows are purged (`SessionService.java:107-112`).
  Revocation on password change is the gap recorded as SEC-01.
- **Cookie attributes, CWE-1004/CWE-614/CWE-1275:** `HttpOnly`, `Secure` and
  `SameSite=Strict` are unconditional with no overload that omits them, the path is
  allowlisted by regex, the token must match the issued format, and `Max-Age` is bounded
  (`SessionCookie.java:19`, `:29-44`); the logout header carries the same attributes
  (`SessionCookie.java:47-52`).
- **Hardcoded credentials, CWE-798/CWE-259:** none in the Java sources, `schema.sql` (which
  seeds no users — `schema.sql:2`), `pom.xml`, or `scripts/smoke-test.sh`, which generates
  its test password at run time into a `umask 077` file and deletes it on exit
  (`scripts/smoke-test.sh:16-29`). The documentation files were grepped for
  password/secret/key/token values and contain only variable names.
- **Credentials on the command line, CWE-214:** `App` refuses all arguments
  (`App.java:31-34`) and `AdminCli set-password` takes only the email and prompts twice for
  the password (`AdminCli.java:98-103`), so no secret reaches the process list.
- **Log redaction, CWE-532:** no password, hash or token is logged; emails are reduced to
  one character plus a fingerprint (`LogMasker.java:15-20`, used at `AuthService.java:79`,
  `:134`, `:143`, `:157`, `:170` and `AdminCli.java:117`), and secrets to a length only
  (`LogMasker.java:34-40`). The smoke test asserts neither the password nor the address
  appears in output (`scripts/smoke-test.sh:74-80`). The hash used for the fingerprint is
  the subject of SEC-06.
- **Error handling / information leakage, CWE-209:** stack traces go to the operator log
  only; the user sees the generic failure text (`AuthService.java:176-179`,
  `App.java:60-63`, `AdminCli.java:52-56`), and configuration errors are reported without
  secret values (`AuthConfig.java:227-231`).
- **Input validation, CWE-20:** email is stripped, bounded to 3…254 chars, restricted to
  printable ASCII, required to have exactly one `@` with RFC-5321 part lengths, matched
  against an anchored pattern, then lower-cased (`InputValidator.java:41-66`); password is
  bounded to 8…256 chars with control characters rejected
  (`InputValidator.java:72-84`); source id is an anchored `[A-Za-z0-9.:_-]{1,64}`
  (`InputValidator.java:86-88`). Input lines are length-capped at read time
  (`ConsoleIo.java:20`, `:55-67`).
- **Unbounded resource consumption, CWE-770:** password length is capped before hashing, the
  throttle key space is bounded by hashing invalid addresses to a single constant
  (`AuthService.java:73`), the throttle and session tables are purged
  (`LoginThrottle.java:162-171`, `SessionService.java:107-112`), and secret files are capped
  at 4,096 bytes (`AuthConfig.java:41`, `:126-129`).
- **Race conditions in the authentication decision, CWE-362:** the credential row is locked
  with `SELECT ... FOR UPDATE` (`CredentialRepository.java:17`) and the verify-then-issue
  sequence runs inside that same transaction (`AuthService.java:126-169`), so a concurrent
  password change or deactivation cannot interleave. The throttle read-modify-write is also
  row-locked (`LoginThrottle.java:37-39`, `:68-78`) with a savepoint around the insert race
  (`LoginThrottle.java:83-95`), and attempts are committed in their own transaction before
  verification so a later failure cannot reset the counter (`AuthService.java:98-123`).
- **Fail-closed behaviour, CWE-636:** an unattributable source is refused
  (`AuthService.java:63-69`), throttle-accounting errors return a failure rather than
  proceeding (`AuthService.java:119-122`), an unreadable counter row refuses the attempt
  (`LoginThrottle.java:119-121`), and a malformed credential row is treated as unusable
  rather than as a pass (`CredentialRepository.java:50-53`).
- **New-password policy, CWE-521:** minimum 12 characters plus at least three character
  classes on set/change (`AdminCli.java:104-111`, `:153-171`), with the login-time minimum
  deliberately kept lower so legacy passwords are not locked out
  (`InputValidator.java:17-22`). No breached-password or common-password check is performed;
  that is a hardening recommendation, not a finding.
- **Session token file permissions, CWE-276/CWE-59:** the file is created with `0600` in a
  single `CREATE_NEW` open, a non-regular path (symlink) is refused, and the terminal shows
  only a masked form (`App.java:93-114`, `:71-84`); `CREATE_NEW` maps to `O_CREAT|O_EXCL`,
  so a pre-planted symlink causes a failure rather than a redirected write. The smoke test
  asserts mode 600 (`scripts/smoke-test.sh:44-45`).
- **DB password file permissions, CWE-732:** group/other read and write are rejected
  outright (`AuthConfig.java:162-178`); the residual issue is only the check/use race in
  SEC-10.
- **Path traversal, CWE-22:** the two caller-influenced paths are absolutised and
  normalised and are used only as whole file names, never joined with other input
  (`AuthConfig.java:106`, `:120`); the schema is loaded from the artifact's own classpath
  resource, not a caller-supplied path (`AdminCli.java:73`).
- **Insecure deserialization, CWE-502:** no Java serialization, XML, YAML or object-graph
  deserialization anywhere; the only parsed external formats are Base64 inside the
  strictly-bounded hash parser and `Integer.parseInt` on bounded configuration values.
- **OS command execution, CWE-78:** no `Runtime.exec`, `ProcessBuilder`, or shell invocation
  in the Java sources. `scripts/smoke-test.sh` runs under `set -euo pipefail` with every
  expansion quoted and a `trap`-cleaned `mktemp -d` work directory
  (`scripts/smoke-test.sh:5-18`).
- **XSS / template injection / SSRF / XXE / open redirect:** not applicable — the component
  renders no markup, evaluates no templates, makes no outbound HTTP request, parses no XML,
  and performs no redirects. Confirmed by grep for `URL`, `HttpClient`, `openStream`,
  `DocumentBuilder` and template APIs across `src/`.
- **Dependency / supply-chain posture, CWE-1104:** a single runtime-scoped dependency pinned
  to an exact version (H2 2.3.232, `pom.xml:17`, `:25-30`) with all cryptography taken from
  the JDK; compiler release pinned to 17 with `-Xlint:all` (`pom.xml:38-46`). No automated
  CVE gate (OWASP dependency-check / `mvn versions`) is wired into the build — a hardening
  recommendation, not a finding.
- **Schema constraints, CWE-20:** unique email, `NOT NULL` hash, bounded column widths
  matching the application's own limits, FK with `ON DELETE CASCADE`, and a composite
  primary key on the throttle scope (`schema.sql:4-30`).
