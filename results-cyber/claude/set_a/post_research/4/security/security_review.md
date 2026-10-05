# Security Review: secure-accounts (local account registration, login and session CLI)

## 1. Executive Summary

`secure-accounts` is a small Java 17 Maven project that implements local account
registration, password authentication and server-side session management on top of a
SQLite database, driven by a four-command CLI (`register`, `login`, `whoami`, `logout`).

The code is defensively written and the high-risk classics are genuinely absent: every
SQL statement is a `PreparedStatement` with bound parameters (no string-built SQL
anywhere), passwords are stored as Argon2id PHC strings with a 16-byte `SecureRandom`
salt, hash comparison is `MessageDigest.isEqual`, session tokens are 256-bit CSPRNG
values stored only as SHA-256 digests and validated exclusively against server-side
state, there are no hardcoded secrets, and user-facing messages are deliberately
uniform so registration and login leak no account-existence oracle.

No critical or high-severity vulnerability was found. The findings below are one
medium-severity file-permission weakness and a set of low-severity hardening gaps:

- **SEC-01 (Medium)** the SQLite database holding password hashes is created under the
  process umask and only chmod-ed to `0600` *after* the schema migration has run.
- **SEC-02 … SEC-08 (Low)** terminal detection that no longer holds on modern JREs,
  an unsalted digest of login identifiers, a fixed- rather than sliding-window rate
  limiter, a client-overridable rate-limit source key, acceptance of out-of-policy
  Argon2 cost parameters from stored hashes, no session rotation/revocation on a new
  login, and a 20-entry stub password blocklist.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/accounts/App.java` | CLI front end for the four commands | Reads passwords from the terminal/stdin, writes and reads the session token file (`0600`), masks user-facing errors, derives the rate-limit source id, wipes secrets in `finally` |
| `src/main/java/com/example/accounts/AccountService.java` | Registration and authentication orchestration | Enumeration-resistant ordering, decoy-hash work equalisation, throttle gating, session issue, identifier canonicalisation, log masking |
| `src/main/java/com/example/accounts/PasswordHasher.java` | Argon2id hashing in PHC format | KDF parameters, `SecureRandom` salt, constant-time compare, strict parsing of stored hashes, pepper as Argon2 secret, buffer wiping |
| `src/main/java/com/example/accounts/SessionService.java` | Server-side session storage | 32-byte CSPRNG token, SHA-256-at-rest, idle/absolute expiry, revocation, strict token format check, pruning |
| `src/main/java/com/example/accounts/SessionCookie.java` | `Set-Cookie` builder for an HTTP front end | `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, no `Domain` |
| `src/main/java/com/example/accounts/ThrottleService.java` | Login/registration attempt counting | Per-source and per-account counters, digest-keyed rows, atomic check-and-increment, window expiry, pruning |
| `src/main/java/com/example/accounts/AccountRepository.java` | All SQL on the `account` table | Parameterised insert/select/update, uniqueness via DB constraint, `SQLState` 23 duplicate detection |
| `src/main/java/com/example/accounts/Database.java` | Connection factory, migration, transactions | `BEGIN IMMEDIATE` transactions, rollback on failure, schema with `CHECK`/`UNIQUE` constraints, database file permissions |
| `src/main/java/com/example/accounts/InputValidator.java` | Validation/canonicalisation of email, username, password | Allowlist character checks, length bounds, NFKC/NFC normalisation, reserved names, password policy and blocklist |
| `src/main/java/com/example/accounts/Config.java` | Environment-driven configuration | Range-checked settings, allowlisted JDBC prefix, pepper from env only, owner-only data directory, secret-free `toString` |
| `src/main/java/com/example/accounts/Logging.java` | Single application logger | `0600` log file, symlink refusal, one-line formatter that neutralises injected newlines |
| `src/main/java/com/example/accounts/Mask.java` | Masking for log/console output | Email/username masking, JDBC URL credential stripping |
| `src/main/java/com/example/accounts/Wipe.java` | Zeroing of `char[]`/`byte[]` credential buffers | Best-effort secret erasure |
| `src/main/java/com/example/accounts/Hex.java` | Lowercase hex encoding | Encoding of digests and session references |
| `src/main/java/com/example/accounts/ValidationException.java` | Format-only error type | Messages must not reflect server-side state |
| `pom.xml` | Build and dependency pinning | Pinned Bouncy Castle 1.79 / sqlite-jdbc 3.47.1.0, HTTPS-only Maven Central with `checksumPolicy=fail`, no snapshots |

Test sources under `src/test` and build output under `target/` were read for context but
are not production attack surface and produced no findings.

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove the file-by-file
  behaviour inventory and the selection of the specialised skills below.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`,
  `SessionService`, `ThrottleService` and `Config` — deprecated algorithms (none: no
  MD5/SHA-1/DES/RC4/ECB), KDF parameter strength, salt/IV handling, RNG choice,
  hardcoded-secret scan (none found), key/pepper storage and wiping. Fired on SEC-03
  and SEC-06.
- `testing-api-authentication-weaknesses`: applied to `AccountService`,
  `SessionService` and `SessionCookie` — token entropy, expiration, server-side
  revocation, logout behaviour, session rotation, password policy and credential-stuffing
  resistance. Fired on SEC-07 and SEC-08.
- `testing-for-sensitive-data-exposure`: applied to `Database`, `Logging`, `Mask`,
  `Config` and the session-token file handling in `App` — data at rest, secret leakage
  into logs/messages/arguments, masking and redaction, file permissions. Fired on
  SEC-01 and SEC-02.
- `implementing-api-rate-limiting-and-throttling` and `performing-api-rate-limiting-bypass`:
  applied to `ThrottleService` and `AccountService.normalizeSourceId` — window algorithm
  choice, counter atomicity, per-source vs per-account scoping, source-identifier
  trustworthiness, lockout-as-DoS. Fired on SEC-04 and SEC-05.
- `exploiting-sql-injection-vulnerabilities` / `performing-second-order-sql-injection`:
  applied to `AccountRepository`, `SessionService` and `ThrottleService` — no finding
  (see section 6).
- `exploiting-race-condition-vulnerabilities`: applied to `Database.inTransaction`,
  `ThrottleService.tryAcquire` and `AccountRepository.insert` — TOCTOU on
  check-then-act sequences; no finding (see section 6).
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill
  matched these behaviours directly: Unicode canonicalisation and homograph collisions
  in `InputValidator` (NFKC-before-casefold, ASCII allowlist), log-injection via
  `Logging.PlainFormatter.oneLine` (CWE-117), symlink/TOCTOU handling on the data
  directory, log file and session-token file (CWE-59/CWE-367), terminal secret input
  handling, generic-error / account-enumeration behaviour (CWE-204), dependency and
  build provenance in `pom.xml` (no known-vulnerable pinned versions identified), and
  insecure deserialization (none: no Java serialization, XML or object parsing exists
  in the codebase).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Database file containing password hashes is created with umask permissions and only restricted after migration | Medium | CWE-732 | `src/main/java/com/example/accounts/Database.java:53` |
| SEC-02 | Secret input gate relies on `System.console() != null` as a terminal test | Low | CWE-549 | `src/main/java/com/example/accounts/App.java:306` |
| SEC-03 | Login identifiers are keyed with an unsalted SHA-256 whose pepper is optional | Low | CWE-916 | `src/main/java/com/example/accounts/ThrottleService.java:190` |
| SEC-04 | Attempt counter is a fixed window, allowing ~2x the configured failures across a boundary | Low | CWE-307 | `src/main/java/com/example/accounts/ThrottleService.java:57` |
| SEC-05 | CLI rate-limit source identifier is taken from the overridable `user.name` property | Low | CWE-807 | `src/main/java/com/example/accounts/App.java:239` |
| SEC-06 | Stored-hash parser accepts Argon2 cost parameters far below the configured policy floor | Low | CWE-916 | `src/main/java/com/example/accounts/PasswordHasher.java:41` |
| SEC-07 | A new successful login neither rotates nor revokes the previous session | Low | CWE-613 | `src/main/java/com/example/accounts/AccountService.java:202` |
| SEC-08 | Breached-password blocklist is a 20-entry stub | Low | CWE-521 | `src/main/java/com/example/accounts/InputValidator.java:40` |

## 5. Detailed Findings

### SEC-01: Database file containing password hashes is created with umask permissions and only restricted after migration
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/accounts/Database.java:53-54`, `src/main/java/com/example/accounts/Database.java:103-124`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/Database.java:52-56
        Database db = new Database(url, props, log);
        db.migrate();
        db.restrictDatabaseFilePermissions(url);
        log.info(() -> "database ready at " + Mask.jdbcUrl(url));
        return db;
```
```java
// src/main/java/com/example/accounts/Database.java:117-123
            Path p = suffix.isEmpty() ? base : Paths.get(pathPart + suffix);
            try {
                if (Files.exists(p) && !Files.isSymbolicLink(p)
                        && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
                }
            } catch (IOException | UnsupportedOperationException e) {
```

**Why it is a problem:** `migrate()` is what causes SQLite to create `accounts.db` (and its
`-wal`/`-shm` siblings, which inherit the main file's mode), so the file that holds every
Argon2 hash and session digest is created with the process umask — typically `0644`,
world-readable — and is only tightened afterwards. Every other sensitive file in this
project is created tightly *first* (`Logging.openPrivateFileHandler` at
`src/main/java/com/example/accounts/Logging.java:64-69` and `App.storeSessionToken` at
`src/main/java/com/example/accounts/App.java:330-335` both pass
`PosixFilePermissions.asFileAttribute`), so this path is the inconsistent one. The default
database lives inside the `0700` data directory, which contains the exposure, but
`ACCOUNTS_JDBC_URL` is only prefix-checked (`src/main/java/com/example/accounts/Config.java:160`)
and may legitimately point anywhere, e.g. `jdbc:sqlite:/var/tmp/accounts.db`, where the
window is directly exploitable by any local user who opens or hard-links the file during
migration. Relatedly, the `isSymbolicLink` guard here runs *after* SQLite has already
opened and followed the path, so it protects the `chmod` but not the write.

**Fix:** Create the database file with owner-only permissions before any connection opens
it, and keep the post-migration tightening as a belt-and-braces step.
```java
    public static Database open(Config config, Logger log) throws SQLException {
        String url = config.jdbcUrl();
        if (!url.startsWith("jdbc:sqlite:")) {
            throw new SQLException("unsupported JDBC URL");
        }
        Properties props = new Properties();
        props.setProperty("foreign_keys", "true");
        props.setProperty("journal_mode", "WAL");
        props.setProperty("synchronous", "NORMAL");
        props.setProperty("busy_timeout", "5000");
        props.setProperty("transaction_mode", "IMMEDIATE");
        Database db = new Database(url, props, log);
        db.precreateDatabaseFileOwnerOnly(url);   // 0600 before SQLite ever opens it
        db.migrate();
        db.restrictDatabaseFilePermissions(url);  // still re-asserted afterwards
        log.info(() -> "database ready at " + Mask.jdbcUrl(url));
        return db;
    }

    /** Creates an empty 0600 database file if absent, so SQLite never widens it. */
    private void precreateDatabaseFileOwnerOnly(String url) {
        String pathPart = databasePath(url); // extracted from restrictDatabaseFilePermissions
        if (pathPart == null) {
            return; // in-memory database, nothing on disk
        }
        Path p = Paths.get(pathPart);
        try {
            if (Files.isSymbolicLink(p)) {
                throw new IOException("database path is a symbolic link");
            }
            if (!Files.exists(p)
                    && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(p, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rw-------")));
            }
        } catch (IOException | UnsupportedOperationException e) {
            log.log(Level.WARNING, "could not pre-create database file with 0600", e);
        }
    }
```

### SEC-02: Secret input gate relies on `System.console() != null` as a terminal test
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `src/main/java/com/example/accounts/App.java:306-317`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/App.java:306-317
    private static char[] readSecret(String label) throws IOException {
        if (System.console() != null) {
            return System.console().readPassword("%s", label);
        }
        if (!"true".equalsIgnoreCase(System.getenv("ACCOUNTS_PASSWORD_STDIN"))) {
            throw new IOException("no terminal available for password entry; "
                    + "set ACCOUNTS_PASSWORD_STDIN=true to read it from standard input");
        }
        // Read into a char[] rather than a String, which could not be wiped afterwards. One extra
        // character of headroom so an over-long password is seen and rejected, not truncated.
        return readLine(stdin(), InputValidator.PASSWORD_MAX_LENGTH + 1);
    }
```

**Why it is a problem:** The whole design rests on "console present implies a real terminal
with echo control". That was true on the JDK 17 this project targets, but from JDK 22
onwards `System.console()` returns a `Console` even when the standard streams are
redirected or attached to a non-echo-controllable virtual terminal, which is exactly why
`Console.isTerminal()` was added. The jar is a shaded executable that will be run on
whatever JRE is installed. On a newer JRE the first branch is taken unconditionally: the
explicit `ACCOUNTS_PASSWORD_STDIN` opt-in that the class documentation presents as the only
way a secret may come from stdin is silently bypassed, echo suppression is not guaranteed
(so the password can appear on screen and in terminal scrollback), and the returned array is
not length-bounded by `readLine`.

**Fix:** Test for an actual terminal, not merely for the presence of a `Console`, and keep
the stdin path behind its opt-in.
```java
    private static char[] readSecret(String label) throws IOException {
        if (isInteractiveTerminal()) {
            return System.console().readPassword("%s", label);
        }
        if (!"true".equalsIgnoreCase(System.getenv("ACCOUNTS_PASSWORD_STDIN"))) {
            throw new IOException("no terminal available for password entry; "
                    + "set ACCOUNTS_PASSWORD_STDIN=true to read it from standard input");
        }
        return readLine(stdin(), InputValidator.PASSWORD_MAX_LENGTH + 1);
    }

    /**
     * True only for a real echo-controllable terminal. On JDK 22+ System.console() is
     * non-null even for redirected streams, so isTerminal() is the load-bearing check;
     * it is called reflectively so the code still compiles and runs on JDK 17.
     */
    private static boolean isInteractiveTerminal() {
        java.io.Console console = System.console();
        if (console == null) {
            return false;
        }
        try {
            return (boolean) java.io.Console.class.getMethod("isTerminal").invoke(console);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return true; // pre-JDK 22: a non-null Console already implies a terminal
        }
    }
```

### SEC-03: Login identifiers are keyed with an unsalted SHA-256 whose pepper is optional
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/accounts/ThrottleService.java:190-204`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/ThrottleService.java:190-204
    private String key(String scope, String identifier) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        if (pepper.length > 0) {
            digest.update(pepper);
        }
        digest.update(scope.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) ':');
        digest.update(identifier.getBytes(StandardCharsets.UTF_8));
        return Hex.encode(digest.digest());
    }
```

**Why it is a problem:** The class documentation claims the `auth_attempt` table "is not a
log of who tried to log in from where" (`src/main/java/com/example/accounts/ThrottleService.java:28-30`),
but the pepper is optional and empty by default (`src/main/java/com/example/accounts/Config.java:165-168`).
With no pepper the key is a plain, unsalted SHA-256 over a low-entropy value — an email
address or an IP string — so anyone who reads the database can recover the exact identifiers
by hashing a candidate list (the entire IPv4 space is ~4 billion digests, and breached email
lists are free). The protection the comment promises therefore does not exist in the default
configuration, and the inputs are precisely the PII the design set out not to store.

**Fix:** Make the keying secret mandatory for this table rather than optional, and use a
proper keyed MAC instead of a hash-prefix construction.
```java
    private final javax.crypto.SecretKey keyingKey;

    public ThrottleService(Config config) {
        this.config = config;
        byte[] pepper = config.pepper();
        // Fail closed: without a keying secret the stored digests are trivially reversible,
        // so refuse to run rather than silently storing recoverable identifiers.
        if (pepper.length < 16) {
            throw new IllegalStateException(Config.ENV_PEPPER
                    + " is required: it keys the throttle identifier digests");
        }
        this.keyingKey = new javax.crypto.spec.SecretKeySpec(pepper, "HmacSHA256");
    }

    /** Domain-separated HMAC of the identifier; 64 lowercase hex characters. */
    private String key(String scope, String identifier) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(keyingKey);
            mac.update(scope.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) ':');
            mac.update(identifier.getBytes(StandardCharsets.UTF_8));
            return Hex.encode(mac.doFinal());
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
```

### SEC-04: Attempt counter is a fixed window, allowing ~2x the configured failures across a boundary
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/accounts/ThrottleService.java:57-65`, `src/main/java/com/example/accounts/ThrottleService.java:146-149`

**Vulnerable code:**
```sql
-- src/main/java/com/example/accounts/ThrottleService.java:58-64
            INSERT INTO auth_attempt (scope, scope_key, window_start, failures)
            VALUES (?, ?, ?, 1)
            ON CONFLICT (scope, scope_key) DO UPDATE SET
              window_start = CASE WHEN auth_attempt.window_start <= ? THEN excluded.window_start
                                  ELSE auth_attempt.window_start END,
              failures     = CASE WHEN auth_attempt.window_start <= ? THEN 1
                                  ELSE auth_attempt.failures + 1 END
```

**Why it is a problem:** `window_start` is anchored at the first attempt and the counter is
reset wholesale once that anchor ages past the cutoff, which is a *fixed* window — not the
"short sliding window" the class documentation describes
(`src/main/java/com/example/accounts/ThrottleService.java:21-22`). An attacker who times
their bursts around the boundary gets twice the budget in a short period: with the defaults,
10 guesses against one account at T+14:59 and 10 more at T+15:01 is 20 guesses in two
minutes against a nominal limit of 10 per 15 minutes, and 50 rather than 25 per source. The
same pattern repeats every window, so the sustained bypass factor is the burst factor.

**Fix:** Use a true sliding window — keep the window anchored to the most recent attempt, or
store per-attempt timestamps and count those inside the window.
```sql
            INSERT INTO auth_attempt (scope, scope_key, window_start, failures)
            VALUES (?, ?, ?, 1)
            ON CONFLICT (scope, scope_key) DO UPDATE SET
              -- Slide the window forward on every counted attempt so a burst straddling
              -- the old boundary cannot double the budget.
              window_start = excluded.window_start,
              failures     = CASE WHEN auth_attempt.window_start <= ? THEN 1
                                  ELSE auth_attempt.failures + 1 END
```

### SEC-05: CLI rate-limit source identifier is taken from the overridable `user.name` property
- **Severity:** Low
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/example/accounts/App.java:239-242`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/App.java:239-242
    private static String sourceId() {
        String user = System.getProperty("user.name");
        return "cli:" + (user == null || user.isBlank() ? "unknown" : user);
    }
```

**Why it is a problem:** `user.name` is an ordinary writable system property, so the person
invoking the jar chooses the value: `java -Duser.name=a1 -jar accounts.jar login`,
`-Duser.name=a2`, and so on each land in a fresh per-source bucket. The per-source counter
is described as "what actually stops credential stuffing"
(`src/main/java/com/example/accounts/ThrottleService.java:17-19`), and here it can be reset
at will by the caller, leaving only the per-account counter. The practical impact is limited
because the default database sits in the invoking user's own `0700` directory, but it becomes
real as soon as the store is shared between local accounts, and it is the same mistake as
trusting `X-Forwarded-For` that `normalizeSourceId` explicitly warns against.

**Fix:** Derive the source from something the caller cannot set, such as the real OS user
behind the process.
```java
    private static String sourceId() {
        // Not user.name: that is a writable system property the caller can rotate with
        // -Duser.name=... to get a fresh rate-limit bucket per attempt.
        String user = System.getenv("USER");
        if (user == null || user.isBlank()) {
            try {
                user = java.nio.file.Files.getOwner(
                        java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"))
                                .getFileSystem().getPath("/proc/self")).getName();
            } catch (IOException | RuntimeException e) {
                user = null;
            }
        }
        return "cli:" + (user == null || user.isBlank() ? "unknown" : user);
    }
```

### SEC-06: Stored-hash parser accepts Argon2 cost parameters far below the configured policy floor
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/accounts/PasswordHasher.java:41-44`, `src/main/java/com/example/accounts/PasswordHasher.java:234-236`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/PasswordHasher.java:40-45
    /** Bounds applied when parsing a stored hash, independent of the configured cost. */
    private static final int MIN_MEMORY_KIB = 8;
    private static final int MAX_MEMORY_KIB = 1_048_576;   // 1 GiB ceiling
    private static final int MAX_ITERATIONS = 20;
    private static final int MAX_PARALLELISM = 16;
    private static final int MAX_ENCODED_LENGTH = 512;
```

**Why it is a problem:** `Config.Argon2Settings` enforces the OWASP floor of
`m>=19456, t>=2` for hashes this code *writes*
(`src/main/java/com/example/accounts/Config.java:77-79`), but `verify` happily honours a
stored `m=8,t=1,p=1` — a KDF roughly four orders of magnitude cheaper than policy. A row
reached through a restored backup, a replication bug or any write primitive short of full
control therefore turns that account's hash into something crackable at near-plaintext
speed, and the cheap verification is also a timing oracle distinguishing such accounts from
normal ones. The upper bounds (the memory-DoS case the comment is aimed at) are handled; the
lower bound is not. `needsRehash` does upgrade the row after a *successful* login, which
limits but does not remove the exposure.

**Fix:** Clamp the accepted parameters to the configured policy floor, so an under-cost row
fails closed like any other unparsable value.
```java
    /** Bounds applied when parsing a stored hash. Floors match the OWASP minimums in Config. */
    private static final int MIN_MEMORY_KIB = 19_456;      // never below the policy floor
    private static final int MIN_ITERATIONS = 2;
    private static final int MAX_MEMORY_KIB = 1_048_576;   // 1 GiB ceiling
    private static final int MAX_ITERATIONS = 20;
    private static final int MAX_PARALLELISM = 16;
    private static final int MAX_ENCODED_LENGTH = 512;

    // ... in parse():
        int memoryKib = parseParam(params[0], "m=", MIN_MEMORY_KIB, MAX_MEMORY_KIB);
        int iterations = parseParam(params[1], "t=", MIN_ITERATIONS, MAX_ITERATIONS);
        int parallelism = parseParam(params[2], "p=", 1, MAX_PARALLELISM);
```

### SEC-07: A new successful login neither rotates nor revokes the previous session
- **Severity:** Low
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/accounts/AccountService.java:202-208`, `src/main/java/com/example/accounts/App.java:162`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/AccountService.java:202-208
            SessionService.IssuedSession issued = database.inTransaction(connection -> {
                throttle.clearAccount(connection, lookupKey, now);
                if (upgraded != null) {
                    accounts.updatePasswordHash(connection, accountId, upgraded, now);
                }
                return sessions.issue(connection, accountId, now);
            });
```
```java
// src/main/java/com/example/accounts/App.java:162
                    storeSessionToken(config, session.token());
```

**Why it is a problem:** Each login mints an additional session and the CLI overwrites the
single-slot token file, so the previous token stays valid server-side until its idle or
absolute timeout — up to 12 hours by default — with no way for the user to reach it:
`logout` can only revoke the token currently in the file. `SessionService.revokeAllForAccount`
exists for exactly this purpose and is never called from anywhere in the codebase. A user who
suspects a stolen token and responds by logging in again (the intuitive action) does not
invalidate it, and `updatePasswordHash` likewise rotates the stored hash without revoking
anything.

**Fix:** Revoke the account's existing sessions as part of the same transaction that issues
the new one, before `issue` runs.
```java
            SessionService.IssuedSession issued = database.inTransaction(connection -> {
                throttle.clearAccount(connection, lookupKey, now);
                if (upgraded != null) {
                    accounts.updatePasswordHash(connection, accountId, upgraded, now);
                }
                // A fresh authentication supersedes older sessions: a stolen token must not
                // outlive the login that replaced it (same transaction, so no window).
                sessions.revokeAllForAccount(connection, accountId);
                return sessions.issue(connection, accountId, now);
            });
```

### SEC-08: Breached-password blocklist is a 20-entry stub
- **Severity:** Low
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

**Why it is a problem:** The rest of the policy (12-character minimum, 5 distinct
characters, no username/email substring, no single repeated character, no monotonic run) is
sound, but the breached-credential check — the control that actually matters against
credential stuffing — covers twenty strings matched by exact equality. `Summer2024!`,
`Password123!` and the millions of other known-breached passwords above 12 characters all
pass. The limitation is acknowledged in the README and in the comment, but as shipped the
check provides essentially no coverage, and the per-account rate limit is a 15-minute window
rather than a lockout, so a weak password remains guessable over time.

**Fix:** Check the prepared password against a real breached-password corpus loaded from a
file (or the Pwned Passwords k-anonymity range API), keeping the in-code set only as a
fallback.
```java
    /**
     * Breached-password check against a SHA-1-prefixed corpus (HIBP "Pwned Passwords"
     * format: one UPPERCASE hex digest per line). Path comes from configuration; the
     * small in-code set remains as a fallback when no corpus is installed.
     */
    private static boolean isBreached(char[] prepared, java.nio.file.Path corpus)
            throws java.io.IOException {
        byte[] utf8 = null;
        try {
            utf8 = toUtf8(prepared); // char[] -> byte[], no String materialised
            String digest = Hex.encode(
                    java.security.MessageDigest.getInstance("SHA-1").digest(utf8))
                    .toUpperCase(Locale.ROOT);
            try (java.util.stream.Stream<String> lines = java.nio.file.Files.lines(corpus)) {
                return lines.anyMatch(line -> line.startsWith(digest));
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 unavailable", e);
        } finally {
            Wipe.bytes(utf8);
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (CWE-89):** every statement in the codebase is a constant string with
  bound parameters — `AccountRepository.java:24-38` (`INSERT`/`SELECT`/`UPDATE`),
  `SessionService.java:33-58` (six statements), `ThrottleService.java:53-73` (four
  statements), and the DDL in `Database.java:143-182` contains no interpolation. No
  `Statement.execute(String)` is ever called with a runtime-built string; `createStatement`
  is used only for the constant schema array. Second-order injection was checked too: values
  read back out of the database (`password_hash`, `session_ref`) are never re-concatenated
  into SQL.
- **Password storage (CWE-916/CWE-759):** Argon2id via Bouncy Castle with
  `m=65536, t=3, p=1` defaults validated against the OWASP floor
  (`Config.java:74-80, 92-95`), a fresh 16-byte `SecureRandom` salt per hash
  (`PasswordHasher.java:69-70`), 32-byte output, standard PHC encoding
  (`PasswordHasher.java:191-197`), and an optional pepper supplied as Argon2's *secret*
  parameter rather than concatenated (`PasswordHasher.java:158-160`).
- **Constant-time comparison (CWE-208):** hash equality uses `MessageDigest.isEqual`
  (`PasswordHasher.java:102`); no `Arrays.equals`/`String.equals` on secret material in the
  authentication path.
- **Hash upgrade path:** `needsRehash` compares stored cost against current policy and the
  row is rewritten inside the post-authentication transaction
  (`PasswordHasher.java:111-126`, `AccountService.java:198-206`).
- **Stored-hash parsing as untrusted input (CWE-20):** length cap, exact field count,
  algorithm and version pinning, bounded integer parsing and bounded base64 decoding, with
  every failure returning `false` rather than throwing
  (`PasswordHasher.java:215-280`, `PasswordHasher.java:87-96`).
- **Session token entropy and handling (CWE-330/CWE-384):** 32 bytes from `SecureRandom`
  generated server-side only, never caller-supplied, so no session fixation is possible
  (`SessionService.java:77-84`); only `SHA-256(token)` is persisted
  (`SessionService.java:203-216`); strict fixed-length base64url format check before the
  value reaches any query (`SessionService.java:189-201`).
- **Session expiration and revocation (CWE-613):** idle and absolute expiry plus the
  `revoked` flag are re-checked against the database on every `validate`, and the idle
  refresh happens in the same transaction as the decision
  (`SessionService.java:113-153`); `revoke` is silent for unknown tokens
  (`SessionService.java:159-168`); expired and revoked rows are pruned
  (`SessionService.java:56-58`). See SEC-07 for the one gap.
- **Cookie attributes (CWE-1004/CWE-614/CWE-352):** `__Host-` prefix with `Path=/`, no
  `Domain`, `HttpOnly`, `Secure`, `SameSite=Strict`, and a token-format precondition before
  the header is built (`SessionCookie.java:20, 38-43`).
- **Account enumeration (CWE-204):** registration returns `ACCEPTED` with identical wording
  for created and duplicate (`AccountService.java:126-137`, `App.java:127-132`);
  authentication returns one `INVALID_CREDENTIALS` for unknown identifier, wrong password
  and disabled account (`AccountService.java:174-195`, `App.java:172-176`); unknown
  identifiers still pay for a full Argon2 verification against a decoy hash with current
  parameters (`AccountService.java:86`, `PasswordHasher.java:132-145`), and an unusable
  password input burns comparable work (`AccountService.java:182`, `241-249`). The
  reserved-username message reveals only membership of a static list.
- **Rate limiting scope design (lockout-as-DoS, CWE-645):** both per-source and per-account
  counters exist, the per-account one expires unattended and is cleared by the victim's own
  successful login, blocked attempts are not counted so a window cannot be renewed
  indefinitely, the source counter is deliberately not cleared on success, and registration
  counts against the source only so nobody can burn a victim's account budget
  (`ThrottleService.java:100-135`, `AccountService.java:114-121`).
- **Concurrency / TOCTOU (CWE-367/CWE-362):** `inTransaction` takes the SQLite write lock up
  front via `transaction_mode=IMMEDIATE` with auto-commit off and rolls back on any failure
  (`Database.java:50-56`, `Database.java:77-92`); the throttle check and increment run inside
  the caller's transaction (`ThrottleService.java:100-119`); account uniqueness is decided by
  `UNIQUE` constraints surfaced as a duplicate rather than by read-then-write
  (`AccountRepository.java:50-68`, `Database.java:147-150`).
- **Input validation (CWE-20/CWE-176):** ASCII-only allowlists with length bounds for email
  local part, domain labels and TLD (`InputValidator.java:56-136`); username bounded
  *before* NFKC normalisation then re-bounded after, with a separator-adjacency rule and a
  reserved-name list, which is what stops full-width and compatibility homographs collapsing
  onto an existing name (`InputValidator.java:144-178`); RFC 8265 OpaqueString preparation
  for passwords, rejecting control, format, surrogate, private-use and unassigned code points
  (`InputValidator.java:184-228`).
- **Secrets in source / arguments (CWE-798/CWE-214):** no credential is compiled in (grep for
  hardcoded key/password/token patterns over `src/main/java` returns only comments and
  `SecureRandom` constructions); the pepper comes from the environment only and is never
  logged or echoed on a decode failure (`Config.java:43-44, 165-181`); passwords are never
  accepted as command-line arguments (`App.java:22-26`); `Config.toString` omits the pepper
  (`Config.java:262-271`).
- **Sensitive data in logs (CWE-532/CWE-117):** passwords and raw tokens have no masking
  helper and are never logged (`Mask.java:4-8`); emails and usernames are masked at every log
  site (`AccountService.java:130-135, 192-193, 209-212`); JDBC URLs are stripped of userinfo
  and query strings before logging (`Mask.java:39-59`, `Database.java:55`); the formatter
  collapses CR/LF/NEL/LS/PS so injected newlines cannot forge entries
  (`Logging.java:107-109`); the session token is never printed — only the non-secret reference
  is (`App.java:163-165`).
- **File permissions for log and session files (CWE-732/CWE-59):** both are created with
  `rw-------` as a creation attribute before any write, both refuse a symlinked path, and
  `FileHandler` is deliberately limited to a single file so no rotated world-readable copy is
  produced (`Logging.java:64-80`, `App.java:324-345`); the data directory itself is forced to
  `rwx------` and rejected if it is a symlink (`Config.java:120-151`); the session file is
  size-bounded before being read (`App.java:347-356`).
- **Secret lifetime in memory (CWE-316):** passwords and tokens are handled as `char[]`/
  `byte[]` and zeroed in `finally` blocks throughout
  (`Wipe.java:13-26`, `PasswordHasher.java:73-78, 103-107, 166-168`,
  `SessionService.java:105-109`, `AccountService.java:138-140, 214-216`,
  `App.java:102-104, 142-145, 182-187`); UTF-8 encoding goes through a `CharBuffer` so no
  `String` copy of the password is created on the common path
  (`PasswordHasher.java:172-189`). The two residual exposures (the rare non-NFC
  normalisation path at `InputValidator.java:207-211` and the cookie `String` at
  `SessionCookie.java:44`) are unavoidable with the platform APIs used and are documented in
  the code.
- **Error handling / information disclosure (CWE-209/CWE-248):** stack traces go only to the
  owner-only log; the console gets generic sentences, and `ValidationException` messages are
  format-only (`App.java:98-101, 134-141, 178-181`, `ValidationException.java:3-7`).
- **Insecure deserialization (CWE-502):** no Java serialization, XML, YAML or object-graph
  parsing exists anywhere in the codebase; the only parsed external formats are the PHC hash
  string and the environment variables, both handled with strict bounded parsers.
- **Dependency and build provenance (CWE-1104/CWE-494):** versions are pinned (Bouncy Castle
  1.79, sqlite-jdbc 3.47.1.0, slf4j-nop 2.0.16), the only repository is Maven Central over
  HTTPS with `checksumPolicy=fail` and snapshots disabled, and no known-vulnerable advisory
  was identified for the pinned versions (`pom.xml:16-31`).
