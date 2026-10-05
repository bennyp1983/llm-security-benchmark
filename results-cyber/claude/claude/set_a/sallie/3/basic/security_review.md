# Security Review: UserAuthenticator (Java email/password authentication CLI)

## 1. Executive Summary
`UserAuthenticator` is a small Java command-line program. It checks an email address and password against a SQL database (SQLite `users.db` by default, or any JDBC database set through `DB_URL`, `DB_USER` and `DB_PASSWORD`). It also has an `add-user` command that creates a user or overwrites an existing user's password. Passwords are stored as per-user salted PBKDF2-HMAC-SHA256 hashes with 600,000 iterations. They are compared in constant time, and every query uses a JDBC `PreparedStatement`.

The core controls are sound. No SQL injection, weak hashing, hardcoded secrets or login-message user enumeration were found. The most important issues are design and hardening gaps:

- **No authentication on password reset (Medium):** `add-user` is in the same binary and uses the same database credentials as `login`. It resets any account's password without asking for the current password or checking the caller's role. Any person or script allowed to run a login can therefore take over any account.
- **No brute-force protection (Medium):** there is no limit, lockout, delay or audit log for failed attempts, so online password guessing is unlimited.
- **Lower-severity issues (Low):** no password strength policy; the `iterations`, `salt` and `hash` values read from the DB are trusted without checks, so a tampered row can downgrade the work factor, cause CPU exhaustion, or crash the program; the SQLite file is created at a relative path with default permissions; raw database error messages are printed; and the bundled `sqlite-jdbc` driver is out of date.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAuthenticator.java` | The whole program: CLI argument handling, `login` and `add-user` commands, DB access, password hashing | SQL queries (JDBC `PreparedStatement`), PBKDF2 password hashing, salt generation (`SecureRandom`), constant-time hash comparison, dummy-hash timing equalisation, password reset/creation, reading credentials from env vars, reading passwords from console/stdin, error handling and exit codes |
| `schema.sql` | Optional DDL for the `users` table | Defines credential storage columns (`password_hash`, `salt`, `iterations`); no default accounts or seeded credentials |
| `README.md` | Plain-English setup and usage guide | Documents the `add-user` password-overwrite behaviour, the default relative DB location, env-var credentials, and how piped input is handled |
| `lib/sqlite-jdbc-3.45.1.0.jar` | Third-party SQLite JDBC driver (bundles native SQLite 3.45.1) | Parses and runs all SQL; vendored binary dependency |
| `lib/slf4j-api-1.7.36.jar`, `lib/slf4j-nop-1.7.32.jar` | Logging facade and no-op binding pulled in by the driver | Discards all log output; no security-relevant processing |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Metadata from the run that generated the code (not program code) | None; reviewed only to confirm there are no credentials or executable content |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: the router workflow. Read every file, extracted security-relevant behaviours, searched the library by skill name, and applied the matching skills in priority order.
- `performing-cryptographic-audit-of-application`: applied to password hashing (algorithm, iteration count, output size), salt generation and RNG, constant-time comparison, hardcoded secrets, and KDF parameter handling. Led to SEC-04.
- `testing-api-authentication-weaknesses`: applied to the login flow. Covered brute-force and credential-stuffing resistance, password policy, and account enumeration through response text, exit code and timing. Led to SEC-02 and SEC-03. The JWT, token and session checks do not apply to this CLI.
- `testing-for-broken-access-control`: applied to the privileged `add-user` function (missing function-level authorisation, overwriting another user's credentials, least privilege). Led to SEC-01.
- `exploiting-sql-injection-vulnerabilities`: applied to all SQL building and execution, including second-order injection through stored email values. No finding.
- `testing-for-sensitive-data-exposure`: applied to error messages, console output, where password material goes, and credentials in source or documentation. Led to SEC-06.
- `performing-sca-dependency-scanning-with-snyk`: its SCA and reachability triage method was applied by hand to the vendored jars in `lib/` (Snyk itself was not run). Led to SEC-07.
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): file-system permissions and the relative path of the SQLite file (CWE-732, SEC-05), resource bounds on DB-supplied work factors (CWE-1284 / CWE-400, SEC-04), unhandled runtime exceptions and fail-closed behaviour, the non-transactional UPDATE-then-INSERT race, and the trust boundary of the JDBC URL taken from the environment.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | `add-user` resets any user's password without authentication or authorisation | Medium | CWE-306 | `UserAuthenticator.java:124` |
| SEC-02 | No throttling, lockout or audit logging of failed logins | Medium | CWE-307 | `UserAuthenticator.java:132` |
| SEC-03 | No password strength policy when creating or resetting passwords | Low | CWE-521 | `UserAuthenticator.java:117` |
| SEC-04 | Work factor, salt and hash read from the DB are used without checks | Low | CWE-1284 | `UserAuthenticator.java:165` |
| SEC-05 | Credential database created at a relative path with default permissions | Low | CWE-732 | `UserAuthenticator.java:46` |
| SEC-06 | Raw database exception messages are shown to the caller | Low | CWE-209 | `UserAuthenticator.java:141` |
| SEC-07 | Out-of-date bundled sqlite-jdbc / SQLite 3.45.1 | Low | CWE-1395 | `lib/sqlite-jdbc-3.45.1.0.jar!/META-INF/maven/org.xerial/sqlite-jdbc/pom.properties:3` |

## 5. Detailed Findings

### SEC-01: `add-user` resets any user's password without authentication or authorisation
- **Severity:** Medium
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `UserAuthenticator.java:122-130` (and `saveUser`, `UserAuthenticator.java:180-206`)

**Vulnerable code:**
```java
// UserAuthenticator.java:122-130
            authenticator.createTableIfMissing();

            if (command.equals("add-user")) {
                boolean created = authenticator.saveUser(email, password);
                System.out.println(created
                        ? "User " + email + " created."
                        : "Password updated for " + email + ".");
                System.exit(EXIT_SUCCESS);
            }
```

**Why it is a problem:** Creating accounts and resetting passwords are privileged operations. Here they sit in the same program, use the same `DB_URL`/`DB_USER`/`DB_PASSWORD`, and have no check of who is calling. `saveUser` runs an `UPDATE` first, so `add-user victim@example.com` silently replaces the victim's password with one the caller chooses. There is no check of the current password and no admin role. The README says the tool is meant to be driven by scripts, which makes the risk concrete: whoever can run `login` (a helpdesk user, a web back end that shells out, a cron job) can also run `add-user` and take over any account (CWE-620). `createTableIfMissing()` also runs on every login, so the login path needs DDL and write privileges, when read-only `SELECT` access would be enough. That breaks least privilege, and a compromised login deployment gets write access to all credentials.

**Fix:** Separate the privileged operations from login. Creating an account must never overwrite an existing one. Changing a password must require the current password; an administrative reset must require separate, write-capable admin credentials. Give the login path a read-only DB account (for SQLite, a file readable but not writable by the login process), and stop running DDL during login.
```java
if (command.equals("add-user")) {
    // Administrative action: needs a separate, write-capable DB account that only
    // administrators hold. The login path uses a read-only account.
    UserAuthenticator admin = new UserAuthenticator(dbUrl,
            requireEnv("DB_ADMIN_USER"), requireEnv("DB_ADMIN_PASSWORD"));
    admin.createTableIfMissing();
    if (!admin.createUser(email, password)) {        // INSERT only, never UPDATE
        System.err.println("Error: user already exists.");
        System.exit(EXIT_ERROR);
    }
    System.out.println("User " + email + " created.");
    System.exit(EXIT_SUCCESS);
}

if (command.equals("change-password")) {
    char[] newPassword = input.readPassword("New password: ");
    try {
        // 'password' holds the CURRENT password and must verify first.
        if (!authenticator.authenticate(email, password)) {
            System.out.println("Authentication failed: invalid email address or password.");
            System.exit(EXIT_AUTH_FAILED);
        }
        authenticator.updatePassword(email, newPassword);   // UPDATE ... WHERE email = ?
        System.out.println("Password updated.");
        System.exit(EXIT_SUCCESS);
    } finally {
        Arrays.fill(newPassword, '\0');
    }
}

// login path: no createTableIfMissing(); a read-only connection is enough.
if (authenticator.authenticate(email, password)) { ... }

public boolean createUser(String email, char[] password) throws SQLException {
    byte[] salt = new byte[SALT_BYTES];
    RANDOM.nextBytes(salt);
    try (Connection conn = connect();
         PreparedStatement insert = conn.prepareStatement(INSERT_USER_SQL)) {
        insert.setString(1, normalizeEmail(email));
        insert.setString(2, Base64.getEncoder().encodeToString(hash(password, salt, ITERATIONS)));
        insert.setString(3, Base64.getEncoder().encodeToString(salt));
        insert.setInt(4, ITERATIONS);
        return insert.executeUpdate() == 1;
    } catch (SQLException e) {
        if (isUniqueViolation(e)) {
            return false;
        }
        throw e;
    }
}
```

### SEC-02: No throttling, lockout or audit logging of failed logins
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAuthenticator.java:132-139` (verification logic in `UserAuthenticator.java:156-174`)

**Vulnerable code:**
```java
// UserAuthenticator.java:132-139
            if (authenticator.authenticate(email, password)) {
                System.out.println("Authentication successful. Welcome, " + email + "!");
                System.exit(EXIT_SUCCESS);
            } else {
                // Deliberately vague: do not reveal whether the email or the password was wrong.
                System.out.println("Authentication failed: invalid email address or password.");
                System.exit(EXIT_AUTH_FAILED);
            }
```

**Why it is a problem:** Each run checks one guess and exits. Nothing records failed attempts in the database: there is no per-account counter, no lockout or progressive delay, and no audit log entry. An attacker who can invoke the program, directly or through a script or service that wraps it, can run password-spraying or credential-stuffing loops in parallel with no limit. PBKDF2 makes each guess cost about 0.3–1 s of CPU, but that only slows offline cracking. It does not stop online guessing of common passwords, and SEC-03 means weak passwords are accepted. Because nothing is logged, defenders cannot detect such an attack (CWE-778).

**Fix:** Store failure state per account in the DB and apply it in `authenticate`. Always compute the hash so timing stays uniform. Log successes and failures to an audit log, never logging the password. Prefer a short, time-limited lock or progressive delay over a permanent lock, so attackers can't lock victims out indefinitely.
```java
// schema: ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
//         ALTER TABLE users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0;
private static final Logger AUDIT = Logger.getLogger("auth.audit");
private static final int MAX_FAILED_ATTEMPTS = 5;
private static final long LOCKOUT_MILLIS = 15 * 60 * 1000L;

public boolean authenticate(String email, char[] password) throws SQLException {
    String normalizedEmail = normalizeEmail(email);
    try (Connection conn = connect();
         PreparedStatement stmt = conn.prepareStatement(
                 "SELECT password_hash, salt, iterations, failed_attempts, locked_until"
                 + " FROM users WHERE email = ?")) {
        stmt.setString(1, normalizedEmail);
        try (ResultSet rs = stmt.executeQuery()) {
            if (!rs.next()) {
                MessageDigest.isEqual(DUMMY_HASH, hash(password, DUMMY_SALT, ITERATIONS));
                AUDIT.warning("login failed: unknown account");
                return false;
            }
            byte[] storedHash = Base64.getDecoder().decode(rs.getString("password_hash"));
            byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
            boolean matches = MessageDigest.isEqual(storedHash,
                    hash(password, salt, rs.getInt("iterations")));
            long now = System.currentTimeMillis();

            if (rs.getLong("locked_until") > now) {
                AUDIT.warning("login rejected: account temporarily locked: " + normalizedEmail);
                return false;
            }
            if (matches) {
                try (PreparedStatement reset = conn.prepareStatement(
                        "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE email = ?")) {
                    reset.setString(1, normalizedEmail);
                    reset.executeUpdate();
                }
                AUDIT.info("login succeeded: " + normalizedEmail);
                return true;
            }
            int failures = rs.getInt("failed_attempts") + 1;
            try (PreparedStatement fail = conn.prepareStatement(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE email = ?")) {
                fail.setInt(1, failures);
                fail.setLong(2, failures >= MAX_FAILED_ATTEMPTS ? now + LOCKOUT_MILLIS : 0L);
                fail.setString(3, normalizedEmail);
                fail.executeUpdate();
            }
            AUDIT.warning("login failed: bad password (" + failures + "): " + normalizedEmail);
            return false;
        }
    }
}
```

### SEC-03: No password strength policy when creating or resetting passwords
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAuthenticator.java:116-120`

**Vulnerable code:**
```java
// UserAuthenticator.java:116-120
            password = input.readPassword("Password: ");
            if (password == null || password.length == 0) {
                System.err.println("Error: password must not be empty.");
                System.exit(EXIT_ERROR);
            }
```

**Why it is a problem:** The only rule is "not empty", and it applies to `add-user` too. `a`, `1234` or `password` are accepted as account passwords. There is no maximum length either, so piped input can hold a password of any size. Weak passwords are the most likely to fall to the unlimited online guessing in SEC-02. If the hashes leak, even 600,000 PBKDF2 iterations won't protect them against a dictionary attack.

**Fix:** When setting a password (not at login), enforce a minimum length. NIST SP 800-63B requires at least 15 characters for passwords used as the only factor, and at least 8 when combined with MFA. Also set a reasonable maximum length and check the password against a blocklist of common or breached passwords.
```java
private static final int MIN_PASSWORD_LENGTH = 15;
private static final int MAX_PASSWORD_LENGTH = 128;

password = input.readPassword("Password: ");
if (password == null || password.length == 0) {
    System.err.println("Error: password must not be empty.");
    System.exit(EXIT_ERROR);
}
if (password.length > MAX_PASSWORD_LENGTH) {
    System.err.println("Error: password is too long.");
    System.exit(EXIT_ERROR);
}
if (command.equals("add-user")) {
    if (password.length < MIN_PASSWORD_LENGTH) {
        System.err.println("Error: password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        System.exit(EXIT_ERROR);
    }
    if (CommonPasswords.contains(password)) {   // blocklist of common or breached passwords
        System.err.println("Error: this password is too common; choose another.");
        System.exit(EXIT_ERROR);
    }
}
```

### SEC-04: Work factor, salt and hash read from the DB are used without checks
- **Severity:** Low
- **CWE:** CWE-1284: Improper Validation of Specified Quantity in Input
- **Location:** `UserAuthenticator.java:165-169` (used by `hash`, `UserAuthenticator.java:221-230`)

**Vulnerable code:**
```java
// UserAuthenticator.java:165-169
                byte[] storedHash = Base64.getDecoder().decode(rs.getString("password_hash"));
                byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
                int iterations = rs.getInt("iterations");

                byte[] suppliedHash = hash(password, salt, iterations);
```

**Why it is a problem:** The number of PBKDF2 rounds comes from the database row and is passed straight to `PBEKeySpec`. Nothing checks it against a floor or a ceiling.
- `iterations = 1` (a hand-edited row, a buggy migration, or someone with DB write access) makes that account's hash trivial to crack offline. That silently undoes the 600,000-round protection (CWE-916).
- `iterations = 2147483647` makes every login for that account burn CPU for hours (CWE-400).
- `iterations <= 0`, invalid Base64, a NULL column, or an empty salt makes `PBEKeySpec` / `Base64.Decoder` throw an unchecked `IllegalArgumentException` or `NullPointerException`. The program catches neither, so it dies with a stack trace (it still fails closed with exit code 1).

Rows with fewer iterations are also never upgraded to the current `ITERATIONS` after a successful login. Their timing also differs from the dummy-hash path, which reopens a small timing oracle for telling which accounts exist.

**Fix:** Check the stored parameters before use. Treat an invalid row as a failed authentication, still computing the dummy hash so timing stays uniform. Rehash with current parameters after a successful login.
```java
private static final int MIN_ITERATIONS = ITERATIONS;      // raise with ITERATIONS
private static final int MAX_ITERATIONS = 10_000_000;

String encodedHash = rs.getString("password_hash");
String encodedSalt = rs.getString("salt");
int iterations = rs.getInt("iterations");
byte[] storedHash;
byte[] salt;
try {
    storedHash = encodedHash == null ? null : Base64.getDecoder().decode(encodedHash);
    salt = encodedSalt == null ? null : Base64.getDecoder().decode(encodedSalt);
} catch (IllegalArgumentException e) {
    storedHash = null;
    salt = null;
}
if (storedHash == null || storedHash.length != HASH_BITS / 8
        || salt == null || salt.length < SALT_BYTES
        || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    MessageDigest.isEqual(DUMMY_HASH, hash(password, DUMMY_SALT, ITERATIONS));
    AUDIT.severe("rejecting malformed credential row for " + normalizeEmail(email));
    return false;
}

byte[] suppliedHash = hash(password, salt, iterations);
boolean matches = MessageDigest.isEqual(storedHash, suppliedHash);
if (matches && iterations < ITERATIONS) {
    saveUser(email, password);   // transparently upgrade to current parameters
}
return matches;
```

### SEC-05: Credential database created at a relative path with default permissions
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `UserAuthenticator.java:46` (used in `connect`, `UserAuthenticator.java:214-219`)

**Vulnerable code:**
```java
// UserAuthenticator.java:46
    private static final String DEFAULT_DB_URL = "jdbc:sqlite:users.db";
```

**Why it is a problem:** The default database is resolved against the current working directory, not a fixed location. SQLite creates it, along with its `-journal`/`-wal` files, using the process umask, which is typically `0644`. That leaves the password hashes and salts world-readable on multi-user hosts, ready for offline cracking. The relative path causes two more problems:
- If the program runs from a directory another user can write to (such as `/tmp` or a shared project folder), that user can plant a `users.db` holding a hash for a password they know. `login` then reports success for any email they choose, and scripts that trust exit code 0 are bypassed.
- Running from the "wrong" directory silently creates a new, empty credential store.

**Fix:** Use an absolute, configured location. Create the directory and file with owner-only permissions before SQLite opens it, and refuse to use a file owned by another user.
```java
private static final Path DEFAULT_DB_PATH =
        Paths.get(System.getProperty("user.home"), ".userauth", "users.db");

private static String defaultDbUrl() throws IOException {
    Path dir = DEFAULT_DB_PATH.getParent();
    if (Files.notExists(dir)) {
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")));
    }
    if (Files.notExists(DEFAULT_DB_PATH)) {
        Files.createFile(DEFAULT_DB_PATH, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rw-------")));
    }
    UserPrincipal me = FileSystems.getDefault().getUserPrincipalLookupService()
            .lookupPrincipalByName(System.getProperty("user.name"));
    if (!Files.getOwner(DEFAULT_DB_PATH).equals(me)
            || Files.getPosixFilePermissions(DEFAULT_DB_PATH).stream()
                    .anyMatch(p -> p.name().startsWith("GROUP") || p.name().startsWith("OTHERS"))) {
        throw new IOException("Refusing to use insecure credential database: " + DEFAULT_DB_PATH);
    }
    return "jdbc:sqlite:" + DEFAULT_DB_PATH.toAbsolutePath();
}
```

### SEC-06: Raw database exception messages are shown to the caller
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `UserAuthenticator.java:140-142`

**Vulnerable code:**
```java
// UserAuthenticator.java:140-142
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
            System.exit(EXIT_ERROR);
```

**Why it is a problem:** JDBC driver messages often include internal details: the database host and port, the DB user name (for example PostgreSQL's `password authentication failed for user "app_user"`), file-system paths, and table or constraint names. The program is designed to be wrapped by scripts, and wrappers commonly pass stderr back to end users or into shared logs, which exposes infrastructure details. Unchecked exceptions (see SEC-04) are not caught at all, so the JVM prints full stack traces with internal class and line information.

**Fix:** Print a generic message to the caller. Send details only to a protected diagnostic log, or show them when an explicit debug flag is set. Catch unexpected runtime exceptions so the program fails closed with a controlled message.
```java
} catch (SQLException e) {
    DIAGNOSTICS.log(Level.SEVERE, "database error", e);   // protected log, not the caller
    System.err.println("Error: the authentication service is unavailable.");
    System.exit(EXIT_ERROR);
} catch (IOException e) {
    System.err.println("Error: could not read input.");
    System.exit(EXIT_ERROR);
} catch (RuntimeException e) {
    DIAGNOSTICS.log(Level.SEVERE, "unexpected error", e);
    System.err.println("Error: authentication could not be completed.");
    System.exit(EXIT_ERROR);
}
```

### SEC-07: Out-of-date bundled sqlite-jdbc / SQLite 3.45.1
- **Severity:** Low
- **CWE:** CWE-1395: Dependency on Vulnerable Third-Party Component
- **Location:** `lib/sqlite-jdbc-3.45.1.0.jar!/META-INF/maven/org.xerial/sqlite-jdbc/pom.properties:1-3`

**Vulnerable code:**
```properties
! lib/sqlite-jdbc-3.45.1.0.jar!/META-INF/maven/org.xerial/sqlite-jdbc/pom.properties:1-3
artifactId=sqlite-jdbc
groupId=org.xerial
version=3.45.1.0
```

**Why it is a problem:** The driver is committed as a binary jar and bundles native SQLite 3.45.1 (early 2024). Memory-safety fixes have shipped in later SQLite releases, for example CVE-2025-29087 (`concat_ws` integer overflow, fixed in 3.49.1) and CVE-2025-6965 (integer truncation with many aggregate terms, fixed in 3.50.2). A reachability check using the SCA skill's method shows those bugs need attacker-controlled SQL. This program only runs fixed, parameterised statements, so present exploitability is low and the severity is Low. However, the jars are vendored with no build manifest, checksum or update path, so later fixes won't be picked up automatically, and future code changes could make the bugs reachable. `slf4j-nop` (1.7.32) and `slf4j-api` (1.7.36) are also mismatched, a sign the dependencies aren't managed.

**Fix:** Manage dependencies with a build tool that pins versions and verifies checksums, upgrade to the current `sqlite-jdbc` release, and run SCA scanning (`snyk test`, OWASP Dependency-Check or similar) in CI.
```xml
<dependencies>
  <dependency>
    <groupId>org.xerial</groupId>
    <artifactId>sqlite-jdbc</artifactId>
    <!-- use the latest release; must bundle SQLite >= 3.50.2 -->
    <version>3.50.3.0</version>
  </dependency>
  <dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-nop</artifactId>
    <version>1.7.36</version>
  </dependency>
</dependencies>
```

## 6. Verified Controls and Checks With No Finding
- **SQL injection (including second-order):** the `SELECT`, `UPDATE` and `INSERT` statements are constant strings with `?` placeholders (`UserAuthenticator.java:64-71`), and all values are bound through `setString`/`setInt` (`UserAuthenticator.java:158-159`, `188-202`). The only `Statement` runs the constant DDL `CREATE_TABLE_SQL` (`UserAuthenticator.java:57-62`, `209-210`). Stored emails are only ever bound back as parameters, never concatenated.
- **Password hashing algorithm and work factor:** PBKDF2WithHmacSHA256, 600,000 iterations, 256-bit output (`UserAuthenticator.java:48-51`, `221-224`). This matches the OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256. No MD5, SHA-1, unsalted or reversible storage.
- **Salt generation:** a fresh 16-byte salt per user from `SecureRandom`, regenerated on every password set (`UserAuthenticator.java:73`, `181-182`). No predictable seed.
- **Hash comparison:** constant-time `MessageDigest.isEqual`, which returns false when lengths differ (`UserAuthenticator.java:171`).
- **Account enumeration by response text or exit code:** unknown email and wrong password produce the same message and exit code 1 (`UserAuthenticator.java:136-138`, `161-163`). A dummy PBKDF2 computation with the same iteration count evens out timing for unknown emails (`UserAuthenticator.java:80-81`, `162`). The one residual timing difference, for rows with non-default iteration counts, is covered in SEC-04.
- **Hardcoded secrets:** none in source, `schema.sql` or `README.md`. DB credentials come only from the `DB_USER`/`DB_PASSWORD` environment variables (`UserAuthenticator.java:102-104`), and the README uses placeholders only.
- **Password exposure on the command line or screen:** passwords can't be passed as arguments (`UserAuthenticator.java:97` allows at most two arguments), are read with `Console.readPassword` without echo (`UserAuthenticator.java:286`), and are never printed or logged.
- **Password memory hygiene:** the `char[]` password is zeroed in `finally` (`UserAuthenticator.java:146-149`), and `PBEKeySpec.clearPassword()` is called (`UserAuthenticator.java:227-229`). The fallback for piped input creates a temporary immutable `String` (`UserAuthenticator.java:288`). That is only a minor, informational in-memory remnant.
- **Fail-closed behaviour:** no error path returns exit code 0. `SQLException`/`IOException` exit with 2, and uncaught runtime exceptions end the JVM with 1 (authentication failed) (`UserAuthenticator.java:140-145`).
- **Email normalisation:** `toLowerCase(Locale.ROOT)` avoids locale-dependent case mapping, such as the Turkish dotless i (`UserAuthenticator.java:233`). Length is capped at 255 to match the column (`UserAuthenticator.java:238`).
- **Deserialization, OS command execution, file path handling from user input, outbound network calls, XSS/HTML output, JWT/session tokens:** none present in the code.
- **Concurrency in `saveUser`:** the UPDATE-then-INSERT sequence isn't in a transaction (`UserAuthenticator.java:187-205`). Two concurrent `add-user` runs for the same new email hit the primary-key constraint and raise `SQLException`. There is no integrity or security impact.
- **JDBC URL from environment:** `DB_URL` (`UserAuthenticator.java:102`) could enable driver options, such as SQLite extension loading. It is set by whoever controls the process environment, who is already trusted, so this is not a finding.
- **`schema.sql`:** matches `CREATE_TABLE_SQL`; it seeds no default accounts or credentials.
- **Run metadata files** (`prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`): contain no secrets or executable code.
