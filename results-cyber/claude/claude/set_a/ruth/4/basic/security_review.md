# Security Review: UserRegistration (JDBC user sign-up and authentication)

## 1. Executive Summary
`UserRegistration.java` is a single JDK-only Java class. It registers user accounts in an SQL database over an existing JDBC `Connection` and later checks username/password pairs against what it stored. Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte `SecureRandom` salt, 256-bit output) and compared in constant time. Every query that takes user input is a `PreparedStatement`. A `main` method is included as a CLI demo.

Overall the implementation is sound. It has no injection flaws, no weak or misused cryptography, no plaintext password storage and no hardcoded application secrets. The main weaknesses are missing controls around the authentication API, not broken primitives:

- **Medium:** `authenticate()` has no brute-force, credential-stuffing or lockout protection. Each call also costs one full 600k-iteration PBKDF2 run, so unthrottled calls can exhaust CPU.
- **Low:** The password policy checks length only (8–128) and has no check against common or breached passwords.
- **Low:** The demo takes the database password as a command-line argument, which is visible in the process list and shell history.
- **Low:** `verifyPassword()` trusts the iteration count and hash length stored in the database without upper bounds. A tampered row can turn each login into a very long CPU task.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserRegistration.java` | Registers users and authenticates them against a `users` table; includes a CLI demo `main` | SQL construction (DDL via `Statement`, DML via `PreparedStatement`); PBKDF2 password hashing, salt generation with `SecureRandom`, constant-time comparison; authentication and username-enumeration timing defence; input validation for username and password; parsing of stored hash strings; handling of DB credentials and password input in `main` |
| `README.md` | Usage, schema, compile and run documentation | Documents the security design; example command lines pass DB credentials as arguments (`README.md:120-121`) |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Task prompt and generation-run metadata (not code) | None: no executable code, no credentials |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow: understand the code, pick matching library skills, apply them, report.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm choice and parameters (`UserRegistration.java:65-69`), salt and RNG (`:71`, `:196-202`), constant-time comparison (`:218`), dummy-hash generation (`:241-248`), hardcoded key/secret checks, and parsing of stored KDF parameters (`:205-222`). This produced SEC-04.
- `exploiting-sql-injection-vulnerabilities`: Applied to every SQL string and execution path (`:47-57`, `:84-86`, `:107-111`, `:134-141`) to check that parameters are bound rather than concatenated.
- `performing-second-order-sql-injection`: Applied to the stored `username` and `password_hash` values to confirm stored data is never concatenated into a later query.
- `testing-api-authentication-weaknesses`: Applied to `authenticate()` and `register()` for password policy, credential-stuffing susceptibility, account enumeration (message and timing differences) and credential leakage. This produced SEC-01 and SEC-02.
- `implementing-api-rate-limiting-and-throttling`: Applied to the lack of per-account or per-client throttling on the authentication path. This supports SEC-01.
- `testing-for-sensitive-data-exposure`: Applied to how credentials and password hashes are handled, logged or printed (`main`, exception messages, README examples). This produced SEC-03.
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): Unicode case-mapping in username normalisation (`:131`, `:160`), static initialisation order of `RANDOM` and `DUMMY_HASH`, exception and error-message handling (`:112-119`, `:179-189`, `:229-230`), and in-memory password handling (`char[]` wiping, `PBEKeySpec.clearPassword()`).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No brute-force / credential-stuffing protection on authentication | Medium | CWE-307 | `UserRegistration.java:127-150` |
| SEC-02 | Weak password policy (length-only, no common/breached password check) | Low | CWE-521 | `UserRegistration.java:168-177` |
| SEC-03 | Database password passed on the command line in demo | Low | CWE-214 | `UserRegistration.java:284-288` |
| SEC-04 | Unbounded KDF parameters parsed from stored hash | Low | CWE-1284 | `UserRegistration.java:211-217` |

## 5. Detailed Findings

### SEC-01: No brute-force / credential-stuffing protection on authentication
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserRegistration.java:127-150`

**Vulnerable code:**
```java
// UserRegistration.java:127-150
    public boolean authenticate(String username, char[] password) throws SQLException {
        if (username == null || password == null) {
            return false;
        }
        String normalized = username.trim().toLowerCase(Locale.ROOT);

        String storedHash = null;
        try (PreparedStatement ps = connection.prepareStatement(SELECT_HASH_SQL)) {
            ps.setString(1, normalized);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    storedHash = rs.getString(1);
                }
            }
        }

        if (storedHash == null) {
            // Do the same amount of work as a real check so response time does not
            // reveal whether the username exists.
            verifyPassword(password, DUMMY_HASH);
            return false;
        }
        return verifyPassword(password, storedHash);
    }
```

**Why it is a problem:** `authenticate()` is the only credential-verification entry point the class offers, and it places no limit on failed attempts. It does not count failures per account, apply a delay or backoff, lock the account temporarily, or expose a hook for the caller to do so. The table has no columns to record failures. Callers who wire this straight into a login endpoint (as the README suggests) get an interface that accepts unlimited online password guessing, password spraying and credential stuffing. The 8-character minimum policy (SEC-02) makes this worse. PBKDF2 slows offline cracking but gives little protection online: an attacker can run many requests in parallel. Each attempt also costs the server one 600,000-iteration PBKDF2 run (about 0.5–1 s of CPU), including attempts for non-existent usernames, so unthrottled login traffic is also a cheap CPU-exhaustion denial of service (CWE-770).

**Fix:** Track failed attempts per account and apply throttling or temporary lockout before doing the expensive hash. Reset the counter on success. Callers should also add per-IP / per-client rate limiting at the endpoint and limit concurrent hash computations. Schema addition: `failed_attempts INT NOT NULL DEFAULT 0, locked_until TIMESTAMP NULL`.
```java
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_SECONDS = 15 * 60;

    private static final String SELECT_AUTH_SQL =
            "SELECT password_hash, failed_attempts, locked_until FROM " + TABLE_NAME + " WHERE username = ?";
    private static final String RECORD_FAILURE_SQL =
            "UPDATE " + TABLE_NAME + " SET failed_attempts = failed_attempts + 1, "
                    + "locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END "
                    + "WHERE username = ?";
    private static final String RESET_FAILURES_SQL =
            "UPDATE " + TABLE_NAME + " SET failed_attempts = 0, locked_until = NULL WHERE username = ?";

    public boolean authenticate(String username, char[] password) throws SQLException {
        if (username == null || password == null || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        String normalized = username.trim().toLowerCase(Locale.ROOT);

        String storedHash = null;
        Timestamp lockedUntil = null;
        try (PreparedStatement ps = connection.prepareStatement(SELECT_AUTH_SQL)) {
            ps.setString(1, normalized);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    storedHash = rs.getString(1);
                    lockedUntil = rs.getTimestamp(3);
                }
            }
        }

        if (storedHash == null) {
            verifyPassword(password, DUMMY_HASH);
            return false;
        }
        if (lockedUntil != null && lockedUntil.toInstant().isAfter(Instant.now())) {
            // Keep timing uniform, but refuse without testing the real hash.
            verifyPassword(password, DUMMY_HASH);
            return false;
        }

        boolean ok = verifyPassword(password, storedHash);
        String sql = ok ? RESET_FAILURES_SQL : RECORD_FAILURE_SQL;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            if (ok) {
                ps.setString(1, normalized);
            } else {
                ps.setInt(1, MAX_FAILED_ATTEMPTS);
                ps.setTimestamp(2, Timestamp.from(Instant.now().plusSeconds(LOCKOUT_SECONDS)));
                ps.setString(3, normalized);
            }
            ps.executeUpdate();
        }
        return ok;
    }
```

### SEC-02: Weak password policy (length-only, no common/breached password check)
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserRegistration.java:168-177`

**Vulnerable code:**
```java
// UserRegistration.java:168-177
    private static void validatePassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters.");
        }
    }
```

**Why it is a problem:** Length is the only rule. Registration accepts `password`, `12345678`, `qwertyui`, all-whitespace strings, and passwords equal to the username (e.g. username `alice123` with password `alice123`). These are the first guesses in any spraying or stuffing list. Combined with SEC-01, many accounts can be guessed online in a handful of attempts. NIST SP 800-63B requires new passwords to be checked against a blocklist of commonly used, expected or compromised values.

**Fix:** Keep the 8–128 length rule, and also reject passwords that are blank, contain the username, or appear on a common/breached-password blocklist. An optional k-anonymity breach check (e.g. Pwned Passwords range API) can be added by the caller. Pass the username into validation.
```java
    private static final java.util.Set<String> COMMON_PASSWORDS = loadBlocklist(); // e.g. top 100k list bundled as a resource

    private static void validatePassword(String normalizedUsername, char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters.");
        }
        String candidate = new String(password);
        String lower = candidate.toLowerCase(Locale.ROOT);
        if (candidate.isBlank()) {
            throw new IllegalArgumentException("Password must not be blank.");
        }
        if (lower.contains(normalizedUsername)) {
            throw new IllegalArgumentException("Password must not contain the username.");
        }
        if (COMMON_PASSWORDS.contains(lower)) {
            throw new IllegalArgumentException("Password is too common; choose a different one.");
        }
    }

    // in register():
    //     String normalized = normalizeUsername(username);
    //     validatePassword(normalized, password);
```

### SEC-03: Database password passed on the command line in demo
- **Severity:** Low
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `UserRegistration.java:284-288` (also documented at `README.md:120-121`)

**Vulnerable code:**
```java
// UserRegistration.java:284-288
        String dbUser = args.length > 2 ? args[2] : null;
        String dbPassword = args.length > 3 ? args[3] : null;

        // In a real application this Connection would be supplied by the caller / pool.
        try (Connection conn = DriverManager.getConnection(url, dbUser, dbPassword)) {
```

**Why it is a problem:** The database password is read from `args[3]`, and the README tells users to run `... UserRegistration "jdbc:postgresql://localhost:5432/app" alice dbuser dbpass`. Command-line arguments can be read by other local users through `ps`, `/proc/<pid>/cmdline` and process-monitoring or EDR telemetry, and they are saved in shell history. The account password is handled correctly here (hidden console input), but the database credential, which is often more privileged, is not. The impact is limited because this is the demo entry point, but the pattern is likely to be copied.

**Fix:** Read the database password from an environment variable or hidden console input instead of `argv`, and update the README examples to match.
```java
        String dbUser = args.length > 2 ? args[2] : System.getenv("DB_USER");
        char[] dbPasswordChars = System.getenv("DB_PASSWORD") != null
                ? System.getenv("DB_PASSWORD").toCharArray()
                : (dbUser != null ? readPassword("Database password for '" + dbUser + "': ") : null);
        String dbPassword = dbPasswordChars != null ? new String(dbPasswordChars) : null;
        if (dbPasswordChars != null) {
            Arrays.fill(dbPasswordChars, '\0');
        }

        // In a real application this Connection would be supplied by the caller / pool.
        try (Connection conn = DriverManager.getConnection(url, dbUser, dbPassword)) {
```

### SEC-04: Unbounded KDF parameters parsed from stored hash
- **Severity:** Low
- **CWE:** CWE-1284: Improper Validation of Specified Quantity in Input
- **Location:** `UserRegistration.java:211-217`

**Vulnerable code:**
```java
// UserRegistration.java:211-217
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            if (iterations <= 0 || salt.length == 0 || expected.length == 0) {
                return false;
            }
            byte[] actual = pbkdf2(password, salt, iterations, expected.length * 8);
```

**Why it is a problem:** The iteration count and derived-key length come from the `password_hash` column and only have lower bounds. If anyone can alter that column (another component with write access, a second-order write bug elsewhere, a restored or migrated dump), they can set it to e.g. `pbkdf2-sha256$2147483647$...`. Every login attempt for that account then runs roughly 3,500 times the normal work (hours of CPU per request), and an oversized `expected` length multiplies the PBKDF2 block count, giving a targeted denial of service. The same missing check also allows a silent downgrade to `iterations = 1`, which weakens that hash against offline cracking if the table leaks later. The precondition is write access to the table, so the severity is low. This is defence in depth.

**Fix:** Accept only the parameter ranges this class can produce: the exact output length and an iteration count between a sane minimum and maximum. Treat anything else as malformed.
```java
    private static final int MIN_ITERATIONS = 100_000;
    private static final int MAX_ITERATIONS = 10_000_000;

            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                    || salt.length < SALT_BYTES || salt.length > 64
                    || expected.length != HASH_BITS / 8) {
                return false;
            }
            byte[] actual = pbkdf2(password, salt, iterations, HASH_BITS);
```

## 6. Verified Controls and Checks With No Finding
- SQL injection (first and second order): `INSERT_SQL` and `SELECT_HASH_SQL` (`UserRegistration.java:53-57`) use `?` placeholders bound with `setString`/`setTimestamp` (`:108-110`, `:135`). The only concatenation is the compile-time constant `TABLE_NAME` (`:41`). The DDL run through a plain `Statement` (`:84-86`) is a constant with no user input. Stored usernames and hashes are never concatenated into later queries.
- Password storage: No plaintext is stored. The value is PBKDF2WithHmacSHA256 with 600,000 iterations (the OWASP 2023 recommendation), a 16-byte salt per user and a 256-bit output (`:65-69`, `:196-202`). The format stores the algorithm ID and iteration count so the work factor can be raised later.
- Randomness: Salts and dummy hashes use a single static `java.security.SecureRandom` (`:71`, `:198`, `:244-245`). `java.util.Random`, time-based seeds and fixed salts are not used.
- Constant-time comparison: Digests are compared with `MessageDigest.isEqual` (`:218`), not `Arrays.equals` or string equality.
- Username enumeration by timing on login: A missing user still costs one PBKDF2 run against `DUMMY_HASH`, which has the same iteration count and output length (`:143-148`, `:241-248`). Wrong-user and wrong-password both return `false` with no distinguishing message. Static initialisation order is correct: `RANDOM` (`:71`) is initialised before `DUMMY_HASH` (`:76`).
- Enumeration on registration: `UsernameTakenException` (`:255-260`) says the name is taken. This is unavoidable for a sign-up flow. Hashing runs before the insert (`:105-111`), so taken and free names take the same time.
- Registration race: Uniqueness is enforced by the primary-key constraint, not check-then-insert (`:49`, `:112-119`), so concurrent registrations of the same name cannot both succeed (no CWE-367).
- Username normalisation and Unicode: Registration lowercases with `Locale.ROOT` and then validates against the ASCII-only `^[a-z0-9._-]{3,50}$` (`:156-166`), so every stored username is ASCII. Characters that lowercase to ASCII (e.g. U+212A KELVIN SIGN to `k`) map to the same canonical account, so there is no look-alike duplicate-account spoofing. `authenticate` applies the same normalisation (`:131`). Input that does not match the pattern simply finds no row.
- Input length and DoS on the hashing input: Registration caps passwords at 128 characters (`:173-176`). `authenticate` has no cap, but the JDK PBKDF2 implementation initialises the HMAC key (hashing a long password once) outside the iteration loop, so a long password costs only a single linear hash, not per-iteration work. Adding the cap to `authenticate` is recommended in the SEC-01 fix as hygiene.
- Malformed stored hashes: Wrong field count, unknown algorithm ID, non-numeric iterations and invalid Base64 are rejected with `false` without leaking an exception (`:206-221`). `NumberFormatException` is a subclass of the `IllegalArgumentException` that is caught. Parameter bounds are covered by SEC-04.
- In-memory secret handling: Passwords are passed as `char[]`, `PBEKeySpec.clearPassword()` runs in `finally` (`:231-233`), and the demo wipes both password arrays (`:310-311`). Passwords are never turned into `String`s in the library path. Account-password input in the demo uses hidden `Console.readPassword` when a console is available (`:316-320`).
- Error handling and information exposure: Exception messages contain only the username and validation rules, never passwords or hashes (`:116`, `:162-176`, `:259`). An unavailable algorithm raises `IllegalStateException` without fallback to a weaker algorithm (`:229-230`). `isUniqueViolation` only decides between `UsernameTakenException` and rethrowing the original exception (`:179-189`), with no security impact.
- Hardcoded secrets: No keys, passwords or connection strings in `UserRegistration.java`. The literal `"definitely-not-the-password"` (`:306`) is a demo negative test value, not a credential. `README.md` holds only placeholder credentials (`dbuser dbpass`), covered under SEC-03.
- Deserialization, command execution, file/path access, XML, network/TLS and XSS: None present in the code. `UsernameTakenException` declares `serialVersionUID` but no data is deserialized. Transport security of the JDBC connection is the caller's responsibility, since the connection is supplied externally.
- Non-code files (`prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`): Reviewed. They are task text and run metadata with no code, credentials or security-relevant configuration.
