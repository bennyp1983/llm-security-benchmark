# Security Review: UserAuthenticator (Java email/password authentication CLI)

## 1. Executive Summary
`UserAuthenticator.java` is a small Java 17 command-line program and reusable class. It checks an email address and password against a `users` table in any JDBC-reachable SQL database. It looks up the stored password hash with a fixed `PreparedStatement`. It then checks the password in Java against a salted PBKDF2-HMAC-SHA256 hash (600,000 iterations) using a constant-time comparison. It also has a `--hash` mode that creates hashes to store in the database.

The core controls are well built. **No SQL injection was found**, including second-order SQL injection. There are no weak cryptographic primitives, no hardcoded secrets, and no error-message leaks. The most important remaining issues are defence-in-depth gaps:

- **SEC-01 (Medium):** Nothing limits or slows repeated attempts, so the public `authenticate()` API and the CLI allow unlimited online password guessing (CWE-307).
- **SEC-02 (Low):** Response time still depends on the stored hash. Hashes with a different iteration count, or malformed ones, take measurably different time than the dummy-hash path, so timing can still reveal which accounts exist (CWE-208).
- **SEC-03 (Low):** The database connection does not require TLS, and the README's example URL has no TLS. Password hashes and database credentials may cross the network in cleartext (CWE-319).
- **SEC-04 (Low):** When no console is attached, the password is read into an immutable `String`. It stays in memory, which contradicts the documented "wiped from memory" guarantee (CWE-316).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAuthenticator.java` | CLI and class that authenticates an email and password against a SQL `users` table; `--hash` mode creates password hashes | JDBC query building (`PreparedStatement`), PBKDF2 password hashing and checking, salt from `SecureRandom`, constant-time comparison, defence against user enumeration (dummy hash, generic message), input validation, DB credentials from environment variables, reading passwords from console or stdin, wiping passwords from memory, error handling and exit codes |
| `README.md` | Plain-English guide: setup, adding users, running, security notes | Deployment guidance: example `DB_URL` without TLS, credentials exported in the shell, advice on a read-only DB account and rate limiting |
| `prompt.txt` | Original generation prompt | None (not code) |
| `cyber_prompt.txt` | Instructions for this review | None (not code) |
| `result.md` | Metadata and summary from the generation run | None (not code) |
| `return.txt` | Raw JSON result from the generation run | None (not code) |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: The router workflow. Step 1: understand the code and extract keywords (sql injection, password hashing/cryptography, authentication, enumeration/timing, sensitive data exposure, secrets). Step 2: grep skill names and read their descriptions. Step 3: apply the selected skills. Step 4: this report.
- `exploiting-sql-injection-vulnerabilities`: Applied to query construction and parameter binding (`UserAuthenticator.java:49-50`, `111-121`), checking that every database input is a bound parameter and that no SQL is built dynamically.
- `performing-second-order-sql-injection`: Applied to data read back from the database (`password_hash` at `UserAuthenticator.java:118`), confirming it is never put into a later SQL statement.
- `performing-cryptographic-audit-of-application`: Applied to password hashing and checking (`UserAuthenticator.java:52-58`, `67-70`, `145-190`): algorithm, KDF iteration count, salt size and RNG, output length, constant-time comparison, hardcoded keys or passwords, and transport encryption of the database link (SEC-03).
- `testing-api-authentication-weaknesses`: Applied to the authentication flow (`UserAuthenticator.java:88-108`, `200-236`): brute-force and credential-stuffing resistance (SEC-01), account enumeration through messages and timing (SEC-02), and generic failure responses.
- `testing-for-sensitive-data-exposure`: Applied to error messages, secret handling, data in transit and credential exposure (`UserAuthenticator.java:211-235`, `265-273`; `README.md:109-129`, `183-184`).
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): Wiping secrets from memory and reading stdin in Java (CWE-316/CWE-226, SEC-04). Email canonicalisation and DB collation effects. Trust in the JDBC URL from the environment (driver-level injection such as H2 `INIT` or MySQL `autoDeserialize`). Denial of service through parsing attacker-influenced hash parameters. Lockout-induced DoS considerations for the SEC-01 fix (CWE-645).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No limit or throttling on failed authentication attempts | Medium | CWE-307 | `UserAuthenticator.java:88` |
| SEC-02 | Residual timing difference allows account enumeration | Low | CWE-208 | `UserAuthenticator.java:159` |
| SEC-03 | Database connection does not enforce TLS | Low | CWE-319 | `UserAuthenticator.java:211` |
| SEC-04 | Password kept in immutable String when read from non-console stdin | Low | CWE-316 | `UserAuthenticator.java:271` |

## 5. Detailed Findings

### SEC-01: No limit or throttling on failed authentication attempts
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAuthenticator.java:88-108` (also the CLI flow at `UserAuthenticator.java:219-227`)

**Vulnerable code:**
```java
// UserAuthenticator.java:88-108
    public boolean authenticate(String email, char[] password) throws SQLException {
        try {
            String normalizedEmail = normalizeEmail(email);
            if (normalizedEmail == null || password == null
                    || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
                verifyPassword(password == null ? new char[0] : password, DUMMY_HASH);
                return false;
            }

            String storedHash = findPasswordHash(normalizedEmail);
            if (storedHash == null) {
                verifyPassword(password, DUMMY_HASH);
                return false;
            }
            return verifyPassword(password, storedHash);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }
```

**Why it is a problem:** `authenticate()` is a public method, meant to be called from other code (for example a login endpoint). It keeps no record of failed attempts per account or per source, adds no delay after a failure, and never locks an account. The CLI gives a clean yes/no signal through its exit code (0 or 1, lines 222-227), so a script can call it in a loop. An attacker who can reach any front end that uses this class can run unlimited password-guessing, credential-stuffing or password-spraying attacks (OWASP A07:2021 / API2:2023). PBKDF2 slows each guess only to about 0.2–1 s of CPU, and guesses can run in parallel. The README (`README.md:185-187`) admits the gap but leaves it to the integrator, and nothing in the code enforces it.

**Fix:** Keep a failed-attempt counter in the database (so it survives across processes and CLI runs). Track unknown emails as well, so lockout does not itself reveal which accounts exist. Refuse attempts while an account is temporarily locked, still doing the dummy work so timing stays uniform. Clear the counter on success. Keep lockouts short to limit lockout-based denial of service (CWE-645). Add per-source rate limiting in whatever network front end calls this class. Only the `login_attempts` table needs write access; `users` can stay read-only.
```java
// CREATE TABLE login_attempts (
//     email         VARCHAR(254) NOT NULL PRIMARY KEY,
//     failed_count  INT          NOT NULL,
//     locked_until  TIMESTAMP    NULL
// );
private static final int MAX_FAILED_ATTEMPTS = 5;
private static final Duration LOCKOUT = Duration.ofMinutes(15);

public boolean authenticate(String email, char[] password) throws SQLException {
    try {
        String normalizedEmail = normalizeEmail(email);
        if (normalizedEmail == null || password == null
                || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            verifyPassword(password == null ? new char[0] : password, DUMMY_HASH);
            return false;
        }

        try (Connection connection = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword)) {
            if (isLockedOut(connection, normalizedEmail)) {
                verifyPassword(password, DUMMY_HASH); // same work as a real check
                return false;
            }

            String storedHash = findPasswordHash(connection, normalizedEmail);
            boolean authenticated;
            if (storedHash == null) {
                verifyPassword(password, DUMMY_HASH);
                authenticated = false;
            } else {
                authenticated = verifyPassword(password, storedHash);
            }
            recordAttempt(connection, normalizedEmail, authenticated);
            return authenticated;
        }
    } finally {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}

private static boolean isLockedOut(Connection connection, String email) throws SQLException {
    try (PreparedStatement statement = connection.prepareStatement(
            "SELECT locked_until FROM login_attempts WHERE email = ?")) {
        statement.setString(1, email);
        try (ResultSet results = statement.executeQuery()) {
            if (!results.next()) {
                return false;
            }
            Timestamp lockedUntil = results.getTimestamp("locked_until");
            return lockedUntil != null && lockedUntil.toInstant().isAfter(Instant.now());
        }
    }
}

private static void recordAttempt(Connection connection, String email, boolean success)
        throws SQLException {
    if (success) {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM login_attempts WHERE email = ?")) {
            statement.setString(1, email);
            statement.executeUpdate();
        }
        return;
    }
    Timestamp lockUntil = Timestamp.from(Instant.now().plus(LOCKOUT));
    try (PreparedStatement update = connection.prepareStatement(
            "UPDATE login_attempts SET failed_count = failed_count + 1, "
            + "locked_until = CASE WHEN failed_count + 1 >= ? THEN ? ELSE locked_until END "
            + "WHERE email = ?")) {
        update.setInt(1, MAX_FAILED_ATTEMPTS);
        update.setTimestamp(2, lockUntil);
        update.setString(3, email);
        if (update.executeUpdate() == 0) {
            try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO login_attempts (email, failed_count, locked_until) VALUES (?, 1, NULL)")) {
                insert.setString(1, email);
                insert.executeUpdate();
            }
        }
    }
}
```

### SEC-02: Residual timing difference allows account enumeration
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `UserAuthenticator.java:159-175` (used from `UserAuthenticator.java:97-102`)

**Vulnerable code:**
```java
// UserAuthenticator.java:159-175
        String[] parts = storedHash.split("\\$");
        if (parts.length != 4 || !HASH_PREFIX.equals(parts[0])) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                return false;
            }
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] salt = decoder.decode(parts[2]);
            byte[] expected = decoder.decode(parts[3]);
            if (salt.length == 0 || expected.length == 0) {
                return false;
            }
            byte[] actual = pbkdf2(password, salt, iterations, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
```

**Why it is a problem:** The dummy-hash defence only works if an unknown email costs the same as a known one. Unknown emails always run 600,000 iterations (`DUMMY_HASH`, line 70). Known accounts run the iteration count stored in their own record, which may be anywhere from 10,000 to 10,000,000 (lines 57-58, 165). The README tells operators they can raise the count while old hashes keep working (`README.md:188-189`). So after any change there will be accounts whose failed logins are clearly faster (e.g. 100k iterations) or slower (e.g. 1.2M) than the unknown-email path. Accounts with malformed or unsupported hashes return almost instantly (lines 160-162, 165-167, 171-173). An attacker can time responses to tell registered emails from unregistered ones, which feeds SEC-01 and targeted phishing. The output length also comes from the stored record (`expected.length * 8`), so hashes of different lengths add more timing variation.

**Fix:** Do the same work whenever a stored hash is unusable. Upgrade old hashes to the current parameters on successful login. After migration, accept only the current iteration count and output length, so every path costs the same.
```java
// After all stored hashes have been migrated, accept only the current parameters.
private static final int MIN_ITERATIONS = ITERATIONS;
private static final int MAX_ITERATIONS = ITERATIONS;

static boolean verifyPassword(char[] password, String storedHash) {
    byte[][] saltAndHash = parse(storedHash);
    if (saltAndHash == null) {
        // Malformed or legacy record: do the same work as a normal check, then fail.
        byte[][] dummy = parse(DUMMY_HASH);
        MessageDigest.isEqual(dummy[1], pbkdf2(password, dummy[0], ITERATIONS, HASH_BITS));
        return false;
    }
    byte[] actual = pbkdf2(password, saltAndHash[0], ITERATIONS, HASH_BITS);
    return MessageDigest.isEqual(saltAndHash[1], actual);
}

/** Returns {salt, hash} only for hashes that use the current parameters, otherwise null. */
private static byte[][] parse(String storedHash) {
    if (storedHash == null) {
        return null;
    }
    String[] parts = storedHash.split("\\$");
    if (parts.length != 4 || !HASH_PREFIX.equals(parts[0])) {
        return null;
    }
    try {
        int iterations = Integer.parseInt(parts[1]);
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            return null;
        }
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] salt = decoder.decode(parts[2]);
        byte[] expected = decoder.decode(parts[3]);
        if (salt.length < SALT_BYTES || expected.length != HASH_BITS / 8) {
            return null;
        }
        return new byte[][] {salt, expected};
    } catch (IllegalArgumentException e) {
        return null;
    }
}
```

### SEC-03: Database connection does not enforce TLS
- **Severity:** Low
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `UserAuthenticator.java:211-217` (connection opened at `UserAuthenticator.java:112`; example URLs at `README.md:111`, `118`, `126`)

**Vulnerable code:**
```java
// UserAuthenticator.java:211-217
            String jdbcUrl = System.getenv("DB_URL");
            if (jdbcUrl == null || jdbcUrl.isBlank()) {
                System.err.println("Error: the DB_URL environment variable is not set.");
                return EXIT_ERROR;
            }
            UserAuthenticator authenticator = new UserAuthenticator(
                    jdbcUrl, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
```

**Why it is a problem:** Any `DB_URL` is accepted and passed straight to `DriverManager.getConnection`. Nothing requires an encrypted, certificate-checked link. Most JDBC drivers (PostgreSQL, MySQL, SQL Server in older versions) connect without TLS or without checking the certificate by default. The README's examples (`jdbc:postgresql://localhost:5432/myapp`) have no TLS settings, so copying them to a remote host sends data in cleartext. That data includes the `password_hash` for the user logging in and, for some auth methods, the database credentials. An attacker on the network can capture hashes for offline cracking, or tamper with the result (e.g. return a hash they know) and log in as anyone.

**Fix:** Refuse to start unless the JDBC URL turns on verified TLS, or the database is embedded or local. Offer an explicit opt-out for local testing only, and update the README examples to use TLS (e.g. `?sslmode=verify-full`).
```java
private static final String[] TLS_URL_MARKERS = {
        "sslmode=verify-full", "sslmode=verify-ca",            // PostgreSQL
        "sslmode=verify_identity", "sslmode=verify_ca",        // MySQL Connector/J
        "encrypt=true",                                        // SQL Server (with cert validation)
        "jdbc:h2:ssl:"                                         // H2 server over TLS
};

static boolean usesVerifiedTransport(String jdbcUrl) {
    String url = jdbcUrl.toLowerCase(Locale.ROOT);
    if (url.startsWith("jdbc:sqlite:")
            || (url.startsWith("jdbc:h2:") && !url.startsWith("jdbc:h2:tcp:"))) {
        return true; // embedded database, no network link
    }
    if (url.contains("trustservercertificate=true")) {
        return false;
    }
    for (String marker : TLS_URL_MARKERS) {
        if (url.contains(marker)) {
            return true;
        }
    }
    return false;
}

// in run():
            String jdbcUrl = System.getenv("DB_URL");
            if (jdbcUrl == null || jdbcUrl.isBlank()) {
                System.err.println("Error: the DB_URL environment variable is not set.");
                return EXIT_ERROR;
            }
            if (!usesVerifiedTransport(jdbcUrl)
                    && !"true".equalsIgnoreCase(System.getenv("DB_ALLOW_PLAINTEXT"))) {
                System.err.println("Error: DB_URL must enable verified TLS "
                        + "(set DB_ALLOW_PLAINTEXT=true only for local testing).");
                return EXIT_ERROR;
            }
            UserAuthenticator authenticator = new UserAuthenticator(
                    jdbcUrl, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
```

### SEC-04: Password kept in immutable String when read from non-console stdin
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserAuthenticator.java:271-272` (method `readSecret`, `UserAuthenticator.java:265-273`)

**Vulnerable code:**
```java
// UserAuthenticator.java:265-273
    private static char[] readSecret(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword("%s", prompt);
            return secret == null ? new char[0] : secret;
        }
        String line = stdinReader().readLine();
        return line == null ? new char[0] : line.toCharArray();
    }
```

**Why it is a problem:** The class docs (`UserAuthenticator.java:32`) and the README (`README.md:48`) promise that passwords are "wiped from memory after use". That holds only for the console path. When stdin is redirected (scripts, pipes, CI, `--hash` run from a pipe), the password is read into a `String`. `Arrays.fill` on the copied `char[]` (lines 105, 248) cannot clear it. It stays on the heap until garbage collection overwrites it, and can show up in heap dumps, core dumps, swap or memory-scraping tools. The security guarantee the code claims is not actually met on this path.

**Fix:** Read the non-console password straight into a `char[]` without creating a `String`, cap its length, and wipe the scratch buffer. (The reader's internal buffer can still hold the characters briefly. Prefer an attached console for interactive use, and tell automated callers to pass secrets through a file descriptor rather than arguments.)
```java
    private static char[] readSecret(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword("%s", prompt);
            return secret == null ? new char[0] : secret;
        }
        BufferedReader reader = stdinReader();
        char[] buffer = new char[MAX_PASSWORD_LENGTH + 1];
        int length = 0;
        boolean tooLong = false;
        try {
            int c;
            while ((c = reader.read()) != -1 && c != '\n') {
                if (length < buffer.length) {
                    buffer[length++] = (char) c;
                } else {
                    tooLong = true; // keep draining the line, but do not store more
                }
            }
            if (!tooLong && length > 0 && buffer[length - 1] == '\r') {
                length--;
            }
            if (tooLong) {
                return new char[MAX_PASSWORD_LENGTH + 1]; // rejected by the length check
            }
            return Arrays.copyOf(buffer, length);
        } finally {
            Arrays.fill(buffer, '\0');
        }
    }
```

## 6. Verified Controls and Checks With No Finding
- SQL injection (CWE-89): The only SQL text is the constant `SELECT password_hash FROM users WHERE email = ?` (`UserAuthenticator.java:49-50`). It runs through `connection.prepareStatement(QUERY)` with `statement.setString(1, email)` (`UserAuthenticator.java:113-115`). No string concatenation, dynamic identifiers, `ORDER BY`/`LIKE` building, stored procedures or `Statement.execute` appear anywhere in the file. The password never goes into SQL.
- Second-order SQL injection: The only value read back from the database, `password_hash` (`UserAuthenticator.java:118`), is parsed in Java (`UserAuthenticator.java:159-170`) and never used in another query.
- Password storage algorithm (CWE-916/CWE-328): PBKDF2WithHmacSHA256 with 600,000 iterations and 256-bit output (`UserAuthenticator.java:52-56`, `145-152`) meets current OWASP Password Storage guidance. No MD5, SHA-1, unsalted hashing or reversible encryption is used.
- Salt and randomness (CWE-330/CWE-759/CWE-760): Each hash gets a 16-byte salt from `java.security.SecureRandom` (`UserAuthenticator.java:55`, `67`, `146-147`). There is no `java.util.Random` and no seeding from time.
- Hash comparison (CWE-208 in the compare step): `MessageDigest.isEqual` does a constant-time comparison (`UserAuthenticator.java:175`).
- Account enumeration through messages (CWE-204): Every failure prints the same text, `Authentication failed: invalid email address or password.` (`UserAuthenticator.java:226`). Unknown emails and invalid input still run a dummy PBKDF2 check (`UserAuthenticator.java:70`, `93`, `99`). The residual timing issue is covered in SEC-02.
- Hardcoded credentials (CWE-798/CWE-259): There are no database credentials, keys or passwords in source. `DB_URL`, `DB_USER` and `DB_PASSWORD` come from the environment (`UserAuthenticator.java:211-217`). The literal `"dummy-password"` (`UserAuthenticator.java:70`) is not a credential: it is hashed with a random salt per process and only used to equalise timing.
- Password not accepted on the command line (CWE-214): Only the email can be passed as an argument. More than one argument, or unknown flags, are rejected (`UserAuthenticator.java:205-209`, `219`), and the password is always read interactively (`UserAuthenticator.java:220`).
- No echo on terminal input (CWE-549): `Console.readPassword` is used when a console exists (`UserAuthenticator.java:268`).
- Clearing secrets in memory (CWE-226): The password array is zeroed in `finally` blocks (`UserAuthenticator.java:103-106`, `247-249`), and `PBEKeySpec.clearPassword()` is called (`UserAuthenticator.java:187-189`). The exception on the non-console path is SEC-04.
- Error handling and information leakage (CWE-209/CWE-200): `SQLException`, `IOException` and `RuntimeException` are caught and replaced by generic messages with no stack trace or driver details (`UserAuthenticator.java:228-235`). Database or hashing errors fail closed (exit code 2, never "successful").
- Input validation and resource bounds (CWE-20/CWE-400): Emails are trimmed, lower-cased with `Locale.ROOT`, limited to 254 characters, and rejected if they contain control or whitespace characters or do not have exactly one `@` (`UserAuthenticator.java:124-142`). Passwords must be 1–1024 characters (`UserAuthenticator.java:91-92`, `241`). HMAC pre-hashes long keys, so long passwords do not multiply PBKDF2 cost.
- Parsing stored hashes safely (CWE-400/CWE-248): Iteration counts are bounded to 10,000–10,000,000 (`UserAuthenticator.java:57-58`, `165`). Malformed Base64 or numbers are caught as `IllegalArgumentException`, which also covers `NumberFormatException` (`UserAuthenticator.java:176-178`). Empty salt or hash values are rejected (`UserAuthenticator.java:171-173`). A corrupt record cannot crash the program or authenticate an empty password.
- Email canonicalisation and collation: Lookup uses the normalised address with `setMaxRows(1)` against a primary key (`UserAuthenticator.java:116`). Even if a case- or accent-insensitive collation matched another row, the password is still checked against that row's hash, so no authentication bypass is possible.
- JDBC URL trust: `DB_URL` comes from the operator-controlled environment, not user input. Driver-specific URL attacks (e.g. H2 `INIT=RUNSCRIPT`, MySQL `autoDeserialize`) would need control of the environment and are out of the threat model. Transport security of that URL is covered in SEC-03.
- Deserialization, OS command execution, file/path handling, XML parsing, XSS, SSRF, JWT/session tokens: None of these appear in the code. The only I/O is stdin/stdout/stderr and a single JDBC connection.
- Least privilege: The README advises a read-only database account for the `users` table (`README.md:181-182`), which fits the code (it only runs `SELECT`).
- Non-code files (`prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`): Checked; they hold prompts and run metadata only, with no executable code or secrets.
