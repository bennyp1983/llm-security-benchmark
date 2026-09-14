# Security Review: UserRegistration (JDBC user registration and password authentication)

## 1. Executive Summary
`UserRegistration.java` is a single Java class that creates a `users` table, registers accounts (username + password) and authenticates them later over any JDBC `Connection`. Its core password storage is strong. It uses PBKDF2-HMAC-SHA256 with 600,000 iterations, a 16-byte `SecureRandom` salt and a self-describing hash format that is upgraded on login. Hash comparison is constant-time, a dummy hash hides unknown users, and every SQL statement is parameterised. No Critical or High issues were found.

The most important findings are:
- **SEC-01 (Medium):** `authenticate` has no brute-force protection. Each guess also forces a 600,000-iteration PBKDF2 run, so unlimited online guessing and CPU exhaustion are both possible.
- **SEC-02 (Medium):** when no console is attached, `main` falls back to a scripted demo. That demo silently creates the account `alice` with a hard-coded, publicly documented password in whatever database the JDBC URL points to.
- **Low findings:** the registration error message reveals which usernames exist, the demo prints a stored password hash, the database password is passed on the command line, there is no breached-password check, and the JDK PBKDF2 key object keeps an un-destroyed copy of the password.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserRegistration.java` | Registers and authenticates users against an SQL `users` table; includes a `main` demo (interactive or scripted) | SQL statement construction (DDL, INSERT, SELECT, UPDATE); PBKDF2 password hashing, salt generation, hash parsing and constant-time comparison; username/password input validation; user-enumeration defences; wiping passwords from memory; database credentials from command-line arguments; hard-coded demo credentials; printing a stored hash to stdout |
| `README.md` | Documentation of the API, hash format, compile and run instructions | Documents passing the DB password as a CLI argument (line 95) and publishes the demo output, including that the scripted demo runs with sample credentials (lines 100-114); recommends rate limiting and TLS as production notes (lines 122-129) |
| `prompt.txt` | Original task text used to generate the code (not code) | None |
| `cyber_prompt.txt` | Text of this review task (not code) | None |
| `result.md` | Metadata and summary from the code-generation run (not code) | None |
| `return.txt` | JSON run metadata from the code-generation run (not code) | None |
| `prompt_hash.txt` | Empty file (not code) | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: router workflow. It inventoried the files, extracted security keywords (cryptography/KDF, password storage, SQL, authentication, enumeration, secrets, sensitive data exposure, rate limiting) and selected the skills below.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher` (algorithm, iterations, salt size and entropy source, derived key length, constant-time comparison, stored-format parsing) and to the check for hard-coded passwords/keys (demo credentials, SEC-02). Weak-KDF and weak-algorithm checks found no issue.
- `testing-api-authentication-weaknesses`: applied to `register`/`authenticate` for weak password policy (SEC-06), credential-stuffing susceptibility (SEC-01) and account enumeration via responses and timing (SEC-03; login path verified clean). The JWT, session and token checks do not apply because the code issues no tokens.
- `implementing-api-rate-limiting-and-throttling`: applied to the authentication path to check for brute-force, credential-stuffing and resource-exhaustion controls (SEC-01).
- `testing-for-sensitive-data-exposure`: applied to output, error messages and credential handling. It covered password hashes in output (SEC-04), revealing messages on duplicate registration (SEC-03), credentials in process arguments (SEC-05) and data in transit (the JDBC URL is caller-supplied).
- `exploiting-sql-injection-vulnerabilities`: its injection-point and second-order criteria were applied to every SQL statement and to how a stored username is reused. No finding.
- `implementing-secret-scanning-with-gitleaks`: its hard-coded secret criteria were applied to the source (API keys, DB connection strings, passwords). Only the demo password was found (SEC-02).
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): clearing sensitive data from memory (CWE-316/CWE-226, SEC-07), Unicode username canonicalisation, format-string use in `Console.printf`, and exception/error-message information leakage.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No brute-force protection or work limit on `authenticate` | Medium | CWE-307 | `UserRegistration.java:133` |
| SEC-02 | Scripted demo runs automatically and creates an account with a hard-coded password | Medium | CWE-798 | `UserRegistration.java:391` |
| SEC-03 | Registration error message reveals which usernames exist | Low | CWE-204 | `UserRegistration.java:118` |
| SEC-04 | Demo prints the stored password hash to stdout | Low | CWE-532 | `UserRegistration.java:407` |
| SEC-05 | Database password accepted as a command-line argument | Low | CWE-214 | `UserRegistration.java:347` |
| SEC-06 | Password policy does not reject common or breached passwords | Low | CWE-521 | `UserRegistration.java:181` |
| SEC-07 | PBKDF2 `SecretKey` holding a copy of the password is never destroyed | Low | CWE-316 | `UserRegistration.java:287` |

## 5. Detailed Findings

### SEC-01: No brute-force protection or work limit on `authenticate`
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserRegistration.java:133-171`

**Vulnerable code:**
```java
// UserRegistration.java:133-158
    public boolean authenticate(String username, char[] password) throws SQLException {
        try {
            if (username == null || password == null || password.length > MAX_PASSWORD_LENGTH) {
                return false;
            }
            String normalized = normalizeUsername(username);

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
                // Unknown user: do equivalent work so response time does not reveal it.
                PasswordHasher.verify(password, PasswordHasher.DUMMY_HASH);
                return false;
            }

            if (!PasswordHasher.verify(password, storedHash)) {
                return false;
            }
```

**Why it is a problem:** `authenticate` is the only authentication entry point, and it has no failed-attempt counter, delay, lockout or hook for one. Any caller that exposes it (a web login, an API, an RMI service) inherits unlimited online password guessing, credential stuffing and password spraying. The 12-character minimum does not stop users choosing known-breached passwords (see SEC-06). Each call also runs a 600,000-iteration PBKDF2 computation, even for unknown usernames by design. A modest number of concurrent unauthenticated requests can therefore tie up every CPU core (CWE-400 / CWE-770), a server-side denial of service. The README notes rate limiting only as optional advice (README.md:122-123); the library itself does not enforce it.

**Fix:** Make throttling part of the API so callers cannot forget it. Check a throttle before any database or hashing work, and record failures for unknown and known usernames alike so the throttle does not itself reveal which accounts exist. Also cap concurrent hash computations (for example with a `Semaphore` sized to the CPU count) and add per-IP limits at the transport layer.
```java
/** Pluggable login throttle (e.g. per-username + per-IP sliding window, backed by Redis or a DB table). */
public interface LoginThrottle {
    /** @return false if this attempt must be rejected without checking the password */
    boolean tryAcquire(String normalizedUsername);
    void onFailure(String normalizedUsername);
    void onSuccess(String normalizedUsername);
}

private final LoginThrottle throttle;
// Bounds CPU spent on PBKDF2 so a login flood cannot starve the host.
private static final Semaphore HASH_PERMITS =
        new Semaphore(Runtime.getRuntime().availableProcessors());

public UserRegistration(Connection connection, LoginThrottle throttle) {
    this.connection = Objects.requireNonNull(connection, "connection");
    this.throttle = Objects.requireNonNull(throttle, "throttle");
}

public boolean authenticate(String username, char[] password) throws SQLException {
    try {
        if (username == null || password == null || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        String normalized = normalizeUsername(username);
        if (!throttle.tryAcquire(normalized)) {
            return false; // or throw a TooManyAttemptsException so the caller can return HTTP 429
        }

        String storedHash = null;
        try (PreparedStatement ps = connection.prepareStatement(SELECT_HASH_SQL)) {
            ps.setString(1, normalized);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    storedHash = rs.getString(1);
                }
            }
        }

        boolean ok;
        if (!HASH_PERMITS.tryAcquire()) {
            return false; // server busy: fail closed
        }
        try {
            if (storedHash == null) {
                // Unknown user: do equivalent work so response time does not reveal it.
                PasswordHasher.verify(password, PasswordHasher.DUMMY_HASH);
                ok = false;
            } else {
                ok = PasswordHasher.verify(password, storedHash);
            }
        } finally {
            HASH_PERMITS.release();
        }

        if (!ok) {
            throttle.onFailure(normalized); // same for unknown and known users
            return false;
        }
        throttle.onSuccess(normalized);

        if (PasswordHasher.needsRehash(storedHash)) {
            try (PreparedStatement ps = connection.prepareStatement(UPDATE_HASH_SQL)) {
                ps.setString(1, PasswordHasher.hash(password));
                ps.setString(2, normalized);
                ps.executeUpdate();
            }
        }
        return true;
    } finally {
        wipe(password);
    }
}
```

### SEC-02: Scripted demo runs automatically and creates an account with a hard-coded password
- **Severity:** Medium
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `UserRegistration.java:353-358, 387-396`

**Vulnerable code:**
```java
// UserRegistration.java:387-396
    private static void runScripted(UserRegistration users) throws SQLException {
        System.out.println("No console detected; running scripted demo with sample credentials.");
        // Sample values for demonstration only. Real code must obtain passwords from the user.
        String user = "alice";
        String pw = "correct horse battery staple";

        tryRegister(users, user, pw.toCharArray());
        tryRegister(users, user, "another long password".toCharArray()); // duplicate
        tryRegister(users, "bob", "short".toCharArray());                  // weak password
        tryRegister(users, "x'; DROP TABLE users; --", "irrelevant-password".toCharArray()); // rejected username
```

**Why it is a problem:** `main` picks the scripted demo whenever `System.console()` returns `null` (lines 353-358). That happens whenever stdin/stdout is not a terminal: `docker run` without `-t`, CI jobs, cron, systemd units, `nohup`, or piped output. `main` accepts any JDBC URL, including production PostgreSQL/MySQL (README.md:95). A tool meant to register one user can therefore insert a working account `alice` with the hard-coded password `correct horse battery staple` into a real `users` table, with nothing to confirm it. The password is published in the source and the README, and it is also a widely known phrase that appears in public password wordlists. An attacker can log in as `alice` to any application using that table (a default-credential backdoor).

**Fix:** Never fall back silently to writing demo data. Require an explicit opt-in, restrict the demo to a throwaway in-memory database, and generate a random demo password instead of hard-coding one.
```java
Console console = System.console();
if (console != null) {
    runInteractive(console, users);
} else if (Boolean.getBoolean("userregistration.demo") && url.startsWith("jdbc:h2:mem:")) {
    runScripted(users); // opt-in only, and only against a throwaway in-memory database
} else {
    System.err.println("No interactive console. Refusing to modify the database. "
            + "Run the demo with -Duserregistration.demo=true and a jdbc:h2:mem: URL.");
    System.exit(2);
}

// in runScripted: no hard-coded password
byte[] rnd = new byte[18];
new SecureRandom().nextBytes(rnd);
char[] pw = Base64.getEncoder().withoutPadding().encodeToString(rnd).toCharArray();
```

### SEC-03: Registration error message reveals which usernames exist
- **Severity:** Low
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `UserRegistration.java:116-121`

**Vulnerable code:**
```java
// UserRegistration.java:116-121
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    throw new RegistrationException("Username is already taken.");
                }
                throw e;
            }
```

**Why it is a problem:** The login path deliberately hides whether an account exists (uniform `false`, dummy hash). The registration path undoes that: the README tells callers to show `e.getMessage()` to the user (README.md:66-67), so anyone can call `register` with a candidate name and a valid password and get "Username is already taken." for every existing account. That lets an attacker build a list of valid usernames to feed into credential stuffing or password spraying against `authenticate` (made worse by SEC-01). Registration has no rate limit either.

**Fix:** Return a generic outcome for duplicates and rate-limit registration. If the product needs to tell a user a name is taken (common for public handles), accept that trade-off deliberately and make sure the login throttle (SEC-01) is in place. For email-based identities, respond identically and send the "account already exists" notice out-of-band.
```java
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    // Same message as other rejections; do not confirm that the account exists.
                    throw new RegistrationException("Registration could not be completed. "
                            + "Try a different username or sign in if you already have an account.");
                }
                throw e;
            }
```

### SEC-04: Demo prints the stored password hash to stdout
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `UserRegistration.java:403-410`

**Vulnerable code:**
```java
// UserRegistration.java:403-410
        try (PreparedStatement ps = users.connection.prepareStatement(SELECT_HASH_SQL)) {
            ps.setString(1, user);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    System.out.println("stored value for alice: " + rs.getString(1));
                }
            }
        }
```

**Why it is a problem:** The scripted path only runs when there is no console, which is exactly when stdout is being captured by container logs, CI logs, journald or a redirect file. The full `pbkdf2-sha256$iterations$salt$hash` value is written there. Anyone with log access gets the salt and derived key and can try to crack the password offline, without touching the database. Combined with SEC-02, the value corresponds to a real account in whatever database was targeted.

**Fix:** Do not print secret material. Show only the non-secret parameters (algorithm and iteration count) to demonstrate the format.
```java
        try (PreparedStatement ps = users.connection.prepareStatement(SELECT_HASH_SQL)) {
            ps.setString(1, user);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String[] parts = rs.getString(1).split("\\$");
                    System.out.println("stored format for alice: " + parts[0] + "$" + parts[1]
                            + "$<salt redacted>$<hash redacted>");
                }
            }
        }
```

### SEC-05: Database password accepted as a command-line argument
- **Severity:** Low
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `UserRegistration.java:345-349` (documented usage at `README.md:95`)

**Vulnerable code:**
```java
// UserRegistration.java:345-349
        String url = args[0];
        String dbUser = args.length > 1 ? args[1] : null;
        String dbPass = args.length > 2 ? args[2] : null;

        try (Connection conn = DriverManager.getConnection(url, dbUser, dbPass)) {
```

**Why it is a problem:** Command-line arguments are visible to other local users and processes (`ps aux`, `/proc/<pid>/cmdline`). They are also saved in shell history and often recorded by process-auditing, CI and orchestration logs. The README tells operators to run `... UserRegistration jdbc:postgresql://localhost/app dbuser dbpass`, which exposes the database password that guards the whole `users` table.

**Fix:** Take the database password from an environment variable or secret file, or prompt for it without echo. Reject a password given as a positional argument.
```java
        String url = args[0];
        String dbUser = args.length > 1 ? args[1] : System.getenv("DB_USER");
        if (args.length > 2) {
            System.err.println("Do not pass the database password on the command line; set DB_PASSWORD instead.");
            System.exit(2);
        }
        String dbPass = System.getenv("DB_PASSWORD");
        if (dbPass == null && dbUser != null && System.console() != null) {
            char[] entered = System.console().readPassword("Database password: ");
            dbPass = entered == null ? null : new String(entered);
            wipe(entered);
        }

        try (Connection conn = DriverManager.getConnection(url, dbUser, dbPass)) {
```

### SEC-06: Password policy does not reject common or breached passwords
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserRegistration.java:181-190`

**Vulnerable code:**
```java
// UserRegistration.java:181-190
    private static void validatePassword(char[] password) throws RegistrationException {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new RegistrationException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new RegistrationException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
    }
```

**Why it is a problem:** Length is the only rule. NIST SP 800-63B requires checking new passwords against known-compromised, dictionary and context-specific values. Twelve-character passwords such as `password1234`, `qwertyuiop12`, or the demo's own `correct horse battery staple` are accepted, and all of them appear in public breach and wordlist corpora. Slow hashing does not help against online guessing (SEC-01) or against cracking of passwords at the top of a wordlist. Also, `password.length` counts UTF-16 code units, not characters, so a password made of astral-plane characters (emoji, some CJK) can pass the 12-character minimum with only 6 real characters.

**Fix:** Check new passwords against a breached-password blocklist (for example a local SHA-256 set built from a Have I Been Pwned or SecLists export, or the HIBP k-anonymity API). Also reject passwords equal to or containing the username, and count code points rather than UTF-16 units.
```java
    private final Set<String> blockedPasswordSha256Hex; // loaded at startup from a breached-password list

    private void validatePassword(String normalizedUsername, char[] password) throws RegistrationException {
        if (password == null) {
            throw new RegistrationException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        int codePoints = Character.codePointCount(password, 0, password.length);
        if (codePoints < MIN_PASSWORD_LENGTH) {
            throw new RegistrationException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new RegistrationException("Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
        if (new String(password).toLowerCase(Locale.ROOT).contains(normalizedUsername)
                || blockedPasswordSha256Hex.contains(sha256Hex(password))) {
            throw new RegistrationException("This password is too common or has appeared in a data breach. Choose another.");
        }
    }

    private static String sha256Hex(char[] password) {
        ByteBuffer buf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] data = new byte[buf.remaining()];
        buf.get(data);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        } finally {
            Arrays.fill(data, (byte) 0);
            if (buf.hasArray()) {
                Arrays.fill(buf.array(), (byte) 0);
            }
        }
    }
```

### SEC-07: PBKDF2 `SecretKey` holding a copy of the password is never destroyed
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserRegistration.java:284-293`

**Vulnerable code:**
```java
// UserRegistration.java:284-293
        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
            try {
                return SecretKeyFactory.getInstance(JCA_ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("PBKDF2 is unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }
```

**Why it is a problem:** The class promises that "Plaintext passwords are never stored ... and wiped from memory after use" (lines 29-30; README.md:41-43). It clears the caller's array and the `PBEKeySpec` copy. However, the `SecretKey` returned by `generateSecret` (SunJCE's PBKDF2 key implementation) keeps its own copy of the password characters and of the derived key. That object is discarded without `destroy()`, so the plaintext password stays on the heap until garbage collection, where it can end up in heap dumps, core files or swap. The impact is limited (it needs memory access), but it undermines a security property the code explicitly claims.

**Fix:** Keep a reference to the key and destroy it in `finally`. Providers that do not support `destroy()` throw `DestroyFailedException`; in current OpenJDK the key's internal copies are then cleared when the object is garbage-collected. Where heap dumps are a concern, also disable them in production (`-XX:-HeapDumpOnOutOfMemoryError`, restricted core dumps).
```java
        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
            SecretKey key = null;
            try {
                key = SecretKeyFactory.getInstance(JCA_ALGORITHM).generateSecret(spec);
                return key.getEncoded(); // returns a fresh copy; callers already zero it
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("PBKDF2 is unavailable", e);
            } finally {
                spec.clearPassword();
                if (key != null && !key.isDestroyed()) {
                    try {
                        key.destroy();
                    } catch (DestroyFailedException ignored) {
                        // Provider does not support destroy(); its internal copy is cleared on GC.
                    }
                }
            }
        }
```

## 6. Verified Controls and Checks With No Finding
- SQL injection (first-order): all data-bearing statements use `PreparedStatement` bind parameters: `INSERT_USER_SQL`/`SELECT_HASH_SQL`/`UPDATE_HASH_SQL` defined at `UserRegistration.java:70-75`, bound at lines 111-115, 141-148, 161-165 and 403-404. The only `Statement` executes the constant DDL `CREATE_TABLE_SQL` (lines 64-69, 89-91), with no user input.
- SQL injection (second-order): the stored username is only ever reused as a bind parameter (line 163), never concatenated into SQL. The demo input `x'; DROP TABLE users; --` (line 396) is rejected by the username regex before reaching the database.
- Password hashing algorithm and work factor: PBKDF2WithHmacSHA256, 600,000 iterations, 256-bit output (lines 221-225, 252). This meets the OWASP Password Storage Cheat Sheet minimum for PBKDF2-HMAC-SHA256. No MD5, SHA-1, DES, RC4, ECB or unsalted hashing is used anywhere.
- Salt and randomness: a unique 16-byte salt per hash from a single `SecureRandom` instance (lines 224, 230, 250-251). No `java.util.Random` or time-based seeds.
- Constant-time verification: `MessageDigest.isEqual` compares the derived key (line 269). The derived key length is taken from the stored hash, so there is no truncation mismatch (line 267).
- Stored-hash parsing robustness: `ParsedHash.parse` requires exactly 4 fields and the expected algorithm ID, bounds iterations to 10,000–10,000,000, rejects empty salt/hash, and catches `NumberFormatException`/Base64 errors (lines 306-326). A tampered or corrupt DB value cannot cause an exception or an unbounded work factor.
- Hash upgrade: `needsRehash` upgrades weaker iterations/salt/key size after a successful login (lines 160-166, 276-282), so legacy parameters do not persist.
- Login-path user enumeration: unknown users trigger a full PBKDF2 run against `DUMMY_HASH`, which uses the current iteration count (lines 150-153, 235-243). Unknown users and wrong passwords both return a plain `false` (lines 153, 157). Over-long passwords are rejected before the lookup, independently of whether the user exists (line 135). The interactive demo prints the same "Invalid username or password." message (lines 383-384).
- Registration timing: the password is hashed before the INSERT (line 109), so duplicate and new usernames take about the same time. Only the message differs (SEC-03).
- Input validation: usernames are trimmed, lower-cased with `Locale.ROOT` and must match `^[a-z0-9._-]{3,64}$` after normalisation (lines 59, 102-103, 177-179). The regex is checked after case-folding, so Unicode case-mapping tricks (e.g. U+212A KELVIN SIGN → `k`) cannot create visually confusable distinct accounts. Normalisation is identical in `register` and `authenticate`. Passwords are capped at 256 chars in both paths to prevent hashing DoS from very long inputs (lines 62, 135, 186).
- Duplicate-account race: uniqueness is enforced by the `PRIMARY KEY` constraint (line 66) and handled on insert (lines 116-119), not by a check-then-insert (no TOCTOU).
- Password memory hygiene (caller-facing): both public methods wipe the caller's `char[]` in `finally` (lines 122-124, 168-170). Derived keys are zeroed (lines 257, 271), `PBEKeySpec.clearPassword()` is called (line 291), and the interactive demo wipes password/confirm arrays (lines 376-379). The remaining gap is SEC-07.
- No secrets in logs or exceptions: all `RegistrationException` messages are constant strings with no user input or password (lines 104-105, 118, 183-184, 187-188). `PBKDF2` failures wrap only the JCA exception (line 289).
- Console handling: passwords are read with `Console.readPassword` (no echo) at lines 364-365 and 382. All `console.printf` format strings are constants, and user-controlled text is only passed as a `%s` argument (lines 368, 372, 374, 383-384), so there is no format-string injection (CWE-134).
- Hard-coded infrastructure secrets: no hard-coded JDBC URLs, database credentials, API keys or private keys in the source. Credentials come from runtime arguments (see SEC-05); the only hard-coded password is the demo credential (SEC-02).
- Out-of-scope attack surface: no deserialization, XML parsing, file/path access, OS command execution, reflection or outbound network calls other than the caller-supplied JDBC connection.
- Data in transit: TLS for the database connection depends on the caller-supplied JDBC URL/driver settings and is not controlled by this class; the README advises using TLS (README.md:128-129). No insecure transport is configured in code, so there is no finding.
- Resource handling: all `Statement`, `PreparedStatement`, `ResultSet` and the demo `Connection` use try-with-resources (lines 89, 111, 141, 143, 161, 349, 403, 405), so there are no leaked cursors or connections.
