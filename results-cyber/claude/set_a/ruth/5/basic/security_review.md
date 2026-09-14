# Security Review: LoginSystem (Java user login handler)

## 1. Executive Summary
`LoginSystem.java` is a self-contained Java login component with no dependencies outside the JDK. It registers users with salted PBKDF2-HMAC-SHA256 hashes and checks login attempts, comparing hashes in constant time. It returns one generic failure result, runs a dummy hash for unknown usernames and locks an account for 15 minutes after 5 failed attempts in a row. It also has an interactive command-line demo and a `--self-test` mode.

The core cryptography is sound: a KDF rather than a fast hash, a random per-user salt from `SecureRandom`, constant-time comparison, fail-closed exceptions and wiping of passwords from memory. No Critical or High issues were found. The main weaknesses are in the **account lockout design**:
- **Password spraying and slow brute force are still possible.** Protection exists only per account and resets after each lock, and there is no limit per client or source (SEC-01).
- **Anyone can lock out any user.** An attacker who knows a username can lock that account indefinitely without logging in (SEC-02).
- **Lockout reveals which usernames exist.** A locked account returns a distinct `ACCOUNT_LOCKED` result and skips the hash, so its response is faster. This undoes the code's own user-enumeration protection (SEC-03).

The Low findings are:
- A password policy that only checks length.
- A PBKDF2 iteration count below current OWASP guidance for SHA-256.
- Lockout state that cannot be saved through the repository interface, so it fails silently with a database or clustered deployment.
- A hard-coded demo password that is printed to the console.
- A fallback that echoes the password when no console is available.
- No Unicode normalization of usernames, so look-alike account names are possible.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginSystem.java` | Complete login implementation: `PasswordHasher`, `Account`, `AccountRepository` / `InMemoryAccountRepository`, `registerUser`, `login`, the CLI demo `main` and `selfTest` | Password hashing (PBKDF2, salt, `SecureRandom`), constant-time comparison, authentication decisions, user-enumeration countermeasures, brute-force lockout and its concurrency, input length limits, username normalization, wiping passwords from memory, reading passwords from the console, a hard-coded demo credential |
| `README.md` | Documentation: design, compile/run instructions and integration notes | Documents the demo credential `alice` / `CorrectHorse42!` and makes security claims (no enumeration, brute-force protection) that were checked against the code |
| `prompt.txt`, `cyber_prompt.txt` | Task prompts used to generate the code and this review | None (plain text, not executed) |
| `result.md`, `return.txt`, `prompt_hash.txt` | Metadata from the code-generation run (JSON/Markdown; `prompt_hash.txt` is empty) | None (no code and no secrets; only session and usage metadata) |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. I read all the files, listed their security-relevant behaviours, searched the skill library by name and picked the skills below.
- `testing-api-authentication-weaknesses`: Applied to `login()` / `registerUser()`: account enumeration through different responses and timing, brute-force and credential-stuffing exposure, and password policy strength (SEC-01, SEC-03, SEC-04).
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher`: hashing algorithm, KDF parameters, salt size and source, RNG, hard-coded keys, and comparison method (SEC-05; the other checks passed, see section 6).
- `exploiting-race-condition-vulnerabilities`: Applied to the failed-attempt counter and lockout (limit overrun / TOCTOU), duplicate-registration races, and the skill's remediation guidance (atomic database updates, distributed locks) (SEC-06).
- `implementing-secret-scanning-with-gitleaks`: Applied to hard-coded passwords in `LoginSystem.java` and `README.md` (SEC-07).
- `testing-for-sensitive-data-exposure`: Applied to how passwords are shown on the console, printed to stdout and kept in memory (SEC-07, SEC-08).
- General OWASP Top 10 (A07:2021 Identification and Authentication Failures) and CWE knowledge, because no library skill specifically covers these behaviours:
  - Lockout-based denial of service (SEC-02).
  - Unicode canonicalization of usernames and homoglyphs (SEC-09).
  - Confirming there is no injection, deserialization, file, OS command, network or TLS code (A03, A08, A10).
- `hunting-credential-stuffing-attacks` was considered but not applied because it covers log-based detection, not source code review.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Brute-force protection allows password spraying and unlimited slow guessing | Medium | CWE-307 | `LoginSystem.java:198-220` |
| SEC-02 | Any unauthenticated party can lock any account (lockout denial of service) | Medium | CWE-645 | `LoginSystem.java:205-220` |
| SEC-03 | `ACCOUNT_LOCKED` result and faster response reveal which usernames exist | Medium | CWE-204 | `LoginSystem.java:205-211` |
| SEC-04 | Password policy only checks length (no common or breached password check) | Low | CWE-521 | `LoginSystem.java:175` |
| SEC-05 | PBKDF2-HMAC-SHA256 iteration count below OWASP guidance and not stored per hash | Low | CWE-916 | `LoginSystem.java:60` |
| SEC-06 | Lockout state cannot be saved through the repository; race-prone outside a single JVM | Low | CWE-362 | `LoginSystem.java:113-118` |
| SEC-07 | Hard-coded demo credential printed to stdout and documented in README | Low | CWE-798 | `LoginSystem.java:260-261` |
| SEC-08 | Password echoed and read into an immutable `String` when no console is available | Low | CWE-549 | `LoginSystem.java:278-287` |
| SEC-09 | Usernames are not Unicode-normalized or restricted, so look-alike accounts can be registered | Low | CWE-1007 | `LoginSystem.java:229-238` |

## 5. Detailed Findings

### SEC-01: Brute-force protection allows password spraying and unlimited slow guessing
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginSystem.java:198-203`, `LoginSystem.java:216-220`

**Vulnerable code:**
```java
// LoginSystem.java:198-203
            if (account == null || !passwordValid) {
                // Burn the same CPU time as a real check so the response time
                // does not reveal whether the username exists.
                hasher.verify(passwordValid ? password : new char[] {'x'}, dummySalt, dummyHash);
                return LoginResult.INVALID_CREDENTIALS;
            }
// LoginSystem.java:216-220
                account.failedAttempts++;
                if (account.failedAttempts >= MAX_FAILED_ATTEMPTS) {
                    account.failedAttempts = 0;
                    account.lockedUntil = now.plus(LOCKOUT_DURATION);
                }
```

**Why it is a problem:** The only limit is a counter on each account, and it has three gaps:
- **The counter resets when the lock is applied** (line 218). After each 15-minute lock, an attacker gets another 5 guesses, which is about 480 guesses per account per day forever. The penalty never increases and nothing raises an alert.
- **Nothing limits a client or source address.** An attacker can spray 4 common passwords across every known username every 15 minutes without ever triggering a lock. With the length-only password policy (SEC-04), this is a realistic way to take over accounts.
- **Unknown usernames are never limited.** Each attempt still costs a full 210,000-iteration PBKDF2 computation (line 201), so a flood of requests can also exhaust the CPU (CWE-400).

The README's claim that lockout "blocks brute-force guessing" is therefore overstated.

**Fix:** Before any hashing, apply a rate limit per client (IP address, device or API key) to every attempt, including attempts for unknown usernames. Stop resetting the failure counter when a lock is applied, so lock durations increase exponentially up to a cap. Alert on high failure rates across many accounts. Combine this with the per-client lockout from SEC-02 so the growing delays do not become a denial-of-service tool.
```java
    private static final Duration MAX_LOCKOUT = Duration.ofHours(24);

    /** Rate limiter keyed by client (IP address, device id, API key), e.g. a token bucket. */
    public interface LoginThrottle {
        boolean tryAcquire(String clientKey);
    }

    private final LoginThrottle clientThrottle;

    public LoginResult login(String username, char[] password, String clientKey) {
        try {
            // Checked before any hashing, for known AND unknown usernames.
            if (!clientThrottle.tryAcquire(clientKey)) {
                return LoginResult.INVALID_CREDENTIALS;
            }
            // ... lookup and single hash computation unchanged ...

                account.failedAttempts++; // no longer reset when a lock is applied
                if (account.failedAttempts >= MAX_FAILED_ATTEMPTS) {
                    // Escalating back-off: 1, 2, 4, 8 ... minutes, capped at 24 hours.
                    int step = Math.min(account.failedAttempts - MAX_FAILED_ATTEMPTS, 20);
                    Duration delay = Duration.ofMinutes(1L << step);
                    account.lockedUntil = now.plus(delay.compareTo(MAX_LOCKOUT) > 0 ? MAX_LOCKOUT : delay);
                }
                return LoginResult.INVALID_CREDENTIALS;
```

### SEC-02: Any unauthenticated party can lock any account (lockout denial of service)
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `LoginSystem.java:205-209`, `LoginSystem.java:216-220`

**Vulnerable code:**
```java
// LoginSystem.java:205-209
            synchronized (account) {
                Instant now = clock.instant();
                if (now.isBefore(account.lockedUntil)) {
                    return LoginResult.ACCOUNT_LOCKED;
                }
// LoginSystem.java:216-220
                account.failedAttempts++;
                if (account.failedAttempts >= MAX_FAILED_ATTEMPTS) {
                    account.failedAttempts = 0;
                    account.lockedUntil = now.plus(LOCKOUT_DURATION);
                }
```

**Why it is a problem:** The lock is global to the account, and anyone can set it by sending 5 wrong passwords. While it is active, even the real owner's correct password is rejected (lines 207-208 return before the password is checked). An attacker who knows or guesses usernames (for example `admin`, or email addresses) can send 5 requests per account every 15 minutes and keep chosen users, or every user, locked out indefinitely. They need no credentials, and the cost is tiny.

**Fix:** Do not let one client's failures block every other client. Track failures per (username, client) pair, with a bounded, evicting cache in production. Treat a high failure count for the account as a whole as a reason to add a step-up check (CAPTCHA or MFA) and to notify the owner, not to deny access outright.
```java
    static final class Failures {
        int count;
        Instant blockedUntil = Instant.EPOCH;
    }

    /** Failure state per (username, client) so a stranger cannot lock the real user out. */
    private final Map<String, Failures> failures = new ConcurrentHashMap<>(); // bound + evict in production

    // inside login(), after the single hash computation (see SEC-03):
    Failures f = failures.computeIfAbsent(normalized + '\n' + clientKey, k -> new Failures());
    synchronized (f) {
        Instant now = clock.instant();
        if (now.isBefore(f.blockedUntil)) {
            return LoginResult.INVALID_CREDENTIALS; // only this client is delayed
        }
        if (account != null && matches) {
            f.count = 0;
            return LoginResult.SUCCESS;
        }
        if (++f.count >= MAX_FAILED_ATTEMPTS) {
            f.blockedUntil = now.plus(LOCKOUT_DURATION);
        }
        return LoginResult.INVALID_CREDENTIALS;
    }
```

### SEC-03: `ACCOUNT_LOCKED` result and faster response reveal which usernames exist
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `LoginSystem.java:205-211`, `LoginSystem.java:293-294`

**Vulnerable code:**
```java
// LoginSystem.java:205-211
            synchronized (account) {
                Instant now = clock.instant();
                if (now.isBefore(account.lockedUntil)) {
                    return LoginResult.ACCOUNT_LOCKED;
                }

                if (hasher.verify(password, account.salt, account.passwordHash)) {
// LoginSystem.java:293-294
                case ACCOUNT_LOCKED:
                    System.out.println("Login failed: account temporarily locked. Try again later.");
```

**Why it is a problem:** The class says failures "never" distinguish unknown users, and it spends a dummy hash to hide timing differences. However, only real accounts can ever reach `ACCOUNT_LOCKED`. An attacker can send 6 wrong passwords for each candidate username:
- A real account returns `ACCOUNT_LOCKED` with its own message.
- An unknown username always returns `INVALID_CREDENTIALS`.

The locked branch also returns before any PBKDF2 work, so it is measurably faster than every other path (roughly 0 ms against more than 100 ms). This gives a second, timing-based way to tell accounts apart. The result is a reliable list of valid usernames to use in spraying (SEC-01) and lockout attacks (SEC-02).

**Fix:** Run exactly one hash on every path, locked accounts included, and return the same result for a locked account as for a wrong password. Tell the real owner about the lock out-of-band, for example by email. If a visible "locked" message is required, track failures by the normalized username string so unknown usernames also appear locked after 5 attempts.
```java
            Account account = normalized == null ? null : repository.findByUsername(normalized);
            boolean usable = account != null && passwordValid;

            // Exactly one PBKDF2 computation on every path, including locked accounts.
            boolean matches = hasher.verify(
                    passwordValid ? password : new char[] {'x'},
                    usable ? account.salt : dummySalt,
                    usable ? account.passwordHash : dummyHash);

            if (!usable) {
                return LoginResult.INVALID_CREDENTIALS;
            }

            synchronized (account) {
                Instant now = clock.instant();
                if (now.isBefore(account.lockedUntil)) {
                    // Same result as a wrong password; notify the real owner out-of-band instead.
                    return LoginResult.INVALID_CREDENTIALS;
                }

                if (matches) {
                    account.failedAttempts = 0;
                    return LoginResult.SUCCESS;
                }
```

### SEC-04: Password policy only checks length (no common or breached password check)
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `LoginSystem.java:175`

**Vulnerable code:**
```java
// LoginSystem.java:175
            if (password == null || password.length < 8 || password.length > MAX_PASSWORD_LENGTH) {
```

**Why it is a problem:** Registration accepts any password of 8 or more characters, including `password`, `12345678`, `qwertyui`, or the username repeated. NIST SP 800-63B requires new passwords to be checked against lists of common, expected and breached passwords. Combined with the spraying exposure in SEC-01, allowing these passwords makes account takeover through a handful of common guesses per account practical.

**Fix:** Keep the length limits and add a check against a blocklist of common and breached passwords, for example a local top-100k list or the k-anonymity range API of Have I Been Pwned. Also reject passwords that contain the username.
```java
            if (password == null || password.length < 8 || password.length > MAX_PASSWORD_LENGTH) {
                throw new IllegalArgumentException("Password must be 8-" + MAX_PASSWORD_LENGTH + " characters");
            }
            if (passwordBlocklist.isCommonOrBreached(password)
                    || new String(password).toLowerCase(java.util.Locale.ROOT).contains(normalized)) {
                throw new IllegalArgumentException("Password is too common or contains the username");
            }
```

### SEC-05: PBKDF2-HMAC-SHA256 iteration count below OWASP guidance and not stored per hash
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `LoginSystem.java:60` (used at `LoginSystem.java:72-75`)

**Vulnerable code:**
```java
// LoginSystem.java:60
        private static final int ITERATIONS = 210_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
```

**Why it is a problem:** The comment is wrong. The OWASP Password Storage Cheat Sheet recommends **600,000** iterations for PBKDF2-HMAC-SHA256; 210,000 is its figure for PBKDF2-HMAC-**SHA512**. At 210,000 iterations, an attacker who steals the hash store can test about 2.9 times more guesses per second on GPUs than intended. The iteration count is also a global constant that is not saved with each hash (`Account`, lines 98-110). The work factor therefore cannot be raised later without invalidating every stored password, which makes the weakness hard to fix once there is real data.

**Fix:** Raise the count to 600,000, or use Argon2id or bcrypt through a vetted library. Save the iteration count with each hash, and rehash with the current settings after a successful login.
```java
        private static final int ITERATIONS = 600_000; // OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256

    static final class Account {
        final String username;
        final byte[] salt;
        final byte[] passwordHash;
        final int iterations; // stored with the hash so the work factor can be raised later
        // ...
    }

    // in login(), after hasher.verify(password, account.salt, account.passwordHash, account.iterations) succeeds:
    if (account.iterations < PasswordHasher.ITERATIONS) {
        byte[] newSalt = hasher.newSalt();
        repository.updatePassword(normalized, newSalt,
                hasher.hash(password, newSalt, PasswordHasher.ITERATIONS), PasswordHasher.ITERATIONS);
    }
```

### SEC-06: Lockout state cannot be saved through the repository; race-prone outside a single JVM
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `LoginSystem.java:113-118`, `LoginSystem.java:205-220`

**Vulnerable code:**
```java
// LoginSystem.java:113-118
    public interface AccountRepository {
        Account findByUsername(String username);

        /** @return false if the username is already taken */
        boolean save(Account account);
    }
// LoginSystem.java:205-206
            synchronized (account) {
                Instant now = clock.instant();
```

**Why it is a problem:** `failedAttempts` and `lockedUntil` are changed directly on the Java object, and the check is synchronized on that object. The `AccountRepository` interface has no method to save these fields: `save` uses insert-if-absent semantics and returns `false` for an existing user. The README says to replace the in-memory store with a database, but a database-backed `findByUsername` returns a new `Account` on each call. When that happens:
- Every login sees `failedAttempts == 0`, so the lock is never reached.
- `synchronized (account)` protects nothing, because each request locks a different object.
- Concurrent requests across threads or servers cannot be counted together (a limit overrun).

The only shipped implementation (`InMemoryAccountRepository`) is safe, but the abstraction makes the lockout control fail silently for the deployment the README recommends.

**Fix:** Add atomic repository operations for lockout state, such as a single conditional `UPDATE ... RETURNING` or `SELECT ... FOR UPDATE`, or a shared store like Redis with `INCR` and `EXPIRE`. Use those operations instead of in-JVM monitors.
```java
    public interface AccountRepository {
        Account findByUsername(String username);

        /** @return false if the username is already taken */
        boolean save(Account account);

        /**
         * Atomically increments the failure counter and applies a lock when the threshold is reached, e.g.
         * UPDATE accounts SET failed_attempts = failed_attempts + 1,
         *        locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END
         * WHERE username = ? RETURNING failed_attempts, locked_until
         */
        LockoutState recordFailure(String username, Instant now, int maxAttempts, Duration lockout);

        /** Atomically resets the failure counter after a successful login. */
        void recordSuccess(String username);
    }
```

### SEC-07: Hard-coded demo credential printed to stdout and documented in README
- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginSystem.java:260-261` (also `README.md:65-68`, `README.md:73`, `README.md:102`)

**Vulnerable code:**
```java
// LoginSystem.java:260-261
        loginSystem.registerUser("alice", "CorrectHorse42!".toCharArray());
        System.out.println("Demo account created: username 'alice', password 'CorrectHorse42!'");
```

**Why it is a problem:** The production class ships with a fixed, publicly documented account and password. The password is also written to stdout, where terminal scrollback, CI logs or process supervisors can capture it. The `main` entry point is in the same class as the library, so any deployment that runs `java LoginSystem` has a known valid login. The README also suggests `auth.registerUser("alice", "CorrectHorse42!"...)` in its integration sample, so the credential is likely to be copied into real code. The impact is limited because the store is in memory and exists only for that process's lifetime.

**Fix:** Do not embed a password. Have the operator choose one through a non-echoing prompt, or generate a random one-time password. Never print passwords. Ideally move the demo into a separate class that is not packaged with the library, and remove the literal password from the README samples.
```java
        LoginSystem loginSystem = new LoginSystem(new InMemoryAccountRepository());
        char[] demoPassword = console.readPassword("Choose a password (8+ characters) for demo user 'alice': ");
        try {
            loginSystem.registerUser("alice", demoPassword); // wipes demoPassword
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(2);
        }
        System.out.println("Demo account 'alice' created.");
```

### SEC-08: Password echoed and read into an immutable `String` when no console is available
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `LoginSystem.java:278-287`

**Vulnerable code:**
```java
// LoginSystem.java:278-287
            } else {
                System.out.print("Username: ");
                username = reader.readLine();
                if (username == null || username.isBlank()) {
                    break;
                }
                System.out.print("Password: ");
                String line = reader.readLine();
                password = line == null ? new char[0] : line.toCharArray();
            }
```

**Why it is a problem:** When `System.console()` is `null` (for example in IDE consoles, some terminals or wrapped processes), the code quietly falls back to `BufferedReader.readLine()`. The typed password is echoed on screen, where shoulder-surfers, screen recordings or scrollback can capture it. It is also held in an immutable `String` (`line`) that cannot be wiped and stays on the heap until garbage collection (CWE-316). This defeats the `char[]` wiping the class advertises. Nothing tells the user their password is now visible.

**Fix:** Fail closed when no console is available instead of silently degrading. If input without a console must be supported, read characters directly into a `char[]` that is wiped afterwards, and warn that input will be visible.
```java
        Console console = System.console();
        if (console == null) {
            // Never fall back to reading a password from an echoing stream into an immutable String.
            System.err.println("An interactive console is required to read passwords securely.");
            System.exit(2);
        }

        while (true) {
            String username = console.readLine("Username: ");
            if (username == null || username.isBlank()) {
                break;
            }
            char[] password = console.readPassword("Password: "); // not echoed, never a String
```

### SEC-09: Usernames are not Unicode-normalized or restricted, so look-alike accounts can be registered
- **Severity:** Low
- **CWE:** CWE-1007: Insufficient Visual Distinction of Homoglyphs Presented to User
- **Location:** `LoginSystem.java:229-238`

**Vulnerable code:**
```java
// LoginSystem.java:229-238
    private static String normalizeUsername(String username) {
        if (username == null) {
            return null;
        }
        String trimmed = username.trim().toLowerCase(java.util.Locale.ROOT);
        if (trimmed.isEmpty() || trimmed.length() > MAX_USERNAME_LENGTH) {
            return null;
        }
        return trimmed;
    }
```

**Why it is a problem:** Normalization only trims ASCII control characters and spaces and lower-cases the name. It applies no Unicode normalization and no character allow-list, so each of the following is stored as a separate account from `alice` even though it looks identical or nearly identical:
- The full-width `ａｌｉｃｅ`.
- The Cyrillic `аlice` (U+0430).
- `alice` followed by a zero-width space (U+200B), which `trim()` does not remove.

An attacker can register a name like `аdmin` to impersonate a real user or administrator wherever usernames are shown. They can also cause confusion in audit logs and access-control lists that are keyed by display name.

**Fix:** Apply NFKC normalization before lower-casing, strip Unicode whitespace, and check the result against an explicit allow-list (or apply Unicode confusable/skeleton checks when registering if international names are required).
```java
    private static final java.util.regex.Pattern USERNAME_PATTERN =
            java.util.regex.Pattern.compile("[a-z0-9._-]{1," + MAX_USERNAME_LENGTH + "}");

    private static String normalizeUsername(String username) {
        if (username == null) {
            return null;
        }
        String normalized = java.text.Normalizer
                .normalize(username.strip(), java.text.Normalizer.Form.NFKC)
                .toLowerCase(java.util.Locale.ROOT);
        return USERNAME_PATTERN.matcher(normalized).matches() ? normalized : null;
    }
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm:** Passwords are hashed with the `PBKDF2WithHmacSHA256` KDF, not a fast hash. No MD5, SHA-1, DES/3DES, RC4, ECB mode or reversible encryption is used anywhere (`LoginSystem.java:59`, `LoginSystem.java:72-81`). The only issue is the iteration count (SEC-05).
- **Salt:** Each account gets a 16-byte salt from `SecureRandom`, generated separately at registration (`LoginSystem.java:61`, `LoginSystem.java:64-70`, `LoginSystem.java:178-179`). No predictable or time-based seed is used. The derived key is 256 bits (`LoginSystem.java:62`).
- **Hard-coded cryptographic keys or peppers:** None. The only literals are the demo password (SEC-07) and the dummy value `"dummy-password"` (`LoginSystem.java:160`). That value is hashed with a random salt and used only to equalize timing, so it grants no access.
- **Hash comparison:** `MessageDigest.isEqual` is used, which runs in constant time on JDK 7u40 and later (`LoginSystem.java:86`).
- **Fails closed:** Exceptions from `SecretKeyFactory` become `IllegalStateException` and are never treated as success (`LoginSystem.java:76-77`). `SUCCESS` is returned only when `verify` returns true (`LoginSystem.java:211-214`). `login(null, null)` and empty passwords return `INVALID_CREDENTIALS` (`LoginSystem.java:192-203`).
- **User enumeration on normal failures:** Unknown usernames and wrong passwords return the same enum value and the same CLI message. Both paths run exactly one PBKDF2 computation, and over-long passwords are hashed as the dummy `'x'` (`LoginSystem.java:198-203`, `LoginSystem.java:296-297`). The only gap is the locked state (SEC-03). Registration returns `false` for an existing username (`LoginSystem.java:131`), which is normal for sign-up flows; callers should show a neutral message.
- **Input size limits:** Usernames are capped at 64 characters and passwords at 1024 characters before hashing (`LoginSystem.java:141-142`, `LoginSystem.java:175`, `LoginSystem.java:193-195`, `LoginSystem.java:234`). HMAC pre-hashes long keys, so PBKDF2 has no long-password denial of service.
- **Locale-safe case folding:** `toLowerCase(Locale.ROOT)` avoids the Turkish dotted/dotless-i problem when matching usernames (`LoginSystem.java:233`).
- **Clearing sensitive data from memory:** `PBEKeySpec.clearPassword()` is called (`LoginSystem.java:79`). The derived hash is zeroed after comparison (`LoginSystem.java:88`). Caller password arrays are wiped in `finally` blocks for both registration and login (`LoginSystem.java:180-182`, `LoginSystem.java:223-225`, `LoginSystem.java:240-244`), and the self-test confirms this (`LoginSystem.java:325-327`).
- **Concurrency in the shipped in-memory store:** `ConcurrentHashMap.putIfAbsent` makes duplicate registration atomic, so there is no TOCTOU race (`LoginSystem.java:122-132`). Counter and lock updates on a single shared `Account` instance happen inside `synchronized (account)`, so parallel requests cannot overrun the limit within one JVM (`LoginSystem.java:205-222`). Behaviour with non-in-memory repositories or multiple servers is covered by SEC-06.
- **Passwords stored or logged in plain text:** `Account` holds only the salt and hash (`LoginSystem.java:98-110`). The login path never logs or prints the submitted password; the only printed password is the demo one (SEC-07).
- **Console password masking:** When a console is available, `Console.readPassword` is used and returns a `char[]` without echoing (`LoginSystem.java:277`). The fallback path is covered by SEC-08.
- **Injection, deserialization, file, OS command and network/TLS code:** None exist. There is no SQL, no `Runtime.exec` or `ProcessBuilder`, no `ObjectInputStream`, no file paths, no reflection on input and no network or TLS code. These were reviewed against OWASP A03, A08, A10 and A02 (transport) with nothing applicable. Credential transport is left to the integrating application, and the README tells integrators to use TLS (`README.md:119`).
- **Self-test code:** The test credentials (`s3cretPass` and others) are in a private method that runs only with `--self-test`, on a separate in-memory store and a mock clock. They grant no access to real data (`LoginSystem.java:304-350`).
- **Non-code files:** `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` and `prompt_hash.txt` were checked for secrets and executable content. They contain only prompts and run metadata such as session IDs and token counts, and no credentials or API keys.
