# Security Review: UserAccountManager (Java credential registration and login CLI/library)

## 1. Executive Summary
`UserAccountManager.java` is a small, dependency-free Java program (and reusable class) that registers user accounts and later authenticates them. Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte `SecureRandom` salt, 256-bit output) and stored with the salt in a colon-separated text file (`credentials.db` by default). Logins re-derive the hash and compare it in constant time.

The core password-storage design is sound. It uses no weak algorithms, no hardcoded secrets and no reversible encryption, and it compares hashes in constant time. No Critical or High issues were found. The most important findings are:

- **SEC-01 (Medium):** Case-insensitive username matching uses locale-dependent `String.toLowerCase()`. Under a Turkish/Azeri default locale, `ADMIN` and `admin` become different accounts. If the store is later loaded under another locale, the second record silently replaces the first, which allows account takeover.
- **SEC-02 (Medium):** `authenticate()` has no failed-attempt throttling or lockout. Every call does 600k PBKDF2 iterations while holding a global lock, so an embedding service can be brute-forced online and blocked for all users by a small number of requests.
- **Low findings:** lost updates and duplicate registrations when more than one process writes the store; a password policy that only checks length; an unbounded work factor read from the store; and piped passwords that are kept in an immutable `String`.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountManager.java` | Registers accounts and authenticates users; CLI entry point plus public `register`/`authenticate` API | PBKDF2 password hashing, salt generation with `SecureRandom`, constant-time hash comparison, username validation and case folding, password length policy, credential file parsing/serialisation, temp-file + atomic move with POSIX `rw-------` permissions, in-JVM `synchronized` locking, console/stdin password input and in-memory wiping, error message handling |
| `README.md` | Plain-English build/usage documentation | Documents security claims (case-insensitive usernames, owner-only file, no brute-force limit, single-process use); used to check the code against its stated guarantees |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Task prompts and run metadata from generation of the code | Not executable code; no security-relevant behaviour (reviewed only for context) |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. Used to understand the code, pick specialised skills by keyword (password storage, cryptography, authentication, brute force, credential file storage, concurrency) and structure the report.
- `performing-cryptographic-audit-of-application`: Applied to `deriveHash` and the constants (algorithm, KDF iteration count, salt size and RNG, output length), the constant-time comparison, hardcoded-secret checks, and the KDF parameters read back from storage (SEC-05).
- `testing-api-authentication-weaknesses`: Applied to `authenticate()`/`register()` as an authentication API. Covered password policy (SEC-04), brute-force/credential-stuffing resistance (SEC-02), account enumeration through messages and timing, and identity matching (SEC-01).
- `testing-for-sensitive-data-exposure`: Applied to how the credential store is kept at rest (file permissions, file contents), error messages, and passwords held in memory (SEC-06).
- `exploiting-race-condition-vulnerabilities`: Its TOCTOU/concurrency guidance (for example "Account Registration Bypass" through concurrent registration) was applied to the read-modify-write cycle of the credential file (SEC-03). The Burp/Turbo Intruder tooling was not used because the target is not a web app.
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): locale-sensitive case folding and Unicode identity (CWE-178), parsing of the custom file format (CWE-20), CLI argument/path handling (`--file`), and exception handling.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Locale-dependent username case folding allows duplicate identities and account takeover | Medium | CWE-178 | `UserAccountManager.java:82` |
| SEC-02 | No throttling or lockout on authentication; global lock around 600k-iteration KDF enables brute force and DoS | Medium | CWE-307 | `UserAccountManager.java:102` |
| SEC-03 | Unsynchronised cross-process read-modify-write of the credential store (lost accounts, duplicate registration) | Low | CWE-362 | `UserAccountManager.java:81` |
| SEC-04 | Password policy only checks length; common/breached passwords accepted | Low | CWE-521 | `UserAccountManager.java:155` |
| SEC-05 | Work factor loaded from store is not bounded or upgraded | Low | CWE-1284 | `UserAccountManager.java:198` |
| SEC-06 | Piped password is held in an immutable `String` that cannot be wiped | Low | CWE-316 | `UserAccountManager.java:350` |

## 5. Detailed Findings

### SEC-01: Locale-dependent username case folding allows duplicate identities and account takeover
- **Severity:** Medium
- **CWE:** CWE-178: Improper Handling of Case Sensitivity
- **Location:** `UserAccountManager.java:82`, `UserAccountManager.java:90`, `UserAccountManager.java:108`, `UserAccountManager.java:213`

**Vulnerable code:**
```java
// UserAccountManager.java:81-82
            Map<String, StoredCredential> accounts = loadAccounts();
            if (accounts.containsKey(username.toLowerCase())) {
```
```java
// UserAccountManager.java:208-214
        for (String line : Files.readAllLines(storeFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            StoredCredential credential = StoredCredential.fromLine(line);
            accounts.put(credential.username.toLowerCase(), credential);
        }
```

**Why it is a problem:** The README promises that "`Alice` and `alice` count as the same user". The code implements this with `String.toLowerCase()`, which uses the JVM's default locale. Under `tr`/`az` locales, `'I'` lowercases to dotless `'ı'` (U+0131), so `"ADMIN"` becomes `"admın"`, not `"admin"`:
1. With `-Duser.language=tr` (or a Turkish OS locale), an attacker registers `ADMIN`. The uniqueness check at line 82 looks up `"admın"`, finds nothing, and adds a second account that looks like the existing `admin`.
2. When the same store is later loaded under any other locale (a different machine, user, service restart, or `LANG`), line 213 maps both records to `"admin"`. `LinkedHashMap.put` silently overwrites the real `admin` record with the attacker's later line. `authenticate("admin", attackerPassword)` then returns `true`, and the next `saveAccounts` permanently deletes the real record.

`loadAccounts` also has no duplicate-key check, so any duplicate line in the file replaces an earlier account without warning.

**Fix:** Case-fold with a fixed, locale-independent locale (`Locale.ROOT`) in one helper. Reject duplicate normalised usernames when loading, and apply the same username validation on login.
```java
import java.util.Locale;

    private static String canonical(String username) {
        return username.toLowerCase(Locale.ROOT);
    }

    // register()
            if (accounts.containsKey(canonical(username))) {
                throw new IllegalArgumentException("That username is already taken.");
            }
            ...
            accounts.put(canonical(username),
                    new StoredCredential(username, ITERATIONS, salt, hash));

    // authenticate()
            if (username == null || password == null
                    || !USERNAME_PATTERN.matcher(username).matches()) {
                deriveHash(password == null ? new char[0] : password, new byte[SALT_BYTES], ITERATIONS);
                return false;
            }
            StoredCredential stored = loadAccounts().get(canonical(username));

    // loadAccounts()
            StoredCredential credential = StoredCredential.fromLine(line);
            if (accounts.putIfAbsent(canonical(credential.username), credential) != null) {
                throw new IllegalStateException("Duplicate username in credential store.");
            }
```

### SEC-02: No throttling or lockout on authentication; global lock around 600k-iteration KDF enables brute force and DoS
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAccountManager.java:102-121`

**Vulnerable code:**
```java
// UserAccountManager.java:102-121
    public synchronized boolean authenticate(String username, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            if (username == null || password == null) {
                return false;
            }
            StoredCredential stored = loadAccounts().get(username.toLowerCase());
            if (stored == null) {
                // Do the same amount of work for unknown users so response
                // time does not reveal which usernames exist.
                byte[] dummySalt = new byte[SALT_BYTES];
                deriveHash(password, dummySalt, ITERATIONS);
                return false;
            }
            byte[] candidate = deriveHash(password, stored.salt, stored.iterations);
            return MessageDigest.isEqual(candidate, stored.hash);
        } finally {
            wipe(password);
        }
    }
```

**Why it is a problem:** The class is documented as a reusable API ("Using it from your own code"). `authenticate()` never counts failures, delays or locks out, so a service built on it can be hit with unlimited password-guessing and credential-stuffing attempts (the README even admits "There is no limit on failed login attempts"). The method is also `synchronized` on the single manager instance, and each call re-reads the whole file and runs 600,000 PBKDF2 iterations (roughly 0.3–1 s of CPU) while holding the lock. A few concurrent requests, including requests for non-existent users (which do the dummy derivation), queue every legitimate login behind them. That lets an attacker deny service without logging in (CWE-400).

**Fix:** Track failures per canonical username (and per source, where the caller has one) with exponential backoff or temporary lockout. Check the limit *before* the expensive KDF, and do not hold the global lock during hashing. Only file access needs serialising.
```java
    private final Map<String, Failure> failures = new java.util.concurrent.ConcurrentHashMap<>();

    private static final class Failure {
        int count;
        long lockedUntilMillis;
    }

    public boolean authenticate(String username, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            if (username == null || password == null) {
                return false;
            }
            String key = username.toLowerCase(Locale.ROOT);
            Failure f = failures.get(key);
            if (f != null && System.currentTimeMillis() < f.lockedUntilMillis) {
                return false; // throttled: no KDF work, no lock held
            }

            StoredCredential stored;
            synchronized (this) {           // lock only around file I/O
                stored = loadAccounts().get(key);
            }

            boolean ok;
            if (stored == null) {
                deriveHash(password, new byte[SALT_BYTES], ITERATIONS);
                ok = false;
            } else {
                byte[] candidate = deriveHash(password, stored.salt, stored.iterations);
                ok = MessageDigest.isEqual(candidate, stored.hash);
            }

            if (ok) {
                failures.remove(key);
            } else {
                Failure nf = failures.computeIfAbsent(key, k -> new Failure());
                synchronized (nf) {
                    nf.count++;
                    if (nf.count >= 5) {
                        long backoff = Math.min(15 * 60_000L, 1_000L << Math.min(nf.count - 5, 20));
                        nf.lockedUntilMillis = System.currentTimeMillis() + backoff;
                    }
                }
            }
            return ok;
        } finally {
            wipe(password);
        }
    }
```

### SEC-03: Unsynchronised cross-process read-modify-write of the credential store (lost accounts, duplicate registration)
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `UserAccountManager.java:75-92`, `UserAccountManager.java:219-249`

**Vulnerable code:**
```java
// UserAccountManager.java:75-92
    public synchronized void register(String username, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            validateUsername(username);
            validatePassword(password);

            Map<String, StoredCredential> accounts = loadAccounts();
            if (accounts.containsKey(username.toLowerCase())) {
                throw new IllegalArgumentException("That username is already taken.");
            }

            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = deriveHash(password, salt, ITERATIONS);

            accounts.put(username.toLowerCase(),
                    new StoredCredential(username, ITERATIONS, salt, hash));
            saveAccounts(accounts);
```

**Why it is a problem:** `synchronized` only serialises calls on the same object in the same JVM. Two CLI processes, or two `UserAccountManager` instances pointing at the same file, can both load the store, spend about a second hashing (a wide race window), and then each overwrite the file with their own snapshot through `Files.move(..., REPLACE_EXISTING)`. The later writer silently erases any account the earlier one added. Two concurrent registrations of the same username both pass the check at line 82 and both print "Account ... created." Only the last one survives, so the other user's password never works. This is the "Account Registration Bypass" pattern from the race-condition skill. It is Low because the tool is documented as single-process.

**Fix:** Keep an exclusive OS-level lock on a sidecar lock file for the whole load → check → write sequence, and do the slow KDF before taking the lock.
```java
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.StandardOpenOption;

    public void register(String username, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            validateUsername(username);
            validatePassword(password);

            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = deriveHash(password, salt, ITERATIONS);   // outside the lock
            String key = username.toLowerCase(Locale.ROOT);

            Path lockPath = storeFile.toAbsolutePath().resolveSibling(storeFile.getFileName() + ".lock");
            synchronized (this) {
                try (FileChannel ch = FileChannel.open(lockPath,
                             StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                     FileLock lock = ch.lock()) {                   // cross-process exclusive lock
                    Map<String, StoredCredential> accounts = loadAccounts();
                    if (accounts.containsKey(key)) {
                        throw new IllegalArgumentException("That username is already taken.");
                    }
                    accounts.put(key, new StoredCredential(username, ITERATIONS, salt, hash));
                    saveAccounts(accounts);
                }
            }
        } finally {
            wipe(password);
        }
    }
```

### SEC-04: Password policy only checks length; common/breached passwords accepted
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAccountManager.java:155-164`

**Vulnerable code:**
```java
// UserAccountManager.java:155-164
    private static void validatePassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
    }
```

**Why it is a problem:** Any 8+ character string is accepted, including `password`, `12345678`, `qwertyuiop`, or the username repeated. The length limits follow NIST SP 800-63B, but the code skips its other requirement: checking new passwords against a list of commonly used, expected or compromised values. Combined with SEC-02, the most common passwords from credential-stuffing lists can be guessed in a handful of attempts, and a stolen store can be cracked quickly for those accounts despite PBKDF2.

**Fix:** Reject passwords found in a blocklist of common/breached passwords (loaded from a bundled file or a k-anonymity breach API) and passwords that contain the username.
```java
    private static final java.util.Set<String> COMMON_PASSWORDS = loadBlocklist(); // e.g. top 100k breached passwords, lower-cased

    private static void validatePassword(String username, char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
        String lowered = new String(password).toLowerCase(Locale.ROOT);
        try {
            if (COMMON_PASSWORDS.contains(lowered)
                    || lowered.contains(username.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException(
                        "That password is too common or contains your username. Choose another.");
            }
        } finally {
            lowered = null; // String cannot be wiped; keep its lifetime minimal
        }
    }
```

### SEC-05: Work factor loaded from store is not bounded or upgraded
- **Severity:** Low
- **CWE:** CWE-1284: Improper Validation of Specified Quantity in Input
- **Location:** `UserAccountManager.java:192-200`, `UserAccountManager.java:116`

**Vulnerable code:**
```java
// UserAccountManager.java:192-200
        static StoredCredential fromLine(String line) {
            String[] parts = line.split(FIELD_SEPARATOR, -1);
            if (parts.length != 5 || !ALGORITHM_ID.equals(parts[1])) {
                throw new IllegalStateException("Corrupt credential record in store.");
            }
            Base64.Decoder b64 = Base64.getDecoder();
            return new StoredCredential(parts[0], Integer.parseInt(parts[2]),
                    b64.decode(parts[3]), b64.decode(parts[4]));
        }
```

**Why it is a problem:** The iteration count, salt length and hash length come straight from the file and go into `deriveHash(password, stored.salt, stored.iterations)` without validation:
- A record with `iterations=1` (restored from an old backup, written by another tool, or planted by someone who can append to the store) is accepted silently. That account then has almost no brute-force resistance, and nothing upgrades it to the current `ITERATIONS` after a successful login.
- A record with `iterations=2147483647` makes each login for that account run for hours on a CPU core. In the current code this also holds the global lock (see SEC-02), so all authentication stops.
- Zero, negative or non-numeric values throw `IllegalArgumentException`/`NumberFormatException` from inside `authenticate`. `main` reports these as user "Error:" messages and leaks the raw field value.

Severity is Low because tampering needs write access to the store, but the checks are cheap defence in depth and the upgrade path matters as work factors rise.

**Fix:** Validate the record strictly when parsing, and rehash on successful login when parameters are below current policy.
```java
        private static final int MIN_ITERATIONS = ITERATIONS;
        private static final int MAX_ITERATIONS = 10_000_000;

        static StoredCredential fromLine(String line) {
            String[] parts = line.split(FIELD_SEPARATOR, -1);
            if (parts.length != 5 || !ALGORITHM_ID.equals(parts[1])
                    || !USERNAME_PATTERN.matcher(parts[0]).matches()) {
                throw new IllegalStateException("Corrupt credential record in store.");
            }
            try {
                int iterations = Integer.parseInt(parts[2]);
                Base64.Decoder b64 = Base64.getDecoder();
                byte[] salt = b64.decode(parts[3]);
                byte[] hash = b64.decode(parts[4]);
                if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                        || salt.length != SALT_BYTES || hash.length != HASH_BITS / 8) {
                    throw new IllegalStateException("Credential record has unsupported parameters.");
                }
                return new StoredCredential(parts[0], iterations, salt, hash);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Corrupt credential record in store.");
            }
        }
```

### SEC-06: Piped password is held in an immutable `String` that cannot be wiped
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserAccountManager.java:350-351`

**Vulnerable code:**
```java
// UserAccountManager.java:350-351
            String line = reader().readLine();
            return line == null ? new char[0] : line.toCharArray();
```

**Why it is a problem:** The code and README both promise that passwords "are wiped from memory once they are no longer needed", and the API uses `char[]` for that purpose. When no console is attached (piped input, IDE runs, service wrappers), the password is first read into a `String`. The `String` is immutable and cannot be cleared, so the plaintext stays on the heap until garbage collection and may end up in heap dumps, core dumps or swap. Only the `char[]` copy is wiped. The `BufferedReader`'s internal buffer also keeps the characters.

**Fix:** Read the line character by character into a `char[]` that the caller can wipe, and clear the temporary buffer.
```java
        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                char[] password = console.readPassword("%s", prompt);
                return password == null ? new char[0] : password;
            }
            if (!warnedNoConsole) {
                System.err.println("(warning: no console detected, password input will not be hidden)");
                warnedNoConsole = true;
            }
            System.out.print(prompt);
            System.out.flush();
            char[] buf = new char[MAX_PASSWORD_LENGTH + 1];
            int len = 0;
            int c;
            while ((c = reader().read()) != -1 && c != '\n') {
                if (c == '\r') {
                    continue;
                }
                if (len < buf.length) {
                    buf[len++] = (char) c;
                }
            }
            char[] result = Arrays.copyOf(buf, len);
            Arrays.fill(buf, '\0');
            return result;
        }
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm:** `PBKDF2WithHmacSHA256` (`UserAccountManager.java:43`, `:131`) is a one-way, approved password KDF. No MD5/SHA-1, unsalted hashing or reversible encryption is used, so the "not recoverable" requirement is met.
- **KDF work factor:** 600,000 iterations (`UserAccountManager.java:46`) meets the current OWASP Password Storage Cheat Sheet minimum for PBKDF2-HMAC-SHA256. Output length is 256 bits (`:48`), matching the PRF, so no extra-block cost is wasted.
- **Salt:** 16 bytes (`:47`), unique per account, from a static `SecureRandom` (`:57`, `:86-87`). No predictable seed and no `java.util.Random`.
- **Hash comparison:** `MessageDigest.isEqual` (`:117`) is constant-time on supported JDKs (Java 11+).
- **Username enumeration:** unknown users trigger an equivalent dummy PBKDF2 derivation (`:109-114`), and the CLI prints the same "Invalid username or password." message for both cases (`:294-297`). A "username already taken" message at registration (`:83`) is inherent to self-registration and not treated as a finding.
- **Hardcoded secrets:** none. There are no keys, passwords, pepper values or tokens in source.
- **Credential file format injection:** the username regex `^[A-Za-z0-9_.-]{3,32}$` (`:52`, `:148-153`) excludes `:` and newlines, and salt/hash are Base64-encoded (`:187-189`), so records cannot be forged through the `:` separator or line breaks during registration.
- **File permissions at rest (POSIX):** the temp file is created with `rw-------` (`:230-233`) and then renamed over the store, so the final file is owner-only. `Files.createTempFile` uses a random name with exclusive creation, and rename replaces a symlink rather than following it. On non-POSIX file systems (`:235`) the file inherits the directory ACL. This is documented behaviour and treated as deployment guidance, not a finding.
- **Crash-safe replacement:** write to temp, then `ATOMIC_MOVE` with fallback, and the temp file is removed in `finally` (`:238-248`).
- **Password input and wiping:** `Console.readPassword` disables echo (`:341`). The password arrays are wiped in `finally` in `register`/`authenticate` (`:93-95`, `:118-120`), `PBEKeySpec.clearPassword()` is called (`:134`), and the confirmation copy is wiped (`:278-280`). The only gap is SEC-06.
- **Input length limits:** maximum password length of 128 (`:51`, `:160`) and username length of 32 prevent oversized inputs to the KDF.
- **Injection classes:** no SQL, OS command execution, reflection, XML parsing, Java deserialization, network calls or TLS configuration are present.
- **`--file` path argument (`:263-264`):** chosen by the local user and used with that user's own privileges. No privilege boundary is crossed, so path traversal does not apply.
- **Error handling:** exceptions are caught in `main` (`:305-311`) and only messages are printed, with no stack traces. Passwords never appear in output or in the store file.
