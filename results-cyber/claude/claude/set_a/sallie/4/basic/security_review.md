# Security Review: User Account Manager (UserAccountManager.java)

## 1. Executive Summary
`UserAccountManager.java` is a self-contained Java command-line program, which can also be used as a library. It registers user accounts and later authenticates them. Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte `SecureRandom` salt, 256-bit output). Only `username:iterations:salt:hash` is stored in a local flat file (`users.db` by default), written atomically through a temp file.

The core cryptography is sound. The algorithm, work factor, salt and RNG meet current OWASP Password Storage guidance, the comparison is constant-time, and a dummy hash keeps login timing the same for unknown usernames. No critical or high-severity vulnerabilities were found. The most important issues are:

- **No brute-force protection** (SEC-01, Medium). `authenticate()` allows unlimited, unthrottled password guesses. This matters most when the class is embedded in another program, as the README encourages.
- **KDF parameters from the credentials file are trusted without bounds checks** (SEC-02, Low). A tampered or legacy entry can silently weaken hashing (e.g. 1 iteration), make login very slow, or crash the program with an empty salt.
- **Weaker hardening points** (all Low): a length-only password policy, lost updates when two processes write the store at once, no owner-only file permissions on non-POSIX systems (Windows), and passwords that are echoed and held as immutable `String`s when no console is attached.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountManager.java` | Registers and authenticates user accounts, persists credentials to a flat file, and provides an interactive CLI menu | Password hashing with PBKDF2 (lines 142-151); salt generation with `SecureRandom` (lines 52, 84-86); constant-time hash comparison and dummy credential for unknown users (lines 55-63, 98-109); username/password validation (lines 47-49, 115-136); credentials file parsing (lines 157-181); atomic temp-file write and POSIX permissions (lines 184-213); terminal / stdin password input and memory wiping (lines 271-346) |
| `README.md` | Plain-English usage documentation | No executable code. Documents the security design (salted PBKDF2, owner-only file, vague login errors) and the limitation of no account lockout, and shows library use of `register`/`authenticate` (lines 117-125) |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Generation / task metadata | No source code; out of scope for vulnerability analysis (reviewed only to confirm they contain no code) |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. It was used to inventory security-relevant behaviour, search the skill library by name, and select and apply the specialised skills below.
- `performing-cryptographic-audit-of-application`: Applied to password hashing: algorithm choice (PBKDF2-HMAC-SHA256), KDF parameters (iteration count, salt size, key length), RNG (`SecureRandom`), hardcoded secrets, and how stored KDF parameters are consumed (SEC-02).
- `testing-api-authentication-weaknesses`: Applied to the `register`/`authenticate` API and the CLI login flow. It covered password policy strength (SEC-03), credential-guessing / brute-force resistance (SEC-01), and account enumeration through login responses.
- `testing-for-sensitive-data-exposure`: Applied to data at rest (the credentials file and its permissions, SEC-05) and to sensitive data in memory and on screen (SEC-06). It also covered sensitive data in error messages and registration responses (username-taken message, IOException messages).
- General OWASP Top 10 / CWE knowledge (no matching library skill): concurrent file access and lost updates (the library's race-condition skill is specific to web request testing) (SEC-04). The same general review covered file-format injection through the `:` delimiter, temp-file creation and symlink handling, format-string use in `Console.readLine`, and fail-closed parsing of the credentials file.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No limit or throttling on failed authentication attempts | Medium | CWE-307 | `UserAccountManager.java:98` |
| SEC-02 | KDF parameters loaded from the credentials file are not validated | Low | CWE-1284 | `UserAccountManager.java:173` |
| SEC-03 | Password policy checks only length; common passwords accepted | Low | CWE-521 | `UserAccountManager.java:122` |
| SEC-04 | Stale in-memory snapshot causes lost or overwritten accounts under concurrent use | Low | CWE-362 | `UserAccountManager.java:79` |
| SEC-05 | Credentials file not restricted to owner on non-POSIX file systems | Low | CWE-732 | `UserAccountManager.java:209` |
| SEC-06 | Password echoed and kept in an immutable String when no console is available | Low | CWE-549 | `UserAccountManager.java:339` |

## 5. Detailed Findings

### SEC-01: No limit or throttling on failed authentication attempts
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAccountManager.java:97-109` (also the CLI loop at `UserAccountManager.java:296-309`)

**Vulnerable code:**
```java
// UserAccountManager.java:97-109
    /** Returns true only if the username exists and the password matches. */
    public synchronized boolean authenticate(String username, char[] password) {
        if (username == null || password == null) {
            return false;
        }
        StoredCredential stored = accounts.get(normalize(username));
        StoredCredential target = (stored != null) ? stored : dummyCredential;

        byte[] candidate = hash(password, target.salt, target.iterations);
        boolean matches = MessageDigest.isEqual(candidate, target.hash);
        Arrays.fill(candidate, (byte) 0);
        return stored != null && matches;
    }
```

**Why it is a problem:** `authenticate()` has no failed-attempt counter, delay or lockout. The CLI also lets a user retry logins forever. The README (lines 117-125) tells developers to embed the class in other programs, so any service built on it inherits unlimited online password guessing. The only cost to an attacker is one PBKDF2 evaluation per guess, roughly 0.3-1 s on one core. That cost is paid by the defender's CPU and parallelises across threads or instances. The minimum 8-character, no-blocklist policy (SEC-03) makes dictionary guessing practical. Because every attempt forces a 600,000-iteration hash, a flood of attempts also exhausts CPU. The README admits the missing lockout, but documenting it does not protect deployments.

**Fix:** Track consecutive failures per normalized username, for unknown usernames too, so the lockout does not reveal whether an account exists. Apply an increasing delay and a temporary lockout, and reject locked attempts before running the expensive hash. Bound the tracking map to stop memory growth. Services that embed the class should also rate-limit per client or source.
```java
    private static final int MAX_FAILURES_BEFORE_LOCK = 5;
    private static final long BASE_LOCK_MS = 30_000L;
    private static final long MAX_LOCK_MS = 15 * 60_000L;
    private static final int MAX_TRACKED_USERNAMES = 10_000;

    private final Map<String, FailureState> failures = new java.util.HashMap<>();

    private static final class FailureState {
        int count;
        long lockedUntil;
    }

    /** Returns true only if the username exists, is not locked out, and the password matches. */
    public synchronized boolean authenticate(String username, char[] password) {
        if (username == null || password == null) {
            return false;
        }
        String key = normalize(username);
        long now = System.currentTimeMillis();
        FailureState state = failures.get(key);
        if (state != null && now < state.lockedUntil) {
            return false; // locked out: do not evaluate (or burn CPU on) the password
        }

        StoredCredential stored = accounts.get(key);
        StoredCredential target = (stored != null) ? stored : dummyCredential;

        byte[] candidate = hash(password, target.salt, target.iterations);
        boolean matches = MessageDigest.isEqual(candidate, target.hash);
        Arrays.fill(candidate, (byte) 0);
        boolean ok = stored != null && matches;

        if (ok) {
            failures.remove(key);
        } else {
            if (state == null) {
                if (failures.size() >= MAX_TRACKED_USERNAMES) {
                    failures.clear(); // simple bound; use an LRU/expiring cache in production
                }
                state = new FailureState();
                failures.put(key, state);
            }
            state.count++;
            if (state.count >= MAX_FAILURES_BEFORE_LOCK) {
                int exponent = Math.min(state.count - MAX_FAILURES_BEFORE_LOCK, 10);
                state.lockedUntil = now + Math.min(MAX_LOCK_MS, BASE_LOCK_MS << exponent);
            }
        }
        return ok;
    }
```

### SEC-02: KDF parameters loaded from the credentials file are not validated
- **Severity:** Low
- **CWE:** CWE-1284: Improper Validation of Specified Quantity in Input
- **Location:** `UserAccountManager.java:168-176` (used at `UserAccountManager.java:105`)

**Vulnerable code:**
```java
// UserAccountManager.java:168-176
            String[] parts = line.split(":");
            try {
                if (parts.length != 4) {
                    throw new IllegalArgumentException("expected 4 fields");
                }
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = decoder.decode(parts[2]);
                byte[] hash = decoder.decode(parts[3]);
                accounts.put(parts[0], new StoredCredential(iterations, salt, hash));
```

**Why it is a problem:** The iteration count, salt and hash come straight from the file and drive `hash(password, target.salt, target.iterations)` at line 105, with no checks:
- **Silent downgrade:** an entry with `iterations` = `1` (from tampering, a legacy export or a buggy migration tool) is accepted and used forever. That hash can be brute-forced offline about 600,000× faster, and nothing ever rehashes it at the current work factor.
- **Denial of service:** `iterations` = `2147483647` makes every login for that account run for hours while holding the object's monitor. That blocks all other `register`/`authenticate` calls, because both methods are `synchronized`.
- **Crash:** a line such as `alice:600000::AAAA` parses successfully, since `split` keeps the empty middle field and Base64 decodes it to a zero-length salt. It also passes the "corrupt file" check. At login, `new PBEKeySpec(...)` throws an unchecked `IllegalArgumentException` ("the salt parameter must be non-empty"), which neither `authenticate` nor `handleLogin` catches, so the program terminates. `iterations` = `0` or a negative value does the same.
- **Unvalidated identity fields:** the username field (`parts[0]`) is not checked against `USERNAME_PATTERN` or normalized. Duplicate lines silently overwrite each other.

Exploiting any of this requires write access to the store. That limits severity, but the README promises the program "will refuse to start rather than guess" on bad data, and these cases break that promise.

**Fix:** Enforce bounds on every field at load time, fail closed, and transparently rehash weaker entries after a successful login.
```java
    private static final int MIN_ITERATIONS = ITERATIONS;      // raise together with ITERATIONS
    private static final int MAX_ITERATIONS = 10_000_000;

            String[] parts = line.split(":", -1);
            try {
                if (parts.length != 4) {
                    throw new IllegalArgumentException("expected 4 fields");
                }
                String name = parts[0];
                if (!USERNAME_PATTERN.matcher(name).matches() || !name.equals(normalize(name))) {
                    throw new IllegalArgumentException("invalid username field");
                }
                if (accounts.containsKey(name)) {
                    throw new IllegalArgumentException("duplicate username");
                }
                int iterations = Integer.parseInt(parts[1]);
                if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                    throw new IllegalArgumentException("iteration count out of range");
                }
                byte[] salt = decoder.decode(parts[2]);
                byte[] hash = decoder.decode(parts[3]);
                if (salt.length < SALT_BYTES) {
                    throw new IllegalArgumentException("salt too short");
                }
                if (hash.length != HASH_BITS / 8) {
                    throw new IllegalArgumentException("unexpected hash length");
                }
                accounts.put(name, new StoredCredential(iterations, salt, hash));
```

### SEC-03: Password policy checks only length; common passwords accepted
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAccountManager.java:122-131`

**Vulnerable code:**
```java
// UserAccountManager.java:122-131
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

**Why it is a problem:** Any 8-128 character value is accepted, including `password`, `12345678`, `qwertyui` and `aaaaaaaa`. NIST SP 800-63B requires checking new passwords against known-breached and commonly used values. That check is most important when a system has no lockout (SEC-01), because the most common passwords fall to online guessing within a handful of attempts, whatever the hashing strength.

**Fix:** Reject passwords found in a blocklist of common or breached passwords that ships with the application, e.g. the top 100k from a breach corpus. Compare against the `char[]` directly, so no immutable `String` copy of the password is made.
```java
    /** Lower-cased common/breached passwords, e.g. loaded once from a bundled resource file. */
    private static final java.util.Set<java.nio.CharBuffer> COMMON_PASSWORDS = loadCommonPasswords();

    private static void validatePassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
        char[] lower = new char[password.length];
        try {
            for (int i = 0; i < password.length; i++) {
                lower[i] = Character.toLowerCase(password[i]);
            }
            if (COMMON_PASSWORDS.contains(java.nio.CharBuffer.wrap(lower))) {
                throw new IllegalArgumentException(
                        "That password is too common. Please choose a less predictable password.");
            }
        } finally {
            Arrays.fill(lower, '\0');
        }
    }
```

### SEC-04: Stale in-memory snapshot causes lost or overwritten accounts under concurrent use
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `UserAccountManager.java:79-90` (with `load()` at `UserAccountManager.java:157-181` called only once, and `save()` at `UserAccountManager.java:184-206`)

**Vulnerable code:**
```java
// UserAccountManager.java:79-90
        String key = normalize(username);
        if (accounts.containsKey(key)) {
            throw new IllegalArgumentException("That username is already taken.");
        }

        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = hash(password, salt, ITERATIONS);

        accounts.put(key, new StoredCredential(ITERATIONS, salt, hash));
        try {
            save();
```

**Why it is a problem:** The store is read once, in the constructor. After that, "is the username taken?" is checked only against that snapshot, and `save()` rewrites the entire file from memory. `synchronized` only protects one JVM instance. If two processes share the same `users.db` (two CLI sessions, or two service instances):
1. An account registered by process A is silently deleted the next time process B saves.
2. Both processes can register the same username. The later write replaces the earlier user's credential, so the earlier user is locked out and the later registrant owns the name.
3. A process never sees accounts or password changes made by others, so authentication decisions are made on stale data.

The README asks that "only one copy of the program should change the accounts file at a time", but nothing enforces it.

**Fix:** Take an exclusive OS-level file lock around a re-read, check, modify and write sequence, so that each registration works on the current on-disk state. `authenticate` should likewise reload, or check the file's modification time, before deciding.
```java
    public synchronized void register(String username, char[] password) throws IOException {
        validateUsername(username);
        validatePassword(password);
        String key = normalize(username);

        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = hash(password, salt, ITERATIONS); // expensive work outside the file lock

        Path absolute = storePath.toAbsolutePath();
        Path lockFile = absolute.resolveSibling(absolute.getFileName() + ".lock");
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(lockFile,
                     java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
             java.nio.channels.FileLock lock = channel.lock()) {
            accounts.clear();
            load(); // re-read the latest on-disk state while holding the lock
            if (accounts.containsKey(key)) {
                throw new IllegalArgumentException("That username is already taken.");
            }
            accounts.put(key, new StoredCredential(ITERATIONS, salt, hash));
            try {
                save();
            } catch (IOException e) {
                accounts.remove(key); // keep memory consistent with the file
                throw e;
            }
        }
    }
```

### SEC-05: Credentials file not restricted to owner on non-POSIX file systems
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `UserAccountManager.java:208-213`

**Vulnerable code:**
```java
// UserAccountManager.java:208-213
    /** On POSIX systems, make the file readable and writable by the owner only. */
    private static void restrictToOwner(Path path) throws IOException {
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
    }
```

**Why it is a problem:** On Windows, and on other file systems without a POSIX view, the method does nothing. The credentials file then inherits whatever ACL its directory has. When `users.db` is created in a shared or world-readable folder (it defaults to the current working directory), other local users can read the salts and hashes and crack them offline. Worse, they may be able to write to the file, which lets them replace a hash with one for a password they know and take over the account (see also SEC-02). The failure is silent, and the README says the file is owner-only only "on Linux and macOS".

**Fix:** On ACL-based file systems, replace the inherited ACL with a single entry for the file owner. If neither view is supported, fail closed rather than silently leaving the file exposed.
```java
    /** Make the file readable and writable by the owner only (POSIX or ACL file systems). */
    private static void restrictToOwner(Path path) throws IOException {
        java.util.Set<String> views = FileSystems.getDefault().supportedFileAttributeViews();
        if (views.contains("posix")) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } else if (views.contains("acl")) {
            java.nio.file.attribute.AclFileAttributeView view =
                    Files.getFileAttributeView(path, java.nio.file.attribute.AclFileAttributeView.class);
            java.nio.file.attribute.AclEntry ownerOnly = java.nio.file.attribute.AclEntry.newBuilder()
                    .setType(java.nio.file.attribute.AclEntryType.ALLOW)
                    .setPrincipal(Files.getOwner(path))
                    .setPermissions(java.util.EnumSet.of(
                            java.nio.file.attribute.AclEntryPermission.READ_DATA,
                            java.nio.file.attribute.AclEntryPermission.WRITE_DATA,
                            java.nio.file.attribute.AclEntryPermission.APPEND_DATA,
                            java.nio.file.attribute.AclEntryPermission.READ_ATTRIBUTES,
                            java.nio.file.attribute.AclEntryPermission.WRITE_ATTRIBUTES,
                            java.nio.file.attribute.AclEntryPermission.READ_ACL,
                            java.nio.file.attribute.AclEntryPermission.WRITE_ACL,
                            java.nio.file.attribute.AclEntryPermission.DELETE,
                            java.nio.file.attribute.AclEntryPermission.SYNCHRONIZE))
                    .build();
            view.setAcl(java.util.Collections.singletonList(ownerOnly)); // drops inherited entries
        } else {
            throw new IOException("Cannot restrict access to the credentials file on this file system");
        }
    }
```

### SEC-06: Password echoed and kept in an immutable String when no console is available
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `UserAccountManager.java:339-345` (fallback read at `UserAccountManager.java:330-333`)

**Vulnerable code:**
```java
// UserAccountManager.java:339-345
        char[] readPassword(String prompt) {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
```

**Why it is a problem:** `System.console()` returns `null` whenever the JVM is not attached to a real terminal. That includes IDE run consoles, many Windows shells and terminal wrappers, and `nohup` and similar setups. In those cases the password is read with `BufferedReader.readLine()`. It is echoed in clear text as it is typed (visible to shoulder-surfers, screen recordings and terminal scroll-back), and the user gets no warning, even though the README promises the password "is hidden as you type it". Separately, CWE-316 (Cleartext Storage of Sensitive Information in Memory) applies: the password also lives in an immutable `String`, and in `BufferedReader`'s internal buffer, that `wipe()` cannot clear. That defeats the careful `char[]` zeroing elsewhere (lines 107, 149, 291-292, 307), and the password stays in heap dumps until garbage collection.

**Fix:** Refuse to read passwords without a console unless the caller explicitly opts in, e.g. for automated tests with piped input. When reading from stdin, read directly into a bounded `char[]` that is wiped afterwards.
```java
        char[] readPassword(String prompt) {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            if (!Boolean.getBoolean("uam.allowUnmaskedPasswordInput")) {
                System.err.println("No interactive terminal detected: refusing to read a password "
                        + "that would be shown on screen.");
                return null;
            }
            System.out.print(prompt);
            System.out.flush();
            char[] buf = new char[MAX_PASSWORD_LENGTH + 1];
            int len = 0;
            boolean overflow = false;
            try {
                int c;
                while ((c = reader.read()) != -1 && c != '\n') {
                    if (c == '\r') {
                        continue;
                    }
                    if (len < buf.length) {
                        buf[len++] = (char) c;
                    } else {
                        overflow = true; // keep consuming the rest of the line
                    }
                }
                if (overflow || (c == -1 && len == 0)) {
                    return null;
                }
                return Arrays.copyOf(buf, len);
            } catch (IOException e) {
                return null;
            } finally {
                Arrays.fill(buf, '\0');
            }
        }
```

## 6. Verified Controls and Checks With No Finding
- Password hashing algorithm and work factor: PBKDF2WithHmacSHA256 with 600,000 iterations and a 256-bit derived key (`UserAccountManager.java:42-45`, `142-151`). This matches the current OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256. No MD5, SHA-1, unsalted or fast hashes are used.
- Salt generation: a unique 16-byte salt per account from `java.security.SecureRandom` (`UserAccountManager.java:44`, `52`, `84-86`). No predictable RNG (`java.util.Random`, time seeds) is used anywhere.
- Constant-time comparison: `MessageDigest.isEqual` is used to compare the derived and stored hash (`UserAccountManager.java:106`), so there is no early-exit timing leak.
- User enumeration through login timing and messages: unknown usernames are hashed against a random dummy credential with the same work factor (`UserAccountManager.java:55-63`, `102-105`). The CLI prints a single generic failure message (`UserAccountManager.java:302-305`).
- Username enumeration at registration (CWE-204): "That username is already taken." (`UserAccountManager.java:80-82`) reveals that an account exists. This was reviewed and accepted as inherent to self-service registration without out-of-band verification. The risk mainly feeds SEC-01 and is reduced by fixing it.
- Hardcoded secrets: none. There are no embedded passwords, keys, peppers or tokens. `DEFAULT_STORE` (`UserAccountManager.java:40`) is only a file name.
- Credentials file format injection: usernames are limited to `^[A-Za-z0-9_.-]{3,32}$` before storage (`UserAccountManager.java:47`, `115-120`, `77`), so the `:` delimiter or newlines cannot be injected. Salt and hash are Base64, which cannot contain `:`.
- Case-insensitive uniqueness: usernames are normalized with `toLowerCase(Locale.ROOT)` (`UserAccountManager.java:133-136`), so the same name cannot be registered twice with different case, and locale-dependent lowercasing issues (e.g. the Turkish dotless i) are avoided.
- Temp-file handling: `Files.createTempFile` in the store's directory (`UserAccountManager.java:194`) uses a random name and exclusive creation (`CREATE_NEW`), and POSIX mode 0600 is applied before any data is written (`UserAccountManager.java:196-197`). There is no predictable-temp-file or symlink pre-creation attack. `Files.move` with `ATOMIC_MOVE` replaces a symlink at the destination rather than writing through it. The temp file is removed in `finally` (`UserAccountManager.java:203-205`).
- Plaintext password storage and logging: passwords are never written to disk or printed. Only the username appears in success messages (`UserAccountManager.java:285`, `301`).
- Sensitive memory handling on the normal path: `PBEKeySpec.clearPassword()` (`UserAccountManager.java:149`), zeroing of derived candidate hashes (`UserAccountManager.java:107`), and wiping of password and confirmation arrays in `finally` blocks (`UserAccountManager.java:290-293`, `306-308`, `311-315`). The no-console exception is covered in SEC-06.
- Password length cap at registration: 128-character maximum (`UserAccountManager.java:127-130`). The JDK's PBKDF2 keys HMAC once per derivation, so a long password at login does not multiply the per-iteration cost.
- Format-string safety: `Console.readLine("%s", prompt)` and `Console.readPassword("%s", prompt)` pass prompts as arguments, not format strings (`UserAccountManager.java:328`, `341`).
- Error handling and information leakage: the error messages shown (`UserAccountManager.java:237`, `286-289`) are the local user's own validation and I/O errors, with no stack traces or secrets. A structurally corrupt credentials file makes startup fail closed (`UserAccountManager.java:170-179`). Gaps in field validation are covered in SEC-02.
- Injection and other OWASP Top 10 categories: no SQL/NoSQL queries, OS command execution, reflection, Java deserialization (`ObjectInputStream`), XML parsing, network or TLS calls, HTML output (XSS), or JWT/session tokens exist in the code. These checks were not applicable, and nothing was found.
- File path input: the store path comes from the invoking user's own command-line argument (`UserAccountManager.java:232`). There is no privilege boundary, so path traversal through it is not a vulnerability in this context.
