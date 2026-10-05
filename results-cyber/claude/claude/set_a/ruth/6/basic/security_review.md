# Security Review: AuthenticationApp (Java user authentication component)

## 1. Executive Summary
`AuthenticationApp.java` is a self-contained Java 17 user authentication component with a command-line front end (`adduser`, `login`, `enable`, `disable`). It stores accounts in a flat file (`users.db`) holding PBKDF2-HMAC-SHA256 password hashes. It enforces a per-account lockout and writes an escaped, one-line-per-event audit log through `java.util.logging`.

The cryptographic core is sound. It uses PBKDF2-HMAC-SHA256 with 600,000 iterations, a 16-byte `SecureRandom` salt and constant-time comparison. Log-injection protection, generic failure messages, dummy-hash timing equalisation and fail-closed handling are also implemented correctly. No injection, deserialization or hard-coded secret issues were found.

The most important findings are:
- **SEC-01 (Medium):** The credential store loads `users.db` once and then rewrites the whole file from its in-memory copy. A long-running process therefore ignores `disable`, password resets and new accounts made by the separate CLI admin commands. Its next write puts the old state back, so an account disabled or reset after a compromise can still log in. Parallel processes can also bypass the lockout counter.
- **SEC-02 (Medium):** Data and log directories that already exist are used without checking who owns them, whether they are symbolic links, or their permissions. Log files are created with the process umask. This exposes the audit log, and in a shared working directory it exposes the credential store itself.
- **Low-severity issues:** Mistyped passwords are written to the audit log. Account existence leaks through timing caused by the store write. The fixed lockout can be used to deny service. The password policy is length-only. Passwords are echoed when no console is available.

This was a static review. No JVM was available to run the code.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthenticationApp.java` | The whole implementation: CLI entry point (`AuthenticationApp`), `AuthenticationService`, `UserAccount`, `FileCredentialStore`, `PasswordHasher`, `UsernamePolicy`, `LogSanitizer`, `AuditLog`, `SecureDirectories`, `Terminal` | Password hashing (PBKDF2, salt, RNG, constant-time compare); authentication decisions and account lockout; username enumeration defences; flat-file credential storage with atomic replace; file and directory permissions; audit logging and log-injection escaping; password input from console or stdin; concurrency (`synchronized`, `ConcurrentHashMap`) |
| `README.md` | Documentation of features, security measures, file formats, run instructions and limitations | Documents the intended threat model (single process, owner-only directories, example `-Dauth.logDir=/var/log/myapp`, stdin password fallback). Used to confirm intended behaviour. |
| `result.md` | Generation run metadata and summary of the implementation | No executable code; nothing security-relevant beyond restating README claims |
| `return.txt` | JSON run record from the generating tool | No executable code; no secrets found |
| `prompt.txt` | Original implementation request | No executable code |
| `cyber_prompt.txt` | This review task's instructions | No executable code |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: The router workflow. It was used to inventory the files, pick out security-relevant behaviour (password hashing, authentication and lockout, credential storage, logging, concurrency, file permissions, terminal input) and choose the specialised skills below.
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher` (`AuthenticationApp.java:457-508`). Checked the algorithm choice, KDF iteration count, salt size and source, output length, constant-time comparison, hard-coded keys and secrets, and RNG use. No finding. Details are in section 6.
- `testing-api-authentication-weaknesses`: Applied to `AuthenticationService.authenticate` and `setPassword` (`AuthenticationApp.java:230-332`) and the CLI login flow. Checked password policy strength (SEC-06), account enumeration through responses and timing (SEC-04), brute-force and lockout behaviour (SEC-05) and credential leakage into logs (SEC-03). The skill's JWT, token and session steps do not apply because the component issues no tokens.
- `exploiting-race-condition-vulnerabilities`: Applied to the lockout counter and account state changes in `AuthenticationService` and `FileCredentialStore` (`AuthenticationApp.java:250-303, 398-454`). Checked TOCTOU and limit-overrun on login attempts and multi-step state changes (SEC-01). In-process thread safety was verified as correct.
- `testing-for-sensitive-data-exposure`: Applied to the credential file, audit log contents and file permissions (`AuthenticationApp.java:428-453, 562-609`). Checked for sensitive data in logs and insecure storage at rest (SEC-02, SEC-03).
- General OWASP Top 10 / CWE knowledge (no library skill matched): filesystem trust, symlinks and permissions on pre-existing directories (CWE-732 / CWE-59); log injection neutralisation (CWE-117); password masking at the terminal (CWE-549); lockout-based denial of service (CWE-645); flat-file record delimiter injection; and injection, deserialization and command execution sinks (none present).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Credential store works from a stale in-memory snapshot: disable, reset and lockout changes from other processes are ignored and overwritten | Medium | CWE-362 | `AuthenticationApp.java:403-431` |
| SEC-02 | Pre-existing data/log directories trusted without owner, symlink or permission checks; log files created with the umask | Medium | CWE-732 | `AuthenticationApp.java:599-608` |
| SEC-03 | Rejected or unknown usernames, often mistyped passwords, are written to the audit log | Low | CWE-532 | `AuthenticationApp.java:233-247` |
| SEC-04 | Store rewrite on failed logins for existing accounts creates a timing oracle for username enumeration | Low | CWE-208 | `AuthenticationApp.java:244-294` |
| SEC-05 | Fixed per-account lockout lets any caller lock a known user out indefinitely | Low | CWE-645 | `AuthenticationApp.java:283-289` |
| SEC-06 | Password policy checks length only (no blocklist of common or breached passwords) | Low | CWE-521 | `AuthenticationApp.java:315-318` |
| SEC-07 | Password is echoed and kept as an immutable String when no console is attached | Low | CWE-549 | `AuthenticationApp.java:627-637` |

## 5. Detailed Findings

### SEC-01: Credential store works from a stale in-memory snapshot: disable, reset and lockout changes from other processes are ignored and overwritten
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `AuthenticationApp.java:403-406`, `AuthenticationApp.java:424-431` (used by `AuthenticationApp.java:243-256`, `AuthenticationApp.java:83`)

**Vulnerable code:**
```java
// AuthenticationApp.java:403-406
    FileCredentialStore(Path file, Logger audit) throws IOException {
        this.file = file.toAbsolutePath();
        if (Files.exists(this.file)) {
            List<String> lines = Files.readAllLines(this.file, StandardCharsets.UTF_8);
// AuthenticationApp.java:424-431
    Optional<UserAccount> find(String normalizedUsername) {
        return Optional.ofNullable(accounts.get(normalizedUsername));
    }

    synchronized void save(UserAccount account) throws IOException {
        Map<String, UserAccount> updated = new TreeMap<>(accounts);
        updated.put(account.username(), account);

```

**Why it is a problem:** `users.db` is read once, in the constructor. After that, every `find()` answers from the in-memory map, and every `save()` writes the entire in-memory map back over the file. The only supported way to administer accounts is the `adduser`, `disable` and `enable` CLI commands, which always run as a separate JVM process. The README also shows embedding the service in an application. In that deployment:
1. The application loads `alice` (enabled, hash H1).
2. After a suspected compromise, an administrator runs `disable alice` or `adduser alice` to reset the password. The file on disk is updated.
3. The application still has `enabled=true` and hash H1 in memory. The attacker logs in with the old password and gets `SUCCESS`, because a successful login with zero failures never writes or re-reads the file.
4. The next failed login for *any* user calls `save()`, which writes the stale map to disk. `alice` is re-enabled and hash H1 comes back. Accounts created by the CLI in the meantime are deleted.

The lockout has the same weakness. Every `login` process starts with the counter it read at startup and never re-reads it. Many processes launched in parallel each get `MAX_CLI_LOGIN_ATTEMPTS` guesses against a counter that still reads 0, and the last writer wins. This breaks the "5 failures lock the account" guarantee. The README's advice not to run several processes against the same file does not help, because the design's own admin commands require it. The result is that access cannot be revoked (OWASP A07 Identification and Authentication Failures).

**Fix:** Serialise every read-modify-write across processes with an OS file lock, and re-read the file under that lock before each authentication decision and each update. Never write from a cached copy. For multi-process or high-volume use, switch to a database with row-level transactions.
```java
/** Persists accounts in a flat file; every read and update re-loads the file under an OS-level lock. */
final class FileCredentialStore {

    @FunctionalInterface
    interface AccountUpdate<T> {
        T apply(Map<String, UserAccount> accounts) throws IOException;
    }

    private final Path file;
    private final Path lockFile;
    private final Logger audit;

    FileCredentialStore(Path file, Logger audit) throws IOException {
        this.file = file.toAbsolutePath();
        this.lockFile = this.file.resolveSibling(".users.lock");
        this.audit = audit;
        SecureDirectories.create(this.file.getParent());
    }

    Optional<UserAccount> find(String normalizedUsername) throws IOException {
        return withLock(false, accounts -> Optional.ofNullable(accounts.get(normalizedUsername)));
    }

    /** Runs {@code update} on a fresh copy of the file and writes the result back while still holding the lock. */
    <T> T update(AccountUpdate<T> update) throws IOException {
        return withLock(true, accounts -> {
            T result = update.apply(accounts);
            write(accounts);
            return result;
        });
    }

    private <T> T withLock(boolean exclusive, AccountUpdate<T> action) throws IOException {
        synchronized (this) {
            try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                         StandardOpenOption.READ, StandardOpenOption.WRITE);
                 FileLock lock = channel.lock(0L, Long.MAX_VALUE, !exclusive)) {
                return action.apply(load()); // always re-read: never trust a cached copy
            }
        }
    }

    private Map<String, UserAccount> load() throws IOException { /* existing parsing loop, returns a TreeMap */ }

    private void write(Map<String, UserAccount> accounts) throws IOException { /* existing temp-file + atomic move */ }
}
```
`AuthenticationService` then makes each decision inside `store.update(accounts -> { ... })`. It checks enabled, lock and hash-unchanged against the freshly loaded record and updates the counter in the same locked transaction. The expensive PBKDF2 step can stay outside the lock, as the code does today.

### SEC-02: Pre-existing data/log directories trusted without owner, symlink or permission checks; log files created with the umask
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AuthenticationApp.java:599-608`, `AuthenticationApp.java:578` (directories chosen at `AuthenticationApp.java:62-63`)

**Vulnerable code:**
```java
// AuthenticationApp.java:599-608
    static void create(Path dir) throws IOException {
        if (Files.isDirectory(dir)) {
            return;
        }
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(dir);
        }
    }
// AuthenticationApp.java:578
        FileHandler handler = new FileHandler(dir.resolve("auth%g.log").toString(), MAX_FILE_BYTES, FILE_COUNT, true);
```

**Why it is a problem:** Owner-only permissions (`rwx------`) are applied only when the code creates the directory. If `data/` or `logs/` already exists, `Files.isDirectory` (which follows symbolic links) returns early. Its owner, group/other permissions and symlink status are never checked. The defaults are relative to the current working directory. Two problems follow:
- **Tampering with the credential store.** If the tool runs from a shared or world-writable directory, another local user can create `data` first, as their own directory or as a symlink to one. That user controls directory entries, so they can swap `users.db` for a file with their own account and hash, or read the hashes written there. The temp-file-then-rename pattern does not protect a file inside a directory the attacker owns.
- **Readable audit logs.** `FileHandler` creates `auth0.log` and `auth0.log.lck` with the process umask, typically `rw-r--r--`. The README's example `-Dauth.logDir=/var/log/myapp` usually points at a pre-created `0755` directory, so the audit log is world-readable. That log holds usernames, OS user names, lockout state and, per SEC-03, mistyped passwords.

The README's claim that the directories are owner-only therefore holds only on first creation.

**Fix:** Refuse symlinks and reject existing directories that the current user does not own or that grant any group/other access. Enforcing `0700` on the directory also protects log files created with a permissive umask.
```java
    static void create(Path dir) throws IOException {
        boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Refusing to use a non-directory or symbolic link: " + dir);
            }
        } else if (posix) {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(dir);
        }
        if (posix) {
            UserPrincipal self = dir.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));
            if (!Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS).equals(self)) {
                throw new IOException("Directory is not owned by the current user: " + dir);
            }
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS);
            boolean shared = perms.stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"));
            if (shared) {
                throw new IOException("Directory must not be accessible to group/other (expected rwx------): " + dir);
            }
        }
    }
```
Also resolve the default `data`/`logs` locations against a fixed, per-user or application-owned base directory instead of the current working directory.

### SEC-03: Rejected or unknown usernames, often mistyped passwords, are written to the audit log
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `AuthenticationApp.java:233-247`

**Vulnerable code:**
```java
// AuthenticationApp.java:233-247
        if (username == null || !UsernamePolicy.isValid(username)
                || password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            audit.warning("event=AUTH_FAILURE user=" + LogSanitizer.quote(username)
                    + " source=" + logSource + " reason=MALFORMED_INPUT");
            return AuthResult.INVALID_CREDENTIALS;
        }

        String key = UsernamePolicy.normalize(username);
        String logUser = LogSanitizer.quote(key);

        Optional<UserAccount> snapshot = store.find(key);
        if (snapshot.isEmpty()) {
            hasher.verify(password, dummyHash);
            audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource + " reason=UNKNOWN_USER");
```

**Why it is a problem:** A common user error is typing the password into the `Username:` prompt, for example after an unexpected re-prompt in the 3-attempt CLI loop. Passwords usually contain characters such as spaces, `!`, `#` or `$` that fail `UsernamePolicy`. Those values reach the `MALFORMED_INPUT` branch and are logged escaped but otherwise verbatim, up to 128 characters. Password-like values that do match the username pattern are logged, lower-cased, in the `UNKNOWN_USER` branch. A log line holds the cleartext password, and the matching `AUTH_SUCCESS` line from the same source a few seconds later identifies the account. The README acknowledges this but leaves it unfixed, and SEC-02 makes those logs readable by other users.

**Fix:** Never log a value that failed username validation or that matched no account. Log a marker instead. If correlation is needed, log a keyed HMAC fingerprint (the key is held outside the log) rather than the raw string.
```java
        if (username == null || !UsernamePolicy.isValid(username)
                || password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            // Do not log the submitted value: input that fails the username policy is frequently a mistyped password.
            audit.warning("event=AUTH_FAILURE user=\"-\" source=" + logSource + " reason=MALFORMED_INPUT");
            return AuthResult.INVALID_CREDENTIALS;
        }

        String key = UsernamePolicy.normalize(username);
        String logUser = LogSanitizer.quote(key);

        Optional<UserAccount> snapshot = store.find(key);
        if (snapshot.isEmpty()) {
            hasher.verify(password, dummyHash);
            audit.warning("event=AUTH_FAILURE user=\"<unknown>\" source=" + logSource + " reason=UNKNOWN_USER");
            return AuthResult.INVALID_CREDENTIALS;
        }
```

### SEC-04: Store rewrite on failed logins for existing accounts creates a timing oracle for username enumeration
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `AuthenticationApp.java:244-248`, `AuthenticationApp.java:290-294`

**Vulnerable code:**
```java
// AuthenticationApp.java:244-248
        if (snapshot.isEmpty()) {
            hasher.verify(password, dummyHash);
            audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource + " reason=UNKNOWN_USER");
            return AuthResult.INVALID_CREDENTIALS;
        }
// AuthenticationApp.java:290-294
                } else {
                    store.save(account.withLoginState(failures, Instant.EPOCH));
                    audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource
                            + " reason=BAD_PASSWORD failedAttempts=" + failures + "/" + MAX_FAILED_ATTEMPTS);
                }
```

**Why it is a problem:** The dummy-hash check hides the PBKDF2 cost, but only a wrong password for an *existing* account then calls `store.save()`. That call copies the whole account map into a `TreeMap`, serialises every record, creates a temp file, writes it and renames it. The extra latency is disk-dependent and grows linearly with the number of accounts, and the unknown-user path never incurs it. Averaged over a few requests, that is enough to tell valid usernames apart, which defeats the README's "No username enumeration" control. A write failure also returns `SYSTEM_ERROR` ("temporarily unavailable") only for existing accounts.

**Fix:** Make every non-success result take the same wall-clock time by padding to a fixed floor that is longer than hash plus store write. Run the current logic in a private method.
```java
    /** Every failed attempt takes at least this long, hiding hash, store-write and lookup differences. */
    static final Duration FAILURE_RESPONSE_FLOOR = Duration.ofSeconds(2);

    AuthResult authenticate(String username, char[] password, String source) {
        long deadline = System.nanoTime() + FAILURE_RESPONSE_FLOOR.toNanos();
        AuthResult result = authenticateInternal(username, password, source); // the existing method body
        if (result != AuthResult.SUCCESS) {
            long remaining;
            while ((remaining = deadline - System.nanoTime()) > 0) {
                java.util.concurrent.locks.LockSupport.parkNanos(remaining);
            }
        }
        return result;
    }
```

### SEC-05: Fixed per-account lockout lets any caller lock a known user out indefinitely
- **Severity:** Low
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `AuthenticationApp.java:283-289` (enforced at `AuthenticationApp.java:268-272`)

**Vulnerable code:**
```java
// AuthenticationApp.java:283-289
                int failures = account.failedAttempts() + 1;
                if (failures >= MAX_FAILED_ATTEMPTS) {
                    Instant lockedUntil = now.plus(LOCKOUT_DURATION);
                    store.save(account.withLoginState(0, lockedUntil));
                    audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource
                            + " reason=BAD_PASSWORD failedAttempts=" + failures + "/" + MAX_FAILED_ATTEMPTS);
                    audit.warning("event=ACCOUNT_LOCKED user=" + logUser + " lockedUntil=" + lockedUntil);
```

**Why it is a problem:** The lockout is keyed only on the account and does not consider the source. Anyone who knows or guesses a username can send 5 bad passwords every 15 minutes and keep that user locked out forever. While locked, the legitimate user's correct password is rejected (lines 268-272), and only an administrator's `enable` clears it. Because the counter is reset to `0` when the lock is set, a patient attacker also gets a steady 480 guesses per account per day. There is no escalation and no alerting threshold. The README notes this but offers no mitigation in code. The `source` parameter is accepted and logged but never used for throttling.

**Fix:** Throttle by account plus source first, so one source cannot lock a user out everywhere. Keep a higher account-wide threshold for distributed attacks, and do not reset the account counter when a lock is applied, so repeated locks can escalate.
```java
    static final int MAX_FAILURES_PER_SOURCE = 5;
    static final int MAX_FAILURES_PER_ACCOUNT = 50;

    private record Throttle(int failures, Instant resetAt) {
    }

    private final Map<String, Throttle> sourceThrottle = new ConcurrentHashMap<>();

    private boolean sourceBlocked(String throttleKey, Instant now) {
        Throttle t = sourceThrottle.get(throttleKey);
        return t != null && t.resetAt().isAfter(now) && t.failures() >= MAX_FAILURES_PER_SOURCE;
    }

    private void recordSourceFailure(String throttleKey, Instant now) {
        sourceThrottle.compute(throttleKey, (k, t) -> (t == null || !t.resetAt().isAfter(now))
                ? new Throttle(1, now.plus(LOCKOUT_DURATION))
                : new Throttle(t.failures() + 1, t.resetAt()));
    }

    // In authenticate(), inside the synchronized block before evaluating passwordMatches:
    //     String throttleKey = key + "|" + source;
    //     if (sourceBlocked(throttleKey, now)) { audit...; return AuthResult.ACCOUNT_LOCKED; }
    // On success: sourceThrottle.remove(throttleKey);
    // On failure:
                recordSourceFailure(throttleKey, now);
                int failures = account.failedAttempts() + 1; // cumulative, not reset when a lock is applied
                if (failures % MAX_FAILURES_PER_ACCOUNT == 0) {
                    long multiplier = Math.min(1L << Math.min(failures / MAX_FAILURES_PER_ACCOUNT - 1, 6), 64L);
                    Instant lockedUntil = now.plus(LOCKOUT_DURATION.multipliedBy(multiplier));
                    store.save(account.withLoginState(failures, lockedUntil));
                    audit.warning("event=ACCOUNT_LOCKED user=" + logUser + " lockedUntil=" + lockedUntil);
                } else {
                    store.save(account.withLoginState(failures, account.lockedUntil()));
                }
```
Internet-facing deployments should also add per-IP rate limiting, CAPTCHA or MFA, and alert on `ACCOUNT_LOCKED`.

### SEC-06: Password policy checks length only (no blocklist of common or breached passwords)
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `AuthenticationApp.java:315-318`

**Vulnerable code:**
```java
// AuthenticationApp.java:315-318
        if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be between " + MIN_PASSWORD_LENGTH
                    + " and " + MAX_PASSWORD_LENGTH + " characters.");
        }
```

**Why it is a problem:** The only rule is 12-1024 characters. Values such as `aaaaaaaaaaaa`, `123456789012`, `passwordpassword`, the username repeated, or well-known breached passwords like `Password1234` are accepted. NIST SP 800-63B requires new passwords to be checked against a list of commonly used, expected or compromised values. Without that check, the 5-guesses-per-15-minutes lockout (SEC-05) still lets dictionary guessing succeed against weak accounts.

**Fix:** Keep the length limits, and also reject blocklisted passwords and passwords that contain the username. The blocklist can be a local breached-password corpus or a k-anonymity range lookup.
```java
        String key = UsernamePolicy.normalize(username);
        if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be between " + MIN_PASSWORD_LENGTH
                    + " and " + MAX_PASSWORD_LENGTH + " characters.");
        }
        if (PasswordBlocklist.contains(password) || containsIgnoreCase(password, key) || isSingleRepeatedChar(password)) {
            throw new IllegalArgumentException("Password is too common, contains the username, or is a repeated character.");
        }
```
```java
    private static boolean isSingleRepeatedChar(char[] password) {
        for (int i = 1; i < password.length; i++) {
            if (password[i] != password[0]) {
                return false;
            }
        }
        return true;
    }

    /** Case-insensitive search for the (already lower-case ASCII) username without creating a String copy of the password. */
    private static boolean containsIgnoreCase(char[] password, String lowerNeedle) {
        outer:
        for (int i = 0; i + lowerNeedle.length() <= password.length; i++) {
            for (int j = 0; j < lowerNeedle.length(); j++) {
                if (Character.toLowerCase(password[i + j]) != lowerNeedle.charAt(j)) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
```
```java
/** Rejects passwords found in a breached/common-password corpus (one SHA-1 hex digest per line). */
final class PasswordBlocklist {
    private static final Set<String> DIGESTS = load(Paths.get(System.getProperty("auth.blocklist", "data/pwned-sha1.txt")));

    static boolean contains(char[] password) {
        try {
            byte[] utf8 = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password)).array();
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(utf8);
            Arrays.fill(utf8, (byte) 0);
            return DIGESTS.contains(java.util.HexFormat.of().formatHex(digest));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Set<String> load(Path path) { /* read lines into a HashSet; empty set + warning if absent */ }
}
```
SHA-1 is used only as a lookup key into the breach corpus, matching its published format. It is not used for password storage.

### SEC-07: Password is echoed and kept as an immutable String when no console is attached
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `AuthenticationApp.java:627-637`

**Vulnerable code:**
```java
// AuthenticationApp.java:627-637
    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        if (!warned) {
            System.err.println("Warning: no interactive console; reading password from standard input.");
            warned = true;
        }
        String line = readLine(prompt);
        return line == null ? null : line.toCharArray();
    }
```

**Why it is a problem:** On the supported JDKs (17-21), `System.console()` returns `null` whenever stdout or stdin is redirected, even if the user is typing at a real terminal. Examples are `java ... login | tee session.txt`, running under IDEs, or wrappers that capture output. In those cases the code silently falls back to `BufferedReader.readLine()`. The password is echoed on screen, visible to shoulder-surfers, and kept in terminal scrollback and screen recordings. It is also read into an immutable `String` that cannot be wiped, which defeats the `wipe()` calls in `addUser`/`login` (CWE-316). The warning goes to stderr only after the choice has been made and does not stop the prompt.

**Fix:** Do not fall back automatically. Allow stdin passwords only when the operator explicitly opts in for non-interactive automation, and read them into a `char[]` without creating a `String`.
```java
    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        if (!Boolean.getBoolean("auth.allowStdinPassword")) {
            throw new IOException("No interactive console: refusing to read a password that could be echoed. "
                    + "Use -Dauth.allowStdinPassword=true only for piped, non-interactive input.");
        }
        char[] buf = new char[AuthenticationService.MAX_PASSWORD_LENGTH + 1];
        int len = 0;
        int c;
        BufferedReader in = stdin();
        while ((c = in.read()) != -1 && c != '\n') {
            if (len == buf.length) {
                Arrays.fill(buf, '\0');
                throw new IOException("Password too long.");
            }
            buf[len++] = (char) c;
        }
        if (c == -1 && len == 0) {
            return null;
        }
        if (len > 0 && buf[len - 1] == '\r') {
            len--;
        }
        char[] result = Arrays.copyOf(buf, len);
        Arrays.fill(buf, '\0');
        return result;
    }
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm and parameters:** `PasswordHasher` (`AuthenticationApp.java:457-508`) uses PBKDF2WithHmacSHA256 with 600,000 iterations, which meets the OWASP Password Storage Cheat Sheet recommendation. It uses a 16-byte salt per password and 256-bit output. No MD5, SHA-1, DES, ECB or unsalted hashing is used for storage.
- **Randomness:** Salts come from `java.security.SecureRandom` (`AuthenticationApp.java:465, 469-470`). No `java.util.Random`, time-based seeds or predictable IVs are present.
- **Constant-time comparison:** `MessageDigest.isEqual(expected, actual)` (`AuthenticationApp.java:495`). No `equals`/`Arrays.equals` on secrets. `Arrays.equals` at line 110 only compares the two typed confirmations locally.
- **Hard-coded secrets:** None. The only literal is the non-secret dummy password `"timing-equalization-placeholder"` (`AuthenticationApp.java:226`). Its hash is regenerated with a random salt on each start and is only ever compared on the unknown-user path, whose result is discarded. Knowing the dummy password grants no access.
- **Stored hash parameters:** `verify()` rejects an unknown scheme, malformed Base64, iterations below 1, and an empty salt or hash (`AuthenticationApp.java:476-493`). A tampered `users.db` could lower the iteration count or set a huge key length, but that needs write access to an owner-only file. Such an attacker could replace hashes outright, so this is noted as hardening only: enforce a minimum and maximum iteration count and a 256-bit length, and rehash on login when parameters are below current values.
- **In-memory secret handling:** Password `char[]` buffers are wiped in `finally` blocks (`AuthenticationApp.java:121-124, 153-155`), and `PBEKeySpec.clearPassword()` is called (`AuthenticationApp.java:505`). The stdin path is the exception (SEC-07).
- **Generic failure messages / enumeration via output:** Unknown user, bad password, locked and disabled all print the same message and exit code 1 (`AuthenticationApp.java:148-151`). The CLI's `no such account` message (`AuthenticationApp.java:162`) is only on the administrative `disable`/`enable` path.
- **Timing equalisation of hash work:** Unknown users are verified against a dummy hash of the same cost (`AuthenticationApp.java:244-245`). Locked and disabled accounts still run the full hash before their state is checked (`AuthenticationApp.java:250-252`). The remaining store-write difference is SEC-04.
- **Lockout enforcement ordering:** Disabled and locked checks come before the success branch, so a correct password is refused during a lockout (`AuthenticationApp.java:264-272`). If the password hash changed during verification, the match is discarded (`AuthenticationApp.java:261-263`).
- **Fail-closed behaviour:** An `IOException` while saving lockout state returns `SYSTEM_ERROR`, never `SUCCESS` (`AuthenticationApp.java:296-301`).
- **In-process thread safety:** `authenticate`, `setPassword` and `setEnabled` synchronise on the `store` instance, which is the same monitor as `synchronized save()`. The account map is a `ConcurrentHashMap`. The read-check-increment of `failedAttempts` is atomic within one JVM (`AuthenticationApp.java:255-302, 428`). The cross-process problem is SEC-01.
- **Log injection / forging (CWE-117):** Every untrusted value (username, source, exception text, file path) goes through `LogSanitizer.quote`. It escapes `"` and `\`, encodes ISO control characters, spaces, U+2028/U+2029 and Unicode FORMAT characters as `\uXXXX`, and truncates to 128 characters (`AuthenticationApp.java:537-558`). Non-sanitised values (`lockedUntil`, counters, the `failures` integer) are generated internally. The custom formatter writes one line per record (`AuthenticationApp.java:580-587`).
- **Credential file record injection:** Usernames are restricted to `[A-Za-z0-9._@-]{3,64}` (`AuthenticationApp.java:514`), so they cannot contain the `:` delimiter or newlines. Hashes are Base64 with `$` separators. `parse()` re-validates every field when loading (`AuthenticationApp.java:381-394`). The `Locale.ROOT` lower-casing (`AuthenticationApp.java:525`) avoids locale-dependent case-folding collisions such as the Turkish dotless i, and the ASCII-only pattern prevents homoglyph usernames.
- **Credential file permissions and atomic write:** `users.db` is written through `Files.createTempFile` (POSIX `rw-------`) and an atomic `REPLACE_EXISTING` move, and the temp file is removed in `finally` (`AuthenticationApp.java:441-451`). The resulting file is owner-only regardless of umask. Directory trust is SEC-02.
- **Sensitive data in the store and logs:** No cleartext passwords are stored. Malformed store lines are not logged because they may contain a hash (`AuthenticationApp.java:415-418`). Passwords are never passed to the logger. Mistyped passwords in the username field are SEC-03.
- **Input length limits / resource exhaustion:** Passwords are capped at 1024 characters on both `authenticate` and `setPassword` (`AuthenticationApp.java:234, 315`), which bounds PBKDF2 input cost. Usernames are capped at 64 characters. Log files rotate at 10 MB × 5 (`AuthenticationApp.java:564-565`).
- **Injection sinks (SQL, OS command, path traversal, deserialization, XML, SSRF):** None present. No database, `Runtime.exec`/`ProcessBuilder`, `ObjectInputStream`, XML parser or network calls. File paths come only from operator-controlled system properties (`AuthenticationApp.java:62-63`), with a fixed file name `users.db`.
- **Error handling / information disclosure:** CLI errors print only `e.getMessage()` for `IOException` (`AuthenticationApp.java:89-91`) and do not print stack traces or hashes. Exception detail written to the log is sanitised (`AuthenticationApp.java:299`).
- **Tokens / sessions / JWT:** Not applicable. The component returns an `AuthResult` and issues no session identifiers or tokens, so the JWT, token-lifetime and revocation checks from `testing-api-authentication-weaknesses` do not apply.
- **Non-code files:** `README.md`, `result.md`, `return.txt`, `prompt.txt`, `cyber_prompt.txt` and `prompt_hash.txt` were reviewed for embedded credentials, keys or tokens. None were found; the only password-like value is the documentation example `Correct-Horse-Battery` in `README.md`.
