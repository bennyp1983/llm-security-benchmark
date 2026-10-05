# Security Review: AdminPortal (Java command-line administrator portal)

## 1. Executive Summary
`AdminPortal.java` is a single-file Java 17 console program. It authenticates administrators against a local credential file (`admins.db`) and then offers an admin menu: list, add and remove administrators, change your own password, and view the audit log (`admin-audit.log`). Its core cryptography is sound. It uses PBKDF2-HMAC-SHA256 with 600,000 iterations and a 16-byte `SecureRandom` salt, compares hashes in constant time, runs a dummy hash for unknown users, shows one generic error message, and has no hard-coded credentials.

The weaknesses are in how the authentication is designed around that core:

- **SEC-01 (Medium):** whenever the credential store is empty or missing, anyone who runs the program can create an administrator without logging in. Both data files use paths relative to the working directory, so the store is easy to make empty.
- **SEC-02 (Medium):** the three-attempt limit only lives inside one process. Restarting the program, or running many copies at once, allows unlimited password guessing.
- **SEC-03 (Medium):** each session loads the credential file once and later overwrites the whole file, with no locking. An administrator who was removed keeps their session, and their next save can bring deleted accounts back.
- **Low findings:** there is no inactivity timeout or re-authentication before privileged actions. Hashing parameters read from the file are not validated. The audit log is created in a non-atomic way that follows symlinks, and no permission checks are made. When no terminal is available, passwords are echoed and held in immutable `String`s.

No injection, deserialization, command-execution or network issues exist because the program has none of those features.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AdminPortal.java` | The whole application: login loop, admin menu, credential store, audit log, file permission helper, console input | Password hashing (PBKDF2), salt/RNG, constant-time comparison, login attempt limiting, first-run admin bootstrap, account add/remove/password change, reading and writing `admins.db` (Java `Properties`, temp file plus atomic move), creating/appending/reading `admin-audit.log`, POSIX permission setting, password input with and without a console, clearing passwords from memory |
| `README.md` | Plain-English user documentation | Describes the security design and known limitations (per-run attempt limit, protecting `admins.db`, echoed passwords without a terminal). Used to confirm intended behaviour; not executable |
| `result.md`, `return.txt` | Metadata and summary from the generation run | No code; nothing security-relevant besides restating the design |
| `prompt.txt`, `cyber_prompt.txt` | Task prompts used to generate and review the code | No code |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: router workflow. Read and characterised every file, extracted keywords (password hashing, authentication, brute force, session, file permissions, race condition, audit log, sensitive data) and selected the specialised skills below.
- `performing-cryptographic-audit-of-application`: applied to PBKDF2 algorithm and parameters, salt generation, RNG, constant-time comparison, hard-coded secrets, and validation of KDF parameters read from `admins.db` (SEC-05).
- `testing-api-authentication-weaknesses`: its authentication checklist (missing authentication, brute-force/credential-stuffing resistance, password policy, account enumeration, session lifetime and revocation) applied to the console login, first-run bootstrap and admin session (SEC-01, SEC-02, SEC-04).
- `exploiting-race-condition-vulnerabilities`: its TOCTOU and limit-overrun concepts applied to the per-process attempt limit, concurrent sessions sharing `admins.db`, and check-then-create of the audit log (SEC-02, SEC-03, SEC-06).
- `testing-for-sensitive-data-exposure`: applied to insecure local storage of credential and audit files, error-message leakage, and passwords in memory and on screen (SEC-06, SEC-07).
- General OWASP Top 10 / CWE knowledge: used for local file-system concerns that no library skill covers (symlink following CWE-59, permissions CWE-732, relative data paths). Also used to confirm that no SQL, OS command, deserialization, XML, network/TLS or format-string surface exists.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unauthenticated first-run admin creation whenever the credential store is empty or missing (cwd-relative paths) | Medium | CWE-306 | `AdminPortal.java:81` |
| SEC-02 | Login attempt limit is per process and resets on restart, so brute force is unlimited | Medium | CWE-307 | `AdminPortal.java:106` |
| SEC-03 | Unlocked, stale credential store: concurrent sessions overwrite each other; removed admins keep access and can restore accounts | Medium | CWE-362 | `AdminPortal.java:471` |
| SEC-04 | No idle timeout on admin session and no re-authentication before adding or removing administrators | Low | CWE-613 | `AdminPortal.java:155` |
| SEC-05 | KDF parameters (iteration count, salt and hash length) from `admins.db` not validated | Low | CWE-1284 | `AdminPortal.java:418` |
| SEC-06 | Audit log created with default permissions and then chmod-ed, follows symlinks, and data-file permissions never checked | Low | CWE-732 | `AdminPortal.java:374` |
| SEC-07 | Without a console, passwords are echoed and kept in immutable Strings | Low | CWE-316 | `AdminPortal.java:529` |

## 5. Detailed Findings

### SEC-01: Unauthenticated first-run admin creation whenever the credential store is empty or missing (cwd-relative paths)
- **Severity:** Medium
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `AdminPortal.java:44-45`, `AdminPortal.java:81-89`, `AdminPortal.java:445`

**Vulnerable code:**
```java
// AdminPortal.java:44-45
    private static final Path CREDENTIALS_FILE = Paths.get("admins.db");
    private static final Path AUDIT_LOG = Paths.get("admin-audit.log");
// AdminPortal.java:81-89
        if (store.isEmpty()) {
            System.out.println("No administrator accounts exist yet. Let's create the first one.");
            String created = createAdmin();
            if (created == null) {
                System.out.println("Setup cancelled. Exiting.");
                return;
            }
            audit("SETUP", created, "initial administrator created");
        }
```

**Why it is a problem:** Creating an administrator is the most privileged action in the program, yet it needs no authentication whenever `CredentialStore.load` finds no file (`Files.exists(file)` at line 445) or an empty one. The program then goes straight to the login it has just set up for the caller, and the caller receives "Access granted".

Both data paths are relative to the working directory, so this state is easy to reach:
- Running `java AdminPortal` from any other directory produces a fresh, empty store.
- Anyone with write access to the directory can delete or rename `admins.db`. The file's 0600 mode does not stop this, because deleting a file needs only directory write permission. The next run then lets that person become the "first" administrator.

The program never distinguishes an intentional first install from a missing, moved or tampered credential file. It fails open instead of refusing to start.

**Fix:** Keep the data in a fixed, absolute, owner-only directory. Make bootstrap an explicit, separate action (an `--init` flag run by the service owner) that only works when the file does not exist yet. At every normal start, a missing or empty store must be a fatal error.
```java
private static final Path DATA_DIR =
        Paths.get(System.getProperty("adminportal.dir", "/var/lib/adminportal")).toAbsolutePath();
private static final Path CREDENTIALS_FILE = DATA_DIR.resolve("admins.db");
private static final Path AUDIT_LOG = DATA_DIR.resolve("admin-audit.log");

public static void main(String[] args) {
    boolean init = args.length == 1 && args[0].equals("--init");
    try {
        FileSecurity.verifyPrivateDirectory(DATA_DIR); // owned by current user, not group/other writable
        if (!init && !Files.exists(CREDENTIALS_FILE, LinkOption.NOFOLLOW_LINKS)) {
            System.err.println("Credential store " + CREDENTIALS_FILE + " is missing. Refusing to start.");
            System.exit(1);
        }
        AdminPortal portal = new AdminPortal(CredentialStore.load(CREDENTIALS_FILE), new Input());
        portal.run(init);
    } catch (IOException e) {
        System.err.println("Error: could not access portal data files (" + e.getMessage() + ").");
        System.exit(1);
    }
}

private void run(boolean init) throws IOException {
    System.out.println("=== Administrator Portal ===");
    if (store.isEmpty()) {
        if (!init) {
            audit("SETUP_REFUSED", "<none>", "credential store empty");
            System.err.println("No administrator accounts exist. Run 'java AdminPortal --init' as the service owner.");
            return;
        }
        String created = createAdmin();
        if (created == null) {
            System.out.println("Setup cancelled. Exiting.");
            return;
        }
        audit("SETUP", created, "initial administrator created");
    } else if (init) {
        System.err.println("--init refused: administrator accounts already exist.");
        return;
    }
    // ... login() and adminMenu() as before
}
```

### SEC-02: Login attempt limit is per process and resets on restart, so brute force is unlimited
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AdminPortal.java:52-53`, `AdminPortal.java:106-138` (also `AdminPortal.java:274-278` for current-password re-checks)

**Vulnerable code:**
```java
// AdminPortal.java:106-138
        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            System.out.println();
            String username = input.readLine("Username: ");
            if (username == null) {
                return null; // end of input
            }
            username = username.trim();

            char[] password = input.readPassword("Password: ");
            if (password == null) {
                return null;
            }

            boolean ok;
            try {
                ok = authenticate(username, password);
            } finally {
                Arrays.fill(password, '\0');
            }

            String logName = USERNAME_PATTERN.matcher(username).matches() ? username : "<invalid>";
            if (ok) {
                audit("LOGIN_SUCCESS", logName, "");
                return username;
            }

            audit("LOGIN_FAILURE", logName, "attempt " + attempt);
            // Same message whether the username or the password was wrong.
            System.out.println("Invalid username or password.");
            sleepQuietly(FAILURE_DELAY_MS * attempt);
        }
        System.out.println("Too many failed attempts.");
        return null;
```

**Why it is a problem:** The attempt counter and growing delay live only in the local variable `attempt`. Nothing is stored between runs, so the limit does not survive a restart. An attacker who can run the program can script it through stdin; the non-console path at lines 508-518 accepts piped input. Starting a new process for each guess, or running many in parallel, skips the 2 s/4 s delays entirely. The only brake left is PBKDF2 cost (roughly 0.3-1 s per guess per core), which still allows thousands of guesses per hour against an admin account. The failures are logged but never acted on.

The same issue appears inside a session: `changePassword` re-checks the current password with only a 2 s delay and no limit. Someone at an unattended logged-in terminal can therefore guess the password without limit. This is the limit-overrun pattern from the race-condition skill, where a rate limit held in volatile per-request state can be bypassed by making many independent attempts.

**Fix:** Keep a failure counter per account (plus one bucket for invalid names) in a locked, owner-only file. Check it before hashing and apply an escalating lockout. Use the same check for the current-password prompt in `changePassword`.
```java
/** Failed-login counters that survive restarts and are shared by concurrent processes. */
static final class LoginThrottle {
    private static final Path FILE = DATA_DIR.resolve("login-throttle.db");
    private static final int MAX_FAILURES = 5;
    private static final long LOCKOUT_MS = 15 * 60 * 1000L;

    private interface Update { void apply(Properties p); }

    private static Properties update(Update u) throws IOException {
        try (FileChannel ch = FileChannel.open(FILE,
                     Set.of(StandardOpenOption.CREATE, StandardOpenOption.READ,
                            StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                     PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
             FileLock lock = ch.lock()) {
            Properties p = new Properties();
            p.load(Channels.newInputStream(ch));
            u.apply(p);
            ch.truncate(0);
            ch.position(0);
            p.store(Channels.newOutputStream(ch), null);
            return p;
        }
    }

    static boolean isLocked(String key) throws IOException {
        long until = Long.parseLong(update(p -> { }).getProperty(key + ".until", "0"));
        return System.currentTimeMillis() < until;
    }

    static void recordFailure(String key) throws IOException {
        update(p -> {
            int n = Integer.parseInt(p.getProperty(key + ".failures", "0")) + 1;
            p.setProperty(key + ".failures", Integer.toString(n));
            if (n >= MAX_FAILURES) {
                long backoff = LOCKOUT_MS << Math.min(n - MAX_FAILURES, 6);
                p.setProperty(key + ".until", Long.toString(System.currentTimeMillis() + backoff));
            }
        });
    }

    static void reset(String key) throws IOException {
        update(p -> { p.remove(key + ".failures"); p.remove(key + ".until"); });
    }
}

// in login(), before authenticate():
String logName = USERNAME_PATTERN.matcher(username).matches() ? username : "<invalid>";
if (LoginThrottle.isLocked(logName)) {
    Arrays.fill(password, '\0');
    audit("LOGIN_LOCKED", logName, "attempt " + attempt);
    System.out.println("Invalid username or password.");
    sleepQuietly(FAILURE_DELAY_MS * attempt);
    continue;
}
boolean ok;
try {
    ok = authenticate(username, password);
} finally {
    Arrays.fill(password, '\0');
}
if (ok) {
    LoginThrottle.reset(logName);
    audit("LOGIN_SUCCESS", logName, "");
    return username;
}
LoginThrottle.recordFailure(logName);
```

### SEC-03: Unlocked, stale credential store: concurrent sessions overwrite each other; removed admins keep access and can restore accounts
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `AdminPortal.java:70`, `AdminPortal.java:257-258`, `AdminPortal.java:286-287`, `AdminPortal.java:471-486`

**Vulnerable code:**
```java
// AdminPortal.java:471-486
        void save() throws IOException {
            Properties props = new Properties();
            entries.forEach((name, hash) -> props.setProperty(name, hash.encode()));

            Path dir = file.toAbsolutePath().getParent();
            Path tmp = Files.createTempFile(dir, "admins", ".tmp");
            try {
                FileSecurity.restrictToOwner(tmp);
                try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                    props.store(w, "Administrator credentials (PBKDF2-HMAC-SHA256: iterations:salt:hash)");
                }
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } finally {
                Files.deleteIfExists(tmp);
            }
        }
```

**Why it is a problem:** `admins.db` is read only once, at start-up (line 70). Every later `save()` writes that process's in-memory map over the whole file, with no file lock and no re-read. When two administrators are logged in at the same time (two processes):

1. Admin A removes admin B, for example because B's password was leaked (lines 257-258). The file no longer lists B.
2. B's session is not checked again. B stays in the menu and keeps full admin rights; nothing ever checks `store.get(currentUser)` again.
3. B chooses "Change my password" or "Add administrator". B's stale map still contains B, and `save()` replaces the file, so B is restored. Any accounts A added or removed in the meantime are silently undone.

This defeats account revocation. It also loses updates between honest administrators, so audit log entries such as "removed X" no longer match the real state of the file.

**Fix:** Serialise every change with an exclusive lock. Under the lock, re-read the file, apply the change and save. Before each menu action, check that the current user still exists, and end the session if it does not.
```java
// CredentialStore
void reload() throws IOException {
    CredentialStore fresh = load(file);
    entries.clear();
    entries.putAll(fresh.entries);
}

/** Re-reads the file under an exclusive lock, applies the change, and saves before releasing the lock. */
void modify(java.util.function.Consumer<CredentialStore> change) throws IOException {
    Path lockFile = file.resolveSibling(file.getFileName() + ".lock");
    try (FileChannel ch = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
         FileLock lock = ch.lock()) {
        reload();
        change.accept(this);
        save();
    }
}

// adminMenu(): at the top of every loop iteration
store.reload();
if (store.get(currentUser) == null) {
    audit("SESSION_REVOKED", currentUser, "account no longer exists");
    System.out.println("Your administrator account has been removed. Logging out.");
    return;
}

// changePassword(): replace store.put(...) / store.save()
StoredHash newHash = StoredHash.create(password);
store.modify(s -> {
    if (s.get(currentUser) == null) {
        throw new IllegalStateException("account was removed");
    }
    s.put(currentUser, newHash);
});

// removeAdmin(): replace store.remove(...) / store.save()
store.modify(s -> s.remove(username));
```

### SEC-04: No idle timeout on admin session and no re-authentication before adding or removing administrators
- **Severity:** Low
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `AdminPortal.java:155-198`

**Vulnerable code:**
```java
// AdminPortal.java:166-184
            String choice = input.readLine("Choose an option: ");
            if (choice == null) {
                choice = "6";
            }

            switch (choice.trim()) {
                case "1":
                    listAdmins();
                    break;
                case "2": {
                    String created = createAdmin();
                    if (created != null) {
                        audit("ADMIN_ADDED", currentUser, "added " + created);
                    }
                    break;
                }
                case "3":
                    removeAdmin(currentUser);
                    break;
```

**Why it is a problem:** After one successful login the menu loop runs forever. The session has no inactivity or absolute timeout. Creating a new administrator (a persistent backdoor account) and removing other administrators require no fresh proof of identity, even though changing your own password does. Anyone who reaches an unattended terminal where an admin is logged in (or a stale `tmux`/`screen` session) can add their own admin account or lock out the real administrators. The authentication-weaknesses skill flags this under session lifetime and revocation.

**Fix:** Track the time since the last activity and end the session once it passes an idle limit. Ask for the current password again before privileged account changes.
```java
private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(5);

private void adminMenu(String currentUser) throws IOException {
    Instant lastActivity = Instant.now();
    while (true) {
        // ... print menu ...
        String choice = input.readLine("Choose an option: ");
        if (Duration.between(lastActivity, Instant.now()).compareTo(IDLE_TIMEOUT) > 0) {
            audit("SESSION_TIMEOUT", currentUser, "");
            System.out.println("Session expired due to inactivity. Please log in again.");
            return;
        }
        lastActivity = Instant.now();
        if (choice == null) {
            choice = "6";
        }
        switch (choice.trim()) {
            case "2": {
                if (!reauthenticate(currentUser)) {
                    break;
                }
                String created = createAdmin();
                if (created != null) {
                    audit("ADMIN_ADDED", currentUser, "added " + created);
                }
                break;
            }
            case "3":
                if (reauthenticate(currentUser)) {
                    removeAdmin(currentUser);
                }
                break;
            // ... other cases unchanged ...
        }
    }
}

private boolean reauthenticate(String currentUser) throws IOException {
    char[] pw = input.readPassword("Re-enter your password: ");
    if (pw == null) {
        return false;
    }
    try {
        if (authenticate(currentUser, pw)) {
            return true;
        }
    } finally {
        Arrays.fill(pw, '\0');
    }
    audit("REAUTH_FAILURE", currentUser, "");
    System.out.println("Password incorrect.");
    sleepQuietly(FAILURE_DELAY_MS);
    return false;
}
```

### SEC-05: KDF parameters (iteration count, salt and hash length) from `admins.db` not validated
- **Severity:** Low
- **CWE:** CWE-1284: Improper Validation of Specified Quantity in Input
- **Location:** `AdminPortal.java:418-425` (used at `AdminPortal.java:146`)

**Vulnerable code:**
```java
// AdminPortal.java:418-425
        static StoredHash decode(String value) {
            String[] parts = value.split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException("malformed entry");
            }
            Base64.Decoder b64 = Base64.getDecoder();
            return new StoredHash(Integer.parseInt(parts[0]), b64.decode(parts[1]), b64.decode(parts[2]));
        }
```

**Why it is a problem:** The iteration count, salt and hash come straight from the file and are trusted without checks. The crypto-audit skill's "weak KDF parameters" check applies here:
- **Downgrade:** `iterations` can be `1`, and `CredentialStore.load` accepts it. That makes an entry trivial to crack offline and hides the tampering from the load-time integrity check.
- **Crash:** `0`, a negative value or an empty salt passes `load` but makes `new PBEKeySpec(...)` throw an uncaught `IllegalArgumentException` inside `authenticate` (line 146). The program then crashes at login for that user, a denial of service.
- **Hang:** a very large value such as `2147483647` makes login appear to hang indefinitely.
- **Hash length:** hash length is never checked either.

Changing these values requires write access to the file, so the impact is limited. Still, input parsing should reject values outside a safe policy rather than fail late or weaken the hash without notice.

**Fix:** Validate the parameters in `decode` so a bad entry is reported as corruption at load time.
```java
private static final int MIN_ITERATIONS = 600_000;
private static final int MAX_ITERATIONS = 10_000_000;

static StoredHash decode(String value) {
    String[] parts = value.split(":");
    if (parts.length != 3) {
        throw new IllegalArgumentException("malformed entry");
    }
    int iterations = Integer.parseInt(parts[0]);
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
        throw new IllegalArgumentException("unacceptable iteration count");
    }
    Base64.Decoder b64 = Base64.getDecoder();
    byte[] salt = b64.decode(parts[1]);
    byte[] hash = b64.decode(parts[2]);
    if (salt.length < SALT_BYTES || hash.length != HASH_BITS / 8) {
        throw new IllegalArgumentException("unacceptable salt or hash length");
    }
    return new StoredHash(iterations, salt, hash);
}
```

### SEC-06: Audit log created with default permissions and then chmod-ed, follows symlinks, and data-file permissions never checked
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AdminPortal.java:374-377`, `AdminPortal.java:491-494`, `AdminPortal.java:445-449`

**Vulnerable code:**
```java
// AdminPortal.java:374-377
            if (!Files.exists(AUDIT_LOG)) {
                FileSecurity.createPrivateFile(AUDIT_LOG);
            }
            Files.writeString(AUDIT_LOG, line, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
// AdminPortal.java:491-494
        static void createPrivateFile(Path path) throws IOException {
            Files.createFile(path);
            restrictToOwner(path);
        }
```

**Why it is a problem:**
- **Brief permission window:** `Files.createFile` applies the process umask (usually 0644), and 0600 is only set afterwards. For that short window another local user can open the log for reading and keep the handle.
- **Check-then-create race (CWE-367):** the existence check and the creation are separate steps. If the file appears between them, `createFile` fails and the audit event is silently lost. On a failure, the program only prints a warning and continues.
- **Symlink following (CWE-59):** `Files.writeString(..., APPEND)` follows symlinks. If `admin-audit.log` is a link planted in a shared working directory (see SEC-01), the log is appended to whatever file the link points at. If the log already exists with loose permissions or belongs to someone else, it is used as is.
- **Credential file not checked:** `CredentialStore.load` (lines 445-449) reads `admins.db` without checking its owner or mode. A group- or world-writable credential file is trusted, even though anyone who can edit it can add an administrator.

**Fix:** Create and open the file in one atomic step with owner-only permissions and `NOFOLLOW_LINKS`, and don't use a separate `exists` check. Before trusting either data file, confirm it is a regular file owned by the current user and not accessible to group or others.
```java
private static final Set<PosixFilePermission> OWNER_RW = PosixFilePermissions.fromString("rw-------");

private static void audit(String event, String username, String detail) {
    String line = Instant.now() + " " + event + " user=" + username
            + (detail.isEmpty() ? "" : " " + detail) + System.lineSeparator();
    Set<OpenOption> opts = Set.of(StandardOpenOption.CREATE, StandardOpenOption.APPEND,
            StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    try (SeekableByteChannel ch = Files.newByteChannel(AUDIT_LOG, opts,
            PosixFilePermissions.asFileAttribute(OWNER_RW))) {
        FileSecurity.verifyPrivate(AUDIT_LOG);
        ch.write(ByteBuffer.wrap(line.getBytes(StandardCharsets.UTF_8)));
    } catch (IOException e) {
        System.err.println("Warning: could not write audit log: " + e.getMessage());
    }
}

// FileSecurity
static void verifyPrivate(Path path) throws IOException {
    PosixFileAttributes a = Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    String me = System.getProperty("user.name");
    boolean shared = a.permissions().stream()
            .anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"));
    if (!a.isRegularFile() || !a.owner().getName().equals(me) || shared) {
        throw new IOException(path + " must be a regular file owned by " + me + " with mode 0600");
    }
}

// CredentialStore.load(): before reading
if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
    FileSecurity.verifyPrivate(file);
    // ... load as before ...
}
```

### SEC-07: Without a console, passwords are echoed and kept in immutable Strings
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `AdminPortal.java:521-531`

**Vulnerable code:**
```java
// AdminPortal.java:521-531
        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            if (!warned) {
                System.err.println("Warning: no terminal detected; password input will not be hidden.");
                warned = true;
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
```

**Why it is a problem:** When `System.console()` is null (IDE runs, piped or redirected stdin, some `ssh`/`sudo`/container setups), the program still accepts passwords. They are shown on screen and may end up in terminal scrollback or session recordings; this also falls under CWE-549, missing password field masking. Each password is also read into a `String` (line 529), which is immutable and cannot be wiped. Every login, new-password, confirm-password and current-password entry therefore stays in the heap until garbage collection, and can be exposed through heap dumps, core files or swap. That undermines the promise at line 40 and in the README that passwords are "wiped from memory after use". A warning does not stop the insecure path.

**Fix:** By default, refuse to read passwords without a console. If non-interactive use is really needed, allow it only through an explicit opt-in, and read straight into a `char[]` that is cleared afterwards.
```java
char[] readPassword(String prompt) throws IOException {
    if (console != null) {
        return console.readPassword("%s", prompt);
    }
    if (!Boolean.getBoolean("adminportal.allowNonInteractive")) {
        throw new IOException("refusing to read a password without a terminal (input would be echoed)");
    }
    System.out.print(prompt);
    System.out.flush();
    char[] buf = new char[MAX_PASSWORD_LENGTH + 1];
    int n = 0;
    int c;
    while ((c = reader.read()) != -1 && c != '\n') {
        if (c == '\r') {
            continue;
        }
        if (n == buf.length) {
            Arrays.fill(buf, '\0');
            throw new IOException("password too long");
        }
        buf[n++] = (char) c;
    }
    if (c == -1 && n == 0) {
        return null;
    }
    char[] result = Arrays.copyOf(buf, n);
    Arrays.fill(buf, '\0');
    return result;
}
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm and parameters:** PBKDF2WithHmacSHA256, 600,000 iterations, 256-bit output (`AdminPortal.java:47-50`, `358-367`). This meets current OWASP guidance for newly created hashes. No MD5, SHA-1 or unsalted hashing anywhere.
- **Salt and RNG:** a 16-byte salt is generated for every password from a single `SecureRandom` (`AdminPortal.java:49`, `58`, `408-411`, `427-431`). No `java.util.Random` or time-based seeds.
- **Hard-coded or default credentials:** none. No passwords, keys or default accounts in source or README (`AdminPortal.java:33-34`, `81-89`). The bootstrap weakness is covered separately in SEC-01.
- **Constant-time comparison and user enumeration:** `MessageDigest.isEqual` compares hashes (`AdminPortal.java:147`). Unknown or invalid usernames still run a full PBKDF2 against `StoredHash.DUMMY`, which uses the same iteration count (`AdminPortal.java:143-146`, `396`). The same "Invalid username or password." message is shown in every failure case (`AdminPortal.java:134`).
- **Password policy:** 12-128 characters, with upper case, lower case, a digit and a symbol, enforced on creation and on change (`AdminPortal.java:309-354`). The 128-character maximum bounds hashing cost. New passwords are entered twice (`AdminPortal.java:322`).
- **Password clearing on the console path:** password arrays are zeroed in `finally` blocks (`AdminPortal.java:122-124`, `231-233`, `271-273`, `288-290`, `334-336`). `PBEKeySpec.clearPassword()` is called (`AdminPortal.java:365`) and the computed hash is zeroed (`AdminPortal.java:148`). The non-console path is covered in SEC-07.
- **Log and terminal injection:** usernames are restricted to `^[A-Za-z0-9_.-]{3,32}$` when created (`AdminPortal.java:215`), when loaded (`AdminPortal.java:452`) and before an attempted username is logged (`AdminPortal.java:126`). Log details are fixed strings or validated names, so no CR/LF or ANSI escape can reach `admin-audit.log` or the screen through `showAuditLog` (`AdminPortal.java:295-306`). Passwords are never logged.
- **Format strings:** `Console.readLine` and `readPassword` use the constant `"%s"` format with the prompt as an argument (`AdminPortal.java:514`, `523`), so there is no format-string injection.
- **Credential file writes:** a temp file created by `Files.createTempFile` (0600 on POSIX) is atomically moved over `admins.db`, so partial writes cannot happen and the replaced file is not accessed through a symlink (`AdminPortal.java:475-485`). Concurrency and permission checks are covered in SEC-03 and SEC-06.
- **Credential file parsing:** `java.util.Properties` text parsing only, with no object deserialization. Malformed Base64 and number parsing errors are caught and reported as corruption (`AdminPortal.java:446-458`). Parameter ranges are covered in SEC-05.
- **Self-lockout and destructive actions:** an admin cannot remove their own account, and removal requires typing the name twice (`AdminPortal.java:244-256`). Password change requires the current password (`AdminPortal.java:264-279`).
- **Error handling and information leakage:** errors go only to the local stderr and include file I/O messages (`AdminPortal.java:73`, `379`). No stack traces are shown, and no credential material appears in any message. This is acceptable for a local admin tool.
- **Injection and other attack surface:** no SQL or JDBC, no `Runtime.exec`/`ProcessBuilder`, no reflection, no `ObjectInputStream`, no XML parsing, no network sockets, HTTP or TLS, and no user-controlled file paths. OWASP A03 (injection), A08 (deserialization) and A10 (SSRF) do not apply.
- **Non-code files:** `README.md`, `result.md`, `return.txt`, `prompt.txt`, `cyber_prompt.txt` and `prompt_hash.txt` were reviewed. None contains executable code, secrets or credentials.
