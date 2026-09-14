# Security Review: AdminPortal (Java command-line administrator portal)

## 1. Executive Summary
`AdminPortal.java` is a single-file Java 17 command-line program. It authenticates administrators with a username and password, then opens a small admin menu: list admins, create an admin, view audit events, verify the audit log, log out. It stores PBKDF2-HMAC-SHA256 password hashes in `admins.db`, keeps failed-login counts in `lockouts.properties`, and writes every authentication event to `audit.log`, a SHA-256 hash-chained file.

The code is careful overall. Password hashing is strong, the hash comparison is constant-time, login errors are generic, unknown usernames are timing-equalised, log fields are escaped against injection, and the program fails closed when audit writes fail. No Critical or High issues were found. The most important findings are:

- **SEC-01 (Medium):** Lockout state is read, checked and rewritten with no lock between processes. Running many `login` processes in parallel lets an attacker go past the 5-failure limit and can even erase an active lock.
- **SEC-02 (Medium):** The data directory defaults to a path relative to the working directory. An existing directory is trusted without checking its owner, permissions or symlinks. Anyone who can write there can plant their own `admins.db` and get admin access, or rewrite the audit log.
- **SEC-03 (Medium):** `setup` checks "no administrators exist" only before its interactive prompts. The final write only rejects duplicate usernames, so a second unauthenticated "first administrator" can be created.
- Six Low findings:
  - Passwords typed into the username field are logged and shown to every admin.
  - The idle timeout is not enforced during admin creation.
  - Passwords are echoed when no `Console` is attached.
  - The audit hash chain is unkeyed and not anchored anywhere else, so deleting the newest entries goes undetected.
  - The password policy has no common-password blocklist.
  - Error messages include internal file paths.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AdminPortal.java` | The whole application: CLI entry point, `Portal` workflows (setup/login/admin menu), `Authenticator`, `Validation`, `PasswordHasher`, `CredentialStore`, `LockoutTracker`, `AuditLog`, `FileUtil`, `Terminal` | Password authentication, PBKDF2 hashing with salt, constant-time compare, account lockout and brute-force throttling, user-enumeration defences, session idle timeout, admin creation, hash-chained audit logging and log-injection escaping, file and directory permissions, atomic writes, cross-process file locking, console password input, error handling |
| `README.md` | User documentation for the program | Documents the intended controls and known limits (hash chain only detects changes, data-folder trust, usernames logged, password hiding needs a terminal). Used to check that the code matches its stated security properties. |
| `result.md` | Run metadata and summary from the session that generated the code | No executable code. Restates the claimed controls and limits. |
| `prompt.txt` | Original requirement for the program | No executable code. Requires authentication plus logging of every success and failure. |
| `cyber_prompt.txt` | Instructions for this security review | No executable code. |
| `return.txt` | JSON result record of the generating session | No executable code, no secrets affecting the application. |
| `prompt_hash.txt` | Empty file | None. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: The router workflow. Understood every file, searched the skill library by name for the behaviours found, and applied the matches below in priority order.
- `testing-api-authentication-weaknesses`: Applied to the login flow in `Authenticator.authenticate`:
  - Account-enumeration resistance (generic message, dummy hashing)
  - Brute-force and lockout controls
  - Password policy (`Validation.passwordProblem`)
  - Session lifecycle (idle timeout in `adminSession`)
  - Credential leakage into logs

  The JWT, refresh-token and HTTP-endpoint checks do not apply to this CLI and were skipped.
- `exploiting-race-condition-vulnerabilities`: Applied its TOCTOU and limit-overrun methodology to two places. The first is the attempt-limiting logic (`LockoutTracker` plus `Authenticator`) when many processes run at once. The second is the multi-step `setup` workflow and `CredentialStore.add`.
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher`:
  - Algorithm, iteration count, salt size and source, output length
  - Constant-time comparison
  - Iteration count and salt read back from `admins.db`
  - `SecureRandom` usage
  - SHA-256 use in `AuditLog`
  - Search for hardcoded secrets
- `implementing-log-integrity-with-blockchain`: Applied to the `AuditLog` hash chain: genesis value, chain construction, verification, tamper detection, and external checkpoint anchoring.
- `testing-for-sensitive-data-exposure`: Applied to secrets in logs (`audit.record` of raw usernames, audit tail shown to admins), information leakage in error messages (`main`, `CredentialStore.load`), and protection of data at rest (file and directory permissions).
- General OWASP Top 10 / CWE review, because no library skill matched these behaviours:
  - Trust and permission checks on the local data directory and files (CWE-732, CWE-59)
  - Terminal password masking (CWE-549)
  - Log-injection escaping (CWE-117)
  - Idle-session expiry within multi-prompt flows (CWE-613)
  - Fail-closed error handling (CWE-636)

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Account lockout can be bypassed by running `login` processes in parallel | Medium | CWE-362 | `AdminPortal.java:318` |
| SEC-02 | Data directory trusted without ownership, permission or symlink checks, and resolved relative to the working directory | Medium | CWE-732 | `AdminPortal.java:90` |
| SEC-03 | Initial `setup` race lets a second unauthenticated first administrator be created | Medium | CWE-367 | `AdminPortal.java:125` |
| SEC-04 | Password typed into the username field is written to the audit log and shown to all admins | Low | CWE-532 | `AdminPortal.java:306` |
| SEC-05 | Idle timeout and re-authentication not enforced inside the create-administrator flow | Low | CWE-613 | `AdminPortal.java:205` |
| SEC-06 | Password echoed and kept in a non-wipeable String when no Console is attached | Low | CWE-549 | `AdminPortal.java:791` |
| SEC-07 | Audit hash chain is unkeyed and not anchored externally, so truncation or a full rewrite goes undetected | Low | CWE-345 | `AdminPortal.java:621` |
| SEC-08 | Password policy accepts common and trivially guessable passwords | Low | CWE-521 | `AdminPortal.java:355` |
| SEC-09 | Error messages disclose absolute file-system paths and internal details | Low | CWE-209 | `AdminPortal.java:78` |

## 5. Detailed Findings

### SEC-01: Account lockout can be bypassed by running `login` processes in parallel
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'). Also CWE-307: Improper Restriction of Excessive Authentication Attempts.
- **Location:** `AdminPortal.java:318-331`, `AdminPortal.java:523-541`

**Vulnerable code:**
```java
// AdminPortal.java:318-331
            Optional<Instant> lockedUntil = lockouts.lockedUntil(username, now);
            if (lockedUntil.isPresent()) {
                PasswordHasher.burnEquivalentTime(password);
                audit.record("LOGIN_FAILURE", username, "FAILURE", "account locked until " + lockedUntil.get());
                return Optional.empty();
            }

            if (PasswordHasher.matches(password, stored)) {
                audit.record("LOGIN_SUCCESS", username, "SUCCESS", "access granted");
                lockouts.recordSuccess(username);
                return Optional.of(username);
            }

            boolean nowLocked = lockouts.recordFailure(username, now);
// AdminPortal.java:523-541
        synchronized boolean recordFailure(String username, Instant now) throws IOException {
            Properties props = load();
            long nowSeconds = now.getEpochSecond();
            long[] state = state(props, username); // [failures, windowStart, lockedUntil]
            boolean windowExpired = nowSeconds - state[1] > FAILURE_WINDOW.getSeconds();
            boolean lockExpired = state[2] != 0 && nowSeconds >= state[2];
            if (windowExpired || lockExpired) {
                state = new long[] {0, nowSeconds, 0};
            }
            state[0]++;
            boolean locked = false;
            if (state[0] >= MAX_FAILURES) {
                state[2] = nowSeconds + LOCK_DURATION.getSeconds();
                locked = true;
            }
            props.setProperty(username, state[0] + "," + state[1] + "," + state[2]);
            save(props);
            return locked;
        }
```

**Why it is a problem:** Each `java AdminPortal.java login` is a separate JVM. `synchronized` only serialises threads inside one process, and `LockoutTracker` takes no file lock, unlike `AuditLog.record`. The lock check (line 318) and the failure update (line 331) are separated by a deliberately slow PBKDF2 computation of 600,000 iterations. The update is a load, modify, rewrite of the whole file.

An attacker who can start the program many times at once (for example through a sudo rule or an SSH forced command) can do three things:
1. All N processes pass the "not locked" check before any of them records a failure. Each process allows 3 attempts per run (`MAX_ATTEMPTS_PER_RUN`), so N processes get far more than 5 guesses per 15-minute window.
2. Concurrent load/rewrite cycles lose increments, because the last writer wins, so the counter under-counts.
3. A process that loaded the file before the lock was written can later write back `failures=4, lockedUntil=0` and silently remove an active lock.

The fixed per-account window also has no global limit, so password spraying across several admin accounts is not throttled. The lockout is the only real brute-force control; the 3-attempt limit per run is reset simply by starting the program again.

**Fix:** Serialise lockout state across processes with an OS file lock. Use a separate, stable lock file, because `writeAtomically` replaces `lockouts.properties` and a lock on the replaced file would mean nothing. Reserve (count) the attempt before the expensive hash check, so parallel attempts cannot all pass the check. Clear the count only on success. Consider also adding a global failure budget across all accounts.
```java
// LockoutTracker: constructed with dataDir.resolve("lockouts.properties") and dataDir.resolve("lockouts.lock")
private final Path file;
private final Path lockFile;

/**
 * Atomically counts one attempt BEFORE the password is checked.
 * Returns the lock expiry if the account is already locked (the attempt is then refused).
 */
Optional<Instant> reserveAttempt(String username, Instant now) throws IOException {
    FileUtil.createPrivateFileIfMissing(lockFile);
    try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE);
         FileLock lock = channel.lock()) { // cross-process mutual exclusion
        Properties props = load();
        long nowSeconds = now.getEpochSecond();
        long[] state = state(props, username);
        if (state[2] != 0 && nowSeconds < state[2]) {
            return Optional.of(Instant.ofEpochSecond(state[2]));
        }
        if (nowSeconds - state[1] > FAILURE_WINDOW.getSeconds() || state[2] != 0) {
            state = new long[] {0, nowSeconds, 0};
        }
        state[0]++;
        if (state[0] >= MAX_FAILURES) {
            state[2] = nowSeconds + LOCK_DURATION.getSeconds(); // later concurrent attempts are refused
        }
        props.setProperty(username, state[0] + "," + state[1] + "," + state[2]);
        save(props);
        return Optional.empty();
    }
}

void recordSuccess(String username) throws IOException {
    FileUtil.createPrivateFileIfMissing(lockFile);
    try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE);
         FileLock lock = channel.lock()) {
        Properties props = load();
        if (props.remove(username) != null) {
            save(props);
        }
    }
}

// Authenticator.authenticate
Optional<Instant> lockedUntil = lockouts.reserveAttempt(username, now);
if (lockedUntil.isPresent()) {
    PasswordHasher.burnEquivalentTime(password);
    audit.record("LOGIN_FAILURE", username, "FAILURE", "account locked until " + lockedUntil.get());
    return Optional.empty();
}
if (PasswordHasher.matches(password, stored)) {
    audit.record("LOGIN_SUCCESS", username, "SUCCESS", "access granted");
    lockouts.recordSuccess(username);
    return Optional.of(username);
}
audit.record("LOGIN_FAILURE", username, "FAILURE", "incorrect password"); // failure was already counted
return Optional.empty();
```

### SEC-02: Data directory trusted without ownership, permission or symlink checks, and resolved relative to the working directory
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource. Related: CWE-59 Improper Link Resolution Before File Access, CWE-427 Uncontrolled Search Path Element.
- **Location:** `AdminPortal.java:90-103`, `AdminPortal.java:616-617`

**Vulnerable code:**
```java
// AdminPortal.java:90-103
    private static Path resolveDataDir() throws IOException {
        String configured = System.getenv("ADMIN_PORTAL_HOME");
        Path dir = Paths.get(configured == null || configured.isBlank() ? "admin-portal-data" : configured)
                .toAbsolutePath().normalize();
        if (!Files.exists(dir)) {
            try {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------")));
            } catch (UnsupportedOperationException e) {
                Files.createDirectories(dir); // Non-POSIX file system (e.g. Windows)
            }
        }
        return dir;
    }
// AdminPortal.java:616-617
            FileUtil.createPrivateFileIfMissing(file);
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE);
```

**Why it is a problem:** All authentication decisions come from files in this directory: `admins.db` defines who is an administrator, `lockouts.properties` defines who is locked, and `audit.log` is the evidence trail. The owner-only permissions are applied only when the program creates the directory. If the directory already exists, whatever permissions, owner or symlink it has are silently accepted.

With `ADMIN_PORTAL_HOME` unset, the path is relative to the current working directory. An administrator who runs the tool from a shared or attacker-writable directory (for example `/tmp` or a shared project folder) uses an `admin-portal-data` directory that someone else may have pre-created. That attacker can:
- Plant an `admins.db` containing their own PBKDF2 hash and log in as an administrator.
- Delete or replace `lockouts.properties` to reset lockouts.
- Rewrite `audit.log` and recompute the unkeyed chain (see SEC-07).
- Point `audit.log` at another file through a symlink. `FileChannel.open` follows symlinks, so the victim's process appends to whatever file the link targets.

On Windows the fallback at line 99 creates the directory with inherited ACLs and no restriction at all.

**Fix:** Require an explicit absolute data directory. Refuse to start unless it is a real directory (not a symlink), owned by the running account, and has no group or other permissions. Open data files with `LinkOption.NOFOLLOW_LINKS`.
```java
private static Path resolveDataDir() throws IOException {
    String configured = System.getenv("ADMIN_PORTAL_HOME");
    if (configured == null || configured.isBlank() || !Paths.get(configured).isAbsolute()) {
        throw new IOException("Set ADMIN_PORTAL_HOME to an absolute directory owned only by this account.");
    }
    Path dir = Paths.get(configured).normalize();
    if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")));
    }
    if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException("Data directory must be a real directory, not a symbolic link.");
    }
    Path probe = Files.createTempFile(dir, ".owner", ".probe"); // owned by the running account
    try {
        if (!Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(probe))) {
            throw new IOException("Data directory is not owned by the account running the portal.");
        }
    } finally {
        Files.deleteIfExists(probe);
    }
    Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS);
    if (!perms.equals(PosixFilePermissions.fromString("rwx------"))) {
        throw new IOException("Data directory permissions must be rwx------ (owner only).");
    }
    return dir;
}

// AuditLog.record
try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE,
                                            LinkOption.NOFOLLOW_LINKS);
     FileLock lock = channel.lock()) {
```

### SEC-03: Initial `setup` race lets a second unauthenticated first administrator be created
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `AdminPortal.java:124-134`, `AdminPortal.java:258-261`, `AdminPortal.java:481-486`

**Vulnerable code:**
```java
// AdminPortal.java:124-134
        int setup() throws IOException {
            if (!credentials.load().isEmpty()) {
                System.err.println("Setup refused: administrator accounts already exist. "
                        + "Log in and use the admin menu to add more.");
                audit.record("SETUP_REFUSED", null, "FAILURE", "administrators already exist");
                return EXIT_DENIED;
            }
            System.out.println("=== Initial administrator setup ===");
            Optional<String> created = createAccountInteractively(null);
            return created.isPresent() ? EXIT_OK : EXIT_ERROR;
        }
// AdminPortal.java:258-261
                // Audit first: if the event cannot be recorded, the account is not created.
                String event = actor == null ? "ADMIN_SETUP" : "ADMIN_CREATED";
                audit.record(event, actor == null ? username : actor, "SUCCESS", "created administrator " + username);
                credentials.add(PasswordHasher.create(username, first));
// AdminPortal.java:481-486
        synchronized void add(StoredCredential credential) throws IOException {
            Map<String, StoredCredential> all = load();
            if (all.containsKey(credential.username())) {
                throw new IOException("Administrator already exists: " + credential.username());
            }
            all.put(credential.username(), credential);
```

**Why it is a problem:** The README says `setup` "only works while there are no administrators yet… so nobody can use it to add themselves." The emptiness check happens once, before the interactive prompts. Those prompts can stay open indefinitely. `CredentialStore.add` checks only for a duplicate username and takes no cross-process lock.

Attack: during initial provisioning, an attacker who can run the program starts `setup` and leaves it waiting at the username prompt. The legitimate administrator then runs `setup` and creates their account. The attacker completes their still-open prompt, and `add` succeeds because the username differs. The attacker now has a full administrator account that no authenticated admin ever approved. The audit log calls it `ADMIN_SETUP`, which looks legitimate.

Concurrent unlocked `add` calls from different processes can also overwrite each other and silently drop a newly created admin.

**Fix:** Re-check the precondition at the moment of the write, inside a cross-process lock, and pass the "must be empty" requirement down to the store. Record the audit event under the same lock, so a refused write is logged as a failure.
```java
// CredentialStore
synchronized void add(StoredCredential credential, boolean requireNoAdmins) throws IOException {
    FileUtil.createPrivateFileIfMissing(lockFile); // e.g. dataDir.resolve("admins.lock")
    try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE);
         FileLock lock = channel.lock()) {
        Map<String, StoredCredential> all = load();
        if (requireNoAdmins && !all.isEmpty()) {
            throw new IOException("Setup refused: an administrator account already exists.");
        }
        if (all.containsKey(credential.username())) {
            throw new IOException("Administrator already exists: " + credential.username());
        }
        all.put(credential.username(), credential);
        // ... serialise and FileUtil.writeAtomically(file, sb.toString()) as before, while still holding the lock
    }
}

// Portal.createAccountInteractively
credentials.add(PasswordHasher.create(username, first), actor == null);
```

### SEC-04: Password typed into the username field is written to the audit log and shown to all admins
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `AdminPortal.java:304-308`, `AdminPortal.java:206-208`

**Vulnerable code:**
```java
// AdminPortal.java:304-308
            if (!Validation.isValidUsername(username)) {
                PasswordHasher.burnEquivalentTime(password);
                audit.record("LOGIN_FAILURE", rawUsername, "FAILURE", "malformed username");
                return Optional.empty();
            }
// AdminPortal.java:206-208
                    case "3" -> {
                        System.out.println("Most recent audit events (oldest first):");
                        audit.tail(20).forEach(line -> System.out.println("  " + line));
```

**Why it is a problem:** A common user error is typing the password at the `Username:` prompt, for example after a missed Enter. Admin passwords must be 12 to 128 characters and usually contain characters outside `[a-z0-9._-]`, or are longer than 32. That input fails the username regex, and the raw text (only escaped, not redacted) is then stored in `audit.log` as `user=<password>`. The log is kept permanently, cannot be edited without breaking the hash chain, and is shown in cleartext to every other administrator through menu option 3. It will also reach any SIEM the log is forwarded to, as the README recommends. The README calls this a trade-off, but it is avoidable. A malformed value is by definition not a valid username and has no investigative value beyond its length.

**Fix:** Do not log raw input that failed username validation. Log only non-sensitive metadata. For well-formed but unknown usernames, consider logging a keyed hash (HMAC) instead of the typed value.
```java
if (!Validation.isValidUsername(username)) {
    PasswordHasher.burnEquivalentTime(password);
    // Never log the raw value: a mistyped password often ends up in the username field.
    audit.record("LOGIN_FAILURE", null, "FAILURE", "malformed username (length " + username.length() + ")");
    return Optional.empty();
}
```

### SEC-05: Idle timeout and re-authentication not enforced inside the create-administrator flow
- **Severity:** Low
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `AdminPortal.java:191-205`, `AdminPortal.java:228-244`

**Vulnerable code:**
```java
// AdminPortal.java:191-205
                Instant now = Instant.now();
                if (Duration.between(lastActivity, now).compareTo(IDLE_TIMEOUT) > 0) {
                    System.out.println("Session expired due to inactivity. Please log in again.");
                    audit.record("SESSION_TIMEOUT", admin, "INFO", "idle for more than " + IDLE_TIMEOUT.toMinutes() + " minutes");
                    return EXIT_DENIED;
                }
                lastActivity = now;

                switch (choice.trim()) {
                    case "1" -> {
                        System.out.println("Administrator accounts:");
                        credentials.load().keySet().forEach(name -> System.out.println("  - " + name));
                        audit.record("ADMIN_ACTION", admin, "SUCCESS", "listed administrator accounts");
                    }
                    case "2" -> createAccountInteractively(admin);
// AdminPortal.java:228-244
        private Optional<String> createAccountInteractively(String actor) throws IOException {
            String rawName = terminal.readLine("New administrator username: ");
            if (rawName == null) {
                return Optional.empty();
            }
            String username = Validation.normalizeUsername(rawName);
            if (!Validation.isValidUsername(username)) {
                System.out.println("Invalid username. Use 3-32 characters: letters, digits, '.', '_' or '-'.");
                return Optional.empty();
            }
            if (credentials.load().containsKey(username)) {
                System.out.println("That username already exists.");
                return Optional.empty();
            }

            char[] first = terminal.readPassword("New password (at least " + Validation.MIN_PASSWORD_LENGTH + " characters): ");
            char[] second = first == null ? null : terminal.readPassword("Repeat new password: ");
```

**Why it is a problem:** The idle check runs only when a menu choice is read. Once option 2 is selected, the three follow-up prompts (username, password, repeat) have no expiry. Suppose an administrator selects "Create administrator account" and walks away. Hours later, anyone at the unattended terminal can type a username and password and create a persistent administrator account. It is attributed in the audit log (`ADMIN_CREATED`) to the absent admin. Creating a privileged account is the most sensitive action in the portal, yet it needs no fresh proof of identity.

**Fix:** Carry a deadline into multi-prompt flows and check it after every read. Also require the acting admin to re-enter their password before an account is created.
```java
case "2" -> {
    if (reauthenticate(admin)) { // re-prompts for the acting admin's password via authenticator
        createAccountInteractively(admin, Instant.now().plus(IDLE_TIMEOUT));
    }
}

private Optional<String> createAccountInteractively(String actor, Instant deadline) throws IOException {
    String rawName = terminal.readLine("New administrator username: ");
    if (rawName == null || expired(deadline)) {
        return Optional.empty();
    }
    // ... username validation as before ...
    char[] first = terminal.readPassword("New password (at least " + Validation.MIN_PASSWORD_LENGTH + " characters): ");
    char[] second = first == null ? null : terminal.readPassword("Repeat new password: ");
    try {
        if (first == null || second == null || expired(deadline)) {
            System.out.println("Session expired or input closed; account not created.");
            return Optional.empty();
        }
        // ... remainder unchanged ...
    } finally {
        if (first != null) Arrays.fill(first, '\0');
        if (second != null) Arrays.fill(second, '\0');
    }
}

private static boolean expired(Instant deadline) {
    return deadline != null && Instant.now().isAfter(deadline);
}
```

### SEC-06: Password echoed and kept in a non-wipeable String when no Console is attached
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking. Related: CWE-316 Cleartext Storage of Sensitive Information in Memory.
- **Location:** `AdminPortal.java:787-797`

**Vulnerable code:**
```java
// AdminPortal.java:787-797
        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            if (!warned) {
                System.err.println("WARNING: no interactive console detected; password input will not be hidden.");
                warned = true;
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
```

**Why it is a problem:** On Java 17 to 21, `System.console()` returns `null` whenever stdin or stdout is redirected, not only when input is piped. An administrator who runs `java AdminPortal.java login | tee session.txt` or `> out.txt` still types at a real TTY. The terminal echoes the password on screen, where it can be shoulder-surfed, captured by screen recording, or kept in terminal scrollback. The warning only appears after output has already been redirected, so the admin may not see it. The password is also read into an immutable `String` (line 795). That copy cannot be zeroed, which defeats the careful `Arrays.fill` wiping elsewhere. This is only a warning, not a refusal, so the application's masking guarantee depends on how it happens to be invoked.

**Fix:** Refuse to read passwords without a console by default. If non-interactive use is genuinely needed, require an explicit opt-in (for example an environment variable) and read the characters straight into a `char[]`.
```java
char[] readPassword(String prompt) throws IOException {
    if (console != null) {
        return console.readPassword("%s", prompt);
    }
    if (!"1".equals(System.getenv("ADMIN_PORTAL_ALLOW_UNMASKED_PASSWORD"))) {
        throw new IOException("Refusing to read a password without an interactive console "
                + "(do not redirect stdin/stdout when logging in).");
    }
    System.out.print(prompt);
    System.out.flush();
    char[] buf = new char[Validation.MAX_PASSWORD_LENGTH + 1];
    int len = 0;
    int c;
    while ((c = reader.read()) != -1 && c != '\n') {
        if (c != '\r' && len < buf.length) {
            buf[len++] = (char) c;
        }
    }
    if (c == -1 && len == 0) {
        return null;
    }
    char[] result = Arrays.copyOf(buf, len);
    Arrays.fill(buf, '\0');
    return result;
}
```

### SEC-07: Audit hash chain is unkeyed and not anchored externally, so truncation or a full rewrite goes undetected
- **Severity:** Low
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `AdminPortal.java:620-621`, `AdminPortal.java:645-650`

**Vulnerable code:**
```java
// AdminPortal.java:620-621
                String previous = lastHash(channel);
                String line = body + "|prev=" + previous + "|hash=" + sha256Hex(previous + "|" + body) + "\n";
// AdminPortal.java:645-650
                if (!prev.equals(expectedPrev) || !hash.equals(sha256Hex(prev + "|" + body))) {
                    return new Verification(false, "Audit log TAMPERED: hash chain broken at line " + (i + 1) + ".");
                }
                expectedPrev = hash;
            }
            return new Verification(true, "Audit log intact: " + lines.size() + " events, hash chain valid.");
```

**Why it is a problem:** The chain uses plain SHA-256 with a public genesis value (`"0".repeat(64)`) and no secret. `verify()` checks only that the file agrees with itself. There is no external checkpoint of the head hash or event count, which is the anchoring step the log-integrity methodology calls for. As a result:
- Deleting the newest N lines, such as a burst of `LOGIN_FAILURE` entries from a brute-force attempt or the attacker's own `LOGIN_SUCCESS`, leaves a perfectly valid chain. `verify-log` reports "intact".
- Anyone with write access can edit any line and recompute every later hash with standard tools, and the result verifies as intact.

The program says the log is "tamper-evident", but in practice it only detects accidental corruption and unsophisticated edits. In addition, `os_user` (line 613) comes from the JVM property `user.name`, which whoever launches the JVM can override with `-Duser.name=`, so that field is not authoritative either. The README acknowledges these limits, but the code offers no mechanism to overcome them.

**Fix:** Key the chain with HMAC-SHA256, using a key that is not stored in the data directory (for example an OS keystore or a root-owned file readable only through a privileged helper). Periodically publish the head hash and line count to a store the portal account cannot rewrite, such as a remote syslog/SIEM or WORM storage. Have `verify()` compare the chain's end against the latest checkpoint, so truncation is detected.
```java
private static String chainMac(byte[] key, String text) {
    try {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(text.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
        throw new IllegalStateException("HMAC-SHA256 unavailable", e);
    }
}

// record(): key loaded from outside the data directory; checkpoint sink is off-host / append-only
String previous = lastHash(channel);
String hash = chainMac(auditKey, previous + "|" + body);
String line = body + "|prev=" + previous + "|hash=" + hash + "\n";
// ... write and force as before ...
checkpointSink.publish(new Checkpoint(Instant.now(), lineCountAfterWrite, hash)); // e.g. remote syslog / SIEM

// verify(): recompute with the key, then compare the end of the chain with the external checkpoint
if (!prev.equals(expectedPrev) || !hash.equals(chainMac(auditKey, prev + "|" + body))) {
    return new Verification(false, "Audit log TAMPERED: hash chain broken at line " + (i + 1) + ".");
}
// ... after the loop:
Checkpoint cp = checkpointSink.latest();
if (cp != null && (lines.size() < cp.lineCount() || !lines.get((int) cp.lineCount() - 1).endsWith("|hash=" + cp.headHash()))) {
    return new Verification(false, "Audit log TAMPERED: entries missing or rewritten since checkpoint " + cp.time() + ".");
}
```

### SEC-08: Password policy accepts common and trivially guessable passwords
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `AdminPortal.java:355-366`

**Vulnerable code:**
```java
// AdminPortal.java:355-366
        static Optional<String> passwordProblem(char[] password, String username) {
            if (password.length < MIN_PASSWORD_LENGTH) {
                return Optional.of("must be at least " + MIN_PASSWORD_LENGTH + " characters long");
            }
            if (password.length > MAX_PASSWORD_LENGTH) {
                return Optional.of("must be at most " + MAX_PASSWORD_LENGTH + " characters long");
            }
            if (containsIgnoreCase(password, username)) {
                return Optional.of("must not contain the username");
            }
            return Optional.empty();
        }
```

**Why it is a problem:** The only checks are length and "does not contain the username". Values like `aaaaaaaaaaaa`, `123456789012`, `password1234` and `Password123!` are all accepted for an administrator account. These appear near the top of every cracking wordlist. With only single-factor authentication, and a lockout that allows 5 guesses per 15 minutes indefinitely (and more with SEC-01), a common password is realistically guessable online. It also falls quickly offline if `admins.db` leaks. NIST SP 800-63B requires checking new passwords against lists of commonly used or breached values.

**Fix:** Reject passwords found in a blocklist of common or breached passwords, plus trivial patterns such as a single repeated character. Compare in `char[]` form, or via a hash, to avoid creating extra `String` copies.
```java
private static final Set<String> COMMON_PASSWORD_SHA256 = loadBlocklistHashes(); // SHA-256 of top breached passwords, shipped with the app

static Optional<String> passwordProblem(char[] password, String username) {
    if (password.length < MIN_PASSWORD_LENGTH) {
        return Optional.of("must be at least " + MIN_PASSWORD_LENGTH + " characters long");
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
        return Optional.of("must be at most " + MAX_PASSWORD_LENGTH + " characters long");
    }
    if (containsIgnoreCase(password, username)) {
        return Optional.of("must not contain the username");
    }
    if (distinctChars(password) < 5) {
        return Optional.of("is too repetitive");
    }
    if (COMMON_PASSWORD_SHA256.contains(sha256HexLowercased(password))) {
        return Optional.of("is a commonly used or breached password; choose another");
    }
    return Optional.empty();
}
```

### SEC-09: Error messages disclose absolute file-system paths and internal details
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `AdminPortal.java:76-79`, `AdminPortal.java:475`

**Vulnerable code:**
```java
// AdminPortal.java:76-79
        } catch (IOException | RuntimeException e) {
            // Never print stack traces to the user; they can leak internal details.
            System.err.println("Fatal error: " + e.getMessage());
            System.exit(EXIT_ERROR);
// AdminPortal.java:475
                    throw new IOException("Credential file " + file + " is malformed at line " + lineNumber);
```

**Why it is a problem:** The comment's intent is to avoid leaking internals, but `e.getMessage()` of JDK exceptions such as `AccessDeniedException`, `NoSuchFileException` and `FileSystemException` is the absolute path of the file involved. Line 475 deliberately embeds the absolute path of `admins.db`. Anyone allowed to run `login` without being an administrator learns the exact location of the credential store and lockout file, which helps with SEC-02-style tampering. Messages from `IllegalStateException` at line 433 also reveal JCE provider details.

**Fix:** Show end users only messages written for them, and send the detailed diagnostics to an owner-only diagnostic channel.
```java
} catch (PortalException e) {            // thrown only with user-safe messages, e.g. "Audit log is corrupt; run verify-log"
    System.err.println("Error: " + e.getMessage());
    System.exit(EXIT_ERROR);
} catch (IOException | RuntimeException e) {
    System.err.println("Fatal error: the operation could not be completed ("
            + e.getClass().getSimpleName() + "). Contact the portal owner.");
    System.exit(EXIT_ERROR);
}

// CredentialStore.load
throw new PortalException("Credential store is malformed at line " + lineNumber);
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm and parameters:** PBKDF2WithHmacSHA256 with 600,000 iterations (the OWASP value), a 16-byte salt per user from `SecureRandom`, and 256-bit output (`AdminPortal.java:389-400`). No MD5, SHA-1, DES, ECB or custom crypto is used.
- **Constant-time hash comparison:** `MessageDigest.isEqual(candidate, stored.hash())` at `AdminPortal.java:405`.
- **Stored KDF parameters:** Iteration count and hash length are read per entry from `admins.db` (`AdminPortal.java:469-473`). The only lower bound is `iterations >= 1`, so a weakened entry would need write access to the file. That risk is covered by SEC-02, and no separate finding is raised.
- **No hardcoded secrets:** No passwords, keys or tokens appear in `AdminPortal.java`. The dummy credential is generated randomly at runtime (`AdminPortal.java:412-420`).
- **User enumeration via messages:** Unknown user, bad password and locked account all print the same `GENERIC_FAILURE` (`AdminPortal.java:59-60`, `162`). The detailed reason goes only to the audit log.
- **User enumeration via timing:** Malformed usernames, unknown usernames and locked accounts all run a full PBKDF2 against a pre-built dummy credential (`AdminPortal.java:141`, `305`, `313`, `320`, `423-426`).
- **Lockout checked before password verification:** The correct password is refused while an account is locked (`AdminPortal.java:318-325`). Apart from the race in SEC-01, the logic is correct within a single process.
- **Fail closed on audit failure:** `audit.record` runs before success is returned, and an `IOException` blocks access (`AdminPortal.java:326`, `258-261`). A truncated last line stops all further logins (`AdminPortal.java:693-701`).
- **Corrupt lockout entries:** Non-numeric three-part values are treated as locked (`AdminPortal.java:557-559`). `Instant.ofEpochSecond(Long.MAX_VALUE)` then throws, which ends the run, so it fails closed. Other malformed values are treated as unlocked, but reaching that needs write access (SEC-02).
- **Log injection (CWE-117):** `AuditLog.sanitize` escapes control characters, non-ASCII, `|` and `\`, and truncates each field to 200 characters (`AdminPortal.java:710-728`). Injected text cannot forge lines, fields, `|prev=` or `|hash=` markers, or terminal escape sequences, including in the admin "view events" output. Bounded field length keeps the 8 KB `lastHash` tail read valid (`AdminPortal.java:685-686`).
- **Cross-process audit appends:** `FileChannel.lock()` serialises writers, and `force(true)` makes the entry durable (`AdminPortal.java:617-627`).
- **File permissions for newly created data:** The directory is created `rwx------` (`AdminPortal.java:96-97`), the audit log `rw-------` (`AdminPortal.java:750`), and `admins.db` and `lockouts.properties` are written through `Files.createTempFile`, which is owner-only on POSIX, then moved into place atomically (`AdminPortal.java:759-767`). The gaps for already-existing directories are covered in SEC-02.
- **Password handling in memory:** Passwords are read into `char[]` through `Console.readPassword`, zeroed after use (`AdminPortal.java:156`, `265-266`), and `PBEKeySpec.clearPassword()` is called (`AdminPortal.java:435`). The non-console path is covered in SEC-06.
- **Passwords never logged:** No `audit.record` call receives password data (`AdminPortal.java:128`, `188-218`, `260`, `306-334`). The username-field case is covered in SEC-04.
- **Username validation and canonicalisation:** Usernames are trimmed and lowercased with `Locale.ROOT`, then matched against the ASCII allow-list `[a-z0-9._-]{3,32}` before any lookup, which prevents case and Unicode confusion (`AdminPortal.java:345-353`). Stored usernames are validated again on load (`AdminPortal.java:465`), which also blocks `:`, `=` and newline injection into `admins.db` and `lockouts.properties`.
- **Password length bounds:** 12 to 128 characters are enforced at creation (`AdminPortal.java:356-361`). Java's PBKDF2 keys HMAC once per derivation, so a long password at login does not multiply the hashing cost.
- **Setup refused once admins exist:** A non-concurrent re-run of `setup` is refused and audited (`AdminPortal.java:125-129`). The concurrent case is SEC-03.
- **Authorization boundary:** All admin functions are reachable only through `adminSession`, which is called only after `authenticate` returns a user (`AdminPortal.java:158-160`). No command-line argument skips authentication (`AdminPortal.java:66-74`). `verify-log` is unauthenticated but read-only and prints only a status message.
- **Injection and dangerous APIs:** No SQL, OS command execution, reflection, deserialization (`ObjectInputStream`), XML parsing, network I/O or TLS is used. `Properties.load` and `Files.readAllLines` parse plain text only.
- **Stack traces:** No stack traces are printed to users (`AdminPortal.java:76-79`). The message content is covered in SEC-09.
- **Non-code files** (`README.md`, `result.md`, `prompt.txt`, `cyber_prompt.txt`, `return.txt`, `prompt_hash.txt`): Reviewed for embedded secrets or executable content. None found.
