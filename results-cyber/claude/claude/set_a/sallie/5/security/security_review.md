# Security Review: Employee Portal Authentication (EmployeePortalAuth.java)

## 1. Executive Summary
`EmployeePortalAuth.java` is a single-file Java 17 command-line program for an internal employee portal. It handles interactive username/password login, keeps salted PBKDF2 password hashes in a flat file (`users.db`), and tracks failed attempts per account with escalating lockouts in `lockouts.db`. Events go to `audit.log`. The same entry point also has two administrator commands, `add-user` (create an account or reset its password) and `unlock`.

The cryptographic basics are sound: PBKDF2-HMAC-SHA256 with a 16-byte `SecureRandom` salt, constant-time comparison, a dummy hash for unknown users, generic error messages, and fail-closed handling of corrupt state files. The most important problems are in how the anti-guessing control and the administrator functions are enforced:

- **SEC-01 (High):** Lockout state is loaded once when a process starts and the whole in-memory map is written back after every attempt. Protection from `synchronized` only works inside one JVM. Two or more login processes sharing the data directory get separate attempt budgets. A long-running "stale" process also erases lockouts that other processes wrote. Guessing is therefore effectively unlimited, which defeats the program's main security requirement. The README claim that "trying many attempts at once does not help" does not hold across processes.
- **SEC-02 (High):** `add-user` (password reset) and `unlock` require no authentication. The login flow needs read/write access to the data directory, so anyone who can start the login program with arguments can reset any employee's password and take over the account.
- **Medium:** Permissions of a pre-existing data directory and its files are never checked (SEC-03). Lockout records for arbitrary usernames are never pruned, so the lockout file grows without limit (SEC-04).
- **Low:** The credential store location comes from the caller's environment or the working directory (SEC-05). Anyone can trigger lockouts of up to 24 hours (SEC-06). There is no per-session or cross-account throttling, which allows password spraying (SEC-07). The PBKDF2 iteration count is below current OWASP guidance for SHA-256 (SEC-08). The password policy checks length only (SEC-09).

No Java runtime was available in the review environment. All findings come from static analysis. The SEC-01 attack sequence was traced line by line through the code.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `EmployeePortalAuth.java` | The whole program: CLI entry point, `Authenticator`, `PasswordHasher`, `CredentialStore`, `LoginAttemptTracker`, `AuditLog`, `Storage` file helpers, `Terminal` console input | Authentication and brute-force lockout, PBKDF2 password hashing and salt generation, flat-file credential and lockout storage, file permissions and atomic writes, data-directory selection from system property or environment, unauthenticated administrator commands (`add-user`, `unlock`), audit logging, password input without echo |
| `README.md` | Plain-English build, usage and design documentation | Reviewed for security claims and deployment assumptions (lockout guarantees, "only the user who runs the program can open it", known limits). Not executable. |
| `prompt.txt` | Original generation request | No executable code. Read for the intended requirement ("prevent unlimited consecutive attempts against a single account"). |
| `cyber_prompt.txt` | Instructions for this review task | No executable code |
| `result.md`, `return.txt` | Metadata and summary from the run that generated the code | No executable code. No secrets found. |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. Read every file, extracted keywords (authentication, brute-force lockout, password hashing/KDF, race condition, file storage/permissions, sensitive data), grepped the skill library by name, and selected the skills below.
- `exploiting-race-condition-vulnerabilities`: Applied to the attempt-limit logic (TOCTOU / limit overrun) in `Authenticator.authenticate` and `LoginAttemptTracker` (load once, `synchronized` sections, whole-file `persist()`), across threads and across separate OS processes. Result: SEC-01.
- `testing-api-authentication-weaknesses`: Its authentication checklist (missing authentication on privileged functions, weak password policy, account enumeration, credential stuffing/spraying susceptibility, lockout behaviour) was applied to the CLI login and admin commands. The skill's HTTP/JWT scripts are not applicable to a Java CLI and were not run. Results: SEC-02, SEC-06, SEC-07, SEC-09, plus the enumeration controls in section 6.
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher` and `UserRecord`: KDF algorithm and iteration count, salt size and RNG, key length, constant-time comparison, hardcoded secrets. Its Python scanner was not run against Java. Result: SEC-08.
- `testing-for-sensitive-data-exposure`: Applied to data at rest (`users.db`, `lockouts.db`, `audit.log`), file and directory permissions, audit log content, error messages, and password echo. Result: SEC-03.
- General OWASP Top 10 / CWE knowledge (no library skill matched): external control of the data-directory path (CWE-15, SEC-05), unbounded growth of persisted state (CWE-770, SEC-04), attacker-triggered lockout denial of service (CWE-645, SEC-06), log injection (CWE-117), insecure temporary files (CWE-377), and the absence of SQL, deserialization, command execution, XML and network code (OWASP A03/A08/A10).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Lockout state is per-process and overwritten by stale processes, so the attempt limit can be bypassed | High | CWE-362 | `EmployeePortalAuth.java:543` |
| SEC-02 | Administrator commands (password reset, unlock) require no authentication | High | CWE-306 | `EmployeePortalAuth.java:105` |
| SEC-03 | Permissions of a pre-existing data directory and its files are not verified | Medium | CWE-732 | `EmployeePortalAuth.java:602` |
| SEC-04 | Lockout records for arbitrary usernames are never pruned, so state grows without limit | Medium | CWE-770 | `EmployeePortalAuth.java:485` |
| SEC-05 | Credential store location comes from the caller's environment or working directory | Low | CWE-15 | `EmployeePortalAuth.java:122` |
| SEC-06 | Anyone can lock any known account for up to 24 hours | Low | CWE-645 | `EmployeePortalAuth.java:505` |
| SEC-07 | No per-session or cross-account throttling, which allows password spraying | Low | CWE-307 | `EmployeePortalAuth.java:135` |
| SEC-08 | PBKDF2-HMAC-SHA256 iteration count below current guidance, with no rehash on login | Low | CWE-916 | `EmployeePortalAuth.java:318` |
| SEC-09 | Password policy checks length only, with no blocklist | Low | CWE-521 | `EmployeePortalAuth.java:183` |

## 5. Detailed Findings

### SEC-01: Lockout state is per-process and overwritten by stale processes, so the attempt limit can be bypassed
- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'). The result is CWE-307, Improper Restriction of Excessive Authentication Attempts.
- **Location:** `EmployeePortalAuth.java:455-482` (state loaded once), `EmployeePortalAuth.java:264-273` (in-JVM lock only), `EmployeePortalAuth.java:543-559` (whole map written back)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:264-273
            // Checking the lock, verifying the password and recording the result happen under one
            // per-account lock. Parallel requests therefore cannot get past the attempt limit.
            synchronized (state) {
                Instant lockedUntil = tracker.activeLockout(state);
                if (lockedUntil != null) {
                    // The password is not checked while the account is locked. A correct guess
                    // during a lockout therefore reveals nothing.
                    audit.record("LOGIN_REJECTED_LOCKED", username);
                    return new AuthOutcome(AuthStatus.LOCKED_OUT, username, lockedUntil);
                }

// EmployeePortalAuth.java:543-559
        private synchronized void persist() {
            List<String> lines = new ArrayList<>();
            lines.add("# Employee portal lockout state. Format: username:failures:lockouts:lockedUntil:lastFailure");
            states.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
                AccountState s = e.getValue();
                if (!s.isClear()) {
                    lines.add(e.getKey() + ":" + s.consecutiveFailures + ":" + s.lockoutCount + ":"
                            + s.lockedUntilMillis + ":" + s.lastFailureMillis);
                }
            });
            try {
                Storage.writeAtomically(file, lines);
            } catch (IOException e) {
                // Fail closed: the caller gets an error, not a successful login.
                throw new UncheckedIOException("could not save lockout state", e);
            }
        }
```

**Why it is a problem:** Each `java EmployeePortalAuth` invocation is its own JVM. `LoginAttemptTracker` reads `lockouts.db` only in its constructor (lines 455-482), and `activeLockout` (line 490) checks only the in-memory copy. `persist()` then replaces the file with that process's in-memory map. The `synchronized` blocks serialise threads inside one JVM but do nothing between processes. Any real deployment where several employees log in at once (terminal sessions, SSH forced command, a kiosk or web wrapper that spawns the CLI) runs several processes against the same files.

1. **Parallel budgets:** N login processes started together each load a clean state and each allow 5 guesses (4 plus the one that triggers the lock) before their own in-memory lock applies. That gives 5×N guesses.
2. **Lockout erasure (unlimited guessing):** The attacker starts process X and leaves it idle, so its snapshot has no lock on the victim. In a second process they make 5 wrong guesses against `victim`, which writes a 15-minute lock. In X they then enter any unused well-formed username (for example `zz-1`) with a wrong password. `recordFailure` calls `persist()` (line 510), which rewrites `lockouts.db` from X's stale map, so the victim's lock and escalation count disappear from disk. A newly started process sees `victim` as clear and allows 5 more guesses. Using a fresh bogus name each time lets X keep erasing the lock, so the attacker gets unlimited guesses at about 1 per second per process. Lockouts also never escalate.
3. Stale processes also undo an administrator's `unlock`/`reset` and miss password resets. `CredentialStore` is also loaded once (lines 396-413), so a login process started before an administrator resets a compromised password still accepts the old password.

This defeats the core requirement in `prompt.txt` and contradicts README points 5 and 6.

**Fix:** Serialise the check-verify-record sequence across processes with an OS-level exclusive file lock. Inside that lock, reload the lockout and credential state from disk, so every decision and every write uses the current on-disk state. Administrator commands must take the same lock and reload before `save`/`reset`. Sleep after releasing the lock. For multi-server deployments, move the state into a transactional database and use an atomic conditional update (for example `UPDATE ... SET failures = failures + 1 ... RETURNING`, or `SELECT ... FOR UPDATE`).
```java
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

// In LoginAttemptTracker (and the same for CredentialStore): move the parsing loop out of the
// constructor into parse(file) and expose reload(), so each attempt works on the on-disk state.
synchronized void reload() throws IOException {
    Map<String, AccountState> fresh = parse(file);   // same parsing and fail-closed checks as today
    states.clear();
    states.putAll(fresh);
}

// In Authenticator: lockFile = dataDir.resolve("portal.lock"), passed in from main().
AuthOutcome authenticate(String rawUsername, char[] password) throws IOException {
    String username = normalizeUsername(rawUsername);
    if (username == null) {
        PasswordHasher.verify(password, dummySalt, PasswordHasher.ITERATIONS, dummyHash);
        audit.record("LOGIN_FAILED_MALFORMED_USERNAME", null);
        pauseAfterFailure();
        return new AuthOutcome(AuthStatus.INVALID_CREDENTIALS, null, null);
    }

    AuthOutcome outcome;
    // One exclusive OS-level lock shared by every process that uses this data directory.
    try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
         FileLock ignored = channel.lock()) {
        tracker.reload();   // see failures and lockouts written by other processes
        store.reload();     // see password resets and new accounts
        LoginAttemptTracker.AccountState state = tracker.stateFor(username);
        synchronized (state) {
            // Existing body: activeLockout -> verify -> recordSuccess/recordFailure (which persists),
            // without the pauseAfterFailure() call.
            outcome = checkVerifyAndRecord(username, password, state);
        }
    }
    if (outcome.status() != AuthStatus.SUCCESS) {
        pauseAfterFailure();   // after releasing the lock, so other accounts are not blocked
    }
    return outcome;
}
```

### SEC-02: Administrator commands (password reset, unlock) require no authentication
- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `EmployeePortalAuth.java:103-108`, `EmployeePortalAuth.java:169-213`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:103-108
            if (args.length == 0) {
                runLogin(terminal, authenticator);
            } else if (args.length == 2 && args[0].equals("add-user")) {
                runAddUser(terminal, store, tracker, audit, args[1]);
            } else if (args.length == 2 && args[0].equals("unlock")) {
                runUnlock(terminal, tracker, audit, args[1]);

// EmployeePortalAuth.java:188-191
            boolean existed = store.find(username).isPresent();
            store.save(UserRecord.create(username, first));
            tracker.reset(username);
            audit.record(existed ? "PASSWORD_RESET" : "USER_CREATED", username);
```

**Why it is a problem:** The login program and the administrator functions share one entry point and one data directory. To log anyone in, the process must be able to read `users.db` and write `lockouts.db`, so whatever OS identity runs the login also has everything `add-user` needs. The code performs no administrator check: no admin credential, no role, no OS group check. `add-user <existing name>` silently replaces the victim's password and clears the lockout. Anyone who can start the program with arguments (a shell as the portal service account, a wrapper or sudo rule that passes arguments through, a kiosk script that forwards input) can run `java EmployeePortalAuth add-user ceo`, choose a new password, and log in as that employee. `unlock` lets an attacker clear lockouts between guessing rounds, which also defeats the brute-force control. The "(administrator)" labels in the usage text and README are documentation only.

**Fix:** Take administrative operations out of the login entry point. Give them a separate program that is installed so only administrators can run it, and that re-authenticates an administrator account listed in a roster the login identity cannot modify. Audit the acting administrator as well as the target account.
```java
// EmployeePortalAuth.main: the login entry point accepts no arguments at all.
public static void main(String[] args) {
    if (args.length != 0) {
        System.err.println("Usage: java EmployeePortalAuth");
        System.exit(2);
    }
    Path dataDir = resolveDataDir();
    Terminal terminal = new Terminal();
    try {
        Storage.ensurePrivateDirectory(dataDir);
        CredentialStore store = new CredentialStore(dataDir.resolve("users.db"));
        LoginAttemptTracker tracker =
                new LoginAttemptTracker(dataDir.resolve("lockouts.db"), Clock.systemUTC());
        AuditLog audit = new AuditLog(dataDir.resolve("audit.log"), Clock.systemUTC());
        runLogin(terminal, new Authenticator(store, tracker, audit));
    } catch (IOException | UncheckedIOException e) {
        System.err.println("Error: the portal records could not be read or written: " + e.getMessage());
        System.exit(1);
    }
}

// EmployeePortalAdmin.java: separate class, installed executable only by the portal-admins group.
// The admin roster (admins.txt) is owned by root and not writable by the login service account.
static void requireAdministrator(Terminal terminal, Authenticator authenticator, Set<String> adminRoster,
                                 AuditLog audit) throws IOException {
    String admin = terminal.readLine("Administrator username: ");
    char[] pw = terminal.readPassword("Administrator password: ");
    AuthOutcome outcome;
    try {
        outcome = authenticator.authenticate(admin, pw == null ? new char[0] : pw);
    } finally {
        if (pw != null) {
            Arrays.fill(pw, '\0');
        }
    }
    if (outcome.status() != AuthStatus.SUCCESS || !adminRoster.contains(outcome.username())) {
        audit.record("ADMIN_AUTH_FAILED", outcome.username());
        System.exit(1);
    }
    audit.record("ADMIN_AUTH_OK", outcome.username());
}
```

### SEC-03: Permissions of a pre-existing data directory and its files are not verified
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `EmployeePortalAuth.java:602-609`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:602-609
        static void ensurePrivateDirectory(Path dir) throws IOException {
            if (Files.notExists(dir)) {
                Files.createDirectories(dir);
                if (posix(dir)) {
                    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
                }
            }
        }
```

**Why it is a problem:** Permissions are only restricted when the program creates the directory itself. If the directory already exists, the program uses it as-is. That covers the README's `/srv/portal/auth` example created with `mkdir`, a group-writable directory, a directory in a shared location, or a symbolic link. Pre-existing `users.db` and `lockouts.db` files are also not checked. The consequences:
- If group or others can write to the directory, they can rename, delete or replace `users.db` even when the file itself is `0600`, because unlinking and renaming depend on the directory's permissions. Replacing it with their own hash for any username gives account takeover. Deleting `lockouts.db` clears every lockout. They can also plant a symlink named `audit.log`, which gets followed at lines 580-583.
- If `users.db` was created or copied with `0644`, every local user can read the password hashes and crack them offline. The file is only rewritten as `0600` when an administrator saves, never during login.

The README states "Only the user who runs the program can open it", but the code does not enforce this.

**Fix:** Create the directory with owner-only permissions atomically. Reject symbolic links and non-directories. Refuse to start if the directory or any existing data file is accessible to group or others. Tightening permissions silently is not enough, because tampering may already have happened.
```java
static void ensurePrivateDirectory(Path dir) throws IOException {
    if (Files.notExists(dir, LinkOption.NOFOLLOW_LINKS)) {
        if (posix(dir)) {
            Files.createDirectories(dir,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(dir);
        }
    }
    if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException(dir + " is not a directory (symbolic links are not accepted)");
    }
    requireOwnerOnly(dir);
    for (String name : List.of("users.db", "lockouts.db", "audit.log")) {
        Path f = dir.resolve(name);
        if (Files.exists(f, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException(f + " is not a regular file");
            }
            requireOwnerOnly(f);
        }
    }
}

private static void requireOwnerOnly(Path p) throws IOException {
    if (!posix(p)) {
        return;
    }
    Set<PosixFilePermission> perms = Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS);
    for (PosixFilePermission perm : perms) {
        if (perm.name().startsWith("GROUP_") || perm.name().startsWith("OTHERS_")) {
            throw new IOException(p + " must not be accessible to group or others (found "
                    + PosixFilePermissions.toString(perms) + ")");
        }
    }
}
```

### SEC-04: Lockout records for arbitrary usernames are never pruned, so state grows without limit
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `EmployeePortalAuth.java:484-487`, `EmployeePortalAuth.java:446-448`, `EmployeePortalAuth.java:546-552`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:484-487
        /** Returns the single shared state object for a username. It is never removed from the map. */
        AccountState stateFor(String username) {
            return states.computeIfAbsent(username, k -> new AccountState());
        }

// EmployeePortalAuth.java:546-552
            states.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
                AccountState s = e.getValue();
                if (!s.isClear()) {
                    lines.add(e.getKey() + ":" + s.consecutiveFailures + ":" + s.lockoutCount + ":"
                            + s.lockedUntilMillis + ":" + s.lastFailureMillis);
                }
            });
```

**Why it is a problem:** To avoid user enumeration, every well-formed username gets tracked, including names that don't exist. After a single failed attempt, `consecutiveFailures` is non-zero, so the entry is written to `lockouts.db`. Entries are never removed. Once a lock has expired and the 24-hour escalation window has passed, `lockoutCount` and `lockedUntilMillis` stay non-zero, so `isClear()` stays false forever. Only a successful login or an administrator reset clears an entry, and neither happens for made-up usernames. An attacker who submits random 64-character usernames adds one permanent line per attempt, from as many processes as they like. Every failed attempt then sorts the whole map and rewrites the whole file (lines 543-554), and every process start parses it all (lines 459-480). Login latency and disk use grow without bound until startup becomes very slow or the disk fills. A full disk makes `persist()` fail, which exits the program, so no one can log in.

**Fix:** Treat entries whose lock has expired and whose escalation window has passed as clear. Such an entry already behaves exactly like a fresh state in `recordFailure` and `activeLockout`, so drop it on load and on persist. Enforce a hard limit on file size and alert when it is reached.
```java
/** True when the entry can no longer affect any decision: no active lock and the escalation window has passed. */
static boolean isExpired(AccountState s, long now) {
    long quietSince = Math.max(s.lastFailureMillis, s.lockedUntilMillis);
    return now >= s.lockedUntilMillis && now - quietSince > ESCALATION_RESET_WINDOW.toMillis();
}

private synchronized void persist() {
    long now = clock.millis();
    List<String> lines = new ArrayList<>();
    lines.add("# Employee portal lockout state. Format: username:failures:lockouts:lockedUntil:lastFailure");
    states.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
        AccountState s = e.getValue();
        if (!s.isClear() && !isExpired(s, now)) {
            lines.add(e.getKey() + ":" + s.consecutiveFailures + ":" + s.lockoutCount + ":"
                    + s.lockedUntilMillis + ":" + s.lastFailureMillis);
        }
    });
    if (lines.size() > MAX_TRACKED_ACCOUNTS) {   // e.g. 100_000; alert operators, fail closed
        throw new UncheckedIOException(new IOException("lockout state exceeds " + MAX_TRACKED_ACCOUNTS + " entries"));
    }
    try {
        Storage.writeAtomically(file, lines);
    } catch (IOException e) {
        throw new UncheckedIOException("could not save lockout state", e);
    }
}

// In the loading loop (constructor / reload), skip entries that are already expired:
//     if (!isExpired(s, clock.millis())) { states.put(p[0], s); }
```

### SEC-05: Credential store location comes from the caller's environment or working directory
- **Severity:** Low
- **CWE:** CWE-15: External Control of System or Configuration Setting
- **Location:** `EmployeePortalAuth.java:122-131`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:122-131
    private static Path resolveDataDir() {
        String dir = System.getProperty("portal.dataDir");
        if (dir == null || dir.isBlank()) {
            dir = System.getenv("PORTAL_DATA_DIR");
        }
        if (dir == null || dir.isBlank()) {
            dir = "portal-data";
        }
        return Paths.get(dir);
    }
```

**Why it is a problem:** The source of truth for authentication (which accounts exist, their hashes, and their lockout state) is chosen by whoever controls the process environment or the working directory. The default is a relative path, so running the program from a different directory silently creates an empty, separate store. That drops all lockouts, and administrator changes end up in the wrong store. If a wrapper passes the caller's environment through, or runs the program from a user-controlled directory, the caller can point `PORTAL_DATA_DIR` at a directory containing their own `users.db` and "authenticate" as anyone. The login decision then no longer reflects the real records.

**Fix:** Use a fixed absolute path owned by the portal service account, or read it from a root-owned configuration file. Do not accept overrides from the environment or relative paths in production builds.
```java
/** Fixed location owned by the portal service account; never taken from the caller's environment. */
static final Path DATA_DIR = Paths.get("/var/lib/employee-portal");

private static Path resolveDataDir() {
    if (!DATA_DIR.isAbsolute()) {
        throw new IllegalStateException("data directory must be absolute");
    }
    return DATA_DIR;
}
```

### SEC-06: Anyone can lock any known account for up to 24 hours
- **Severity:** Low
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `EmployeePortalAuth.java:61-68`, `EmployeePortalAuth.java:505-509`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:61-68
    /** Consecutive failed attempts allowed before the account is locked. */
    static final int MAX_CONSECUTIVE_FAILURES = 5;

    /** Length of the first lockout. Each further lockout doubles, up to MAX_LOCKOUT. */
    static final Duration BASE_LOCKOUT = Duration.ofMinutes(15);

    /** Upper limit for any single lockout. */
    static final Duration MAX_LOCKOUT = Duration.ofHours(24);

// EmployeePortalAuth.java:505-509
            if (s.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                s.lockedUntilMillis = now + lockoutDuration(s.lockoutCount).toMillis();
                s.lockoutCount = s.lockoutCount + 1;
                s.consecutiveFailures = 0;
            }
```

**Why it is a problem:** No credential is needed to lock an account. Five wrong passwords for a username lock it. Repeating the 5 attempts each time a lock expires escalates to 24-hour locks (15 min, 30 min, … 16 h, 24 h). Usernames follow an obvious pattern (`jsmith`), so one person can lock out a whole department or a specific administrator, and a correct password is refused during the lock. The README acknowledges this, but the only recovery is a manual administrator `unlock`, which SEC-01 and SEC-02 show is itself weak.

**Fix:** Use a hard lock that is short and capped, and prefer throttling (rising delays) over long lockouts, following NIST SP 800-63B §5.2.2. Alert on repeated lockouts so the attack is visible. Where possible, offer a second factor so a legitimate user can unlock themselves.
```java
/** Consecutive failed attempts allowed before the account is temporarily locked. */
static final int MAX_CONSECUTIVE_FAILURES = 10;

/** Short first lock; each further lock doubles, capped so a malicious lockout cannot last a working day. */
static final Duration BASE_LOCKOUT = Duration.ofMinutes(1);
static final Duration MAX_LOCKOUT = Duration.ofMinutes(30);

// in recordFailure, after applying a lock:
if (s.lockoutCount >= 3) {
    audit.record("ALERT_REPEATED_LOCKOUT", username);   // forward to monitoring / SIEM
}
```

### SEC-07: No per-session or cross-account throttling, which allows password spraying
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `EmployeePortalAuth.java:133-136`, `EmployeePortalAuth.java:161-165`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:133-136
    private static void runLogin(Terminal terminal, Authenticator authenticator) throws IOException {
        terminal.println("=== Employee Portal Login ===");
        while (true) {
            String username = terminal.readLine("Username (leave blank to quit): ");

// EmployeePortalAuth.java:161-165
                case INVALID_CREDENTIALS:
                default:
                    terminal.println("Access denied. Invalid username or password.");
                    break;
            }
```

**Why it is a problem:** All limits are per account. One session can loop forever, trying `Winter2026!!` or other common passwords against every username at 1 attempt per second (4 guesses per account before a lock) without ever triggering a lockout. Across many parallel sessions the total rate is unbounded. The program has no global failed-login rate limit and no per-session attempt cap, so password spraying and credential stuffing with leaked lists go unchecked. This is the attack the README admits the design does not stop.

**Fix:** End the session after a few failures, whichever accounts they were against. Add a global failed-attempt rate limit, stored under the same cross-process lock as SEC-01, that slows every login when it is exceeded. For anything reachable outside a trusted network, add MFA.
```java
private static final int MAX_FAILURES_PER_SESSION = 3;

private static void runLogin(Terminal terminal, Authenticator authenticator) throws IOException {
    terminal.println("=== Employee Portal Login ===");
    int sessionFailures = 0;
    while (sessionFailures < MAX_FAILURES_PER_SESSION) {
        String username = terminal.readLine("Username (leave blank to quit): ");
        if (username == null || username.isBlank()) {
            terminal.println("Goodbye.");
            return;
        }
        char[] password = terminal.readPassword("Password: ");
        if (password == null) {
            return;
        }
        AuthOutcome outcome;
        try {
            outcome = authenticator.authenticate(username, password);   // also enforces a global failure-rate limit
        } finally {
            Arrays.fill(password, '\0');
        }
        if (outcome.status() == AuthStatus.SUCCESS) {
            terminal.println("Access granted. Welcome, " + outcome.username() + ".");
            return;
        }
        sessionFailures++;
        terminal.println(outcome.status() == AuthStatus.LOCKED_OUT
                ? "Access denied. Too many failed attempts. This account is locked until "
                        + TIME_FORMAT.format(outcome.lockedUntil()) + "."
                : "Access denied. Invalid username or password.");
    }
    terminal.println("Too many failed attempts in this session.");
}
```

### SEC-08: PBKDF2-HMAC-SHA256 iteration count below current guidance, with no rehash on login
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `EmployeePortalAuth.java:317-320`, `EmployeePortalAuth.java:381-383`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:317-320
        static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        static final int ITERATIONS = 210_000;
        static final int MIN_ITERATIONS = 10_000;
        static final int MAX_ITERATIONS = 5_000_000;
```

**Why it is a problem:** 210,000 iterations is the OWASP Password Storage Cheat Sheet figure for PBKDF2-HMAC-**SHA512**. For PBKDF2-HMAC-**SHA256** the recommendation is 600,000. If `users.db` is stolen (see SEC-03), cracking costs about 3× less than recommended. Records with as few as 10,000 iterations are also accepted (lines 381-383) and never upgraded, so legacy or tampered-in weak hashes stay weak forever.

**Fix:** Raise the work factor. On every successful login, transparently rehash any record below the current count, under the cross-process lock from SEC-01 so the save cannot overwrite concurrent administrator changes. Consider Argon2id (via a vetted library) for memory hardness.
```java
static final String ALGORITHM = "PBKDF2WithHmacSHA256";
static final int ITERATIONS = 600_000;          // OWASP guidance for PBKDF2-HMAC-SHA256
static final int MIN_ITERATIONS = 100_000;      // older records are still readable, then upgraded
static final int MAX_ITERATIONS = 5_000_000;

// In Authenticator.authenticate, inside the lock, when the password is valid:
if (valid && record.get().iterations() < PasswordHasher.ITERATIONS) {
    store.save(UserRecord.create(username, password));   // rehash with the current work factor
}
```

### SEC-09: Password policy checks length only, with no blocklist
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `EmployeePortalAuth.java:183-187`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:183-187
            if (first.length < MIN_PASSWORD_LENGTH || first.length > MAX_PASSWORD_LENGTH) {
                terminal.println("Passwords must be between " + MIN_PASSWORD_LENGTH + " and "
                        + MAX_PASSWORD_LENGTH + " characters. No changes were made.");
                System.exit(2);
            }
```

**Why it is a problem:** Any 12-character string is accepted, including `passwordpassword`, `123456789012`, `Company2026!`, or the username repeated. The main defence left against the spraying in SEC-07 is that passwords must not be common, and nothing checks for that. NIST SP 800-63B requires checking new passwords against known-breached and commonly used values and context-specific words.

**Fix:** Reject passwords found in a breached or common-password blocklist, and passwords that contain the username or the portal or company name. Keep the length limits.
```java
if (first.length < MIN_PASSWORD_LENGTH || first.length > MAX_PASSWORD_LENGTH) {
    terminal.println("Passwords must be between " + MIN_PASSWORD_LENGTH + " and "
            + MAX_PASSWORD_LENGTH + " characters. No changes were made.");
    System.exit(2);
}
String candidate = new String(first).toLowerCase(Locale.ROOT);
// PasswordBlocklist loads a breached/common password list (e.g. a top-100k list) from a read-only resource.
if (PasswordBlocklist.contains(candidate)
        || candidate.contains(username)
        || candidate.contains("portal")
        || candidate.chars().distinct().count() < 5) {
    terminal.println("That password is too common or too easy to guess. No changes were made.");
    System.exit(2);
}
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm and salt:** PBKDF2WithHmacSHA256 with a 256-bit derived key and a per-user 16-byte salt from a shared `SecureRandom` (`EmployeePortalAuth.java:316-332`, `364-368`). No MD5/SHA-1, no unsalted hashing, no predictable RNG. Only the iteration count is flagged (SEC-08).
- **Constant-time comparison:** `MessageDigest.isEqual` is used for the hash comparison (`EmployeePortalAuth.java:352`).
- **Hardcoded secrets:** No passwords, keys, tokens or default accounts in the source, README or metadata files.
- **Username enumeration:** Every bad username or password gets the same message (`EmployeePortalAuth.java:161-164`). Unknown and malformed usernames still run a full PBKDF2 against a random dummy hash (`254`, `281`). Unknown usernames are tracked and locked like real ones (`260-262`), so lockout messages don't reveal which accounts exist. The account lookup happens only after the lock check (`266-275`).
- **No password verification while locked:** A locked account is rejected before the password is checked (`EmployeePortalAuth.java:267-273`), so a correct guess during a lock reveals nothing.
- **In-process concurrency:** Within one JVM, the check-verify-record sequence runs under a per-account monitor that is never removed (`266`, `485-487`), and `persist()` is synchronized (`543`). Lock ordering (account, then tracker) is consistent in `authenticate` and `reset` (`526-534`), so no deadlock. Cross-process behaviour is the problem (SEC-01).
- **Fail-closed state handling:** A failure to persist lockout state stops the process without granting access (`EmployeePortalAuth.java:553-558`, `116-119`). Malformed `lockouts.db` or `users.db` lines stop startup instead of being skipped (`476-479`, `408-410`).
- **Lockout arithmetic:** The escalation shift is capped at 20 and the duration at `MAX_LOCKOUT`, so there is no overflow (`EmployeePortalAuth.java:537-541`).
- **Input validation / injection into files and logs (CWE-117, CWE-93):** Usernames are normalised and must match `^[a-z0-9._-]{1,64}$` (`80`, `242-248`) before they are used in the `:`-delimited stores or the audit log. Malformed names are logged as `<invalid>` (`577`), so an attacker cannot inject delimiters or newlines. Stored records are validated again on load (`377`, `467`).
- **Resource limits on hashing:** Passwords over 128 characters and empty passwords are rejected before hashing (`EmployeePortalAuth.java:347-349`). Iteration counts loaded from disk are capped at 5,000,000 (`381-383`), which stops a hash-cost denial of service.
- **Sensitive data in memory and logs:** Password arrays are wiped after use (`150`, `194-199`), `PBEKeySpec.clearPassword()` is called (`341`), and derived candidates are zeroed (`354`). The audit log records only event and username, never passwords (`576-578`). Error output shows only the I/O message, with no stack trace (`117`).
- **Password echo:** `Console.readPassword` is used when a terminal is present (`EmployeePortalAuth.java:662-664`). Without a console, the program prints an explicit warning that input will be visible (`677-680`). Accepted as documented behaviour.
- **File creation and temporary files (CWE-377, CWE-276):** New data files and temp files are created with `rw-------` (`614`, `626-629`). Temp files use unpredictable names from `Files.createTempFile` in the target directory and are atomically moved into place and cleaned up (`624-640`). Pre-existing directory and file permissions are not checked (SEC-03).
- **Not present / not applicable:** No SQL or NoSQL queries (no SQL injection), no object deserialization (`readAllLines` plus strict parsing only), no OS command execution, no XML parsing (no XXE), no outbound network or TLS use (no SSRF or transport issues), no JWT or session tokens, and no web output (no XSS).
