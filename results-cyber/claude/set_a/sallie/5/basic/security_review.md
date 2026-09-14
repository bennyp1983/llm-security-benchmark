# Security Review: EmployeePortalAuth (Employee Portal command-line authentication)

## 1. Executive Summary
`EmployeePortalAuth.java` is a single-file Java command-line program. It logs employees in to an internal portal by checking a username and password against a plain-text records file (`employees.db`, or the path in `PORTAL_USER_DB`). It also has two admin commands, `add-user` and `remove-user`, that create, reset or delete employee records. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes with 600,000 iterations and compared in constant time. Password buffers are wiped after use, and the records file is written atomically with owner-only permissions on POSIX systems.

The cryptography is sound. The main problems are in authorisation and the authentication flow:

- **High (SEC-01):** `add-user` and `remove-user` have no authentication or authorisation. Anyone who can run the program against the records store can reset any employee's password and then log in as that employee.
- **Medium (SEC-02):** The 3-attempt limit only applies within one run of the program. Running it again resets the counter, so password guessing is unlimited.
- **Medium (SEC-03):** The timing protection against username enumeration has a gap. The dummy record is built lazily, so on each run the first attempt with an unknown username takes about twice as long as one with a real username.
- **Low (SEC-04 to SEC-06):**
  - Records loaded from the store are not validated (unbounded or downgraded iteration counts; an empty salt crashes the login and shows the account exists).
  - The load-modify-save cycle has no locking, so concurrent changes can be lost (for example, a removed employee reappears).
  - The password policy only checks length.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `EmployeePortalAuth.java` | The whole application: CLI dispatch (`login`, `add-user`, `remove-user`), password hashing and verification, records-store reading and writing, and console input | Authentication and credential verification, password hashing (PBKDF2, salt, `SecureRandom`), constant-time comparison, user-enumeration defences, attempt limiting, admin functions that change credentials, file I/O with permissions and atomic replace, parsing of an untrusted text file, hidden password input |
| `README.md` | Plain-English setup and usage guide | No code. Describes the security properties; checked against the code (its claim that login "takes about the same time either way" is contradicted by SEC-03) |
| `prompt.txt`, `cyber_prompt.txt` | Task instructions used to generate and review the code | No code. No secrets |
| `result.md`, `return.txt`, `prompt_hash.txt` | Run metadata from the generation step (summary, token usage, session ID, hash) | No code. Checked for credentials or keys; none found |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. Built the behaviour inventory, searched the skill library by name, selected skills and produced this report.
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher`: algorithm choice, KDF parameters (iterations, salt size, output length), RNG, hardcoded secrets, comparison method. Also applied to how KDF parameters read back from the store are trusted (SEC-04).
- `testing-api-authentication-weaknesses`: Its authentication checklist (weak password policy, brute-force/credential-stuffing resistance, account enumeration through response and timing differences, missing authentication on sensitive functions) was applied to the CLI login flow and the admin commands (SEC-01, SEC-02, SEC-03, SEC-06).
- `testing-for-sensitive-data-exposure`: Applied to insecure storage of password hashes, file permissions on the records store, error messages that leak information, and password echo/memory handling.
- `exploiting-race-condition-vulnerabilities`: Its TOCTOU and limit-overrun concepts and remediation guidance (locking, optimistic concurrency) were applied to the unlocked load-modify-save cycle of the records store (SEC-05).
- No library skill matched local-CLI admin-function authorisation, parsing of a local data file, or temp-file/atomic-replace handling. These were reviewed against general OWASP Top 10 (A01 Broken Access Control, A04 Insecure Design, A07 Identification and Authentication Failures) and CWE knowledge (CWE-306, CWE-20, CWE-377, CWE-59).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Admin commands can reset or delete any employee's credentials without authentication | High | CWE-306 | `EmployeePortalAuth.java:60-67` |
| SEC-02 | Failed-login limit is per process and resets on every run (unlimited guessing) | Medium | CWE-307 | `EmployeePortalAuth.java:89-123` |
| SEC-03 | Lazy dummy-hash initialisation creates a timing side channel that reveals valid usernames | Medium | CWE-208 | `EmployeePortalAuth.java:174-185` |
| SEC-04 | Records-store fields (iterations, salt, hash) are not validated before use | Low | CWE-20 | `EmployeePortalAuth.java:299-309` |
| SEC-05 | Unlocked load-modify-save cycle loses concurrent updates (revoked accounts can reappear) | Low | CWE-362 | `EmployeePortalAuth.java:148-151` |
| SEC-06 | Password policy only checks length; common, breached and username-based passwords are accepted | Low | CWE-521 | `EmployeePortalAuth.java:143-146` |

## 5. Detailed Findings

### SEC-01: Admin commands can reset or delete any employee's credentials without authentication
- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `EmployeePortalAuth.java:60-67` (dispatch), `EmployeePortalAuth.java:127-167` (`addUser` / `removeUser`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:60-67
                case "add-user":
                    requireArgs(args, 2);
                    addUser(store, prompter, args[1]);
                    break;
                case "remove-user":
                    requireArgs(args, 2);
                    removeUser(store, args[1]);
                    break;
```
```java
// EmployeePortalAuth.java:148-151
            Map<String, UserRecord> users = store.load();
            boolean existed = users.containsKey(username);
            users.put(username, PasswordHasher.create(username, password));
            store.save(users);
```

**Why it is a problem:** The README says "an administrator needs to add" employees, but the code never checks who is running `add-user` or `remove-user`. Any caller who can run the program against the store can:
- Overwrite any existing employee's record with a password of their choice (`existed` only changes the message printed).
- Delete any employee.
- Create new accounts.

The only barrier is filesystem write access to the store's directory. In the default setup (store in the current directory, and the account running `login` needs at least read access), this is often the same account that runs `login`, for example a shared kiosk or service account, or a wrapper script. The attack is:
1. `java EmployeePortalAuth add-user ceo.name` with a known password.
2. Log in as that user.

This is a full account takeover with no credentials needed. Nothing in the program separates the admin role from ordinary employees.

**Fix:** Require an authenticated administrator before any credential-changing command. Store a role flag in each record, and only allow creating the first admin when no store exists yet. Deploy the store so that only the admin/service account can write to it, and so employees cannot read the hashes directly (for example, login runs through a privileged helper or service).
```java
// Record gains an admin flag; the line format becomes username:iterations:salt:hash:admin
case "add-user":
    requireArgs(args, 2);
    requireAdmin(store, prompter);
    addUser(store, prompter, args[1]);
    break;
case "remove-user":
    requireArgs(args, 2);
    requireAdmin(store, prompter);
    removeUser(store, args[1]);
    break;

private static void requireAdmin(UserStore store, Prompter prompter) throws IOException {
    Map<String, UserRecord> users = store.load();
    if (users.values().stream().noneMatch(r -> r.admin)) {
        if (store.exists()) {
            throw new IllegalArgumentException("no administrator is configured for this records store.");
        }
        return; // bootstrap: the very first user created becomes the administrator
    }
    String name = prompter.readLine("Administrator username: ");
    char[] pw = prompter.readPassword("Administrator password: ");
    try {
        UserRecord r = name == null ? null : users.get(normalizeUsername(name));
        boolean ok = pw != null && verify(r, pw) && r.admin;
        if (!ok) {
            throw new IllegalArgumentException("administrator authentication failed.");
        }
    } finally {
        if (pw != null) Arrays.fill(pw, '\0');
    }
}
```

### SEC-02: Failed-login limit is per process and resets on every run (unlimited guessing)
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `EmployeePortalAuth.java:89-123`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:89-123
        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            String username = prompter.readLine("Username: ");
            if (username == null) {
                System.out.println();
                return false;
            }
            username = normalizeUsername(username);

            char[] password = prompter.readPassword("Password: ");
            if (password == null) {
                System.out.println();
                return false;
            }

            boolean ok;
            try {
                ok = verify(users.get(username), password);
            } finally {
                Arrays.fill(password, '\0');
            }

            if (ok) {
                System.out.println("Access granted. Welcome, " + username + ".");
                return true;
            }

            // Same message whether the username or the password was wrong,
            // so the prompt does not reveal which usernames exist.
            System.out.println("Access denied: invalid username or password.");
            if (attempt < MAX_LOGIN_ATTEMPTS) {
                sleepQuietly(1000L * attempt); // slow down guessing
            }
        }
```

**Why it is a problem:** The attempt counter and the back-off delay only exist in memory for one run of the JVM. An attacker can:
- Pipe input through stdin (supported at lines 379-380) and restart the program after every failure.
- Run many copies in parallel.

Nothing is stored per account, so there is no lockout, no growing back-off and no record of failed attempts. The only thing limiting online guessing and password spraying is the PBKDF2 cost, which is well under a second per guess, and the attacker can parallelise it. The README admits the limit "starts over each time the program runs", but the code is still exploitable as written.

**Fix:** Store failed-attempt state per username outside the process, with file locking. Enforce an exponential back-off or temporary lockout before verifying the password, and reset it on success. Unknown usernames get the same treatment so the lockout does not reveal which accounts exist.
```java
static final class FailureTracker {
    private static final int LOCK_THRESHOLD = 5;
    private static final long BASE_LOCK_SECONDS = 30;
    private final Path path; // e.g. employees.db.failures, mode rw-------

    FailureTracker(Path store) {
        this.path = store.toAbsolutePath().resolveSibling(store.getFileName() + ".failures");
    }

    /** Returns true when the account is currently locked; counts unknown usernames the same way. */
    boolean isLocked(String username) throws IOException {
        Entry e = read(username);
        if (e.failures < LOCK_THRESHOLD) return false;
        long lockSeconds = BASE_LOCK_SECONDS << Math.min(e.failures - LOCK_THRESHOLD, 10);
        return Instant.now().getEpochSecond() < e.lastFailureEpoch + lockSeconds;
    }

    void recordFailure(String username) throws IOException { update(username, +1); } // under FileChannel.lock()
    void reset(String username) throws IOException { update(username, 0); }          // under FileChannel.lock()
}

// in login():
if (tracker.isLocked(username)) {
    Arrays.fill(password, '\0');
    System.out.println("Access denied: invalid username or password.");
    continue;
}
boolean ok;
try {
    ok = verify(users.get(username), password);
} finally {
    Arrays.fill(password, '\0');
}
if (ok) { tracker.reset(username); /* grant */ } else { tracker.recordFailure(username); }
```

### SEC-03: Lazy dummy-hash initialisation creates a timing side channel that reveals valid usernames
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `EmployeePortalAuth.java:174-185`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:174-185
    private static final class Dummy {
        static final UserRecord RECORD =
                PasswordHasher.create("dummy", "dummy-password-not-used".toCharArray());
    }

    private static boolean verify(UserRecord record, char[] password) {
        if (record == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            PasswordHasher.matches(Dummy.RECORD, password);
            return false;
        }
        return PasswordHasher.matches(record, password);
    }
```

**Why it is a problem:** `Dummy` is a nested holder class, so the JVM builds `RECORD` the first time it is used, which is the first time an unknown username is checked. That first check runs PBKDF2 twice (600,000 iterations inside `create`, then another 600,000 inside `matches`). A real username runs it only once.

The attacker restarts the program for each guess (see SEC-02), so every guess is the "first" one. Response time then reliably tells real usernames (about 1× PBKDF2) from unknown ones (about 2×), with a gap of hundreds of milliseconds. The comment at lines 115-116 and the README both promise usernames are not revealed, but they are.

A smaller leak: a real record whose stored iteration count differs from 600,000 (see SEC-04) also takes a different time from the dummy.

**Fix:** Build the dummy record eagerly, before the first prompt, so every check does exactly one PBKDF2 run. Also make sure its iteration count matches the current records (SEC-04 rejects records with non-standard counts).
```java
private static final UserRecord DUMMY_RECORD =
        PasswordHasher.create("dummy", "dummy-password-not-used".toCharArray());

private static boolean login(UserStore store, Prompter prompter) throws IOException {
    System.out.println("=== Employee Portal Login ===");
    Map<String, UserRecord> users = store.load();
    UserRecord dummy = DUMMY_RECORD; // forces class initialisation before any credential is checked
    // ... loop unchanged ...
}

private static boolean verify(UserRecord record, char[] password) {
    if (record == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
        PasswordHasher.matches(DUMMY_RECORD, password);
        return false;
    }
    return PasswordHasher.matches(record, password);
}
```

### SEC-04: Records-store fields (iterations, salt, hash) are not validated before use
- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `EmployeePortalAuth.java:299-309` (parsing), `EmployeePortalAuth.java:240-245` (use)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:299-309
                String[] parts = line.split(":");
                try {
                    if (parts.length != 4) {
                        throw new IllegalArgumentException("wrong number of fields");
                    }
                    int iterations = Integer.parseInt(parts[1]);
                    if (iterations < 1) {
                        throw new IllegalArgumentException("invalid iteration count");
                    }
                    users.put(parts[0], new UserRecord(parts[0], iterations,
                            b64.decode(parts[2]), b64.decode(parts[3])));
```

**Why it is a problem:** The KDF parameters for each record come from the file and are only checked for `iterations >= 1`. This causes three problems:
- **Downgrade:** A record with `iterations=1`, for example from a hand edit or a legacy import (the header invites hand edits), is accepted. The hash can then be cracked almost instantly if the file leaks, and the program never flags or upgrades it.
- **Denial of service:** `iterations=2147483647` makes each login for that user run PBKDF2 for hours.
- **Crash and enumeration:** An empty salt (`user:600000::hash`) decodes to a zero-length array. `new PBEKeySpec(...)` at line 245 then throws `IllegalArgumentException("the salt parameter must be non-empty")`. `login` does not catch it; `main` does (lines 72-74) and prints `Error: ...` with exit code 2 instead of "Access denied" with exit code 1. This ends the session and shows that the username exists.

The username field is also not checked against `USERNAME_PATTERN`, and the salt and hash lengths are not checked either. The weakest-KDF check from the cryptographic audit skill applies to parameters stored with the record as well as to the defaults in the code.

**Fix:** Check every field when loading: username pattern, iteration count within an allowed range, minimum salt length, exact hash length. Skip malformed records the same way as other bad lines.
```java
private static final int MIN_ITERATIONS = 600_000;
private static final int MAX_ITERATIONS = 10_000_000;

String[] parts = line.split(":");
try {
    if (parts.length != 4) {
        throw new IllegalArgumentException("wrong number of fields");
    }
    if (!USERNAME_PATTERN.matcher(parts[0]).matches()) {
        throw new IllegalArgumentException("invalid username");
    }
    int iterations = Integer.parseInt(parts[1]);
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
        throw new IllegalArgumentException("iteration count outside allowed range");
    }
    byte[] salt = b64.decode(parts[2]);
    byte[] hash = b64.decode(parts[3]);
    if (salt.length < 16 || hash.length != 32) {
        throw new IllegalArgumentException("invalid salt or hash length");
    }
    users.put(parts[0], new UserRecord(parts[0], iterations, salt, hash));
```

### SEC-05: Unlocked load-modify-save cycle loses concurrent updates (revoked accounts can reappear)
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `EmployeePortalAuth.java:148-151`, `EmployeePortalAuth.java:161-165`, `EmployeePortalAuth.java:318-343`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:161-165
        Map<String, UserRecord> users = store.load();
        if (users.remove(username) == null) {
            throw new IllegalArgumentException("no employee named " + username + ".");
        }
        store.save(users);
```

**Why it is a problem:** `add-user` and `remove-user` each read the whole store, change it in memory and write the whole file back, with no lock. `add-user` is especially slow here: it waits for the operator to type the password twice (lines 134-135) and runs 600,000 PBKDF2 iterations before loading. If two admin runs overlap, the last write wins and the other change is lost.

The security impact: an admin removes a departed employee's account while another admin (or a script) runs `add-user` for someone else. Whichever write lands second puts back the old snapshot, so the revoked employee can still log in with no error shown. The atomic move stops the file being half-written but does not stop lost updates. This is the check-then-act (TOCTOU) pattern described in the race-condition skill, whose remediation is locking.

**Fix:** Hold an exclusive lock on a sidecar lock file for the whole load-modify-save cycle. Prompt for passwords before taking the lock so it is held only briefly.
```java
// in UserStore
interface StoreUpdate {
    void apply(Map<String, UserRecord> users) throws IOException;
}

void update(StoreUpdate change) throws IOException {
    Path lockFile = path.toAbsolutePath().resolveSibling(path.getFileName() + ".lock");
    try (FileChannel channel = FileChannel.open(lockFile,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
         FileLock lock = channel.lock()) {
        Map<String, UserRecord> users = load();
        change.apply(users);
        save(users);
    }
}

// in removeUser
store.update(users -> {
    if (users.remove(username) == null) {
        throw new IllegalArgumentException("no employee named " + username + ".");
    }
});
```

### SEC-06: Password policy only checks length; common, breached and username-based passwords are accepted
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `EmployeePortalAuth.java:143-146`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:143-146
            if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
                throw new IllegalArgumentException("password must be between " + MIN_PASSWORD_LENGTH
                        + " and " + MAX_PASSWORD_LENGTH + " characters.");
            }
```

**Why it is a problem:** The 12-128 character length rule is reasonable, but it is the only rule. Passwords like `password1234`, `123456789012`, `qwertyuiopas`, or the username repeated (`jsmithjsmith`) are all accepted. NIST SP 800-63B requires new passwords to be checked against lists of commonly used, expected or compromised values. Without that check, password spraying (see SEC-02) is far more likely to succeed, and so is cracking if the hash file leaks.

**Fix:** Reject passwords that contain the username or appear on a blocklist of common or breached passwords, loaded from a file the administrator controls.
```java
if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    throw new IllegalArgumentException("password must be between " + MIN_PASSWORD_LENGTH
            + " and " + MAX_PASSWORD_LENGTH + " characters.");
}
String lowered = new String(password).toLowerCase(java.util.Locale.ROOT);
if (lowered.contains(username)) {
    throw new IllegalArgumentException("password must not contain the username.");
}
if (PasswordBlocklist.load().contains(lowered)) { // e.g. a top-100k breached-password list
    throw new IllegalArgumentException("password is too common; choose a different one.");
}
```

## 6. Verified Controls and Checks With No Finding
- Password hashing algorithm and parameters: PBKDF2WithHmacSHA256, 600,000 iterations (meets current OWASP guidance), 256-bit output, 16-byte salt per record (`EmployeePortalAuth.java:227-236`). No MD5, SHA-1, unsalted or reversible storage.
- Randomness: salts come from `java.security.SecureRandom` (`EmployeePortalAuth.java:231, 235`). `java.util.Random` is not used and nothing is seeded from the clock.
- Hash comparison: `MessageDigest.isEqual` is constant-time (`EmployeePortalAuth.java:241`).
- Hardcoded secrets: none. The dummy password (`EmployeePortalAuth.java:176`) only feeds a throwaway record used for timing padding and never matches a real account. No keys, tokens or default credentials in code, README or metadata files.
- Generic failure message: the same "invalid username or password" text is shown whether the username or the password was wrong (`EmployeePortalAuth.java:115-117`). The timing gap is reported separately as SEC-03.
- Password length cap before hashing: passwords over 128 characters are rejected (`EmployeePortalAuth.java:143, 180`), which limits CPU abuse through very long inputs.
- Password memory handling: passwords are kept as `char[]` and wiped after use (`EmployeePortalAuth.java:106-108, 153-156`), and `PBEKeySpec.clearPassword()` is called (`EmployeePortalAuth.java:251`). The stdin fallback briefly holds the password in a `String` (`EmployeePortalAuth.java:379-380`); this only applies without a terminal and is accepted as low risk.
- Password masking: `Console.readPassword` hides input (`EmployeePortalAuth.java:372-373`). When there is no terminal, a warning is printed before the echoed input is read (`EmployeePortalAuth.java:375-377`), so this is not treated as CWE-549.
- Username validation on create: `^[a-z0-9._-]{3,32}$` after trimming and lowercasing with `Locale.ROOT` (`EmployeePortalAuth.java:48, 129-132, 191-193`). This blocks `:` and newline injection into the colon-delimited store format.
- Records file permissions and write safety: the temp file is created with a random name in the target directory (`Files.createTempFile` uses exclusive create), set to `rw-------` before any data is written, then moved into place atomically (falling back to a plain move), and deleted in `finally` if something fails (`EmployeePortalAuth.java:328-349`). A rename replaces a symlink at the destination rather than writing through it, so there is no CWE-59/CWE-377 issue on POSIX. On non-POSIX filesystems the file inherits the directory's ACLs, which the README says is expected.
- Store path: `PORTAL_USER_DB` is read from the environment of the operator running the program (`EmployeePortalAuth.java:195-198`). It is not controlled by a remote party, so it is not path traversal.
- Error handling and information leakage: I/O errors and malformed lines produce messages without hash, salt or password data (`EmployeePortalAuth.java:72-77, 311-312`). The one crash path that reveals an account exists is covered in SEC-04.
- Injection classes: no SQL, OS command execution, deserialization, XML parsing, reflection, network calls or TLS configuration anywhere in the code, so those categories do not apply.
- Argument handling: an unknown command or the wrong argument count prints usage and exits with code 2 (`EmployeePortalAuth.java:68-70, 200-205`). The `login` exit codes (`EmployeePortalAuth.java:58`) match the README.
