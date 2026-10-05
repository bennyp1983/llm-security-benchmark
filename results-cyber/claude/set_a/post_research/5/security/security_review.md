# Security Review: Employee Portal Authenticator (`com.example.portal.auth`)

## 1. Executive Summary

The component is a self-contained, dependency-free Java 17 authenticator for an employee portal,
usable both from a console front end (`PortalCli`) and, by design, from a web front end that wraps
the same classes. It stores credentials as PBKDF2-HMAC-SHA256 hashes in a line-oriented file,
enforces per-account and per-source attempt budgets (persisted to a lock-protected state file so the
limit survives a short-lived CLI process), issues 256-bit random session tokens stored server-side by
digest, and writes a masked, control-character-stripped audit log.

The security engineering here is well above average: password hashing parameters match the OWASP
2023 recommendation, comparison is constant-time, failure responses and timings are deliberately
uniform (decoy KDF work on every non-verifying path), rate-limit reservations are atomic and fail
closed, and tokens, hashes and passwords are kept out of logs, `toString()` output and command-line
arguments. No SQL, no deserialization, no HTTP parsing, and no hardcoded secrets exist in the code.

The findings are therefore concentrated in the local filesystem trust boundary and in the
enrolment path, which is the one place that does not reuse the project's own hardening helper:

- **SEC-01 (High)** — `PortalCli.appendRecord` opens the credential file by path with no file-type,
  ownership or permission check, so a symlink planted (or configured) at that path silently
  redirects the credential write, and an already-world-readable credential file is appended to
  rather than refused. Every other file path in the project calls `PrivateFiles.requireOwnerOnly`;
  this one does not.
- **SEC-02 (Medium)** — the per-source attempt budget is keyed on an unauthenticated,
  caller-supplied source identifier, so the password-spraying defence it exists to provide is
  bypassed by rotating that value.
- **SEC-03 (Medium)** — `PrivateFiles.requireOwnerOnly` only rejects a *world*-writable parent
  directory; a group-writable one still allows another local account to unlink and replace the
  credential or attempt-state file.

The remainder (SEC-04 to SEC-08) are Low: a check-then-open TOCTOU window, a length-only enrolment
password policy with no breached-password check, byte-to-char handling of piped passwords, silently
swallowed audit-log write errors, and a non-atomic rewrite of the attempt-state file.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/portal/auth/PortalCli.java` | Console front end: `login` and `enroll` subcommands | Argument/env path resolution, refuses `--password` on the command line, reads passwords with echo off or from stdin, appends credential records under a file lock, clears password buffers |
| `src/main/java/com/example/portal/auth/Authenticator.java` | Orchestrates one authentication attempt | Input validation, attempt reservation before verification, constant-time verify, uniform denial, decoy KDF work, fail-closed exception handling, audit emission |
| `src/main/java/com/example/portal/auth/PasswordHasher.java` | PBKDF2-HMAC-SHA256 hashing/verification | `SecureRandom` 16-byte salt, 600 000 iterations, 256-bit key, `MessageDigest.isEqual` comparison, derived-key zeroing, strict parsing of stored records, decoy derivation |
| `src/main/java/com/example/portal/auth/SessionManager.java` | Issues and validates session tokens | 256-bit CSPRNG tokens, SHA-256-keyed server-side table, idle + absolute expiry inside one atomic `compute`, shape validation, session cap, revocation |
| `src/main/java/com/example/portal/auth/SessionCookie.java` | Builds `Set-Cookie` for the web front end | `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, no `Domain`, token shape check before interpolation |
| `src/main/java/com/example/portal/auth/Session.java` | Server-side session record | Omits the token; `toString()` renders only a non-secret reference |
| `src/main/java/com/example/portal/auth/AuthResult.java` | Outcome object returned to callers | Single generic failure message; token exposed only via `sessionToken()`, redacted in `toString()` |
| `src/main/java/com/example/portal/auth/InputPolicy.java` | Whitelist validation of usernames, passwords, source ids | Length bounds, allowed character sets, lower-case canonicalisation, password length caps protecting the KDF |
| `src/main/java/com/example/portal/auth/CredentialStore.java` | Lookup interface | Declares the store as the sole server-side authority |
| `src/main/java/com/example/portal/auth/FileCredentialStore.java` | File-backed credential store | Ownership/permission/size/record-count validation, per-record parsing, duplicate rejection, immutable in-memory map |
| `src/main/java/com/example/portal/auth/AttemptLimiter.java` | Rate-limit interface and tunable `Limits` | Two independent budgets, expiring restrictions, bounded tracked keys |
| `src/main/java/com/example/portal/auth/AttemptCounters.java` | Shared counting rules | Window/restriction arithmetic, clock-skew clamping, capacity pruning |
| `src/main/java/com/example/portal/auth/InMemoryAttemptLimiter.java` | In-process limiter | Single `ReentrantLock` makes check-then-spend atomic; source budget evaluated first |
| `src/main/java/com/example/portal/auth/FileAttemptLimiter.java` | Cross-process limiter | Exclusive `FileLock` plus per-path in-process lock, re-verified file privacy, bounded parsing, fail-closed `UNAVAILABLE`, `force(true)` durability |
| `src/main/java/com/example/portal/auth/PrivateFiles.java` | File privacy helper | Atomic `rw-------` creation, regular-file/owner/permission/parent-directory checks |
| `src/main/java/com/example/portal/auth/AuditLog.java` | Append-only audit log | Owner-only log file, control-character stripping, field truncation, account and source masking |
| `src/main/java/com/example/portal/auth/ValidationException.java` | Checked validation failure | Message is documented as log-only, never surfaced to the submitter |
| `src/test/java/com/example/portal/auth/SelfTest.java` | Adversarial self-test | Asserts uniform denials, budget enforcement, concurrency safety, log hygiene, no password on the command line |
| `build.sh` | JDK-only build/test script | No third-party downloads; compiles with `-Xlint:all -Werror` |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove the read-then-match-then-apply workflow over all 18 source files.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`, `SessionManager` and `PrivateFiles` — KDF choice and parameters, salt size and source, RNG, cipher/digest selection, constant-time comparison, hardcoded-secret scan, key-material lifetime.
- `testing-api-authentication-weaknesses`: applied to `Authenticator`, `SessionManager`, `SessionCookie`, `AuthResult`, `InputPolicy` — session token entropy, expiry and revocation, token leakage into logs/output, user enumeration via differential responses and timing, password policy strength.
- `implementing-api-rate-limiting-and-throttling` and `performing-api-rate-limiting-bypass`: applied to `AttemptLimiter`, `AttemptCounters`, `InMemoryAttemptLimiter`, `FileAttemptLimiter` — budget placement relative to verification, atomicity, shared-state vs per-instance counters, client-controlled bucket keys, fail-open behaviour, counter exhaustion.
- `testing-for-sensitive-data-exposure`: applied to `AuditLog`, `Session`, `AuthResult`, `PasswordHasher.StoredHash`, `PortalCli` — secrets in source, secrets in logs and `toString()`, masking quality, secrets on the command line, insecure at-rest storage.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched: local filesystem trust boundary (symlink following CWE-59, permission assignment CWE-732, check-then-use races CWE-367), non-atomic security-state persistence, character-encoding handling of credential input (CWE-176), and audit-log reliability (CWE-778). No skill in this library covers secure local file handling or terminal input for a non-web, non-cloud Java component.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Enrolment writes the credential record to an unverified path (symlink following, no permission check) | High | CWE-59 | `src/main/java/com/example/portal/auth/PortalCli.java:186` |
| SEC-02 | Per-source attempt budget keyed on an unauthenticated caller-supplied identifier | Medium | CWE-807 | `src/main/java/com/example/portal/auth/Authenticator.java:83` |
| SEC-03 | Group-writable parent directory accepted for private files | Medium | CWE-732 | `src/main/java/com/example/portal/auth/PrivateFiles.java:84` |
| SEC-04 | Check-then-open race between privacy verification and file access | Low | CWE-367 | `src/main/java/com/example/portal/auth/FileCredentialStore.java:60` |
| SEC-05 | Enrolment password policy is length-only, with no common/breached password check | Low | CWE-521 | `src/main/java/com/example/portal/auth/InputPolicy.java:97` |
| SEC-06 | Piped passwords are read byte-wise and cast to `char`, corrupting non-ASCII credentials | Low | CWE-176 | `src/main/java/com/example/portal/auth/PortalCli.java:306` |
| SEC-07 | Audit-log write failures are silently swallowed by `PrintStream` | Low | CWE-778 | `src/main/java/com/example/portal/auth/AuditLog.java:59` |
| SEC-08 | Attempt-state file is rewritten by truncate-then-write, so an interrupted commit clears every restriction | Low | CWE-754 | `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:244` |

## 5. Detailed Findings

### SEC-01: Enrolment writes the credential record to an unverified path (symlink following, no permission check)

- **Severity:** High
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following') — with a contributing CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Location:** `src/main/java/com/example/portal/auth/PortalCli.java:186-188` and `src/main/java/com/example/portal/auth/PortalCli.java:212-231`, with `src/main/java/com/example/portal/auth/PrivateFiles.java:40-49`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PortalCli.java:186-188
            String record = username + ":" + new PasswordHasher().hash(password);
            FileCredentialStore.createIfAbsent(storePath);
            appendRecord(storePath, username, record);
```
```java
// src/main/java/com/example/portal/auth/PortalCli.java:212-219
    private static void appendRecord(Path storePath, String username, String record)
            throws IOException, ValidationException {
        Path resolved = storePath.toAbsolutePath().normalize();
        try (FileChannel channel = FileChannel.open(resolved, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
```
```java
// src/main/java/com/example/portal/auth/PrivateFiles.java:40-43
    static void createPrivateIfAbsent(Path path) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
```

**Why it is a problem:** Every other file access in this component gates on
`PrivateFiles.requireOwnerOnly`, which rejects non-regular files (`FileCredentialStore.java:60`,
`FileAttemptLimiter.java:157`, `AuditLog.java:57`). The enrolment path does not. The consequences
are two:

1. *Symlink following.* `createPrivateIfAbsent` returns early for any existing path entry, because
   `Files.exists(..., NOFOLLOW_LINKS)` is true for a symlink itself. `FileChannel.open` then
   resolves the link. If `PORTAL_CREDENTIAL_FILE` (or `--store`) names a symlink — planted by
   another local account in a shared directory such as `/tmp` or `/var/tmp`, or configured in error
   — the `username:pbkdf2-sha256$...` record, and the `channel.force(true)` that follows it, are
   written to the link's target with the portal user's privileges. An attacker who can plant the
   link chooses the write target: append-corrupting a file the portal user owns, or growing a file
   they can read in order to harvest the hash. The same open also *reads* the target for the
   duplicate check, so `ValidationException("that account already has a credential on file")` leaks
   whether the chosen target contains a line beginning `username:`.
2. *No privacy check on an existing file.* If the credential file already exists with `rw-r--r--`
   or `rw-rw-r--` — pre-created by an operator, restored from a backup, or planted by another
   account — `enroll` appends to it without complaint. The login path will later refuse to load that
   file, so the misconfiguration is only discovered after a real password hash has been written
   somewhere other local accounts can read, and (in the group/world-writable case) after an attacker
   has been handed a file in which they can enrol themselves as any employee.

The first case is reachable by an unprivileged local account whenever the credential file lives in a
directory that account can write to; the second is reachable by ordinary operator error, which is
exactly the class of mistake `PrivateFiles` was centralised to prevent.

**Fix:** Call the project's own helper before opening, and open with `NOFOLLOW_LINKS` so the check
and the use cannot refer to different objects. `requireOwnerOnly` already rejects symlinks, FIFOs,
foreign owners and group/world-accessible modes.

```java
    private static void appendRecord(Path storePath, String username, String record)
            throws IOException, ValidationException {
        Path resolved = storePath.toAbsolutePath().normalize();
        // Same gate as every other file this program touches: a symlink, a file owned by another
        // account, or one readable beyond its owner must never receive a credential record.
        PrivateFiles.requireOwnerOnly(resolved, "credential file");
        try (FileChannel channel = FileChannel.open(resolved,
                     StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
             FileLock lock = channel.lock()) {
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
```

### SEC-02: Per-source attempt budget keyed on an unauthenticated caller-supplied identifier

- **Severity:** Medium
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/example/portal/auth/Authenticator.java:70-83`, `src/main/java/com/example/portal/auth/PortalCli.java:116`, `src/main/java/com/example/portal/auth/InputPolicy.java:120-138`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/Authenticator.java:70-83
            source = InputPolicy.requireValidSource(rawSource);
            username = InputPolicy.requireValidUsername(rawUsername);
            InputPolicy.requireSubmittablePassword(password);
        } catch (ValidationException e) {
            // Rejected before any budget is touched, so malformed input cannot be used to burn a
            // legitimate employee's attempt allowance.
            audit.warn("authentication input rejected: " + e.getMessage(),
                    "account=" + AuditLog.maskAccount(rawUsername) + " source=" + AuditLog.maskSource(rawSource));
            return AuthResult.denied();
        }

        AttemptLimiter.Reservation reservation;
        try {
            reservation = limiter.tryReserve(username, source);
```
```java
// src/main/java/com/example/portal/auth/PortalCli.java:116
        String source = option(arguments, "--source").orElse(localSource());
```

**Why it is a problem:** The source identifier is validated for *shape* but never for
*authenticity*. On the CLI it is whatever `--source` says; on the web path it is "as recorded by the
front end", which in practice is frequently an `X-Forwarded-For`-derived value. The per-source
budget exists for one stated purpose — "Stops an attacker spreading a few guesses each across the
whole employee directory -- password spraying, which a per-account limit never notices"
(`AttemptLimiter.java:12-13`). An attacker who varies the identifier on each request gets a fresh
50-attempt bucket every time, which removes that control entirely: they can try four passwords
against each of ten thousand accounts and never trip either budget, because the per-account budget
of five is never reached for any single account. The code comment at `InputPolicy.java:114-115`
asserts only that the per-account limit survives, which is true but is not the control being
defeated. The 100 000-key tracking cap makes it worse under load: inventing distinct sources floods
the tracker, and once `maxTrackedKeys` is hit new keys return `CAPACITY_EXHAUSTED`, converting the
bypass into a denial of service against genuine users whose counters have not yet been created.

**Fix:** Derive the rate-limit key from a value the caller cannot choose — the transport peer
address at the web front end, a fixed constant on the console — and treat any caller-supplied hint
as untrusted metadata for logging only. Where a reverse proxy is genuinely in front, accept a
forwarded address only from an allow-listed proxy and use the last untrusted hop. Add a global
backstop budget so that spreading across buckets still meets a ceiling.

```java
    /**
     * @param rawSource identifier for where the attempt came from. Must be established by the
     *                  server (transport peer address, or the hop immediately before a trusted
     *                  proxy) -- never a value the client can set, or the per-source spray budget
     *                  can be reset at will.
     */
    public AuthResult authenticate(String rawUsername, char[] password, String rawSource) {
        ...
            source = InputPolicy.requireValidSource(rawSource);
```
```java
// PortalCli.java: do not let an argument choose the rate-limit bucket.
        String source = localSource();
        option(arguments, "--source").ifPresent(hint ->
                audit.info("caller-supplied source hint ignored for rate limiting",
                        "hint=" + AuditLog.maskSource(hint)));
```

### SEC-03: Group-writable parent directory accepted for private files

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/portal/auth/PrivateFiles.java:83-89`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PrivateFiles.java:83-89
        Path parent = path.getParent();
        if (parent != null && posixSupported()
                && Files.getPosixFilePermissions(parent).contains(PosixFilePermission.OTHERS_WRITE)) {
            // A world-writable directory lets another account replace the file wholesale, which
            // defeats every check above.
            throw new ValidationException(kind + " sits in a world-writable directory");
        }
```

**Why it is a problem:** The comment states the threat correctly but the check covers only
`OTHERS_WRITE`. Write permission on a directory is what authorises unlink and rename of the entries
inside it, regardless of the entries' own modes. A directory mode of `rwxrwxr-x` owned by, say,
group `portal-ops` lets every member of that group delete the credential file and create their own
in its place — with their own `rw-------` mode and their own ownership. That replacement passes the
ownership check only if they are the portal user, but the more direct attack needs no bypass at all:
deleting the *attempt-state* file resets every rate-limit restriction (`createPrivateIfAbsent`
recreates it empty on the next attempt), and deleting the *credential* file while `enroll` is
available lets the attacker enrol accounts into a fresh one. The check also inspects only the
immediate parent, so a loose ancestor (`/var/portal` world-writable, `/var/portal/data` tight) is
missed, and it follows symlinks when reading the parent's mode.

**Fix:** Reject group-writable as well as world-writable directories unless the sticky bit is set,
verify the parent is owned by the same user, and walk the ancestor chain.

```java
        for (Path dir = path.getParent(); dir != null; dir = dir.getParent()) {
            Set<PosixFilePermission> mode = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS);
            boolean sticky = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                    .permissions().contains(PosixFilePermission.OTHERS_EXECUTE) && isSticky(dir);
            if ((mode.contains(PosixFilePermission.OTHERS_WRITE)
                    || mode.contains(PosixFilePermission.GROUP_WRITE)) && !sticky) {
                throw new ValidationException(kind + " sits under a directory writable by other accounts: " + dir);
            }
            String dirOwner = Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS).getName();
            if (!dirOwner.equals(processUser) && !dirOwner.equals("root")) {
                throw new ValidationException(kind + " sits under a directory owned by another account: " + dir);
            }
        }
```

### SEC-04: Check-then-open race between privacy verification and file access

- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/portal/auth/FileCredentialStore.java:59-67`, `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:156-158`, `src/main/java/com/example/portal/auth/AuditLog.java:56-61`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/FileCredentialStore.java:59-67
        Path resolved = path.toAbsolutePath().normalize();
        PrivateFiles.requireOwnerOnly(resolved, "credential file");

        long size = Files.size(resolved);
        if (size > MAX_FILE_BYTES) {
            throw new ValidationException("credential file exceeds the maximum accepted size");
        }

        List<String> lines = Files.readAllLines(resolved, StandardCharsets.UTF_8);
```
```java
// src/main/java/com/example/portal/auth/FileAttemptLimiter.java:156-158
            PrivateFiles.createPrivateIfAbsent(statePath);
            PrivateFiles.requireOwnerOnly(statePath, "attempt tracker state file");
            FileChannel opened = FileChannel.open(statePath, StandardOpenOption.READ, StandardOpenOption.WRITE);
```

**Why it is a problem:** `requireOwnerOnly` validates the object currently named by the path, using
`NOFOLLOW_LINKS`; the subsequent `Files.size`, `Files.readAllLines`, `FileChannel.open` and
`Files.newOutputStream` each re-resolve the same path, following symlinks, and may therefore operate
on a different object. An attacker who can create entries in the containing directory — which
SEC-03 shows is possible for a group member, and which is the normal state of a shared temporary
directory — can replace the validated file with a symlink between the check and the use. For the
credential store that means reading attacker-chosen content as credential records; for the state
file it means the rate-limit counters are read from and written to a file of the attacker's
choosing. The window is small and the attack needs directory write access, hence Low, but the
mitigation is cheap and the component already pays for privacy checks everywhere else.

**Fix:** Open the file once with `NOFOLLOW_LINKS`, then validate the *open descriptor* rather than
the path, so check and use refer to the same object.

```java
        Path resolved = path.toAbsolutePath().normalize();
        try (SeekableByteChannel channel = Files.newByteChannel(resolved,
                Set.of(StandardOpenOption.READ), /* no create */ new FileAttribute<?>[0])) {
            // Validate what we actually opened, not what the name resolved to a moment ago.
            PrivateFiles.requireOwnerOnlyOf(resolved, channel, "credential file");
            if (channel.size() > MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
            List<String> lines = readLines(channel);
            ...
        }
```

### SEC-05: Enrolment password policy is length-only, with no common/breached password check

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/example/portal/auth/InputPolicy.java:93-106`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/InputPolicy.java:93-106
    public static void requireEnrollablePassword(char[] password) throws ValidationException {
        if (password == null) {
            throw new ValidationException("password is absent");
        }
        if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException(
                    "password must be between " + PASSWORD_MIN_LENGTH + " and " + PASSWORD_MAX_LENGTH + " characters");
        }
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                throw new ValidationException("password contains a control character");
            }
        }
    }
```

**Why it is a problem:** A 12-character minimum with no composition rule is the right modern choice
(NIST SP 800-63B), but 800-63B pairs it with a mandatory check against a list of commonly used,
expected or compromised values — precisely because a length rule alone accepts `passwordpassword`,
`123456789012`, `qwertyuiop12` and every company-name-plus-year variant. Those are the first
candidates in any spraying run, and the attempt budgets slow spraying but do not stop it,
particularly given SEC-02. The strong KDF does not help here either: a cracker with a stolen
credential file tries a wordlist before anything else, and 600 000 PBKDF2 iterations only costs them
seconds for a top-10 000 password. This is the one control in the component that is weaker than the
standard it otherwise tracks.

**Fix:** Add a denylist check against a bundled list of the most common passwords (and the site's
own obvious strings), compared case-insensitively after trimming, before the credential is accepted.

```java
    public static void requireEnrollablePassword(char[] password) throws ValidationException {
        ...
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                throw new ValidationException("password contains a control character");
            }
        }
        // NIST SP 800-63B 5.1.1.2: a length rule alone still accepts the passwords that are tried
        // first. Compare against the known-bad list before enrolling.
        if (CommonPasswords.contains(password)) {
            throw new ValidationException("password appears on the list of commonly used or breached passwords");
        }
    }
```

### SEC-06: Piped passwords are read byte-wise and cast to `char`, corrupting non-ASCII credentials

- **Severity:** Low
- **CWE:** CWE-176: Improper Handling of Unicode Encoding
- **Location:** `src/main/java/com/example/portal/auth/PortalCli.java:301-319`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PortalCli.java:301-319
    private static char[] readBoundedChars() throws IOException {
        int limit = InputPolicy.PASSWORD_MAX_LENGTH;
        char[] buffer = new char[limit];
        int length = 0;
        int c;
        while ((c = System.in.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (length == limit) {
                Arrays.fill(buffer, '\0');
                throw new IOException("input line exceeds the accepted length");
            }
            buffer[length++] = (char) c;
        }
        char[] line = Arrays.copyOf(buffer, length);
        Arrays.fill(buffer, '\0');
        return line;
    }
```

**Why it is a problem:** `System.in.read()` returns a *byte*, which is then widened to a `char`. For
any non-ASCII character the UTF-8 encoding is split into one `char` per byte, so the array that
reaches `PasswordHasher` differs from the one the terminal path produces for the same typed
password: `Console.readPassword` decodes correctly. A passphrase containing an accented letter or a
non-Latin script therefore hashes to one value when enrolled at a terminal and a different value
when submitted through `--password-stdin`, locking the account out of the scripted path — and each
such failed attempt burns a slot in the employee's own attempt budget. The same mis-decoding silently
changes the effective length check: `PASSWORD_MAX_LENGTH` becomes a byte limit on this path and a
character limit on the other, so a legitimate long passphrase is rejected with an `IOException`
rather than a validation message. There is no direct bypass here — the mangling is deterministic and
does not reduce entropy to anything guessable — but inconsistent credential canonicalisation across
two entry points for the same account is a correctness defect in an authentication path, and such
mismatches have historically become bypasses once a third entry point is added.

**Fix:** Decode the stream as UTF-8 before bounding, rather than treating bytes as characters.

```java
    private static char[] readBoundedChars() throws IOException {
        int limit = InputPolicy.PASSWORD_MAX_LENGTH;
        // Decode UTF-8 rather than widening raw bytes: a password typed at the terminal and the
        // same password piped in must produce the same char[].
        Reader reader = new InputStreamReader(System.in, StandardCharsets.UTF_8);
        char[] buffer = new char[limit];
        int length = 0;
        int c;
        while ((c = reader.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (length == limit) {
                Arrays.fill(buffer, '\0');
                throw new IOException("input line exceeds the accepted length");
            }
            buffer[length++] = (char) c;
        }
        char[] line = Arrays.copyOf(buffer, length);
        Arrays.fill(buffer, '\0');
        return line;
    }
```

### SEC-07: Audit-log write failures are silently swallowed by `PrintStream`

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/example/portal/auth/AuditLog.java:59-63` and `src/main/java/com/example/portal/auth/AuditLog.java:80-84`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/AuditLog.java:59-63
        PrintStream stream = new PrintStream(
                Files.newOutputStream(resolved, StandardOpenOption.CREATE, StandardOpenOption.APPEND),
                true, StandardCharsets.UTF_8);
        return new AuditLog(stream, true);
    }
```
```java
// src/main/java/com/example/portal/auth/AuditLog.java:80-84
    private synchronized void write(String level, String event, String detail) {
        String line = Instant.now() + " " + level + " " + sanitise(event)
                + (detail == null || detail.isEmpty() ? "" : " | " + sanitise(detail));
        sink.println(line);
    }
```

**Why it is a problem:** `PrintStream` never throws on write; it sets an internal error flag that
nothing here consults, and `close()` ignores it too. This log is, by the class's own description,
"the only place failure detail is allowed to go" — the sole record distinguishing a grant from a
spraying run. If the filesystem fills, the quota is exceeded, or the descriptor breaks, every
subsequent `security()` call returns normally while writing nothing, and authentication continues
unaffected. An attacker who can fill the volume (for instance by provoking enrolments or by any
unrelated local write access) thereby turns the audit trail off for the duration of their attack,
silently. Detection, not access control, is what is lost, hence Low.

**Fix:** Check the error state after each write and escalate once, so a broken audit trail is
visible rather than silent; for a security log, consider failing the operation outright.

```java
    private synchronized void write(String level, String event, String detail) {
        String line = Instant.now() + " " + level + " " + sanitise(event)
                + (detail == null || detail.isEmpty() ? "" : " | " + sanitise(detail));
        sink.println(line);
        // PrintStream swallows IOExceptions. An audit log that has stopped recording must not do so
        // quietly: surface it once on standard error so the failure is noticed.
        if (sink.checkError() && !degradedReported) {
            degradedReported = true;
            System.err.println("AUDIT LOG WRITE FAILED - authentication events are no longer being recorded");
        }
    }
```

### SEC-08: Attempt-state file is rewritten by truncate-then-write, so an interrupted commit clears every restriction

- **Severity:** Low
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:234-250`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/FileAttemptLimiter.java:244-249
            channel.truncate(0);
            channel.position(0);
            channel.write(ByteBuffer.wrap(bytes));
            // Durability matters for a security control: a restriction lost to a crash is a
            // restriction an attacker can provoke by crashing the host.
            channel.force(true);
```

**Why it is a problem:** The comment names the threat and the `force(true)` addresses only half of
it. Between `truncate(0)` and a completed `write`, the file on disk is empty or partial; a crash,
`SIGKILL`, container eviction or power loss in that window leaves a state file from which every
counter is either absent or dropped as unparseable (`read`/`parseInto`, lines 189-199). Both outcomes
are indistinguishable from "no attempts have ever been made", so every account and source
restriction currently in force is lifted and the attacker resumes with a full budget. The window is
narrow and the attacker needs a way to interrupt the process at the right moment, so this is Low —
but the fix is the standard one and the code already holds the lock that makes it safe.

**Fix:** Write to a temporary file in the same directory, fsync it, then atomically rename over the
state file, so a reader only ever sees a complete generation.

```java
        void commit() throws IOException {
            ...
            byte[] bytes = out.toString().getBytes(StandardCharsets.UTF_8);

            // Atomic replace rather than truncate-in-place: an interrupted write must not be able
            // to leave a state file that reads as "no restrictions in force".
            Path temporary = Files.createTempFile(statePath.getParent(), ".attempts", ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            try (FileChannel scratch = FileChannel.open(temporary,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                scratch.write(ByteBuffer.wrap(bytes));
                scratch.force(true);
            }
            Files.move(temporary, statePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
```

## 6. Verified Controls and Checks With No Finding

- **Password hashing algorithm and parameters**: PBKDF2-HMAC-SHA256 with a 256-bit output
  (`PasswordHasher.java:27,43`) at 600 000 iterations, matching the OWASP Password Storage Cheat
  Sheet 2023 figure (`PasswordHasher.java:35`); a floor of 100 000 is enforced on both the
  constructor and parsed records (`PasswordHasher.java:38,53,162`). Argon2id would be preferable on
  memory-hardness grounds; the trade-off is documented and defensible for a zero-dependency build.
- **Salting**: a fresh 16-byte salt per hash from `SecureRandom` (`PasswordHasher.java:45,74-75`),
  with the length re-checked on parse (`PasswordHasher.java:167`). No shared or static salt exists.
- **Constant-time comparison**: `MessageDigest.isEqual` on the derived key
  (`PasswordHasher.java:95`); no `Arrays.equals` or `String.equals` on secret material.
- **Key material lifetime**: derived keys and password buffers are zeroed in `finally` blocks
  (`PasswordHasher.java:82,97,117-118`; `PortalCli.java:149,196-198,311,317`), and `PBEKeySpec` is
  cleared (`PasswordHasher.java:130`).
- **Randomness**: `SecureRandom` for salts, decoy material and session tokens
  (`PasswordHasher.java:45`, `SessionManager.java:45`); no `java.util.Random`, no time-derived seed.
- **Hardcoded secrets**: none. All paths come from options or environment
  (`PortalCli.java:38-42,247-257`); no key, password or token literal appears in any file.
- **Upgrade-safe hash encoding**: iteration count is stored per record and range-checked on read
  rather than clamped (`PasswordHasher.java:145-174`), so raising the cost does not invalidate
  existing records and a tampered record cannot turn the KDF off.
- **Session token entropy and format**: 32 bytes of `SecureRandom` rendered as unpadded Base64url
  (`SessionManager.java:99-101`); nothing is derived from the username, a counter or a clock.
- **Session storage**: the table is keyed by SHA-256 of the token, never the token itself
  (`SessionManager.java:104,189-197`), so a table or heap dump yields no usable bearer credential.
- **Session expiry and revocation**: independent idle and absolute expiries, both evaluated and the
  idle one refreshed inside a single `ConcurrentHashMap.compute` (`SessionManager.java:128-138`);
  expired entries are removed on contact; `invalidate` provides server-side revocation
  (`SessionManager.java:143-147`); the session table is capped with pruning
  (`SessionManager.java:42,93-98`).
- **Session token shape validation**: enforced before the value is used as a map key or interpolated
  into a cookie (`SessionManager.java:161-176`, `SessionCookie.java:51-53`), which also prevents
  cookie-attribute smuggling through the value.
- **Cookie attributes**: `HttpOnly`, `Secure`, `SameSite=Strict`, no `Domain`, `Path=/` and the
  `__Host-` prefix, all fixed rather than parameterised (`SessionCookie.java:33-34,57-60`); the
  clear-cookie header carries the same attributes (`SessionCookie.java:65`). The class Javadoc at
  line 21 says `Path=/portal` while the constant is `/` — a documentation inconsistency only; `/` is
  what `__Host-` requires.
- **Username enumeration**: identical `AuthResult.GENERIC_FAILURE_MESSAGE` for unknown account,
  wrong password, account restriction, source restriction, tracker failure and internal exception
  (`AuthResult.java:19-42`, `Authenticator.java:78,90,97,107,114,130`); `AuthResult` carries no
  reason field at all.
- **Timing-based enumeration**: exactly one PBKDF2 derivation on every path past input validation —
  real on the verify path, decoy otherwise (`Authenticator.java:87,94,103`,
  `PasswordHasher.java:109-119`).
- **Fail-closed authentication**: there is no path to `AuthResult.granted` except an explicit
  `hasher.verify` pass; limiter failures, store failures and any `RuntimeException` all fall through
  to denial (`Authenticator.java:84-91,123-131`), and a missing PBKDF2 provider throws rather than
  returning a default (`PasswordHasher.java:125-128`).
- **Rate limiting placement and atomicity**: the slot is consumed *before* verification
  (`Authenticator.java:83` precedes line 110); in-process updates are serialised by one
  `ReentrantLock` (`InMemoryAttemptLimiter.java:41-64`) and cross-process updates by an exclusive
  `FileLock` plus a per-path in-process lock (`FileAttemptLimiter.java:62,83-85,161`), so concurrent
  attempts cannot share one remaining slot. `SelfTest.java:202-208` exercises this concurrently.
- **Rate-limit persistence**: the CLI uses the file-backed limiter precisely because an in-memory
  one in a process that exits per attempt would be decorative (`PortalCli.java:118-129`,
  `InMemoryAttemptLimiter.java:11-14`).
- **Rate-limit fail-closed behaviour**: an unreadable or unwritable state file yields
  `Decision.UNAVAILABLE` and a refusal, not a free pass (`FileAttemptLimiter.java:103-107`,
  `AttemptLimiter.java:39`); tracker exhaustion yields `CAPACITY_EXHAUSTED` rather than an untracked
  attempt (`AttemptCounters.java:66-71`).
- **Lockout as a denial-of-service lever**: restrictions expire rather than persisting
  (`AttemptCounters.java:84-92`), and the source budget is evaluated before the account budget so a
  blocked attacker cannot keep a real employee locked out (`InMemoryAttemptLimiter.java:44-49`).
- **Clock-skew and tampering of persisted counters**: a future-dated window start is reset to now and
  an over-long restriction is clamped to one period (`AttemptCounters.java:76-83`), so a forged
  state record cannot create a permanent lockout.
- **Bounded parsing of persisted state**: field count, scope character, key validation, numeric
  ranges, line length, file size and tracked-key count are all enforced, and unparseable records are
  dropped rather than guessed at (`FileAttemptLimiter.java:50-52,162-163,189,199-231`).
- **Credential-file loading as untrusted input**: regular-file/ownership/permission checks, an 8 MiB
  size cap, a 50 000-record cap, a 512-character line cap, per-field validation and rejection of
  duplicate accounts (`FileCredentialStore.java:37-41,59-106`).
- **Input validation**: whitelist character sets and length bounds for usernames, source identifiers
  and passwords, with lower-case canonicalisation so `Alice` and `alice` share one lockout counter
  (`InputPolicy.java:45-138`). Invalid input is refused, never repaired.
- **KDF cost as a DoS vector**: submitted passwords are capped at 256 characters before reaching
  PBKDF2 (`InputPolicy.java:23,81`), and CLI input is bounded at the same limit
  (`PortalCli.java:302`).
- **Login-path policy leakage**: content rules are deliberately not applied to submitted passwords,
  only to enrolled ones, so an unauthenticated party cannot probe the policy
  (`InputPolicy.java:69-84`).
- **Secrets in logs**: no password, derived key, salt, stored hash or session token is written;
  accounts are masked to first character plus length and sources to their network part
  (`AuditLog.java:113-146`), applied to raw rejected values too (`Authenticator.java:76`). Asserted
  by `SelfTest.java:56`.
- **Log injection**: control characters are replaced and fields truncated at 200 characters before
  emission (`AuditLog.java:91-104`), so no input can forge an extra log line.
- **Secrets in process arguments**: `--password` and `--password=` are refused with an explicit
  rotation warning (`PortalCli.java:68-76`), passwords are read with terminal echo disabled or from
  stdin (`PortalCli.java:279-292`), and the session token is never printed — only the non-secret
  reference (`PortalCli.java:143-146`). Asserted by `SelfTest.java:57`.
- **Secrets in `toString()`**: redacted in `PasswordHasher.StoredHash`, `Session`,
  `SessionManager.Issued` and `AuthResult` (`PasswordHasher.java:205-207`, `Session.java:21-23`,
  `SessionManager.java:214-217`, `AuthResult.java:72-74`). Asserted by `SelfTest.java:59`.
- **Error messages to the operator**: generic (`PortalCli.java:100,112`); `ValidationException`
  detail is documented as log-only (`ValidationException.java:6-7`).
- **Private file creation**: permissions are passed to `Files.createFile` as an atomic attribute
  rather than applied afterwards, so there is no world-readable window
  (`PrivateFiles.java:40-49`), and non-POSIX filesystems are refused rather than assumed safe
  (`PrivateFiles.java:71-72`).
- **Concurrent enrolment**: the duplicate check and append are performed under one exclusive
  `FileLock` (`PortalCli.java:212-231`), so two administrators cannot create two records for one
  account. (The missing privacy check on that same path is SEC-01.)
- **Path input handling**: configured paths are length- and NUL-checked, then absolutised and
  normalised (`PortalCli.java:247-257`, `FileCredentialStore.java:59`,
  `FileAttemptLimiter.java:75`). No user-supplied value is ever concatenated into a path, so there is
  no path-traversal surface; the paths are deployment configuration, not request data.
- **Injection classes not present**: no SQL, NoSQL, LDAP or ORM query construction; no
  `Runtime.exec`/`ProcessBuilder`; no Java or XML deserialization, no `ObjectInputStream`; no
  template rendering, no HTML or JavaScript emission, hence no XSS sink; no outbound network calls,
  URL fetching or TLS client configuration, hence no SSRF or transport-security surface. Verified by
  reading all 18 files and by grep across `src/`.
- **Supply chain**: the build uses the JDK alone with `-Xlint:all -Werror` and downloads nothing
  (`build.sh:1-20`), so there is no third-party dependency to audit or pin.
