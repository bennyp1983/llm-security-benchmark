# Security Review — Administrator Portal (Java console app)

**Scope reviewed:** all Java sources under `src/` (11 main classes + 1 test harness, 1,274 lines)
and `README.md`. The non-source harness artefacts in the folder (`prompt.txt`, `result.md`,
`return.txt`, `cyber_*.txt`, `prompt_hash.txt`) are run metadata, not application code, and were
read only to confirm that.

**Overall:** this is an unusually careful implementation for its size. The high-severity classics
are genuinely absent: no SQL, no deserialization, no command execution, no hardcoded credentials,
no plaintext password storage, no MD5/SHA-1, no `Random` where `SecureRandom` is needed, no
user-enumerating error messages, and constant-time hash comparison. The findings below are
real but concentrate on **work-factor**, **state durability**, **file permissions**, and
**output neutralisation**, plus one design-level authentication-bypass path.

---

## Step 1 — What each file does, and its security-relevant behaviour

| File | Role | Security-relevant behaviour |
| --- | --- | --- |
| `AdminPortal.java` | Entry point; first-run bootstrap, login loop | Credential store/audit paths from system properties; unauthenticated creation of the first `SUPER_ADMIN`; attempt loop |
| `AuthenticationService.java` | Credential verification + throttling | Lockout state, dummy-hash timing equalisation, audit calls |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256 | KDF parameters, salt generation, constant-time compare, parameter parsing from stored value |
| `CredentialStore.java` | File-backed accounts | File parsing, record serialisation, POSIX permissions, atomic temp-file write, input validation of usernames/roles |
| `AdminUser.java` | Account record | `username:hash:role\|role:enabled` serialisation/parsing (delimiter injection surface) |
| `AdminSession.java` | Authenticated session | 256-bit `SecureRandom` session id, idle + absolute expiry, role check |
| `AdminConsole.java` | Post-auth functionality | Per-action authorisation, account creation, audit-log display (file read) |
| `AuthenticationResult.java` | Outcome value object | Uniform denial message (anti-enumeration) |
| `PasswordPolicy.java` | Strength rules | Length bounds, character-class requirements |
| `AuditLog.java` | Append-only event log | Log-record construction, control-character sanitisation, file creation |
| `TextIo.java` | Console I/O | Non-echoing password read, `char[]` wiping, fallback that echoes |
| `AuthenticationTests.java` | Dependency-free test harness | Test-only credentials; asserts salting, lockout, enumeration parity, role enforcement |

Keywords derived: *password hashing / KDF work factor, salts, secure RNG, hardcoded secrets,
authentication bypass, brute force / lockout, user enumeration, session management, access
control / privilege escalation, sensitive data at rest, file permissions, log injection, input
validation, race conditions.*

---

## Findings

Severity is judged against this program's realistic threat model: a locally-run console portal
whose attackers are (a) an unauthenticated user at the prompt, (b) a lower-privileged `ADMIN`
seeking `SUPER_ADMIN`, and (c) a local user without read access to the store file.

### 1. Authentication is bypassable by controlling the credential-store location — MEDIUM
**CWE-306: Missing Authentication for Critical Function** (also **CWE-15: External Control of
System Setting**)
**Evidence:** `src/main/java/com/example/adminportal/AdminPortal.java:34-35`, `AdminPortal.java:54`,
`AdminPortal.java:106-138`

```java
Path storeFile = Paths.get(System.getProperty("adminportal.store", "data/admin-users.txt"));
...
if (store.isEmpty() && !bootstrapFirstAdministrator(store, io)) {
```

The "no shipped default credentials" design is sound, but its consequence is that an **empty
store means anyone at the console becomes `SUPER_ADMIN` with no authentication at all**. The
store path defaults to the *relative* path `data/admin-users.txt` and can be overridden by an
unprivileged system property, so an attacker who can start the JVM merely needs to run it from a
different working directory (or pass `-Dadminportal.store=/tmp/x`) to reach the bootstrap branch
and mint a `SUPER_ADMIN` account. Deleting or renaming the real store achieves the same. Nothing
binds the program to a specific, protected store.

**Fix:** resolve the store path from a trusted, absolute, deploy-time configuration (not a
per-invocation system property), and refuse to run if the resolved file is missing, is not owned
by the expected user, or has non-`0600` permissions. Gate the bootstrap flow behind an explicit
one-shot mode (e.g. `--init`, refusing to run if the file already exists) rather than making it
the implicit fallback of every startup.

---

### 2. Lockout state is in-memory only — brute-force throttling resets on restart — MEDIUM
**CWE-307: Improper Restriction of Excessive Authentication Attempts**
**Evidence:** `AuthenticationService.java:28` (`private final Map<String, FailureState> failures = new HashMap<>();`),
`AuthenticationService.java:89-93`, `AdminPortal.java:59-62`, `AdminPortal.java:78`

`AuthenticationService` is constructed fresh on every `main()` invocation, and the failure map
lives only in that object. The login loop stops after 5 attempts and the process exits — at which
point the counter is destroyed. An attacker scripting `java -cp out com.example.adminportal.AdminPortal`
in a loop gets 5 free guesses per process with **no cumulative limit and no lockout ever taking
effect**. The 15-minute lockout is therefore effective only within a single interactive session.
The README lists this as a "deliberate limit", but as shipped it means the advertised
brute-force control does not hold against the most obvious attack.

**Fix:** persist failure counters and lockout expiry alongside the account record (same
`0600` file, written through the existing atomic `persist()`), so they survive process restarts.
Add a global/per-host failure counter and a delay that escalates with total failures.

---

### 3. Audit log is created with default (world-readable) permissions — MEDIUM
**CWE-276: Incorrect Default Permissions** (also **CWE-732**)
**Evidence:** `AuditLog.java:36-45`

```java
Path parent = file.toAbsolutePath().getParent();
if (parent != null) { Files.createDirectories(parent); }
Files.write(file, List.of(entry), StandardCharsets.UTF_8,
        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
```

`CredentialStore` carefully restricts its file to `rw-------` (`CredentialStore.java:99`, `:107`,
`:110-117`), but `AuditLog` applies no equivalent restriction — the log and the `data/` directory
it creates are left at the process umask (typically `rw-r--r--` / `rwxr-xr-x`). By default the log
sits in the *same* `data/` directory as the credential store, so a directory created here with
default permissions also weakens the store's containing directory. The log discloses the full
administrator username list, login times, lockout state, and which accounts are being attacked —
exactly the reconnaissance an attacker wants — and any local user can also append forged entries
to it.

**Fix:** call the same `PosixFilePermissions.fromString("rw-------")` treatment on the audit file
after creation, and create the parent directory with `rwx------` via
`Files.createDirectories(parent, PosixFilePermissions.asFileAttribute(...))`.

---

### 4. Audit-log `outcome` field is never sanitised — log / terminal escape injection — MEDIUM
**CWE-117: Improper Output Neutralization for Logs** (also **CWE-150: Improper Neutralization of
Escape, Meta, or Control Sequences**)
**Evidence:** `AuditLog.java:31-34` and `AuditLog.java:52-61`; reached via `AdminConsole.java:146`

```java
String entry = ... + " user=" + sanitise(username) + " outcome=" + outcome;   // AuditLog.java:32-34
...
auditLog.record(session.user().username(), "CREATE_ADMIN:" + username.trim()); // AdminConsole.java:146
```

`sanitise()` is applied to the `username` argument only. The `outcome` argument is concatenated
raw, and at `AdminConsole.java:146` it embeds an **operator-supplied new-account username**.
`CredentialStore.addUser` validates only for `:` and `|` (`CredentialStore.java:78-88`) — control
characters, ANSI escape sequences, and NUL are all accepted. The same unfiltered value is stored
in the record (`AdminUser.java:44`) and echoed back at `AdminConsole.java:104-107`,
`AdminConsole.java:42-43` and, via the log, at `AdminConsole.java:166-170`.

An account named `bob<ESC>[2J<ESC>[1;1H2026-01-01T00:00:00Z user=root outcome=GRANTED` lets a
`SUPER_ADMIN` (or the unauthenticated bootstrap user — see finding 1) plant content that clears
and rewrites the terminal of any `ADMIN` who later views the audit log, forging apparently
legitimate entries. Full line forging via `\n` is *not* currently reachable, because both input
paths (`Console.readLine` / `BufferedReader.readLine` at `TextIo.java:41-48`) strip line
terminators — the format's lack of escaping is nonetheless one input-source change away from
that.

**Fix:** run `sanitise()` over the whole assembled entry (or over every interpolated field, not
just `username`), and reject non-printable characters in usernames at
`CredentialStore.addUser` — allow an explicit character class such as `[A-Za-z0-9._-]{1,64}`
rather than blacklisting two delimiters.

---

### 5. PBKDF2-HMAC-SHA256 work factor is below current guidance — MEDIUM
**CWE-916: Use of Password Hash With Insufficient Computational Effort**
**Evidence:** `PasswordHasher.java:17-21`

```java
private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
private static final int DEFAULT_ITERATIONS = 210_000;
```

210,000 is the OWASP Password Storage figure for PBKDF2-**HMAC-SHA512**; for
PBKDF2-**HMAC-SHA256** the corresponding recommendation is **600,000** iterations. The code pairs
the SHA-256 variant with the SHA-512 iteration count, so offline cracking of a leaked store is
roughly 3x cheaper than the intended design point. The 16-byte per-user salt
(`PasswordHasher.java:20`, `:30-31`) and 256-bit output are correct, and the parameters are
encoded with the hash so the factor is upgradable.

**Fix:** raise `DEFAULT_ITERATIONS` to 600,000, or move to a memory-hard KDF (Argon2id /
scrypt / bcrypt) which resists GPU cracking far better than any PBKDF2 setting. Since the format
already carries the iteration count, also re-hash on successful login when the stored count is
below the current default.

---

### 6. `verify()` honours any iteration count from the stored record — no floor, no ceiling — LOW
**CWE-916** (downgrade) and **CWE-1284: Improper Validation of Specified Quantity in Input**
(resource exhaustion)
**Evidence:** `PasswordHasher.java:60`, `PasswordHasher.java:66`

```java
iterations = Integer.parseInt(parts[1]);
...
if (iterations <= 0 || salt.length == 0 || expected.length == 0) { return false; }
```

The only constraint is `> 0`. Anyone able to write the store can (a) rewrite a record to
`pbkdf2_sha256$1$...` and make that account's hash crackable essentially instantly, or (b) set
`2147483647` and turn every login attempt into an hours-long CPU burn — a denial of service on
the portal, including the `DUMMY_HASH` timing path. Salt length is likewise unchecked beyond
non-empty, so a 1-byte salt is accepted.

**Fix:** enforce a minimum accepted work factor (e.g. reject `iterations < 100_000`) and an upper
bound (e.g. `> 5_000_000`), and require `salt.length >= 16` and `expected.length == KEY_BITS/8`.

---

### 7. Creation of the initial `SUPER_ADMIN` is not audited — LOW
**CWE-778: Insufficient Logging**
**Evidence:** `AdminPortal.java:106-138` (no `auditLog.record(...)` anywhere in
`bootstrapFirstAdministrator`); contrast `AdminConsole.java:146`, which does log
`CREATE_ADMIN`

The single most privileged event the program can perform — creating an unauthenticated
`SUPER_ADMIN` account with both roles (`AdminPortal.java:132-135`) — leaves no audit record at
all. Combined with finding 1, an attacker who forces the bootstrap path gains full privilege with
no trace in the log. Related gaps: the audit log is written by the same identity that can rewrite
it (acknowledged in the README) and login-loop exhaustion is not recorded as a distinct event.

**Fix:** record a `BOOTSTRAP_ADMIN_CREATED` event (and a failure event) in
`bootstrapFirstAdministrator`, and ship logs to an appender the portal cannot rewrite.

---

### 8. Password is read into an immutable `String` — and echoed — when no console is attached — LOW
**CWE-316: Cleartext Storage of Sensitive Information in Memory** (also **CWE-549: Missing
Password Field Masking**)
**Evidence:** `TextIo.java:55-61`, warned about at `AdminPortal.java:50-52`

```java
char[] readPassword(String prompt) {
    if (console != null) { return console.readPassword("%s", prompt); }
    String line = readLine(prompt);
    return line == null ? null : line.toCharArray();
}
```

On the fallback path (piped input, IDE, no controlling TTY) the plaintext password first exists as
a `String`, which `TextIo.wipe` (`TextIo.java:64-68`) cannot zero — it lingers on the heap until
GC and can surface in a heap dump or core file. On the same path the password is echoed to the
terminal and, if stdin is a file or history-backed shell, persists on disk. The rest of the code
is diligent about `char[]` hygiene (`AdminPortal.java:90`, `:146-147`;
`AdminConsole.java:152-153`; `PasswordHasher.java:40`, `:74`, `:86`), so this is the one gap in
an otherwise consistent control.

**Fix:** read the fallback path character-by-character into a `char[]` (or `CharBuffer`) instead of
via `readLine()`, and consider refusing to accept a password at all when no console is available
unless an explicit `--allow-echo` flag is passed.

---

### 9. Concurrent portal instances silently overwrite each other's accounts — LOW
**CWE-362: Race Condition** (lost update / TOCTOU on the store file)
**Evidence:** `CredentialStore.java:29-32` (load once, in the constructor), `CredentialStore.java:93-108`
(`persist()` rewrites the whole file from the in-memory map), `CredentialStore.java:106`
(`Files.move(temp, file, REPLACE_EXISTING)`)

The store is read once at startup and every `addUser` rewrites the entire file from the stale
in-memory snapshot. Two portal processes running concurrently will each write their own view: the
second `persist()` silently deletes the account the first one created. The temp-file-and-move
gives atomicity for a *single* writer only — there is no lock and no re-read/merge. A failure
between `createTempFile` and `move` also leaves an orphan `admin-users*.tmp` containing hashes in
the data directory.

**Fix:** hold an exclusive `FileLock` (or a lock file) across the read-modify-write, re-read the
file inside the lock before mutating, and delete the temp file in a `catch`/`finally`.

---

### 10. Unbounded failure map keyed by attacker-supplied usernames — LOW
**CWE-770: Allocation of Resources Without Limits or Throttling**
**Evidence:** `AuthenticationService.java:28`, `AuthenticationService.java:89-93`

```java
FailureState state = failures.computeIfAbsent(key, k -> new FailureState());
```

Every distinct username string that fails authentication creates a permanent map entry; entries are
removed only on success (`:68`) or on lockout expiry during a *subsequent* attempt on that same key
(`:85`). Nothing bounds the map or evicts stale entries. Impact is limited by the 5-attempt login
loop in the current front end, but any longer-lived embedding of `AuthenticationService` (a service
wrapper, the networked deployment the README contemplates) makes this a memory-exhaustion lever.

**Fix:** cap the map size with LRU eviction, or sweep entries whose lockout has expired on each
call.

---

### 11. Permission hardening failures are silently swallowed — LOW
**CWE-732: Incorrect Permission Assignment for Critical Resource**
**Evidence:** `CredentialStore.java:110-117`

```java
} catch (IOException | UnsupportedOperationException e) {
    // Non-POSIX filesystem (e.g. Windows): fall back to platform defaults.
}
```

If `setPosixFilePermissions` fails for any reason — not just the documented Windows case, but also
an `IOException` on a POSIX filesystem — the store is left at the umask default and the program
continues without a word to the operator or the audit log. There is also no verification that the
permissions took effect. Note that the *parent* directory created at `CredentialStore.java:96` is
never restricted at all, so on a shared host `data/` is typically `rwxr-xr-x`.

**Fix:** distinguish "platform does not support POSIX permissions" from "the call failed", warn or
refuse to start in the latter case, restrict the parent directory too, and verify the resulting
permission set after writing.

---

### 12. Usernames beginning with `#` create accounts that silently disappear — LOW
**CWE-20: Improper Input Validation**
**Evidence:** `CredentialStore.java:43` (`if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;`)
versus `CredentialStore.java:78` (validation rejects only `:` and `|`)

Creating an administrator named `#ops` succeeds and reports success
(`AdminConsole.java:143-146`), but on the next load the record is parsed as a comment and skipped —
the account vanishes with no error. The mirror case is that a username whose stored record fails
`AdminUser.fromRecord` makes `load()` throw (`CredentialStore.java:49-52`), and `AdminPortal.java:41-47`
then exits with status 2 — a single malformed line renders the entire portal unusable
(availability). The comment convention and the record delimiters are unescaped in-band signalling.

**Fix:** apply an allow-list charset to usernames at creation time (see finding 4) that excludes a
leading `#`, and skip-with-warning rather than hard-fail on an individual corrupt record so one bad
line cannot lock every administrator out.

---

### 13. Password policy has no breached/common-password check, and there is no credential rotation — LOW
**CWE-521: Weak Password Requirements** (partial) / missing lifecycle function
**Evidence:** `PasswordPolicy.java:9-52`; no password-change action in `AdminConsole.java:72-80`

The 12-character minimum with four character classes (`PasswordPolicy.java:16-52`) is reasonable
and the 256-character cap correctly prevents a KDF-cost DoS (`PasswordPolicy.java:22-25`). But
NIST SP 800-63B's central recommendation — screening candidates against a breached/common-password
list — is absent, so `Password1234!` passes. Separately, the menu offers no way to change a
password, disable an account, or delete one: the `enabled` flag (`AdminUser.java:34-36`) is
honoured at `AuthenticationService.java:60` but can only ever be set by hand-editing the store.
A compromised administrator credential cannot be rotated through the application at all.

**Fix:** screen new passwords against a common-password list (Have I Been Pwned's k-anonymity API
or a bundled top-100k list), and add role-gated change-password / disable-account actions that go
through the existing `persist()` path.

---

## Checks that passed

These were tested against the code and found sound — listed so the review's negative results are
explicit:

- **No hardcoded or default credentials** — grep across `src/` finds none; the sentinel at
  `AuthenticationService.java:21` (`"::no-such-user::"`) is a timing-equalisation input, not a
  secret. The literals in `AuthenticationTests.java:45-48` etc. are test fixtures in a test-only
  class. **CWE-798 does not fire.**
- **No plaintext password storage** — only encoded PBKDF2 hashes are written
  (`CredentialStore.java:89`, `AdminUser.java:44`), verified by `AuthenticationTests.java:151-156`.
  **CWE-256/CWE-257 do not fire.**
- **Salting** — 128-bit `SecureRandom` per-user salt, fresh on every hash
  (`PasswordHasher.java:20`, `:23`, `:30-31`). **CWE-759/CWE-760 do not fire.**
- **Constant-time verification** — `MessageDigest.isEqual` (`PasswordHasher.java:72`), not
  `Arrays.equals`/`String.equals`. **CWE-208 does not fire.**
- **Secure RNG everywhere it matters** — `SecureRandom` for both salts (`PasswordHasher.java:23`)
  and the 256-bit session identifier (`AdminSession.java:17`, `:37-41`). No `java.util.Random`,
  no time-based seeding. **CWE-330/CWE-338 do not fire.**
- **No user enumeration** — unknown user, wrong password and disabled account all return the same
  `AuthenticationResult.denied()` message (`AuthenticationResult.java:28-32`,
  `AuthenticationService.java:56-66`), and an unknown username still runs a full KDF against
  `DUMMY_HASH` so the timing matches (`AuthenticationService.java:58`). **CWE-204/CWE-203 do not
  fire.**
- **Fail-closed hash parsing** — a malformed or `null` stored hash returns `false` rather than
  throwing or short-circuiting to success (`PasswordHasher.java:48-68`). **CWE-393 does not fire.**
- **Correct authentication conjunction** — `found.isPresent() && enabled() && passwordMatches`
  (`AuthenticationService.java:60`); no path grants access on an absent user or an exception.
- **Per-action authorisation, not menu-level** — every privileged action re-checks the role
  *and* session liveness through `denied()` → `AdminSession.isAuthorised`
  (`AdminConsole.java:83-90`, `:99`, `:113`, `:158`; `AdminSession.java:68-70`). A plain `ADMIN`
  cannot reach account creation. **CWE-862/CWE-863 do not fire** for the exposed actions.
- **Bounded sessions with real revocation** — idle timeout and absolute lifetime both enforced,
  re-checked after every blocking read (`AdminConsole.java:46`, `:52`; `AdminSession.java:51-57`),
  and `logout()` terminates the session (`AdminConsole.java:177-181`). **CWE-613 does not fire.**
- **Password hashes never displayed or logged** — `listAdministrators` prints only
  username/roles/enabled (`AdminConsole.java:104-107`), `AdminUser.toString` deliberately omits
  the hash (`AdminUser.java:61-65`), and `AuditLog` records only username + outcome
  (`AuditLog.java:31-34`). **CWE-532 does not fire.**
- **`char[]` password buffers are wiped** on every console-backed path
  (`AdminPortal.java:90`, `:146-147`; `AdminConsole.java:152-153`; `PasswordHasher.java:40`, `:74`;
  `PBEKeySpec.clearPassword()` at `PasswordHasher.java:86`) — see finding 8 for the one gap.
- **Case normalisation is locale-safe** — `toLowerCase(Locale.ROOT)`
  (`CredentialStore.java:120`, `AuthenticationService.java:102`), so the Turkish-dotless-I
  username-collision trick does not apply.
- **Store written atomically with restricted permissions** — temp file created inside the target
  directory, permissions applied before content, then moved (`CredentialStore.java:98-107`), so a
  partial write cannot leave a readable or truncated store.
- **KDF cost is bounded on input length** (`PasswordPolicy.java:22-25`), so an oversized password
  cannot be used as a CPU-exhaustion lever at account creation.

**Behaviours with no matching library skill,** reviewed against general OWASP Top 10 / CWE
knowledge instead, and reported above where they fired: file-permission handling and umask
behaviour (findings 3, 11 — CWE-276/732); log-record construction and terminal escape sequences
(finding 4 — CWE-117/150); audit completeness (finding 7 — CWE-778); in-memory secret lifetime
(finding 8 — CWE-316); filesystem concurrency and lost updates (finding 9 — CWE-362); resource
limits on server-side state (finding 10 — CWE-770); and in-band delimiter/comment handling in the
record format (finding 12 — CWE-20). No SQL, ORM, HTTP, XML/JSON deserialization, template
rendering, path-parameter handling, or outbound network call exists anywhere in the codebase, so
the corresponding injection, SSRF, XXE, XSS and deserialization skill families were checked for
applicability and correctly found to have no attack surface here.

---

## Skills applied

Selected from the library by name-grep on the Step 1 keywords, then by reading each candidate's
`description` frontmatter; applied in this order, reading each skill body only when reached:

1. **`performing-cryptographic-audit-of-application`** — weak-algorithm, cipher-mode, hardcoded-key,
   entropy and KDF-parameter checklist → findings 5 and 6; cleared the weak-hash, weak-RNG and
   hardcoded-secret categories.
2. **`testing-api-authentication-weaknesses`** — credential-stuffing resistance, password policy,
   account enumeration, session-token entropy and token revocation → findings 2 and 13; cleared
   enumeration, session entropy and logout revocation. (Its JWT/OAuth sections are not applicable:
   no tokens leave the process.)
3. **`testing-for-broken-access-control`** — endpoint/role matrix and function-level check
   methodology, applied to the five menu actions → no vertical privilege-escalation path found;
   confirmed each privileged action re-checks the role rather than trusting the rendered menu.
4. **`testing-for-sensitive-data-exposure`** — data-at-rest, secret-leakage, log-content and
   error-message checks → findings 3 and 8; cleared hash/PII leakage in output.
5. **`performing-hash-cracking-with-hashcat`** — offline-cracking economics used to judge the
   stored hash format's resistance → corroborates finding 5 (PBKDF2-SHA256 is GPU-friendly
   relative to memory-hard alternatives, so the iteration shortfall matters).
6. **`testing-for-business-logic-vulnerabilities`** — workflow-bypass, state-manipulation and
   race-condition patterns → findings 1 and 9.

## Summary table

| # | Severity | CWE | Location |
| --- | --- | --- | --- |
| 1 | Medium | CWE-306 / CWE-15 | `AdminPortal.java:34`, `:54` |
| 2 | Medium | CWE-307 | `AuthenticationService.java:28`, `AdminPortal.java:59` |
| 3 | Medium | CWE-276 / CWE-732 | `AuditLog.java:36-45` |
| 4 | Medium | CWE-117 / CWE-150 | `AuditLog.java:34`, `AdminConsole.java:146`, `CredentialStore.java:78` |
| 5 | Medium | CWE-916 | `PasswordHasher.java:19` |
| 6 | Low | CWE-916 / CWE-1284 | `PasswordHasher.java:60`, `:66` |
| 7 | Low | CWE-778 | `AdminPortal.java:132` |
| 8 | Low | CWE-316 / CWE-549 | `TextIo.java:55-61` |
| 9 | Low | CWE-362 | `CredentialStore.java:29`, `:93-108` |
| 10 | Low | CWE-770 | `AuthenticationService.java:28`, `:90` |
| 11 | Low | CWE-732 | `CredentialStore.java:110-117` |
| 12 | Low | CWE-20 | `CredentialStore.java:43`, `:78` |
| 13 | Low | CWE-521 | `PasswordPolicy.java:9-52`, `AdminConsole.java:72-80` |
