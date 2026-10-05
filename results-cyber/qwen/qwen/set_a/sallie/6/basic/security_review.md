# Security Review: Administrator Portal (src/portal)

## 1. Executive Summary

The Administrator Portal is a self-contained Java 17 command-line tool: PBKDF2-HMAC-SHA256 credentials in a tab-separated file, a fail-closed append-only audit log, per-username lockout, and role-gated administration commands. The core authentication design is unusually careful — constant-time key comparison, equal-cost "shadow" work on branches that cannot succeed, zeroization of password arrays, and refusal to grant access when the audit record cannot be written.

The weaknesses cluster **around** that core rather than inside it:

- **1 High** finding: the credential store is briefly **world-readable under a predictable file name** on every save, exposing every account's salt+hash for offline cracking (and enabling a symlink/overwrite trick when the store directory is attacker-writable).
- **7 Medium** findings: the store file is trusted for authentication with **no integrity protection**; the **first supervisor can be created without any authentication** (including into any attacker-chosen directory via `portal.home` / `ADMIN_PORTAL_HOME`); the audit log and home directory are created **world-readable / listable**; lockout state lives in **unsynchronized hash maps** while the rest of the code is synchronized; the login answers **leak account existence and lock state** through different messages; sessions are **bearer tokens that nothing can revoke**; and the PBKDF2 iteration count (100,000) is well below current OWASP guidance (600,000).
- **5 Low** findings: composition-rule password policy, password bytes materialized as immutable `String`s on piped input, audit-sequence numbering that can silently restart (no chain/MAC), silent downgrade of unknown stored roles, and hardcoded passwords in the self-test harness.

All findings assume the documented local-CLI threat model (a shared multi-user host, or an attacker who can influence the environment or the store directory). No network attack surface exists: the portal opens no sockets and executes no shell. None of the fixes require a format change to `credentials.tsv` except where noted; rows already persist their own iteration count, so raising it (SEC-08) is transparent.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/portal/AdminPortal.java` (566 lines) | Interactive CLI: login, `create`/`reset`/`remove`/`unlock`/`audit`, bootstrap of the first supervisor | Resolves store home from `portal.home` / `ADMIN_PORTAL_HOME` (`home()`, 101–111); creates the first supervisor **without authentication** when the store is empty (`run()` 118–126, `bootstrapSupervisor()` 386–415); command gating via `requireSession`/`mayManage`; base `askSecret` reads piped stdin through a `String` (493–502); console subclass uses `readPassword()` |
| `src/portal/LoginService.java` (239 lines) | Credential verification, per-username lockout, session issue/validation | Equal-cost work on all branches; constant-time compare; fail-closed audit for grants; **unsynchronized** `HashMap` lockout state (63–64, 215–223); **branch-specific user-visible messages** (126–131, 140–146, 151–155); sessions are 16 random bytes, 15-min TTL, never re-checked against any registry (48–52, 183–194) |
| `src/portal/CredentialStore.java` (166 lines) | File-backed store `user⇥iterations⇥salt⇥hash⇥role` | `synchronized` methods; strict row validation on `load()` (95–131); atomic save via temp file + `ATOMIC_MOVE` — but temp is **created world-readable with a predictable name before being restricted** (143–147); file content is trusted with **no MAC/signature** |
| `src/portal/AuditLog.java` (107 lines) | Append-only audit trail | Refuses grants when write fails; `clean()` (70–81) strips control characters and caps field length (anti log-injection); file **created with default permissions** (46–48) and never restricted; sequence reseeded from disk, **resets to 0 on parse/IO failure** (83–105); no integrity chain |
| `src/portal/Pbkdf2.java` (103 lines) | PBKDF2-HMAC-SHA256 hashing + equal-cost shadow work | 16-byte `SecureRandom` salt, 32-byte key, **`ITERATIONS = 100_000`** (17); `PBEKeySpec.clearPassword()` in `finally`; `MessageDigest.isEqual` constant-time `matches()`; shadow salt derived from SHA-256 and never accepted as a credential |
| `src/portal/PasswordPolicy.java` (90 lines) | Password rules | Min 10 chars, username containment check, **letter/digit + ≥3 character-class composition rules** (43–48); `new String(password)` materializes plaintext (20); `structural()` (59–89) rejects NULs and unpaired surrogates (prevents dual-encoding unlock) |
| `src/portal/Names.java` | Username validation | Allowlist regex `[a-z0-9._-]+`, length 3–32, rejects `..`, reserved names (`credentials`, `admin-portal`) — username is never usable for path traversal |
| `src/portal/Roles.java` | Role constants + hierarchy | `supervisor`/`operator`/`auditor`; only supervisor manages accounts; any known role may read the audit log |
| `src/portal/PortalChecks.java` (849 lines) | Self-test suite (111 checks) | **Hardcoded passwords** `CLI_PASS` / `CLI_CAROL_PASS` (37–38) and several literals (e.g. 150–151); CLI child processes launched with argument-list `ProcessBuilder` + `-Dportal.home=` (636–652) — no shell interpolation; timing-equalization assertions (754–781) |
| `README.md` / `run-checks.sh` | Docs / build+test script | README honestly documents limits (single process, in-memory locks, "append-only by convention… not signed", "piped input is not private"); build uses `javac -Xlint:all -Werror` |
| `out/portal/*.class` | Compiled output | Not separately reviewed; assumed to match `src/` (rebuild via `run-checks.sh`) |

## 3. Skills Applied

- **`review-code-for-security-vulnerabilities`** — the router/orchestrator skill; its workflow (determine what the code actually does → match specialised skills → apply each one → report with CWE + file:line) defined the process for this review.
- **`performing-cryptographic-audit-of-application`** — applied to `Pbkdf2.java` and `CredentialStore.java`: KDF choice (PBKDF2-HMAC-SHA256), iteration count vs. current guidance, per-account `SecureRandom` salts, salt/iteration validation on load, constant-time comparison via `MessageDigest.isEqual`, and the deterministic shadow-salt construction.
- **`testing-api-authentication-weaknesses`** — applied to `LoginService.verify/issueSession/authorized`: token entropy (16 `SecureRandom` bytes), session lifetime and (missing) revocation, lockout counter correctness, and differential responses that leak account state.
- **`testing-for-broken-access-control`** — applied to `AdminPortal`'s command matrix: `requireSession` (430–440), `mayManage` (443–451), role gates on `create`/`reset`/`remove`/`unlock`, the unauthenticated bootstrap path, and state retained after an account is removed or reset.
- **`testing-for-sensitive-data-exposure`** — applied to on-disk secrets: file-creation permissions and predictable temp files for the credential store and audit log, the skill's "password hashes should never be exposed" scenario (world-readable salt+hash → offline cracking), plaintext password bytes surviving in `String`s, and hardcoded credentials in `PortalChecks.java` (Step 5 secret-scanning of source).
- **`implementing-log-integrity-with-blockchain`** — applied to `AuditLog.java`: its hash-chained, externally-anchorable ledger design was used to assess the audit log's tamper-evidence (it has none) and to shape the SEC-11 fix.
- **`testing-for-business-logic-vulnerabilities`** — applied to workflow gating: first-run bootstrap as a step-bypassable flow, the last-admin removal guard, race conditions in the lockout business rule (the skill's Step 4), and privilege/session retention after `reset`/`remove` (analogous to its password-reset-token-reuse scenario).
- **Reviewed against general OWASP Top 10 / CWE knowledge, with no matching skill in the library:** thread-safety of shared mutable state (`CWE-362`, inconsistent with the store's own `synchronized` contract), POSIX permission hygiene and predictable temp-file creation (`CWE-377`/`CWE-732` details), atomic-file-replacement correctness (`ATOMIC_MOVE` with cleanup — verified sound), username-to-path traversal analysis (`Names.java` — verified safe), audit-field sanitisation as log-injection defence (`AuditLog.clean()` — verified effective), and argument-list `ProcessBuilder` usage in `PortalChecks` (no command injection).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Credential store written world-readable to a predictable temp file on every save | High | CWE-732 (also CWE-377) | `src/portal/CredentialStore.java:143-147` |
| SEC-02 | Credential file trusted for authentication with no integrity protection | Medium | CWE-345 (also CWE-353) | `src/portal/CredentialStore.java:108-126` |
| SEC-03 | First supervisor can be created without authentication; store home is attacker-controllable | Medium | CWE-287 (also CWE-1188) | `src/portal/AdminPortal.java:101-126, 386-415` |
| SEC-04 | Audit log created world-readable; home directory listable | Medium | CWE-276 (also CWE-200) | `src/portal/AuditLog.java:46-48`, `src/portal/AdminPortal.java:58` |
| SEC-05 | Lockout/failure state in unsynchronized hash maps | Medium | CWE-362 | `src/portal/LoginService.java:63-64, 98-101, 215-223` |
| SEC-06 | Sessions are unrevocable bearer tokens; survive removal and password reset | Medium | CWE-613 | `src/portal/LoginService.java:48-52, 183-194`, `src/portal/AdminPortal.java:290-317` |
| SEC-07 | Login responses leak account existence and lock state | Medium | CWE-204 | `src/portal/LoginService.java:55, 126-131, 140-146, 151-155` |
| SEC-08 | PBKDF2 iteration count below current guidance | Medium | CWE-916 | `src/portal/Pbkdf2.java:17` |
| SEC-09 | Composition-rule password policy, no breached-password screening | Low | CWE-521 | `src/portal/PasswordPolicy.java:6, 43-48` |
| SEC-10 | Plaintext passwords materialized as immutable `String`s (piped input path) | Low | CWE-316 | `src/portal/AdminPortal.java:493-498`, `src/portal/PasswordPolicy.java:20` |
| SEC-11 | Audit sequence silently restarts on unreadable tail; no integrity chain | Low | CWE-353 | `src/portal/AuditLog.java:83-105` |
| SEC-12 | Unknown stored role silently coerced to `operator` | Low | CWE-1188 (also CWE-639) | `src/portal/LoginService.java:162` |
| SEC-13 | Hardcoded passwords in the self-test harness | Low | CWE-798 | `src/portal/PortalChecks.java:37-38, 150-151` |

## 5. Detailed Findings

### SEC-01: Credential store written world-readable to a predictable temp file on every save

**Severity:** High
**CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource (also CWE-377: Insecure Temporary File)
**Location:** `src/portal/CredentialStore.java:143-147`
**Vulnerable code:**
```java
// src/portal/CredentialStore.java:143-147
        Path temp = path.resolveSibling(path.getFileName() + ".tmp-" + ProcessHandle.current().pid());
        Files.write(temp, sb.toString().getBytes(StandardCharsets.UTF_8));
        try {
            restrict(temp);
            Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
```
**Why it is a problem:** `Files.write` with default options creates the temp file with the process umask (typically `0644` — **world-readable**) and only *afterwards* does `restrict()` (line 146) tighten it to owner-only. Every `create`/`reset`/bootstrap therefore emits a complete copy of the credential store — every username, salt, derived key, and role — in a world-readable file for the window between the write returning and `restrict()` running. On a shared host a local user watching the directory (`inotify`) can grab it, and every salt+hash pair obtained is offline-crackable, made cheaper still by the 100,000-iteration count (SEC-08). Two aggravating factors: the temp name is fully predictable (`.tmp-<pid>`, and PIDs are trivially guessable for a CLI a victim launches routinely), and `Files.write` follows symlinks — if the store directory is writable by an attacker (e.g. the victim was steered into `ADMIN_PORTAL_HOME=/tmp/shared`, per SEC-03), a pre-planted symlink at `credentials.tsv.tmp-<pid>` makes the portal truncate and write any file the victim can access.
**Fix:** Create the temp file closed, with owner-only permissions *at creation time* and an unpredictable name, then write into it:
```java
// add: import java.security.SecureRandom;
    private static final SecureRandom TEMP_RANDOM = new SecureRandom();

        String nonce = Long.toHexString(TEMP_RANDOM.nextLong());
        Path temp = path.resolveSibling(path.getFileName() + ".tmp-" + nonce);
        try {
            Files.createFile(temp, PosixFilePermissions.asFileAttribute(Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            Files.write(temp, sb.toString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | RuntimeException failure) {
            Files.deleteIfExists(temp);
            throw failure;
        }
```
With the mode set atomically at `createFile`, no world-readable window exists, and the random nonce defeats temp-file squatting and symlink pre-placement alike (the file's permissions also stop the write from silently following an attacker's symlink target on any sane configuration).

### SEC-02: Credential file trusted for authentication with no integrity protection

**Severity:** Medium
**CWE:** CWE-345: Insufficient Verification of Data Authenticity (also CWE-353)
**Location:** `src/portal/CredentialStore.java:108-126`
**Vulnerable code:**
```java
// src/portal/CredentialStore.java:108-126
            String[] parts = line.split("\t");
            if (parts.length != 5) {
                malformedRows++;
                continue;
            }
            try {
                String username = parts[0];
                Names.validate(username);
                int iterations = Integer.parseInt(parts[1].trim());
                byte[] salt = B64DEC.decode(parts[2]);
                byte[] key = B64DEC.decode(parts[3]);
                String role = parts[4];
                if (salt.length != Pbkdf2.SALT_BYTES || key.length != Pbkdf2.KEY_BYTES
                        || iterations < Pbkdf2.MIN_ITERATIONS || iterations > Pbkdf2.MAX_ITERATIONS
                        || !Roles.isKnown(role)) {
                    malformedRows++;
                    continue;
                }
                rows.put(username, new AdminCredential(username, iterations, salt, key, role));
```
**Why it is a problem:** `load()` syntactically validates each row (field count, name syntax, salt/key lengths, iteration range, known role) but performs **no authenticity check** on the row contents: the file is accepted as the sole authority for who can log in and with what role. Anyone who can write `credentials.tsv` — today that requires the owner's write access, but SEC-01's window and SEC-03's attacker-chosen home both shrink that margin — can replace any row's hash with one for a password they know, or flip the final field to `supervisor`, and the portal will honour it: a well-formed forged row is indistinguishable from a genuine one. Nothing records that the file changed; the only trace would be a coincidental `ADMIN_*` audit record for a legitimate write, and edits made directly on disk are never noticed at all.
**Fix:** Bind each row to a keyed MAC, and reject rows whose MAC does not verify, so edits and row swaps become detection events rather than silent privilege grants:
```java
// in load(), inside the loop, after the length/role validation block:
                byte[] payload = line.getBytes(StandardCharsets.UTF_8);
                byte[] expected = mac(java.util.Arrays.copyOf(payload,
                        line.lastIndexOf('\t') + 1)); // bytes before the MAC field
                byte[] got;
                try {
                    got = B64DEC.decode(parts.length == 6 ? parts[5] : "");
                } catch (IllegalArgumentException bad) {
                    malformedRows++;
                    continue;
                }
                if (!MessageDigest.isEqual(expected, got)) {
                    malformedRows++; // tampered row: reported like a malformed one, never trusted
                    continue;
                }

// helper (save() appends '\t' + B64URL.encodeToString(mac(rowBytes)) per row):
    private byte[] mac(byte[] rowBytes) throws IOException, GeneralSecurityException {
        Path keyPath = path.resolveSibling(path.getFileName() + ".key");
        if (!Files.exists(keyPath)) {
            byte[] fresh = new byte[32];
            new SecureRandom().nextBytes(fresh);
            Files.write(keyPath, fresh, PosixFilePermissions.asFileAttribute(Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
        }
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(Files.readAllBytes(keyPath), "HmacSHA256"));
        return hmac.doFinal(rowBytes);
    }
```
This is defence-in-depth, not a cure: on a local CLI the MAC key shares the file's directory, so an attacker with the owner's full write access can recompute MACs. The honest residual — *"anyone who can write the store owns the portal"* — should stay documented; the MAC (plus the 0700 home from SEC-04) converts casual and SEC-01-window tampering into visible `malformedRows` reports, and a real deployment would source the key from an HSM or keyring.

### SEC-03: First supervisor can be created without authentication; store home is attacker-controllable

**Severity:** Medium
**CWE:** CWE-287: Improper Authentication (also CWE-1188: Insecure Default Initialization of Resource)
**Location:** `src/portal/AdminPortal.java:101-126, 386-415`
**Vulnerable code:**
```java
// src/portal/AdminPortal.java:101-126
    public static Path home() {
        String fromProperty = System.getProperty("portal.home");
        if (fromProperty != null && !fromProperty.isBlank()) {
            return Paths.get(fromProperty.trim());
        }
        String fromEnv = System.getenv("ADMIN_PORTAL_HOME");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return Paths.get(fromEnv.trim());
        }
        return Paths.get(System.getProperty("user.home", "."), ".admin-portal");
    }

    /**
     * Interactive loop.
     *
     * @return process exit code
     */
    public int run(String[] args) throws IOException {
        if (store.isEmpty()) {
            out.println("no administrator account exists yet.");
            out.println("create the first supervisor to unlock the portal.");
            if (!bootstrapSupervisor()) {
                out.println("no administrator account could be created, the portal stays locked.");
                return EXIT_UNAVAILABLE;
            }
        }
```
(and `bootstrapSupervisor()`, `src/portal/AdminPortal.java:400-406`)
```java
// src/portal/AdminPortal.java:400-406
            try {
                if (!record("ADMIN_BOOTSTRAP", name, "role=" + Roles.SUPERVISOR)) {
                    return false;
                }
                store.put(name, password, Roles.SUPERVISOR);
                out.println("created " + name + " with role " + Roles.SUPERVISOR + ".");
                return true;
```
**Why it is a problem:** Whenever the store loads empty, the next person at the console becomes supervisor by typing a name and any policy-passing password — no authenticator, installer token, or out-of-band check gates it. Combined with `home()`, which takes its location from an *attacker-influenced* system property or environment variable with no validation whatsoever, "store empty" is trivially attacker-satisfiable: run the portal with `portal.home`/`ADMIN_PORTAL_HOME` pointing at any empty directory (or truncate/delete `credentials.tsv` in a home the victim later uses — one more reason the file needs integrity, SEC-02) and the portal cheerfully invites supervisor creation on the next interactive start. The bootstrap also records `ADMIN_BOOTSTRAP` but cannot distinguish a legitimate first run from a hijacked one, so the audit trail offers no alarm signal.
**Fix:** Require explicit, deliberate operator intent before initializing a supervisor — an implicit "directory happens to be empty" must not be sufficient:
```java
        if (store.isEmpty()) {
            if (!"true".equals(System.getProperty("portal.allow-bootstrap"))) {
                out.println("no administrator account exists yet.");
                out.println("nothing was created: re-run from the installation console with"
                        + " -Dportal.allow-bootstrap=true to create the first supervisor.");
                return EXIT_UNAVAILABLE;
            }
            if (!bootstrapSupervisor()) {
                out.println("no administrator account could be created, the portal stays locked.");
                return EXIT_UNAVAILABLE;
            }
        }
```
Additionally, refuse a `portal.home` outside the user's own home directory unless a similar explicit override is set, and note the bootstrap event prominently in `audit` output so a surprise supervisor creation is conspicuous.

### SEC-04: Audit log created world-readable; home directory listable

**Severity:** Medium
**CWE:** CWE-276: Incorrect Default Permissions (also CWE-200: Exposure of Sensitive Information)
**Location:** `src/portal/AuditLog.java:46-48`, `src/portal/AdminPortal.java:58`
**Vulnerable code:**
```java
// src/portal/AuditLog.java:46-48
        byte[] bytes = (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
        Files.write(path, bytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
```
```java
// src/portal/AdminPortal.java:58
            Files.createDirectories(home);
```
**Why it is a problem:** The credential store is deliberately restricted (`restrict()`), but the audit log is not: `Files.write(..., CREATE, ...)` creates `audit.log` with the umask default (typically `0644`, world-readable) and *nothing ever tightens it* — the `restrict()` helper exists in `CredentialStore` but is never applied here. The log is a detailed map of the administrator population: every username, successful and failed logins, roles (`role=supervisor`), lockouts, and admin actions with timestamps — exactly the reconnaissance data a local attacker needs before the SEC-01/SEC-02/SEC-07 attacks, and itself a privacy exposure. The parent directory is likewise created with `Files.createDirectories(home)` (mode 0755): every local user can list the portal's files (username list even leaks through file names if the temp naming of SEC-01 is fixed but the directory is not) — the README's claim that the credential file is OS-protected is true for the file, not for its surroundings.
**Fix:** Apply owner-only permissions at creation time in both places:
```java
// AuditLog.java — alongside the imports:
    private static final Set<PosixFilePermission> OWNER_ONLY = Set.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);

    public synchronized void record(String event, String subject, String detail) throws IOException {
        ...
        if (!Files.exists(path)) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        }
        Files.write(path, bytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
    }
```
```java
// AdminPortal.java:58 — mode 0700 at creation:
            Files.createDirectories(home, PosixFilePermissions.asFileAttribute(Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE)));
```
(An existing 0755 home should be tightened on upgrade; a one-time `setPosixFilePermissions` when the directory's permissions are found to be broader than owner-only is a reasonable migration shim.)

### SEC-05: Lockout/failure state in unsynchronized hash maps

**Severity:** Medium
**CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
**Location:** `src/portal/LoginService.java:63-64, 98-101, 215-223`
**Vulnerable code:**
```java
// src/portal/LoginService.java:215-223
    private void registerFailure(String name) {
        int seen = failuresFor(name) + 1;
        if (seen >= maxFailures) {
            failuresByName.remove(name);
            lockedUntilByName.put(name, System.currentTimeMillis() + lockoutMillis);
            return;
        }
        failuresByName.put(name, seen);
    }
```
**Why it is a problem:** Every state-mutating method of `CredentialStore` and `AuditLog` is `synchronized`, but `LoginService`'s own mutable state — `failuresByName` and `lockedUntilByName` (lines 63–64), read at lines 87–95 and written by `registerFailure`, `clearLock` (98–101), and the success path — uses plain `java.util.HashMap` with no locking. `registerFailure` is the textbook read-modify-write race: two concurrent failures on the same username can both read the old count, so a failed attempt vanishes and `maxFailures` is effectively *n*+1 — or, worse, concurrent `put`/`remove`/`get` on a plain `HashMap` can tear (documented unsafe publication and, under resize, corrupted structure). The shipped CLI is single-threaded today, so this is latent rather than live — but that is precisely the trap: the class is `public`, its two collaborators are fully synchronized, and nothing in the API (no javadoc, no guard) says `LoginService` must be used from one thread. The first wrapper that serves two sessions concurrently silently loses lockout enforcement, and the self-tests cannot catch it because the invariant is only violated across threads.
**Fix:** Use concurrent maps and make the increment atomic per username, matching the store's concurrency contract:
```java
    private final Map<String, Integer> failuresByName = new ConcurrentHashMap<>();
    private final Map<String, Long> lockedUntilByName = new ConcurrentHashMap<>();

    private void registerFailure(String name) {
        long now = System.currentTimeMillis();
        failuresByName.compute(name, (key, seen) -> {
            int next = (seen == null ? 0 : seen) + 1;
            if (next >= maxFailures) {
                lockedUntilByName.put(key, now + lockoutMillis);
                return null; // returning null removes the counter, as before
            }
            return next;
        });
    }
```
`ConcurrentHashMap.compute` is atomic per key, so no failed attempt is ever lost; document the thread-safety guarantee on the class either way.

### SEC-06: Sessions are unrevocable bearer tokens; survive removal and password reset

**Severity:** Medium
**CWE:** CWE-613: Insufficient Session Expiration
**Location:** `src/portal/LoginService.java:48-52, 183-194`, `src/portal/AdminPortal.java:290-317`
**Vulnerable code:**
```java
// src/portal/LoginService.java:190-194
    /** Confirms that an admin-level command runs inside a live session. */
    public boolean authorized(Session session) {
        return session != null && session.live(System.currentTimeMillis())
                && Roles.isKnown(session.role());
    }
```
**Why it is a problem:** `issueSession` (183–189) mints a random 16-byte token but stores nothing: the `Session` record (48–52) is a self-contained value object, and `authorized` checks only TTL and a role *string carried inside the session itself* — the token is never compared against any registry, so there is nothing that could be revoked. Consequently the supervisor commands that ought to cut access cannot: `remove()` (290–317) deletes the account and clears its lock but any already-issued session of that username — including that of the operator removing their own account, which succeeds whenever the store has >1 admin — keeps full power for the remaining TTL; `reset()` (258–288, record at 277) replaces the password — the classic reason to force re-authentication — and explicitly leaves the old session alive; and the role inside a live session is a snapshot, so even a store-side role change has no effect until the 15-minute TTL expires. With `DEFAULT_SESSION_TTL_MILLIS` of 15 minutes, "remove this admin right now" is really "remove them in up to 15 minutes" — during which they can still `create` new supervisors.
**Fix:** Keep a registry of live sessions and consult it at use time, so the admin commands can revoke:
```java
    private final Map<String, Session> activeSessions = new ConcurrentHashMap<>();

    public Session issueSession(String username, String role) {
        byte[] raw = new byte[16];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Session session = new Session(token, username, role,
                System.currentTimeMillis() + sessionTtlMillis);
        activeSessions.put(token, session);
        return session;
    }

    public boolean authorized(Session session) {
        return session != null
                && activeSessions.get(session.token()) == session  // revoked => gone
                && session.live(System.currentTimeMillis())
                && Roles.isKnown(session.role());
    }

    /** Call from remove()/reset()/unlock flows. */
    public void revokeSessions(String username) {
        activeSessions.values().removeIf(s -> s.username().equals(username));
    }
```
`AdminPortal.remove` and `AdminPortal.reset` then call `login.revokeSessions(name)` after success (and `reset` should also re-derive the session's role from `store.roleOf` if the session is kept deliberately). Requiring object identity (`get(token) == session`) also stops a hand-reconstructed `Session` with a known token from being replayed after revocation.

### SEC-07: Login responses leak account existence and lock state

**Severity:** Medium
**CWE:** CWE-204: Observable Response Discrepancy
**Location:** `src/portal/LoginService.java:55, 126-131, 140-146, 151-155`
**Vulnerable code:**
```java
// src/portal/LoginService.java:126-131
            if (isLockedOut(name)) {
                spendWork(row, name);
                return refuse(started, Status.LOCKED, name, null,
                        "this account is temporarily locked, try again later",
                        "AUTH_LOCKED", name, "attempt while locked");
            }
```
**Why it is a problem:** Considerable engineering (and two self-test assertions) goes into making *timing* reveal nothing: every branch, including the "no such administrator" branch, pays one full PBKDF2 derivation. The *messages*, however, are free oracles. With no valid credentials at all, an attacker can submit five wrong passwords for any candidate name and read back "this account is temporarily locked, try again later" only if the account exists — `registerFailure` runs only on the wrong-password path (148–156), which requires `row != null`, while a nonexistent name always answers the generic line 55 string. The same asymmetry exists in the unusable-row reply (140–146: "this account cannot be used, ask a supervisor to reset its password"). Once the name list is known (SEC-04's world-readable audit log makes this near-trivial), the attacker can confirm targets and deliberately lock out real administrators — and the self-tests' equal-timing property masks the leak because they never compare message text across branches.
**Fix:** Pay the shadow work, keep the truthful `event` for the audit log (it must remain accurate), but return the *same* status and message as the generic denial to the caller:
```java
            if (isLockedOut(name)) {
                spendWork(row, name);
                return refuse(started, Status.DENIED, name, null, GENERIC_FAILURE,
                        "AUTH_LOCKED", name, "attempt while locked");
            }
```
and identically on the post-`registerFailure` lockout branch (151–155: `Status.DENIED`, `GENERIC_FAILURE`, event `"AUTH_LOCKED"`), plus the unusable-row branch (140–146). Genuine lockout state then lives only in the audit log, which the owner protects; every pre-authentication reply is byte-identical, closing the channel the timing work was meant to protect.

### SEC-08: PBKDF2 iteration count below current guidance

**Severity:** Medium
**CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
**Location:** `src/portal/Pbkdf2.java:17`
**Vulnerable code:**
```java
// src/portal/Pbkdf2.java:17
    public static final int ITERATIONS = 100_000;
```
**Why it is a problem:** PBKDF2-HMAC-SHA256 is the right primitive, the per-account `SecureRandom` salts are right, and 100,000 iterations was reasonable when older guidance was written — but OWASP's current Password Storage Cheat Sheet recommends **600,000** iterations for PBKDF2-HMAC-SHA256, and a 6× gap is a 6× discount for every offline cracker who obtains the hashes (which SEC-01/SEC-04 make materially possible, and which is the single scenario where work factors matter). The stored format already carries a per-row iteration count that `load()` accepts anywhere in 10,000–5,000,000 and `verify()` honours exactly (`row.iterations()`), so this constant only governs *newly written* rows — raising it is transparent to existing accounts and is precisely how versioned KDF parameters are meant to work.
**Fix:**
```java
    public static final int ITERATIONS = 600_000;
```
Existing rows keep their recorded count and are re-hashed at the new cost whenever `reset()`/`create` writes them (or opportunistically re-derive-and-`put` on successful login when `row.iterations() < ITERATIONS` — the password is in hand at exactly that moment, and `put` re-salts anyway).

### SEC-09: Composition-rule password policy, no breached-password screening

**Severity:** Low
**CWE:** CWE-521: Weak Password Requirements
**Location:** `src/portal/PasswordPolicy.java:6, 43-48`
**Vulnerable code:**
```java
// src/portal/PasswordPolicy.java:43-48
        if (!hasLetter || !hasDigit) {
            return "the password must contain at least one letter and one digit";
        }
        if (Integer.bitCount(classes) < 3) {
            return "the password must mix upper case, lower case, digits or other characters";
        }
```
**Why it is a problem:** The policy is the composition-rule style that NIST SP 800-63B (§5.1.1.2) now explicitly discourages: mandating character classes and a 10-character minimum pushes users toward the exact patterns offline cracking is tuned for (`Sup3r-Sentinel-77`-style — the self-test's own constant passes with room to spare) while permitting 10-character garbage like `aaaa1111AA`. There is no blocklist of breached/common passwords and no length incentive beyond 10, so the policy filters the trivially bad and misses the practically guessable — and because PBKDF2 work factor is the other half of the defence (SEC-08), weak-policy + moderate-KDF compounds for exactly the supervisor accounts that matter.
**Fix:** Follow 800-63B: drop the composition gates, reward length, and screen against a breached/common list:
```java
    public static final int MIN_CHARS = 14;

    // replaces the hasLetter/hasDigit and bitCount(classes) blocks:
        if (BREACHED.contains(value.toLowerCase(java.util.Locale.ROOT))) {
            return "that password is too common, choose a different one";
        }
        // BREACHED: a bundled set of the usual top-breached candidates, extended by
        // any corpus policy the deployment adopts; no composition rules are imposed.
```
Username containment (24–27) and the structural checks are worth keeping exactly as they are.

### SEC-10: Plaintext passwords materialized as immutable `String`s (piped input path)

**Severity:** Low
**CWE:** CWE-316: Cleartext Exposure of Sensitive Information in a Process's Address Space
**Location:** `src/portal/AdminPortal.java:493-498`, `src/portal/PasswordPolicy.java:20`
**Vulnerable code:**
```java
// src/portal/AdminPortal.java:493-498
    protected char[] askSecret(String prompt) {
        out.print(prompt);
        out.flush();
        try {
            String line = readLine();
            return line == null ? new char[0] : line.toCharArray();
```
**Why it is a problem:** On a terminal, `ConsolePortal.askSecret` uses `readPassword()` and the array is zeroized after use — good. On piped input, however, the secret passes through two immutable, non-zeroizable `String`s: `readLine()` builds one here (line 497), and `PasswordPolicy.check` materializes another via `new String(password)` (`PasswordPolicy.java:20`) for the policy scan. Both persist in the heap until garbage collection, reachable from a core dump, swap, or a debugger — while every *other* copy in the design (`PBEKeySpec.clearPassword()`, the `Arrays.fill(password, '\0')` in every `finally`) shows the authors were deliberately fighting exactly this exposure. The README candidly warns that "piped input is not private", so severity is Low, but the code can shrink the exposure even on that path, and policy checking shouldn't be the reason a second copy exists.
**Fix:** Read the piped line into a zeroizable buffer, and check policy without building a `String`:
```java
    protected char[] askSecret(String prompt) {
        out.print(prompt);
        out.flush();
        char[] buffer = new char[1025]; // MAX_CHARS + 1, to detect over-length
        try {
            int length = readLineInto(buffer); // char-by-char, like readLine() above, into buffer
            if (length < 0) {
                return new char[0];
            }
            return Arrays.copyOf(buffer, length);
        } catch (IOException readFailed) {
            return new char[0];
        } finally {
            Arrays.fill(buffer, '\0');
        }
    }
```
In `PasswordPolicy.check`, iterate `password`'s code points directly (the class-bit loop and the username-containment test both translate to a `StringBuilder` scan that the caller zeroizes), and compare against the breached list on that scratch builder instead of the immutable `value`.

### SEC-11: Audit sequence silently restarts on unreadable tail; no integrity chain

**Severity:** Low
**CWE:** CWE-353: Missing Support for Integrity Check
**Location:** `src/portal/AuditLog.java:83-105`
**Vulnerable code:**
```java
// src/portal/AuditLog.java:95-99
                try {
                    return Long.parseLong(line.substring(0, tab).trim());
                } catch (NumberFormatException notUs) {
                    return 0L;
                }
```
**Why it is a problem:** Each record's sequence is `lastSequenceOnDisk() + 1`, and every failure path in `lastSequenceOnDisk` — an unparseable last line (line 98), an I/O error (101–103), an empty tail (104) — returns `0L` instead of signalling trouble, so the next record restarts at `1` *appended to content whose real numbering was higher*. The `record()` contract then treats these as normal, distinct events: the sequence is the audit log's only anti-insertion property, and an editor who mangles or deletes the file's tail gets both a clean-looking numbering restart and no error anywhere — while an *honest* operator sees the same silent restart and learns nothing. Beyond that, the log is "append-only by convention" (the README's own words): with no per-record chaining or signing, nothing detects truncation, reordering, or line edits at all, and the world-readable-but-owner-only-writable default (SEC-04) is the only thing actually defending it.
**Fix:** Fail closed on an unreadable tail — an audit log that can't state its own sequence must not keep writing as though it could — and chain each record to the previous hash so edits and removals are detectable (the hash-chain design from the log-integrity literature applies directly):
```java
                try {
                    return Long.parseLong(line.substring(0, tab).trim());
                } catch (NumberFormatException notUs) {
                    throw new IOException("audit log tail is unreadable; refusing to append", notUs);
                }
```
(`lastSequenceOnDisk` and the constructor then propagate `IOException`, which is already how the portal handles an unusable log — SEC-11's restart window closes.) For chaining, extend the record format one field:
```java
        line.append('\t').append(clean(prevChain));            // SHA-256 of the previous line
        ...
        lastChain = sha256Hex((line + System.lineSeparator())
                .getBytes(StandardCharsets.UTF_8));
```
and provide a `verify-chain` command that recomputes it offline; anchoring the current chain hash into the credential-store save (or an external timestamping service) turns "the log was edited" into something detectable even against the write-privileged owner.

### SEC-12: Unknown stored role silently coerced to `operator`

**Severity:** Low
**CWE:** CWE-1188: Insecure Default Initialization of Resource (also CWE-639)
**Location:** `src/portal/LoginService.java:162`
**Vulnerable code:**
```java
// src/portal/LoginService.java:162
            String role = Roles.isKnown(row.role()) ? row.role() : Roles.OPERATOR;
```
**Why it is a problem:** This line runs only on the successful-password branch, so it cannot be steered by an unauthenticated attacker — and `CredentialStore.load()` already rejects rows with unknown roles (lines 120–122), so under the current invariants it should be unreachable. But that is exactly what makes it a hazard for the future: it is the *only* place an out-of-range role can land, and it resolves to a **granted** privilege (`operator`, which may run `create` and `reset`) instead of failing — a silent downgrade/fallback. If any future code path (the test-only `putRow` helper today, a migration, an import feature) inserts a row with a corrupt role while bypassing `load()`'s validation, the user authenticates successfully and gets a *different* role than stored, with an `AUTH_GRANTED` audit line reporting the substituted role as if it were the real one. Fail-closed is the correct instinct for credential metadata: the code already refuses grants when the *audit write* fails; an unrecognizable role deserves the same treatment.
**Fix:** Refuse the login rather than invent a role:
```java
            if (!Roles.isKnown(row.role())) {
                return refuse(started, Status.DENIED, name, null,
                        "this account cannot be used, ask a supervisor to reset its password",
                        "AUTH_DENIED", name, "unknown role in stored credential");
            }
            String role = row.role();
```
(The message is post-authentication, so it leaks nothing to unauthenticated users, and the audit event names the corruption explicitly.)

### SEC-13: Hardcoded passwords in the self-test harness

**Severity:** Low
**CWE:** CWE-798: Use of Hard-coded Credentials
**Location:** `src/portal/PortalChecks.java:37-38, 150-151`
**Vulnerable code:**
```java
// src/portal/PortalChecks.java:37-38
    private static final String CLI_PASS = "Sup3r-Sentinel-77";
    private static final String CLI_CAROL_PASS = "Turbine-Op3rate-55";
```
**Why it is a problem:** The self-test embeds fixed, policy-valid passwords (the pair above plus literals such as `Alice-Passw0rd-1`/`Bob-Passw0rd-22` at 150–151 and several more sites) and runs the portal as real subprocesses against them. They guard scratch homes only, the README discloses them, and no production credential is involved — hence Low — but they are the classic pattern that ages badly: a test suite copied into a service, a developer reusing the memorable `Sup3r-Sentinel-77` as a real supervisor password because "that's what the portal ships with", or a scanner/trufflehog run (the sensitive-data-exposure skill's Step 5) flagging the repo. Secrets in source also can't be rotated without a rebuild.
**Fix:** Generate the check passwords at runtime — they only need to satisfy `PasswordPolicy` and differ from the usernames:
```java
    private static final SecureRandom CHECK_RANDOM = new SecureRandom();

    private static String checkPassword() {
        byte[] raw = new byte[18];
        CHECK_RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw) + "-kQ9!";
    }

    private static final String CLI_PASS = checkPassword();
    private static final String CLI_CAROL_PASS = checkPassword();
```
(Tests that assert *specific* policy boundaries — "this exact string is rejected/accepted" — keep their literals inside those checks, where they are test data being examined, not credentials being used; everything that actually authenticates uses fresh randomness, and the 111 checks remain deterministic in their assertions.)

## 6. Verified Controls and Checks With No Finding

The following were explicitly tested and held; several are stronger than typical for a tool this size:

- **Credential check mechanics.** `Pbkdf2.matches` uses `MessageDigest.isEqual` (constant-time); the derived-key buffer is wiped after comparison; `PBEKeySpec.clearPassword()` runs in `finally` on every derivation; per-account 16-byte `SecureRandom` salts; `derive()` refuses empty passwords, wrong salt length, and out-of-range iteration counts.
- **Timing equalization.** Every branch reaching the store performs exactly one full PBKDF2 derivation, including the "no such account" and "locked" branches (`spendWork`/`shadowWorkSafely`, with the shadow salt derived from SHA-256 and never comparable to stored material); `PortalChecks` asserts the timings stay within factor and spread. (Message-channel leakage is separately reported as SEC-07.)
- **Anti dual-encoding.** `PasswordPolicy.structural` runs *before* any hashing in `verify` and rejects NULs and unpaired surrogates, closing the "two inputs, one stored key" class; `MAX_CHARS` bounds memory.
- **Fail-closed audit for grants.** An `AUTH_GRANTED` record that cannot be written is withdrawn (`RECORDING_FAILED` + `AUTH_GRANT_WITHDRAWN` event), and admin actions likewise require a successful `record()` before acting.
- **Log-injection resistance.** `AuditLog.clean()` caps every field at 96 characters and maps all non-printable bytes (including tab and newline) to `?`, so hostile usernames/details cannot forge or split records; log-injection was reviewed against the OWASP/CWE baseline with no skill gap found.
- **Path traversal.** `Names.ALLOWED` (`[a-z0-9._-]+`), length bounds, `..`/leading-dot rejection, and reserved names (`credentials`, `admin-portal`) are re-validated on every stored row, so no username can name a file outside the store's own directory.
- **Store load validation.** Row count, base64 decode, salt/key lengths, iteration range, and known-role checks; malformed rows are skipped *and counted* (`malformedRows()`) rather than trusted; non-regular store paths abort with an error.
- **Atomic persistence mechanics.** Whole-file save via `ATOMIC_MOVE` with `REPLACE_EXISTING`, temp cleanup on failure, `synchronized` mutators; readers never observe a half-written store (the permission weakness in that same path is SEC-01).
- **Zeroization discipline.** `char[]` password arrays are wiped in `finally` at every call site (`verify`, `readAcceptedPassword`, bootstrap/reset/create, the shadow-work probe clone), with the `String`-materialization gaps reported separately (SEC-10).
- **Session/lockout configuration guards.** `maxFailures >= 1` enforced at construction; session TTL enforced on every authorized command; the last administrator cannot be removed (`remove` guard at 299–302); role gates (`requireSession`, `mayManage`, audit readable by any known role) match the documented matrix.
- **No injection/execution surface.** No SQL, no shell strings, no deserialization, no XML, no eval/template/XSS surface, no listening sockets; `PortalChecks` spawns its CLI children through argument-list `ProcessBuilder` (636–652), never a shell, so the harness itself cannot be injected.
- **Build and test posture.** `run-checks.sh` compiles with `javac -Xlint:all -Werror` and runs `PortalChecks`; all 111 checks pass, including ten deliberate-defect assertions (tamper scenarios the suite proves it catches) and the timing-equalization tests.
- **Honest documentation.** The README states the single-process model, in-memory lockouts, "append-only by convention… not signed", and that piped input is not private — matching what the code actually does (each finding above either narrows or reinforces those disclosures rather than contradicting them).
