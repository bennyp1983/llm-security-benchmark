# Security Code Review — Administrator Portal (Java)

**Scope:** `src/com/example/adminportal/*.java` (7 files, 1233 LoC), `test/com/example/adminportal/PortalSelfTest.java`, `build.sh`, `README.md`.
**Method:** the `review-code-for-security-vulnerabilities` router skill — Step 1 comprehension of every file, Step 2 selection of specialised library skills by keyword, Step 3 application of each skill against the code, Step 4 this report.
**Date:** 2026-09-09

---

## 1. What the code does (Step 1)

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `AdminPortal.java` | CLI entry point: bootstrap, login loop (3 tries), role-gated menu, session expiry | Console password input, privilege gating, first-admin bootstrap, storage paths from system properties |
| `AuthenticationService.java` | Credential verification, decoy-hash timing equalisation, in-memory lockout, audits every attempt | Authentication, brute-force throttling, timing side channels, fail-closed on audit failure |
| `CredentialStore.java` | File-backed account records (`username:role:enabled:hash`), atomic replace, POSIX 0600 | Credential storage at rest, file permissions, input validation on usernames |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256, 210 000 iterations, 128-bit `SecureRandom` salt, 256-bit key, `MessageDigest.isEqual` | Password hashing/KDF parameters, constant-time compare, RNG |
| `PasswordPolicy.java` | Length ≥ 12, ≥ 3 character classes, deny list, username containment, repeat-run check | Password strength, secret handling in memory |
| `AuditLogger.java` | Tab-separated append-only trail, SHA-256 hash chain, escaping, integrity verification | Log integrity, log injection, file permissions, availability |
| `AdminUser.java` | Immutable account record; `Role → Set<Permission>` mapping | Authorisation model |
| `PortalSelfTest.java` | 24 behavioural assertions, temp-dir fixtures | Test-only hardcoded passwords (see §4) |
| `build.sh` | `javac` + run self test | No network fetch, no privileged operations |

Derived keywords: *password storage / KDF, authentication, brute force & lockout, access control / privilege escalation, audit-log integrity, log injection, cryptography, sensitive data in memory, file permissions / TOCTOU, secrets in source, resource exhaustion.*

**Not present in this codebase (checked and confirmed absent):** SQL or any database query construction, deserialization (`readObject`, XML, YAML), OS command execution (`Runtime.exec`, `ProcessBuilder`), network servers/clients or TLS configuration, HTML/template rendering (no XSS surface), JWT or any token format, reflection on user input, and hardcoded production secrets. Those OWASP categories therefore do not apply.

---

## 2. Findings

Severity reflects impact in the documented deployment model (a local CLI run under a dedicated service account that owns the credential and log files).

---

### F-01 — Audit hash chain is unkeyed and unanchored: a write-capable attacker can silently rewrite or truncate the trail
**Severity: High · CWE-354 (Improper Validation of Integrity Check Value), CWE-345 (Insufficient Verification of Data Authenticity)**

**Evidence:** `src/com/example/adminportal/AuditLogger.java:85`
```java
String digest = sha256(previous + "\n" + payload);
```
`src/com/example/adminportal/AuditLogger.java:126-152` (`verifyIntegrity`), `src/com/example/adminportal/AuditLogger.java:166-183` (`lastDigest`).

**Why it is a problem.** Every input to the chain digest — the previous digest and the full payload — is stored in the file itself, and `sha256()` uses no secret key. Anyone who can write the log (the service account itself, any process running as it, or root) can delete or edit the record of their own login, recompute the chain from that point forward with fifteen lines of script, and `verifyIntegrity()` will return `0` ("intact"). Truncation is worse still: `verifyIntegrity` iterates only the lines that are present and returns `0` at `AuditLogger.java:151`, so lopping off the last *N* records — the usual attacker goal — leaves a perfectly verifying chain. There is no record count, no end-of-chain anchor, and no external checkpoint. The README claim at *Security properties → Audit trail* ("cannot quietly remove the record of their own login") is therefore not achieved against the very actor the control exists to constrain; the hash chain only detects accidental corruption and naive edits.

**Fix.**
1. Replace `sha256(previous + "\n" + payload)` with `HMAC-SHA256` under a key the portal process cannot read back — ideally held by a separate log-collector identity, an HSM/KMS, or a TPM-sealed key. A key stored in the same 0600 file tree buys nothing.
2. Include a monotonically increasing sequence number in the signed payload and persist the highest sequence + last digest to a separate integrity-protected checkpoint, so truncation is detectable.
3. Ship records off-box as they are written (syslog/SIEM, append-only remote collector) or anchor periodic checkpoint digests externally. The README's *Deployment notes* recommends this for the "local root" case only — it is in fact required for any adversary with write access, which includes the portal's own service account.

---

### F-02 — Account lockout is per-process, so restarting the CLI resets brute-force protection
**Severity: High · CWE-307 (Improper Restriction of Excessive Authentication Attempts)**

**Evidence:** `src/com/example/adminportal/AuthenticationService.java:42`
```java
private final Map<String, AttemptState> attempts = new ConcurrentHashMap<>();
```
constructed fresh per portal instance at `src/com/example/adminportal/AdminPortal.java:42`, whose process runs exactly one login session (`AdminPortal.java:80-90`, `main` calls `System.exit(portal.run())` at `AdminPortal.java:57`).

**Why it is a problem.** The counter that implements "five failed attempts within 15 minutes locks the account for 15 minutes" lives only in heap memory of one JVM. This program is a short-lived command-line process that permits three password attempts (`MAX_LOGIN_ATTEMPTS = 3`, `AdminPortal.java:30`) and then exits. The lockout threshold of five is therefore never reachable in normal operation, and an attacker scripting `java -cp out com.example.adminportal.AdminPortal` in a loop gets unlimited attempt batches with the counter zeroed each time. The only remaining rate limit is PBKDF2 cost. The README lists this behaviour as *"Five failed attempts within 15 minutes lock the account… which makes online guessing impractical"* under **Security properties**, while the *Deployment notes* mention the in-process table only as a horizontal-scaling caveat; the single-instance case is already broken.

**Fix.** Persist attempt state — failure count, first-failure time, `lockedUntil` — alongside the account in `CredentialStore` (or in a shared cache/DB), updated under the same file lock as `save()`, and consult it in `authenticate()`. Additionally add a per-attempt delay that survives restart, and consider a global failure budget so distributed guessing across many usernames is also throttled.

---

### F-03 — Credential-store rewrite creates the file with default umask permissions before restricting them (TOCTOU window)
**Severity: Medium · CWE-732 (Incorrect Permission Assignment for Critical Resource), CWE-377 (Insecure Temporary File)**

**Evidence:** `src/com/example/adminportal/CredentialStore.java:128-133`
```java
Path temp = file.resolveSibling(file.getFileName() + ".tmp");
Files.writeString(temp, sb.toString(), StandardCharsets.UTF_8);   // line 129: created with 0666 & ~umask
trySetPermissions(temp);                                          // line 130: restricted only afterwards
Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
```
and `src/com/example/adminportal/CredentialStore.java:124-126`:
```java
if (parent != null && !Files.exists(parent)) {
    Files.createDirectories(parent);   // no permissions argument at all
}
```

**Why it is a problem.** `Files.writeString` creates `admins.db.tmp` with the process umask (commonly `0644`) and the full set of PBKDF2 hashes is written into it *before* `trySetPermissions` narrows it to `0600`. A local attacker polling the directory can read every password hash in that window and take it offline to hashcat. The temp file name is fully predictable (`admins.db.tmp`), which also makes it a symlink-plant target on any shared-parent deployment. Separately, when the credential path is configured to a directory that does not yet exist (the `-Dadminportal.credentials=/var/lib/adminportal/...` form documented in the README), line 125 creates that directory with default permissions — unlike `AuditLogger.prepareStorage`, which does set `rwx------` at `AuditLogger.java:189`.

**Fix.** Create the file with restrictive permissions atomically rather than fixing them after the fact:
```java
FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(OWNER_ONLY);
Path temp = Files.createTempFile(file.getParent(), ".admins", ".tmp", attr);
Files.writeString(temp, sb.toString(), StandardCharsets.UTF_8,
        StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
```
and pass `PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIR)` to `Files.createDirectories` at line 125. Also verify permissions on `load()` and refuse to start if the store is group- or world-readable.

---

### F-04 — Audit log is recreated with default permissions if it is removed at runtime
**Severity: Medium · CWE-732 (Incorrect Permission Assignment for Critical Resource)**

**Evidence:** `src/com/example/adminportal/AuditLogger.java:88-89`
```java
Files.writeString(logFile, line, StandardCharsets.UTF_8,
        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
```

**Why it is a problem.** `prepareStorage()` sets `rw-------` once, at construction (`AuditLogger.java:191-194`). Every subsequent `record()` uses `StandardOpenOption.CREATE` and never re-applies permissions. If the log is deleted or rotated away while the portal is running — trivially arranged by an attacker who wants exactly this — the next audit write recreates it with the umask default, exposing the full history of usernames, roles, source hosts, and lockout state to every local user. The same call path will happily follow a symlink planted at the log path, letting an unprivileged user cause the service account to append to a file it should not touch.

**Fix.** Hold a single `FileChannel` opened once with `CREATE_NEW`/`APPEND` and `PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE)`, plus `LinkOption.NOFOLLOW_LINKS`, for the lifetime of the logger, and write through that handle. Re-verify ownership and mode (and refuse to write) if the handle must be reopened.

---

### F-05 — Missing authentication on the bootstrap path: an empty or unreadable store grants an unauthenticated SUPER_ADMIN
**Severity: Medium · CWE-306 (Missing Authentication for Critical Function)**

**Evidence:** `src/com/example/adminportal/AdminPortal.java:72`
```java
if (store.isEmpty() && !bootstrapFirstAdministrator()) {
```
with `bootstrapFirstAdministrator` creating a `SUPER_ADMIN` with no prior authentication at `AdminPortal.java:305-330`, and `CredentialStore.load()` silently returning when the file is absent at `src/com/example/adminportal/CredentialStore.java:90-92`.

**Why it is a problem.** "No accounts exist" is treated as a trusted state rather than an anomalous one. Anyone who can unlink or rename the credential file — or who can influence the `adminportal.credentials` path (F-08) — puts the portal back into bootstrap and is handed the highest privilege level with no credential check. The event *is* audited (`AdminPortal.java:319`), but F-01 means that record is removable. The README's *"On first start, when no accounts exist, the portal asks you to create the initial SUPER_ADMIN"* documents the intended flow without noting that the precondition is attacker-influenceable.

**Fix.** Record a one-time "initialised" marker (a sentinel line in the store plus a checkpoint outside it) and refuse to bootstrap when the marker exists but no accounts are readable — fail closed with an operator error instead. Alternatively require bootstrap to be an explicit, separately authorised subcommand (`--bootstrap`) rather than an implicit fallback of the normal login path.

---

### F-06 — `ADMIN` role can disable or re-enable `SUPER_ADMIN` accounts
**Severity: Medium · CWE-269 (Improper Privilege Management), CWE-284 (Improper Access Control)**

**Evidence:** `src/com/example/adminportal/AdminPortal.java:222-241` (`toggleAccount`), gated only by `MANAGE_ACCOUNTS` at `AdminPortal.java:145-146`, which `ADMIN` holds per `src/com/example/adminportal/AdminUser.java:180`.

**Why it is a problem.** `createAccount` correctly refuses to let a non-`SUPER_ADMIN` mint a `SUPER_ADMIN` (`AdminPortal.java:199-204`), but `toggleAccount` applies no such check on the *target's* role. An `ADMIN` can therefore disable every `SUPER_ADMIN` — locking the organisation out of audit-log access and of the only role that can create more super-admins, a durable denial of service against oversight — or re-enable a `SUPER_ADMIN` account that was deliberately disabled during an offboarding or incident. The only guard present is the self-disable check at `AdminPortal.java:228`, which protects the actor, not the hierarchy. `CredentialStore.setEnabled` (`CredentialStore.java:65-74`) performs no authorisation of its own.

**Fix.** In `toggleAccount`, resolve the target account first and require `actor.role() == SUPER_ADMIN` whenever the target's role is `SUPER_ADMIN`; audit the refusal with `ACCESS_DENIED` exactly as `createAccount` does. More generally, express the rule as "an actor may only act on accounts whose privilege set is a subset of its own" so it survives the addition of new roles.

---

### F-07 — Password is copied into an immutable `String`, defeating the `char[]` zeroing design
**Severity: Low · CWE-316 (Cleartext Storage of Sensitive Information in Memory)**

**Evidence:** `src/com/example/adminportal/PasswordPolicy.java:60`
```java
String lowered = new String(password).toLowerCase(Locale.ROOT);
```
Secondary instance: `src/com/example/adminportal/AdminPortal.java:379-380` (`Prompter.readPassword` fallback reads the password as a `String` via `reader.readLine()` before converting with `toCharArray()`).

**Why it is a problem.** The codebase goes to real trouble to keep passwords in `char[]` and wipe them (`AdminPortal.java:113`, `:218`, `:288`, `:328`; `PasswordHasher.java:93`), and the README advertises this. Line 60 undoes it for every password ever set: `new String(password)` and the `toLowerCase` result are immutable, unreachable for zeroing, and linger on the heap until GC — recoverable from a core dump, a heap dump, or swap. The non-TTY branch of `Prompter` leaks the password the same way for every login on that path.

**Fix.** Perform the deny-list and username-containment comparisons over the `char[]` directly (lower-case into a scratch `char[]`, compare with `Arrays.equals`/a `char[]`-keyed structure, then `Arrays.fill` the scratch buffer). For the console fallback, read raw bytes into a mutable buffer rather than `BufferedReader.readLine()`, or refuse to accept passwords when no terminal is available.

---

### F-08 — Storage paths taken from unauthenticated system properties
**Severity: Low · CWE-15 (External Control of System or Configuration Setting)**

**Evidence:** `src/com/example/adminportal/AdminPortal.java:48-51`
```java
Path credentials = Paths.get(System.getProperty("adminportal.credentials", ...));
Path logFile = Paths.get(System.getProperty("adminportal.auditlog", ...));
```

**Why it is a problem.** Whoever launches the JVM chooses both the account database and the audit destination. `-Dadminportal.credentials=/tmp/mine.db` yields a fresh store, hence the unauthenticated bootstrap of F-05; `-Dadminportal.auditlog=/dev/null` disposes of the trail while `record()` still succeeds, so the fail-closed guarantee at `AuthenticationService.java:131-134` never fires. Neither path is validated, canonicalised, or checked against a permitted root, and neither is checked for symlinks. Impact is bounded because in the documented model only the service account runs the portal — this is a hardening gap, not a break, in that model — but any deployment that lets a lower-privileged user invoke the binary (a wrapper script, a sudo rule, a shared jump host) turns it into full authentication bypass.

**Fix.** Resolve both paths against a compiled-in or root-owned-config base directory, reject paths outside it after `toRealPath()`, refuse non-regular files and symlinks for the log, and verify at startup that both files are owned by the running user with mode `0600`.

---

### F-09 — PBKDF2 iteration count is below the current OWASP guidance for HMAC-SHA256
**Severity: Low · CWE-916 (Use of Password Hash With Insufficient Computational Effort)**

**Evidence:** `src/com/example/adminportal/PasswordHasher.java:23`
```java
private static final int DEFAULT_ITERATIONS = 210_000;
```

**Why it is a problem.** 210 000 is the OWASP Password Storage Cheat Sheet figure for PBKDF2-**HMAC-SHA512**; the recommendation for PBKDF2-**HMAC-SHA256**, which is what `ALGORITHM` at `PasswordHasher.java:21` selects, is 600 000. The gap is roughly a 3× discount on an attacker's offline cracking cost should the store leak (F-03 makes a leak plausible). The rest of the construction is sound — 128-bit `SecureRandom` salt, 256-bit output, per-record iteration count enabling rehash-on-upgrade, constant-time `MessageDigest.isEqual`.

**Fix.** Raise `DEFAULT_ITERATIONS` to 600 000 for SHA-256, and preferably migrate to a memory-hard KDF (Argon2id, or scrypt via a vetted library) since PBKDF2 offers no defence against GPU/ASIC parallelism. Because `verify()` reads the iteration count from the stored record (`PasswordHasher.java:67`), existing hashes keep working; add an opportunistic rehash on successful login when `iterations < DEFAULT_ITERATIONS`.

---

### F-10 — Username-keyed lockout permits targeted denial of service against administrators
**Severity: Low · CWE-645 (Overly Restrictive Account Lockout Mechanism)**

**Evidence:** `src/com/example/adminportal/AuthenticationService.java:81` keys `AttemptState` on the submitted username; `AuthenticationService.java:100`, `:108`, `:114` call `registerFailure` for *every* failure class, including "no such account" and "account disabled".

**Why it is a problem.** Within a single process (or in any future long-lived deployment), five wrong passwords against a known administrator username lock that account for 15 minutes regardless of where the attempts came from, with no cost to the attacker. Sustained, this locks out every administrator indefinitely. This finding is in tension with F-02 — today the lockout is too weak to be reached from the CLI, but the moment F-02 is fixed by persisting the state, this becomes exploitable, so the two must be fixed together.

**Fix.** When persisting lockout state, key it on the (username, source) pair, apply exponential backoff rather than a hard lock, exempt the origin that most recently authenticated successfully, and expose an operator unlock path. Rate-limit by source independently of any username so that account enumeration by lockout side effect is not free.

---

### F-11 — Unbounded attempt map and unbounded audit log with linear-scan appends
**Severity: Low · CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption)**

**Evidence:** `src/com/example/adminportal/AuthenticationService.java:81` (`attempts.computeIfAbsent` — entries are created for arbitrary submitted usernames and never evicted, even after `state.reset()`), and `src/com/example/adminportal/AuditLogger.java:78` → `:171` (`lastDigest()` calls `Files.readAllLines` on the whole log for *every single* appended record).

**Why it is a problem.** `attempts` grows without bound under an enumeration attack against a long-running instance — one map entry per distinct string ever submitted — until the JVM heap is exhausted. Independently, appending record *n* reads *n−1* records into memory first, making the audit trail O(n²) in time and O(n) in peak memory per write; with no rotation or size cap, a log that reaches a few hundred megabytes makes every authentication attempt slow enough to constitute a self-inflicted denial of service, and `read()` (`AuditLogger.java:105`) loads the entire trail into a `List` as well.

**Fix.** Bound `attempts` with a size-capped, time-expiring cache (evict entries whose `firstFailure` is older than `ATTEMPT_WINDOW` and that hold no active lock). Cache `lastDigest` in a field maintained under `lock` instead of re-reading the file, seeding it once at construction. Add size-based rotation that carries the chain digest across files, and stream `read()`/`verifyIntegrity()` line by line via `Files.lines`.

---

### F-12 — Locked-out accounts are distinguishable by response time
**Severity: Informational · CWE-208 (Observable Timing Discrepancy)**

**Evidence:** `src/com/example/adminportal/AuthenticationService.java:84-89` returns before the KDF runs, whereas every other path executes `PasswordHasher.verify` at `AuthenticationService.java:97`. Related: the decoy hash is built with `DEFAULT_ITERATIONS` (`AuthenticationService.java:48` → `PasswordHasher.java:38`), so once F-09's iteration upgrade lands, accounts still holding legacy hashes will verify at a measurably different cost than the decoy.

**Why it is a problem.** The decoy-hash design (`AuthenticationService.java:96`) is a genuinely good control that equalises the exists/does-not-exist paths, and the empty-input guard at `AuthenticationService.java:75` is not an enumeration oracle since it precedes any lookup. The lockout early return, however, answers in microseconds instead of the ~200 ms a PBKDF2 pass takes, so an attacker can learn which usernames are real *and currently locked* — useful confirmation that a guessing campaign is hitting a live account.

**Fix.** Run the decoy derivation before returning from the lockout branch, or normalise every authentication response to a fixed minimum wall-clock duration. Derive the decoy at the same iteration count as the weakest stored hash, or pad accordingly.

---

### F-13 — Corrupted or hostile audit records raise unchecked exceptions during review
**Severity: Informational · CWE-248 (Uncaught Exception), CWE-390 (Detection of Error Condition Without Action)**

**Evidence:** `src/com/example/adminportal/AuditLogger.java:265`
```java
sb.append((char) Integer.parseInt(value.substring(i + 1, i + 5), 16));
```
called from `unescape` in `read()` (`AuditLogger.java:113-114`); plus `AuditLogger.java:110-112`, where a single malformed line makes the entire trail unreadable.

**Why it is a problem.** A `\u` escape with non-hex digits — reachable only by direct file tampering, since `escape()` at `AuditLogger.java:222-244` correctly doubles backslashes and encodes control characters — throws `NumberFormatException`, an unchecked exception that propagates out of `showAuditTrail` past the `catch (IOException)` in `guarded` (`AdminPortal.java:166`) and terminates the session. Likewise one bad line anywhere aborts `read()` for the whole file. An attacker who cannot forge the chain can still make the trail un-reviewable, which is most of the practical benefit of deleting it. The escaping itself is correct: log injection / record forgery via a hostile username (CWE-117) was specifically checked and is **not** exploitable.

**Fix.** Catch `NumberFormatException` in `unescape` and fall through to a literal rendering; in `read()`, emit a placeholder `Entry` marking the record as unparseable and continue, so operators see both the damage and the surrounding records. Keep `verifyIntegrity()` reporting the first broken index as it does today.

---

### F-14 — Test fixtures carry realistic-looking credentials
**Severity: Informational · CWE-798 (Use of Hard-Coded Credentials)**

**Evidence:** `test/com/example/adminportal/PortalSelfTest.java:25-27`
```java
store.addUser("root.admin", "Correct-Horse-9!".toCharArray(), AdminUser.Role.SUPER_ADMIN);
```
**Why it is a problem.** These are test-only values written to a `Files.createTempDirectory` fixture (`PortalSelfTest.java:17`) and never reach production, so there is no live exposure. They are flagged only because they will trip secret scanners and because strings shaped like real admin passwords have a habit of being copied into deployment scripts. No hardcoded secret exists anywhere in `src/`.

**Fix.** Generate fixture passwords at test time, or prefix them unmistakably (`test-only-…`), and add a scanner allowlist entry for the test tree.

---

## 3. Controls verified as sound

These were examined and found correct — worth stating so a future reader does not "fix" them:

- **No plaintext or reversible credential storage.** Only `pbkdf2-sha256$…` records are written (`CredentialStore.java:112-121`), asserted by the self test at `PortalSelfTest.java:47-51`.
- **Constant-time hash comparison** via `MessageDigest.isEqual` (`PasswordHasher.java:79`) and for the chain digest (`AuditLogger.java:145`).
- **Per-password salt from `SecureRandom`**, 128-bit, generated fresh per hash (`PasswordHasher.java:27`, `:36-37`) — no static salt, no `Random`, no `Math.random`.
- **Uniform failure messaging.** Every denial returns `GENERIC_FAILURE` (`AuthenticationService.java:28`, returned at `:78`, `:88`, `:103`, `:111`, `:123`); the specific cause reaches only the audit trail.
- **Username-existence timing equalisation** via a decoy hash (`AuthenticationService.java:38`, `:96-97`).
- **Fail-closed on audit failure.** `AuditFailureException` denies access rather than granting it unrecorded (`AuditLogger.java:90-94`, `AuthenticationService.java:131-134`).
- **Log injection is prevented.** `escape()` handles backslash, tab, CR, LF and all C0/DEL characters (`AuditLogger.java:222-244`), so a hostile username cannot forge fields or extra records (CWE-117 checked, not exploitable).
- **Passwords never reach the logger.** No `record(...)` call site passes password material; `detail` strings are counts, roles and timestamps only.
- **Username input validation.** `[a-z0-9._-]{3,64}` (`CredentialStore.java:52`) excludes the `:` field separator, preventing credential-record forgery; `Locale.ROOT` is used for every case fold (`CredentialStore.java:145`, `AuthenticationService.java:72`), avoiding the Turkish-İ collision that has caused real authentication bypasses.
- **Authorisation is re-checked per action**, not only at login (`AdminPortal.java:141-148` → `AuthenticationService.authorize`), and denials are audited.
- **Password policy** enforces length ≥ 12 (weighted above composition), a maximum length of 256 that caps KDF work (`PasswordPolicy.java:20-21`), username containment, and repeat runs — the deny list is small (14 entries) but extensible via `/weak-passwords.txt`, which is the right shape.
- **No injection sinks.** No SQL, LDAP, XPath, command execution, deserialization, template rendering, or reflection anywhere in `src/`; `AuditLogger.read()` parses a fixed 6-field tab format with `split("\t", -1)` and validates the outcome enum (`AuditLogger.java:205-211`).
- **`build.sh`** compiles from local sources only, with no network fetch, no `curl | sh`, and no privileged operations.

---

## 4. Summary

| ID | Severity | CWE | Location |
| --- | --- | --- | --- |
| F-01 | High | CWE-354, CWE-345 | `AuditLogger.java:85`, `:126-152` |
| F-02 | High | CWE-307 | `AuthenticationService.java:42`, `AdminPortal.java:42` |
| F-03 | Medium | CWE-732, CWE-377 | `CredentialStore.java:125`, `:129-130` |
| F-04 | Medium | CWE-732 | `AuditLogger.java:88-89` |
| F-05 | Medium | CWE-306 | `AdminPortal.java:72`, `:305-330` |
| F-06 | Medium | CWE-269, CWE-284 | `AdminPortal.java:222-241` |
| F-07 | Low | CWE-316 | `PasswordPolicy.java:60`, `AdminPortal.java:379-380` |
| F-08 | Low | CWE-15 | `AdminPortal.java:48-51` |
| F-09 | Low | CWE-916 | `PasswordHasher.java:23` |
| F-10 | Low | CWE-645 | `AuthenticationService.java:81`, `:100-114` |
| F-11 | Low | CWE-770, CWE-400 | `AuthenticationService.java:81`, `AuditLogger.java:171` |
| F-12 | Informational | CWE-208 | `AuthenticationService.java:84-89` |
| F-13 | Informational | CWE-248, CWE-390 | `AuditLogger.java:265`, `:110-112` |
| F-14 | Informational | CWE-798 | `PortalSelfTest.java:25-27` |

**Overall.** This is a well-constructed piece of security code: the hashing, the constant-time comparisons, the generic failure messages, the decoy-hash timing defence, the fail-closed audit coupling, and the log escaping are all done properly and would pass most reviews. The two High findings are cases where a control is *documented* as providing a guarantee it does not actually deliver — the audit chain against a write-capable adversary (F-01) and the lockout against a process that exits after every login (F-02). Fix those two first; F-03 through F-06 next, as each converts a local-user or lower-privileged-admin position into credential or oversight compromise.

**Suggested order of work:** F-02 together with F-10 (they share the persistence change) → F-01 → F-03 and F-04 → F-05 and F-08 (they share the path-validation change) → F-06 → the remainder.

---

## 5. Skills applied

Selected from the library by grepping skill names for the Step 1 keywords, then reading the matched `description` frontmatter, then reading each body at the point of use:

1. **`performing-cryptographic-audit-of-application`** — KDF parameter review, RNG/entropy, hardcoded secrets, weak-algorithm and key-management checks → F-01, F-09, F-14, and the §3 crypto verifications.
2. **`implementing-log-integrity-with-blockchain`** — SHA-256 hash-chain construction, chain verification, and the checkpoint-anchoring requirement → F-01, F-11, F-13.
3. **`testing-api-authentication-weaknesses`** — password policy strength, credential-stuffing/brute-force resistance, session expiration and revocation, credential leakage into logs → F-02, F-07, F-09, F-10.
4. **`testing-for-broken-access-control`** — vertical privilege escalation and function-level authorisation checks → F-05, F-06.
5. **`testing-for-sensitive-data-exposure`** — insecure storage of secrets at rest and in memory → F-03, F-04, F-07.
6. **`exploiting-race-condition-vulnerabilities`** — TOCTOU analysis, including attempt-limiting races → F-03, F-04.
7. **`performing-hash-cracking-with-hashcat`** — offline cracking economics of the stored PBKDF2 records → severity rationale for F-03 and F-09.
8. **`testing-for-business-logic-vulnerabilities`** — multi-step workflow bypass → F-05 (bootstrap-by-deletion), F-06.

**Behaviours reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:** POSIX file-permission and umask handling in Java NIO (`Files.writeString`/`createFile`/`createDirectories`) — reviewed against CWE-732/CWE-377 (F-03, F-04); JVM system-property configuration as a trust boundary — reviewed against CWE-15 (F-08); Java in-memory secret lifetime and `String` interning — reviewed against CWE-316 (F-07); unchecked-exception handling in the CLI control flow — reviewed against CWE-248/CWE-390 (F-13); and unbounded collection/file growth — reviewed against CWE-770/CWE-400 (F-11).
