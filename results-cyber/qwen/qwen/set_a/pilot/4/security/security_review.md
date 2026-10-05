# Security Review — `secureaccount` (Java 17+, single-operator password-store CLI)

**Date:** 2026-09-09
**Scope:** all code in this folder — `src/main/java/secureaccount/` (5 files) and `src/test/java/secureaccount/Tests.java`.
**Method:** followed the `review-code-for-security-vulnerabilities` router workflow: (1) read and understand every source file, (2) select every clearly-matching specialised skill from the library by name/description, (3) apply each selected skill body one at a time, citing `file:line` for every check that fires, (4) report findings below with severity, CWE id, `file:line`, why it is a problem, and the fix.

The application is a local, single-operator CLI that registers user accounts, stores PBKDF2-HMAC-SHA256 password verifiers in a file (owner-only permissions), and authenticates. It deliberately has no network surface, no object deserialization, and no tokens/OAuth/JWT.

---

## Summary

| # | Severity | CWE | Location | Issue |
|---|----------|-----|----------|-------|
| F1 | Medium | CWE-307 | `AccountService.java:85`, `Main.java:164` | No rate limiting / lockout / backoff on login |
| F2 | Low–Medium | CWE-204 / CWE-540 | `Main.java:127–130`, `Main.java:191` | Account-existence leakage via register pre-flight and `list` |
| F3 | Low | CWE-521 | `AccountService.java:55–60` | No minimum password length at registration |
| F4 | Low | CWE-208 | `AccountService.java:100–102` | Empty-password failure path skips the timing-equaliser derivation |
| F5 | Low | CWE-732 | `AccountStore.java:141` | Lock sidecar file not restricted to owner-only permissions |
| F6 | Low | CWE-20 | `Main.java:255–256` | Piped password keeps trailing `\r` from CRLF input (silent credential corruption) |
| F7 | Informational | CWE-733 (adjacent) | `AccountStore.java:153` | Temp-file sweep deletes any `<store-name>*.tmp` in the parent directory |
| F8 | Informational | CWE-798 | `Tests.java:591` (and scattered) | Plaintext test secrets in test sources (conventionally allowlisted) |
| F9 | Informational | — | `Tests.java:706` | Test fixtures written under world-writable `/tmp` with default directory permissions |

No critical or high-severity issues. The cryptographic and storage core is sound (see *Verified secure*).

---

## Findings

### F1 — No rate limiting / lockout / backoff on the login path

- **Severity:** Medium
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location:** `AccountService.java:85` (`authenticate`), `Main.java:164` (`login`)
- **Why it is a problem:** A remote- or local attacker who can invoke `login` (or the `authenticate` API) can mount unlimited online brute-force and credential-stuffing attempts. Each attempt costs one PBKDF2-SHA256 derivation (~310 000 iterations, ≈ hundreds of ms at the default), which *slows* brute force but does not *bound* it: there is no per-username failure tracking, no lockout, no increasing delay, and no audit trail of failures. The timing-equalisation design (good) makes *enumeration* hard, but the absence of throttling leaves *offline-unlimited online guessing* wide open. This is the single largest residual risk in an otherwise tight design.
- **Fix:** add a minimal backoff/lockout: e.g. track failed attempts per canonical username (in-memory or a small persisted file) and impose an exponential delay (or temporary lockout with a bounded duration) before accepting further attempts for that username; optionally log failures to a separate owner-only audit file. Because the design goal is uniform timing, apply the delay *symmetrically* (or always perform the derivation first) so the lockout itself does not become a new enumeration oracle.

### F2 — Account-existence leakage via register pre-flight and `list`

- **Severity:** Low–Medium
- **CWE:** CWE-204 (Observable Response Discrepancy) / CWE-540 (Incompatible Encryption Technologies in Negotiation) — account enumeration.
- **Location:** `Main.java:127–130` (register pre-flight `service.exists(username)` → distinct message + `EXIT_FAILED`), `AccountService.java:142` (`exists`, whose own javadoc notes it exists "for the CLI's own pre-flight"), `Main.java:191` (`list` prints every username + creation time).
- **Why it is a problem:** The login path is carefully built so that unknown-user, wrong-password, and malformed-name failures are indistinguishable in *message and timing*. That protection is undermined by the `register` command: before any password is read, `Main.java:127` calls `exists()` and, if true, prints a distinct message (`username '...' is already registered`, `Main.java:128–130`) and exits. An observer of the CLI (a co-tenant on a shared host, a screen-share, a wrapper script capturing stdout) learns *which usernames are registered* without any credential. The `list` command additionally prints all usernames and creation timestamps on demand (intended functionality, but it widens the exposure surface).
- **Fix:** drop the pre-flight in `register` and let the locked `register` path (which already re-checks under the lock and throws `UsernameAlreadyTakenException`) be the sole source of the "already registered" answer, ideally with a message that does not distinguish "exists" from other registration failures. Consider removing or restricting `list` (e.g. to an explicit `--reveal-usernames` flag) so usernames are not printed by a casual invocation.

### F3 — No minimum password length at registration

- **Severity:** Low
- **CWE:** CWE-521 (Weak Password Requirements)
- **Location:** `AccountService.java:55–56` (rejects only the empty password), `AccountService.java:58–60` (enforces only the 1024-character maximum).
- **Why it is a problem:** Registration accepts any non-empty password, including a single character (`"a"`). The cost bound (`MAX_PASSWORD_CHARS`) is a DoS guard, not a strength policy. With PBKDF2 a 1-char password is trivially brute-forced offline if the store file is ever read, and even online it is guessable instantly. The authentication skill's password-policy checklist directly fired this.
- **Fix:** enforce a minimum length (e.g. `>= 8`, OWASP-recommended floor) in `register`, mirroring the existing max-length check, and reject weak passwords early with a clear message.

### F4 — Empty-password failure path skips the timing-equaliser derivation

- **Severity:** Low
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Location:** `AccountService.java:100–102`
- **Why it is a problem:** The design explicitly makes *all* login failures cost a full PBKDF2 derivation so that timing cannot distinguish outcomes: malformed-name failures burn time at `AccountService.java:90`, unknown-user failures at `AccountService.java:97`. But the empty-password branch (`password == null || password.length == 0`) at `AccountService.java:100–102` throws immediately **without** a derivation. For a *known* username, an empty attempt therefore returns measurably faster than a wrong-password or unknown-user attempt, breaking the uniform-cost invariant on exactly the one path the tests do not cover (`failureMessageIsUniform` checks messages only; `unknownUserCostsADerivation` times known-vs-unknown users, not the empty-password branch). An attacker who knows a username can use this as a low-cost probe.
- **Fix:** in that branch, call `hasher.burnTime(dummySecret())` before throwing, matching the other failure paths. Add a test that times an empty-password attempt against a known user and asserts the ratio to a wrong-password attempt is within a tight band.

### F5 — Lock sidecar file not restricted to owner-only permissions

- **Severity:** Low
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Location:** `AccountStore.java:141` (`FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE)`)
- **Why it is a problem:** The store file itself and its temp file are both locked down to owner read/write (`AccountStore.java:126`, `AccountStore.java:109`). But the lock sidecar is created with only `CREATE`/`WRITE` and **no** `restrictToOwner(...)`, so it inherits the process umask — typically `0644`. It holds no secret (it is an empty advisory-lock file), but the inconsistency is a real posture gap: on a shared host the lock file is world-readable, its name is world-visible, and its existence/timestamps can be watched. It also means the "everything the store touches is owner-only" invariant is not actually true.
- **Fix:** apply `restrictToOwner(lockFile)` immediately after creating the lock file (or set the umask / `Files.setPosixFilePermissions` before `FileChannel.open`), so the sidecar matches the store file's `0600`.

### F6 — Piped password retains a trailing `\r` from CRLF input (silent credential corruption)

- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `Main.java:255–256` (`String line = pipeReader.readLine(); return line == null ? null : line.toCharArray();`)
- **Why it is a problem:** The console path reads via `console.readPassword` (`Main.java:245`), but the non-interactive/pipe path uses a `BufferedReader.readLine()`. `readLine()` strips `\n` but **not** a trailing `\r`. The store layer is CRLF-tolerant (`AccountStore.stripCr`, `AccountStore.java:221`), but the CLI password path is not. Consequence: a password supplied from a CRLF-terminated file (e.g. `printf 'pw\r\n' | ...`) is silently stored/checked *with* the `\r` as part of the secret. Registration from a CRLF file and login from an LF file (or vice-versa) then produce a mismatch that is indistinguishable from a "wrong password" — a confusing, hard-to-diagnose failure and a subtle integrity hazard.
- **Fix:** in the pipe path, strip a single trailing `\r` before returning (mirror `AccountStore.stripCr`): `if (line != null && line.endsWith("\r")) line = line.substring(0, line.length() - 1);`.

### F7 — Temp-file sweep is over-broad (informational)

- **Severity:** Informational
- **CWE:** CWE-733 (Adjacent resource, over-broad file operation)
- **Location:** `AccountStore.java:153` (`sweepTempFiles`)
- **Why it is a problem:** `sweepTempFiles` deletes every file in the store's parent directory matching `<store-name>*.tmp`. The intent is to clean up the store's own stale temp files after a crash, but the pattern is a prefix match against *the directory*, not a scoped namespace. Any *other* process that happens to create a `<store-name>Something.tmp` in the same parent directory would have that file deleted. In the intended single-operator local use the risk is low (the parent directory is typically operator-controlled), but the operation is broader than necessary.
- **Fix:** scope the sweep to files the store actually created, e.g. by having `createTempFile` record its exact name (it already returns a `Path`) and only deleting known/pending names, or by using a dedicated subdirectory for temp files that the store owns.

### F8 — Plaintext test secrets in test sources (informational)

- **Severity:** Informational
- **CWE:** CWE-798 (Use of Reversible One-Way Hash with Insufficient Computational Effort) — misclassified here for *hardcoded credentials*; the accurate tag is CWE-798/CWE-312 (use of hardcoded test credentials).
- **Location:** `Tests.java:591` (`private static final char[] SECRET = "hunter2!".toCharArray();`) and scattered literals (`Tests.java:110–112, 123, 129, 157, 238, 310, 348, 377, 536`). Also note `AccountService.java:164` (`dummySecret()`) — this is a documented, intentional low-entropy timing decoy, **not** a real secret, and would be allowlisted.
- **Why it is a problem (why it is only informational):** The test suite embeds plaintext passwords (`hunter2!`, `Tr0ub4dor&3`, etc.). These are fixtures for an isolated in-process test store under a temp directory; they protect no real system. Applying the gitleaks skill's conventions: files under `src/test/` match the standard allowlist path `(^|/)test(s)?/`, and gitleaks-style scanners allowlist test paths by default. No *production* secret, API key, token, or private key exists anywhere in the repository (verified by an entropy/keyword sweep across all sources). The only residual concern is hygiene: if these fixtures were ever reused as real passwords, they would be weak.
- **Fix (optional):** no action strictly required. For hygiene, you could centralise test secrets in one obviously-fixture constant (partially done via `SECRET`) and avoid reusing any of them as a real credential. The `dummySecret()` decoy is correctly designed and needs no change.

### F9 — Test fixtures under world-writable `/tmp` (informational)

- **Severity:** Informational
- **Location:** `Tests.java:706` (`Path dir = Path.of("/tmp/secureaccount-tests", name + "-" + System.nanoTime());`)
- **Why it is a problem (why it is only informational):** Test data directories are created under the shared, world-writable `/tmp`. Each test directory name is namespaced with `System.nanoTime()` and the *store file itself* is still locked to `0600` (`AccountStore.java:126`), so a co-tenant cannot read the contents; the exposure is limited to directory-level metadata (existence, names). This is a test-environment concern, not a production one.
- **Fix (optional):** use `Files.createTempDirectory("secureaccount-tests")` (which honours `$TMPDIR` and applies safer defaults) instead of hand-rolling a path under `/tmp`.

---

## Items explicitly examined and **not** findings

- **Printing the verifier on register** (`Main.java:150`): deliberate and correct. A PBKDF2 verifier is *not* reversible to the password; the test `cliNeverEchoesPassword` asserts the password itself never reaches stdout/stderr while the verifier is intentionally shown. Not a leak.
- **`list` printing usernames:** intended functionality; the relevant concern (enumeration exposure) is captured under F2, not double-counted here.
- **Register TOCTOU:** `register` performs the `exists` check and then the mutation, but the mutation is done under the exclusive store lock and re-validates (`UsernameAlreadyTakenException`), so a concurrent registration cannot corrupt the store. Safe.
- **Atomic store writes:** `createTempFile` + `channel.force(true)` (fsync) + `Files.move(REPLACE_EXISTING)` (`AccountStore.java:109, 120, 125`) is a correct atomic-replace pattern; a crash cannot leave a partially-written store. Safe.
- **Password material handling:** passwords are never placed on the command line (the CLI reads them from the console/pipe), are held in `char[]`, and are erased with `Arrays.fill` on all paths. Good.

---

## Verified secure (crypto audit)

Applying `performing-cryptographic-audit-of-application`, the cryptographic core is sound across every weakness category:

- **KDF / hash strength:** PBKDF2-HMAC-SHA256 at 310 000 iterations (`PasswordHasher.DEFAULT_ITERATIONS`) — meets/exceeds the OWASP minimum for PBKDF2-SHA256. No MD5, SHA-1, DES, 3DES, RC4, or ECB anywhere.
- **Salt / key length:** 16-byte random salt per account, 32-byte derived key — both adequate.
- **Randomness:** `SecureRandom` (not `Math.random`/`Random`) for salts.
- **Constant-time comparison:** verifier equality uses a constant-time compare (no early-exit `==`), preventing a timing side-channel in hash comparison.
- **Secret erasure:** `PBEKeySpec`/password arrays are zeroed after use.
- **No hardcoded production keys:** none found (see F8 — test fixtures only).
- **Algorithm negotiation / downgrade:** the stored record format is self-describing and versioned; the code pins the KDF and does not silently fall back to a weaker algorithm.
- **Password length DoS:** bounded by `MAX_PASSWORD_CHARS` (1024) to prevent a memory/CPU DoS via an oversized password.

Storage integrity (from the broken-access-control and general review): strict whole-file parsing that rejects unknown/corrupt lines, `NOFOLLOW_LINKS` on read (`AccountStore.java:69, 72`), owner-only `0600` permissions on the store and temp file, and an advisory cross-process `FileLock`. All consistent with a defensively written store.

---

## Skills applied

1. **`performing-cryptographic-audit-of-application`** — full weakness-category sweep (weak hash/KDF parameters, hardcoded secrets, entropy, insecure modes, key sizes, deprecated protocols). Fired the *verified-secure* conclusions and informed F3 (password policy).
2. **`testing-api-authentication-weaknesses`** — transferable portions: weak-password policy checklist (→ F3), account enumeration via response differences (login is uniform, but the `exists` pre-flight and `list` leak → F2), brute-force resistance (→ F1), empty-input handling (→ F4). JWT/OAuth/Burp-specific portions do not apply to a local CLI with no tokens.
3. **`implementing-secret-scanning-with-gitleaks`** — secret-scan knowledge (entropy thresholds, test-path allowlist convention `(^|/)test(s)?/`, keyword patterns). Result: no production secrets; test fixtures are conventionally allowlisted (→ F8). No scanner is configured in this repo, which is an informational gap rather than a code vulnerability.
4. **`testing-for-broken-access-control`** — web/Burp-centric; only partially transferable. Applied its function-level-access and permission-matrix concepts: the store file is `0600` but the lock sidecar is not (→ F5), and the CLI command surface was checked for missing/unauthenticated function-level checks (→ F2). IDOR/multi-tenant/vertical-privilege-escalation portions do not apply to a single-operator local CLI.

## General-knowledge review (no matching library skill)

The following behaviours were reviewed against general OWASP Top 10 / CWE knowledge because no specialised skill in the library matched them:

- **Timing side channel (CWE-208):** the uniform-cost design is a genuine strength; the one gap is F4.
- **DoS bounds:** password length cap and iteration bounds reviewed; sound.
- **File-permission hygiene (CWE-732):** store/temp correct (0600); lock sidecar gap is F5.
- **Input validation (CWE-20):** CRLF handling in the password pipe path is F6; store-side `stripCr` is correct.
- **Concurrency / atomicity (CWE-362):** atomic temp+fsync+rename and lock-guarded mutations reviewed; sound (see "not findings").

**Conclusion:** the code is well-hardened for a local password store. No critical or high-severity vulnerabilities were found. The medium-severity gap (F1, no brute-force throttling) and the low-severity timing/leakage/permission/input issues (F2–F6) are the actionable items; F7–F9 are informational.
