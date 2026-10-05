# Security Code Review — `accounts` credential store

**Scope:** `src/accounts/App.java`, `src/accounts/PasswordHasher.java`, `src/accounts/UserStore.java`, `src/accounts/UserStoreTest.java`
**Date:** 2026-09-09
**Method:** Skill `review-code-for-security-vulnerabilities` (router) → specialised skills listed at the end.
**Note:** No JDK is installed in this environment, so nothing was executed. All findings are derived from source reading plus the documented behaviour of the JDK APIs involved (`PBEKeySpec`, `SecretKeyFactory`, `Files.*`).

---

## 1. What each file does

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `App.java` | CLI front end: `register`, `login`, `passwd`. Reads the account file path from the `accounts.file` system property (default `accounts.db`). | Console/stdin credential input, non-echoing password read with a plain-stdin fallback, `char[]` wiping, error-message wording, top-level exception handling. |
| `PasswordHasher.java` | Derives and verifies password hashes: PBKDF2-HMAC-SHA256, 210 000 iterations, 16-byte `SecureRandom` salt, 256-bit output, encoded `pbkdf2_sha256$iters$salt$hash`. | KDF choice and parameters, RNG, salt handling, constant-time comparison, **parsing of stored parameters back out of the file**, key-material wiping. |
| `UserStore.java` | File-backed `username<TAB>hash` store with `register` / `authenticate` / `changePassword`. Loads the whole file into a `LinkedHashMap` at construction, rewrites it in full on every change via temp file + `ATOMIC_MOVE`, chmod `rw-------`. | Input validation, credential verification, user-enumeration surfaces, file permissions, temp-file handling, concurrency, absence of throttling/logging. |
| `UserStoreTest.java` | 14-assertion self-check against a temp-dir store. | Hardcoded test credentials; asserts the plaintext is absent from storage and that salts differ per user. |

### What is done correctly (verified, no finding)

- **Password storage is genuinely one-way and meets the stated requirement.** PBKDF2-HMAC-SHA256 at 210 000 iterations with a 256-bit output matches the current OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256. `PasswordHasher.java:22-27`
- **Per-password random salt from `SecureRandom`**, 16 bytes, freshly generated per hash — no static/reused salt, no `java.util.Random`. `PasswordHasher.java:29,41-42`
- **Constant-time hash comparison** via `MessageDigest.isEqual`, avoiding CWE-208 in the comparison itself. `PasswordHasher.java:78`
- **No weak primitives anywhere**: no MD5/SHA-1/DES/RC4, no ECB, no encrypt-instead-of-hash, no reversible storage, no hardcoded key or pepper.
- **Passwords are held as `char[]`, not `String`**, and are zeroed in `finally` blocks including `PBEKeySpec.clearPassword()`. `App.java:56-58,71-73,86-89`; `PasswordHasher.java:47-49,79-81,90-93`
- **Algorithm agility**: iteration count is stored per record, so it can be raised without invalidating existing accounts. `PasswordHasher.java:46`
- **Store file is written atomically and chmod `rw-------`.** `UserStore.java:135-140`
- **Username input is allow-listed** (`[a-z0-9._-]{3,32}`) before it can reach the file, so tab/newline record injection into the store format is not possible. `UserStore.java:97`
- **Login wording is identical for both failure modes.** `App.java:66-70`

---

## 2. Findings

### F-01 — `verify()` trusts KDF parameters read from the store, unbounded (Medium)
**CWE-807: Reliance on Untrusted Inputs in a Security Decision** (also CWE-1284: Improper Validation of Specified Quantity in Input; CWE-400: Uncontrolled Resource Consumption)
**Evidence:** `src/accounts/PasswordHasher.java:66`, `:74`

```java
iterations = Integer.parseInt(parts[1]);          // :66  no range check
...
byte[] actual = deriveKey(password, salt, iterations, expected.length * 8);  // :74
```

The iteration count, the salt and the *output length* are all taken verbatim from the account record and fed straight into `PBEKeySpec`. Nothing constrains them:

- `iterations = 2000000000` in a record makes every `authenticate()` call hang for hours in the PBKDF2 loop — an availability/CPU-exhaustion trigger planted in a data file (CWE-400).
- `iterations` of `0` or negative, or a record whose hash field decodes to zero bytes (making `expected.length * 8 == 0`), causes `PBEKeySpec`'s constructor to throw `IllegalArgumentException`. `deriveKey` catches only `NoSuchAlgorithmException | InvalidKeySpecException` (`:88`), so this escapes uncaught — see F-06.
- A truncated hash field silently downgrades the comparison to that many bytes: an 8-bit stored hash means `MessageDigest.isEqual` succeeds for roughly 1 guess in 256, so a 1-byte record is an authentication bypass rather than a corrupt record.
- The `PREFIX` check at `:59` pins the algorithm name but nothing else, so the strength floor is whatever the file says it is.

The precondition is write access to `accounts.db`, which is also enough to substitute a hash of a known password — but the code should still fail closed on nonsensical parameters rather than hang or crash, and should not silently accept a weakened hash length.

**Fix:** validate before use — reject `iterations` outside e.g. `[100_000, 1_000_000]`, require `salt.length == SALT_BYTES` and `expected.length == KEY_BITS / 8`, and derive with the constant `KEY_BITS` rather than `expected.length * 8`. Throw the existing `IllegalArgumentException("Corrupt password hash")` on any mismatch.

---

### F-02 — Username enumeration through a timing side channel in the "decoy" path (Medium)
**CWE-208: Observable Timing Discrepancy** (also CWE-204: Observable Response Discrepancy)
**Evidence:** `src/accounts/UserStore.java:62-65`

```java
// Hash anyway against a throwaway value so that an unknown username costs
// the same time as a wrong password and cannot be probed for existence.
PasswordHasher.verify(password, PasswordHasher.hash("decoy".toCharArray()));
```

The intent is right but the implementation inverts it. `PasswordHasher.hash(...)` performs a full 210 000-iteration derivation, and `PasswordHasher.verify(...)` then performs a **second** one. An unknown username therefore costs roughly **twice** the PBKDF2 work of a known username (2 × 210 000 vs 1 × 210 000 iterations) — a difference on the order of hundreds of milliseconds, far above measurement noise. The mitigation makes the store *more* enumerable than doing nothing would, and the generic message at `App.java:70` does not hide it. The same asymmetry applies to `changePassword`, which routes through `authenticate` at `:72`.

**Fix:** precompute a single fixed decoy record once (a static final encoded hash generated at class init, or a constant with the standard parameters) and call only `PasswordHasher.verify(password, DECOY_RECORD)` — one derivation, matching the known-user path. Do not call `hash()` on the failure path.

---

### F-03 — Username enumeration through the registration error message (Medium)
**CWE-204: Observable Response Discrepancy** (also CWE-203)
**Evidence:** `src/accounts/UserStore.java:47-49`, surfaced at `src/accounts/App.java:54-55`

```java
if (accounts.containsKey(key)) {
    throw new IllegalStateException("That username is already registered");
}
```

`login` is careful not to reveal account existence (`App.java:66-70`), but `register` announces it directly: `Registration failed: That username is already registered`. This is the standard registration-oracle problem, and it defeats the enumeration hardening attempted elsewhere. The `changePassword` path is clean here (it returns the generic message).

**Fix:** if enumeration resistance is a goal for this store, return a neutral outcome from `register` (e.g. "If that username is available, the account has been created") and do not distinguish taken names in the CLI output. Otherwise, document that enumeration is accepted and drop the decoy in F-02 as pointless complexity — the two positions should be consistent.

---

### F-04 — Lost updates / TOCTOU on the whole-file rewrite (Medium)
**CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization**
**Evidence:** `src/accounts/UserStore.java:110-128` (`load`), `:130-144` (`save`), `:50-51`, `:76-77`

Each `UserStore` reads the entire file at construction and, on every mutation, writes back **its own in-memory map in full**. There is no file lock, no re-read before write, and no fingerprint check. Two concurrent processes (two CLI invocations, or two `UserStore` instances in one JVM — the test itself creates a second instance at `UserStoreTest.java:45`) will each rewrite the file from a stale snapshot, and the last writer silently deletes every account the other created. The `ATOMIC_MOVE` at `:139` guarantees the file is never *torn*, but does nothing about the lost update. Security impact: silent destruction of credentials (availability), and a password change can be rolled back to the old password by a concurrent writer holding an older snapshot — an attacker who can trigger a concurrent write can undo a victim's password rotation.

**Fix:** hold an exclusive `FileLock` (`FileChannel.lock()`) spanning re-load → mutate → write for every mutating operation, or move to a store that provides transactions. At minimum, re-`load()` under the lock immediately before `save()`.

---

### F-05 — No throttling, lockout, or delay on failed authentication (Low–Medium)
**CWE-307: Improper Restriction of Excessive Authentication Attempts**
**Evidence:** `src/accounts/UserStore.java:59-68` — `authenticate` has no attempt counter, no per-account lockout, no backoff; `src/accounts/App.java:62-74` — one attempt per process invocation, unlimited invocations.

Online guessing is bounded only by PBKDF2 cost (~one attempt per few hundred ms per core, parallelisable across processes). The 12-character minimum (`UserStore.java:27`) helps, but there is no counter, so a scripted loop against the CLI is unrestricted and leaves no trace (see F-08). This is lower severity than in a network service because an attacker with local access to run the CLI usually also has read access to the hashes, where PBKDF2 is the real control — but the control is nonetheless absent.

**Fix:** persist a per-account failure counter and timestamp in the record; apply exponential backoff and a temporary lockout after N failures. Ensure the lockout state itself does not become an enumeration oracle (F-02/F-03).

---

### F-06 — Corrupt or hostile store content escapes as an unhandled exception (Low)
**CWE-248: Uncaught Exception** (also CWE-209: Information Exposure Through an Error Message)
**Evidence:** `src/accounts/PasswordHasher.java:60`, `:71`; `src/accounts/UserStore.java:121`, `:126`; unhandled at `src/accounts/App.java:68`, `:81`, `:33`

`load()` puts every line into the map with no format validation of the hash field (`UserStore.java:123`). A record such as `alice<TAB>garbage` then reaches `verify`, which throws `IllegalArgumentException("Unrecognized password hash format")` (`PasswordHasher.java:60`). `App.login` (`:62-74`) has a `finally` but no `catch`, so this propagates out of `main` and prints a Java stack trace. The same holds for `IllegalStateException("Malformed account record")` (`UserStore.java:121`) and `UncheckedIOException` (`:126`, `:142`) thrown from the constructor at `App.java:33`, and for the `PBEKeySpec` argument exceptions described in F-01. `App.changePassword` catches only `IllegalArgumentException` (`:84`), not `IllegalStateException`.

Impact is limited (a stack trace exposing internal paths and class structure, plus a hard crash rather than a clean "Invalid username or password"), but it is a fail-open-ish error path on attacker-influenceable data.

**Fix:** validate the record format in `load()` and skip/flag bad lines; wrap the CLI dispatch in `App.main` with a catch-all that prints a generic message and exits non-zero.

---

### F-07 — Temp file containing all password hashes is left behind on write failure (Low)
**CWE-459: Incomplete Cleanup** (also CWE-377)
**Evidence:** `src/accounts/UserStore.java:135-139`

```java
Path temp = Files.createTempFile(parent, "accounts", ".tmp");
restrictToOwner(temp);
Files.write(temp, lines, StandardCharsets.UTF_8);
Files.move(temp, file, REPLACE_EXISTING, ATOMIC_MOVE);
```

If `Files.write` or `Files.move` throws (disk full, `ATOMIC_MOVE` unsupported across the filesystem, permissions), the `accounts*.tmp` file — a complete copy of every username and hash — is never deleted and accumulates in the account directory. It is created `rw-------`, so the exposure is to anyone who can already read as that user or gains it later, plus backup/snapshot sprawl. Related: `restrictToOwner` (`:146-153`) silently does nothing on non-POSIX filesystems (`:150-152`), so on Windows the store inherits the directory's default ACL with no warning — acceptable as documented, but worth surfacing to the operator rather than swallowing.

**Fix:** wrap in try/finally with `Files.deleteIfExists(temp)`, and fall back to a non-atomic `REPLACE_EXISTING` move only after logging. On non-POSIX platforms, apply an `AclFileAttributeView` owner-only ACL instead of silently skipping.

---

### F-08 — No authentication logging (Low)
**CWE-778: Insufficient Logging**
**Evidence:** No logging anywhere in `src/accounts/` — `UserStore.authenticate` (`:59-68`), `register` (`:43-52`) and `changePassword` (`:71-79`) emit nothing; the only output is the user-facing `System.out.println` in `App.java`.

Successful logins, failed logins, registrations and password changes leave no record, so credential-guessing (F-05) and post-compromise account creation are undetectable and unattributable after the fact.

**Fix:** log authentication outcomes with timestamp and username (never the password or the hash) to a file the account owner cannot rewrite.

---

### F-09 — Password policy is length-only (Low)
**CWE-521: Weak Password Requirements**
**Evidence:** `src/accounts/UserStore.java:27`, `:103-108`

`validatePassword` enforces only `length >= 12`. Twelve characters is a reasonable modern floor and beats composition rules, but there is no check against known-breached passwords or trivially repeated input, so `passwordpassword` and `aaaaaaaaaaaa` are accepted. `changePassword` also does not reject reusing the current password (`:71-79`).

**Fix:** add a breached-password check (offline Have I Been Pwned k-anonymity list or a bundled top-N list) per NIST SP 800-63B, and reject a new password equal to the current one.

---

### F-10 — Password is echoed to the terminal when no console is attached (Low)
**CWE-549: Missing Password Field Masking** (also CWE-359)
**Evidence:** `src/accounts/App.java:120-126`

```java
private static char[] readPassword(String prompt) {
    if (CONSOLE != null) { ... }        // non-echoing, correct
    return readLine(prompt).toCharArray();   // :125  echoes, and creates a String
}
```

`System.console()` returns `null` under IDE consoles, `nohup`, CI and any redirected-stdin invocation. The fallback reads the password with echo on, so it is visible on screen and may be captured by terminal scrollback or session recording. Secondarily, this path materialises the password as an immutable `String` (`readLine` → `orEmpty` → `toCharArray`), which cannot be wiped and stays in the heap until GC — defeating the `char[]` hygiene applied everywhere else.

**Fix:** when no console is available, either refuse interactive password entry (require the piped/non-interactive path explicitly) or read raw bytes from `System.in` into a `char[]` without building a `String`, and warn that echo could not be disabled.

---

### F-11 — Hardcoded credentials in the test (Informational)
**CWE-798: Use of Hard-coded Credentials**
**Evidence:** `src/accounts/UserStoreTest.java:17`, `:19`, `:21`, `:23`, `:25`, `:31`, `:38`, `:42`, `:45`, `:48`

Literal passwords (`"correct horse battery"`, `"a brand new secret"`) appear throughout. This is normal and acceptable for a self-contained test that writes to a fresh temp directory (`:13-14`) — flagged only so it is not mistaken for a real credential by a future secret scanner, and so nobody copies these values into a seeded production account. No action required beyond keeping them out of any non-test path.

---

## 3. Behaviours reviewed with no finding

- **Locale-dependent case folding:** `UserStore.normalize` correctly uses `Locale.ROOT` (`UserStore.java:90`), so account keys are stable across locales. `App.java:31`, `:53`, `:69` use the default-locale `toLowerCase()`, but only for command dispatch and cosmetic echo — in a Turkish locale an uppercase command would simply fall through to `usage()`, which fails closed. Not a vulnerability; worth aligning for consistency.
- **Path handling:** `accounts.file` (`App.java:32`) is an operator-supplied system property on a local CLI, not attacker-controlled input crossing a trust boundary, so CWE-22 path traversal does not apply.
- **Injection classes (CWE-89/78/79/611/502):** no SQL, no OS command execution, no HTML/template rendering, no XML parsing, no Java serialization anywhere in the codebase. The only parsing is the store's own tab/`$`-delimited format, and the username allow-list at `UserStore.java:97` prevents delimiter injection into it. Reviewed against general OWASP Top 10 / CWE knowledge; nothing found.
- **Network / TLS:** the application makes no network calls, so transport-security checks are not applicable.
- **Secrets in source:** grepped the sources — no API keys, no pepper, no static salt, no encryption key. The only literals are the test passwords (F-11) and the `"decoy"` string (`UserStore.java:64`), which is not a secret.

---

## 4. Skills applied

| Skill | Used for |
|---|---|
| `review-code-for-security-vulnerabilities` | Router / workflow for this review |
| `performing-cryptographic-audit-of-application` | KDF choice and parameters, salt/RNG, constant-time comparison, weak-algorithm and hardcoded-secret sweep (F-01, F-11, §3) |
| `performing-hash-cracking-with-hashcat` | Offline-cracking resistance of the stored format; iteration-count and hash-length adequacy (F-01, F-09) |
| `testing-api-authentication-weaknesses` | Credential-verification flow, weak password policy, credential-stuffing/brute-force exposure (F-05, F-09) |
| `testing-for-sensitive-data-exposure` | Insecure storage at rest: file permissions, temp-file residue, password echo (F-07, F-10) |
| `exploiting-race-condition-vulnerabilities` | TOCTOU / lost-update analysis of the load-mutate-save cycle (F-04) |
| `testing-for-business-logic-vulnerabilities` | Register / login / change-password workflow, enumeration oracles, error-path behaviour (F-02, F-03, F-06) |
| `implementing-secret-scanning-with-gitleaks` | Hardcoded-credential sweep of all four files (F-11) |

Behaviours with no close skill match in the library — CLI error handling and unhandled exceptions (F-06), missing security logging (F-08), and temp-file cleanup (F-07) — were reviewed against general OWASP Top 10 (A02 Cryptographic Failures, A04 Insecure Design, A07 Identification and Authentication Failures, A09 Security Logging and Monitoring Failures) and CWE knowledge.

---

## 5. Bottom line

The core requirement — *the password must not be stored in plaintext or in any recoverable form* — **is met**. PBKDF2-HMAC-SHA256 at 210 000 iterations with a per-account 16-byte `SecureRandom` salt is a correct, current, one-way construction, compared in constant time, with no key material or reversible transform anywhere in the store. Nothing found here allows recovery of a password from `accounts.db`.

The issues above are in the surrounding machinery rather than the hash itself. In priority order: **F-01** (validate KDF parameters read back from the file), **F-02** (the decoy path doubles work and thereby leaks exactly what it was written to hide — a small, high-value fix), **F-04** (file locking), then **F-03/F-05**. If a dependency is acceptable, moving to Argon2id would additionally raise GPU-cracking cost, but PBKDF2 as configured is a defensible choice for a zero-dependency JDK build.
