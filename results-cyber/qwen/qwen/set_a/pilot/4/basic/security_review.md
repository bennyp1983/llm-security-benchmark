# Security Review — Account Credential Store (Java)

- **Reviewed:** all code in `/data/results-cyber/qwen/set_a/pilot/4/basic` (2026-09-09)
- **Method:** `review-code-for-security-vulnerabilities` skill workflow (understand → find applicable library skills → apply → report). One specialized skill matched and was applied in full (`performing-cryptographic-audit-of-application`); remaining behaviors were reviewed against general OWASP Top 10 / CWE knowledge (see *Skills applied* at the end).
- **Files in scope:** `src/accounts/{AccountApp,CredentialRecord,PasswordHasher,UserRegistry,UserStore}.java`, `tests/accounts/TestRunner.java`, `run-tests.sh`, `demo.sh`, `mutation-check.sh`, `README.md`. (Non-code context files — `prompt.txt`, `result.md`, `cyber_prompt.txt` — were read for context only.)

## Step 1 — What the code does

| File | Purpose |
|---|---|
| `src/accounts/AccountApp.java` (340 ln) | CLI: `register` / `login` / `check` / `list`; resolves the password from `--password-stdin`, `--password VALUE`, the `ACCOUNTS_PASSWORD` env var, or a terminal prompt; zeroes the `char[]` in `finally`. |
| `src/accounts/UserRegistry.java` (312 ln) | Input policy (username shape, password length/charset/composition), case-folded lookup, register, authenticate, timing-equalized unknown-user path. |
| `src/accounts/PasswordHasher.java` | PBKDF2-HMAC-SHA256 (default 600 000 iterations, 16-byte `SecureRandom` salt, 256-bit hash); username mixed into KDF input; `MessageDigest.isEqual` compare; key material zeroed. |
| `src/accounts/CredentialRecord.java` | On-disk codec `v1:base64url(user):alg:iters:base64url(salt):base64url(hash)`; 6-field + version + bounds validation on decode; `toString` omits salt/hash. |
| `src/accounts/UserStore.java` | Loads the store (skips blanks/comments, counts malformed lines), rewrites it atomically (temp + fsync + `ATOMIC_MOVE`) with mode `0600`. |
| `tests/accounts/TestRunner.java` (627 ln) | 17 cases / 117 assertions, plain `main`; includes timing-floor and cross-process persistence tests. |
| `run-tests.sh` / `demo.sh` / `mutation-check.sh` | Build-and-test script; end-to-end demo; 14-mutation sanity check (hard-coded source path). |

Security-relevant behaviors → keywords used for the skill lookup: password hashing / KDF parameters, cryptography audit, authentication, brute force / rate limiting, account enumeration, secrets in command line / environment, sensitive data in memory, temporary-file security, file integrity, race condition, shell injection.

## Findings

Severity scale: **Medium** = exploitable weakness a threat model should address; **Low** = real issue with limited exposure or acknowledged trade-off; **Informational** = hardening note / accepted risk, no action required for a demo scope.

### F1 — No rate limiting, lockout, or throttling of failed authentications
- **Severity:** Medium
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Evidence:** `src/accounts/AccountApp.java:221` (`doLogin`), `src/accounts/UserRegistry.java:223-239` (`authenticate`); no attempt counter, delay, or lockout anywhere in the codebase.
- **Why:** Each `login` attempt is independently accepted, so an attacker with store read/execute access (or remote access if this CLI were ever networked) can brute-force any account online without penalty. The 600k-iteration KDF raises per-guess cost but does not bound total guesses. `README.md` ("Known limits") acknowledges this.
- **Fix:** Track failures per (account, source) with exponential backoff or temporary lockout, or gate the CLI behind an authentication broker that enforces attempt policy.

### F2 — Password accepted on the command line and from an environment variable
- **Severity:** Medium (partially mitigated — the `--password` path prints a warning; the env path does not)
- **CWE:** CWE-214 (String-Based Command Execution / use of a password in a command line); env path also CWE-548-family exposure
- **Evidence:** `src/accounts/AccountApp.java:138` (`--password VALUE`), `:147` (`--password=` form), `:303-306` (warning), `:309-311` (`ACCOUNTS_PASSWORD`).
- **Why:** `--password` puts the credential in the process list (`/proc/*/cmdline`, shell history, monitoring tools) for the lifetime of the JVM; `ACCOUNTS_PASSWORD` leaves it in the process environment (visible via `/proc/*/environ` to the same user and inherited by any child process). Both defeat the otherwise-careful `char[]`-only handling.
- **Fix:** Drop the `--password` and env-var sources (or mark them explicitly unsafe and disable by default); require `--password-stdin` or the terminal prompt.

### F3 — Plaintext passwords persist in non-zeroable `String` objects
- **Severity:** Low
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information — in-memory)
- **Evidence:** `src/accounts/AccountApp.java:299-301` (stdin `line`), `:304` (`passwordArg`), `:310` (`fromEnv`); `src/accounts/UserRegistry.java:298` (`String lowered = new String(password)...`).
- **Why:** Every password source materializes the secret in a `String` before the `char[]` copy; `String` contents cannot be zeroed and survive GC/heap dumps. `UserRegistry` additionally builds a `String` from the `char[]` inside `validatePassword` (the "username substring" check at `:298-300`), despite the class documentation claiming the password is never copied into a `String`.
- **Fix:** Validate on the `char[]` directly (e.g., loop for the lowered-substring test, or use `CharBuffer`); remove the `String` materializations; treat `--password`/env sources (F2) as the root cause to eliminate.

### F4 — `check` and `list` leak account existence and enumerate usernames
- **Severity:** Low
- **CWE:** CWE-204 (Observable Response Discrepancy) / CWE-200 (Exposure of Sensitive Information)
- **Evidence:** `src/accounts/AccountApp.java:250-261` (`doCheck`: prints "is registered" at `:257`, returns distinct exit code 6 at `:261`), `:264-282` (`doList`: prints every username at `:281`).
- **Why:** The login path is timing- and message-equalized, but `check` and `list` are unauthenticated local commands that disclose exactly which usernames exist and the full account inventory (plus algorithm/iterations). Any process running as the store owner can enumerate accounts without guessing.
- **Fix:** Remove `check` (or make it return a constant response/exit code), restrict `list` to authenticated administrators, or at minimum document that these commands are out of scope for the no-enumeration property.

### F5 — Timing equalizer uses a fixed cost that may not match the stored record's cost
- **Severity:** Informational
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Evidence:** `src/accounts/UserRegistry.java:243-248` (dummy credential created with `hasher.createCredential(...)`, i.e. `DEFAULT_ITERATIONS = 600_000` per `src/accounts/PasswordHasher.java:34`), vs `:235` where the real comparison uses the per-record stored iteration count (bounded 100 000–5 000 000 by `src/accounts/CredentialRecord.java:31-32`).
- **Why:** For accounts whose stored cost differs from 600k, a login attempt on that account takes measurably longer than the unknown-user derivation, so the equalizer only holds exactly for default-cost accounts. A careful attacker can still partition "exists (600k)" from "unknown" by timing.
- **Fix:** Derive the dummy with the same iteration count as the *most recent* or a representative stored record, or document the residual oracle.

### F6 — No integrity protection over the credential store file
- **Severity:** Low (acknowledged in `README.md` "Known limits")
- **CWE:** CWE-354 (Improper Validation of Integrity Check)
- **Evidence:** `src/accounts/UserStore.java` (`load` / `replaceAll`, temp+move at `:107-125`); no MAC or signature over records in `src/accounts/CredentialRecord.java`.
- **Why:** A party with write access to the file (or its directory) can delete or swap whole records. The username-mixed KDF prevents making a foreign record validate for a new identity, but wholesale tampering (removing an account, replaying an old record after a hypothetical password change) is undetectable.
- **Fix:** If integrity matters, attach a per-record HMAC keyed with a secret held outside the file, or store the file under a filesystem that provides integrity (e.g., signed metadata), or accept and document the limitation (as currently done).

### F7 — Whole-file rewrite races across concurrent writer processes
- **Severity:** Informational (acknowledged in `README.md`)
- **CWE:** CWE-362 (Race Condition)
- **Evidence:** `src/accounts/UserStore.java:107-130` (every `replaceAll` rewrites the entire file; in-process calls are monitor-serialized in `UserRegistry`, cross-process writers are not).
- **Why:** Two concurrent `register` processes can interleave temp-file writes and moves; last writer wins and one registration can be silently lost. Security impact is availability/integrity of the store rather than credential theft.
- **Fix:** Take an exclusive lock (e.g., `FileChannel.tryLock` on a side lock file) around the read-modify-write, or move to per-record storage.

### F8 — Temp file name is predictable
- **Severity:** Informational
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **Evidence:** `src/accounts/UserStore.java:107` (`"accounts-" + System.nanoTime() + ".tmp"`).
- **Why:** `nanoTime` is not unpredictable to a local attacker; a same-directory attacker who can guess the name could pre-create or watch the temp file. Mitigations already present: `Files.createFile` fails if the path exists (no following of a planted entry), and the temp is created `0600` at `:110`.
- **Fix:** Use `Files.createTempFile` in the target directory (random suffix) or add a `SecureRandom`-derived suffix.

### F9 — `eval` of unquoted command assembly in `demo.sh`
- **Severity:** Informational (development/demo script only; no external input today)
- **CWE:** CWE-78 (OS Command Injection)
- **Evidence:** `demo.sh:15` (`eval "$@"` inside `step()`).
- **Why:** `step` re-executes its arguments through the shell; if a future edit passes a user- or file-derived value through `step`, it becomes command injection. The current invocations use only literals.
- **Fix:** Drop `eval` (pass the command array directly, e.g. `"$@"` without eval) or quote-escape all interpolated values.

### F10 — PBKDF2 instead of a memory-hard KDF (hardening note)
- **Severity:** Informational (not a defect at current parameters)
- **CWE:** n/a (design choice; adjacent to CWE-326/CWE-916 concerns)
- **Evidence:** `src/accounts/PasswordHasher.java:31` (`PBKDF2WithHmacSHA256`), `:34` (`DEFAULT_ITERATIONS = 600_000`).
- **Why:** 600k iterations of PBKDF2-HMAC-SHA256 meets the current OWASP Password Storage Cheat Sheet minimum, so this is acceptable — but Argon2id/scrypt resist GPU/ASIC brute force better per unit cost, and the per-record cost field (`CredentialRecord`) already supports migrating algorithms later.
- **Fix (optional):** Add an `Argon2id` algorithm branch when a dependency becomes available; the versioned record format is built for this.

## Checked and found sound

- **KDF parameters:** PBKDF2-HMAC-SHA256, 600 000 default iterations, 16-byte `SecureRandom` salt per account, 256-bit output — within current OWASP/NIST guidance (`PasswordHasher.java:31-40`, `:97`).
- **Username binding into KDF input** with NUL domain separation — cross-account record transplant does not validate (`PasswordHasher.java:38`, `:97`).
- **Constant-time hash comparison** via `MessageDigest.isEqual` (`PasswordHasher.java:82`).
- **Key-material zeroing:** `PBEKeySpec.clearPassword()` (`PasswordHasher.java:104`), `Arrays.fill` on salt material (`:109`) and hashes (`:71`, `:84`); CLI zeroes the password `char[]` in `finally` for both register (`AccountApp.java:217`) and login (`:246`).
- **Per-record iteration cost with decode-time bounds** (100k–5M) — a hand-edited `iterations=999999999` is rejected, not turned into a login DoS (`CredentialRecord.java:31-32`, `:103`).
- **Record codec hygiene:** base64url (no padding) usernames, fixed 6-field layout, version pinning, colon-rejection in `validateUsername` — no newline/colon injection into the line format (`CredentialRecord.java:86-110`, `UserRegistry.java:260-270`).
- **File hygiene:** mode `0600` on create and on open (`UserStore.java:110`, `:147`), fsync + atomic move with non-atomic fallback, malformed lines skipped and counted rather than fatal (`UserStore.java:122-125`).
- **Input policy:** username regex 3–32 chars, leading/trailing alnum, no NUL/colon (`UserRegistry.java:102-104`, `:251-270`); password 10–1024 printable ASCII, ≥1 letter + ≥1 digit, must not contain the username (`UserRegistry.java:105-106`, `:272-301`).
- **Case-folded identity:** `Ada.Lovelace` ≡ `ada.lovelace`, no collidable twin accounts (`UserRegistry.java:304-311`).
- **Equalized login response:** unknown user, wrong password, and empty input all return the same message and exit code 5, each costing one KDF derivation (`UserRegistry.java:223-239`; residual cost mismatch noted in F5).
- **No hardcoded secrets** in any source file; the timing-equalizer constants (`"timing-equalizer-probe"` / `"probe-password-1"`, `UserRegistry.java:243-246`) are public probe values, not secrets.

## Skills applied

1. **`performing-cryptographic-audit-of-application`** — applied in full (body + `references/standards.md`). Its weakness categories (weak/legacy hashes such as MD5/SHA-1, ECB mode, insufficient key length, hardcoded secrets, weak KDF, poor entropy) and its reference standards (NIST SP 800-131A / SP 800-57, OWASP A02:2021 Cryptographic Failures, OWASP Password Storage and Cryptographic Storage Cheat Sheets) drove F10 and the "found sound" KDF assessment; its bundled scanners are Python-only, so the knowledge was applied to the Java sources directly rather than executed.
2. Library scan: all ~819 skills in `/root/.qwen/skills` were screened cheaply by name/description against the Step-1 keyword list; no other skill matched the behaviors under review (remaining hits were offensive, cloud, or OT-domain skills outside this codebase's scope).

## Behaviors with no matching library skill

The following were reviewed against **general OWASP Top 10 / CWE knowledge** because the library search returned no applicable specialized skill:

- Authentication attempt restriction / lockout (F1 — OWASP A07, CWE-307)
- Secrets in command line / environment (F2 — OWASP A02/A07, CWE-214)
- Sensitive data retention in memory (F3 — OWASP A02, CWE-316)
- User/account enumeration oracles (F4, F5 — OWASP A01/A07, CWE-204/CWE-208)
- Data integrity protection for stored credentials (F6 — OWASP A03, CWE-354)
- Concurrency/atomicity of store writes (F7, F8 — CWE-362, CWE-330, CWE-377-adjacent temp-file guidance)
- Shell-script command construction (F9 — OWASP A03, CWE-78)

## Verdict

The cryptographic core is sound for a dependency-free JDK-only build: correct KDF choice and parameters, per-account salt, username binding, constant-time comparison, bounded per-record cost, and disciplined memory/file hygiene. The open issues are operational rather than cryptographic: no brute-force throttling (F1), two legacy password ingestion paths that leak the secret before hashing (F2/F3), unauthenticated enumeration commands (F4/F5), and acknowledged store-integrity/concurrency limits (F6/F7). None of the findings indicates plaintext or hash storage of passwords on disk; the store contains only salted PBKDF2 hashes.
