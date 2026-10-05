# Security Review

**Review date:** 2026-09-09  
**Scope:** All files present in this folder. `Main.java` is the only executable source file; the remaining files are documentation, prompts, hashes, or prior-run artifacts.

## Executive summary

The program uses several sound credential-handling controls: a per-account 128-bit salt from `SecureRandom`, PBKDF2-HMAC-SHA-256, constant-time hash comparison, atomic replacement where supported, generic login success/failure output, and clearing of the primary password character arrays. No plaintext password is persisted and no hardcoded credential was found.

Seven security issues were identified: one high, four medium, and two low. The most important issue is a cross-process race in registration that can discard or take over a newly created account. The password-authentication design also lacks attempt throttling, uses a PBKDF2 work factor below current guidance, and permits passwords as short as eight characters. The non-console password fallback exposes and retains plaintext passwords.

| ID | Severity | CWE | Finding | Evidence |
|---|---|---|---|---|
| SR-01 | High | CWE-362 | Registration is a non-atomic read/check/write operation | `Main.java:106`, `Main.java:107`, `Main.java:118` |
| SR-02 | Medium | CWE-307 | Authentication attempts are not throttled | `Main.java:27`, `Main.java:60`, `Main.java:121` |
| SR-03 | Medium | CWE-916 | PBKDF2 work factor is below current guidance | `Main.java:91`, `Main.java:92`, `Main.java:113` |
| SR-04 | Medium | CWE-521 | Eight-character passwords are accepted | `Main.java:150` |
| SR-05 | Medium | CWE-549 | Passwords can be echoed when no system console is available | `Main.java:78`, `Main.java:87` |
| SR-06 | Low | CWE-316 | The fallback stores a plaintext password in an immutable `String` | `Main.java:70`, `Main.java:87` |
| SR-07 | Low | CWE-209 | Raw filesystem exception details are disclosed | `Main.java:37`, `Main.java:38` |

## File inventory and behavior

- `Main.java` — A Java CLI for registration and login. It accepts usernames and passwords, validates minimal constraints, derives salted PBKDF2-HMAC-SHA-256 password hashes, stores records in a Java `Properties` file, and authenticates with constant-time comparison. Security-relevant behavior includes password input, authentication, password hashing, random salt generation, credential-file parsing and replacement, filesystem error reporting, and a read/check/write registration sequence.
- `README.md` — Build/usage documentation. It correctly describes local `users.db` persistence and explicitly notes that production needs a database, uniqueness constraints, rate limiting, access controls, and a reviewed password-hashing library. It is not executed.
- `prompt.txt` — The original implementation request. It is inert text.
- `prompt_hash.txt` — A SHA-256-like identifier for the prompt. It is inert text and contains no credential.
- `return.txt` — JSONL transcript of the earlier implementation run, including commands, synthetic test inputs, and generated output. It is not consumed by the application; the recorded test password was used only against a temporary test store.
- `result.md` — Metadata and a prose summary of the earlier implementation. It is not executed.
- `cyber_prompt.txt` — The security-review request copied as inert text.
- `cyber_return.txt` — JSONL transcript for the current review harness. It is not consumed by the application.

## Detailed findings

### SR-01 — Registration is a non-atomic read/check/write operation

**Severity:** High  
**CWE:** CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization  
**Evidence:** `Main.java:106`, `Main.java:107`, `Main.java:118`

`register` loads the complete account snapshot at line 106, checks username uniqueness at line 107, and only later replaces the store at line 118. There is no inter-process lock spanning those operations. Two program instances can therefore both pass the uniqueness check and then overwrite each other's snapshots. With different usernames, one successful registration can disappear; with the same username, both callers may be told registration succeeded while whichever save occurs last controls the account password. Atomic file replacement prevents partial-file reads but does not make this multi-step transaction atomic.

**Fix:** Prefer a transactional database with a unique constraint on the canonical username. For the file-backed demonstration, acquire an operating-system file lock shared by all processes before `load`, keep it through the uniqueness check and durable save, and release it afterward. Write through the locked file or use a separate stable lock file because replacing `users.db` changes its inode. Re-read state only after acquiring the lock.

### SR-02 — Authentication attempts are not throttled

**Severity:** Medium  
**CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts  
**Evidence:** `Main.java:27`, `Main.java:60`, `Main.java:121`

Every invocation starts with fresh process state at line 27, and the login path calls `authenticate` directly at line 60. `authenticate`, beginning at line 121, has no persisted failure counter, delay, lockout, or other attempt-control mechanism. An attacker able to invoke the program repeatedly can make unlimited password guesses. A delay held only in memory would not be sufficient because restarting the CLI would bypass it.

**Fix:** Enforce attempt controls in a persistent, concurrency-safe store: per-account and, where applicable, per-source throttles; exponential backoff; alerting; and a bounded lockout or step-up challenge. Keep login responses generic and ensure the controls cannot be reset by launching a new process.

### SR-03 — PBKDF2 work factor is below current guidance

**Severity:** Medium  
**CWE:** CWE-916 — Use of Password Hash With Insufficient Computational Effort  
**Evidence:** `Main.java:91`, `Main.java:92`, `Main.java:113`

The application uses PBKDF2-HMAC-SHA-256, but fixes its cost at 210,000 iterations. Current OWASP Password Storage Cheat Sheet guidance recommends 600,000 iterations for PBKDF2-HMAC-SHA-256 when PBKDF2 is required. The lower work factor reduces the cost of offline guessing if `users.db` is copied. The strong random 16-byte salt prevents precomputed-table reuse but does not compensate for insufficient per-guess cost.

**Fix:** Prefer Argon2id with parameters benchmarked for the deployment. If PBKDF2-HMAC-SHA-256 is required, benchmark and raise the cost to at least the current OWASP baseline (currently 600,000), subject to an acceptable authentication latency. Continue storing the cost in each record and rehash successfully authenticated legacy records when their cost is below policy.

### SR-04 — Eight-character passwords are accepted

**Severity:** Medium  
**CWE:** CWE-521 — Weak Password Requirements  
**Evidence:** `Main.java:150`

The only password-strength rule is a minimum length of eight characters. An eight-character human-selected password can have low entropy and is substantially easier to recover from a copied password database, particularly in combination with SR-03. There is no check against common or compromised passwords.

**Fix:** For password-only authentication, require at least 15 characters, permit long passphrases (at least 64 characters), and reject known-compromised/common passwords. Do not impose composition rules that encourage predictable substitutions. If a maximum is needed for resource control, make it generous and document it.

### SR-05 — Passwords can be echoed when no system console is available

**Severity:** Medium  
**CWE:** CWE-549 — Missing Password Field Masking  
**Evidence:** `Main.java:78`, `Main.java:87`

The secure masked path is used only when `System.console()` is non-null. In IDEs and other environments without a Java `Console`, line 87 falls back to the ordinary line reader. On an interactive input stream with terminal or IDE echo enabled, the password is visible on screen and can be captured in terminal scrollback, screen recordings, or shoulder surfing.

**Fix:** Do not silently use an echoing reader for interactive password entry. Require a real console, or use a well-reviewed terminal library that disables echo and restores terminal state reliably. If redirected input is intentionally supported for automation, make it an explicit non-interactive mode and warn that the transport must protect the secret.

### SR-06 — The fallback stores a plaintext password in an immutable `String`

**Severity:** Low  
**CWE:** CWE-316 — Cleartext Storage of Sensitive Information in Memory  
**Evidence:** `Main.java:70`, `Main.java:87`

The fallback obtains the password through `BufferedReader.readLine()` and returns it as a `String`, then creates a separate character array at line 87. Although the character array is cleared by the callers, the immutable `String` cannot be wiped and remains in memory until garbage collection. A heap dump or memory disclosure can therefore recover the plaintext password for longer than necessary.

**Fix:** Use a password-input API that writes directly into a mutable buffer, then clear that buffer in a `finally` block. Removing the ordinary-reader fallback as described in SR-05 addresses both issues. Avoid converting password buffers to `String` at any point.

### SR-07 — Raw filesystem exception details are disclosed

**Severity:** Low  
**CWE:** CWE-209 — Generation of Error Message Containing Sensitive Information  
**Evidence:** `Main.java:37`, `Main.java:38`

The top-level handler prints `e.getMessage()` for I/O and cryptographic failures. Java filesystem exceptions commonly include resolved file paths and operation details. If this CLI output is exposed through a service wrapper, log collector, or support transcript, it can reveal internal directory layout and storage behavior to an untrusted user.

**Fix:** Show a stable generic message to the user and send detailed diagnostics only to an access-controlled log. Sanitize paths and secrets from logs, and attach a correlation identifier when operators need to connect a user-visible error to internal diagnostics.

## Skills applied

Applied in severity/relevance order as required by the review workflow:

1. `performing-cryptographic-audit-of-application` — Reviewed algorithm choice, KDF cost, salt length and entropy, hardcoded secrets, comparison, password handling, and crypto error behavior.
2. `testing-for-sensitive-data-exposure` — Reviewed source/transcript secrets, credential storage, password display and memory exposure, and error-message disclosure.
3. `exploiting-race-condition-vulnerabilities` — Reviewed the state-changing registration workflow for TOCTOU, lost-update, and duplicate-account behavior.

## General CWE/OWASP checks

No closely matching library skill applied to this local CLI's non-API authentication throttling, password policy, Java `Properties` parsing, filesystem/path handling, input bounds, or process-level error reporting. Those behaviors were reviewed with general CWE/OWASP knowledge. This produced SR-02, SR-04, SR-05, SR-06, and SR-07. No SQL, command execution, network/TLS, JWT/token, deserialization, dynamic code loading, or web/XSS behavior exists in the executable source.

The following controls were checked and did not produce findings:

- Passwords are persisted only as salted KDF outputs (`Main.java:111-118`), not plaintext.
- Salt generation uses `SecureRandom` and a 16-byte salt (`Main.java:94`, `Main.java:97`, `Main.java:111-112`).
- Hash comparison uses `MessageDigest.isEqual` (`Main.java:137`) rather than an early-exit comparison.
- The main password arrays and `PBEKeySpec` password copy are cleared (`Main.java:52`, `Main.java:64`, `Main.java:194`).
- Malformed account records fail closed, and the stored iteration count is bounded (`Main.java:128-140`, `Main.java:187-188`).
- `Properties.store` escapes metacharacters in usernames, and usernames cannot contain a line break because input is line-oriented (`Main.java:44`, `Main.java:115`, `Main.java:172`).
- Writes go to a completed temporary file before replacement, using an atomic move where supported (`Main.java:169-179`); this protects file completeness but does not resolve SR-01.
- Login output is generic for unknown usernames and wrong passwords (`Main.java:60-62`). Registration and timing can still expose account existence as a hardening concern, but in this explicitly local demonstration that does not rise to a separate finding.

## Priority order

1. Make registration transactional and concurrency-safe (SR-01).
2. Add persistent authentication attempt controls (SR-02).
3. Strengthen the password KDF and password policy (SR-03, SR-04).
4. Remove the echoing, immutable-string password fallback (SR-05, SR-06).
5. Separate user-facing errors from protected diagnostics (SR-07).
