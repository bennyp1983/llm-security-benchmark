# Security Review

## Scope and approach

All files in this folder were inspected. The executable code consists of `UserAccountApp.java` and `UserAccountAppTest.java`; the remaining files are documentation, task prompts, hashes, or prior-run transcripts and do not execute as part of the application.

The application is a local Java CLI that registers and authenticates users against a line-oriented credential file. It reads a password from the console or standard input, creates a unique random salt, derives a verifier with PBKDF2-HMAC-SHA-256, and appends a versioned record while holding a file lock. Authentication reloads the file, derives a candidate verifier, and compares it in constant time. The test covers persistence, correct and incorrect passwords, unknown users, duplicate registration, and absence of the plaintext password in the store.

Security-relevant behaviors reviewed were password hashing and memory handling, authentication policy and response behavior, local credential storage and permissions, attacker-influenced filesystem paths, credential-file parsing, input bounds, randomness, and error handling. There is no SQL, OS-command execution, network/TLS code, token handling, or object deserialization.

## Summary

Eight findings were identified: five medium severity and three low severity. No critical or high-severity issue was found in the stated local CLI deployment model.

The implementation gets several important controls right: it uses a fresh 128-bit salt from `SecureRandom` (`UserAccountApp.java:111-113`, `UserAccountApp.java:135-137`), stores a one-way verifier rather than plaintext (`UserAccountApp.java:176-183`, `UserAccountApp.java:235-241`), compares derived values with `MessageDigest.isEqual` (`UserAccountApp.java:167-171`), clears mutable password/hash buffers where practical (`UserAccountApp.java:60-62`, `UserAccountApp.java:146-148`, `UserAccountApp.java:170-182`), and serializes cooperative access with file locks (`UserAccountApp.java:126-130`, `UserAccountApp.java:161-163`). The test password in `UserAccountAppTest.java:13` is test data, not a production credential.

## Findings

### 1. PBKDF2 work factor is below the current recommended minimum

- **Severity:** Medium
- **CWE:** CWE-916 — Use of Password Hash With Insufficient Computational Effort
- **Evidence:** `UserAccountApp.java:109-112` fixes PBKDF2-HMAC-SHA-256 at 310,000 iterations; `UserAccountApp.java:137` and `UserAccountApp.java:176-180` use that value when generating verifiers.
- **Why this matters:** The work factor directly controls the cost of offline password guessing after theft of `accounts.db`. The current OWASP Password Storage Cheat Sheet recommends 600,000 iterations for PBKDF2-HMAC-SHA-256, so this configuration supplies materially less resistance. The code also has no path for upgrading an older verifier after successful authentication.
- **Fix:** Prefer Argon2id with parameters calibrated for the deployment. If PBKDF2 is required, benchmark the target systems, use at least the current recommended HMAC-SHA-256 work factor (currently 600,000), retain the per-record cost, and transparently rehash successful logins whose stored parameters are obsolete.

### 2. Trivially weak passwords are accepted

- **Severity:** Medium
- **CWE:** CWE-521 — Weak Password Requirements
- **Evidence:** `UserAccountApp.java:186-195` rejects only a null or empty password. A one-character or commonly breached password is accepted and persisted.
- **Why this matters:** Salting and a slow KDF cannot compensate for a very small or predictable password search space. An attacker who obtains the verifier file can quickly recover such passwords offline.
- **Fix:** Enforce a minimum length appropriate to the authentication assurance level, permit long passphrases, screen new passwords against a blocklist of common and breached values, and avoid arbitrary composition rules. Add boundary and blocklist tests.

### 3. The entire credential file is allocated and expanded in memory without a practical limit

- **Severity:** Medium
- **CWE:** CWE-400 — Uncontrolled Resource Consumption
- **Evidence:** `UserAccountApp.java:215-225` accepts any file up to `Integer.MAX_VALUE`, allocates one buffer equal to the complete file size, and converts it to a second in-memory `String`; `UserAccountApp.java:227-230` then splits and decodes all records into further objects. `UserAccountApp.java:255-256` also permits a store-controlled PBKDF2 cost as high as 10,000,000 iterations.
- **Why this matters:** A malformed, oversized, or deliberately replaced credential file can exhaust heap or impose excessive CPU cost during either registration or authentication, terminating the process and denying account access. The nominal two-gigabyte check is far above a safe heap-dependent application limit.
- **Fix:** Define a practical maximum store size, record count, line length, decoded username/salt length, and acceptable KDF cost. Parse records incrementally with bounded buffers instead of materializing and splitting the whole file. Reject out-of-policy data before expensive allocation or derivation.

### 4. Credential paths are followed through symbolic links

- **Severity:** Medium
- **CWE:** CWE-59 — Improper Link Resolution Before File Access ('Link Following')
- **Evidence:** The default is a relative path at `UserAccountApp.java:29`, and an optional caller-controlled path is accepted at `UserAccountApp.java:41`. Registration opens it with `CREATE`, `READ`, and `WRITE` at `UserAccountApp.java:126-128`, changes its permissions at `UserAccountApp.java:205-209`, and appends data at `UserAccountApp.java:139-145`; none of these operations reject symbolic links or verify the opened file's identity.
- **Why this matters:** If the program is run with greater filesystem privileges from an attacker-writable working directory, or is given a path whose final component can be swapped, an attacker can redirect registration to another file. The application can then append attacker-chosen account-record data to and change the mode of that target. File locking does not prevent link substitution before the open.
- **Fix:** Keep the store in a fixed, trusted directory; reject symbolic links for every path component; open the final component with no-follow semantics; validate the opened file's type, owner, and identity; and use directory-relative secure filesystem operations where available. Do not run this CLI elevated with a store path or working directory controlled by another user.

### 5. Credential-file permissions are not securely enforced on non-POSIX filesystems

- **Severity:** Medium
- **CWE:** CWE-732 — Incorrect Permission Assignment for Critical Resource
- **Evidence:** `UserAccountApp.java:205-212` applies owner-only mode only through the POSIX permission view and silently does nothing when that view is unsupported. The file is created earlier at `UserAccountApp.java:126-128` without platform-specific restrictive creation attributes or a postcondition check.
- **Why this matters:** On Windows and other non-POSIX providers, the credential verifier file simply inherits ambient ACLs. In a shared or permissively configured directory, other principals may be able to read verifiers for offline cracking or modify records to take over an account or deny service.
- **Fix:** Create the file atomically with restrictive attributes supported by the active filesystem. On Windows, set and verify an ACL granting only the intended account (and required administrators/system principals) access. Fail closed, or prominently require a presecured store, when adequate permissions cannot be established. Validate owner, type, and permissions for existing files before reading them.

### 6. Password input has no maximum length

- **Severity:** Low
- **CWE:** CWE-400 — Uncontrolled Resource Consumption
- **Evidence:** `UserAccountApp.java:85-100` reads until newline or EOF and repeatedly doubles the password buffer at `UserAccountApp.java:92-95` without enforcing a maximum.
- **Why this matters:** An unbounded standard-input stream can make the process continually allocate and copy memory until heap exhaustion. A very large password is also copied into KDF-related objects. In this CLI the impact is normally confined to the invoking process, which lowers severity, but the method is unsafe if reused behind an automated or remotely fed interface.
- **Fix:** Set a generous explicit maximum (for example, at least 64 characters and high enough for passphrases), stop reading once exceeded, clear temporary buffers, and return a generic validation error. Keep the maximum consistent between registration and authentication.

### 7. The fallback password reader can expose typed passwords

- **Severity:** Low
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Evidence:** `UserAccountApp.java:65-73` uses the non-echoing `Console.readPassword` only when a console is available. When it is unavailable, `UserAccountApp.java:75-80` reads ordinary standard input without disabling echo, while explicitly treating IDE use as a supported fallback.
- **Why this matters:** In IDE consoles, wrappers, or terminal configurations where ordinary input is displayed or logged, the password may be visible on screen, captured in console history, or retained by surrounding tooling.
- **Fix:** Use a platform-supported no-echo terminal mechanism, accept password input only from an explicitly noninteractive protected stream, or refuse interactive fallback with a clear instruction. Do not silently treat an echoing IDE console as secure password entry.

### 8. Unknown usernames are distinguishable through authentication timing

- **Severity:** Low
- **CWE:** CWE-208 — Observable Timing Discrepancy
- **Evidence:** `UserAccountApp.java:163-166` returns immediately when no record matches, whereas a known username performs an expensive PBKDF2 derivation at `UserAccountApp.java:167-169`.
- **Why this matters:** Although the visible error is generic, the large work difference allows a caller able to make repeated measurements to enumerate registered usernames. The local-only interface limits exposure, but the package-private store can also be reused by other code without preserving that assumption.
- **Fix:** When the username is absent, derive against a fixed dummy salt and the same current work factor before returning failure. Keep the externally visible message and processing path equivalent for unknown usernames and wrong passwords.

## File-by-file notes

- `UserAccountApp.java`: Implements argument parsing, password input, registration/authentication, PBKDF2 verifier generation, credential serialization, locking, permission changes, and record parsing. All findings arise here.
- `UserAccountAppTest.java`: Exercises core success/failure and plaintext-storage properties. It does not test weak-password rejection, input/store bounds, link handling, permissions on unsupported filesystems, KDF parameter policy, or timing equivalence.
- `README.md`: Documents build/use and accurately states that owner-only permissions are limited to POSIX filesystems. Its production cautions do not enforce the missing controls.
- `prompt.txt`, `cyber_prompt.txt`: Task descriptions; not executable application code.
- `return.txt`, `cyber_return.txt`, `result.md`: Prior tool/run transcripts and metadata; not executable application code. Password-looking values in the transcript are test fixtures, not identified live secrets.
- `prompt_hash.txt`: A task-content digest; no executable behavior.

## Skills applied

- `performing-cryptographic-audit-of-application` — applied to algorithm choice, KDF cost, salt and RNG quality, verifier length, hardcoded-secret checks, comparison behavior, and sensitive-buffer handling.
- `performing-thick-client-application-penetration-test` — applied to local credential storage, filesystem access and permissions, plaintext exposure, authentication behavior, and input validation.

No closer specialized library skill matched bounded credential-file parsing, symbolic-link safety, portable filesystem ACL enforcement, or username timing behavior. Those behaviors were additionally reviewed against general OWASP/CWE secure-design guidance.

## Reference

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
