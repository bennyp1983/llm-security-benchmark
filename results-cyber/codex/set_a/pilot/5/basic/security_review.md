# Security Review: Employee Portal Authentication

## Executive summary

The review found four security issues: three medium-severity findings and one low-severity finding. The most important weaknesses are that newly generated PBKDF2-HMAC-SHA-256 hashes use only 210,000 iterations while the parser permits hashes with as few as 100,000 iterations, and that attacker- or corruption-controlled credential-record parameters can force effectively unbounded CPU and memory consumption. Account creation and credential-store updates also contain a cross-process time-of-check/time-of-use race. Finally, protection of the password-hash file silently falls back to platform defaults when POSIX permissions are unavailable.

The implementation otherwise makes several sound security choices: it uses a unique 128-bit salt from `SecureRandom`, PBKDF2-HMAC-SHA-256, constant-time hash comparison, defensive copying, generic login failures, a dummy hash for unknown users, atomic file replacement when supported, and clearing of password arrays.

## Scope and file understanding

The review covered all authored code and supporting project files in the folder. Files under `out/` are compiled forms of the corresponding Java sources and do not define additional source-level behavior. The prompt/result `.txt` and `.md` artifacts are task metadata rather than application code.

| File | Purpose and security-relevant behavior |
|---|---|
| `src/main/java/com/example/portal/AuthenticationService.java` | Normalizes usernames, retrieves records, verifies passwords, checks enabled status, performs a dummy hash for missing users, and clears supplied password arrays. |
| `src/main/java/com/example/portal/CredentialStore.java` | Defines credential lookup and save operations. |
| `src/main/java/com/example/portal/EmployeeRecord.java` | Immutable value object for usernames, status, KDF iterations, salts, and password hashes; clones sensitive byte arrays. |
| `src/main/java/com/example/portal/FileCredentialStore.java` | Parses and serializes the local credential file, validates record fields, creates temporary files, replaces the store, and attempts to apply owner-only POSIX permissions. |
| `src/main/java/com/example/portal/PasswordHasher.java` | Generates salts with `SecureRandom`, derives PBKDF2-HMAC-SHA-256 hashes, compares hashes in constant time, and clears temporary password/hash material. |
| `src/main/java/com/example/portal/PortalApplication.java` | Selects the credential path from the environment, dispatches login or account creation, validates usernames/password length, and reads passwords from a hidden console unless visible input is explicitly enabled. |
| `src/test/java/com/example/portal/AuthenticationTests.java` | Exercises valid, invalid, unknown, and disabled-account authentication plus weak-iteration rejection and non-storage of the plaintext test password. |
| `build.sh` | Compiles main and test Java sources into `out/`. |
| `test.sh` | Rebuilds the application and runs the assertion-based test class. |
| `README.md` | Documents operation, credential-file location, visible-password opt-in, filesystem protection assumptions, and production hardening gaps. |

## Findings

### 1. Medium — Insufficient password-hash work factor (CWE-916)

**Evidence:** `src/main/java/com/example/portal/PasswordHasher.java:10`, `src/main/java/com/example/portal/PasswordHasher.java:27`, `src/main/java/com/example/portal/PasswordHasher.java:32-38`, and `src/main/java/com/example/portal/FileCredentialStore.java:63-66`.

New passwords are hashed with 210,000 PBKDF2-HMAC-SHA-256 iterations, and persisted records with only 100,000 iterations are accepted. Both values are below the current OWASP recommendation of 600,000 iterations for PBKDF2-HMAC-SHA-256. If the credential file is disclosed, the reduced work factor makes offline password guessing materially cheaper. The authentication path also has no mechanism to upgrade an older record after a successful login, so weak records remain weak indefinitely.

**Fix:** Prefer Argon2id with parameters tuned to the deployment (OWASP's baseline is 19 MiB memory, 2 iterations, and parallelism 1). If PBKDF2 is required, raise the creation and acceptance policy to at least 600,000 HMAC-SHA-256 iterations after benchmarking the target host, store an algorithm/version identifier, and rehash successfully authenticated records whose parameters are below the current policy. See the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### 2. Medium — Credential records can trigger unbounded CPU and memory consumption (CWE-400)

**Evidence:** `src/main/java/com/example/portal/FileCredentialStore.java:44`, `src/main/java/com/example/portal/FileCredentialStore.java:47`, `src/main/java/com/example/portal/FileCredentialStore.java:60-65`, `src/main/java/com/example/portal/AuthenticationService.java:34`, and `src/main/java/com/example/portal/PasswordHasher.java:35-38`.

The parser enforces minimums but no maximums. An iteration count up to `Integer.MAX_VALUE` is accepted and then passed directly to `PBEKeySpec` whenever that username authenticates, which can monopolize CPU for an extreme period. The store is also loaded wholesale with `Files.readAllLines`, while individual lines and Base64-decoded salt/hash fields have no size ceiling. A malformed, corrupted, or attacker-replaced records file can therefore exhaust heap memory during any lookup or save. Although modifying the credential store already requires crossing an important filesystem trust boundary, the application should not let persisted data select unbounded computational or allocation costs.

**Fix:** Stream the file with a strict total-size, record-count, and line-length limit. Before decoding, reject oversized Base64 fields; after decoding, require exact supported salt and hash lengths rather than minimum lengths. Define a tested maximum iteration count and reject values outside the supported policy range before constructing `PBEKeySpec`. Treat violations as a bounded configuration error and emit an operational alert without including credential contents.

### 3. Medium — Account creation and file updates are not atomic across processes (CWE-367)

**Evidence:** `src/main/java/com/example/portal/PortalApplication.java:70-82` and `src/main/java/com/example/portal/FileCredentialStore.java:28-36`.

Account creation checks that a username is absent and later calls `save` as a separate operation. `save` itself performs a read-modify-write sequence. The `synchronized` modifiers protect only one `FileCredentialStore` instance inside one JVM; they do not coordinate separate CLI invocations or multiple store instances. Two concurrent `--add-user` operations can both pass the absence check, after which one can overwrite the other's newly created credentials. Concurrent saves for different users can also operate on stale snapshots and lose an update. This can corrupt account state and, where an attacker can race a legitimate provisioning operation, leave the attacker-selected password on the account.

**Fix:** Move “create only if absent” into the credential-store API and perform the check plus update under one inter-process lock, such as a lock on a separate stable lock file using `FileChannel.lock()`. Hold the lock across rereading the latest file, validating absence, writing, and atomically replacing the store. Do not silently upsert from the account-creation path; return a duplicate-account result. A transactional database with a unique username constraint is preferable for concurrent deployments.

### 4. Low — Credential-file protection silently degrades on non-POSIX filesystems (CWE-732)

**Evidence:** `src/main/java/com/example/portal/FileCredentialStore.java:95-103` and `src/main/java/com/example/portal/FileCredentialStore.java:109-115`.

The store contains password hashes and account status, but owner-only protection is implemented solely with POSIX permissions. `UnsupportedOperationException` is swallowed, leaving the file protected only by inherited platform defaults. The read path also does not validate that an existing store has an acceptable owner, ACL/mode, and regular-file type before trusting it. On an unsupported or permissively configured filesystem, another local principal may be able to read hashes for offline cracking or alter records to choose a password and enabled status.

**Fix:** Create the temporary file with restrictive attributes at creation time. On Windows or other non-POSIX platforms, set and verify an owner-only ACL using the platform's supported attribute view. Before every read, reject symbolic links/non-regular files and verify owner and effective permissions. Fail closed with an actionable configuration error if the application cannot establish or verify the required protection; do not silently continue.

## Reviewed concerns that did not produce findings

- **Cryptography:** No deprecated hashes/ciphers, insecure modes, hardcoded production secrets, predictable randomness, or non-constant-time hash comparisons were found. Salts are generated per record with `SecureRandom` and are 16 bytes long.
- **Password handling:** Interactive passwords are hidden by default; visible input requires an explicit flag. Password character arrays and derived candidates are cleared. The literal password in `AuthenticationTests.java:12` is test data, not a production credential.
- **Authentication responses:** Unknown users, disabled users, and bad passwords all receive denial responses without exposing the specific reason. The dummy hash reduces the normal same-policy username timing signal. Records with varying KDF costs could reintroduce timing differences; enforcing and upgrading to one current KDF policy as recommended in finding 1 limits that risk.
- **Input and command execution:** Usernames are normalized and allowlisted before account creation. No SQL, OS-command execution, unsafe deserialization, XSS, SSRF, or network/TLS code exists in scope.
- **Administrative trust boundary:** `--add-user` has no application-level administrator login. In the documented local-console design, authorization is delegated to the operating system's ability to write the records file. The command must not be exposed through a service wrapper, `sudo` rule, setuid mechanism, or shared service account without a separate administrative authorization control.
- **Online guessing:** The application performs one login attempt per invocation and contains no persistent throttling. For the stated local-console design, operating-system access is the primary boundary. Any remote or long-running wrapper must add durable rate limiting, lockout/step-up controls, and monitoring before deployment.
- **Build scripts:** Shell syntax is valid. Their unquoted `find` command substitutions are fragile for source paths containing whitespace, but the fixed repository paths do not make this a demonstrated security boundary bypass.

## Skills applied

- `performing-cryptographic-audit-of-application` — applied to password hashing, algorithm selection, KDF work factors, salt entropy, hardcoded-secret checks, password handling, and constant-time comparison.

No sibling library skill clearly matched this local Java application's credential-file bounds/permissions or its cross-process provisioning race. Those behaviors were reviewed using general OWASP/CWE secure-design knowledge, as required by the router workflow.

## Verification notes

- Every authored Java source, test, shell script, and README was reviewed.
- Shell scripts passed `bash -n` syntax validation.
- Java compilation/tests were not rerun because `java`, `javac`, and `javap` are unavailable in the review environment. Existing compiled `.class` outputs were not modified.
- This was a static, source-level review; deployment filesystem ACLs and any external wrapper around the console application were not available for validation.
