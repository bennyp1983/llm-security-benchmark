# Security review: Administrator portal

Review date: 2026-09-09

## Executive summary

The application has a small, understandable attack surface and several sound controls: passwords are salted with `SecureRandom`, hashed with PBKDF2-HMAC-SHA-256, compared with `MessageDigest.isEqual`, cleared from mutable buffers, and never written to the audit log; unknown users receive a dummy KDF operation; JSON control characters are escaped; audit failure denies authentication; and newly created POSIX audit files receive owner-only permissions.

Eight vulnerabilities remain: seven medium-severity findings and one low-severity finding. The most important trust-boundary problem is that the invoking user can select both the credential database and audit log through environment variables. This permits an invoker to substitute credentials and redirect the evidence of the resulting login. File ownership and permissions are also not validated independently of that issue. These findings become directly security-impacting when this CLI is used to gate privileged administrator operations, as its design and comments intend. In the current snapshot, `showAdminFunctions` is only a placeholder that prints messages, so present-day post-authentication impact is limited.

## Scope and file understanding

| File(s) | Purpose and security-relevant behavior |
| --- | --- |
| `admin-portal` | Shell launcher. Builds all main Java sources into `build/classes` and starts `AdminPortal`, forwarding arguments. |
| `src/main/java/com/example/adminportal/AdminPortal.java` | CLI entry point. Selects credential/audit paths from the environment, reads a username and password, dispatches authentication or password-hash generation, clears password arrays, and gates administrator functions. |
| `src/main/java/com/example/adminportal/AuthenticationService.java` | Looks up a stored hash, performs real or dummy password verification to reduce username timing disclosure, records every result, and fails closed if logging fails. |
| `src/main/java/com/example/adminportal/CredentialStore.java` | Loads an immutable username-to-password-hash map from a Java properties file. It validates only basic key/value shape. |
| `src/main/java/com/example/adminportal/PasswordHasher.java` | Generates and verifies versioned PBKDF2-HMAC-SHA-256 password hashes with random 16-byte salts and constant-time hash comparison. |
| `src/main/java/com/example/adminportal/AuditLogger.java` | Creates/appends a JSON Lines authentication audit file, escapes fields, uses a process/file lock, forces writes to storage, rejects final-component symbolic links, and attempts POSIX mode `0600`. |
| `src/test/java/com/example/adminportal/AdminPortalTest.java` | Dependency-free tests for password verification, successful/failed/unknown-user auditing, log escaping, password non-disclosure, and fail-closed behavior. The hardcoded password is test data, not a production secret. |
| `config/admin-credentials.properties.example` | Non-secret credential-file template containing an intentionally invalid placeholder hash. |
| `build/classes/**`, `build/test-classes/**`, and `build/*.list` | Generated class files and compiler source lists corresponding to the reviewed sources. The launcher recompiles main sources before normal execution. |
| `README.md` | Operator instructions and deployment warnings, including external rate limiting, log rotation, and credential-file permissions. Documentation does not itself enforce those controls. |

No third-party dependency manifest is present; the code uses Java 17 platform APIs only. The remaining `.txt` and prior `.md` files are task/result metadata rather than application code.

## Findings

### SR-01 — Caller-controlled credential and audit paths undermine the authentication trust boundary

- **Severity:** Medium
- **CWE:** CWE-15 — External Control of System or Configuration Setting
- **Evidence:** `src/main/java/com/example/adminportal/AdminPortal.java:36-43`

`ADMIN_CREDENTIALS_FILE` and `ADMIN_AUDIT_FILE` are accepted directly from the process environment. For a command-line program, the invoking user normally controls that environment. An invoker can therefore point the portal at a properties file containing a hash for a password they know, point auditing at a file they control, authenticate successfully, and reach `showAdminFunctions`. The audit logger's fail-closed behavior does not help because the attacker can supply a writable audit destination. This is a full application-level authentication bypass once real privileged functions are added. Current impact is limited because the checked-in administrator function is a placeholder.

**Fix:** Do not take security-critical paths from the environment in the privileged execution path. Resolve them from a trusted, administrator-owned configuration or fixed allowlisted directory. If overrides are needed for development, require an explicit non-production mode that cannot enable privileged functions. Independently validate the canonical file/directory ownership, type, link count, and permissions before loading credentials or recording audit data. If a privileged wrapper invokes this process, it must also construct a clean environment rather than inherit caller variables.

### SR-02 — Credential-store ownership, type, and permissions are not validated

- **Severity:** Medium
- **CWE:** CWE-732 — Incorrect Permission Assignment for Critical Resource
- **Evidence:** `src/main/java/com/example/adminportal/CredentialStore.java:20-23`; `src/main/java/com/example/adminportal/AdminPortal.java:41`

The credential file is opened with `Files.newBufferedReader` and trusted immediately. The code does not reject a symbolic link, require a regular file, verify the expected owner, or reject group/world-writable permissions. Even after removing the environment override in SR-01, a less-privileged local user who can replace or modify the configured file can install an attacker-chosen password hash and pass authentication. The README's instruction to protect the file is useful operational guidance but is not an enforced security boundary.

**Fix:** Provision the file as owner-only (`0600` on POSIX) in a directory that untrusted users cannot modify. Before reading it, use a no-follow open where supported and verify attributes without following links: regular-file type, expected owner, no group/other write access (preferably no group/other access at all), and—where available—an acceptable hard-link count. Apply equivalent ACL validation on non-POSIX systems. Keep the file descriptor and validated object coupled to avoid a check/use race.

### SR-03 — Existing audit targets are trusted before their owner and permissions are established

- **Severity:** Medium
- **CWE:** CWE-732 — Incorrect Permission Assignment for Critical Resource
- **Evidence:** `src/main/java/com/example/adminportal/AuditLogger.java:41-45`; `src/main/java/com/example/adminportal/AuditLogger.java:57-68`; `src/main/java/com/example/adminportal/AuditLogger.java:80-98`

The logger correctly rejects a final-component symbolic link, but an already existing non-symlink file is accepted without checking whether it is regular, who owns it, whether it has other hard links, or whether other principals can alter it. Permission restriction happens only after an event has been appended. Changing mode does not change an attacker-owned file's owner, so an attacker who pre-created the target can retain the ability to forge, truncate, or delete the audit trail. Parent-directory ownership and link traversal are also not validated.

**Fix:** Place logs in a pre-provisioned, administrator-owned directory and validate every relevant path component. For an existing file, verify regular-file type, expected owner, restrictive ACL/mode, and link count before the first write; reject rather than repair an untrusted owner. Set restrictive permissions before writing. Prefer a platform audit service or append-only remote collector for stronger integrity. Use descriptor-relative/secure-directory operations where available to minimize path races.

### SR-04 — Passwords can be echoed when no Java `Console` is available

- **Severity:** Medium
- **CWE:** CWE-522 — Insufficiently Protected Credentials
- **Evidence:** `src/main/java/com/example/adminportal/AdminPortal.java:45-57`; `src/main/java/com/example/adminportal/AdminPortal.java:83-90`

When `System.console()` is null, authentication reads the password with `Scanner.nextLine()` after displaying a normal password prompt; hash generation does the same. Redirected standard input is an intentional automation feature, but `System.console()` can also be null in IDE consoles, process supervisors, and some pseudo-terminal arrangements where typed input is echoed or captured. The program does not distinguish redirected automation from an interactive but unprotected input channel, so an administrator can expose a plaintext password on screen, in terminal scrollback, or in supervisor logs.

**Fix:** Fail with a clear message when no secure console exists unless an explicit non-interactive mode is selected. In that mode, accept the secret through a deliberately provisioned protected channel (for example, a restricted file descriptor or secret manager), do not print an interactive password prompt, and document the channel's confidentiality requirements. Avoid environment variables and command-line arguments for passwords.

### SR-05 — Online password guessing is unrestricted

- **Severity:** Medium
- **CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts
- **Evidence:** `src/main/java/com/example/adminportal/AuthenticationService.java:19-26`; `src/main/java/com/example/adminportal/AdminPortal.java:68-74`

Every invocation performs authentication and there is no persistent retry counter, backoff, lockout, or other throttling control. PBKDF2 slows each guess but is not an online attempt limit, and separate processes can run concurrently. An attacker able to reach the CLI or a service wrapper can make unlimited guesses against an administrator account. The README delegates rate limiting to an unspecified service or gateway, but the repository contains no such enforced boundary.

**Fix:** Put authentication behind a trusted, shared rate limiter that persists across processes and limits attempts per account and per source, with bounded exponential backoff or temporary lockout and alerting. Design it to resist parallel-attempt bypass and denial-of-service abuse. If this CLI remains directly callable, store protected attempt state outside each short-lived process.

### SR-06 — Password provisioning permits weak single-factor administrator passwords

- **Severity:** Medium
- **CWE:** CWE-521 — Weak Password Requirements
- **Evidence:** `src/main/java/com/example/adminportal/AdminPortal.java:92-98`

The only password-quality control is a minimum of 12 Java characters. There is no check against commonly used, context-specific, or compromised passwords. Consequently, easily guessed values that satisfy the length check can protect the single-factor administrator account. Current NIST SP 800-63B guidance requires at least 15 characters for single-factor passwords and comparison against a blocklist.

**Fix:** Require at least 15 Unicode code points for this single-factor flow, permit long passwords (at least 64 characters), normalize Unicode consistently, and reject the complete candidate when it appears in a locally maintained common/compromised-password blocklist. Do not add arbitrary character-class composition rules. Prefer adding a phishing-resistant second factor for actual administrator access. See [NIST SP 800-63B password verifier requirements](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver).

### SR-07 — Generated and accepted PBKDF2 work factors are below current guidance

- **Severity:** Medium
- **CWE:** CWE-916 — Use of Password Hash With Insufficient Computational Effort
- **Evidence:** `src/main/java/com/example/adminportal/PasswordHasher.java:12-16`; `src/main/java/com/example/adminportal/PasswordHasher.java:40-49`

New hashes use 210,000 PBKDF2-HMAC-SHA-256 iterations, and verification accepts values as low as 100,000. These costs make offline guessing materially cheaper than current guidance if the credential file is copied. The algorithm, salt generation, output size, versioned encoding, and constant-time comparison are otherwise sound. OWASP currently recommends Argon2id for general password storage, or at least 600,000 PBKDF2-HMAC-SHA-256 iterations when PBKDF2 is required for FIPS-oriented deployments.

**Fix:** Prefer a maintained Argon2id implementation with parameters calibrated on production hardware. If the dependency-free/FIPS constraint requires PBKDF2-HMAC-SHA-256, benchmark an interactive-safe cost at or above the current 600,000-iteration baseline, raise the verification floor for newly provisioned credentials, and support rehash-on-success or a controlled migration for older hashes. Recalibrate periodically. See the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### SR-08 — Audit growth is unbounded and can exhaust storage

- **Severity:** Low
- **CWE:** CWE-400 — Uncontrolled Resource Consumption
- **Evidence:** `src/main/java/com/example/adminportal/AuditLogger.java:48-67`; `src/main/java/com/example/adminportal/AuthenticationService.java:24-26`

Every accepted or rejected attempt is durably appended, but the application enforces no maximum size, quota, retention, or rotation. Combined with unrestricted attempts, a reachable attacker can grow the file until its filesystem is exhausted, potentially affecting this application and unrelated services. External rotation is suggested in the README but is not supplied or verified by the repository.

**Fix:** Send events to a managed logging facility with quotas and retention, or implement safe rotation with bounded total storage and monitoring. Keep failure semantics explicit: do not silently grant access when logging is unavailable. Rate limiting from SR-05 reduces amplification but does not replace storage limits.

## Skills applied

- `review-code-for-security-vulnerabilities` — routing workflow used to inventory every source file, identify security-relevant behavior, select specialized reviews, and verify coverage.
- `performing-cryptographic-audit-of-application` — applied to password hashing, salts, randomness, KDF cost, comparison, hardcoded-secret checks, and password-memory handling.

Authentication design, password input, file/path trust, file permissions, audit integrity/availability, logging, and rate limiting had no clearly matching non-API application-security skill in the local library name/description search. They were therefore reviewed against general CWE and OWASP/NIST guidance as required by the router workflow.

## Checks that did not produce findings

- No plaintext production password, private key, API token, or other hardcoded secret was found. The test password and example placeholder are non-production fixtures.
- No SQL/database operations, network requests, TLS configuration, command execution from user input, object deserialization, templating, or browser-rendered output exists in scope.
- Username and audit reason fields are JSON-escaped, including line-breaking control characters, preventing JSONL log injection through those fields.
- Authentication gives a generic denial and uses a dummy password hash for unknown usernames, reducing user-enumeration differences in the normal path.
- Password hashes have random per-password salts and a versioned format; comparisons use `MessageDigest.isEqual`; mutable password and derived-key buffers are cleared where practical.
- Audit writes use a file lock, loop until the complete record is written, call `force(true)`, and deny authentication on logging failure.
- The launcher quotes its paths and arguments; no shell-command injection source was identified.

## Verification and limitations

This was a complete manual static review of the shell launcher, all main and test Java sources, configuration template, and generated-file relationship. The available environment did not contain `java`, `javac`, or `javap`, so the existing compiled classes and tests could not be independently executed or disassembled. The normal launcher recompiles the reviewed main sources before execution, which limits reliance on the checked-in main class artifacts. No application file was modified as part of the review; this report is the only created file.
