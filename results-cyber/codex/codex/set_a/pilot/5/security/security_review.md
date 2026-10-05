# Security Review

## Executive summary

The project is a small Java 17 employee-login demonstration. The review found seven security issues: two high, three medium, and two low severity. The most important problem is that the intended attempt limit does not survive a real portal invocation: `EmployeePortal` creates a new in-memory account store, authenticates once, and exits, so a new process begins with a fresh failure counter. The application also ships a working, universal default credential.

The password-hashing implementation has several good properties: it uses `SecureRandom`, a 128-bit per-password salt, PBKDF2-HMAC-SHA256, a 256-bit output, `MessageDigest.isEqual`, defensive array copies, and clearing of temporary password/derived-key buffers. Those controls do not eliminate the findings below.

## Findings

### SR-01 — High — Hard-coded production-accessible credential (CWE-798)

**Evidence:** `src/main/java/com/company/portal/EmployeePortal.java:26` embeds the password `ChangeMe-123!`; `src/main/java/com/company/portal/EmployeePortal.java:29` always creates the predictable `employee` account from it. The same credential is advertised at `README.md:17`.

**Why this is a problem:** Every copy of the program starts with the same known username and password. If the demonstration entry point is deployed or reused without modification, anyone who can reach it can authenticate. Hashing the value at startup does not protect it because the plaintext credential is present in source, bytecode, documentation, and repository history.

**Fix:** Remove the seed credential and fail closed until an account is provisioned through an authenticated administrative process. Load any bootstrap secret from a secrets manager or one-time deployment channel, force immediate rotation, and disable it after first use. Remove the exposed value from documentation and repository history; if it has ever protected a real system, rotate it immediately. Add repository secret scanning to CI and pre-commit checks.

### SR-02 — High — Attempt limit is reset on every real portal invocation (CWE-307)

**Evidence:** `src/main/java/com/company/portal/EmployeePortal.java:24` constructs a new `InMemoryEmployeeRecordStore` on every start, `src/main/java/com/company/portal/EmployeePortal.java:29` inserts a fresh record whose counters begin at zero, and `src/main/java/com/company/portal/EmployeePortal.java:41` performs only one authentication before `main` ends. The failure state exists only in the process-local map declared at `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:14`.

**Why this is a problem:** The tests call the same service repeatedly, but the actual entry point accepts only one attempt per process. An attacker can relaunch the program for every guess; each launch recreates the account and discards all prior failures. Process restarts similarly clear every lock. Thus the advertised five-attempt control does not restrict consecutive attempts in the program's real execution path.

**Fix:** Store password records, failure counters, observation-window data, and lock expiration in a durable repository. Perform read/check/update atomically in a transaction or locked row shared by every application instance. Run the portal as a persistent service (or otherwise reuse that durable state) and add an integration test that performs attempts across process/service restarts and multiple instances.

### SR-03 — Medium — Account-only throttling permits password spraying and unbounded unknown-account work (CWE-307)

**Evidence:** `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:24-28` performs a full PBKDF2 operation for every unknown username and returns without recording an attempt. For known users, `src/main/java/com/company/portal/auth/EmployeeRecord.java:38-42` counts failures only on that employee record. There is no caller-, source-, device-, or global attempt limit in `src/main/java/com/company/portal/auth/AuthenticationService.java:31-33`.

**Why this is a problem:** An attacker can rotate through nonexistent or many valid usernames indefinitely, enabling password spraying and credential-stuffing attacks without reaching any individual account threshold. Requests for nonexistent users also consume the deliberately expensive KDF on every attempt, enabling CPU exhaustion. The `synchronized` authentication method at `InMemoryEmployeeRecordStore.java:21` serializes this work and can amplify availability impact in a service deployment.

**Fix:** Retain per-account controls, but add layered throttles keyed to trusted source identity (for example, validated client IP/device), account, and a global service budget. Persist/shared counters across instances, use bounded queues and concurrency, introduce progressive delays or risk challenges, and monitor distributed attempts. Do not remove the dummy hash solely to address load, because it helps prevent username enumeration; bound requests around it instead.

### SR-04 — Medium — Fixed account lockout can be weaponized for denial of service (CWE-400)

**Evidence:** `src/main/java/com/company/portal/auth/EmployeeRecord.java:38-42` lets any sequence of failed passwords set `lockedUntil`; `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:30-31` then rejects even a correct password until expiry. The entry point configures a five-attempt, fifteen-minute lock at `src/main/java/com/company/portal/EmployeePortal.java:34-35`.

**Why this is a problem:** Anyone who knows or guesses an employee username can intentionally submit five bad passwords and deny that employee access for fifteen minutes. Repeating the sequence after expiry creates sustained account-level denial of service. The code has no recovery path, trusted-device exception, adaptive challenge, or source-level control to make this expensive for the attacker.

**Fix:** Use a balanced, risk-based policy: short progressive/exponential delays, an observation window, per-source throttling, MFA or CAPTCHA escalation, user notification, and a secure recovery path. Ensure an attacker cannot keep an account unavailable cheaply, and alert on repeated targeted lockouts.

### SR-05 — Medium — PBKDF2 work factor is below current guidance and cannot be upgraded per record (CWE-916)

**Evidence:** `src/main/java/com/company/portal/auth/PasswordHasher.java:14` fixes PBKDF2-HMAC-SHA256 at 210,000 iterations. `src/main/java/com/company/portal/auth/EmployeeRecord.java:9-13` stores only username, salt, hash, failure count, and lock expiry—there is no algorithm/version/work-factor metadata.

**Why this is a problem:** Current OWASP Password Storage guidance recommends 600,000 iterations for PBKDF2-HMAC-SHA256, subject to deployment-specific benchmarking. A 210,000-round hash gives an offline attacker materially more guesses per unit of hardware. Because the parameters are global and absent from each record, increasing the constant makes old hashes unverifiable and prevents gradual rehash-on-login migration.

**Fix:** Prefer a memory-hard password KDF such as Argon2id with parameters benchmarked for the deployment. If FIPS requirements mandate PBKDF2, benchmark and raise PBKDF2-HMAC-SHA256 to an appropriate current work factor (at least the applicable policy baseline). Store a version, algorithm, and cost parameters with every hash, accept legacy records during migration, and rehash them after successful authentication.

### SR-06 — Low — Locked-account path creates an observable timing discrepancy (CWE-208)

**Evidence:** `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:25-27` hashes a candidate for an unknown account and `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:37` hashes it for an unlocked known account, but `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:30-31` returns immediately for a locked account. `src/main/java/com/company/portal/auth/AuthenticationResult.java:6-7` also exposes different internal results for invalid and locked states.

**Why this is a problem:** Although `EmployeePortal.java:42-45` prints a generic denial string, a remote integration can distinguish the much faster locked-account path by repeated timing measurements; an incautious caller can also expose the distinct enum directly. This leaks account state and can help an attacker verify targeted lockouts or account activity.

**Fix:** Keep externally visible responses and status codes identical and ensure all failure paths perform comparable bounded work, including the locked path. Keep detailed lock state only in trusted internal telemetry. Add statistical timing tests at the actual network boundary; do not rely solely on identical messages.

### SR-07 — Low — Authentication failures and lockouts are not security-audited (CWE-778)

**Evidence:** `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java:25-46` returns for unknown users, locked accounts, successes, and failures without emitting an audit event. `src/main/java/com/company/portal/auth/AuthenticationService.java:31-34` only delegates and returns a result, while `src/main/java/com/company/portal/EmployeePortal.java:43-45` prints only the immediate outcome.

**Why this is a problem:** Operators cannot detect password spraying, targeted lockout denial of service, repeated failures, or suspicious successes, and cannot reconstruct an authentication incident. Ordinary console output is not a durable, structured, integrity-protected audit trail.

**Fix:** Emit structured security events for successes, failures, lockouts, unlocks, and throttling decisions to a protected centralized sink. Include timestamp, correlation ID, account identifier in a privacy-safe form, trusted source/device context, and outcome; never log plaintext passwords or password hashes. Alert on distributed spraying and repeated lockouts, and define retention/access controls.

## File-by-file review notes

- `pom.xml`: Minimal Java 17 Maven descriptor with no third-party dependencies or plugin configuration. No dependency vulnerability surface is declared.
- `src/main/java/com/company/portal/EmployeePortal.java`: Interactive console bootstrap; creates the demo account, configures the lockout, reads hidden input, authenticates once, emits a generic result, and clears the entered password array. It is the source of SR-01, SR-02, and part of SR-04.
- `src/main/java/com/company/portal/auth/AuthenticationResult.java`: Defines success, invalid-credential, and locked-account outcomes. Its distinct locked state contributes to SR-06 if exposed by another caller.
- `src/main/java/com/company/portal/auth/AuthenticationService.java`: Validates lockout configuration and delegates authentication with a clock. It lacks broader throttling and audit hooks (SR-03 and SR-07).
- `src/main/java/com/company/portal/auth/EmployeeRecord.java`: Holds defensive copies of salt/hash plus mutable failure and lock state. Its per-record fixed lock logic contributes to SR-03 and SR-04, and it lacks KDF metadata (SR-05).
- `src/main/java/com/company/portal/auth/EmployeeRecordStore.java`: Defines the authentication-store contract and explicitly requires atomic read/check/update behavior. No issue was found in the interface itself.
- `src/main/java/com/company/portal/auth/InMemoryEmployeeRecordStore.java`: Provides synchronized, case-normalized lookup, dummy hashing for unknown users, constant-time password verification through `PasswordHasher`, and per-account lockout. It contains the process-local state and failure-path issues in SR-02, SR-03, SR-04, SR-06, and SR-07.
- `src/main/java/com/company/portal/auth/PasswordHasher.java`: Generates random salts and derives/compares PBKDF2 hashes while clearing temporary values. Its work factor and lack of versioned parameters are covered by SR-05; no weak RNG, weak digest, non-constant-time hash comparison, or salt-reuse issue was found.
- `src/test/java/com/company/portal/auth/AuthenticationServiceTest.java`: Dependency-free assertions cover case-insensitive login, threshold lockout, expiry, reset, and unknown usernames. Test-only passwords are fixtures, not deployed credentials. The test does not exercise the real entry point, restart persistence, global/source throttling, lockout abuse, timing, or audit logging.
- `target/classes/**/*.class` and `target/test-classes/**/*.class`: Generated Java bytecode corresponding to the reviewed source and test files; no separate handwritten logic was available in these artifacts. Findings are cited against maintainable source lines.

`README.md`, `prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt`, `cyber_prompt.txt`, and `cyber_return.txt` are documentation or task/run artifacts rather than executable code. They were inspected for security-relevant configuration or exposed credentials; the README's advertised demo credential is included in SR-01.

## Skills applied

- `implementing-secret-scanning-with-gitleaks` — applied to source, documentation, configuration, and task artifacts for embedded credentials; the installed environment did not provide the Gitleaks executable, so the repository was inspected directly using the skill's detection/remediation criteria.
- `performing-cryptographic-audit-of-application` — applied to the KDF algorithm and cost, salt generation, RNG, comparison, buffer handling, parameter storage, secrets, dependencies, and absence of TLS/configured encryption surfaces.
- `implementing-api-rate-limiting-and-throttling` — applied to brute-force protection, atomicity, per-account versus per-source/global limits, cross-instance persistence, and resource-exhaustion behavior. Although this program is a console application rather than an HTTP API, the skill explicitly covers authentication brute force and credential stuffing, and its control criteria apply to the reusable authentication service.

General OWASP/CWE review was additionally used for security-relevant behaviors without a closer matching library skill: username normalization and input handling, in-memory state/storage, error/result disclosure, denial-of-service implications of lockout, audit logging, and generated/build artifacts. No SQL, command execution, file/path access, deserialization, network/TLS, session, JWT, authorization, or third-party dependency behavior exists in the reviewed code.

## Verification and limitations

- Every executable source and test file plus the build descriptor was read line by line; non-code artifacts were inspected, and generated bytecode was mapped to its source counterpart.
- Secret patterns and all cryptographic/authentication call sites were manually traced. No additional API keys, tokens, private keys, database credentials, or network endpoints were found.
- The existing compiled test runner could not be executed in the review environment because the Java runtime is unavailable. The review is therefore static; no files other than this report were created or modified.
