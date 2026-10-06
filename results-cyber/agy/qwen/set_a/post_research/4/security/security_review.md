# Security Review: Account Registration and Authentication CLI

## 1. Executive Summary
A static application security review was conducted on the account registration and authentication command-line application located in `/data/results/qwen/set_a/post_research/4/security/`. The application is written in Java 17 and provides offline user registration, credential verification, bearer session management, rate limiting, and maintenance operations backed by an embedded H2 SQL database.

The review was performed following the structured methodology defined in `review-code-for-security-vulnerabilities`, evaluating all source files, build scripts, dependency manifests, and database schema definitions against specialized security auditing skills and general OWASP Top 10 / Common Weakness Enumeration (CWE) standards.

**Overall Assessment:** No security vulnerabilities were identified in the codebase. The application demonstrates an exemplary security posture and defense-in-depth architecture. Notable verified controls include:
- Strict use of parameterized SQL queries (`PreparedStatement`) paired with database-level schema `CHECK REGEXP` constraints.
- Robust password hashing using Argon2id via Bouncy Castle, enforcing OWASP minimum work factor floors and capping maximum resource allocations to prevent denial-of-service.
- Defense against side-channel timing attacks via uniform dummy Argon2id derivations for unknown accounts, locked accounts, and malformed inputs.
- Atomic SQL-level dual-layer throttling (per-source kernel UID and per-account temporary lockout) resilient to concurrency races.
- Cryptographically strong (256-bit `SecureRandom`) session tokens stored exclusively as SHA-256 hashes and emitted with fully hardened RFC 6265 cookie attributes.
- Strict POSIX file and directory permission controls (`0600`/`0700`), link-traversal prevention (`NOFOLLOW_LINKS`), and fail-closed audit logging with per-process salted tag masking.
- Pinned dependency verification enforcing dual-mirror SHA-256 matching, published SHA-1 cross-checking, and digital signature validation.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/app/AccountStore.java` | Account persistence and lookup operations | Executes parameterized SQL inserts and selects; handles unique constraints without leaking account existence; enforces transactional audit logging before commit; bounds registration DoS via duplicate attempt charging; performs atomic password hash upgrades. |
| `src/main/java/app/AuditLog.java` | Append-only security event audit logger | Enforces owner-only (`0600`) POSIX permissions; prevents symlink hijacking with `NOFOLLOW_LINKS`; omits `CREATE` option on append to prevent umask fallback; escapes JSON fields; enforces 64 MiB size budget with rollover marker (`TRAIL_RETURED`). |
| `src/main/java/app/AuthService.java` | Credential verification and session orchestration | Enforces uniform failure responses (`INVALID_MESSAGE`); executes dummy Argon2id derivation on invalid/locked accounts and throttled requests for constant-time behavior; coordinates atomic rate limiting and session issuance. |
| `src/main/java/app/Config.java` | Environment and CLI option parser | Enforces `0700` permissions on data directories and `0600` on database/audit files; rejects paths containing symlink components; validates and zeroes database passwords in memory; validates Argon2 cost parameters against security floors. |
| `src/main/java/app/CookiePolicy.java` | Session cookie generation | Constructs RFC 6265 compliant `Set-Cookie` headers; unconditionally enforces `Secure`, `HttpOnly`, `SameSite=Strict`, explicit path validation, and bounded `Max-Age` / `Expires`. |
| `src/main/java/app/Db.java` | JDBC connection and schema management | Disables autocommit; configures lock timeouts (`SET LOCK_TIMEOUT 2000`); serializes database access via thread synchronization; applies rigorous DDL constraints (`CHECK REGEXP`) for defence-in-depth data validation. |
| `src/main/java/app/Digests.java` | Cryptographic hashing utility | Computes standard SHA-256 digests and lowercase hex encodings for high-entropy values and correlation tags; handles standard JCA exceptions safely. |
| `src/main/java/app/Gate.java` | Transactional audit gating proxy | Mediates audit event logging; fails closed by throwing `AuditException` to roll back state changes if audit records fail; generates non-reversible per-process salted correlation tags. |
| `src/main/java/app/InputPolicy.java` | Strict input validation trust boundary | Applies strict whitelisting, length bounding, and character set checks for email, username, and password; rejects normalization/trimming to prevent canonicalization bypasses; screens against reserved usernames. |
| `src/main/java/app/Main.java` | CLI interface and command controller | Reads passwords without terminal echo via `Console.readPassword`; caps byte reading streams (`readCapped`) to 4096 chars; prompts for session tokens via stdin (rejecting argv exposure); derives source identities from kernel UID (`/proc/self/status`). |
| `src/main/java/app/Maintenance.java` | Database housekeeping and state pruning | Purges expired and revoked sessions, elapsed rate limit buckets, and decayed account guards outside retention windows; catches housekeeping errors without disrupting caller operations. |
| `src/main/java/app/PasswordHasher.java` | Argon2id key derivation and verification | Implements RFC 9106 Argon2id using Bouncy Castle; validates parameter floors (19 MiB memory, t=2) and upper ceilings; enforces canonical Base64 and PHC string formats; executes constant-time digest comparison via `MessageDigest.isEqual`. |
| `src/main/java/app/Secrets.java` | Sensitive credential memory container | Encapsulates sensitive `char[]` data; provides explicit memory wiping (`close()`); overrides `toString()` to return `Secrets[redacted]` to prevent accidental leakage in logs and traces. |
| `src/main/java/app/SessionStore.java` | Bearer session lifecycle manager | Generates 256-bit CSPRNG tokens (`SecureRandom`); stores SHA-256 token digests; resolves sessions via `FOR UPDATE` row locks; enforces hard 8-hour expiry; supports account-wide session revocation. |
| `src/main/java/app/Throttle.java` | Rate limiting and account lockout store | Enforces per-source (10 attempts/300s) and per-account (5 failures/900s) rate limits using atomic SQL queries and row locks; manages sliding decay windows and self-healing lockouts. |
| `scripts/build.sh` | Clean build compilation script | Verifies jar integrity against `deps.lock` before compiling; compiles main source code under `-encoding UTF-8 -Xlint:all -Werror` into an isolated output directory. |
| `scripts/get-deps.sh` | Dependency resolution and verification | Downloads dependencies over TLS 1.2+; verifies pinned SHA-256 against `deps.lock`; validates mirror checksum agreement and published SHA-1; verifies archive readability, internal entries, and jar signatures. |
| `scripts/run.sh` | Execution entry point wrapper | Enforces `set -euo pipefail`; verifies dependency digests against `deps.lock`; dynamically rebuilds stale binaries; configures strict, minimal runtime classpaths without test dependencies. |
| `scripts/test.sh` | Test suite execution runner | Compiles and executes 12 standalone verification test suites without third-party test framework overhead; validates security bounds, error branches, and fail-closed behaviors. |
| `deps.lock` | Cryptographic dependency manifest | Pinned record of approved jar dependencies, specifying expected SHA-256 digests, Maven coordinates, expected archive entries, and digital signature requirements. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to inspect Argon2id parameters, RFC 9106 compliance, PHC string parsing, canonical Base64 decoding, CSPRNG salt generation (16 bytes), SHA-256 session token hashing, `MessageDigest.isEqual` constant-time verification, and in-memory buffer clearing in `PasswordHasher.java`, `SessionStore.java`, `Digests.java`, and `AuthService.java`.
- `exploiting-sql-injection-vulnerabilities`: Applied to review all SQL statements, JDBC query constructions, parameter binding mechanisms, DDL definitions, and H2 database configurations in `Db.java`, `AccountStore.java`, `Throttle.java`, and `SessionStore.java`.
- `testing-api-authentication-weaknesses`: Applied to audit credential authentication workflows, session issuance, constant-time dummy derivation pads, account lockout mechanics, credential upgrade flows, and error uniformity across `AuthService.java`, `AccountStore.java`, and `Main.java`.
- `performing-api-rate-limiting-bypass`: Applied to evaluate rate limiting architecture, source identification integrity (kernel UID), account failure counters, atomic SQL update queries, sliding window mechanics, and maintenance sweep interactions in `Throttle.java`, `AuthService.java`, and `Maintenance.java`.
- `testing-for-sensitive-data-exposure`: Applied to examine credential lifecycle in memory, terminal echo suppression, process listing exposure (`argv`), JSON audit log serialization, per-process salted tag masking, and exception handling in `Secrets.java`, `Gate.java`, `AuditLog.java`, `Main.java`, and `Config.java`.
- `performing-security-headers-audit`: Applied to verify RFC 6265 compliance of session cookies, ensuring compulsory assignment of `Secure`, `HttpOnly`, `SameSite=Strict`, path constraints, and server-controlled expiration in `CookiePolicy.java`.
- `testing-for-broken-access-control`: Applied to assess session resolution against server-side database state, token revocation integrity, row-level locking (`FOR UPDATE`), and operator session revocation in `SessionStore.java`, `AuthService.java`, and `Main.java`.
- General OWASP Top 10 / CWE Knowledge:
  - **Input Validation & Canonicalization (CWE-20, CWE-1284, OWASP A03:2021)**: Evaluated regex structures, surrogate pair checks, control character rejections, length bounds, and non-trimming policies in `InputPolicy.java`.
  - **Filesystem Permissions & Link Traversal (CWE-22, CWE-59, CWE-732)**: Evaluated POSIX file permission validations (`0600`/`0700`), link resolution checks (`LinkOption.NOFOLLOW_LINKS`), and atomic file operations in `Config.java` and `AuditLog.java`.
  - **Supply Chain Integrity (CWE-1357, CWE-494)**: Evaluated dependency verification pipelines, dual-mirror verification, SHA-256 cryptographic pinning, and signature checks in `scripts/get-deps.sh` and `deps.lock`.
  - **Audit Logging & Fail-Closed Design (CWE-778, CWE-754)**: Evaluated transactional audit write coupling, fail-closed rollback handling, and JSON injection prevention in `AuditLog.java` and `Gate.java`.

## 4. Summary of Findings
No vulnerabilities were found during this static security review.

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| None | No vulnerabilities identified | N/A | N/A | N/A |

## 5. Detailed Findings
No vulnerabilities were found during this static security review. All audited application logic, database schemas, cryptographic operations, and supporting scripts adhere to secure development best practices and robust defensive programming principles.

## 6. Verified Controls and Checks With No Finding
The following security controls and vulnerability checks were systematically verified across the codebase without identifying any exploitable weakness or deficiency:

- **SQL Injection Prevention (CWE-89):**
  - Verified that all queries across `AccountStore.java`, `Throttle.java`, and `SessionStore.java` utilize `java.sql.PreparedStatement` with typed parameter binding (`setString`, `setLong`, `setInt`).
  - Verified that dynamic SQL concatenation is strictly limited to compile-time constant predicate strings (`email = ?`, `username = ?`, `id = ?`) in `AccountStore.java` lines 165-174 and `AuthService.java` line 181.
  - Verified that DDL statements in `Db.java` use fixed text blocks, with format parameters restricted to integer constants from `PasswordHasher.java` (lines 80-83).
  - Verified that DDL definitions enforce redundant database-level `CHECK REGEXP` constraints on emails, usernames, and password hash formats (`Db.java` lines 60-79).

- **Password Storage & Cryptographic Primitives (CWE-916, CWE-328, CWE-330, RFC 9106):**
  - Verified in `PasswordHasher.java` (lines 77-90) that Argon2id key derivation enforces OWASP work factor minimums: memory >= 19,456 KiB, iterations >= 2, parallelism >= 1.
  - Verified that maximum resource consumption is strictly capped (memory <= 1,048,576 KiB, iterations <= 20, parallelism <= 8) to prevent database-driven memory exhaustion attacks.
  - Verified that salts are generated via `java.security.SecureRandom` with 16 bytes of entropy (line 100), and outputs are 32 bytes (256 bits).
  - Verified that stored credential strings follow the canonical PHC format validated by strict regular expressions (`PHC` pattern in line 54) and canonical Base64 round-trip re-encoding in `decodeCanonical()` (lines 233-241) to reject non-canonical representations.
  - Verified that credential verification uses `java.security.MessageDigest.isEqual` (line 144) for constant-time byte comparison.
  - Verified automatic credential upgrade logic in `AccountStore.java` (lines 204-226) and `AuthService.java` (lines 226-228), guarded by `password_updated_at` to prevent race conditions during concurrent updates.

- **Timing Attack Mitigation & Response Uniformity (CWE-208, CWE-209):**
  - Verified in `AuthService.java` that sign-in failures across non-existent accounts (lines 184-187), locked accounts (lines 196-199), and wrong passwords (lines 206-216) execute exactly one Argon2id derivation.
  - Verified that `dummyHash` is generated at startup with a fresh random salt and throwaway password (`AuthService.java` lines 70-79), ensuring unknown and locked account paths incur identical memory and CPU derivation cost.
  - Verified that rate-limited requests and malformed input refusals execute `equaliseWork()` (line 160) outside the database transaction monitor to equalize response times without creating lock contention.
  - Verified that all authentication failure paths return the identical generic message `INVALID_MESSAGE` ("The email or password is not correct.").
  - Verified that registration returns `OUTCOME_MESSAGE` for both successful creation and duplicate account submissions (`AccountStore.java` line 48), preventing user enumeration.

- **Rate Limiting & Denial of Service Defenses (CWE-307, CWE-400):**
  - Verified atomic token bucket updates in `Throttle.java` (lines 79-87) using single `UPDATE ... WHERE ... > 0` statements whose affected row count governs the throttling decision, eliminating check-then-act race conditions.
  - Verified account failure counting using row-level locking (`SELECT ... FOR UPDATE` in line 153) to serialize concurrent requests.
  - Verified that duplicate registration attempts consume a token from the caller's source quota in an independent committed transaction (`AccountStore.java` lines 148-153) to prevent registration-based resource exhaustion.
  - Verified that account lockouts are temporary (900 seconds) and self-clearing upon successful authentication or window decay (`Throttle.java` lines 41-45, 170-172), preventing permanent denial of service.
  - Verified that the source identifier cannot be spoofed via `-Duser.name`, deriving directly from the kernel effective UID in `/proc/self/status` with fallback to a single host-wide shared bucket (`Main.java` lines 427-445).
  - Verified that input stream readers in `Main.java` (`readCapped` lines 511-548) apply a strict 4096-character limit during streaming, terminating oversized inputs immediately without unbounded buffering.

- **Session Management & Cookie Hardening (CWE-613, CWE-1004, CWE-614, CWE-1275):**
  - Verified in `SessionStore.java` (lines 60-70) that session tokens are generated with 256 bits of entropy (32 bytes from `SecureRandom` formatted as 64 lowercase hex characters).
  - Verified that bearer tokens are stored strictly as SHA-256 hashes (`token_hash`), preventing credential exposure in the event of a database compromise.
  - Verified that session resolution queries check `revoked_at IS NULL AND expires_at > now` under `FOR UPDATE` row locks (lines 113-122).
  - Verified that sessions have an absolute 8-hour expiration (`SESSION_LIFETIME_SECONDS = 28800`) with no sliding extension.
  - Verified that sign-out confirms revocation in the database before emitting an expired cookie with `Max-Age=0` (`Main.java` lines 289-300).
  - Verified in `CookiePolicy.java` (lines 44-55) that emitted cookies unconditionally specify `HttpOnly`, `Secure`, `SameSite=Strict`, validated `Path`, and computed `Max-Age` / `Expires`.

- **Sensitive Data Protection & Memory Hygiene (CWE-200, CWE-244, CWE-532):**
  - Verified that sensitive credentials (passwords, tokens, database keys) are stored in `char[]` and wrapped in `Secrets.java`, with explicit zeroing (`Arrays.fill(..., '\0')`) in `finally` blocks across `Main.java`, `AuthService.java`, `AccountStore.java`, and `PasswordHasher.java`.
  - Verified that `Secrets.toString()` is overridden to return `Secrets[redacted]` to prevent accidental leakage in logs or string concatenations.
  - Verified that passwords are read via `Console.readPassword()` in `Main.java` (line 497) to suppress terminal echo.
  - Verified that bearer session tokens are prompted via standard input rather than accepted as command-line arguments (`Main.java` lines 363-368), preventing exposure in system process tables (`/proc` / `ps`).
  - Verified that `AuditLog.java` records non-reversible per-process salted tags (generated via `Gate.java` lines 72-75) instead of raw usernames, emails, or tokens.
  - Verified that H2 database configuration in `Config.java` (line 71) sets `TRACE_LEVEL_FILE=0` to prevent SQL query text containing credentials from being written to trace files.
  - Verified that detailed exception stack traces are suppressed in `Main.java` (lines 152-160), logging only high-level exception class names to operator stderr while emitting generic error messages to standard output.

- **Input Validation & Trust Boundaries (CWE-20, CWE-1284):**
  - Verified that `InputPolicy.java` enforces strict whitelist character sets for emails (`[A-Za-z0-9._%+-]`), domains, usernames (`[a-z0-9-]`), and passwords.
  - Verified that normalization or trimming functions (`trim()` / `strip()`) are deliberately avoided, ensuring leading/trailing whitespace or invisible control characters cause explicit validation rejections rather than unexpected transformations.
  - Verified surrogate pair validation in `InputPolicy.java` (lines 162-167, 246-249) to reject unpaired Unicode surrogates.
  - Verified reserved username enforcement blocking 13 administrative identities (`admin`, `root`, `support`, etc.).
  - Verified password complexity rules requiring at least 12 characters, at least one digit, at least one letter, and prohibiting passwords containing the username or email local-part (`passwordNotRelatedTo`).

- **Filesystem Security & Link Traversal Protections (CWE-22, CWE-59, CWE-732):**
  - Verified that `Config.java` enforces `0700` permissions on the data directory (lines 281-311) and `0600` on the database file (lines 319-346), refusing execution if directories or files are world-writable or group-accessible.
  - Verified that all path components are inspected with `Files.isSymbolicLink` and `rejectSymlinkComponents` to reject symlinks in data directories.
  - Verified that `AuditLog.java` appends records with `LinkOption.NOFOLLOW_LINKS` (lines 184-186) and omits `StandardOpenOption.CREATE`, ensuring swapped symlinks are rejected by the kernel and missing files fail closed rather than recreating with default umask permissions.

- **Supply Chain Integrity & Dependency Management (CWE-1357, CWE-494):**
  - Verified that `scripts/get-deps.sh` downloads dependencies over TLS 1.2+, checks SHA-256 digests against authoritative entries pinned in `deps.lock`, verifies mirror agreement against a secondary distributor, validates published SHA-1 hashes, and verifies digital signatures on signed JARs (`bcprov`).
  - Verified that `scripts/run.sh` and `scripts/build.sh` execute dependency verification prior to compiling or running.
  - Verified that runtime classpaths are strictly partitioned, excluding test-only libraries (`spring-security-crypto`).

- **Transaction Integrity & Fail-Closed Logging (CWE-754, CWE-778):**
  - Verified in `AccountStore.java`, `AuthService.java`, and `SessionStore.java` that audit logging calls (`gate.record`) occur inside active database transactions before commit.
  - Verified that any audit failure raises `AuditException`, causing `Db.inTransaction()` to execute a complete database rollback (`Db.java` lines 174-180), guaranteeing that state changes cannot commit without an audit trail.
