# Security Review: Secure Account Registry (`example.security` / `secure-account-registry` 1.0.0)

## 1. Executive Summary

This is a Java 17 command-line account registry: it registers an email/username/password triple into a local SQLite database (`accounts.db`) and later authenticates by username or email. Passwords are derived with PBKDF2-HMAC-SHA-256 (600,000 iterations, 128-bit random salt, 256-bit output) and compared with `MessageDigest.isEqual`; authentication is rate-limited per account and per source inside a single `BEGIN IMMEDIATE` transaction; all data files are enforced to owner-only POSIX modes with no-follow semantics.

The code is deliberately hardened and withstood the applied skill checklists almost entirely. Only one reportable issue was found: the security event log **destroys all prior audit history** when it reaches its 1 MiB cap (`truncate(0)` with no archive), so an attacker's failed-authentication trail can be fully erased simply by generating enough further events (SEC-01, Low, CWE-778). Notably absent: no SQL injection (all user values are bound parameters; the only dynamic SQL fragment is chosen from a closed enum), no weak or deprecated cryptography, no hardcoded secrets, no account-enumeration or timing oracle, and fail-closed behaviour on every error path. Sessions/tokens/cookies/JWTs do not exist in this component, so those rules are not applicable. Supply-chain posture is strong (single pinned dependency, Maven `--strict-checksums`, SHA-256 pin script); a CVE review of `sqlite-jdbc:3.53.4.0` could not be performed under the static-review constraint and is noted as residual.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/example/security/SecureAccountApplication.java` | CLI entry point (`register` / `authenticate`) | Exact-allowlist command parsing; password read only via non-echoing `Console.readPassword`; data directory from env var; generic error messages; password buffer cleared in `finally` |
| `src/main/java/example/security/PasswordHasher.java` | Password hashing and verification | PBKDF2-HMAC-SHA256 KDF, `SecureRandom` salts, strict stored-hash parser, constant-time comparison, dummy-salt timing equalisation, buffer zeroisation |
| `src/main/java/example/security/AccountStore.java` | SQLite persistence, registration, authentication, lockout | Prepared statements; single enum-selected dynamic SQL column; per-account and per-source failure rate limiting in one `BEGIN IMMEDIATE` transaction; clock-rollback resistance; fail-closed on exceptions; `PRAGMA trusted_schema=OFF`; private `org.sqlite.tmpdir` |
| `src/main/java/example/security/InputValidator.java` | Input validation/canonicalisation | ASCII-allowlist regexes, length bounds, NFC-only requirement, single-`@` email parsing, password charset/length policy, locale-independent lowercasing |
| `src/main/java/example/security/SecureFiles.java` | Private storage path/permission enforcement | Absolute-normalised-path regex, symlink rejection on every component, parent not group/world-writable, exact `0700`/`0600` mode rechecks with `NOFOLLOW_LINKS` |
| `src/main/java/example/security/SecurityLog.java` | Bounded security event log | Event-code allowlist, sanitised exception type, US-ASCII output, file lock, 1 MiB cap with destructive truncate-and-rotate |
| `src/test/java/example/security/SecuritySelfTest.java` | Security self-tests (non-JUnit `main`) | Asserts canonicalisation, salt uniqueness, strict parse rejection, non-enumerating duplicate registration, account lockout fails closed |
| `pom.xml` | Maven build | Single runtime dependency pinned to `org.xerial:sqlite-jdbc:3.53.4.0`; plugin versions pinned |
| `scripts/verify-dependencies.sh` | Dependency integrity check | Verifies driver JAR against a pinned SHA-256 before use |
| `.mvn/maven.config` | Maven defaults | Enables `--strict-checksums` for repository artifact resolution |

Out of scope: `README.md`, `prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`, `.gitignore` (documentation and generation metadata, no executable code), and `target/` build output. The code was reviewed statically only; nothing was built, executed, or imported.

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java` (KDF algorithm and parameters, salt generation, key size, encoded-format parser, constant-time comparison, key-material zeroisation) and to `AccountStore.scopeKey` (SHA-256 used as a non-security identifier digest), plus RNG usage across the codebase.
- `exploiting-sql-injection-vulnerabilities`: knowledge applied as an injection-point inventory over `AccountStore.java` — every value reaching SQL, the one string-concatenated SQL fragment, second-order use of stored usernames/emails, and the JDBC URL construction — checked statically rather than exercised.
- `testing-api-authentication-weaknesses`: applied to `AccountStore.authenticate`/`register` and `InputValidator.password` for weak-password policy, brute-force/credential-stuffing throttling, account enumeration, and credential leakage (token/JWT/cookie sub-checks not applicable — the component issues no sessions or tokens).
- `performing-sca-dependency-scanning-with-snyk`: knowledge applied to `pom.xml`, `.mvn/maven.config`, and `scripts/verify-dependencies.sh` (dependency inventory, pinning, checksum enforcement). The Snyk CLI was not run; the project was not built.
- `implementing-secret-scanning-with-gitleaks`: applied as a manual secret sweep of all sources, build files, and shell scripts for hardcoded credentials (per the dispatcher rule to apply the skill's knowledge, not run its scripts).
- `testing-for-broken-access-control`: applied conceptually to fail-closed verification and file-level access enforcement — `SecureFiles.java` permission/symlink gates, and the rule that authentication outcomes depend only on validated server-side (database) state. (The web-endpoint/role-matrix workflow is not applicable to a local CLI.)
- General OWASP Top 10 / CWE knowledge (no matching library skill): path traversal and symlink/TOCTOU handling in `SecureFiles.java`; log injection and audit-log retention in `SecurityLog.java` (CWE-117/CWE-778); resource exhaustion / denial of service (account cap, length bounds, log cap); Unicode normalisation and case-mapping of identifiers (CWE-178); exception information leakage (CWE-209/CWE-755); check-then-act concurrency (CWE-362/CWE-367); and availability abuse via clock manipulation.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Security event log rotation destroys all prior audit history | Low | CWE-778 | `src/main/java/example/security/SecurityLog.java:36` |

## 5. Detailed Findings

### SEC-01: Security event log rotation destroys all prior audit history
- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/example/security/SecurityLog.java:36-41` (cap defined at line 13)

**Vulnerable code:**
```java
// SecurityLog.java:34-44
                byte[] bytes = line.getBytes(StandardCharsets.US_ASCII);
                long size = channel.size();
                if (size + bytes.length > MAX_BYTES) {
                    channel.truncate(0);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
                writeFully(channel, ByteBuffer.wrap(bytes));
```

**Why it is a problem:** When the log reaches the 1 MiB cap, `channel.truncate(0)` deletes every previously recorded security event in place; the only trace that anything existed is a single `LOG_ROTATED` marker line. Each event line is roughly 30–40 bytes, so a few tens of thousands of events wipe the history — and an adversary (or anyone able to invoke `authenticate` with wrong passwords, which itself records `AUTHENTICATION_FAILED` events) can deliberately generate events to flush evidence of an earlier brute-force or tampering trail. The component therefore cannot support post-incident timeline reconstruction beyond the most recent window of activity, and the rotation is attacker-influenced in volume. This is Low rather than High because the threat model is a single-host CLI whose primary controls (KDF, rate limiting, fail-closed authentication) do not depend on the log, and the design intent to bound size is sound — it is the destructive *method* of bounding that is deficient.

**Fix:** Preserve a bounded one-generation archive instead of erasing history: copy the current contents into a second private file (created through the same `SecureFiles.privateFile` gate, so mode and no-follow rules are enforced) before truncating. Total on-disk cost stays bounded at 2 MiB.

```java
                byte[] bytes = line.getBytes(StandardCharsets.US_ASCII);
                long size = channel.size();
                if (size + bytes.length > MAX_BYTES) {
                    SecureFiles.privateFile(path.getParent(), "security.log.1");
                    Path archive = path.resolveSibling("security.log.1");
                    try (FileChannel archiveChannel = FileChannel.open(archive,
                            StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                        archiveChannel.truncate(0);
                        long transferred = 0;
                        while (transferred < size) {
                            long moved = channel.transferTo(transferred, size - transferred, archiveChannel);
                            if (moved <= 0) {
                                break;
                            }
                            transferred += moved;
                        }
                    }
                    channel.truncate(0);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
                writeFully(channel, ByteBuffer.wrap(bytes));
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection inventory** (`exploiting-sql-injection-vulnerabilities`): every attacker-influenced value (email, username, password hash, login, rate-scope keys) is bound via `PreparedStatement` placeholders (`AccountStore.java:69-76`, `139-140`, `230-236`, `262-277`, `280-284`). The only concatenated SQL fragment is a column name selected from a closed enum ternary — `"email_norm"`/`"username_norm"` (`AccountStore.java:137-138`) — never caller text. Stored usernames/emails are reused later only as bound parameters (no second-order injection). The JDBC URL is built from a path restricted to `[A-Za-z0-9_./-]` by regex (`SecureFiles.java:18`, used at `AccountStore.java:37`), so no `?`/URL metacharacters can smuggle driver options; `PRAGMA trusted_schema=OFF` (`AccountStore.java:198`) and `STRICT` tables with `CHECK` constraints (`AccountStore.java:160-180`) further constrain the engine.
- **Cryptographic audit** (`performing-cryptographic-audit-of-application`): PBKDF2-HMAC-SHA256 at 600,000 iterations with 16-byte `SecureRandom` salts and 256-bit output (`PasswordHasher.java:12-16`, `26-27`, `55-57`) meets the OWASP password-storage baseline; no MD5/SHA-1/DES/RC4/ECB anywhere; `SHA-256` at `AccountStore.java:305-307` is used only as an identifier digest, not a security proof; randomness comes solely from `SecureRandom` (`PasswordHasher.java:18`); salt, derived key, `PBEKeySpec` password, and caller `char[]` buffers are zeroised in `finally` blocks (`PasswordHasher.java:34-35`, `45-46`, `58-59`; `SecureAccountApplication.java:61-63`). No hardcoded keys or working credentials exist (the `dummySalt` is runtime-random and not a secret).
- **Constant-time verification and anti-enumeration timing** (`performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`): hash comparison uses `MessageDigest.isEqual` (`PasswordHasher.java:44`); a missing or malformed stored record still performs one full 600k-iteration KDF against a per-process dummy salt (`PasswordHasher.java:40-42`; invoked unconditionally at `AccountStore.java:114-116`), so unknown accounts, blocked accounts, and wrong passwords do comparable work; registration of a duplicate is indistinguishable from success (error code 19 mapped to `ACCEPTED`, `AccountStore.java:84-88`) and still performs a full KDF.
- **Stored-hash parser hardening** (`performing-cryptographic-audit-of-application`): the parser rejects any hash not exactly matching scheme `pbkdf2-sha256`, cost `i=600000`, 16-byte salt, 32-byte digest, and ≤160 encoded chars (`PasswordHasher.java:61-84`), so a tampered database row cannot force a KDF-downgrade (e.g. 1-iteration) verification or a memory-exhausting oversized input; the DB schema independently bounds the column at 80–160 chars (`AccountStore.java:166`).
- **Authentication fails closed with atomic rate limiting** (`testing-api-authentication-weaknesses`, `testing-for-broken-access-control`): the check-then-act sequence (load counters → verify → update/reset → decide) runs inside one `BEGIN IMMEDIATE` transaction with `busy_timeout` (`AccountStore.java:99-123`, `155-158`, `193-200`); per-account limit 5 and source limit 20 per 15-minute window (`AccountStore.java:19-20`); any exception path returns `false` (`AccountStore.java:126-130`); persisted `last_seen` prevents clock rollback from reopening a window (`AccountStore.java:244-250`). The per-account lockout that blocks even a correct password after 5 failures is the intended brute-force control of this single-OS-account threat model (covered by `SecuritySelfTest.accountRateLimitFailsClosed`) and its abuse surface — an actor already running as the owning OS user — is outside the enforceable boundary documented in `README.md`; not raised as a finding.
- **Password policy and handling** (`testing-api-authentication-weaknesses`): 15–128 characters with control-character and malformed-surrogate rejection (`InputValidator.java:54-65`); the minimum exceeds the OWASP 8/12-character floors; passwords never traverse argv, environment, logs, or exception text and are read with `Console.readPassword` with a hard refusal to run without a console (`SecureAccountApplication.java:16-21`, `31`, `48`).
- **Identifier canonicalisation / case-mapping** (general CWE-178 review): inputs must already be NFC-normalised, strip-stable, and control-free (`InputValidator.java:72-75`); usernames/emails are matched only against ASCII allowlist regexes before locale-independent lowercasing via `toLowerCase(Locale.ROOT)` (`InputValidator.java:11-14`, `21`, `47`), eliminating Turkish-I case folding, homoglyph/look-alike aliasing, and invisible-character ambiguity; username and email login forms cannot collide because the username pattern excludes `@`.
- **Path traversal / symlink / TOCTOU file handling** (general knowledge — no path-traversal skill in the library): the env-var data directory must match `SAFE_ABSOLUTE_PATH`, be absolute and equal to its own normalisation, have every component checked for symlinks, and a parent that is neither group- nor world-writable (`SecureFiles.java:18-47`); directories and files are re-verified post-creation with `NOFOLLOW_LINKS` and exact `0700`/`0600` modes, closing the create-then-verify race for any actor without write access to a `0700` directory (`SecureFiles.java:49-84`, `86-100`); the log channel is opened `NOFOLLOW_LINKS` (`SecurityLog.java:31-32`) and SQLite native/temp files are redirected from shared `/tmp` into the private directory (`AccountStore.java:34-35`).
- **Log injection and information content** (general CWE-117 review): event codes must match `[A-Z0-9_]{1,48}`, the exception contribution is only the class simple name filtered to `[A-Za-z0-9_$]{1,80}` with a `REDACTED` fallback, and output is US-ASCII — no attacker text, identifiers, hashes, or paths can enter the log or inject newlines (`SecurityLog.java:21-28`).
- **Error information leakage** (general CWE-209/CWE-755 review): top-level `catch` prints a fixed string and never the exception, path, SQL, or configuration (`SecureAccountApplication.java:56-58`); `SQLException` details reach only the sanitised log (`AccountStore.java:89-91`); all public failure messages are identical regardless of cause.
- **Secrets in source** (`implementing-secret-scanning-with-gitleaks`, applied manually): manual sweep of all Java, XML, shell, and config files found no credentials, API keys, or private keys; the only literal that resembles a secret is the public SHA-256 checksum constant in `scripts/verify-dependencies.sh:5`, which is an integrity pin, not a credential.
- **Supply chain / dependency posture** (`performing-sca-dependency-scanning-with-snyk`, knowledge applied without running the scanner): one runtime dependency, pinned to `org.xerial:sqlite-jdbc:3.53.4.0` (`pom.xml:17-21`), all build plugins version-pinned, Maven resolution hardened with `--strict-checksums` (`.mvn/maven.config:1`), and an explicit pre-use SHA-256 check of the driver JAR (`scripts/verify-dependencies.sh:4-15`); no remote files are fetched at runtime and no code is loaded from world-writable locations. Residual: known-CVE screening of `sqlite-jdbc:3.53.4.0` and its bundled SQLite was not performed (no scanner was run against untrusted, un-built code) and should be done in the normal CI pipeline.
- **Resource exhaustion** (general knowledge): account table capped at 100,000 rows with `CHECK` bounds on every column and `STRICT` typing (`AccountStore.java:21`, `64-67`, `160-180`); failure counters clamped non-negative and ≤1,000,000 with saturating time addition (`AccountStore.java:289-300`); unknown accounts never create persistent rate rows; encoded-hash, email (254), username (32), password (128), and log-size inputs all have upper bounds before processing.
- **Sessions/tokens/cookies** (`testing-api-authentication-weaknesses`): verified absent — this CLI issues no session identifiers, tokens, or cookies, so cryptographic-token-generation and cookie-attribute rules have nothing to apply to; `SecureFiles`-enforced `0600`/`0700` modes are the only confidentiality boundary on stored state, consistent with the documented single-OS-account model.
