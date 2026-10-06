# Security Review: Secure Account Registry (Java 17 CLI, SQLite)

## 1. Executive Summary

The component is a local command-line program (`example.security.SecureAccountApplication`) that registers accounts (email, username, password) into a SQLite database under a private data directory and later authenticates them by username or email. Password storage uses PBKDF2-HMAC-SHA-256 with 600,000 iterations, a 16-byte `SecureRandom` salt, a 256-bit output and constant-time comparison; all SQL uses prepared statements; the data directory and all created files are forced to POSIX `0700`/`0600` with symlink and non-POSIX rejection; failure messages are uniform and both authentication and registration do a full KDF on every path to suppress enumeration; rate state is updated inside `BEGIN IMMEDIATE` transactions.

The core credential handling is sound: **no SQL injection, no hardcoded secrets, no weak hash or weak RNG, no plaintext password storage, no credential leakage into logs or messages, and no timing/message-based account enumeration was found.** The issues that remain are secondary: an account/host lockout that an attacker can weaponise for denial of service, a registration path that reports success while silently discarding the account once a hard cap is reached (with no throttle on reaching that cap), an audit log that is truncated to zero on rotation and can be flooded to destroy earlier evidence, password buffers that are not zeroized on the `System.exit` paths, and filesystem checks that validate permission bits but never ownership or ancestor writability beyond the immediate parent.

Findings: 2 Medium, 3 Low. No Critical or High issues.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/example/security/SecureAccountApplication.java` | CLI entry point; dispatches `register` / `authenticate`, reads console input | Argument allowlist, console-only password entry with echo disabled, generic error reporting, password buffer zeroization, `System.exit` paths |
| `src/main/java/example/security/AccountStore.java` | SQLite persistence, registration, authentication, rate limiting, schema | Prepared statements, dynamic column from closed enum, `BEGIN IMMEDIATE` atomicity, per-account/per-source failure limits, clock-rollback handling, account cap, uniform results |
| `src/main/java/example/security/PasswordHasher.java` | Password KDF and verification | PBKDF2WithHmacSHA256, 600k iterations, `SecureRandom` salt, dummy-salt work on missing/malformed records, `MessageDigest.isEqual`, buffer clearing, strict encoded-hash parser |
| `src/main/java/example/security/InputValidator.java` | Validation/canonicalization of email, username, login, password | ASCII allowlists, length bounds, NFC/strip/control-character checks, surrogate-pair validation, locale-independent lowercasing after validation |
| `src/main/java/example/security/SecureFiles.java` | Private data directory and file creation | Env-var path allowlist regex, absolute/normalized check, symlink-component rejection, parent write-bit check, `0700`/`0600` enforcement with `NOFOLLOW_LINKS` |
| `src/main/java/example/security/SecurityLog.java` | Append-only security event log | Event-code allowlist, exception type sanitization, file lock, 1 MiB cap with truncating rotation, errors swallowed |
| `src/test/java/example/security/SecuritySelfTest.java` | Dependency-free self tests | Exercises validators, hasher, rate limits (not a control itself) |
| `pom.xml`, `.mvn/maven.config`, `scripts/verify-dependencies.sh` | Build and dependency integrity | Pinned driver `3.53.4.0` and plugin versions, `--strict-checksums`, manual SHA-256 verification of the JDBC JAR |
| `README.md` | Threat model and rule-by-rule justification | Documents trust boundaries and residual risks |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java` (KDF choice and parameters, salt generation and entropy source, encoded-hash parsing, constant-time comparison, key/secret handling) and to `AccountStore.scopeKey` (SHA-256 used as an identifier derivation, not as a password hash). No weak algorithm, insecure mode, low-iteration KDF, predictable seed or hardcoded key was found.
- `testing-api-authentication-weaknesses`: applied to `AccountStore.authenticate`/`register` and `SecureAccountApplication` (credential verification against server-side state, fail-closed behaviour, password policy, account-enumeration via differing messages or response times, lockout and credential-stuffing resistance). Produced SEC-01.
- `exploiting-sql-injection-vulnerabilities` and `performing-second-order-sql-injection`: applied to every query in `AccountStore.java` (`register`, `findHash`, `loadRate`, `recordFailure`, `deleteRate`, `initializeSchema`) plus the JDBC URL construction at `AccountStore.java:37`. All user values are bound parameters; the only concatenated fragment is a column name chosen from a two-value enum; stored values read back from the database are re-parsed strictly, so no second-order injection path exists.
- `exploiting-race-condition-vulnerabilities` (TOCTOU/concurrency): applied to the check-then-act sequences — rate check / verify / counter update (`AccountStore.java:101-124`), count-then-insert (`AccountStore.java:63-77`), and the file create-then-stat sequences in `SecureFiles.java`. Database races are correctly contained in `BEGIN IMMEDIATE` transactions; the filesystem sequences produced SEC-05.
- `testing-for-sensitive-data-exposure`: applied to `SecurityLog.java`, the console output in `SecureAccountApplication.java`, and the file modes in `SecureFiles.java` (no identifiers, passwords, hashes, paths, SQL or exception text in output or log; private file modes). Produced SEC-03 and SEC-04.
- `performing-directory-traversal-testing`: applied to `SecureFiles.initializeDataDirectory` and `privateFile`/`privateDirectory` (`ACCOUNT_DATA_DIRECTORY` as an attacker-controlled path, `..` handling, symlink components, filename resolution). Traversal and symlink-following are blocked; residual ownership gap reported as SEC-05.
- `performing-hash-cracking-with-hashcat` (offline-cracking resistance): applied to the stored hash format and cost parameters in `PasswordHasher.java` and the password policy in `InputValidator.java:9-11` — per-user 128-bit salt, 600k iterations and a 15-character minimum make offline cracking of the stored records expensive; no finding.
- `performing-sca-dependency-scanning-with-snyk` and `implementing-secrets-scanning-in-ci-cd`: applied to `pom.xml`, `.mvn/maven.config` and `scripts/verify-dependencies.sh` (single pinned dependency, pinned plugins, published-checksum verification, no committed secrets). No finding; see section 6 for the advisory nature of the script.
- `testing-for-business-logic-vulnerabilities`: applied to the registration/authentication workflow (duplicate registration, account cap, counter reset on success). Produced SEC-02.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill matched: process-level handling of `char[]` credential buffers and `System.exit` semantics (CWE-226), log rotation as an anti-forensic primitive (CWE-778), JVM system-property side effects (`org.sqlite.tmpdir` at `AccountStore.java:35`), clock-rollback handling for rate windows (`AccountStore.java:239-247`), and the error-handling/exception-suppression strategy. Skills for XSS, JWT, deserialization, access control (multi-tenant), CORS/headers and SSRF were considered and rejected as inapplicable: the program has no HTTP surface, no HTML/template rendering, no tokens or sessions, no serialization of untrusted data, no multi-user authorization model and no outbound network calls.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Attacker-triggerable account and host-wide authentication lockout | Medium | CWE-645 | `src/main/java/example/security/AccountStore.java:108` |
| SEC-02 | Registration reports success while silently discarding the account at the account cap, which is reachable without any registration throttle | Medium | CWE-392 | `src/main/java/example/security/AccountStore.java:64` |
| SEC-03 | Security log rotation truncates the whole file and can be flooded to destroy prior audit records | Low | CWE-778 | `src/main/java/example/security/SecurityLog.java:36` |
| SEC-04 | Password buffer is never zeroized on the `System.exit` failure paths | Low | CWE-226 | `src/main/java/example/security/SecureAccountApplication.java:37` |
| SEC-05 | Data-directory checks verify permission bits but never ownership or ancestors above the immediate parent | Low | CWE-367 | `src/main/java/example/security/SecureFiles.java:37` |

## 5. Detailed Findings

### SEC-01: Attacker-triggerable account and host-wide authentication lockout

- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/example/security/AccountStore.java:19-20`, `src/main/java/example/security/AccountStore.java:108-123`

**Vulnerable code:**
```java
// src/main/java/example/security/AccountStore.java:17-20
    private static final String SOURCE_SCOPE = "local-console-v1";
    private static final long WINDOW_MILLIS = 15 * 60 * 1000L;
    private static final int ACCOUNT_FAILURE_LIMIT = 5;
    private static final int SOURCE_FAILURE_LIMIT = 20;
```
```java
// src/main/java/example/security/AccountStore.java:108-123
            boolean rateAllowed = source.allowed(SOURCE_FAILURE_LIMIT)
                    && (storedHash == null || account.allowed(ACCOUNT_FAILURE_LIMIT));

            boolean passwordMatches = hasher.verify(password == null ? new char[0] : password, storedHash);
            boolean authenticated = inputValid && rateAllowed && storedHash != null && passwordMatches;
            if (authenticated) {
                deleteRate(connection, "ACCOUNT", accountScope);
                commit(connection);
                log.event("AUTHENTICATION_SUCCEEDED", null);
                return true;
            }

            recordFailure(connection, "SOURCE", SOURCE_SCOPE, source, SOURCE_FAILURE_LIMIT);
            if (storedHash != null) {
                recordFailure(connection, "ACCOUNT", accountScope, account, ACCOUNT_FAILURE_LIMIT);
            }
```

**Why it is a problem:** Both counters are hard blocks, not graduated delays, and `rateAllowed` is ANDed into `authenticated`, so a blocked principal is refused **even when it presents the correct password**. Two denial-of-service effects follow:

1. Per-account: anyone who knows or guesses a username or email can make 5 wrong-password attempts (`ACCOUNT_FAILURE_LIMIT`, `AccountStore.java:19`) and lock the legitimate owner of that account out for a full 15-minute window; repeating the five attempts every window keeps the victim permanently locked out.
2. Host-wide: `SOURCE_SCOPE` is a single compile-time constant (`AccountStore.java:17`), so every authentication attempt on the host shares one counter, and `recordFailure(..., "SOURCE", ...)` at line 120 increments it on *every* failed attempt — including attempts rejected purely for invalid input, where `inputValid` is false and no account was even looked up. 20 such failures disable authentication for all users of the installation for 15 minutes. The prompt's rule 3 explicitly asked that the limit not be usable to lock out a legitimate user; this implementation satisfies the "limit attempts" half but not the "cannot be used to lock out" half, and the README acknowledges only the clock-based variant of this risk.

**Fix:** Keep counting failures, but make the response a cost (an increasing per-attempt delay) rather than a refusal of valid credentials, and stop charging the shared source counter for attempts that never reached a credential check. Verify the password first and let a correct password clear the counters; only throttle.

```java
// Count failures, but never refuse a correct password: impose cost instead of a hard block.
            boolean passwordMatches = hasher.verify(password == null ? new char[0] : password, storedHash);
            boolean authenticated = inputValid && storedHash != null && passwordMatches;

            // Delay proportional to recent failures, capped; applied to every outcome so it leaks nothing.
            long delayMillis = Math.min(MAX_THROTTLE_MILLIS,
                    THROTTLE_STEP_MILLIS * (long) Math.max(source.failures(), account.failures()));

            if (authenticated) {
                deleteRate(connection, "ACCOUNT", accountScope);
                deleteRate(connection, "SOURCE", SOURCE_SCOPE);
                commit(connection);
                log.event("AUTHENTICATION_SUCCEEDED", null);
                sleepQuietly(delayMillis);
                return true;
            }

            // Malformed input never reached a credential check: do not charge the shared source counter.
            if (inputValid) {
                recordFailure(connection, "SOURCE", SOURCE_SCOPE, source, SOURCE_FAILURE_LIMIT);
                if (storedHash != null) {
                    recordFailure(connection, "ACCOUNT", accountScope, account, ACCOUNT_FAILURE_LIMIT);
                }
            }
            commit(connection);
            log.event("AUTHENTICATION_FAILED", null);
            sleepQuietly(delayMillis);
            return false;
```

### SEC-02: Registration reports success while silently discarding the account at the account cap, which is reachable without any registration throttle

- **Severity:** Medium
- **CWE:** CWE-392: Missing Report of Error Condition (with CWE-770: Allocation of Resources Without Limits or Throttling)
- **Location:** `src/main/java/example/security/AccountStore.java:63-68`

**Vulnerable code:**
```java
// src/main/java/example/security/AccountStore.java:62-68
            connection = connect();
            beginImmediate(connection);
            if (accountCount(connection) >= MAX_ACCOUNTS) {
                commit(connection);
                log.event("REGISTRATION_PROCESSED", null);
                return RegistrationResult.ACCEPTED;
            }
```

**Why it is a problem:** When the table has reached `MAX_ACCOUNTS` (100,000, `AccountStore.java:21`) the method returns `ACCEPTED`, which `SecureAccountApplication.java:32-34` turns into the positive message "If the account can be created, it is now available." No row is inserted, and the log records the same `REGISTRATION_PROCESSED` code used for genuine success, so neither the user nor the operator can distinguish "stored" from "dropped on the floor" in the output or the audit trail. Combined with the complete absence of any throttle, cost or source-based limit on `register` — unlike `authenticate`, registration consults no rate state at all — an attacker with console access can insert 100,000 junk accounts and thereby permanently disable registration for everyone while the program continues to claim success. The uniform message is a deliberate anti-enumeration measure for the *duplicate* case, but silently swallowing a hard capacity failure is a different condition and should be reported to the operator and the log without revealing anything about any particular account.

**Fix:** Keep the caller-facing message uniform, but return and log a distinct internal outcome for capacity exhaustion, and apply the existing per-source rate state to registration so the cap is not cheap to reach.

```java
// Distinguish capacity exhaustion internally; the caller-facing message stays generic.
            connection = connect();
            beginImmediate(connection);
            if (accountCount(connection) >= MAX_ACCOUNTS) {
                commit(connection);
                log.event("REGISTRATION_CAPACITY_EXHAUSTED", null); // operator-visible, no identifiers
                return RegistrationResult.ERROR;
            }
```
```java
// And throttle registration on the same per-source state used by authenticate(), so
// MAX_ACCOUNTS cannot be reached in an unbounded burst:
//   RateState source = loadRate(connection, "SOURCE", SOURCE_SCOPE, safeNow());
//   if (!source.allowed(REGISTRATION_SOURCE_LIMIT)) {
//       recordFailure(connection, "SOURCE", SOURCE_SCOPE, source, REGISTRATION_SOURCE_LIMIT);
//       commit(connection);
//       log.event("REGISTRATION_THROTTLED", null);
//       return RegistrationResult.ERROR;
//   }
```

### SEC-03: Security log rotation truncates the whole file and can be flooded to destroy prior audit records

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/example/security/SecurityLog.java:36-40`

**Vulnerable code:**
```java
// src/main/java/example/security/SecurityLog.java:35-43
                long size = channel.size();
                if (size + bytes.length > MAX_BYTES) {
                    channel.truncate(0);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
```

**Why it is a problem:** Rotation discards the entire history instead of rolling it to a retained file, so every record of earlier activity is irrecoverably lost once 1 MiB accumulates. Log lines are roughly 60 bytes, so about 17,000 events wipe the file. `AccountStore.register` emits `REGISTRATION_REJECTED` (`AccountStore.java:48`) on every malformed input, before any rate state is consulted and without any throttle, which gives an attacker a cheap, unlimited event generator: flood invalid registrations until the file rotates and all evidence of the preceding `AUTHENTICATION_FAILED` / `DATABASE_ERROR` records is gone. Secondarily, `SecurityLog.event` swallows every `IOException` and `RuntimeException` (line 46), so if the log file ever fails its `privateFile` safety re-check the program keeps authenticating with no audit trail at all and no operator signal.

**Fix:** Roll to a retained, mode-`0600` predecessor file instead of truncating, so the previous window survives rotation; and record the fact that logging itself failed.

```java
                long size = channel.size();
                if (size + bytes.length > MAX_BYTES) {
                    // Retain the previous window instead of destroying it.
                    Path rolled = SecureFiles.privateFile(path.getParent(),
                            path.getFileName() + ".1");
                    try (FileChannel target = FileChannel.open(rolled,
                            StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING,
                            LinkOption.NOFOLLOW_LINKS)) {
                        channel.position(0);
                        channel.transferTo(0, size, target);
                    }
                    channel.truncate(0);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
```

### SEC-04: Password buffer is never zeroized on the `System.exit` failure paths

- **Severity:** Low
- **CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- **Location:** `src/main/java/example/security/SecureAccountApplication.java:36-37`, `src/main/java/example/security/SecureAccountApplication.java:45-46`, `src/main/java/example/security/SecureAccountApplication.java:52-56`

**Vulnerable code:**
```java
// src/main/java/example/security/SecureAccountApplication.java:36-37
                console.writer().println("Unable to complete request.");
                System.exit(1);
```
```java
// src/main/java/example/security/SecureAccountApplication.java:52-56
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
```

**Why it is a problem:** `System.exit` begins JVM shutdown and does not unwind the stack, so the `finally` block that zeroizes `password` never runs on any of the failure paths — the rejected-registration exit (line 37), the failed-authentication exit (line 46) and the catch-all exit (line 51). The cleartext password therefore remains in the heap array for the rest of the shutdown sequence, which is exactly the interval in which a core dump, a heap dump triggered by a shutdown hook, or a swapped page can capture it. The code and README both state this clearing as a control (README rule 5), so the control is present but ineffective on precisely the paths an attacker can reach most easily (a wrong password).

**Fix:** Zeroize before exiting — compute an exit status inside the `try` and call `System.exit` after the `finally` block has run.

```java
        char[] password = null;
        int status = 0;
        try {
            // ... as before, but set `status` instead of calling System.exit():
            //   status = 1;  in place of each System.exit(1)
        } catch (Exception ignored) {
            System.err.println("Unable to complete request.");
            status = 1;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
        if (status != 0) {
            System.exit(status); // only after the buffer has been cleared
        }
```

### SEC-05: Data-directory checks verify permission bits but never ownership or ancestors above the immediate parent

- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/example/security/SecureFiles.java:35-47`, `src/main/java/example/security/SecureFiles.java:79-85`

**Vulnerable code:**
```java
// src/main/java/example/security/SecureFiles.java:35-47
        requirePosix(path.getParent());
        rejectSymlinkComponents(path.getParent());
        Set<PosixFilePermission> parentMode = Files.getPosixFilePermissions(
                path.getParent(), LinkOption.NOFOLLOW_LINKS);
        if (parentMode.contains(PosixFilePermission.GROUP_WRITE)
                || parentMode.contains(PosixFilePermission.OTHERS_WRITE)) {
            throw new IOException("data directory parent is writable by other users");
        }
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));
        }
        validatePrivateDirectory(path);
        return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
```

**Why it is a problem:** Only the *immediate* parent's write bits are examined, and no check anywhere confirms that the parent, the data directory or the created files are owned by the current user. A path such as `/tmp/registry/data`, where the attacker created `/tmp/registry` as mode `0755`, passes every check: the symlink scan and the parent mode test succeed, yet the attacker owns the parent directory and can therefore unlink or rename entries inside it at will. Because the returned `Path` is subsequently re-resolved by name on each use (`SecureFiles.privateFile`, `SecurityLog.event` at `SecurityLog.java:30`), the attacker can swap the leaf directory between the check at line 46 and any later use, so the database and the security log are created or reopened in a location of the attacker's choosing — an availability and log-suppression primitive, and a hardlink/substitution foothold. `validatePrivateDirectory` (lines 79-85) compares mode bits only, so an attacker-owned `0700` directory also satisfies it.

**Fix:** Assert ownership explicitly and walk every ancestor, not just the parent, rejecting any ancestor that is group/other-writable without the sticky bit or not owned by the current user; then operate on an opened directory handle-equivalent (`SecureDirectoryStream`) so later file operations are relative to the validated directory rather than re-resolved by name.

```java
    private static void requireOwnedAndPrivateAncestors(Path path) throws IOException {
        UserPrincipal me = path.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
        Path current = path.getRoot();
        for (Path part : path) {
            current = current.resolve(part);
            PosixFileAttributes attributes = Files.readAttributes(
                    current, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink()) {
                throw new IOException("symlink in data path");
            }
            Set<PosixFilePermission> mode = attributes.permissions();
            boolean sharedWritable = mode.contains(PosixFilePermission.GROUP_WRITE)
                    || mode.contains(PosixFilePermission.OTHERS_WRITE);
            if (sharedWritable || !attributes.owner().equals(me)) {
                // An ancestor the current user does not own, or that others can write,
                // lets a third party substitute the leaf after validation.
                throw new IOException("data directory ancestor is not exclusively owned");
            }
        }
    }
```
```java
        // ... and call it in place of the parent-only checks:
        requirePosix(path.getParent());
        requireOwnedAndPrivateAncestors(path.getParent());
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));
        }
        validatePrivateDirectory(path);
        requireOwnedAndPrivateAncestors(path);
        return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (CWE-89), first and second order:** Every user-supplied value is bound with `setString`/`setLong`/`setInt` — registration insert (`AccountStore.java:69-75`), account lookup (`AccountStore.java:139-140`), rate load (`AccountStore.java:230-234`), rate upsert (`AccountStore.java:262-274`), rate delete (`AccountStore.java:280-283`). The only concatenated SQL fragment is the column name at `AccountStore.java:137-138`, derived from the two-value `InputValidator.LoginKind` enum and never from caller text. Values read back out of the database are re-validated rather than trusted (`PasswordHasher.parse` at `PasswordHasher.java:63-88`, `nonNegative`/clamping at `AccountStore.java:239-243`), so there is no second-order path. `PRAGMA trusted_schema=OFF` is set on every connection (`AccountStore.java:198`) and the schema uses `STRICT` with `CHECK` bounds on all columns (`AccountStore.java:159-178`).
- **JDBC URL injection:** `jdbcUrl` is built at `AccountStore.java:37` from a path that `SecureFiles.SAFE_ABSOLUTE_PATH` (`SecureFiles.java:18`) restricts to `[A-Za-z0-9_./-]`, excluding `?`, `&`, `:` and whitespace, so no SQLite JDBC URL parameters can be smuggled in through `ACCOUNT_DATA_DIRECTORY`.
- **Password storage (CWE-256/CWE-916):** PBKDF2WithHmacSHA256, 600,000 iterations, 256-bit output, 128-bit per-password salt from `SecureRandom` (`PasswordHasher.java:12-37`) — matches the OWASP Password Storage Cheat Sheet floor. Only the versioned encoded string is persisted; no reversible or unsalted storage anywhere.
- **Credential comparison (CWE-208):** `MessageDigest.isEqual` at `PasswordHasher.java:44` is constant-time; no early-return string comparison of digests exists.
- **Randomness (CWE-338):** All random material comes from `java.security.SecureRandom` (`PasswordHasher.java:18-27`); no `java.util.Random`, no time-based seeds, no predictable salt or IV.
- **Hardcoded secrets (CWE-798):** Reviewed all sources, `pom.xml`, `.mvn/maven.config`, `scripts/verify-dependencies.sh` and `README.md`. The only constants are a scope label (`AccountStore.java:17`), the KDF format prefix, numeric parameters and a published SHA-256 artifact checksum — none is a credential, and none would authenticate anyone who ran the program.
- **Password never in arguments, environment, output, or logs:** The password is read solely via `console.readPassword` with echo disabled (`SecureAccountApplication.java:30`, `:40`); a missing console fails closed (`SecureAccountApplication.java:16-19`); argv is restricted to an exact two-value allowlist (`SecureAccountApplication.java:11`). Log lines contain only an allowlisted `[A-Z0-9_]{1,48}` event code and a sanitized exception class name (`SecurityLog.java:21-28`) — never identifiers, hashes, paths or SQL.
- **Account enumeration (CWE-204/CWE-208):** Authentication performs exactly one full 600k-iteration KDF on every outcome, using a process-random dummy salt when the record is missing or malformed (`PasswordHasher.java:39-51`, called unconditionally at `AccountStore.java:111`), and all failures return the single message at `SecureAccountApplication.java:45`. Registration hashes before touching the database (`AccountStore.java:54`) and maps the `SQLITE_CONSTRAINT` duplicate case to the same `ACCEPTED` result as success (`AccountStore.java:82-84`), so duplicates are indistinguishable.
- **Error handling / information disclosure (CWE-209):** Every exception is caught and replaced with a fixed generic string; no stack trace, SQL text, path or configuration value reaches the console (`SecureAccountApplication.java:48-51`, `AccountStore.java:80-87`, `AccountStore.java:127-130`).
- **Fail-closed authentication:** `authenticated` at `AccountStore.java:112` requires input validity, rate allowance, an existing stored hash and a password match; any exception path returns `false` (`AccountStore.java:127-130`); a malformed stored hash yields `parsed == null` and therefore a guaranteed `false` (`PasswordHasher.java:44`); duplicate or over-length lookup rows are treated as "no account" (`AccountStore.java:143-149`).
- **Concurrency / check-then-act atomicity (CWE-367 in the database):** Rate load, credential verification, counter update/reset and the decision all occur inside one `BEGIN IMMEDIATE` transaction (`AccountStore.java:101-124`), as does count-then-insert for registration (`AccountStore.java:63-77`); `UNIQUE` constraints are the final arbiter, `PRAGMA busy_timeout=5000` is set (`AccountStore.java:197`), and `recordFailure` uses a single atomic `INSERT ... ON CONFLICT DO UPDATE` (`AccountStore.java:262-268`).
- **Clock manipulation:** `safeNow` clamps negative time (`AccountStore.java:288-290`), `last_seen` is persisted and effective time never moves backward (`AccountStore.java:239-240`), `elapsed` cannot go negative (`AccountStore.java:296-298`), and `saturatingAdd` prevents overflow of `blocked_until` (`AccountStore.java:300-302`). Rollback cannot reopen a window.
- **Input validation (CWE-20):** Username is a 3-32 character ASCII allowlist (`InputValidator.java:11`); email is length-capped at 254 with a single `@`, a bounded local part rejecting leading/trailing/double dots, and per-label domain validation (`InputValidator.java:24-48`); `isStableText` rejects untrimmed, non-NFC and control-character input (`InputValidator.java:72-75`); lowercasing uses `Locale.ROOT` *after* validation, avoiding Turkish-I style canonicalization aliasing; password validation enforces 15-128 characters, no ISO controls and well-formed surrogate pairs (`InputValidator.java:50-62`) — I traced the surrogate loop and the `++i` advance is correct for both lone high and lone low surrogates. Unknown commands are rejected rather than defaulted (`SecureAccountApplication.java:11-14`).
- **Path traversal and symlink attacks (CWE-22/CWE-59):** `ACCOUNT_DATA_DIRECTORY` must match an absolute portable-character regex under 4096 bytes, be absolute and equal to its own normalization (so `..` and `.` are rejected), and contain no symlink component; every file and directory is created with an explicit POSIX mode attribute and re-checked with `LinkOption.NOFOLLOW_LINKS` for symlink, type and exact mode `0700`/`0600` (`SecureFiles.java:22-85`). Non-POSIX filesystems fail closed (`SecureFiles.java:87-92`). The residual ownership gap is SEC-05.
- **Stored-value bounds (CWE-400):** Encoded hash parsing caps length at 160 and checks salt and digest lengths exactly (`PasswordHasher.java:64-81`), the lookup discards over-length hashes (`AccountStore.java:145`), accounts are capped at 100,000 (`AccountStore.java:21`), failure counters are clamped to `[0, 1000000]` (`AccountStore.java:242`), and the log is capped at 1 MiB (`SecurityLog.java:13`).
- **Sessions, tokens, cookies, XSS, CSRF, SSRF, deserialization:** None of these surfaces exist in this component — there is no HTTP server or client, no template or HTML output, no session or token issuance, no `ObjectInputStream` or other deserialization of untrusted data, and no outbound network call. Verified by reading all six source files and the test; no finding is possible for these classes here.
- **Dependency integrity:** A single runtime dependency pinned to `org.xerial:sqlite-jdbc:3.53.4.0` with all build plugins version-pinned (`pom.xml:16-48`), Maven `--strict-checksums` enabled (`.mvn/maven.config:1`), and a maintainer-published SHA-256 verified by `scripts/verify-dependencies.sh:4-16`. Advisory note, not a finding: that script is a documented manual step rather than a build-enforced gate, so `mvn package` succeeds without it; binding it to a Maven phase (or using the `maven-dependency-plugin` checksum verification) would make the control non-optional. Native library extraction is redirected into the private `0700` directory rather than a shared temporary directory (`AccountStore.java:33-35`), avoiding untrusted-code loading from a world-writable location.
- **Operational note, not a finding:** `PasswordHasher.parse` requires the stored iteration count to equal the current `ITERATIONS` constant exactly (`PasswordHasher.java:69`), so raising the cost later invalidates every existing hash and silently converts all logins into failures. This is an upgrade-path/availability concern rather than a vulnerability, but it should be replaced with "accept any iteration count within an allowed range and re-hash on successful login."
