# Security Review: Account Registration and Sign-In CLI

## 1. Executive Summary
The component is a Java 17 command-line account service that validates registration and login input, stores Argon2id password verifiers in H2, issues hashed opaque session tokens, builds hardened session cookies, rate-limits authentication, and writes an owner-only audit trail. The review found four vulnerabilities: a High-severity H2 JDBC URL injection through the configurable data-directory path, a Medium-severity missing authorization check on the bulk session-revocation command, and two Low-severity weaknesses involving unthrottled session verification and timing differences when stored password costs differ from the active policy. The code otherwise has strong controls around parameterized SQL, password hashing, randomness, cookie flags, secret redaction, transaction rollback, and audit-file handling.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/app/AccountStore.java` | Creates, looks up, and upgrades accounts. | Uses prepared statements, unique constraints, Argon2id verifiers, registration throttling, and transactional audit records. |
| `src/main/java/app/AuditLog.java` | Maintains the append-only JSON-lines security trail. | Enforces owner-only mode, no-follow writes, bounded size, escaping, and fail-closed append errors. |
| `src/main/java/app/AuthService.java` | Authenticates credentials and manages session resolution/logout. | Performs dummy password work, account/source throttling, lockout, hash upgrade, session issuance, and security auditing. |
| `src/main/java/app/Config.java` | Loads paths, database secrets, and Argon2 policy. | Builds the H2 JDBC URL, checks filesystem modes/symlinks, reads a password file, and bounds KDF settings. |
| `src/main/java/app/CookiePolicy.java` | Renders issue/delete session cookies. | Validates token/path syntax and sets `Secure`, `HttpOnly`, `SameSite=Strict`, `Path`, and expiry attributes. |
| `src/main/java/app/Db.java` | Owns the JDBC connection, schema, and transaction wrapper. | Defines database constraints, serializes transactions, applies lock timeout, and rolls back on audit/store failures. |
| `src/main/java/app/Digests.java` | Provides SHA-256 and hexadecimal encoding helpers. | Hashes high-entropy session tokens and salted audit correlation values. |
| `src/main/java/app/Gate.java` | Gates security decisions on audit persistence. | Produces per-process-salted tags and propagates audit failures. |
| `src/main/java/app/InputPolicy.java` | Validates all account and password fields. | Enforces length, character, canonicalization, reserved-name, and password-composition rules. |
| `src/main/java/app/Main.java` | Parses commands, reads secrets, and dispatches operations. | Defines the CLI trust boundary, source identity, output behavior, and privileged bulk-revocation path. |
| `src/main/java/app/Maintenance.java` | Removes expired sessions and stale throttle state. | Bounds security-state growth while preserving live lockouts and budgets. |
| `src/main/java/app/PasswordHasher.java` | Encodes and verifies Argon2id password hashes. | Uses CSPRNG salts, bounded parameters, canonical PHC parsing, and constant-time digest comparison. |
| `src/main/java/app/Secrets.java` | Holds erasable secret character arrays. | Redacts `toString()` and zeroes owned buffers on close. |
| `src/main/java/app/SessionStore.java` | Issues, resolves, revokes, and purges sessions. | Generates 256-bit tokens, stores only SHA-256 token hashes, uses prepared statements, expiry, and transactional revocation. |
| `src/main/java/app/Throttle.java` | Implements source quotas and account lockout. | Uses atomic SQL updates, row locks, separate scopes, decay windows, and safe stale-state cleanup. |
| `src/test/java/app/AccountStoreTest.java` | Tests account persistence and schema defenses. | Covers duplicate handling, throttling, credential secrecy, SQL constraints, and guarded rehashing. |
| `src/test/java/app/AuditFailClosedTest.java` | Tests audit tampering and recovery. | Covers modes, symlinks, directories, transaction rollback, trail retirement, and recovery. |
| `src/test/java/app/AuthServiceTest.java` | Tests authentication paths and timing. | Covers uniform messages/work at one policy cost, lockout, source limits, recovery, and rehashing. |
| `src/test/java/app/CliTest.java` | Exercises CLI behavior through streams. | Covers prompts, exit codes, operand refusal, source-key behavior, and audit events. |
| `src/test/java/app/ConfigTest.java` | Tests environment and path configuration. | Covers KDF bounds, password-file modes, data/store modes, symlinks, and ordinary JDBC URL options. |
| `src/test/java/app/CookiePolicyTest.java` | Tests cookie construction. | Covers cookie flags, path/token injection resistance, lifetime bounds, and deletion cookies. |
| `src/test/java/app/Harness.java` | Provides test fixtures and assertions. | Creates private temporary stores, mutable clocks, services, and controlled credentials. |
| `src/test/java/app/InputPolicyTest.java` | Tests trust-boundary validation. | Covers accepted/rejected identities, passwords, control characters, lengths, and canonicalization. |
| `src/test/java/app/MaintenanceTest.java` | Tests cleanup safety. | Verifies sweeps do not reset live source limits or account lockouts. |
| `src/test/java/app/PasswordHasherTest.java` | Tests password-hash behavior. | Covers parameter bounds, malformed hashes, canonical Base64, interoperability, timing, and policy upgrades. |
| `src/test/java/app/SchemaBoundsTest.java` | Tests schema/KDF bound consistency. | Verifies accepted cost ranges and credential widths agree with database constraints. |
| `src/test/java/app/SessionStoreTest.java` | Tests session lifecycle. | Covers entropy/shape, hashed storage, expiry, scoped revocation, foreign keys, and audit redaction. |
| `src/test/java/app/SourceDisciplineTest.java` | Performs source-pattern regression checks. | Scans for hardcoded secrets, weak crypto, SQL composition, secret sinks, subprocesses, shared paths, and unsafe audit opens. |
| `scripts/build.sh` | Verifies dependencies and compiles production sources. | Uses an absolute runtime classpath and pinned dependencies. |
| `scripts/get-deps.sh` | Downloads and verifies dependency jars. | Enforces pinned SHA-256, mirror agreement, published SHA-1, expected entries, and required signatures. |
| `scripts/run.sh` | Rebuilds when needed and launches the CLI. | Uses an absolute classpath and re-verifies dependency jars before launch. |
| `scripts/test.sh` | Compiles and runs the plain-Java test suites. | Uses pinned dependencies and separate production/test output paths. |
| `deps.lock` | Pins runtime and test dependencies. | Supplies artifact coordinates, hashes, expected entries, and signature requirements. |
| `README.md` | Documents operation, threat assumptions, tests, and residual risks. | Declares the operator trust model, security claims, and known timing/authorization limitations. |
| `bin/app/*.class`, `build/test-classes/app/*.class` | Precompiled copies of reviewed production/test sources. | Generated bytecode was not executed; the corresponding Java sources were the authoritative review target. |
| `libs/*.jar`, `libs/test/*.jar` | Pinned third-party H2, Bouncy Castle, Spring Security, and Commons Logging binaries. | Dependency acquisition and pinning code was reviewed; vendored library internals were not decompiled as application source. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory every source file, map security-relevant behavior, select specialized review skills, and require CWE/file-line evidence.
- `testing-for-broken-access-control`: Applied to the command/function matrix, especially privileged bulk session revocation and ownership-sensitive session operations.
- `performing-cryptographic-audit-of-application`: Applied to Argon2id parameters and parsing, salt/token entropy, SHA-256 uses, constant-time comparison, secret handling, and hardcoded-secret checks.
- `exploiting-sql-injection-vulnerabilities`: Applied statically to every SQL statement, private dynamic predicate, bind operation, schema statement, and the H2 connection initialization surface.
- `implementing-api-rate-limiting-and-throttling`: Applied to login, registration, malformed-input, duplicate-registration, session-verification, and maintenance paths.
- `testing-for-sensitive-data-exposure`: Applied to password/token storage, CLI output, audit content, exception messages, file modes, and configuration secrets.
- `performing-security-headers-audit`: Applied to the generated session cookie's `Secure`, `HttpOnly`, `SameSite`, path, and expiry attributes; other HTTP headers are out of scope because the component contains no web server.
- General OWASP Top 10 / CWE knowledge: Applied to filesystem check/use races, H2 JDBC URL metacharacters, CLI parsing, audit-retention abuse, transaction boundaries, resource exhaustion, and timing side channels where no closer library skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Data-directory input can inject H2 JDBC settings and initialization SQL | High | CWE-89 | `src/main/java/app/Config.java:104` |
| SEC-02 | Bulk session revocation has no authorization check | Medium | CWE-862 | `src/main/java/app/Main.java:303-327` |
| SEC-03 | Session verification is unthrottled and can churn the audit trail | Low | CWE-770 | `src/main/java/app/AuthService.java:283-288` |
| SEC-04 | Mixed Argon2 costs expose account existence through response time | Low | CWE-208 | `src/main/java/app/AuthService.java:184-206` |

## 5. Detailed Findings

### SEC-01: Data-directory input can inject H2 JDBC settings and initialization SQL
- **Severity:** High
- **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- **Location:** `src/main/java/app/Config.java:97-108,147-149`

**Vulnerable code:**
```java
// src/main/java/app/Config.java:97-108,147-149
        String dirValue = firstOption(argv, "--data-dir");
        if (dirValue == null) {
            dirValue = env.apply(ENV_DATA_DIR);
        }
        if (dirValue == null || dirValue.isEmpty()) {
            throw new ConfigException(ENV_DATA_DIR + " (or --data-dir) must be set");
        }
        Path dataDir = Path.of(dirValue).toAbsolutePath().normalize();
        ensurePrivateDirectory(dataDir);

        Path dbBase = dataDir.resolve("accounts");
        ensurePrivateStoreFile(dbBase);

    public String jdbcUrl() {
        return "jdbc:h2:file:" + dbBase + DB_OPTIONS;
    }
```

**Why it is a problem:** H2 uses semicolons in a JDBC URL to introduce connection settings, and its `INIT` setting executes SQL when a connection is opened. H2 also specifies that an embedded database name must not contain a semicolon. `--data-dir` and `APP_DATA_DIR` accept arbitrary path text, including `;`, and that text is concatenated directly into the JDBC URL. A caller who can influence either configuration source can therefore terminate the intended file path and add H2 settings such as `INIT`, redirect the database away from the pre-created owner-only store, or weaken hardening options. Depending on the injected SQL and enabled H2 facilities, impact can include arbitrary database modification and code execution in the application process. The filesystem checks validate the literal OS path, not the different path/settings interpretation performed later by H2.

**Fix:** Reject H2's URL delimiter and control characters before converting the value to a path, and keep all JDBC settings code-owned. Because H2 explicitly disallows semicolons in database names, rejecting them does not remove a valid file-database use case. Add regression tests for both the environment and `--data-dir` forms.
```java
private static Path validatedDataDir(String value) throws ConfigException {
    if (value == null || value.isEmpty()) {
        throw new ConfigException(ENV_DATA_DIR + " (or --data-dir) must be set");
    }
    if (value.indexOf(';') >= 0 || value.chars().anyMatch(Character::isISOControl)) {
        throw new ConfigException("the data directory contains a character that is not allowed in an H2 file URL");
    }
    return Path.of(value).toAbsolutePath().normalize();
}

String dirValue = firstOption(argv, "--data-dir");
if (dirValue == null) {
    dirValue = env.apply(ENV_DATA_DIR);
}
Path dataDir = validatedDataDir(dirValue);
ensurePrivateDirectory(dataDir);

public String jdbcUrl() {
    return "jdbc:h2:file:" + dbBase + DB_OPTIONS;
}
```

### SEC-02: Bulk session revocation has no authorization check
- **Severity:** Medium
- **CWE:** CWE-862: Missing Authorization
- **Location:** `src/main/java/app/Main.java:303-327`

**Vulnerable code:**
```java
// src/main/java/app/Main.java:303-327
    private int revokeSessions(AccountStore accounts, SessionStore sessions)
        throws IOException, SQLException, AuditLog.AuditException {
        char[] usernameChars;
        try {
            usernameChars = reader.readLine("Username: ");
        } catch (InputTooLong oversized) {
            out.println("Sign-out is complete.");
            recordQuietly(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT, "input line too long");
            return REFUSED;
        }
        try {
            String username;
            try {
                username = InputPolicy.username(usernameChars);
            } catch (InputPolicy.ValidationException invalid) {
                // Same wording as the success path: this command must not reveal whether an
                // account exists either. The event names the operation that was refused, not
                // registration - a trail that labelled an admin refusal as a sign-up would send
                // whoever reads it looking for the wrong attack.
                out.println("Sign-out is complete.");
                recordQuietly(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT, invalid.getMessage());
                return REFUSED;
            }
            AccountStore.Account account = accounts.findByUsername(username);
            int revoked = account == null ? 0 : sessions.revokeAllForAccount(account.id());
```

**Why it is a problem:** The method and audit events identify this as an administrative operation, but the dispatcher invokes it without authentication, role validation, an operator capability, or confirmation tied to a privileged identity. Knowledge of a valid username is sufficient to terminate every live session for that account. File permissions and possession of the database password may limit who can start this standalone CLI, but they are deployment assumptions rather than an application authorization control; the README itself warns that the command must be wrapped before exposure. If the CLI is called by a service, job runner, support tool, or wrapper that supplies configuration, any caller who can select this command can force arbitrary-user logout.

**Fix:** Require a separately authenticated and authorized operator context before accepting the target username, and fail closed before account lookup or revocation. Do not treat access to ordinary login/registration commands as administrative authority.
```java
private int revokeSessions(AccountStore accounts, SessionStore sessions,
    OperatorAuthorizer operator) throws IOException, SQLException, AuditLog.AuditException {
    if (!operator.isAuthenticated() || !operator.hasPermission("sessions:revoke-all")) {
        gate.record(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT,
            "reason", "operator authorization failed");
        err.println("This operation is not authorized.");
        return REFUSED;
    }

    char[] usernameChars = reader.readLine("Username: ");
    try {
        String username = InputPolicy.username(usernameChars);
        AccountStore.Account account = accounts.findByUsername(username);
        int revoked = account == null ? 0 : sessions.revokeAllForAccount(account.id());
        gate.record(AuditLog.Event.ADMIN_REVOKE_REQUESTED,
            "operator", operator.auditTag(), "username", gate.usernameTag(username),
            "account", account == null ? "none" : gate.accountTag(account.id()),
            "count", Integer.toString(revoked));
        out.println("Sign-out is complete.");
        return OK;
    } finally {
        Arrays.fill(usernameChars, '\0');
    }
}
```

### SEC-03: Session verification is unthrottled and can churn the audit trail
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/app/AuthService.java:283-288`

**Vulnerable code:**
```java
// src/main/java/app/AuthService.java:283-288
    public Long resolveSession(String token) {
        try {
            Long accountId = sessions.resolve(token);
            if (accountId == null) {
                gate.record(AuditLog.Event.SESSION_REJECTED, "session", gate.sessionTag(token));
            }
            return accountId;
```

**Why it is a problem:** Login and registration have source budgets, but `verify` accepts an unlimited stream of well-formed random tokens. Each miss performs a transaction and indexed database lookup and then appends an audit record. A caller with access to the CLI invocation context can therefore consume CPU/I/O and repeatedly force the 64 MiB trail to retire older evidence. Token entropy prevents guessing a valid token but does not prevent resource exhaustion or audit-history churn. The fixed maximum log size limits disk consumption, not request rate or loss of older records.

**Fix:** Give verification and logout their own source-scoped budgets, charge them before database access, and audit throttling with a bounded event strategy. The caller must pass a server-derived source key, not an attacker-selected identifier.
```java
public Long resolveSession(String token, String sourceId) {
    try {
        boolean allowed = Boolean.TRUE.equals(accounts.db().inTransaction(connection ->
            throttle.tryConsumeSource(connection, Throttle.VERIFY_SOURCE_SCOPE, sourceId)));
        if (!allowed) {
            return null;
        }
        Long accountId = sessions.resolve(token);
        if (accountId == null) {
            gate.record(AuditLog.Event.SESSION_REJECTED, "session", gate.sessionTag(token));
        }
        return accountId;
    } catch (SQLException | AuditLog.AuditException fault) {
        return null;
    }
}

// CLI call site:
Long accountId = auth.resolveSession(sessionHandleFrom(operands, reader), sourceKey("verify"));
```

### SEC-04: Mixed Argon2 costs expose account existence through response time
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/app/AuthService.java:184-206`

**Vulnerable code:**
```java
// src/main/java/app/AuthService.java:184-206
            if (account == null) {
                paidForWork[0] = true;
                hasher.verify(password, dummyHash);
                gate.record(AuditLog.Event.LOGIN_FAILURE, "reason", "no such account",
                    "source", gate.sourceTag(sourceId),
                    "identity", identity.byEmail() ? gate.emailTag(identity.value())
                        : gate.usernameTag(identity.value()));
                outcome[0] = invalid();
                return Boolean.FALSE;
            }

            Throttle.AccountGuard guard = throttle.lockAccountGuard(connection, account.id());
            if (guard.isBlocked(clock.instant().getEpochSecond())) {
                paidForWork[0] = true;
                hasher.verify(password, dummyHash);
                gate.record(AuditLog.Event.LOGIN_THROTTLED_ACCOUNT, "account", gate.accountTag(account.id()),
                    "source", gate.sourceTag(sourceId));
                outcome[0] = throttled();
                return Boolean.FALSE;
            }

            paidForWork[0] = true;
            if (!hasher.verify(password, account.passwordHash())) {
```

**Why it is a problem:** `dummyHash` is generated with the currently configured Argon2 cost, while a real account is verified with the parameters embedded in its stored hash. The schema intentionally permits a wide range (`m=19456..1048576`, `t=2..20`, `p=1..8`) and configuration can change between runs. During a cost migration, unknown accounts consume the current dummy cost while existing accounts consume their individual stored cost. The difference can be seconds and hundreds of MiB at the allowed extremes, making account existence observable despite identical messages. The README acknowledges this window, and the timing tests only exercise a steady-state fixture where costs match.

**Fix:** Do not serve authentication while multiple online verification costs exist. Perform an authenticated offline migration (or require password reset) and verify at startup that every stored credential exactly matches the active cost before constructing the service. This makes the real and dummy derivations use one invariant cost.
```java
private static void requireUniformPasswordCost(Connection connection, PasswordHasher hasher)
    throws SQLException {
    try (PreparedStatement query = connection.prepareStatement("""
        SELECT COUNT(*) FROM accounts
         WHERE kdf_memory_kib <> ? OR kdf_iterations <> ? OR kdf_parallelism <> ?
        """)) {
        query.setInt(1, hasher.policyMemoryKib());
        query.setInt(2, hasher.policyIterations());
        query.setInt(3, hasher.policyParallelism());
        try (ResultSet rows = query.executeQuery()) {
            rows.next();
            if (rows.getLong(1) != 0) {
                throw new SQLException("password-cost migration is required before authentication can start");
            }
        }
    }
}

// Run after schema creation and before AuthService is made available.
database.inTransaction(connection -> {
    requireUniformPasswordCost(connection, hasher);
    return Boolean.TRUE;
});
```

## 6. Verified Controls and Checks With No Finding
- SQL value binding: All user-reachable email, username, token-hash, account-id, time, count, and throttle values use `PreparedStatement` bind parameters. The two concatenated predicates in `AccountStore.select` and `AuthService.accountBy` are private and only receive fixed code literals.
- Password storage: Passwords are hashed with Argon2id, 16-byte CSPRNG salts, bounded parameters at or above the configured floor, canonical PHC parsing, and `MessageDigest.isEqual`; plaintext passwords are not persisted.
- Session tokens: `SessionStore` generates 32 random bytes with `SecureRandom`, exposes 64 lowercase hex characters, stores only SHA-256 of the high-entropy token, validates shape before lookup, and enforces absolute expiry/revocation.
- Cookie policy: Issued and deletion cookies include `Secure`, `HttpOnly`, `SameSite=Strict`, an explicit validated path, and server-derived `Max-Age`/`Expires`; token and path validation prevents header injection.
- Login and registration throttling: Source consumes are atomic database updates, account failures use row locks, malformed login input is charged, duplicate registration is charged after rollback, and stale-state cleanup preserves live windows.
- Authentication failure handling: Invalid identifiers, unknown accounts, incorrect passwords, lockouts, and source throttling share client-visible wording; store/audit errors fail closed and issue no session.
- Transaction integrity: `Db.inTransaction` serializes the single connection, reuses nested transactions without early commit, commits only successful outer calls, and rolls back SQL, runtime, and audit failures.
- Audit record integrity: Values are escaped and bounded; identifiers and tokens are represented by per-process-salted tags; appends use `NOFOLLOW_LINKS` without `CREATE`; owner-only mode and regular-file checks are enforced.
- Secret configuration: No credential is hardcoded; the database password is required from environment or a private file, excluded from the JDBC URL, redacted by `Secrets.toString()`, and its mutable copy is erased on retirement.
- File permissions: The data directory is tightened to `0700`; database and audit files are required/created as `0600`; symlinks and non-regular final files are rejected. Residual check/use race concerns require an attacker able to mutate a path in the operator-controlled filesystem namespace and were not elevated beyond the documented deployment boundary.
- Dependency integrity: Artifact versions and SHA-256 digests are pinned; downloads are compared across two distributors, checked against published SHA-1, checked for expected jar entries, and Bouncy Castle is required to carry a valid jar signature.
- Subprocess/dynamic loading exposure: Production Java code spawns no subprocess and performs no dynamic class loading; launch/build scripts use absolute repository-derived classpaths.
- Sensitive output: Passwords, database credentials, raw identifiers, stored password hashes, bearer tokens, and token lookup hashes are not written to the audit trail or exception responses. The session cookie is printed only on successful login as the CLI's delivery mechanism.
- Input bounds and canonicalization: Account fields are length/character checked, email case-folding is deterministic, usernames are canonical lowercase ASCII, passwords are bounded before KDF use, and session tokens are exact-shape checked.
- Maintenance safety: Expired/revoked sessions and stale throttle rows are removed, while active source windows, failure windows, and account lockouts are retained.
