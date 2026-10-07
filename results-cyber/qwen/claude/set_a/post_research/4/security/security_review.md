# Security Review: secure-accounts (com.example:secure-accounts — Java account/authentication library + CLI)

## 1. Executive Summary

The project is a self-contained Java 17 account library with a CLI front end: Argon2id password hashing with a pepper, server-side sessions (only SHA-256 digests of tokens stored), SQLite persistence, per-source/per-account authentication throttling, and enumeration-resistant (uniform-work) login handling. Overall the code is unusually defensive — parameterised SQL throughout, constant-time hash comparison, cost-parameter bounds at parse time, `__Host-`-style session cookie attributes, allowlist input validation with confusable folding, fail-closed error handling, and secret-wiping hygiene on the main paths. Tests cover many of the claimed properties.

Ten findings were identified, none of which enable remote code execution or wholesale credential theft, but several weaken the stated security rules:

* **One High**: `AccountService.authenticate` verifies the password outside any transaction and then mints a session and blindly overwrites the password hash in a second transaction, without re-checking the account's `disabled` flag or the previously-read hash. An admin disable (or a concurrent hash upgrade) that lands between the read and the commit is silently ignored — a session is issued for a disabled account, and a lost `UPDATE ... WHERE id = ?` can resurrect an older password hash (SEC-01).
* **Medium**: with no pepper configured (the default), throttle keys are unsalted SHA-256 of email/IP-derived strings, turning `auth_attempt` into a brute-forceable identity/IP log (SEC-02); a stored-hash parse failure returns in microseconds with zero Argon2 work, and the decoy is always hashed at current cost while legacy accounts may be cheaper — both break the uniform-timing guarantee the design promises (SEC-03); the password policy is a 20-entry blocklist that admits high-frequency breached passwords (SEC-04); the database file is created under the process umask and only chmod'ed afterwards, with failures logged and ignored (SEC-05).
* **Low / informational**: pepper lifecycle leaks copies on long-lived hosts (SEC-06), the `jdbc:sqlite:` prefix check permits arbitrary on-disk paths (SEC-07), the never-cleared per-source counter plus a tiny source-id space creates shared-NAT lockout (SEC-08), revoked sessions are deleted on prune leaving no audit trail (SEC-09), and CSRF defence rests solely on `SameSite=Strict` (SEC-10).

## 2. Scope

Source folder (read-only, reviewed statically; never executed or built): `/data/results/claude/set_a/post_research/4/security/`.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/accounts/AccountService.java` | Register/authenticate orchestration | Throttle gate + account read in tx1, Argon2 verify outside any tx, session issue + hash upgrade in tx2; decoy-hash equal-work for nonexistent/disabled accounts |
| `src/main/java/com/example/accounts/App.java` | CLI entry point (register/login/whoami/logout) | Reads secrets via console, derives `sourceId` from OS username, stores session token in `0600` file, wipes pepper in `finally` |
| `src/main/java/com/example/accounts/Config.java` | Environment-driven configuration | Pepper decode (optional, 16–64 B), Argon2 bound checks, `jdbc:sqlite:` prefix allowlist, owner-only data dir, pepper accessor returns live array |
| `src/main/java/com/example/accounts/Database.java` | SQLite lifecycle | JDBC URL prefix check, WAL/IMMEDIATE pragmas, per-transaction connections, schema migration, post-migration chmod of DB files (fail-open) |
| `src/main/java/com/example/accounts/PasswordHasher.java` | Argon2id PHC strings | Random 16-B salt, pepper as secret, constant-time `MessageDigest.isEqual`, parse-time cost bounds, `needsRehash`, decoy hash generation |
| `src/main/java/com/example/accounts/InputValidator.java` | Allowlist validation | RFC-5321-ish email/username rules with NFKC confusable folding, reserved names, OpaqueString password prep, 12-char minimum, 20-entry blocklist, distinct-char and monotonic-run checks |
| `src/main/java/com/example/accounts/SessionService.java` | Server-side sessions | 32-byte `SecureRandom` token, SHA-256(token) stored, idle + absolute expiry, touch/revoke/prune SQL |
| `src/main/java/com/example/accounts/ThrottleService.java` | Sliding-window attempt limiting | SHA-256(pepper\|scope:identifier) keys, UPSERT check-and-count in caller's tx, success clears account scope only |
| `src/main/java/com/example/accounts/AccountRepository.java` | Account DAO | Parameterised SELECT/INSERT/UPDATE; uniqueness decided by UNIQUE constraints; blind `UPDATE ... WHERE id = ?` hash upgrade |
| `src/main/java/com/example/accounts/Logging.java` | Audit logging | 0600 single-wrap log file, symlink refusal, CRLF/line-separator folding, lambda (lazy) messages |
| `src/main/java/com/example/accounts/SessionCookie.java` | Cookie rendering | `__Host-session=...; Path=/; HttpOnly; Secure; SameSite=Strict`, no `Domain` |
| `src/main/java/com/example/accounts/Mask.java` | Log redaction | Email/username/JDBC-URL masking before logging |
| `src/main/java/com/example/accounts/Wipe.java` | Secret erasure helper | `Arrays.fill` of char[]/byte[] |
| `src/main/java/com/example/accounts/Hex.java` | Hex encoding | Used for throttle keys and digests |
| `src/main/java/com/example/accounts/ValidationException.java` | Validation error type | Message is user-safe (no secret echo) |
| `pom.xml` | Build | HTTPS-only Maven Central, `checksumPolicy=fail`, pinned deps (BC 1.79, sqlite-jdbc 3.47.1.0), shade fat jar |
| `src/test/java/...` (4 test classes) | Tests | Assert pepper requirement, hostile-cost-param refusal, enumeration uniformity, confusable folding, etc. — context for behaviour, not separately reviewed for defects |

`README.md`, `prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt`, and `target/` were not treated as review targets (the last four are harness artifacts, `target/` is build output).

## 3. Skills Applied

* **`performing-cryptographic-audit-of-application`** — applied to `PasswordHasher.java` (Argon2id parameters vs OWASP floor, per-hash random salt, pepper as KDF secret, PHC parse-time bound checks, constant-time comparison via `MessageDigest.isEqual`), `SessionService.java` (256-bit `SecureRandom` token entropy, digest-at-rest), and `Config.java`/`ThrottleService.java`/`App.java` for secret lifecycle (pepper provenance, copying, and wiping → SEC-02, SEC-06).
* **`testing-api-authentication-weaknesses`** — applied to the session lifecycle in `SessionService.java` (token format validated before query, idle + absolute expiry, touch requires exactly one row updated, revocation → SEC-09), to `AccountService.java` login flow (attempt limiting, enumeration resistance, token leakage into logs/files → SEC-01, SEC-03), and to password policy in `InputValidator.java` (SEC-04). Its JWT/OAuth-specific steps are not applicable — the component issues opaque session tokens, not bearer JWTs.
* **`testing-for-sensitive-data-exposure`** — applied to at-rest protection and redaction: DB/log/session-token file permissions and creation windows (`Database.java`, `Logging.java`, `App.java` → SEC-05), identifier masking (`Mask.java`), pepper/char[]-wipe hygiene (→ SEC-06), and a hardcoded-secrets sweep across the tree (none found; pepper is env-only and `toString()` masks it).
* **`exploiting-race-condition-vulnerabilities`** — applied to the multi-step login workflow and the throttle/verify/commit sequence in `AccountService.java` (read-verify-commit split across two transactions → SEC-01), and to check-then-create patterns elsewhere — the UNIQUE-constraint-as-authority design under `BEGIN IMMEDIATE` was verified race-safe (see §6).
* **`testing-for-broken-access-control`** — applied to session-as-authorization and account-state enforcement: disabled-account handling, revocation, and whether authorization state is re-checked at the enforcement point (→ SEC-01).

Behaviours covered by general OWASP/CWE knowledge rather than a specialised skill from the library (a name-grep of the skill index confirmed no matching checklist): configuration-surface validation of `ACCOUNTS_JDBC_URL` (→ SEC-07), source-id bucketing and availability/lockout design (→ SEC-08), audit-trail retention (→ SEC-09), and `SameSite`-only CSRF posture (→ SEC-10). The library's remaining candidates (JWT/OAuth/web-pentest/mobile/cloud/forensics skills) do not match a CLI-plus-library SQLite component.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Verify-then-commit TOCTOU: session issued and hash upgraded without re-checking account state | High | CWE-367 | `AccountService.java:157-215`; `AccountRepository.java:36-38, 93-101` |
| SEC-02 | Throttle keys are unsalted SHA-256 when pepper is unset (default) — reversible identity/IP log | Medium | CWE-261 | `ThrottleService.java:190-204`; `Config.java:165-168` |
| SEC-03 | Timing side-channel: zero-work rejection of unparsable hashes and cost-mismatched decoy | Medium | CWE-208 | `PasswordHasher.java:87-108`; `AccountService.java:182, 189-190` |
| SEC-04 | Weak-password policy: 20-entry blocklist admits common breached passwords | Medium | CWE-521 | `InputValidator.java:40-45, 245, 271` |
| SEC-05 | Database files created under process umask; restrictive chmod only afterwards, fail-open | Medium | CWE-276 | `Database.java:53-54, 103-124` |
| SEC-06 | Pepper copied into services and never wiped; accessor hands out the live array | Low-Medium | CWE-244 | `Config.java:228-231`; `ThrottleService.java:80`; `PasswordHasher.java:60`; `App.java:103` |
| SEC-07 | `jdbc:sqlite:` prefix-only allowlist permits arbitrary on-disk database paths | Low | CWE-22 | `Config.java:153-163`; `Database.java:41-43` |
| SEC-08 | Source counter never cleared by success + tiny source-id space → shared-source lockout | Low | CWE-770 | `ThrottleService.java:121-134`; `AccountService.java:289+`; `App.java:239-241` |
| SEC-09 | Revoked sessions deleted on prune — no durable revocation audit trail | Low | CWE-778 | `SessionService.java:48-50, 56-58` |
| SEC-10 | CSRF defence rests solely on `SameSite=Strict`; no `Origin`/anti-CSRF hook for a future HTTP layer | Informational | CWE-352 | `SessionCookie.java:31-45`; `README.md` |

## 5. Detailed Findings

### SEC-01: Verify-then-commit TOCTOU — session issued and password hash overwritten without re-checking account state

- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition (with authorization-impact per CWE-863)
- **Location:** `src/main/java/com/example/accounts/AccountService.java:157-215`, `src/main/java/com/example/accounts/AccountRepository.java:36-38` and `93-101`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/AccountService.java:157-215 (condensed to the load-bearing lines)
        Decisionable gate = database.inTransaction(connection -> {
            ThrottleService.Decision decision =
                    throttle.tryAcquire(connection, source, lookupKey, now);
            if (!decision.allowed()) {
                return new Decisionable(decision, null);
            }
            Optional<AccountRepository.Account> account =
                    lookupKey == null ? Optional.empty() : accounts.findByLogin(connection, lookupKey);
            return new Decisionable(decision, account.orElse(null));
        });
...
        AccountRepository.Account account = gate.account();
        // A disabled account verifies against the decoy too, so "disabled" is not observable.
        boolean usable = account != null && !account.disabled();
...
            String candidateHash = usable ? account.passwordHash() : decoyHash;
            verified = hasher.verify(prepared, candidateHash) && usable;
...
            final long accountId = account.id();
            final boolean rehash = hasher.needsRehash(account.passwordHash());
            final String upgraded = rehash ? hasher.hash(prepared) : null;

            // Step 2 (atomic): clear the account counter and mint the session together.
            SessionService.IssuedSession issued = database.inTransaction(connection -> {
                throttle.clearAccount(connection, lookupKey, now);
                if (upgraded != null) {
                    accounts.updatePasswordHash(connection, accountId, upgraded, now);
                }
                return sessions.issue(connection, accountId, now);
            });
```

```sql
-- src/main/java/com/example/accounts/AccountRepository.java:36-38
    private static final String UPDATE_HASH_SQL = """
            UPDATE account SET password_hash = ?, password_changed_at = ? WHERE id = ?
            """;
```

**Why it is a problem:** The account row (including `disabled` and `password_hash`) is read in transaction 1. Argon2 verification deliberately takes ~0.1–1 s *outside any transaction* — a wide window — and transaction 2 then (a) issues a session for `accountId` and (b) blindly writes a new hash, both keyed only by `accountId`. Neither statement re-checks what changed in the window. Concretely:

1. **Disabled mid-login becomes a successful login.** An operator disables the account (or it is disabled by any future administrative path) after tx1's read but before tx2's commit. The session is still minted for a disabled account — `sessions.issue()` never consults `account.disabled` — so the disable is silently defeated for exactly the race window, and the resulting session persists for its full idle/absolute lifetime. The code's own rule ("a disabled account verifies against the decoy") is enforced only at the moment of the stale read.
2. **Lost-update hash resurrection.** `UPDATE_HASH_SQL` has no expected-old-value guard. Two concurrent successful logins for the same account (each rehashing, e.g. after a cost-parameter bump — salts differ, so both compute a different `upgraded`), or a rehash interleaving with any other future writer of `password_hash`, can commit in either order; the *older* derived hash can overwrite the newer one, and `password_changed_at` moves forward regardless of which hash won. The session minted in the losing transaction then authenticates against a hash the service believes it replaced. SQLite's `IMMEDIATE` write lock serialises the two transactions, which is precisely why the blind write silently clobbers rather than conflicts.

The uniform-work design (Argon2 outside the tx) is worth keeping; the fix is to make tx2 conditional on fresh state, not to shrink the window.

**Fix:** Re-read and re-validate inside transaction 2, and make the upgrade compare-and-swap:

```java
// src/main/java/com/example/accounts/AccountService.java (transaction 2)
            final String expectedHash = account.passwordHash();
            SessionService.IssuedSession issued = database.inTransaction(connection -> {
                throttle.clearAccount(connection, lookupKey, now);
                // Re-check state at the enforcement point: the row read before hashing may be stale.
                Optional<AccountRepository.Account> fresh = accounts.findById(connection, accountId);
                if (fresh.isEmpty() || fresh.get().disabled()
                        || !fresh.get().passwordHash().equals(expectedHash)) {
                    throw new SQLException("account state changed during authentication"); // rolls back
                }
                if (upgraded != null) {
                    accounts.updatePasswordHash(connection, accountId, expectedHash, upgraded, now);
                }
                return sessions.issue(connection, accountId, now);
            });
```

```sql
-- src/main/java/com/example/accounts/AccountRepository.java
            UPDATE account SET password_hash = ?, password_changed_at = ?
            WHERE id = ? AND password_hash = ? AND disabled = 0
```

With `updatePasswordHash` throwing unless `executeUpdate() == 1`, a stale read, a mid-flight disable, or a concurrent upgrade aborts the whole transaction — no session, no clobbered hash.

### SEC-02: Unsalted SHA-256 throttle keys when the pepper is unset (the default) turn `auth_attempt` into a recoverable identity log

- **Severity:** Medium
- **CWE:** CWE-261: Weak Encoding for Password-adjacent Identifiers (weak, unsalted digest of sensitive identifiers; disclosure per CWE-359)
- **Location:** `src/main/java/com/example/accounts/ThrottleService.java:190-204`, `src/main/java/com/example/accounts/Config.java:165-168`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/ThrottleService.java:190-204
    private String key(String scope, String identifier) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        if (pepper.length > 0) {
            digest.update(pepper);
        }
        digest.update(scope.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) ':');
        digest.update(identifier.getBytes(StandardCharsets.UTF_8));
        return Hex.encode(digest.digest());
    }
```

```java
// src/main/java/com/example/accounts/Config.java:165-168
    private static byte[] decodePepper(String raw) {
        if (raw == null || raw.isEmpty()) {
            return new byte[0];
        }
```

**Why it is a problem:** `ACCOUNTS_PEPPER_B64` is optional (`Config.java:165-168` returns an empty pepper when unset), and the guard at line 197 then makes `scope_key = SHA-256("source:" <identifier>)` — a *fast, unsalted* digest of the identifier. Both identifier spaces are trivially recoverable by offline brute force against the rows in `auth_attempt`:

* account scope keys are SHA-256 of a canonical email or username. Anyone who can read the database file (backup, snapshot, another process running as the same user before SEC-05's chmod lands) can confirm membership of any guessed address in microseconds per try — GPUs do ~10¹⁰ SHA-256/s. The throttle table becomes a list of the site's real email addresses plus per-address activity timestamps.
* source scope keys are worse: in this CLI `sourceId()` is `"cli:" + <OS username>` (`App.java:239-241`), and the documented HTTP deployment is a socket peer address — a few-billion key space, exhaustible in minutes, so an attacker (or anyone with file read) can map every row back to a specific IP/local account.

This directly contradicts the intent recorded in the code ("Domain-separated digest of the identifier", rule 5 framing) — the digest is only as un-linkable as the pepper is strong, and by default it is not un-linkable at all.

**Fix:** Make the keying material always present and use a proper MAC rather than a prepend-hash (which is also length-extension-adjacent hygiene); if no pepper is configured, derive and persist a random per-database key instead of degrading to unsalted:

```java
// src/main/java/com/example/accounts/ThrottleService.java
    private String key(String scope, String identifier) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256"); // key = pepper if set, else per-DB random
                                                   // key generated at migrate() and stored in DB meta
            mac.init(new SecretKeySpec(throttleKey, "HmacSHA256"));
            mac.update(scope.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) ':');
            return Hex.encode(mac.doFinal(identifier.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }
```

Alternatively make `ACCOUNTS_PEPPER_B64` mandatory for any deployment that persists throttle rows.

### SEC-03: Uniform-work guarantee leaks through two timing side channels — zero-work rejection of unparsable hashes, and a cost-mismatched decoy

- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/accounts/PasswordHasher.java:87-108`, `src/main/java/com/example/accounts/AccountService.java:182, 189-190`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/PasswordHasher.java:87-108
    public boolean verify(char[] password, String encoded) {
        if (password == null || password.length == 0 || encoded == null) {
            return false;
        }
        Parsed parsed;
        try {
            parsed = parse(encoded);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] actual = null;
        try {
            actual = derive(password, parsed.salt, parsed.memoryKib, parsed.iterations,
                    parsed.parallelism);
            // Constant-time: a timing difference here would leak the hash prefix byte by byte.
            return MessageDigest.isEqual(actual, parsed.hash);
        } finally {
            Wipe.bytes(actual);
            Wipe.bytes(parsed.salt);
            Wipe.bytes(parsed.hash);
        }
    }
```

```java
// src/main/java/com/example/accounts/AccountService.java:189-190
            String candidateHash = usable ? account.passwordHash() : decoyHash;
            verified = hasher.verify(prepared, candidateHash) && usable;
```

**Why it is a problem:** The whole `burnComparableWork()` / decoy-hash design exists so that response time does not reveal whether an identifier exists, is disabled, or has a usable password. Two paths break that promise measurably (microseconds vs ~100 ms — an easily detectable ratio over a network):

1. If a stored `password_hash` fails `parse()` — truncated cell, disk corruption, or an attacker with write access to the DB deliberately shortening a row (cheaper than stealing the DB, since SEC-05 shows file permissions are only enforced post-creation) — `verify` returns `false` at line 95 after **zero** Argon2 work, while every honest request against that account costs a full 64 MiB × 3-pass derivation. A remote observer timing logins can distinguish "row parses" from "row corrupted/tampered", and, more importantly, can use the fast-fail to probe at effectively unlimited rate the moment cost params differ from the decoy's.
2. `decoyHash` is generated with the *current* settings (`PasswordHasher.newDecoyHash`), while legitimate accounts upgraded lazily on login can hold *older, cheaper* parameters until their next successful login (`needsRehash` is applied only on success). During any cost-raise window, real-account logins are systematically faster than nonexistent-account logins — an enumeration oracle that inverts exactly as the deployment increases security. The README/code claim comparable work for every failure path (rule 6); these two paths do not honor it.

**Fix:** On parse failure, still spend one current-parameter derivation before returning false, and normalize the decoy path so every failure pays the current configured cost:

```java
// src/main/java/com/example/accounts/PasswordHasher.java — verify()
        Parsed parsed;
        try {
            parsed = parse(encoded);
        } catch (IllegalArgumentException e) {
            // Fail closed, but fail at the same speed: burn one current-cost derivation so a
            // corrupt/tampered stored hash is not distinguishable by response time.
            byte[] burn = null;
            try {
                burn = derive(password, currentSaltForBurn(), settings.memoryKib(),
                        settings.iterations(), settings.parallelism());
            } finally {
                Wipe.bytes(burn);
            }
            return false;
        }
```

For (2), have `needsRehash` failures *and* the decoy both route through a fixed current-cost derivation, or store the decoy's parameters and re-generate the decoy whenever settings change so `verify`'s work per request is constant across all failure branches.

### SEC-04: Password policy accepts the vast majority of real-world breached passwords

- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/example/accounts/InputValidator.java:40-45`, `245`, `271`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/InputValidator.java:39-45
    /** A small, high-frequency blocklist; see README for wiring a full breached-password list. */
    private static final Set<String> BLOCKED_PASSWORDS = Set.of(
            "123456789012", "passwordpassword", "password1234", "qwertyuiop12", "administrator",
            "iloveyou1234", "letmein12345", "welcome12345", "monkey123456", "dragon123456",
            "football1234", "baseball1234", "sunshine1234", "princess1234", "qwerty123456",
            "abc123456789", "trustno12345", "changeme1234", "secret123456", "superman1234");
```

```java
// src/main/java/com/example/accounts/InputValidator.java:245
        if (countDistinct(prepared) < 5) {
```

```java
// src/main/java/com/example/accounts/InputValidator.java:271
            if (isSingleRepeatedCharacter(folded) || isMonotonicRun(folded)) {
```

**Why it is a problem:** The composition rules are weak in exactly the region attackers populate. The blocklist contains 20 strings, all of which exist only because they had to be padded to the 12-character minimum — meaning every *actual* top breach password shorter than 12 chars is already blocked by length, while the enormous band of ≥12-character high-frequency passwords ("william12345", "qwertyuiop1234", "1q2w3e4r5t6y", "zaq12wsxedcv", date-of-birth combinations, "correct horse battery staple"-style corpus phrases, and anything from the top-100k lists that is ≥12 chars and has ≥5 distinct characters) passes. `countDistinct < 5` rejects only degenerate strings, and `isMonotonicRun` (`InputValidator.java:332`) checks a single contiguous ascending/descending run — "1q2w3e4r5t6y" style keyboards-as-words and simple word+year patterns sail through. The result: thousands of users will choose passwords that appear on credential-stuffing lists, and the component's only backstop at login is the *per-account* throttle of 10 failures per 15 minutes — which an attacker bypasses by stuffing *many accounts* once each (per-source limit is 25 and SEC-08 shows source identity is weak here). Argon2 cost slows *offline* cracking; it does nothing against online credential stuffing of admitted passwords. The README acknowledges the stub, but a security review must score the shipped behaviour, not the intention.

**Fix:** Wire a real breached-password check at enrollment — HIBP k-anonymity keeps it private and offline-free of storage:

```java
// src/main/java/com/example/accounts/InputValidator.java (enrollment path)
    /** Rejects passwords appearing in the HIBP breached-password corpus (k-anonymity: only the
     *  first 5 hex chars of the SHA-1 leave the process). */
    static void rejectIfBreached(char[] prepared) throws ValidationException {
        byte[] sha1 = MessageDigest.getInstance("SHA-1")
                .digest(StandardCharsets.UTF_8.encode(CharBuffer.wrap(prepared)).array());
        String prefix = Hex.upper(sha1, 0, 2);              // 5 hex chars
        RangeResult[] suffixes = hibpClient.range(prefix);  // p=0..4999, cached daily
        for (RangeResult r : suffixes) {
            if (Hex.equalsConstantTime(r.suffix(), Hex.upper(sha1, 2, 20))) {
                throw new ValidationException("That password has appeared in a data breach.");
            }
        }
    }
```

If outbound calls at enrollment are unacceptable, bundle the top 100k breached passwords (SHA-1 prefix bloom filter + exact suffix set) instead of a 20-entry list.

### SEC-05: Database files are first created under the process umask; restrictive permissions are applied only afterwards and failures are only logged

- **Severity:** Medium
- **CWE:** CWE-276: Incorrect Default Permissions (insecure creation window; fail-open handling per CWE-703)
- **Location:** `src/main/java/com/example/accounts/Database.java:53-54`, `103-124`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/Database.java:52-55 (open())
        Database db = new Database(url, props, log);
        db.migrate();
        db.restrictDatabaseFilePermissions(url);
        log.info(() -> "database ready at " + Mask.jdbcUrl(url));
```

```java
// src/main/java/com/example/accounts/Database.java:103-124
    private void restrictDatabaseFilePermissions(String url) {
        String pathPart = url.substring("jdbc:sqlite:".length());
        int q = pathPart.indexOf('?');
        if (q >= 0) {
            pathPart = pathPart.substring(0, q);
        }
        if (pathPart.isEmpty() || pathPart.startsWith(":")) {
            return; // in-memory database, nothing on disk
        }
        Path base = Paths.get(pathPart);
        for (String suffix : new String[] {"", "-wal", "-shm", "-journal"}) {
            Path p = suffix.isEmpty() ? base : Paths.get(pathPart + suffix);
            try {
                if (Files.exists(p) && !Files.isSymbolicLink(p)
                        && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
                }
            } catch (IOException | UnsupportedOperationException e) {
                log.log(Level.WARNING, "could not restrict permissions on database file", e);
            }
        }
    }
```

**Why it is a problem:** Two gaps:

1. **Creation window.** `migrate()` (called at line 53) opens the JDBC connection first, which is the moment SQLite creates `accounts.db` — and sqlite-jdbc then creates `-wal`/`-shm` on first write — under the *process umask*. On typical systems (umask 022) the files exist as `0644` for the whole migration + checkpoint window before line 54's chmod. Any local user who lists the directory in that window (and the parent data dir is owner-only, but the window also matters for the `-wal`/`-shm` files created *after* `restrictDatabaseFilePermissions` has already run — SQLite recreates them on every fresh connection set after a clean shutdown, again under the umask, until the *next* startup chmod) can read password hashes, session token digests, and throttle rows. The WAL/-shm recreation path is the recurring one: each clean start→stop cycle leaves fresh 0644 WAL files behind between runs.
2. **Fail-open.** Every chmod failure is swallowed with a WARNING (lines 120-122) and the service starts anyway — on a filesystem without the posix view (the explicit `else` path doesn't even warn), on NFS with root-squash, or if an attacker made the file immutable, the DB runs world-readable or with unknown permissions while claiming the rule-5 protection.

**Fix:** Create with final permissions (no window) and fail startup when protection cannot be established:

```java
// src/main/java/com/example/accounts/Database.java (open())
        Path dbPath = Path.of(url.substring("jdbc:sqlite:".length()));
        boolean posix = dbPath.getFileSystem().supportedFileAttributeViews().contains("posix");
        require(posix || inMemory, "POSIX permissions required to protect the database file");
        if (!Files.exists(dbPath)) {
            // Create it ourselves, atomically with the final mode, before SQLite can touch it.
            Files.createFile(dbPath, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")));
        }
        Database db = new Database(url, props, log);
        db.migrate();
        db.restrictDatabaseFilePermissions(url); // must now throw SQLException on any failure
```

and replace the `log.log(Level.WARNING, ...)` with a rethrow so startup aborts if any existing `-wal`/`-shm`/`-journal`/main file cannot be brought to `0600`; additionally run `restrictDatabaseFilePermissions` on connection close (or rely on `journal_mode=DELETE` if WAL residue cannot be tolerated) to close the between-runs window.

### SEC-06: Pepper lifecycle — accessor hands out the live array, service clones are never wiped

- **Severity:** Low-Medium
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Improper Erase')
- **Location:** `src/main/java/com/example/accounts/Config.java:228-231`, `src/main/java/com/example/accounts/ThrottleService.java:80`, `src/main/java/com/example/accounts/PasswordHasher.java:60`, `src/main/java/com/example/accounts/App.java:103`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/Config.java:228-231
    /** Returns the pepper itself (not a copy) so the caller can wipe it; empty array if unset. */
    public byte[] pepper() {
        return pepper;
    }
```

```java
// src/main/java/com/example/accounts/ThrottleService.java:80
        this.pepper = config.pepper().clone();
```

```java
// src/main/java/com/example/accounts/PasswordHasher.java:60
        this.pepper = pepper == null ? new byte[0] : pepper.clone();
```

```java
// src/main/java/com/example/accounts/App.java:103
            Wipe.bytes(config.pepper());
```

**Why it is a problem:** The project's own rule 5 is that secrets should not linger in the heap, and it is diligently applied to passwords and session tokens. The pepper — the value whose secrecy is the second factor behind Argon2 in a database-theft scenario — gets worse treatment:

1. Both long-lived services `clone()` the pepper (`ThrottleService.java:80`, `PasswordHasher.java:60`) and **never wipe the clones**. `App.java:103` wipes only `Config`'s original, in a CLI-specific `finally`. Deployed as a daemon/server (the direction the code's own comments anticipate — "an HTTP front end must pass the socket peer address instead"), at least two copies of the pepper remain resident for the process lifetime — recoverable from a heap dump, core dump, or `/proc/<pid>/mem` read, all of which are realistic once an attacker has the level of access that makes pepper theft interesting (same as the DB file, minus the SEC-05 chmod).
2. The accessor's contract is also self-defeating in a server: it returns the *live* array "so the caller can wipe it" — meaning any caller can (and `App` does) pull the pepper out from under `PasswordHasher`/`ThrottleService` at will; in the CLI that happens after their work is done, but nothing in the type system keeps a future caller from wiping it *during* operation (every subsequent verify would then silently hash with a different — empty — secret, failing closed but un-debuggably).

**Fix:** Give one owner the lifecycle and make the others consume a non-wipeable view; document the daemon policy:

```java
// src/main/java/com/example/accounts/Config.java
    /** Read-only view of the pepper for KDF/throttle use; cannot be wiped through this handle. */
    public ByteBuffer pepperView() {
        return ByteBuffer.wrap(pepper).asReadOnlyBuffer();
    }

    /** Only the process owner calls this, exactly once, on shutdown. */
    public void wipePepper() {
        Wipe.bytes(pepper);
    }
```

and in `PasswordHasher`/`ThrottleService` accept the `ByteBuffer`, keeping a clone that is wiped in a `close()` (make the services `AutoCloseable`) wired into the host's shutdown path, so every copy is accounted for.

### SEC-07: `jdbc:sqlite:` prefix-only allowlist lets the environment point the database (and its created files) at any writable path

- **Severity:** Low
- **CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') — of a configuration surface (CWE-73 adjacent)
- **Location:** `src/main/java/com/example/accounts/Config.java:153-163`, `src/main/java/com/example/accounts/Database.java:41-43`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/Config.java:153-163
    private static String resolveJdbcUrl(String configured, Path dataDir) {
        if (configured == null || configured.isBlank()) {
            return "jdbc:sqlite:" + dataDir.resolve("accounts.db");
        }
        require(configured.length() <= 2048, "ACCOUNTS_JDBC_URL is too long");
        require(configured.chars().noneMatch(c -> c < 0x20 || c == 0x7f),
                "ACCOUNTS_JDBC_URL contains control characters");
        boolean allowed = ALLOWED_JDBC_PREFIXES.stream().anyMatch(configured::startsWith);
        require(allowed, "ACCOUNTS_JDBC_URL must start with one of " + ALLOWED_JDBC_PREFIXES);
        return configured;
    }
```

**Why it is a problem:** `ALLOWED_JDBC_PREFIXES = List.of("jdbc:sqlite:")` (`Config.java:38`) and the identical check in `Database.open` (`Database.java:41-43`) constrain only the *scheme*, not the *path*. `ACCOUNTS_JDBC_URL=jdbc:sqlite:/tmp/x/accounts.db`, `jdbc:sqlite:/home/victim/.bashrc.db`... any absolute path is accepted; `migrate()` then creates a real SQLite file (plus WAL/-shm) wherever the process can write. The threat model is the environment-injection / misconfiguration / shared-runner case the rest of the config layer clearly worries about (NUL-byte checks, control-char checks, symlink refusals everywhere else): an attacker or sloppy operator who controls the env gets the service to create, hold a lock on, and write owner-only files at a path of their choosing — file-creation primitive, log-dir/backup confusion, or pointing a fleet at a wrong (possibly world-readable, per SEC-05) location while the operator believes rule-5 placement holds. It also silently bypasses `resolveDataDir`'s owner-only + no-symlink directory guarantees (`Config.java:120-141`), which only cover the *default* path.

**Fix:** Require the configured URL's path to resolve inside the vetted data directory:

```java
// src/main/java/com/example/accounts/Config.java
        boolean allowed = ALLOWED_JDBC_PREFIXES.stream().anyMatch(configured::startsWith);
        require(allowed, "ACCOUNTS_JDBC_URL must start with one of " + ALLOWED_JDBC_PREFIXES);
        String pathPart = configured.substring("jdbc:sqlite:".length());
        int q = pathPart.indexOf('?');
        if (q >= 0) pathPart = pathPart.substring(0, q);
        if (!pathPart.isEmpty() && !pathPart.startsWith(":")) { // in-memory forms stay allowed
            Path dbFile = Paths.get(pathPart).toAbsolutePath().normalize();
            require(dbFile.startsWith(dataDir),
                    "ACCOUNTS_JDBC_URL must point inside ACCOUNTS_DATA_DIR: " + dataDir);
            require(!Files.isSymbolicLink(dbFile), "database file must not be a symbolic link");
        }
        return configured;
```

### SEC-08: Per-source failure budget is never cleared by success and is keyed on a near-predictable id — one abusive co-tenant locks out everyone behind it

- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (availability aspect; account-manipulation-adjacent CWE-384)
- **Location:** `src/main/java/com/example/accounts/ThrottleService.java:121-134`, `src/main/java/com/example/accounts/App.java:239-241`, `src/main/java/com/example/accounts/AccountService.java:289+`

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/ThrottleService.java:121-134
    /**
     * Clears the account-scope counter after a successful authentication, so a victim's own
     * successful login immediately undoes an attacker's failed attempts against them.
     *
     * <p>The source-scope counter is deliberately <em>not</em> cleared: otherwise an attacker who
     * holds one valid credential could log in to reset their own budget between probes and the
     * per-source limit would be worthless.
     */
    public void clearAccount(Connection connection, String accountIdentifier, Instant now)
            throws SQLException {
        if (accountIdentifier != null) {
            clear(connection, SCOPE_ACCOUNT, key(SCOPE_ACCOUNT, accountIdentifier));
        }
        prune(connection, windowCutoff(now));
    }
```

```java
// src/main/java/com/example/accounts/App.java:239-241
    private static String sourceId() {
        String user = System.getProperty("user.name");
        return "cli:" + (user == null || user.isBlank() ? "unknown" : user);
    }
```

**Why it is a problem:** The never-clear rule is correct for an attacker holding one credential, but combined with the *client-identity granularity actually available*, it converts into a denial-of-authentication primitive:

* Behind any shared egress (corporate NAT, campus, carrier NAT) or any shared OS account, all co-tenants hash to one source key. 25 failures in 15 minutes — a few seconds of spraying — locks every innocent user behind that address out of *logging in at all* (`SOURCE_THROTTLED` is returned before any credential check) for the remainder of the window, repeatedly, with no success path that resets it. The victim cannot even authenticate to prove they are not the attacker.
* `App.sourceId()` uses `System.getProperty("user.name")`, which is attacker-chosen in the sense that it is inherited from the environment: a shared CI runner or multi-user host collapses many operators into `cli:<svc-account>`; and `AccountService.normalizeSourceId` buckets every non-printable/oversized value into a single `"unknown-source"` key, creating one more shared lockout bucket fed by any caller that fails to pass a real peer address.
* Registration (`accountIdentifier == null` → source-scope only) is the same: spraying registrations from a shared source blocks legitimate signups for the whole co-tenant group.

This is a design trade the README half-acknowledges, but the fail-closed lockout of *all* co-tenants with no self-service escape is a usability-of-security failure that invites operators to just disable throttling.

**Fix:** Keep the never-clear rule for the *attacker's* benefit but make the budget pair-aware and raise the ceiling with monitoring, e.g. count source failures **per distinct account attempted** toward the source budget and apply the hard source block only when failures span > N distinct accounts (spray signature), leaving single-account probing to the per-account limit:

```java
// src/main/java/com/example/accounts/ThrottleService.java (tryAcquire)
        // Block the source only on spray behaviour: many distinct accounts, not many failures
        // concentrated on targets that also fail their (smaller) per-account budget.
        if (distinctAccountsFailed(connection, sourceKey, cutoff) >= config.distinctAccountsPerSource()
                && failures(connection, SCOPE_SOURCE, sourceKey, cutoff) >= config.maxFailuresPerSource()) {
            return Decision.SOURCE_THROTTLED;
        }
```

and in `App.sourceId()` incorporate the audit user + a per-boot random component, and never collapse unknown sources into one shared bucket (fall back to "unthrottled-by-source, account-limit-only" instead).

### SEC-09: Revoked sessions are deleted by the next prune — the system forgets when and whether a session was revoked

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/example/accounts/SessionService.java:48-50`, `56-58`

**Vulnerable code:**

```sql
-- src/main/java/com/example/accounts/SessionService.java:48-50
    private static final String REVOKE_SQL = """
            UPDATE auth_session SET revoked = 1 WHERE token_hash = ?
            """;
```

```sql
-- src/main/java/com/example/accounts/SessionService.java:56-58
    private static final String PRUNE_SQL = """
            DELETE FROM auth_session WHERE absolute_expires_at <= ? OR revoked = 1
            """;
```

**Why it is a problem:** Logout and revocation are security-relevant state transitions, but the durable record of them lasts only until the next `prune()` call (which runs on ordinary traffic paths). After that, the database cannot answer "was session *h* ever issued, and when was it revoked?" — the row is indistinguishable from one that never existed. For incident response this removes the attribution trail (when did the user of a stolen token actually log out vs. get kicked; was there a revocation at all before an account was abused), and `revokeAllForAccount` leaves no marker either. The application log carries a `session=<ref>` line, but logs are rotating 1 MiB single-file (`Logging.java:80`) and are not a durable audit store.

**Fix:** Keep revoked rows until natural absolute expiry (the row is tiny and already indexed by expiry), or append to a durable event table:

```sql
-- src/main/java/com/example/accounts/SessionService.java
            DELETE FROM auth_session WHERE absolute_expires_at <= ?
```

```sql
            INSERT INTO session_event (token_hash, kind, at_epoch) VALUES (?, 'revoked', ?)
```

executed inside the same transaction as `REVOKE_SQL`, with `session_event` pruned on a longer retention window.

### SEC-10: CSRF defence rests solely on `SameSite=Strict`; no `Origin`/anti-CSRF hook for a future HTTP layer

- **Severity:** Informational
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF) (residual-risk note)
- **Location:** `src/main/java/com/example/accounts/SessionCookie.java:31-45`, `README.md` (documented scope limits)

**Vulnerable code:**

```java
// src/main/java/com/example/accounts/SessionCookie.java:31-44
    public static String setCookieHeader(char[] token, Duration maxAge) {
        if (!SessionService.isWellFormedToken(token)) {
            // Fail closed rather than emit a header with something unexpected in it.
            throw new IllegalArgumentException("token is not a well-formed session token");
        }
        long seconds = Math.max(0, maxAge.getSeconds());
        StringBuilder sb = new StringBuilder(160);
        sb.append(NAME).append('=').append(token, 0, token.length)
                .append("; Path=/")
                .append("; Max-Age=").append(seconds)
                .append("; HttpOnly")
                .append("; Secure")
                .append("; SameSite=Strict");
        return sb.toString();
```

**Why it is a problem:** There is no anti-CSRF token, no `Origin`/`Sec-Fetch-Site` check, and no re-authentication step on state-changing operations; the entire cross-site defence is the header above's `SameSite=Strict` attribute — the browser simply will not attach the cookie to cross-site requests. Today that combination (`__Host-` prefix semantics + `HttpOnly` + `Secure` + `Strict`, no `Domain`) is a sound, widely accepted posture, so this is not a present defect — hence *Informational*. It is recorded because the component is explicitly designed to be fronted by an HTTP layer that does not yet exist: the guidance that such a front end must still verify `Origin` (defence-in-depth against future user-agent `Strict`-semantics changes, and the only defence once non-GET requests are exposed) exists only in Javadoc/README prose, and nothing in `SessionCookie`/`AccountService` gives that future layer a hook to enforce it. One acknowledged residue in the same rendering path: `sb.toString()` materialises the raw session token into an immortal, non-wipeable `String` header value, which — unlike every other secret in the codebase (`IssuedSession.token` is `char[]`, `hashToken` wipes its `byte[]` copy) — cannot be scrubbed from the heap; unavoidable for emitting an HTTP header, but a reason never to log that return value.

**Fix:** Keep the cookie as-is and add the cheap server-side belt so future consumers inherit it:

```java
// proposed, in the future HTTP front end or as a SessionCookie helper:
    static boolean sameOriginOk(String originHeader, String host) {
        // Reject any state-changing request that carries an Origin not equal to this host;
        // (once browsers universally send Sec-Fetch-Site, require cross-site == absent).
        return originHeader == null || originHeader.equalsIgnoreCase("https://" + host);
    }
```

and document on `setCookieHeader` that its return value contains the raw token and must never be passed to the audit log (the `Mask` helpers already cover identifiers but not this value).

## 6. Verified Controls and Checks With No Finding

The following were exercised by the applied skills' checklists and held up:

* **SQL injection:** every data-path statement in `AccountService`/`SessionService`/`ThrottleService`/`AccountRepository` is a static-`String` `PreparedStatement` with `?` binding; the only `Statement` use is `Database.migrate()` over a hard-coded DDL array. No string concatenation reaches SQL (`AccountRepository.java:53-68, 71-90`, `ThrottleService.java` SELECT/UPSERT/DELETE/PRUNE, `SessionService.java:33-58`).
* **Password storage:** Argon2id (BC 1.79) at ≥ OWASP 2024 floors (default 64 MiB/3 iters/1 par), fresh 16-byte `SecureRandom` salt per hash, pepper used as the KDF secret parameter, PHC-string encoding; `verify` compares with `MessageDigest.isEqual` (constant time) and clamps hostile stored cost parameters at parse time (≤1 GiB mem / ≤20 iters / ≤16 par / ≤512-char encoding), so a tampered row cannot mount a memory-DoS through the verifier; `needsRehash` upgrades outdated parameters on successful login (`PasswordHasher.java:42-45, 87-124, 216-236`). No passwords/hashes/pepper are hardcoded anywhere; `Config.toString()` masks the pepper.
* **Session tokens and storage:** 32-byte `SecureRandom` token (256-bit, base64url, no padding), only SHA-256(token) persisted, token shape (43 base64url chars) validated *before* any query, idle (30 min) + absolute (12 h) expiry, `TOUCH_SQL` requires exactly one updated row, revoked/expired sessions stop authenticating, and revocation on `revokeAllForAccount` is transactional with account state changes (`SessionService.java:33-75, 160-209`; retention gap separately noted as SEC-09).
* **Cookie hardening:** `__Host-session` with `Path=/; HttpOnly; Secure; SameSite=Strict` and no `Domain` — the host-only, secure-only, root-path requirements of the `__Host-` prefix are satisfied as rendered (`SessionCookie.java`; CSRF residual as SEC-10).
* **Input handling:** allowlist (not denylist) validation for email/username with an explicit narrow character model, NFKC + confusable folding so `paypal`/`pᴀypal` collide deterministically, reserved-name list applied to the folded form, OpaqueString-style password normalisation that rejects control/format/surrogate/private-use code points; all failure messages are user-safe and never echo secret input (`InputValidator.java`, `ValidationException`).
* **Concurrency/uniqueness:** registration relies on the `UNIQUE` constraints under `transaction_mode=IMMEDIATE` rather than check-then-insert, making two simultaneous registrations deterministically one-winner (`AccountRepository.insert` + `isUniqueViolation`); throttle check-and-count is a single UPSERT inside the caller's write transaction, closing the classic attempt-limit TOCTOU (`ThrottleService.tryAcquire` doc and implementation); the session issue + counter clear commit atomically. (The *cross-transaction* gap is SEC-01; the intra-transaction patterns are sound.)
* **Fail-closed behaviour:** unparsable/corrupt stored hashes fail authentication (the timing of that failure is SEC-03; the decision itself is correct), `disabled` accounts cannot obtain sessions on the normal path, config validation aborts startup on any violation, and unknown JDBC schemes are refused (`Database.java:41-43`).
* **Data-at-rest layout:** default state directory created owner-only (`0700`), symlink refused, `Mask.jdbcUrl/email/username` applied before any log line, `oneLine()` folds CR/LF/NEL/LS/PS so identifier-shaped input cannot forge log entries, log file created `0600` (existing file re-chmod'd, symlink refused) with a deliberate single-wrap `FileHandler` so rotation cannot spawn umask-default files, and the CLI session file is symlink-checked, `0600`, read back only if regular and ≤128 bytes (`Logging.java`, `Mask.java`, `App.java:327-355`, `Config.java:120-148`).
* **Secret-hygiene plumbing:** passwords read via `console.readPassword` (stdin fallback requires an explicit opt-in env var and never argv), carried as `char[]`, wiped in `finally` on every main path (`AccountService.java:214-216`, `App.java`), with the documented rare NFC-normalisation `String` materialisation.
* **Build hygiene:** HTTPS-only Maven Central with `checksumPolicy=fail`, pinned dependency versions with published SHA-256s in `README.md`, shade plugin repackages only this artifact's classes (`pom.xml`).
* **Enumeration resistance (mechanism):** nonexistent and disabled identifiers verify against a decoy hash with equal code-path work, throttling responses are intentionally indistinguishable between scopes, and auth failures return one generic status — the two timing exceptions are SEC-03; the rest of the design is consistent and is exercised by the enumeration/uniformity tests.
