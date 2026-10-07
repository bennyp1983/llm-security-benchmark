# Security Review: secure-auth (Java 17 authentication reference implementation, `com.example.auth`)

## 1. Executive Summary

The component is a small, deliberately defensive authentication core: an admin CLI (`init-schema`,
`set-password`), a login service that issues opaque database-backed session tokens, PBKDF2 password
hashing, DB-backed login throttling, and a hardened cookie header. It was reviewed **statically only**
(no build, no execution, nothing imported), because it is untrusted generated code.

The implementation is materially better than typical generated auth code. SQL injection is absent
(every statement is a constant string bound through `PreparedStatement`), session tokens are 256-bit
`SecureRandom` values persisted only as SHA-256, hash comparison is constant-time, and the failure
paths are consistently fail-closed. The findings below are therefore mostly second-order defects in
places where a security control is present but incomplete.

The most consequential issue is that the "masking" of email addresses is not masking: `LogMasker`
writes an unsalted, truncated SHA-256 fingerprint (plus the first character) of every address into
every login log line, and `LoginThrottle` persists the same unsalted digest of the address as
`login_throttle.scope_key`. Email is low-entropy input, so anyone with read access to logs or to the
throttle table can recover the underlying addresses by hashing a candidate list — the same
"unsalted hash of a low-entropy secret" failure that applies to passwords — which defeats the stated
purpose of the masking layer and turns log/backup access into PII disclosure.

The remaining findings cluster into three groups. First, controls that are declared but not closed:
a stored password hash can dictate the KDF work factor for up to 24× the intended cost (CPU
amplification plus a timing channel that undercuts the decoy-equalisation claim), a password reset
silently forces `is_active = TRUE` and therefore re-enables a deactivated account, and no code path
ever calls `SessionService.revoke`, so a password change leaves already-issued sessions live.
Second, guards that fail open or are incomplete: the `AUTH_DB_URL` option denylist misses
driver options that instantiate caller-named classes, and `requireOwnerOnly` returns silently when
POSIX attributes are unavailable. Third, secret-handling residuals: the DB password falls back to an
environment variable and is copied into an unwipeable `String` for the JDBC driver.

Ten findings are reported: one High, six Medium, three Low. Nothing here requires a redesign, but the
fingerprint/logging issue and the session/`is_active` behaviour on password reset should be fixed
before this code is used as the basis of a real deployment.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/App.java` | Interactive login entry point; writes the session token to a file | Writes token with `rw-------` (0600) via `PosixFilePermissions` and `CREATE_NEW`; rejects non-regular/symlinked target (`:93-112`); token never logged |
| `AdminCli.java` | Admin tool: `init-schema`, `set-password <email>` | Executes DDL only from the artifact's own classpath (`:73-82`); password prompted, never taken from argv; ≥12 chars + 3 character classes (`:104-111`); hashes then writes credential in one transaction (`:112-116`); zeroes password arrays (`:120-126`); logs only masked email |
| `AuthConfig.java` | Reads and validates all configuration from the environment | JDBC URL shape regex (`:29`) + forbidden-option denylist (`:36-39`, applied `:72-78`); secret read from `AUTH_DB_PASSWORD_FILE` with 0600 gate, falling back to `AUTH_DB_PASSWORD` (`:117-159`); numeric bounds for throttle/TTL (`:94-99`); `AUTH_SOURCE_ID` default `local-cli` (`:88`) |
| `AuthService.java` | Login orchestration: validate → throttle → verify → issue session | Fail-closed on unusable source (`:65-70`); constant `"<invalid>"` counter key for unparseable addresses (`:73`); decoy verification on every failure path; success reachable only at `:171`; throttle errors refuse the attempt (`:117-121`) |
| `AuthResult.java` | Result object returned to callers | Two user-visible strings only (`:29`, `:66`); `Reason` enum is log-only, so failure cause is not disclosed to the caller |
| `ConsoleIo.java` | Reads email/password from terminal or stdin | Uses `Console.readPassword` when available; otherwise prints an echo warning and reads the password as a `String` (`:43-50`); all reads bounded to 1024 chars |
| `CredentialRepository.java` | Read/write of `app_user` credential rows | All SQL is constant text bound via `PreparedStatement`; `SELECT … FOR UPDATE` row lock (`:16`); `setMaxFieldSize(512)` bounds hostile row reads (`:42`); malformed rows treated as unusable, never as a pass (`:50-53`); writes force `is_active = TRUE` (`:20`, `:24`) |
| `Database.java` | Opens JDBC connections with auto-commit off | Passes credentials through `Properties`, never in the URL; copies the `char[]` secret into an immutable `String` for the driver (`:28`); `READ_COMMITTED` isolation |
| `Hashing.java` | SHA-256 helpers for lookup keys | Documented as "never for password storage" (`:7`); used for throttle keys and session-token hashing — unsalted digests of low-entropy input |
| `InputValidator.java` | Email/source-id/password validation and normalisation | Email regex + 254-char cap; `SOURCE_ID ^[A-Za-z0-9.:_-]{1,64}$`; password length window 8–256 (12 minimum for new passwords) bounding KDF input |
| `LogMasker.java` | Log-safe stand-ins for sensitive values | `maskEmail` emits first character + 12-hex-char unsalted SHA-256 fingerprint (`:19-31`); `maskSecret` reveals only length (`:34-41`) |
| `LoginThrottle.java` | DB-backed windowed attempt counters per source and per account | Row-locked read-modify-write; savepoint-recovered insert race (`:83-95`); key is unsalted `sha256(scope:email)` (`:63`, `:153`); counter purge 1-in-50 (`:162-166`) |
| `LoggingSetup.java` | Root logger wiring | Single `ConsoleHandler` at INFO; no file handler, so no additional log destination is introduced |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA512 hash/verify with decoy equalisation | 210 000 iterations, 16-byte salt, 256-bit key (`:26-31`); strict parse of the hostile stored value; constant-time compare (`:118`); `PBEKeySpec.clearPassword()` and buffer zeroing; accepted iteration band 100 000–5 000 000 (`:30-31`, `:95`) and derived length taken from the stored hash (`:115`) |
| `SessionCookie.java` | Builds `Set-Cookie` headers | `sid=<opaque>; HttpOnly; Secure; SameSite=Strict`; `Path` matched against a strict allow-regex; `Max-Age` clamped to 1…86400; clear header carries identical attributes (`:19-51`) |
| `SessionService.java` | Issues/validates/revokes opaque sessions | 32-byte `SecureRandom` token, format-validated before use, stored only as SHA-256; validation requires `revoked_at IS NULL`, `expires_at > ?` and `u.is_active = TRUE` (`:34-37`); `revoke()` is defined (`:95`) but never called |
| `src/main/resources/schema.sql` | DDL for `app_user`, `user_session`, `login_throttle` | `email VARCHAR(254) UNIQUE`, `password_hash VARCHAR(256)`, `scope_key VARCHAR(64)` — bounded stored sizes; FK `ON DELETE CASCADE` from sessions to users; no seeded credentials |
| `pom.xml` | Build definition | H2 2.3.232 pinned and `runtime`-scoped only (PostgreSQL is the target driver); build plugins version-pinned; `-Xlint:all` |
| `scripts/smoke-test.sh` | Non-interactive end-to-end demo | Feeds a password over stdin, i.e. exercises the echo-able `ConsoleIo` fallback path; uses in-memory H2 with no password |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: the router workflow itself — first establishing what each
  file does, then matching behaviour to specialised skills, then applying them one at a time with
  `file:line` evidence.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java`, `Hashing.java`,
  `LogMasker.java` and `SessionService.java` — primitive selection (PBKDF2-HMAC-SHA512, SHA-256,
  `SecureRandom`), KDF parameters and salt handling, constant-time comparison, key/secret lifetime,
  and the "weak KDF / poor entropy / unsalted digest" weakness classes in the skill's audit table.
- `testing-api-authentication-weaknesses`: applied to `AuthService.java`, `SessionService.java` and
  `LoginThrottle.java` — Step 5 token-lifecycle testing (token validity after logout and after a
  password change) and Step 6 account-enumeration testing (differences in response text, status and
  work between existing and non-existing accounts).
- `testing-for-sensitive-data-exposure`: applied to `LogMasker.java`, `AuthConfig.java`,
  `Database.java`, `ConsoleIo.java` and `App.java` — PII in logs, secrets in configuration and in
  process memory, and secret exposure through files, environment and terminal echo.
- `testing-for-broken-access-control`: applied to `CredentialRepository.java`, `AdminCli.java` and
  `SessionService.java` — the account-state matrix (`is_active`) and whether an administrative action
  can change authorisation state as a side effect.
- `implementing-api-rate-limiting-and-throttling`: applied to `LoginThrottle.java`,
  `AuthService.java` and `AuthConfig.java` — counter key selection (`by ip` vs `by user`), window
  semantics, charge ordering between scopes, and lockout/availability side effects of the limiter.
- `exploiting-sql-injection-vulnerabilities`: applied to every SQL surface in
  `CredentialRepository.java`, `SessionService.java`, `LoginThrottle.java` and `AdminCli.java` to
  hunt for an injection point; none exists (recorded in §6).

Reviewed against general OWASP Top 10 / CWE knowledge only, with no matching specialised skill in the
library: the JDBC URL option parser and its denylist completeness (`AuthConfig.java:29-78`), the POSIX
permission gate on the secret file and its fail-open branch (`AuthConfig.java:162-178`), and the
non-interactive stdin password path in the CLI (`ConsoleIo.java:38-53`).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Email "masking" is an unsalted truncated digest that is reversible by enumeration, in logs and in the throttle table | High | CWE-359 | `LogMasker.java:16-31`, `LoginThrottle.java:63` |
| SEC-02 | Hostile stored hash chooses the KDF work factor and derived-key length | Medium | CWE-400 | `PasswordHasher.java:95-118` |
| SEC-03 | Credential write forces `is_active = TRUE`, re-enabling deactivated accounts | Medium | CWE-284 | `CredentialRepository.java:19-24` |
| SEC-04 | Password change never revokes issued sessions (`revoke()` is never called) | Medium | CWE-613 | `AdminCli.java:112-116`, `SessionService.java:95` |
| SEC-05 | Incomplete JDBC URL option denylist lets other driver options through | Medium | CWE-184 | `AuthConfig.java:36-39` |
| SEC-06 | Secret-file permission check fails open when POSIX attributes are unavailable | Medium | CWE-636 | `AuthConfig.java:162-167` |
| SEC-07 | Default `local-cli` source scope concentrates all clients of a deployment into one lockout budget | Medium | CWE-400 | `AuthConfig.java:88`, `AuthService.java:73` |
| SEC-08 | Database secret falls back to an environment variable after the protected-file path | Low | CWE-522 | `AuthConfig.java:151-156` |
| SEC-09 | Database secret copied into an unwipeable immutable `String` for the JDBC driver | Low | CWE-316 | `Database.java:26-31` |
| SEC-10 | Non-interactive password read yields an unwipeable `String` and is echoed | Low | CWE-316 | `ConsoleIo.java:38-52` |

## 5. Detailed Findings

### SEC-01: Email "masking" is an unsalted truncated digest that is reversible by enumeration, in logs and in the throttle table

- **Severity:** High
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor (weak-derivation aspect CWE-916: Use of a One-Way Hash with a Predictable Input to protect an identifier)
- **Location:** `LogMasker.java:16-31` (and `LogMasker.java:19`), `LoginThrottle.java:63` and `LoginThrottle.java:153`

**Vulnerable code:**

```java
// LogMasker.java:16-31
    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "<none>";
        }
        return email.charAt(0) + "***@*** (eid:" + fingerprint(email) + ")";
    }

    /** Short, non-reversible correlation id for any sensitive string. */
    public static String fingerprint(String value) {
        byte[] digest = Hashing.sha256(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(12);
        for (int i = 0; i < 6; i++) {
            sb.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
            sb.append(Character.forDigit(digest[i] & 0xF, 16));
        }
        return sb.toString();
    }
```

**Why it is a problem:**

The Javadoc calls the value "non-reversible", which is true only in the preimage sense and is
irrelevant here. The input is an email address — a low-entropy, highly enumerable string space. An
attacker does not invert SHA-256; they hash a candidate list (a corporate directory, a leaked-credentials
corpus, or simply permutations of a known local part and domain) and match the first 6 bytes. That is
exactly the attack that makes unsalted password hashes useless, and the codebase itself acknowledges
the principle in `Hashing.java:7` ("never for password storage") while applying the same construction
to identity. The first character of the address is additionally reproduced verbatim at `:19`, which
both confirms a candidate immediately and discloses identity even when the digest does not match.

The blast radius is not limited to logs. `LoginThrottle.java:63` computes
`Hashing.sha256Hex(scope.name() + ':' + rawKey)` and stores it as `login_throttle.scope_key`
(`schema.sql:24`, `VARCHAR(64)`), and `:153` repeats the same construction on the clear path. Anyone
who can read the throttle table — a monitoring account, a backup, a read replica, a `pg_dump` for
troubleshooting — recovers every address that has recently attempted a login, including addresses
that never have an `app_user` row. Log access is normally granted at a far lower trust level than
database access, and this logging layer is explicitly designed to make log lines safe; as written,
every throttled and failed login (`AuthService.java:77-79`, `:127`, `:134`, `:149`, `:169`) publishes
recoverable PII to that lower-trust channel. The `scope`/`scope_key` pair is also stable across time,
so log lines from different hosts and windows can be joined on `eid:` to build a per-person login
timeline.

**Fix:**

Make the identifier a keyed digest (HMAC) with a deployment secret, widen the truncation so it cannot
be matched by exhaustive enumeration of a candidate list, and stop reproducing any character of the
address. The same key must then be used by the throttle so correlation still works.

```java
// LogMasker.java
    // Keyed, and 16 hex chars (64 bits) rather than 12: an observer who knows the
    // candidate email space still cannot test candidates without the key.
    private static byte[] correlationKey() {
        byte[] key = AuthConfig.correlationSecret(); // loaded from the 0600 secret path, never env/URL
        if (key == null) {
            throw new IllegalStateException("correlation secret unavailable; refusing to log identifiers");
        }
        return key;
    }

    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "<none>";
        }
        // No character of the address is reproduced.
        return "<redacted-email> (eid:" + fingerprint(email) + ")";
    }

    /** Keyed correlation id: unusable without the deployment's correlation secret. */
    public static String fingerprint(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(correlationKey(), "HmacSHA256"));
            byte[] digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                sb.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
                sb.append(Character.forDigit(digest[i] & 0xF, 16));
            }
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Identity fingerprinting is unavailable", e);
        }
    }
```

```java
// LoginThrottle.java:63 and :153 — the persisted counter key must be keyed for the same reason,
// and must match whatever LogMasker uses so log lines and rows still correlate.
    String key = Hashing.hmacHex(AuthConfig.correlationSecret(), scope.name() + ':' + rawKey);
```

If a keyed design is unacceptable, the alternative is to stop emitting or storing any
address-derived value at all: log a per-request correlation id and join it to the account in the
database, and derive throttle keys inside a `pgcrypto` `HMAC()` in SQL so the digest never leaves the
database boundary.

### SEC-02: Hostile stored hash chooses the KDF work factor and derived-key length

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption (contributing to CWE-208: Observable Timing Discrepancy)
- **Location:** `PasswordHasher.java:95-118` (bounds at `:30-31`, decoy path at `:131-139`)

**Vulnerable code:**

```java
// PasswordHasher.java:95-118
        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
            verifyDecoy(password);
            return false;
        }
        byte[] salt;
        byte[] expected;
        try {
            Base64.Decoder dec = Base64.getDecoder();
            salt = dec.decode(parts[2]);
            expected = dec.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            verifyDecoy(password);
            return false;
        }
        if (salt.length < 8 || salt.length > 64 || expected.length < 16 || expected.length > 64) {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            verifyDecoy(password);
            return false;
        }
        byte[] actual = derive(password, salt, iterations, expected.length * 8);
        try {
            // Length-independent, constant-time comparison from the platform.
            return java.security.MessageDigest.isEqual(expected, actual);
```

**Why it is a problem:**

The method's own contract states the reasoning: "The stored value comes out of the database and is
therefore treated as attacker-controlled: it is parsed strictly, with bounds on every field." Every
field is bounded except the two that matter for cost. `MAX_ACCEPTED_ITERATIONS = 5_000_000`
(`:31`) is roughly 24× the policy cost of 210 000 (`:29`), and `expected.length * 8` at `:115` lets the
row choose the derived-key length up to 512 bits. So a stored hash that passes the parse bounds
directs the server's CPU: one login against that row costs ~24× the intended work, and the throttle
budget (30 attempts per source per 15 minutes by default) multiplies it — a single row write buys an
attacker a repeating, authenticated-cheap CPU amplification primitive against every login to that
account.

The same two lines break the equalisation guarantee that the decoy exists to provide. `verifyDecoy`
(`:131-139`) always derives at the decoy's own iteration count, which is the policy value 210 000, and
at `KEY_BITS`. A real verification at 5 000 000 iterations therefore takes ~24× longer than any decoy
path, and the class-level comment's claim that "response time does not disclose which accounts are
real" is false for such a row: an unauthenticated caller can distinguish "account exists with a
high-cost hash" from "no such account / unusable hash / wrong password" by measuring latency. That is
the exact account-enumeration-by-timing channel that `testing-api-authentication-weaknesses` Step 6
tests for, and it is the only surviving enumeration channel — the response text is uniform
(`AuthResult.java:29`, `:66`) and the `Reason` enum is log-only.

Related, and worth fixing in the same place: a row whose iteration count is *below* policy but above
`MIN_ACCEPTED_ITERATIONS` is accepted forever. There is no rehash-on-success anywhere, so a one-time
cost downgrade to 100 000 iterations persists indefinitely and quietly weakens that account against
offline cracking if the hash ever leaks.

**Fix:**

Collapse the accepted band to something that cannot be weaponised, never let the stored row choose the
output length, and rehash to policy cost on a successful verification so cost never drifts downward.

```java
// PasswordHasher.java
    private static final int ITERATIONS = 210_000;
    private static final int MIN_ACCEPTED_ITERATIONS = 210_000;
    // At most 2x policy work is ever spent on one verification, so a hostile row cannot
    // exceed the decoy's cost by more than a constant factor.
    private static final int MAX_ACCEPTED_ITERATIONS = 420_000;
    private static final int ACCEPTED_HASH_BYTES = KEY_BITS / 8; // 32, not a caller-chosen 16..64

    // ... replacing PasswordHasher.java:109-115:
        if (salt.length < 16 || salt.length > 32 || expected.length != ACCEPTED_HASH_BYTES) {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            verifyDecoy(password);
            return false;
        }
        byte[] actual = derive(password, salt, iterations, KEY_BITS);
        boolean matches;
        try {
            matches = java.security.MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
        // Signal that the row needs re-encoding at policy cost; the caller rehashes inside
        // its existing row-locked transaction (see rehashOnLogin below).
        if (matches && iterations != ITERATIONS) {
            needsRehash.set(true);
        }
        return matches;
```

```java
// AuthService.java (inside verifyAndIssue, still holding the row lock from findForUpdate)
    if (result && passwordHasher.needsRehash()) {
        String upgraded = hasher.verifyAndRehash(password, credential.passwordHash());
        credentials.replaceHash(connection, email, upgraded); // UPDATE ... SET password_hash = ? only
    }
```

### SEC-03: Credential write forces `is_active = TRUE`, re-enabling deactivated accounts

- **Severity:** Medium
- **CWE:** CWE-284: Improper Access Control (business-logic side effect, CWE-840)
- **Location:** `CredentialRepository.java:19-24`, reached from `AdminCli.java:112-116`

**Vulnerable code:**

```java
// CredentialRepository.java:19-24
    private static final String UPSERT =
            "UPDATE app_user SET password_hash = ?, is_active = TRUE WHERE email = ?";

    private static final String INSERT =
            "INSERT INTO app_user (email, password_hash, is_active, created_at) "
            + "VALUES (?, ?, TRUE, CURRENT_TIMESTAMP)";
```

**Why it is a problem:**

`is_active` is this component's authorisation switch, and it is the mechanism that actually cuts off a
compromised account at session-validation time: `SessionService.java:34-37` requires
`u.is_active = TRUE` before a token resolves. `saveCredential` is documented as "Creates or replaces a
user's password hash. Used by the admin tool only" — but both of its statements overwrite the account
state as an unrelated side effect. An operator responding to a compromise typically deactivates the
account first and resets the password afterwards; this write silently reverses the containment step,
and because the reset also re-enables the account, every session that deactivation had just
invalidated becomes valid again. The reset path is also the *only* write path in the codebase, so there
is no way to reset a password without also granting activation — the two decisions cannot be expressed
separately at all.

The two-statement sequence at `CredentialRepository.java:62-73` (UPDATE, and INSERT only if the UPDATE
affected zero rows) is additionally not atomic: two concurrent credential writes for a brand-new
address can both see zero updated rows and race on the `email` UNIQUE constraint
(`schema.sql:6`), aborting one transaction with a constraint violation. Because `findForUpdate`
(`:39-57`) takes no lock for a row that does not exist yet, nothing serialises the two. That is a
correctness defect rather than a privilege bypass, but it is fixed by the same change.

**Fix:**

Never touch `is_active` from the credential write, and make the create-or-replace genuinely atomic with
a real upsert against the existing UNIQUE constraint.

```java
// CredentialRepository.java
    // Password changes must not change account state; activation is its own operation.
    private static final String UPDATE =
            "UPDATE app_user SET password_hash = ? WHERE email = ?";

    // Atomic create-or-nothing against app_user.email UNIQUE (schema.sql:6);
    // a new account is created inactive and must be activated explicitly.
    private static final String INSERT_IF_ABSENT =
            "INSERT INTO app_user (email, password_hash, is_active, created_at) "
            + "VALUES (?, ?, FALSE, CURRENT_TIMESTAMP) ON CONFLICT (email) DO NOTHING";
```

```java
// CredentialRepository.java:59-74
    /** Creates or replaces a user's password hash without altering is_active. */
    public void saveCredential(Connection connection, String email, String encodedHash)
            throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(INSERT_IF_ABSENT)) {
            insert.setString(1, email);
            insert.setString(2, encodedHash);
            insert.executeUpdate(); // no-op when the row already exists; no constraint race
        }
        try (PreparedStatement update = connection.prepareStatement(UPDATE)) {
            update.setString(1, encodedHash);
            update.setString(2, email);
            if (update.executeUpdate() == 0) {
                throw new SQLException("credential write had no effect");
            }
        }
    }

    /** Explicit activation, so enabling an account is a deliberate, auditable action. */
    public void setActive(Connection connection, String email, boolean active) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE app_user SET is_active = ? WHERE email = ?")) {
            ps.setBoolean(1, active);
            ps.setString(2, email);
            ps.executeUpdate();
        }
    }
```

### SEC-04: Password change never revokes issued sessions (`revoke()` is never called)

- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `AdminCli.java:112-116`; `SessionService.java:95-103` (`revoke` has no caller anywhere in the artifact)

**Vulnerable code:**

```java
// AdminCli.java:112-116
            String encoded = new PasswordHasher().hash(first);
            try (Connection connection = database.openTransaction()) {
                new CredentialRepository().saveCredential(connection, email.get(), encoded);
                connection.commit();
            }
```

**Why it is a problem:**

`SessionService` implements revocation correctly — `REVOKE` (`:38-39`) is idempotent and
`SELECT_ACTIVE` (`:34-37`) honours `revoked_at IS NULL` — but a search of the artifact finds no caller
of `revoke` at all. Consequently the password-reset path above, which is the only credential write in
the component, leaves every previously issued token valid until it expires: 30 minutes by default, and
up to 24 hours with `AUTH_SESSION_TTL_SECONDS` at its allowed maximum (`AuthConfig.java:99`).

This is precisely the test that `testing-api-authentication-weaknesses` Step 5 codifies as "Test 2:
Token reuse after password change". The scenario that matters is the one an operator actually performs:
an account is suspected compromised, the administrator resets the password to lock the attacker out —
and the attacker's existing session continues to work for the rest of its TTL, because resetting a
password invalidates nothing. Combined with SEC-03, the same reset also re-activates a deactivated
account, so the containment action restores both the credential *and* the stolen session. Note that a
`revoked_at` column, a working revoke statement and an `ON DELETE CASCADE` from sessions to users
(`schema.sql:14`) are all present; only the call site is missing, which makes this a wiring gap rather
than a design gap.

**Fix:**

Revoke all of the user's sessions inside the same transaction that replaces the password, so a reset is
atomic with invalidation.

```java
// SessionService.java
    private static final String REVOKE_ALL_FOR_USER =
            "UPDATE user_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL";

    /** Revokes every live session of a user (password change, deactivation, forced logout). */
    public void revokeAllForUser(Connection connection, long userId, Instant now) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(REVOKE_ALL_FOR_USER)) {
            ps.setObject(1, OffsetDateTime.ofInstant(now, ZoneOffset.UTC));
            ps.setLong(2, userId);
            ps.executeUpdate();
        }
    }
```

```java
// CredentialRepository.java — return the row identity so the caller can revoke its sessions
    private static final String UPDATE =
            "UPDATE app_user SET password_hash = ? WHERE email = ? RETURNING user_id";

// AdminCli.java:112-116 — reset and revocation commit together, under one transaction
    String encoded = new PasswordHasher().hash(first);
    try (Connection connection = database.openTransaction()) {
        long userId = new CredentialRepository()
                .saveCredentialAndReturnId(connection, email.get(), encoded);
        new SessionService().revokeAllForUser(connection, userId, Instant.now());
        connection.commit();
    }
```

(`RETURNING` is supported by both target engines, PostgreSQL 12+ and H2 2.x, per `schema.sql:1`. If
portability beyond those is required, re-select `user_id` inside the same transaction instead.)

### SEC-05: Incomplete JDBC URL option denylist lets other driver options through

- **Severity:** Medium
- **CWE:** CWE-184: Incomplete Denylist for Security-Relevant Input (insecure-by-default defence-in-depth control)
- **Location:** `AuthConfig.java:36-39`, applied at `AuthConfig.java:70-78` with the shape regex at `:29`

**Vulnerable code:**

```java
// AuthConfig.java:36-39
    private static final String[] FORBIDDEN_URL_TOKENS = {
            "init=", "runscript", "trace_level", "script_", "shutdown",
            "allowothersettings", "socketfactory", "loggerfile", "sslfactory",
    };
```

**Why it is a problem:**

The comment above this array states its purpose: "Configuration is normally trusted, but a single
mis-set variable should not turn into code execution, so they are refused outright." A substring
denylist cannot deliver that, because the driver's dangerous surface is much larger than nine
substrings, and the shape regex at `:29` explicitly admits `?`, `;`, `=`, `&` and `@`, so arbitrary
option text reaches `DriverManager.getConnection` (`Database.java:30`) untouched.

Concretely, the denylist blocks `socketfactory`, `sslfactory` and `loggerfile`, but not the sibling
options that instantiate caller-named classes or redirect the connection in the same way on the
target driver — for example `sslhostnameverifier` (which names a class to instantiate), `loggerlevel`
plus `logdir` (arbitrary file write of driver logs, which is what `loggerfile` was there to stop), or
`ssh*`/`krbsrvname` style options that make the driver contact attacker-chosen hosts. It also does not
cover H2's own option surface beyond the literal substrings listed, and it is defeated by spelling an
allowed option differently since the comparison is against a lowercased raw string rather than parsed
keys. Any one of these is reachable from a single environment variable, which is exactly the failure
mode the control was written to survive: file read/write as the service account, driver-side SSRF to
internal endpoints, or class instantiation from whatever happens to be on the classpath.

**Fix:**

Parse the option surface and allowlist keys instead of denylisting substrings, and reject anything
unrecognised.

```java
// AuthConfig.java
    /** Only these driver options may appear in AUTH_DB_URL; everything else is refused. */
    private static final Set<String> ALLOWED_URL_OPTIONS = Set.of(
            "currentschema", "application_name", "connecttimeout", "sockettimeout",
            "tcpkeepalive", "locktimeout", "cancelsignaltimeout", "preparethreshold");

    /** Applies to both the PostgreSQL '?' query and H2 ';' parameter segments. */
    private static void rejectUnknownUrlOptions(String url) {
        String body = url.substring("jdbc:".length());
        int cut = body.indexOf('?');
        String query = cut < 0 ? "" : body.substring(cut + 1);
        if (query.isEmpty()) {
            // H2 carries parameters after the database name using ';'.
            int semi = body.indexOf(';');
            query = semi < 0 ? "" : body.substring(semi + 1);
        }
        for (String pair : query.split("[;&]")) {
            if (pair.isBlank()) {
                continue;
            }
            String key = pair.split("=", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (!ALLOWED_URL_OPTIONS.contains(key)) {
                throw new ConfigException("AUTH_DB_URL sets an option that is not allowed: " + key);
            }
        }
    }

    // fromEnvironment(), replacing the denylist loop at :72-78:
        String lowered = url.toLowerCase(Locale.ROOT);
        rejectUnknownUrlOptions(lowered);
```

Then pass anything operational as driver `Properties` in `Database.openTransaction()` rather than
through the URL, so the set of accepted options is a code-level constant rather than a string match.

### SEC-06: Secret-file permission check fails open when POSIX attributes are unavailable

- **Severity:** Medium
- **CWE:** CWE-636: Not Failing Securely ('Failing Open')
- **Location:** `AuthConfig.java:162-167` (check invoked at `:130`, rejection at `:175-176`)

**Vulnerable code:**

```java
// AuthConfig.java:162-167
    private static void requireOwnerOnly(Path path) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            return; // non-POSIX file system; permissions enforced by the platform ACL
        }
```

**Why it is a problem:**

`readDbPassword` presents this as a hard gate: the file path exists so that the secret "never appears
in a process listing or in a shared environment dump" (`:114-116`), and `README.md` advertises the
0600 requirement as an enforced control. But when the attribute view is unavailable, the method
returns *before* performing any check, and the caller proceeds to read and use the secret. Every
filesystem on which the view is unsupported — container volume mounts and NFS/CIFS exports that do not
surface POSIX attributes, overlay or tmpfs configurations mounted with odd options, encrypted or
deduplicating mounts, and any Windows/SMB path — silently becomes a filesystem on which a
group- or world-readable database password is accepted.

The comment's assumption ("permissions enforced by the platform ACL") is exactly the property that
cannot be verified here, and on the mount types above it is frequently false: bind-mounted secrets,
NFS with `no_root_squash`, and CIFS mounts presented as `file_mode=0777` are common and routinely
world-readable to everything on the host. The result is a control that fails in the unsafe direction
on the less-audited platforms, and a security claim in the documentation that does not hold on those
platforms. Compare `App.java:93-112`, which uses the same attribute API but *supplies* the 0600 mode
and uses `CREATE_NEW`; there, a missing POSIX view means the file is created without protection, so a
check would be needed there too.

**Fix:**

Fail closed when exclusivity cannot be proven, and verify ownership as well as mode bits.

```java
// AuthConfig.java:162-178
    private static void requireOwnerOnly(Path path) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            // We cannot prove the file is private, so we cannot treat it as a protected
            // secret store. Refuse rather than assume the platform's ACL is equivalent.
            throw new ConfigException("AUTH_DB_PASSWORD_FILE is on a file system that does not "
                    + "expose POSIX permissions; refusing to read a secret we cannot verify");
        }
        PosixFileAttributes attrs = view.readAttributes();
        Set<PosixFilePermission> perms = attrs.permissions();
        boolean sharedRead = perms.contains(PosixFilePermission.GROUP_READ)
                || perms.contains(PosixFilePermission.OTHERS_READ)
                || perms.contains(PosixFilePermission.GROUP_WRITE)
                || perms.contains(PosixFilePermission.OTHERS_WRITE);
        if (sharedRead) {
            throw new ConfigException("AUTH_DB_PASSWORD_FILE must not be readable or writable "
                    + "by group or others (chmod 600)");
        }
        String owner = attrs.owner().getName();
        String me = System.getProperty("user.name");
        if (owner != null && me != null && !owner.equals(me) && !"root".equals(me)) {
            throw new ConfigException("AUTH_DB_PASSWORD_FILE must be owned by the service account");
        }
    }
```

On platforms where an ACL API is available (Windows), implement an equivalent explicit check via that
API and keep the fail-closed default for anything else.

### SEC-07: Default `local-cli` source scope concentrates all clients of a deployment into one lockout budget

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption (availability of the authentication service)
- **Location:** `AuthConfig.java:88` (default value), consumed at `AuthService.java:62-75`

**Vulnerable code:**

```java
// AuthConfig.java:86-88
        // Per-source scope key: the caller's network address or client id, supplied by
        // the trusted deployment (not by the remote user) and validated all the same.
        String sourceId = optional("AUTH_SOURCE_ID", "local-cli");
```

**Why it is a problem:**

The per-source counter is the component's only defence against distributed guessing, and its scope key
comes from a *single process-wide constant* unless the operator overrides `AUTH_SOURCE_ID`. With the
default, every login attempt in the process shares one bucket of `AUTH_MAX_ATTEMPTS_PER_SOURCE` = 30
per 15-minute window (`:94`). On any shared host — the CLI's own stated deployment, and equally a
single-instance service behind one process — a user who merely mistypes a password 30 times, or anyone
able to submit 30 rejected attempts, locks every other user of that instance out of authentication for
the remainder of the window. Because `AuthService.java:75` evaluates the source counter *before* the
account counter and returns `SOURCE_LIMIT` without reaching verification, the lockout is total: no
account can authenticate, and per-account clearing on success (`AuthService.java:168`) cannot help.

The failure is asymmetric and cheap to exploit: the attacker is never themselves locked out of
anything, and setting `AUTH_SOURCE_ID` per client is not actually possible in a shared-process
deployment, since the value is read once at configuration time. This is the classic error that
`implementing-api-rate-limiting-and-throttling` Step 1 avoids by scoping auth endpoints "by ip"
rather than by a global label. The constant `"<invalid>"` account key at `AuthService.java:73` shares
the shape: it is a deliberate and reasonable defence against unbounded counter rows, but it also means
all malformed-address traffic from an instance shares one 10-attempt bucket, so garbage input can
degrade the account scope for everyone on that instance too.

**Fix:**

Do not default to a shared bucket — require a per-client source key, and bound the blast radius of a
shared bucket when one is genuinely intended.

```java
// AuthConfig.java:86-92
        // The per-source key must identify one request origin (client address or session
        // id), supplied per attempt by the embedding caller. A process-wide default would
        // let one client's failures lock out every other client of this instance.
        String sourceId = System.getenv("AUTH_SOURCE_ID"); // no fallback: unset means "per-attempt key required"
        if (sourceId != null && !InputValidator.isValidSourceId(sourceId)) {
            Arrays.fill(dbPassword, '\0');
            throw new ConfigException("AUTH_SOURCE_ID must be 1-64 chars of [A-Za-z0-9.:_-]");
        }
```

```java
// AuthService.java — resolve the source per attempt instead of per process
    public AuthResult authenticate(String rawEmail, char[] password, String rawSource) {
        Instant now = Instant.now();
        Optional<String> email = InputValidator.normalizeEmail(rawEmail);
        boolean passwordAcceptable = InputValidator.isAcceptablePassword(password);
        // rawSource is the transport peer identity (peer address / connection id), not
        // configuration; a shared fallback is only permitted with an explicit opt-in.
        String source = InputValidator.isValidSourceId(rawSource) ? rawSource
                : (config.allowSharedSource() ? config.sharedSourceId() : null);
```

Additionally, prefer a soft slowdown over hard refusal at the source scope (exponential backoff plus
alerting rather than a 15-minute total denial), and cap the `"<invalid>"` bucket at a fraction of the
per-account budget so malformed input cannot consume the whole instance's account-scope allowance.

### SEC-08: Database secret falls back to an environment variable after the protected-file path

- **Severity:** Low
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `AuthConfig.java:151-156` (the documented preferred path is `:117-150`)

**Vulnerable code:**

```java
// AuthConfig.java:151-156
        String env = System.getenv("AUTH_DB_PASSWORD");
        if (env != null) {
            if (env.length() > MAX_SECRET_FILE_BYTES) {
                throw new ConfigException("AUTH_DB_PASSWORD is too long");
            }
            return env.toCharArray();
        }
```

**Why it is a problem:**

The preferred path is the file, guarded by a size cap, a regular-file check and the 0600 gate, and its
Javadoc justifies that design as keeping the secret out of "a process listing or in a shared
environment dump". This fallback then re-introduces precisely the exposure the file path exists to
avoid, and does so unconditionally: if `AUTH_DB_PASSWORD_FILE` is unset or blank — a typo, a renamed
secret, a deployment that mounted the secret under a different name — the secret is read from the
environment instead, with no permission check possible and no warning emitted. Environment variables
are readable by any process running as the same uid through `/proc/<pid>/environ`, survive into every
child process and debug helper, land in crash dumps and in the environment blocks that supervisors,
`ps e`, container-inspection tools and CI systems routinely collect.

The consequence is not only weaker protection at rest but a silently weaker configuration: the operator
believes they are on the checked path because the service starts successfully. Note also that because
the file branch throws on any problem rather than falling through, this fallback only fires when the
file variable is absent — so the insecure configuration is exactly the mis-typed or mis-mounted case
where an operator most needs a loud failure. `README.md` describes the file as the secure route and the
environment variable as a fallback, but does not flag that using it forfeits the checks.

**Fix:**

Make the insecure route an explicit, acknowledged opt-in, and prefer a streamed secret over an
environment value.

```java
// AuthConfig.java:151-159
        String env = System.getenv("AUTH_DB_PASSWORD");
        if (env != null) {
            // The environment cannot be permission-checked the way a 0600 file can, so it is
            // only honoured when the operator has explicitly accepted that weaker posture.
            if (!"true".equalsIgnoreCase(System.getenv("AUTH_ALLOW_INSECURE_ENV_SECRET"))) {
                throw new ConfigException("AUTH_DB_PASSWORD is not used unless "
                        + "AUTH_DB_PASSWORD_FILE is set; set AUTH_ALLOW_INSECURE_ENV_SECRET=true "
                        + "to accept the weaker posture");
            }
            if (env.length() > MAX_SECRET_FILE_BYTES) {
                throw new ConfigException("AUTH_DB_PASSWORD is too long");
            }
            System.err.println("WARNING: database secret read from the environment; "
                    + "any process with this uid can read it.");
            return env.toCharArray();
        }
        // Embedded in-memory H2 (demo only) legitimately has no password.
        return new char[0];
```

### SEC-09: Database secret copied into an unwipeable immutable `String` for the JDBC driver

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in a Process
- **Location:** `Database.java:26-31`

**Vulnerable code:**

```java
// Database.java:26-31
        char[] password = config.dbPassword();
        if (password.length > 0) {
            props.setProperty("password", new String(password));
        }
        Connection connection = DriverManager.getConnection(config.jdbcUrl(), props);
        props.clear();
```

**Why it is a problem:**

The surrounding code is careful about secret lifetime: the password is held as `char[]` in
`AuthConfig`, zeroed on every early-exit validation path, and the raw file bytes are zeroed in a
`finally` (`AuthConfig.java:145-149`). This line gives that care away: `new String(password)` creates
an immutable `String` that is interned nowhere but is nevertheless pinned in the heap until the
collector happens to reclaim it, cannot be zeroed through the reference, and is invisible to
`props.clear()` at `:31` — clearing the map drops the reference, not the characters. Every connection
open (one per login, per `AuthService.countAttempt` and `verifyAndIssue`) leaves another copy behind,
so steady-state authentication steadily accumulates unrecoverable cleartext copies in the young
generation until GC, from where a heap dump, a core dump, or a swapping host exposes them. The
component's own README acknowledges this as a known limitation; it is reported here because it is the
one place the design's stated secret-hygiene property is not achieved.

**Fix:**

Avoid the `String` copy where the driver allows it, and otherwise confine the copy and document the
residual.

```java
// Database.java — replace the per-login Properties construction with a single
// lazily-opened pooled connection, so exactly one cleartext copy is ever created and
// the config's char[] can be wiped as soon as the driver has connected.
    private Connection pooled;

    private synchronized Connection pooled() throws SQLException {
        if (pooled != null && !pooled.isClosed()) {
            return pooled;
        }
        Properties props = new Properties();
        if (!config.dbUser().isEmpty()) {
            props.setProperty("user", config.dbUser());
        }
        char[] password = config.takeDbPassword(); // transfers ownership from AuthConfig
        try {
            if (password.length > 0) {
                props.setProperty("password", new String(password)); // the only copy, made once
            }
            pooled = DriverManager.getConnection(config.jdbcUrl(), props);
            pooled.setAutoCommit(false);
            pooled.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            return pooled;
        } finally {
            props.clear();
            java.util.Arrays.fill(password, '\0');
        }
    }
```

The driver's own `DataSource` implementations are the better answer where available —
`org.postgresql.ds.PGSimpleDataSource` and H2's `JdbcConnectionPool` hold the password in a mutable
array internally and reuse a physical connection, so `Database` need not build the properties map at
all. What must not continue is one `new String(password)` per login. If a `String` copy is genuinely
unavoidable for the target driver, keep it, state the limitation in the class Javadoc alongside the
other accepted residuals, and restrict heap dumps and core dumps for the process.

### SEC-10: Non-interactive password read yields an unwipeable `String` and is echoed

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in a Process (with exposure to stdout)
- **Location:** `ConsoleIo.java:38-52`

**Vulnerable code:**

```java
// ConsoleIo.java:38-52
    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            char[] value = console.readPassword("%s", prompt);
            return value == null ? new char[0] : bound(value);
        }
        System.out.println("Warning: no terminal attached; the password will be echoed.");
        System.out.print(prompt);
        System.out.flush();
        String line = reader.readLine();
        if (line == null) {
            return new char[0];
        }
        char[] value = line.toCharArray();
        // The String copy cannot be wiped; this path is for non-interactive testing only.
        return bound(value);
    }
```

**Why it is a problem:**

When no `Console` is attached, the password is read with `BufferedReader.readLine()` into a `String`
(`:46`). `BufferedReader` retains its line-buffer contents until overwritten, and the returned
`String` itself cannot be zeroed — the caller's `Arrays.fill` on the derived `char[]` (`AdminCli.java:120-126`)
does not reach it. So the secret persists in process memory in a form no code can erase. The same path
also echoes the secret to stdout: the warning at `:43` discloses that this happens, but disclosure is
not mitigated by disclosure — the password lands in terminal scrollback, and in any CI job log,
`docker logs` capture, or `script`/`tee` wrapper that collected the session's output. `scripts/smoke-test.sh`
exercises exactly this path, which is how the behaviour gets normalised into a pipeline.

This is a CLI/test-only surface rather than a network one, hence Low, but it is the path most likely to
be automated, and a password that reaches a CI log has to be treated as burned.

**Fix:**

Refuse to accept a secret over a non-tty stdin by default, so the demo convenience cannot become a
pipeline credential path; if piped input must be supported, read raw bytes into a `char[]` so no
`String` is created and make echo explicit rather than silent.

```java
// ConsoleIo.java:38-53
    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            char[] value = console.readPassword("%s", prompt);
            return value == null ? new char[0] : bound(value);
        }
        // No console means stdin is a pipe or a file: the bytes are echoed into whatever
        // collected stdout, and BufferedReader.readLine() would leave an unerased String
        // in the heap. Neither is acceptable for a real credential.
        if (!"true".equalsIgnoreCase(System.getenv("AUTH_ALLOW_PIPED_SECRET"))) {
            throw new IOException("No terminal attached: refusing to read a password from stdin. "
                    + "Set AUTH_ALLOW_PIPED_SECRET=true only for throwaway test credentials.");
        }
        System.err.println("WARNING: reading a password from stdin; it is not protected from echo.");
        System.err.print(prompt);
        System.err.flush();
        char[] raw = new char[MAX_LINE + 1];
        int len = 0;
        int b;
        // Reading byte by byte keeps the secret out of BufferedReader's internal char
        // buffer, which would otherwise retain the line until the next read.
        while ((b = System.in.read()) != -1 && b != '\n' && len < raw.length) {
            raw[len++] = (char) b;
        }
        try {
            return bound(java.util.Arrays.copyOf(raw, len));
        } finally {
            java.util.Arrays.fill(raw, '\0');
        }
    }
```

Two practical notes: the warning and prompt go to stderr rather than stdout so they cannot be
interleaved with or captured alongside program output, and `scripts/smoke-test.sh` — which is the
reason this path exists — must stay limited to throwaway in-memory H2 credentials, which it currently
is. `AdminCli` should also be checked for a `finally` that zeroes the returned array on this path as it
already does for the console path (`AdminCli.java:120-126`).

## 6. Verified Controls and Checks With No Finding

- **SQL injection absent** (`exploiting-sql-injection-vulnerabilities` Step 1 injection-point discovery):
  every SQL statement in the artifact is a `private static final String` constant —
  `CredentialRepository.java:16/20/23-24`, `SessionService.java:31-42`, the four throttle statements in
  `LoginThrottle.java`, `AdminCli` DDL — and every value reaches the server through
  `PreparedStatement.setString/setLong/setObject` binding. No statement text is concatenated, formatted
  or appended anywhere.
- **Dynamic DDL execution is not attacker-reachable:** `AdminCli.java:73-83` reads `schema.sql` only via
  `getResourceAsStream("/schema.sql")` from the artifact's own classpath, refuses to continue if it is
  missing (`:74-76`), and `splitStatements` (`:134-151`) merely strips `--` comment lines and splits on
  `;`. No remote or filesystem-supplied input reaches `statement.execute(sql)`.
- **Session token strength and storage:** 32 bytes from `SecureRandom`, URL-safe Base64 without padding,
  re-validated against `^[A-Za-z0-9_-]{43}$` *before* the database is touched
  (`SessionService.java:30`, `:51-55`, `:76-79`); only the SHA-256 of the token is stored
  (`INSERT` at `:31-33`), so a database leak does not yield usable sessions; the raw token is returned
  once and never logged.
- **Server-side session invalidation works as designed:** `SELECT_ACTIVE` requires
  `s.revoked_at IS NULL AND s.expires_at > ? AND u.is_active = TRUE` (`SessionService.java:34-37`), so
  expiry, revocation and administrative deactivation all cut off a live token; `REVOKE` (`:38-39`) and
  `PURGE_EXPIRED` (`:41-42`) are idempotent/bounded. (The gap is only that no caller invokes `revoke` —
  SEC-04.)
- **Constant-time credential comparison:** `java.security.MessageDigest.isEqual(expected, actual)` at
  `PasswordHasher.java:118`, after a strict parse; the malformed/short/long paths all take the decoy
  route rather than short-circuiting.
- **KDF secret hygiene:** `PBEKeySpec` is always cleared in a `finally` block
  (`PasswordHasher.java:141-150`), derived bytes, salt and expected hash are zeroed after use
  (`:120-123`, `:137-138`), the CLI zeroes both password arrays (`AdminCli.java:120-126`), and the raw
  secret-file bytes are zeroed in a `finally` (`AuthConfig.java:145-149`).
- **Fail-closed throughout:** a KDF that will not run raises `IllegalStateException` instead of reading
  as a pass (`PasswordHasher.java:145-148`); throttle accounting errors return `ERROR` and refuse the
  attempt (`AuthService.java:117-121`); an unusable source is refused rather than metered nowhere
  (`:65-70`); a malformed credential row is reported as unusable, not as a pass
  (`CredentialRepository.java:50-53`); `AuthResult.success` is reachable from exactly one place, after
  `passwordMatches && credential.active()` (`AuthService.java:151-171`).
- **Rate limiting is atomic and correctly ordered:** the counter is read under `SELECT … FOR UPDATE`
  before the read-modify-write, so concurrent attempts cannot both see "one attempt left"
  (`LoginThrottle.java:39`, `:66-79`); a lost insert race is recovered through a savepoint rather than
  aborting the outer transaction (`:83-95`); the window is not extended by further attempts
  (`:103-105`); a source that is already over its limit is not charged to the account, so a blocked
  attacker cannot keep consuming a victim's budget (`AuthService.java:103-106`); only the account
  counter is cleared on success, deliberately preserving the spraying quota (`:166-168`).
- **Equal-work failure paths and uniform user-facing text:** `verifyDecoy` is invoked on every
  non-verifying failure branch (`AuthService.java:67`, `:77`, `:89`, `:133`, `:139`) and verification is
  performed even for a deactivated account (`:149`), so cost and *text* do not separate "no such
  account", "unusable hash", "inactive" and "wrong password"; `AuthResult` exposes two strings total
  (`:29`, `:66`) and the `Reason` enum is used only in log records. (Residual timing risk under a hostile
  stored hash is SEC-02.)
- **Transaction discipline around the credential read:** `findForUpdate` holds the user row lock across
  "verify password → issue session", so verification cannot interleave with a concurrent password
  change or deactivation (`CredentialRepository.java:39-57`, `AuthService.java:129-171`), with
  `READ_COMMITTED` set explicitly (`Database.java:34`) and auto-commit off.
- **Token file is written privately:** mode `rw-------` supplied at creation time, `CREATE_NEW` so an
  existing path is never clobbered, symlink/non-regular files rejected via `NOFOLLOW_LINKS` plus an
  explicit delete-and-recreate guard (`App.java:88-113`); `AuthConfig` separately bounds
  `AUTH_SESSION_FILE` to 1024 characters and normalises the path (`:101-109`).
- **Cookie hardening:** `SessionCookie.java:40-43` emits `HttpOnly; Secure; SameSite=Strict` on every
  header, the `Path` is matched against a strict allow-regex before use (`:19`, `:33-35`) so CRLF and
  attribute injection into the header are impossible, `Max-Age` is clamped to 1…86400 (`:38`), and the
  clear-cookie path repeats the same attributes (`:47-51`).
- **Input bounding at every boundary:** email normalisation with strict regex and 254-char cap, source
  id constrained to `^[A-Za-z0-9.:_-]{1,64}$`, passwords limited to 8–256 characters (bounding KDF
  work per attempt) with a 12-character and three-character-class policy for new passwords
  (`InputValidator.java:20-31`, `AdminCli.java:104-111`); all console reads capped at 1024
  (`ConsoleIo.java:20`); hostile-row reads bounded by `setMaxFieldSize(512)`
  (`CredentialRepository.java:42`) with matching `VARCHAR` caps in `schema.sql:6-8`, `:13`, `:24`;
  secret file capped at 4096 bytes (`AuthConfig.java:41`, `:126-128`); encoded-hash parse capped at 256
  characters (`PasswordHasher.java:32`, `:78-81`).
- **No other attack surface present:** no command execution, no `Runtime`/`ProcessBuilder`, no
  deserialization (`ObjectInputStream`/Jackson/Gson), no JWT or XML parsing, no template or shell
  interpolation, no URL fetching, and no filesystem path derived from remote input. No SQL or
  credential text is written to a URL (`Database.java` passes the password only through `Properties`).
- **Administrative secret hygiene:** `AdminCli` never accepts a password on argv — it prompts twice and
  requires agreement (`:98-102`), and the `usage()` text documents that the password is prompted for
  (`:61`), so credentials cannot appear in the process listing or shell history.
- **Supply-chain posture of the build:** H2 is pinned to 2.3.232 and scoped `runtime` only
  (`pom.xml`), the compiler runs with `-Xlint:all`, and build plugins are version-pinned, so no
  floating plugin or dependency version is resolved at build time.
- **Logging destinations are minimal and secrets-free:** `LoggingSetup.java` removes inherited root
  handlers and installs a single INFO `ConsoleHandler`, and `LogMasker.maskSecret` reproduces no
  character of a secret (`:34-41`) — session tokens are never logged. (The email-fingerprint issue is
  SEC-01.)
