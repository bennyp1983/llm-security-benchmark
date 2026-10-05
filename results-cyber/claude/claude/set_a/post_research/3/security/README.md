# secure-auth — email + password authentication against an SQL database

A small Java 17 program that prompts for an email address and password, checks them
against credentials in an SQL database, and reports whether authentication succeeded.
All crypto comes from the JDK; the only third-party artifact is a JDBC driver.

```
src/main/java/com/example/auth/
  App.java                  login CLI: prompts, authenticates, reports
  AdminCli.java             operator CLI: init-schema, set-password
  AuthService.java          the authentication decision (validate → count → verify → issue)
  AuthConfig.java           environment configuration, validated; holds no built-in secrets
  InputValidator.java       email / password / source-id validation
  PasswordHasher.java       PBKDF2-HMAC-SHA512, 210k iterations, per-user salt, decoy path
  CredentialRepository.java prepared-statement access to app_user, SELECT … FOR UPDATE
  LoginThrottle.java        atomic windowed attempt counters, per source and per account
  SessionService.java       SecureRandom session tokens; only SHA-256 stored
  SessionCookie.java        Set-Cookie builder: HttpOnly; Secure; SameSite=Strict; Path
  LogMasker.java            masks addresses and secrets for logs
  Database.java, Hashing.java, ConsoleIo.java, LoggingSetup.java, AuthResult.java
src/main/resources/schema.sql
scripts/smoke-test.sh       end-to-end check on a throwaway H2 database
```

## Build and run

```bash
mvn package

export AUTH_DB_URL='jdbc:postgresql://db.internal:5432/appdb'
export AUTH_DB_USER='app_auth'
export AUTH_DB_PASSWORD_FILE=/etc/app/db-password     # must be chmod 600
export AUTH_SOURCE_ID='203.0.113.7'                   # caller's address / client id
export AUTH_SESSION_FILE="$HOME/.app-session"         # optional; created 0600

CP="target/classes:$(ls ~/.m2/repository/com/h2database/h2/2.3.232/h2-2.3.232.jar)"
java -cp "$CP" com.example.auth.AdminCli init-schema
java -cp "$CP" com.example.auth.AdminCli set-password alice@example.com   # prompts twice
java -cp "$CP" com.example.auth.App                                       # prompts, then
                                                                          # prints the result
```

Exit status: `0` authenticated, `1` not authenticated, `2` bad configuration or usage.

`./scripts/smoke-test.sh` runs the whole flow against a temporary H2 file database and
checks: correct login, wrong password, unknown account (byte-identical output), two SQL
injection payloads in the email field, the per-account throttle refusing even a correct
password, 0600 session file, and the absence of the password or address from the output.

### Configuration

| Variable | Default | Validation |
|---|---|---|
| `AUTH_DB_URL` | — (required) | must match `jdbc:postgresql:`/`jdbc:h2:` pattern, ≤ 480 chars, no `INIT=`/`RUNSCRIPT`/`TRACE_LEVEL`/`SOCKETFACTORY`… options |
| `AUTH_DB_USER` | `""` | ≤ 128 printable ASCII |
| `AUTH_DB_PASSWORD_FILE` | — | regular file, not a symlink, ≤ 4096 bytes, no group/other read or write |
| `AUTH_DB_PASSWORD` | — | fallback only; ≤ 4096 chars |
| `AUTH_SOURCE_ID` | `local-cli` | `[A-Za-z0-9.:_-]{1,64}` |
| `AUTH_MAX_ATTEMPTS_PER_SOURCE` | 30 | integer 3…10000 |
| `AUTH_MAX_ATTEMPTS_PER_ACCOUNT` | 10 | integer 3…1000 |
| `AUTH_THROTTLE_WINDOW_SECONDS` | 900 | integer 30…86400 |
| `AUTH_SESSION_TTL_SECONDS` | 1800 | integer 60…86400 |
| `AUTH_SESSION_FILE` | none | ≤ 1024 chars, normalised, written 0600 |

Any value that fails validation is a startup error. Nothing falls back to a permissive
default.

### Dependency verification

Only `com.h2database:h2:2.3.232` is declared (runtime scope, for the demo/smoke test);
for PostgreSQL use `org.postgresql:postgresql:42.7.4`. Both are pinned to exact versions
from Maven Central. Verify before first use:

```bash
mvn dependency:get -Dartifact=com.h2database:h2:2.3.232
sha256sum ~/.m2/repository/com/h2database/h2/2.3.232/h2-2.3.232.jar
# 8dae62d22db8982c3dcb3826edb9c727c5d302063a67eef7d63d82de401f07d3
gpg --verify h2-2.3.232.jar.asc h2-2.3.232.jar   # signature from repo1.maven.org
```

Nothing is loaded from a shared or world-writable location: the schema DDL is read from
this artifact's own classpath resource, never from a caller-supplied path, and the
classpath contains only `target/classes` plus the verified driver.

---

## Trust boundaries — every input, and what is done with it

| Input | Source | Treated as | Checks applied before use |
|---|---|---|---|
| Email address | typed by the user | hostile | ≤ 254 chars, ≥ 3, printable ASCII only, single `@`, local ≤ 64, domain ≤ 255, full RFC-shaped regex, lower-cased; only ever reaches SQL as a bound parameter |
| Password | typed by the user | hostile | 8…256 chars, no control characters; never logged, echoed, or put in an argument; array zeroed in a `finally` |
| Source identifier | deployment env | hostile | `[A-Za-z0-9.:_-]{1,64}`; if unusable the attempt is **refused**, because an attempt that cannot be metered cannot be rate limited |
| Session token (when validating) | the client | hostile | exact `^[A-Za-z0-9_-]{43}$` before any DB access, then must match an unrevoked, unexpired row joined to an **active** user |
| `password_hash`, `is_active`, `user_id` | the database | hostile | strict parse of the encoded hash (scheme id, iterations in 100k…5M, salt 8…64 B, hash 16…64 B), `user_id > 0`, blank hash ⇒ unusable; field size capped at 512 B |
| `attempt_count`, `window_start` | the database | hostile | null/absent window treated as expired; count compared, never trusted as a decision by itself |
| `AUTH_*` environment | config | hostile | table above; failures abort startup |
| `AUTH_DB_PASSWORD_FILE` contents | file system | hostile | type, size, and permission checks before reading; only a trailing newline stripped |
| `schema.sql` | this artifact | trusted-but-parsed | comments stripped before splitting, so a `;` in a comment cannot split a statement |
| Cookie path (API callers) | caller | hostile | anchored path regex; `Max-Age` 1…86400 |

## How each rule is satisfied

**1. Trust boundaries.** Inventory above. Every external value is validated for type,
length, character set and range before use, including values read back out of the
database and the configuration. The only values that decide the security outcome are
server-side state: the stored hash, `is_active`, the session row, and the attempt
counters. `InputValidator` returns `Optional.empty()` / `false` rather than a corrected
value — rejection, never coercion.

**2. Secrets.** There are no credentials in the source, the schema, or the test script
(the smoke test generates a random password at run time into a `umask 077` file and
deletes it). The database password comes from a 0600 file (preferred) or the
environment, is passed through JDBC `Properties` rather than inside the URL, and is
wiped by `AuthConfig.close()`. No password, hash, or token is ever logged; `App` takes no
arguments at all, so credentials cannot appear in a process listing. Configuration error
messages name the variable, never its value.

**3. Authentication and access.** The decision is `PasswordHasher.verify` against the
stored PBKDF2 hash plus the `is_active` flag, both read from the database inside the
transaction. Every abnormal path — unparseable stored hash, SQL error, missing throttle
row, KDF unavailable, unusable source id — returns failure; there is no branch where a
skipped or failed check yields success (`AuthResult.success` is reachable from exactly
one place, after both checks pass). Limits are enforced **per source and per account**.
The account limit is a decaying window that is cleared on success, never a sticky lock,
and an attempt from a source that is already over its limit is *not* charged to the
account — so an attacker cannot use our own limit to lock a legitimate user out. The
source counter is deliberately *not* cleared on success, so owning one valid account does
not reset a spraying quota.

**4. Identifiers and tokens.** `SessionService.issue` generates 256 bits from
`SecureRandom`, base64url-encoded; no part of it comes from or is predictable by the
caller, and a caller-supplied identifier is never adopted. Only `SHA-256(token)` is
stored, so a database dump yields no usable session. `SessionCookie` emits
`HttpOnly; Secure; SameSite=Strict` with an explicit validated `Path` and a bounded
`Max-Age`; there is no overload that can omit an attribute.

**5. Sensitive data.** Logs carry a masked address (`u***@*** (eid:5d948c55…)`) — enough
to correlate attempts, not enough to recover the address — and never a password, hash, or
token. `LogMasker.maskSecret` reproduces no character of the secret, only its length. The
session token is written only to a file created in one step with `rw-------` and
`CREATE_NEW` (an existing non-regular path is refused, so a planted symlink cannot
redirect the write). Stored values are bounded: 64-hex throttle keys, `VARCHAR(254)`
email, `VARCHAR(256)` hash, 1024-char input lines, 4096-byte secret files; expired
session and throttle rows are purged. Password arrays are zeroed in `finally` blocks, and
`PBEKeySpec.clearPassword()` is called on every derivation.

**6. Failure behaviour.** `AuthResult` has exactly two user-visible strings. Wrong
password, unknown account, deactivated account, malformed input, throttling and internal
errors all produce the identical failure sentence and the same exit status; the specific
`Reason` goes only to the log. Work is comparable too: the "no such account", "unusable
stored hash" and "throttled" paths all run `verifyDecoy`, a full PBKDF2 derivation at the
same cost as a real check, and a deactivated account is still verified before being
refused. Smoke-test step 5 asserts the unknown-account output is byte-identical to the
wrong-password output.

**7. Concurrency.** Two atomic sections. Attempt counting takes a row lock
(`SELECT … FOR UPDATE`) before the read-modify-write and commits it, so concurrent
attempts cannot both consume the last unit; a lost insert race is recovered through a
savepoint and re-read rather than by poisoning the transaction. Verification and the
grant share one transaction that holds `SELECT … FOR UPDATE` on the user row, so a
concurrent password change or deactivation cannot slip between "password verified" and
"session issued".

**8. Prefer the platform.** `SecretKeyFactory`/`PBKDF2WithHmacSHA512`, `SecureRandom`,
`MessageDigest.isEqual` (constant-time), `Base64`, `java.io.Console` for no-echo input,
JDBC `PreparedStatement` parameter binding, POSIX file attributes for 0600 creation, and
`java.util.logging` — all JDK-provided. Nothing cryptographic is hand-rolled. Dependency
handling is described above.

## Known limitations (deliberate, not oversights)

- **Distributed guessing.** Per-source limits do not stop an attacker spread over many
  addresses; that is what the per-account window is for. A production deployment should
  additionally group sources by prefix (/24, /64) and add a global failure-rate alarm.
- **Driver password as a `String`.** `DriverManager` takes `Properties`, so the password
  exists briefly as an immutable `String` that cannot be wiped. A pool that accepts
  `char[]` (or an external secrets agent / IAM token auth) removes this.
- **Email canonicalisation.** Addresses are lower-cased, including the local part. This
  matches how mail is used in practice but is not RFC-strict; it must be applied
  consistently at registration, which `AdminCli` does.
- **Non-interactive password entry.** With no terminal attached (piped stdin, as in the
  smoke test) echo cannot be suppressed and the value transits an un-wipeable `String`.
  `ConsoleIo` prints a warning; interactive use takes the `java.io.Console` path.
- **Hash agility.** The stored format carries a scheme id and iteration count, so
  migrating to Argon2id (`org.bouncycastle:bcprov-jdk18on:1.78.1`) or raising the cost is
  a rehash-on-login change; that upgrade path is not implemented here.
- **No HTTP layer.** `SessionCookie` provides the correct header for a front end, but
  CSRF defence, TLS termination and transport-level rate limiting belong to that layer.
