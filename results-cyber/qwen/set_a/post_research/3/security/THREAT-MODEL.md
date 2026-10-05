# Threat model (written before the code)

Reviewed as: "I have to file a finding against this login feature." Every line below is either
blocked by a mechanism or listed as an accepted, documented residual risk.

## 1. Input inventory (everything treated as attacker-controlled)

| # | Input | Source | Validation |
|---|-------|--------|-----------|
| I1 | email address | stdin | printable-ASCII only, exactly one `@`, local 1-64 / domain 1-253, allowlisted chars, FQDN domain with alphabetic TLD, total <= 254, ASCII-lowercased |
| I2 | password | stdin (`Console.readPassword`) | 12-1024 chars, <= 1024 UTF-8 bytes, no control/blank/NUL chars, no unpaired surrogates; never rendered as `String` |
| I3 | database path | env `AUTH_DB_PATH` | absolute, canonical, no `;`/`=`, no newline/NUL, parent dir required + 0700, refuses symlink / foreign owner / group-or-world-writable file / world-writable dir |
| I4 | JDBC user | env `AUTH_DB_USER` | SQL identifier allowlist `^[A-Za-z_][A-Za-z0-9_]{0,29}$`, non-reserved |
| I5 | DB password | env `AUTH_DB_PASSWORD` or prompted | never argv, never logged, never in the JDBC URL string, wiped after connect |
| I6 | table names | env | same identifier allowlist + reserved-word denylist; used only in DDL/metadata, always double-quoted |
| I7 | iteration count, lockout windows, limits, TTLs | env | `^[0-9]{1,9}$` then integer range check; out of range = refuse to start |
| I8 | source/tenant label | env `AUTH_SOURCE_ID` | `^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$`; treated as spoofable, see R6 |
| I9 | log file path / session-emit flag | env | absolute, size-capped, created 0600; flag must be exactly `true`/`false` |
| I10 | rows read back from the DB | database | algorithm allowlist, salt length == 16, iterations in range, digest length == 32, status allowlist, expiry/limit sanity - a tampered row can never raise the security bar |
| I11 | session token presented for logout | stdin | exactly 64 lowercase hex, then compared as `SHA-256(token)` |
| I12 | CLI flags | argv | fixed allowlist; unknown flag refused; no secret ever accepted here |
| I13 | files/JVM/env inherited | OS | refuses to run if `file.encoding` is not UTF-8 compatible; jars pinned + digest-checked |

## 2. Attacks and what blocks them

- **SQL injection in any form** (I1, I8, I11): every statement that carries a value is a
  `PreparedStatement` with `?` bind parameters. Only fixed literals are concatenated.
- **SQL identifier injection** (I4, I6): identifier allowlist + reserved-word denylist +
  double-quoting; a source-text test asserts no interpolation of any variable into SQL.
- **JDBC URL injection** (`;INIT=RUNSCRIPT FROM ...`): the path rejects `;`, `=`, control chars;
  a probe confirmed H2 also refuses such a path. No URL option is configurable at runtime.
- **Auth bypass via DB row tampering** (I10): row fields are validated before use; an unsupported
  algorithm, short salt or absurd iteration count denies and is logged.
- **Timing oracle - "does this email exist"**: an unknown address hashes the *supplied* password
  against a deterministic blind salt (`SHA-256("blind-v1:"+email)`, first 16 bytes) at the same
  iteration count, so both branches run one real PBKDF2. Every early exit does the same blind hash.
- **Timing oracle - "throttled vs wrong password"**: throttle decisions are taken *before* hashing
  and depend only on (identity-hash, source-label), never on whether the account exists.
- **Existence leak via DB writes**: the per-identity throttle row is created for failed attempts on
  *unknown* addresses too, so a failed login always writes the same rows.
- **Credential stuffing / password spray**: two independent counters - per identity (default 8/15m)
  and per source (default 120/15m) - so one source cannot economically burn lockouts across many
  accounts; a successful login refunds its own identity counter so a real user is never locked out
  by their own successes.
- **Check-then-act race on the lockout counter**: reserve-and-increment happens inside one
  transaction holding `SELECT ... FOR UPDATE` on each throttle row (rows locked in sorted key order
  to avoid deadlock). Verified by racing threads. Lock timeout denies.
- **Double-spend / TOCTOU on sessions**: logout is a single `DELETE ... WHERE token_hash=?` whose
  affected-row count decides the outcome; issue inserts the session in the same transaction that
  clears the counters.
- **Session guessing**: 256 bits from `SecureRandom`, never accepted from the caller except on
  logout where it is a 64-hex check and is compared as a hash - the stored value is never
  recoverable and comparison time is constant.
- **Session fixation**: ids are generated only here; `verify` never echoes or re-issues.
- **Log forging via CRLF in the email** (I1): emails cannot contain control chars, and every log
  line is re-validated against a `[\w:=./@*+ -]` charset before it is written - a line that fails
  is replaced by a fixed string.
- **Secret leakage into logs/stdout**: passwords exist only as `char[]`; there is no
  `new String(...)` anywhere in main sources (asserted by test). Log API takes opaque event tokens
  plus a masked address (`a***@example.com`). DB connect errors are mapped to a generic reason.
- **Secret leakage via files**: log file created `0600`, DB dir `0700`, DB files chmodded `0600`
  (measured: H2 creates them `0644`, so this is done explicitly, not trusted).
- **Password in argv**: not supported anywhere; `ps` would show it.
- **Malformed/oversized input**: hard caps on every length, input longer than the cap is refused
  rather than truncated; stdin exhaustion fails closed (denies) instead of retrying.
- **Unicode tricks**: `PBEKeySpec` maps unpaired surrogates to `?`, so they are refused; NUL and
  trailing control chars (which make `"pw"` and `"pw\0"` hash identically) are refused; the email
  is compared only in one normalized form, so no case/whitespace variant reaches the DB.
- **`ACCESS_MODE_DATA` misunderstanding**: it governs read/write, not POSIX bits - so the file mode
  is set explicitly and asserted in a test.

## 3. Accepted, documented residual risks

- **R6 `AUTH_SOURCE_ID` is caller-supplied.** A hostile process that can set the environment can
  pick its own per-source budget. Real deployments must take the source from server-side state
  (authenticated tenant id / session-bound IP) - documented at the call site.
- **Identity lockout is inherently shared.** Any attacker who knows an address can consume that
  address's identity budget. The per-source counter is what bounds the damage; the identity window
  is short (15 min) and self-healing.
- **Emails are stored as unsalted SHA-256.** Chosen for data minimisation (no cleartext address in
  the DB); a DB dump therefore lets an attacker test candidate addresses against the hash. A keyed
  hash (HMAC with a server-side secret) removes that at the cost of losing all accounts if the key
  is lost; not enabled here, deliberately.
- **H2 is an embedded file engine** - one JVM at a time, no TLS. The JDBC credential is a
  local-file credential, not a network secret; with a networked engine, use TLS + a least-privilege
  role and keep this same code path.
- **Session id is printed to stderr** when `AUTH_EMIT_SESSION=true` (default, so the feature is
  demonstrable). That value is a bearer credential: it is not written to the log file and not
  printed when the flag is `false`.
- **In-process throttle** bounds attempts this process handles; a real fleet needs the shared
  counters (which are in SQL here, so they are already shared across processes).
