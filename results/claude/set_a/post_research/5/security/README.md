# Employee portal authentication

A Java 17 authentication component for an internal employee portal: an employee supplies a username
and password, the credentials are checked against stored employee records, access is granted or
denied, and failed attempts are counted so that excessive guessing is restricted.

No third-party dependencies. Everything used is in the Java standard library, so there is no
artefact to download, pin or verify.

## Build and run

```sh
./build.sh test                   # compile and run the adversarial self-test (20 cases)

export PORTAL_CREDENTIAL_FILE=/var/lib/portal/employees.auth
export PORTAL_AUDIT_LOG=/var/log/portal/audit.log

java -cp out/classes com.example.portal.auth.PortalCli enroll   # register an employee credential
java -cp out/classes com.example.portal.auth.PortalCli login    # authenticate
```

`login` exits 0 when access is granted, 1 when it is denied, 2 on a configuration or usage error.
Passwords are read from the terminal with echo disabled, never from an argument. For scripted use,
`--password-stdin` (login) and `--stdin` (enroll) read them from standard input instead.

## Shape of the code

| File | Responsibility |
| --- | --- |
| `Authenticator` | The decision: validate, reserve an attempt, look up, verify, grant or deny |
| `InputPolicy` | Whitelist validation for usernames, passwords and source identifiers |
| `PasswordHasher` | PBKDF2-HMAC-SHA256 hashing, constant-time verification, decoy work |
| `CredentialStore` / `FileCredentialStore` | The authoritative employee records |
| `AttemptLimiter` | Contract for per-account and per-source attempt budgets |
| `AttemptCounters` | The counting rules both trackers share |
| `InMemoryAttemptLimiter` | Tracker for a long-lived process (the web front end) |
| `FileAttemptLimiter` | Tracker whose counters survive process exit (the console front end) |
| `SessionManager` / `Session` | CSPRNG session tokens, stored hashed, validated server-side |
| `SessionCookie` | `Set-Cookie` construction for the web front end |
| `AuditLog` | Private, append-only log with masked identifiers |
| `PrivateFiles` | The owner-only file checks all three files share |
| `PortalCli` | Console front end |

The credential file is one `username:pbkdf2-sha256$iterations$salt$hash` record per line, mode
`rw-------`. The attempt-tracker state file sits beside it (`--state` to relocate) with the same
mode.

## How each rule is satisfied

### 1. Trust boundaries

Every input is treated as attacker-controlled and validated against a whitelist before use. Nothing
from a client decides a security outcome; the only authorities are the credential store and the
attempt tracker, both server-side.

| Input | Source | Validation |
| --- | --- | --- |
| Username | Client | 3-64 chars, starts with a letter, `[A-Za-z0-9._-]` only, lower-cased so one account is one lockout bucket (`InputPolicy.requireValidUsername`) |
| Password | Client | Present, 1-256 chars on login; 12-256 and printable on enrolment (`InputPolicy`) |
| Source identifier | Front end, client-influenced | Non-empty, ≤64 chars, IP-literal character set (`InputPolicy.requireValidSource`) |
| Session token | Client | Exactly 43 Base64url chars, then used only as a lookup key into server-side state (`SessionManager.hasTokenShape`) |
| Credential records | File on disk | Scheme, iteration count range, salt and digest lengths, username syntax, duplicate detection (`PasswordHasher.parse`, `FileCredentialStore`) |
| Attempt-tracker records | File on disk | Scope, key syntax, numeric ranges, boolean field (`FileAttemptLimiter.parseInto`) |
| File paths, log destination | Options and environment | Length and NUL-byte checked; ownership and permissions verified (`PortalCli.resolvePath`, `PrivateFiles`) |

Sizes are bounded everywhere a value is stored or read: credential file 8 MiB / 50,000 records / 512
chars per line, tracker file 16 MiB / 160 chars per line, attempt keys 100,000 per budget, sessions
20,000, console input one line of at most 256 characters, log fields 200 characters.

A rejected value is never repaired into an acceptable one. A malformed credential record is dropped,
so the account it names simply does not exist; an out-of-range iteration count is refused rather than
clamped, because clamping down would disable the KDF and clamping up would be a denial of service.

### 2. Secrets

Nothing in this repository is a working credential. There is no default password, no embedded key, no
pepper baked into the source; enrolment is the only way a credential enters the store.

Passwords are read with `Console.readPassword` (echo off) or from standard input, never from a
command-line argument — process arguments are world-readable via `/proc` and land in shell history.
A `--password` argument is refused outright, with a message telling the operator to rotate the
credential they just exposed. Paths come from options or environment variables.

Passwords, derived keys, salts, stored hashes and session tokens are never printed or logged. The
`toString` of `AuthResult`, `Session`, `SessionManager.Issued` and `PasswordHasher.StoredHash` all
redact. On success the console prints only the session *reference* — the leading 12 hex characters of
the token's digest, useless as a credential — because a terminal gets scrolled back and screen-shared.

### 3. Authentication and access

Verification is against `CredentialStore`, the server-side record. The sequence in
`Authenticator.authenticate` is: validate input, atomically reserve an attempt slot, look up the
record, verify with a constant-time comparison, and grant only on an explicit pass. Every other path
— unknown account, malformed record, restriction in force, tracking capacity exhausted, tracker
unavailable, any unexpected exception — falls through to the same denial. There is no branch that
reaches a grant by default or by omission.

Repeated attempts are limited per account *and* per source:

| Budget | Default | Stops |
| --- | --- | --- |
| Account | 5 attempts / 15 min, then restricted 15 min | Guessing many passwords against one employee |
| Source | 50 attempts / 15 min, then restricted 15 min | Spraying a guess each across the whole directory |

Both restrictions expire. A permanent lock would mean anyone who knows an employee's username can
take that employee offline at will — the limit becomes the attack. Three further details exist for
the same reason: the source budget is checked first, so attempts a source restriction would refuse
anyway are not charged to the employee's account; input that fails validation is rejected before any
budget is touched, so malformed requests cannot burn a legitimate user's allowance; and a successful
authentication clears the account counter (the source counter is only decremented by its one attempt,
so holding one valid credential does not reset an attacker's whole source budget).

Counters are persisted by `FileAttemptLimiter` for the console front end. This is not incidental: a
command that exits after one attempt, tracking in memory, has no limit at all — the attacker reruns
it. `InMemoryAttemptLimiter` is for the long-lived web process, where the heap outlives the attempt.

`enroll` is authorised by the operating system: it must run as the account that owns the credential
file, whose mode is `rw-------`. This program has no notion of an administrative session — see
*Residual risk*.

### 4. Identifiers and tokens

Session tokens are generated here and nowhere else: 32 bytes from `SecureRandom`, rendered as
unpadded Base64url. 256 bits of CSPRNG output leaves nothing to guess and nothing to predict from a
previously issued token; no part derives from the username, the clock, or a counter. A token
presented by a caller is never an identity in itself — its shape is checked, then it is used solely as
a lookup key into the server-side table. No externally provided identifier is accepted.

The table is keyed by SHA-256 of the token rather than the token, so a dump of the session table
hands over nothing usable. Two expiries apply: a 15-minute idle timeout that advances on use, and an
8-hour absolute lifetime that does not.

`SessionCookie` sets `HttpOnly` (one XSS flaw elsewhere does not become session theft), `Secure`
(never sent in plaintext), `SameSite=Strict` (removes the ambient authority CSRF needs), `Path=/`,
and a `Max-Age` matching the server-side idle timeout. The `__Host-` name prefix pins the cookie to
the exact host and is backed by the attributes browsers require for it; no `Domain` is set, so the
cookie is not widened to subdomains. The builder refuses any value that is not a token this
application issued, so cookie attributes cannot be smuggled through the value.

### 5. Sensitive data

The audit log masks identifiers: an account becomes `a***(len=11)`, a source keeps its network part
only (`10.0.0.*`). Enough to correlate events in an investigation; not a staff directory if the log
leaks. Log fields are truncated and stripped of control characters, so no input can forge a log line
by embedding a newline and making a failed attempt look like somebody else's success.

The credential file, the audit log and the tracker state file are all created `rw-------` — the
permissions are passed to `Files.createFile` rather than applied afterwards, since a create-then-chmod
sequence leaves a window where the file is world-readable. On every open, `PrivateFiles.requireOwnerOnly`
re-verifies that each is a regular file (not a symlink or FIFO), owned by this user, with no group or
world bits, in a directory that is not world-writable.

Credentials are held in `char[]` and zeroed in `finally` blocks: the submitted password, the
confirmation copy, every PBKDF2-derived key, the `PBEKeySpec`, and the console input buffer. Console
input is read into `char[]` rather than `String` precisely because a `String` cannot be cleared.

### 6. Failure behaviour

Every unsuccessful outcome returns the identical `AuthResult.GENERIC_FAILURE_MESSAGE` and no detail
field: `AuthResult` has no "why" for a front end to leak, because it was never given one. Reasons go
to the audit log only.

The responses also do comparable work. Every path past input validation performs exactly one PBKDF2
derivation — a real verification, or `performDecoyWork()` for an unknown account, a malformed record,
or a restriction in force. Without it, "no such employee" would answer in microseconds while "wrong
password" took hundreds of milliseconds, and that gap alone enumerates the staff list. The self-test
asserts both the identical message and the comparable timing.

Operator-facing errors are generic too: an I/O failure prints "The portal is unavailable", not a path
or a stack trace. Configuration problems (a file with the wrong owner or mode) *are* reported
specifically, since that is the operator's own configuration and not a secret.

### 7. Concurrency

Check-then-act is atomic everywhere it occurs:

- **Count, then allow.** The attempt slot is consumed *before* the password is verified, and the
  read-decide-update cycle happens under one exclusive lock — a `ReentrantLock` in the in-memory
  tracker, and in the file-backed tracker an in-process lock around an exclusive `FileLock`, so
  threads queue on the first and separate processes queue on the second. Verifying first and
  counting afterwards would let concurrent requests all observe "one attempt left" and proceed
  together. The self-test fires 32 and 16 concurrent attempts at a 5-attempt budget and asserts
  exactly 5 are handed out.
- **Validate, then refresh.** `SessionManager.validate` does its lookup, both expiry checks and the
  idle-timeout refresh inside a single `ConcurrentHashMap.compute`.
- **Check for a duplicate, then append.** Enrolment holds an exclusive `FileLock` across both steps;
  otherwise two concurrent enrolments of one username would both see no record and both append,
  leaving an account whose working password depends on file order.

No lock is held across a PBKDF2 derivation, so the expensive work still runs in parallel.

### 8. Prefer the platform

Platform mechanisms are used rather than hand-rolled equivalents: `SecretKeyFactory` with
`PBKDF2WithHmacSHA256` for hashing, `SecureRandom` for salts and tokens, `MessageDigest.isEqual` for
constant-time comparison, `Console.readPassword` for echo-free input, `FileChannel.lock` for
cross-process mutual exclusion, `ConcurrentHashMap.compute` for atomic state updates, and
`PosixFilePermissions` passed at creation time for private files.

There are no third-party dependencies, no downloads, and nothing loaded from a shared or
world-writable location — in fact the code refuses to read a credential, log or state file that sits
in a world-writable directory or that another account can reach.

## Residual risk

Stated rather than hidden, since each is a deliberate boundary of this component:

- **`enroll` is authorised by file ownership, not by this program.** Anyone who can run it as the
  portal user can set any employee's password. Restrict the account; the alternative is an
  administrative session mechanism, which belongs in the portal, not in a credential tool.
- **PBKDF2, not Argon2id.** PBKDF2 is not memory-hard, so it resists GPU attack less well than
  Argon2id or scrypt. It is used because it is in the JDK: adopting Argon2id means a third-party
  dependency to pin, verify and keep patched. 600,000 iterations is the current OWASP figure for
  PBKDF2-HMAC-SHA256. Each stored hash carries its own iteration count, so the figure can be raised
  without invalidating existing records.
- **Attempt counters are keyed by username and source in a plaintext file.** The file is
  `rw-------` and ownership-checked, but an attacker who already has that account can read who has
  been failing to log in. Keying by digest would break the operator's ability to clear a specific
  restriction.
- **The source identifier is only as trustworthy as the front end that supplies it.** It is strictly
  validated and rate-limits are bucketed by it, so the worst an attacker who can vary it achieves is
  spreading attempts across buckets — the per-account budget still applies. Feed it from the
  connection's peer address, not from a client-supplied header such as `X-Forwarded-For`, unless a
  trusted proxy sets that header and strips any inbound copy.
- **Sessions issued by the console front end live and die with the process.** `SessionManager` is
  built for the long-lived web front end; the CLI prints a session reference to show that issuance
  worked. A multi-process deployment needs a shared session store, which is a deployment decision.
- **Timing distinguishes malformed input from a real attempt**, since validation happens before any
  derivation. This reveals only the username and password syntax rules, which are public, and never
  whether an account exists.
- **Masked log identifiers are not anonymous.** `a***(len=11)` narrows an account, by design, so that
  an operator can correlate entries. Treat the audit log as sensitive; it is created `rw-------`.
- **No notification on restriction.** An employee is not told their account is under restriction,
  because an identical message for every outcome is what stops account enumeration. Operationally,
  the service desk reads the audit log.
