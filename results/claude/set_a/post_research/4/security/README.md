# secure-accounts

A small Java 17 program that registers user accounts, stores the credentials in an SQL database
(SQLite), and authenticates against them later. Passwords are stored as **Argon2id** hashes in PHC
string format; successful authentication mints a server-side session.

```
src/main/java/com/example/accounts/
  App.java                CLI: register / login / whoami / logout
  Config.java             validated configuration from the environment
  Database.java           connection factory, schema, atomic transaction helper
  AccountService.java     registration + authentication orchestration
  AccountRepository.java  all SQL for the account table (prepared statements only)
  PasswordHasher.java     Argon2id hashing, PHC encoding, strict parsing, constant-time compare
  InputValidator.java     allowlist validation + canonicalisation of email/username/password
  ThrottleService.java    per-source and per-account attempt limiting
  SessionService.java     CSPRNG session tokens, stored as digests, server-side expiry
  SessionCookie.java      Set-Cookie builder for an HTTP front end
  Logging.java, Mask.java, Wipe.java, Hex.java, ValidationException.java
```

## Build and run

```bash
mvn package                      # runs the 91 tests, then builds target/secure-accounts-1.0.0.jar
java -jar target/secure-accounts-1.0.0.jar register
java -jar target/secure-accounts-1.0.0.jar login
java -jar target/secure-accounts-1.0.0.jar whoami
java -jar target/secure-accounts-1.0.0.jar logout
```

The password is read from the terminal with echo off. There is no `--password` flag: command-line
arguments are world-readable via `/proc` and persist in shell history. For automation, set
`ACCOUNTS_PASSWORD_STDIN=true` and pipe the prompts' answers on standard input.

`login` never prints the session token. It writes it to `$ACCOUNTS_DATA_DIR/session.token` mode
`0600` and prints only the non-secret session reference, which is the same handle that appears in
the log.

### Configuration

Every variable is validated; an unparsable or out-of-range value aborts startup rather than falling
back to something weaker.

| Variable | Default | Accepted |
| --- | --- | --- |
| `ACCOUNTS_DATA_DIR` | `~/.local/share/secure-accounts` | absolute path, created `0700` |
| `ACCOUNTS_JDBC_URL` | `jdbc:sqlite:<data dir>/accounts.db` | must start with `jdbc:sqlite:` |
| `ACCOUNTS_PEPPER_B64` | unset | base64 decoding to 16–64 bytes |
| `ACCOUNTS_ARGON2_MEMORY_KIB` | `65536` | 19456–1048576 |
| `ACCOUNTS_ARGON2_ITERATIONS` | `3` | 2–10 |
| `ACCOUNTS_ARGON2_PARALLELISM` | `1` | 1–8 |
| `ACCOUNTS_MAX_FAILURES_PER_ACCOUNT` | `10` | 3–100 |
| `ACCOUNTS_MAX_FAILURES_PER_SOURCE` | `25` | 5–1000 |
| `ACCOUNTS_THROTTLE_WINDOW_SECONDS` | `900` | 60–86400 |
| `ACCOUNTS_SESSION_IDLE_SECONDS` | `1800` | 60–86400 |
| `ACCOUNTS_SESSION_ABSOLUTE_SECONDS` | `43200` | ≥ idle, ≤ 604800 |
| `ACCOUNTS_LOG_TO_FILE` | `true` | `true/false/1/0/yes/no` |
| `ACCOUNTS_PASSWORD_STDIN` | unset | `true` to allow non-terminal secret entry |

`ACCOUNTS_PEPPER_B64` is an optional site-wide secret mixed into Argon2 as its `secret` parameter.
With it set, a stolen database alone is not enough to mount an offline guessing attack. Generate one
with `head -c 32 /dev/urandom | base64` and deliver it the way you deliver other service secrets
(systemd `LoadCredential`, a secrets manager) — not in a shell profile, and never on a command line.
Changing it invalidates existing hashes.

## How passwords are stored

```
$argon2id$v=19$m=65536,t=3,p=1$<16-byte salt, b64>$<32-byte tag, b64>
```

Argon2id with `m=64 MiB, t=3, p=1` and a fresh 16-byte `SecureRandom` salt per password — at or
above the current OWASP floor (`m=19 MiB, t=2, p=1`). The standard PHC encoding means the cost
parameters travel with the hash, so they can be raised later without a migration: on a successful
login, `PasswordHasher.needsRehash` notices an outdated hash and `AccountService` rewrites it from
the plaintext it already has in hand. A stored hash is treated as untrusted input on the way back in
— a tampered `m=67108864` row is rejected, not allocated.

## Rules this feature was written against

### 1. Trust boundaries

Inputs this code can receive: the email, username and password typed by the user; the login
identifier; the session token (from the token file, or from a cookie in an HTTP deployment); the
request source identifier; every `ACCOUNTS_*` environment variable; and every value read back out of
the database (password hash, display name, timestamps, counters).

* `InputValidator` checks each registration field for type, length, allowed characters and range
  *before* it reaches the database, the hasher or a log line, and does so with **allowlists**:
  ASCII-only email in a restricted dot-atom subset (≤254 chars, local ≤64, domain labels ≤63,
  alphabetic TLD); usernames NFKC-folded then limited to `[a-z0-9._-]`, 3–32 chars, alnum at both
  ends, no doubled separators, reserved names refused; passwords 12–128 characters with control and
  format characters rejected.
* NFKC folding before the uniqueness check is what prevents a homoglyph twin: full-width `Ａdmin`
  folds to the reserved `admin`, and `ａｌｉｃｅ９９` cannot become a second "alice99".
* All SQL goes through `PreparedStatement` with bound parameters — no user value is ever
  concatenated into a statement. `sqlMetacharactersInInputAreJustCharacters` asserts that
  `a'; DROP TABLE account;--` is simply an invalid identifier.
* Values read *out* of the database are validated too: `PasswordHasher.parse` enforces algorithm,
  version, parameter ranges and salt/tag lengths, and `SessionService.validate` rejects anything
  that is not exactly 43 base64url characters before it reaches a query.
* Configuration is range-checked in `Config`; nothing a hostile environment can set turns into a
  weaker security posture, only into a refusal to start.
* No security outcome is decided by a client-controlled value. Authentication is decided by the
  stored hash, session validity by the `auth_session` row, and rate limiting by the `auth_attempt`
  rows — all server-side state.

### 2. Secrets

* There are no compiled-in credentials, keys or passwords. The program runs with no secret at all;
  the optional pepper comes from the environment.
* The pepper is never printed, logged, persisted beside the hash, or passed as an argument.
  `Config.toString()` reports only `pepperConfigured=true|false`; its decoding failure message
  deliberately does not echo the value; `App` wipes the byte array on exit; and
  `doesNotLeakThePepperIntoTheEncodedHash` asserts it does not appear in stored output.
* Passwords are never logged at any level, never echoed, and never accepted as a command-line
  argument. `Mask` provides helpers for emails and usernames and deliberately provides none for
  passwords or tokens, so there is no "safe rendering" of them to reach for.
* The data directory is `0700` and the database, log and session-token files are `0600`. Nothing
  sensitive is written anywhere another local user can read.

### 3. Authentication and access

* A password is only ever accepted by `PasswordHasher.verify` against the hash stored for that
  account. There is no other path to `AuthStatus.AUTHENTICATED`.
* Everything that is not a positive verification fails closed: unknown identifier, wrong password,
  disabled account, corrupt stored hash, unparsable cost parameters, unknown/expired/revoked
  session, malformed token, zero rows updated on the session refresh. `aCorruptStoredHashFailsClosed`
  and `aDisabledAccountCannotLogIn…` cover two of those.
* Attempts are limited **per source and per account** (`ThrottleService`). The per-source limit is
  what actually stops credential stuffing, because it bites however many accounts the attacker
  spreads across; the per-account limit is the backstop against a distributed attack on one
  high-value account.
* **The per-account limit cannot be used to lock a legitimate user out.** It is a 15-minute sliding
  window, not a lock: it expires by itself with no administrator involved
  (`throttlesRepeatedFailuresForOneAccount` advances the clock and logs in), and the real user's own
  successful login clears it immediately (`aSuccessfulLoginClearsTheAccountCounter`). Registration
  is limited per *source only*, so an attacker cannot drain a victim's account budget by repeatedly
  "registering" their address (`anAttackerCannotBurnTheAccountCounterThroughRegistration`).
* Conversely, a successful login does **not** clear the source counter — otherwise an attacker
  holding one valid credential could launder their own budget between probes
  (`aSuccessfulLoginDoesNotResetTheSourceBudget`).
* A blocked attempt is not counted, so a blocked source stops feeding the account counter and that
  counter ages out. The throttle gate also runs *before* the Argon2 work, so a blocked caller cannot
  make the server spend 64 MiB and three passes per request.

### 4. Identifiers and tokens

* Session tokens are 32 bytes from `SecureRandom`, generated by `SessionService.issue` — never
  accepted from, chosen by, or derivable from the caller, and not a function of the account or the
  time. A caller-supplied value of the right shape resolves to nothing
  (`resolvesAValidSessionAndRejectsEverythingElse`), so there is no session fixation.
* Only `SHA-256(token)` is stored, so reading the database does not let you replay a session. The
  separate 16-byte `session_ref` is the non-secret handle used in logs and console output.
* `SessionCookie` emits `__Host-session=<token>; Path=/; Max-Age=…; HttpOnly; Secure;
  SameSite=Strict` — and no `Domain`. The `__Host-` prefix makes the browser itself enforce
  Secure + `Path=/` + no Domain, so a sibling subdomain cannot plant the cookie over plain HTTP. The
  cookie's own lifetime is never trusted: idle and absolute expiry are re-checked against the
  database on every request.
* This feature uses no externally provided identifier. The one externally influenced value is the
  **source identifier** used for rate limiting. It must be server-observed — the socket peer address
  for an HTTP front end, the local OS account for the CLI. If you ever source it from
  `X-Forwarded-For`, only do so behind a proxy that is the sole possible writer of that header;
  otherwise an attacker rotates the header and the per-source limit is worthless. `normalizeSourceId`
  bounds and sanitises it, and a missing value falls into one shared bucket rather than escaping
  rate limiting.

### 5. Sensitive data

* Logs carry `a***@example.com` and `a***(7)`, never a full address, never a password, never a
  token. Log records are forced onto one line so an injected newline cannot forge an entry.
* The log file is created *before* the handler opens it so its mode can be set to `0600`, and
  rotation count is deliberately 1 — a higher count would have `FileHandler` create its own
  `accounts.log.N` files under the process umask, i.e. world-readable.
* Every stored text column is length-bounded by a `CHECK` constraint; the log is capped at 1 MiB;
  the attempt table is pruned of expired windows on every write; the session table drops expired and
  revoked rows; the session-token file is not read if it exceeds 128 bytes; console input is read
  into fixed-size buffers with the overflow drained.
* Credentials live in `char[]`/`byte[]` and are zeroed in `finally` blocks (`Wipe`). The password is
  UTF-8 encoded through a `CharBuffer` so no unwipeable `String` copy is made, and the password
  policy checks run on char arrays rather than on `new String(password)`.
* Two residual exposures, accepted and noted rather than hidden: a password that is not already
  NFC-normalised takes a path through `java.text.Normalizer`, which only returns `String` (rare, and
  hand-rolling NFC would be worse); and `SessionCookie.setCookieHeader` necessarily returns a
  `String` containing the token, which the HTTP layer should write to the response and drop.

### 6. Failure behaviour

* Users get generic errors — "Invalid credentials.", "Too many attempts. Please try again later.",
  "Something went wrong. Please try again later." Reasons, stack traces and the duplicate/new
  distinction go to the `0600` log only.
* **No response reveals whether an account exists.** Registration returns the identical
  `ACCEPTED` status and identical wording whether the account was created or the email or username
  was already taken, and hashes the password on both paths before the insert so the elapsed time
  matches (`duplicateRegistrationIsIndistinguishableFromSuccess`). Login returns one
  `INVALID_CREDENTIALS` for unknown identifier, wrong password, disabled account and corrupt hash,
  and runs a full Argon2 verification against a decoy hash with the current parameters when there is
  no account to check, so the work done is comparable
  (`unknownAccountAndWrongPasswordAreIndistinguishable`). A password too malformed to prepare still
  burns one decoy verification. Both throttle scopes produce the same message, so which limit fired
  is not observable either. A reserved username is refused with the same "not available" wording a
  taken one would get.
* Invalid input is rejected, never coerced: an unknown CLI command exits 2 rather than guessing, an
  out-of-range configuration value aborts startup rather than snapping to a default, a non-SQLite
  JDBC URL is refused rather than attempted without its migration, and a stored hash with
  unsupported parameters fails verification rather than being honoured.
* The residual, unavoidable signal is the throttle status itself: being told "too many attempts"
  reveals that *this source* has been failing, which is the point of telling the user.

### 7. Concurrency

* `Database.inTransaction` opens each unit of work with `BEGIN IMMEDIATE` (via sqlite-jdbc's
  `transaction_mode` pragma), taking the write lock up front, with `busy_timeout=5000` and WAL.
* `ThrottleService.tryAcquire` is the whole check-then-act in one call inside that transaction:
  read the counters, decide, increment. Two concurrent logins cannot both observe "one attempt left"
  and both proceed.
* Account uniqueness is **not** a read followed by a write. `AccountRepository.insert` relies on the
  `UNIQUE` constraints and reports the constraint violation as "taken", so one of two simultaneous
  registrations for the same address loses deterministically.
  `concurrentRegistrationsForOneEmailCreateExactlyOneAccount` races eight threads and asserts one
  row.
* `SessionService.validate` checks revocation and both expiry timers and refreshes the idle timer in
  the same transaction, so a session cannot be revoked between the decision and the refresh; the
  refresh is itself guarded by `WHERE revoked = 0` and a row-count check.
* Session minting and the account-counter clear happen together in one transaction.

### 8. Prefer the platform

* Argon2id comes from Bouncy Castle's reviewed implementation; randomness from `SecureRandom`;
  digest comparison from `MessageDigest.isEqual` (constant-time); base64 from `java.util.Base64`;
  Unicode folding from `java.text.Normalizer`; password entry from `System.console().readPassword`;
  file modes from `java.nio.file.PosixFilePermissions`; atomicity and uniqueness from the database
  engine. The on-disk format is the standard PHC string, so other tools can verify these hashes.
* Nothing cryptographic is hand-rolled. The one algorithm not in the JDK is Argon2 itself, which is
  the sole reason a third-party dependency appears at all.

#### Dependency provenance

Pinned to exact versions from Maven Central over HTTPS, with `checksumPolicy=fail` and snapshots
disabled. No mirrors, no snapshot repositories, nothing loaded from a shared or world-writable
location, and no code fetched at runtime. Verified SHA-256 of the artifacts this was built and
tested against:

| Artifact | SHA-256 |
| --- | --- |
| `org.bouncycastle:bcprov-jdk18on:1.79` | `0d81ecc3124536b539bce9aa3fe9621b7f84c9cee371b635a5b31c78b79ab1da` |
| `org.xerial:sqlite-jdbc:3.47.1.0` | `4164d95347aeab42b754cabb7945b93e54f29ddb2eded967dbe979b4045cb685` |
| `org.slf4j:slf4j-nop:2.0.16` | `deca6c04ed35515a0a911fa44c0e836bee92c0c59d2e8fa9bab8ffbc464a9ba7` |

`slf4j-nop` is present only to bind sqlite-jdbc's logging to a no-op so the driver cannot write
anywhere unexpected. Check these before trusting a build:
`sha256sum ~/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.79/bcprov-jdk18on-1.79.jar`.

## Deliberate scope limits

These are design decisions, not oversights.

* **No email verification.** A real deployment must confirm ownership of the address before the
  account can do anything, and must keep the same enumeration-resistant wording when it does
  ("if that address was available, check your inbox").
* **No password reset or change.** `SessionService.revokeAllForAccount` is the intended hook: a
  password change must revoke every existing session.
* **Breached-password blocklist is a stub.** `InputValidator.BLOCKED_PASSWORDS` holds twenty common
  values. Wire it to a full list (e.g. a local Pwned Passwords SHA-1 range file, queried offline —
  not a live third-party API call carrying user passwords) before production.
* **The email local part is case-folded.** Strictly, `Alice@` and `alice@` are different mailboxes
  per RFC 5321. Folding is a deliberate product choice so users cannot create two accounts they
  cannot tell apart; it rules out the rare provider that is local-part case-sensitive.
* **The email allowlist is narrower than RFC 5322.** Quoted local parts, the rarer RFC
  punctuation (`!#$%&'*/=?^_` and friends) and internationalised (IDN/UTF-8) addresses are refused. Widening it means widening the allowlist
  explicitly, with tests.
* **SQLite only.** The schema is SQLite DDL. Another engine needs its own migration and its own
  `BEGIN IMMEDIATE` equivalent; `Config` refuses other JDBC URLs rather than pretending.
* **No HTTP layer.** `SessionCookie` is the contract for one. Such a layer must pass the socket peer
  address as the source identifier, add CSRF defences appropriate to its endpoints (`SameSite=Strict`
  covers a lot but not everything), and terminate TLS — `Secure` cookies are useless over plain HTTP.

## Tests

`mvn test` — 91 tests. Beyond the happy paths they assert the security properties above: that the
plaintext password appears nowhere under the data directory, that duplicate registration is
indistinguishable from success, that unknown-account and wrong-password are indistinguishable, that
SQL metacharacters are inert, that a tampered hash row with hostile cost parameters is refused, that
eight concurrent registrations produce one account, that both throttle scopes fire and that neither
can be turned into a lockout, that tokens are unpredictable and stored only as digests, that
revocation and both expiry timers work, that the attempt table holds only digests, and that the data
directory and database are owner-only.
