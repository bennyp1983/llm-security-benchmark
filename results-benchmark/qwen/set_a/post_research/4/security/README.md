# Account registration and sign-in (Java 17)

A command-line feature that registers an account from an email, a username and a password,
stores the credential in an SQL database, and authenticates against that stored state later.

```
scripts/build.sh          compile src/main/java into bin/ (jar digests verified first)
scripts/test.sh           compile everything and run all 12 test suites
scripts/run.sh <command>  run the feature: register | login | verify | logout | revoke-sessions
```

```
APP_DATA_DIR=/srv/portal APP_DB_PASSWORD_FILE=/etc/portal/db.pass scripts/run.sh register
```

`APP_DATA_DIR` is required. The database password comes from `APP_DB_PASSWORD` or from a
`0600` file named by `APP_DB_PASSWORD_FILE` - never from a default, never from argv, never from
a file this program created. `APP_ARGON2_MEMORY_KIB`, `APP_ARGON2_ITERATIONS` and
`APP_ARGON2_PARALLELISM` optionally raise the key-derivation cost and are each bounded to a
range the store can also hold; any value below the approved floor stops startup.

The last full run of the suite: **12 suites, 895 checks, 0 failed, `OVERALL: PASS`**. Every
number quoted below is read from that run's own `MEASURED` lines rather than from a comment.

---

## The eight rules, and where each one lives

### Rule 1 - Trust boundaries: validate every externally supplied value

`InputPolicy` is the only place an external value becomes an internal one.

| Input | Type / length / character / range checks |
|---|---|
| email | 1..254 chars, local part 1..64 from `[A-Za-z0-9._%+-]`, no leading/trailing/double dot, domain 2+ labels of 1..63 from `[A-Za-z0-9-]` not starting or ending in `-`, no address literal, TLD not all digits; exactly one `@`; no control chars, no unpaired surrogates, no leading/trailing whitespace; folded to lower case (the documented mailbox-equivalence rule) |
| username | 3..32 chars, must start `[a-z]`, alphabet `[a-z0-9-]`, may not end in `-`, 13 reserved names refused |
| password | 12..256 chars, at least one letter and one digit, no control/invisible chars, no unpaired surrogates, may not start or end with whitespace, may not contain the account's own name (case-insensitive) |
| session cookie | exactly 64 lower-case hex chars, checked structurally *before* any query touches the store |
| `--data-dir=<path>` | one argv element (a bare `--data-dir` is refused rather than swallowing the next token), no symlink in any component, not world-writable |
| `APP_*` env vars | integers parsed and range-checked against the same constants the hasher enforces; the password file must be a regular non-symlink file with no group/other access, <= 1 MiB |
| every free-text field | hard 4096-char cap applied **while reading bytes**, so an oversized line is never buffered whole |

There is deliberately **no `trim()`/`strip()` anywhere**: stripping turns `"user@corp.example "`
or a trailing tab into the real account and silently undoes every later check. Values are either
accepted exactly as supplied or refused. `InputPolicyTest` (108 checks) drives each rule from
both sides.

A value validated in one place is not *trusted* to decide a security question in another, and the
layers that re-check independently are named rather than implied:

- `SessionStore.resolve` and `SessionStore.revoke` each apply `isWellFormedToken` themselves, so
  an embedded caller cannot skip the shape check the CLI happens to perform, and the identity
  returned comes from the session row after re-confirming the account still exists - never from
  the token.
- `AuthService.login` validates the identifier and bounds the password length itself, so the
  key-derivation cost can never be steered by an unvalidated caller.
- `CookiePolicy` re-validates both the token and the path it is asked to emit, and throws rather
  than emit a cookie missing an attribute.
- `AccountStore` takes an already-canonical email/username, and the schema's `CHECK` constraints
  (below) are what stop a future caller that forgets to validate - a documented exception to the
  rule above, enforced in SQL rather than duplicated in Java.

SQL never sees a concatenation: every value is a bind parameter with an explicit type
(`setString`/`setLong`), and `SourceDisciplineTest` fails the build if any user-reachable value
is concatenated into SQL. The schema additionally repeats the character-class rules as
`CHECK ... REGEXP` constraints, so a future code path that forgets to validate still cannot
persist a newline in an email or the same mailbox spelled two ways.

### Rule 2 - Secrets: none baked in, config only, never printed

No password, key, salt or token appears in the source. `SourceDisciplineTest` (53 checks) scans
every shipped source file for credential-shaped literals and, separately, proves each of its
scanners reports a deliberately planted bad file - so an absence assertion cannot pass vacuously.

- **Not in argv.** The CLI accepts no credential as an argument; `register`, `login` and
  `revoke-sessions` prompt, and `verify`/`logout` *refuse* a cookie given as an operand because
  argv is readable in other users' process listings.
- **Not logged.** Nothing externally typed is ever passed to `AuditLog.record`; the only
  identity values that reach the trail are salted digests. The suite scans 24576 bytes of the
  store for 10 encodings of the passwords used and the post-run trail for every secret and
  identifier in play, and finds none in either.
- **Private.** `accounts.mv.db` and `audit.log` are created `0600`, their directory `0700`
  (asserted in `AccountStoreTest`/`ConfigTest`); H2 gets `TRACE_LEVEL_FILE=0` so it cannot write
  SQL text to a sidecar.
- **Erased.** Passwords live in `char[]`, are wiped in `finally` blocks, and `Secrets.toString()`
  returns `Secrets[redacted]`. The DB password is wiped as soon as the connection exists.

### Rule 3 - Authentication and access control: server-side state, fail closed, dual limits

Access is decided only by the database. `SessionStore.resolve` answers from a
`SELECT ... FOR UPDATE` of the session row, and `AuthService` verifies the credential against
the stored Argon2id string - a presented value is never an identity.

**Fail closed.** Every write to the trail goes through `Gate`, which throws on failure, and each
state-changing decision writes its own record *inside* the transaction that makes it -
registration, sign-in, session issue and session revoke all do - so an unwritable trail rolls the
change back rather than committing something no record accounts for. An attacker who replaces
`audit.log` with a directory, widens its mode, or symlinks it cannot make security events
unrecorded: the registration rolls back, the sign-in returns "unavailable", no session row is
committed and no revocation commits unrecorded. `AuditFailClosedTest` (52 checks) performs each of
those tamperings and then asserts *recovery*, because a guard that latches after one failure would
be a denial-of-service bug of its own. A malformed store, an unreadable config or an unexpected
`RuntimeException` all return a refusal exit code, never a pass.

**Limits per source *and* per account, so a limit cannot lock out a legitimate user.**

- per account: 5 failures inside a 900 s window lock for 900 s (`AuthServiceTest` measures
  exactly this);
- per source: 10 attempts per 300 s, a separate bucket namespace (`login-source:` /
  `register-source:`) that an account's own strikes cannot drain;
- the account counter decays, and a successful sign-in clears it, so knowing a colleague's email
  buys an attacker one window of denial, not permanent exclusion. Burning an account's five
  strikes costs the attacker five of their own ten source tokens.

Maintenance sweeps never reset a live limit: a bucket becomes eligible only once its whole
window has elapsed, and a guard row is deleted only when it is outside the retention window
*and* holds neither a live lock nor a live failure window (`MaintenanceTest` asserts a lockout
survives a sweep that retires its account).

### Rule 4 - Identifiers and tokens: CSPRNG, strict validation, cookie hardening

Session tokens are generated here: 32 bytes from `java.security.SecureRandom` rendered as 64
lower-case hex - **256 bits** measured - never derived from an account id, never accepted as an
input identity. Only the SHA-256 of the token is stored (`CHAR(64)` with a hex `CHECK`), so a
database dump yields no usable credential; because the input is uniformly random, an exact
indexed match needs no blind index. Lifetime is a hard `28800 s` with no sliding extension, so a
captured token expires.

Presented tokens are validated against the exact issued shape before any lookup, so a caller
cannot probe the shape of stored digests. `revoke-sessions` ends every live session of an
account, so a credential change cannot leave an issued bearer token valid.

Cookies carry `HttpOnly; Secure; SameSite=Strict` with an explicit `Path` and `Max-Age`/`Expires`
derived from the server-side expiry, never from a client value. `Secure` is unconditional -
there is no configuration that yields a cleartext cookie - and `CookiePolicy` throws rather than
emit a cookie missing any of the four attributes (`CookiePolicyTest`, 48 checks).

**Documented residual risk.** The per-source key is derived from the kernel effective uid
(`/proc/self/status`), because the JVM-visible `user.name` is forgeable with `-Duser.name=$RANDOM`.
Where the uid is unreadable the fallback is one *shared* bucket for the host, never a fresh one.
A deployment behind a gateway must supply an authenticated client/tenant key and validate it as
opaque `[A-Za-z0-9._:-]{1,64}` before using it as a bucket key, or one tenant can empty another's
bucket. See "Residual risks" below.

### Rule 5 - Sensitive data: masked in logs, private on disk, bounded, erased

- **Masked.** Trail records carry salted SHA-256 tags (16 hex chars, per-process random salt),
  never the email, username, account id, session token, or the token's stored digest. Records
  can be joined within one run; they cannot be joined back to rows, and two runs produce
  unrelated tags. The suite greps the post-incident trail for every secret used and finds none.
- **Private.** `0600` files, `0700` directory, symlink and non-regular-file components refused
  at startup; an over-open existing directory is tightened to `0700` or startup stops. The trail's
  own mode check is not trusted on its own: the single append passes `NOFOLLOW_LINKS` to `open`, so
  it is the kernel - not a `stat` a few instructions earlier - that refuses a trail swapped for a
  link, and the mode is fixed by the create attribute rather than a later `chmod`, which follows
  links. The append also cannot create, so a trail that disappears makes that one record fail
  closed instead of reappearing at the process umask.
- **Bounded.** Audit trail 67108864 bytes (64 MiB); fields capped while reading (4096);
  password <= 256 chars; credential column 100 chars - the exact width of the widest credential
  the accepted parameter range can produce (`m=1048576,t=20,p=8`), so storage can never refuse a
  legal stronger configuration; `sessions`, `throttle_bucket` and `auth_guard` are swept on every
  invocation (measured: 36 bucket rows -> 0, 8 guard rows -> 5 under a retention window of 5).
- **Erased.** See rule 2. Erasure is best-effort and the limits are stated below rather than
  overclaimed.

When the trail hits its budget it **retires** the oldest records instead of denying the feature -
anyone able to trigger refusals can fill a log, and a budget that refused would turn the audit
control into an outage for every later sign-in. The cut is marked twice: a `NOTE` on the
operator's terminal *and* a `TRAIL_RETURED` record written as the new trail's first line,
carrying the retired byte count, so a reader of the file alone can tell history was cut instead
of concluding nothing ever happened.

### Rule 6 - Failure behaviour: generic to the client, comparable work everywhere

Every sign-in failure - malformed input, unknown email, unknown username, wrong password,
account in its lockout window - prints the same sentence, `The email or password is not
correct.`, and every successful-or-failed path performs **exactly one** Argon2id derivation.
The unknown-account and locked-account branches derive against an internal random-salt dummy
hash, so neither wall-clock time nor peak memory names the branch; there is no sleep-based pad
that could drift out of step with the configured cost. Measured medians (microseconds):

```
malformed identifier 53583   unknown email 52760   unknown username 51758
wrong password       52474   locked account 51447  correct password 52357
slowest / fastest across the six paths: 1.04x
same six paths measured as CPU time: 51453 .. 52864 us (1.03x)
```

The equalising derivation runs *after* the transaction closes, never inside it, so padding does
not serialise concurrent requests behind the store lock. A throttled attempt prints the same
line as a wrong password; whether a lock caused the refusal is recorded in the trail, not in the
response. `register` prints one sentence for both `CREATED` and `DUPLICATE`, so it cannot
enumerate accounts; `revoke-sessions` prints `Sign-out is complete.` whether or not the account
exists. Config errors name the setting and the rule, never the value. Detail goes only to the
operator's terminal: an unexpected `RuntimeException` yields a generic line plus the exception's
one-line type, not a stack trace naming absolute paths and the dependency layout.

`logout` is the one place honesty beats uniformity, deliberately: `REVOKED` and
`NO_LIVE_SESSION` are worded identically so a caller cannot probe session ids, but if the store
could not confirm the revocation the CLI reports *unavailability* and withholds the `Max-Age=0`
cookie. Reporting a revocation that never happened is precisely the failure that leaves a
captured token live while its owner believes they signed out.

### Rule 7 - Concurrency: no check-then-act

- **Rate limiting is one statement.** `UPDATE throttle_bucket SET ... WHERE bucket_key = ? AND
  (refilled or current tokens) > 0`; the affected-row *count* is the decision, so N concurrent
  attempts cannot each observe the same token. Verified against H2 2.5.252.
- **Account strikes take a row lock.** `SELECT ... FROM auth_guard ... FOR UPDATE` inside the
  attempt transaction; two concurrent failures for one account serialise and a count cannot be
  lost. A first-time insert race is resolved by catching the unique violation and re-reading
  under the lock.
- **Duplicate accounts are decided by the unique constraint**, not by "select, then insert": the
  insert runs and a violation rolls the whole attempt back, budget included.
- **Password re-hash is guarded** by `WHERE id = ? AND password_updated_at = ?`, so a concurrent
  change wins and the upgrade is skipped rather than clobbering it.
- One transaction per attempt in a fixed lock order (`throttle_bucket`, `accounts`,
  `auth_guard`); `Db.inTransaction` is `synchronized`, confines the JDBC connection to one
  caller, rolls back completely on any failure including an unwritable audit record, and a lock
  wait over 2000 ms raises an error that callers translate into a refusal. The throttle consume
  and the work it protects commit together, so a failure cannot be charged to an account without
  the source budget also being spent.

### Rule 8 - Platform built-ins, pinned dependencies, no shared-directory code

`SecureRandom`, `MessageDigest`, `java.util.Base64`, `java.time`, `java.nio.file` POSIX
attributes and `Console.readPassword` do the cryptographic and I/O work. Third-party code is
three pinned jars, and `scripts/get-deps.sh` refuses any file whose SHA-256 differs from
`deps.lock`, requiring the same digest from two independent Maven Central distributors plus the
published SHA-1 before installing one. `bcprov` is additionally required to carry a verifiable
jar signature (`keytool -printcert -jarfile`), and every jar must contain the entry named in the
lock file, so a wrong artifact is a hard stop rather than a `ClassNotFoundException` later.
`build.sh`, `test.sh` and `run.sh` each invoke that verification first, so nothing compiles or
runs against an unverified jar:

| jar | version | role |
|---|---|---|
| `h2` | 2.5.252 | embedded SQL engine |
| `bcprov-jdk18on` | 1.82 (signed) | Argon2id primitive |
| `spring-security-crypto` | 6.5.11 | **test-only**: an independent oracle for the stored hash format |

Argon2id is used directly rather than through Spring's `Argon2PasswordEncoder`, for two reasons:
Spring's shipped defaults (`m=16384,t=2,p=1`) are *below* the OWASP Argon2id floor of
`m=19456,t=2,p=1` that this code enforces - the suite measures that refusal - and `matches()`
re-derives using whatever parameters a database row contains, letting stored data decide how
much memory this process allocates. Here, a stored credential must match a canonical PHC pattern
*and* fall inside the approved parameter range before any derivation happens; `MessageDigest.isEqual`
compares digests in constant time; non-canonical base64 spellings are rejected by re-encoding.

The program loads nothing from a world-writable location and spawns nothing - the classpath is
absolute in every script, and `SourceDisciplineTest` asserts both. `Config` refuses a data path
whose any component is a symlink and a data directory writable by other users.

---

## Password storage

`$argon2id$v=19$m=<KiB>,t=<iters>,p=<par>$<22-char salt>$<43-char hash>` - RFC 9106 Argon2id,
16-byte per-record CSPRNG salt, 32-byte tag.

| parameters | measured cost | note |
|---|---|---|
| `m=65536,t=3,p=1` | 572 ms | shipped default |
| `m=19456,t=2,p=1` | 115 ms | OWASP floor; below this, startup stops |
| `m=1048576,t=20,p=8` | - | widest accepted string: 100 chars, exactly the column width |
| `m=1048576,t=2` | 4749 ms | strongest legal registration still completes |

A credential stored below current policy is re-hashed on the next *successful* sign-in (a path
that already required the correct password) and the cost columns are read back out of the hash
string, so they cannot drift from the credential they describe. A hash that is malformed or
outside the range verifies `false` - indistinguishable from a wrong password, and neither grants
access.

---

## What the adversarial pass found, and what changed

Two independent security reviewers plus a test-quality audit were run against the code; each
finding below was fixed and then **mutation-verified**: the guard was removed, the suite was
re-run, and the checks that failed are named. A fix with no falsifier is a comment.

| finding | defect | fix | falsifier (checks that fail without it) |
|---|---|---|---|
| C-1 | `-Duser.name=$RANDOM` minted a fresh, full source budget per attempt, defeating the per-source limit for anyone able to exec the program | source key derives from the kernel effective uid; fallback is one shared bucket, never a fresh one | `CliTest`: 13 forged-name runs must produce `LOGIN_THROTTLED_SOURCE` (1 fails pre-fix) |
| H-1 | `logout` printed "Sign-out is complete." plus `Max-Age=0` even when the store never confirmed revocation - a captured token stays live while its owner believes otherwise. A related defect: the revocation record was written *after* the transaction committed, so an unwritable trail committed an unrecorded sign-out and reported it as confirmed | tri-state `LogoutStatus` - `UNAVAILABLE` reports unavailability and withholds the cookie; an operand-supplied cookie refuses without claiming anything; the `SESSION_REVOKED` record now lives *inside* the revoking transaction, so an unwritable trail rolls the revocation back and "unconfirmed" honestly means "nothing changed" | `CliTest`: operand refusal + token still live. `AuditFailClosedTest` `logoutNeedsTheTrail`: with the record moved back outside the transaction, 4 checks fail - the attempt is reported `REVOKED`, the session really is ended, and the trail claims a revocation it cannot back |
| M-1 | malformed sign-in input was free: a full derivation and an audit record per attempt, forever, never touching the limit meant to bound online work | the source budget is charged on the pre-store refusals too | `AuthServiceTest`: 13 malformed logins must serve exactly 10 and record throttling (3 fail pre-fix) |
| M-3 | a filled trail erased every `LOGIN_SUCCESS`/`ACCOUNT_LOCKED` ever written and left a file indistinguishable from one where nothing happened; the terminal `NOTE` was the only signal | `TRAIL_RETURED` marker written as the restarted trail's first line, with the retired byte count; one 64 MiB budget source (`Config`'s duplicate literal removed) | `AuditFailClosedTest`: first surviving line must be the marker (2 fail pre-fix) |
| M-4 | always submitting a taken mailbox forced a full Argon2id derivation plus a store write for free, every time - the rollback also undid the budget consume | the duplicate charge commits in its own transaction so it survives the rollback | `AccountStoreTest`: 12 duplicate registrations must exhaust a 10-token window and then recover (measured: 6 answered, 6 throttled) |
| self-found | the maintenance sweep deleted guard rows purely by account age, so registering enough accounts to push a target out of retention silently erased its lockout - a lockout-reset primitive | a guard is retired only when it holds no live lock and its failure window has decayed | `MaintenanceTest`: a live lockout on a retired account survives `purgeStaleState` and its `blocked_until` is unchanged (6 fail pre-fix) |
| L-1 (second pass) | the trail's own checks ran a few instructions *before* the write, and the write followed symbolic links: a trail swapped for a link inside that window sent security records to the intruder's file, and the `chmod` that re-tightened `0600` rewrote *that* file's mode. Their claim that the append re-creates a deleted trail at the umask mode was **disproved by measurement** - `Files.write(..., WRITE, APPEND)` without `CREATE` throws `NoSuchFileException`, and `guardFile()` re-creates a missing trail at `0600` - but the create-free form is now pinned for the same reason | the one append passes `NOFOLLOW_LINKS` to the open, so the kernel refuses the swap (measured: the link's target is left byte-identical, and a directory is refused too), and passes no `CREATE`; the mode comes from the create attribute, never from a later `chmod`; the size and mode reads are `NOFOLLOW` as well | `SourceDisciplineTest`: dropping `NOFOLLOW_LINKS` or restoring the `chmod` fails 2 checks, and the same section's positive controls prove the four predicates fire on a deliberately bad writer |
| L-3 (second pass) | the bucket sweep decided a row was dead from a constant, while the refill path reads `window_seconds` from the row - one migration, default or hand-edited row away from a sweep that deletes a budget the decision still regards as live, i.e. the same reset primitive again | the sweep uses the refill predicate against the row's own column, so the two readings cannot disagree | `MaintenanceTest`: a bucket widened to 3600 s and aged 400 s must survive the sweep and keep refusing (2 fail with the constant restored, including "the sweep did not hand the spent source back a fresh budget") |
| L-7 (second pass) | `revoke-sessions` recorded a malformed *operator* input as `REGISTRATION_REFUSED_INVALID_INPUT` - sending whoever reads the trail hunting for sign-ups that never happened - and its oversized-line branch recorded nothing at all | new `ADMIN_REVOKE_REFUSED_INVALID_INPUT`, written from both refusal branches | `CliTest`: the trail must contain the new event for the refused run and must contain no registration-refusal event anywhere in the section (2 fail with the old label) |

---

## Verification

```
scripts/test.sh          # 12 suites, 895 checks, 0 failed
```

| suite | checks | covers |
|---|---:|---|
| `InputPolicyTest` | 108 | every validation rule, both directions |
| `AuthServiceTest` | 118 | uniform failure, lockout budgets, source budget on malformed input, one derivation per path |
| `CliTest` | 106 | real piped runs of the binary: prompts, exit codes, operand refusal, forged-name budget, admin-refusal trail label |
| `AccountStoreTest` | 98 | registration, duplicate handling, secret-free store, upgrade race guard |
| `PasswordHasherTest` | 98 | PHC format, parameter bounds, canonical base64, Spring-oracle cross-check |
| `MaintenanceTest` | 74 | sweeps that never reset a live limit, lockout survival, sweep bounded by the row's own window |
| `ConfigTest` | 60 | env/argv validation, password-file rules, directory and store modes |
| `AuditFailClosedTest` | 52 | tamper-then-refuse-then-recover for registration, sign-in *and* sign-out; budget retirement with in-trail marker |
| `SessionStoreTest` | 53 | issuance, resolution, expiry, revocation scoping, tag-only trail |
| `SourceDisciplineTest` | 53 | no baked secrets, no SQL concatenation, no credential sink, no shared-dir loading, trail writes that cannot be misdirected |
| `CookiePolicyTest` | 48 | attribute completeness, path validation, token shape |
| `SchemaBoundsTest` | 27 | column width and CHECK bounds vs the accepted parameter range |

Tests are plain `main()` classes - no test framework is on the classpath - with per-process
scratch directories cleaned by a shutdown hook, a `MutableClock` for window arithmetic, and
fresh fixtures per section so one suite cannot contaminate another. `scripts/test.sh` verifies
jar digests before compiling and compiles `src/main/java` under `-Xlint:all -Werror`.
`scripts/run.sh` rebuilds when any source file is newer than `bin/app/Main.class`, so a stale
artifact cannot be run by accident - verified by hand: `touch src/main/java/app/Main.java` makes
the next `scripts/run.sh` print `built`, and the run after that does not. The jars need no such
timestamp test because `get-deps.sh` compares each digest against `deps.lock` first.

---

## Residual risks (deliberate, and what would remove them)

1. **Per-source identity is host-local.** With no network layer, the only honest source key is
   the OS user. Anyone who can already exec the program *as another user* gets another budget;
   the fallback when the uid is unreadable is a shared bucket, which can be exhausted but not
   reset. Behind a gateway, supply and validate an authenticated tenant key (rule 4) - until then
   the per-source limit is a *per-local-user* limit.
2. **`char[]` erasure is best-effort.** The JVM copies `char[]` and `String` internally and Bouncy
   Castle keeps internal blocks this code cannot reach, so a heap dump can still recover a
   credential. The one unavoidable `String` hand-off is JDBC's `Properties` for the DB password.
3. **Cost-rotation timing window.** Equal-cost is exact per branch *at one cost*. During an
   operator-led raise, an account whose stored hash is below policy verifies faster than the dummy
   derivation, so its wrong-password answer differs from an unknown-account answer by about the gap
   between the two costs (at the fixture's floor against the shipped default, 115 ms against 572
   ms). Adding the missing work where a reviewer would put it - one more derivation at policy cost
   on the mismatch branch - does not close it: that branch then costs `stored + policy` against
   `policy`, still a gap; and if the same pad goes on the unknown-account branch too, the
   correct-password and wrong-password answers for the *same* account end up `policy` apart, trading
   the disclosure that matters least for the one that matters most. A verification must derive at the
   parameters the credential records, so no number of extra derivations equalises two different
   costs. What closes it is a wall-clock pad (rejected: it drifts out of step with the configured
   cost) or re-hashing the population before raising the floor. Steady state is equalised (1.04x
   across all six paths), and every successful sign-in on such a row re-hashes it at policy, so the
   window closes itself as users return.
4. **`revoke-sessions` is unauthenticated by design.** It is an operator action; anyone able to
   run the binary already owns the data directory and the database password. Wrap it in a
   privileged account or an approver before exposing it.
5. **Registration answers `CREATED` and `DUPLICATE` identically.** That is a deliberate deviation
   at the endpoint where "already taken" is legitimate feedback; the disclosure is only that a
   mailbox exists, which is equally learnable from sign-in. Sign-in, where the rule matters, is
   uniform.
6. **A full audit trail retires rather than denies.** Availability of the feature is ranked above
   retaining the whole trail; the cut is marked in-trail and quantified. Ship the trail to a
   collector if you need append-only history.
7. **An unexpected `Error` is not caught**, and a caught `RuntimeException` prints its class name.
   Access is still refused; only the class name is exposed. Map it to a correlation id if even
   that is too much for your threat model.
8. **H2 sidecars.** `accounts.trace.db` is not pre-guarded to `0600` because `TRACE_LEVEL_FILE=0`
   keeps H2 from creating it; if an operator re-enables tracing, inspect that file before it
   inherits a umask default.
9. **`auth_guard.window_seconds` / `max_failures` are recorded, not re-read.** The effective
   per-account policy is the constants in `Throttle`, and both the decision and the sweep use those
   constants, so the two agree; the columns document what a row was created under. A future
   operator-tunable policy must read them instead of writing them. The per-source table is already
   column-driven on both paths - the refill and the sweep both read `window_seconds` - which is what
   makes a widened window safe there.
