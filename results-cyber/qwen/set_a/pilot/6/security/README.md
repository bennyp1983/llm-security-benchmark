# Administrator Portal (Java 17)

Authenticates administrators, gates admin functionality behind a successful login, and records
**every** authentication attempt -- granted or denied -- in a reviewable, tamper-evident trail.

Pure JDK 17. No build tool, no dependencies, no network.

```
./build.sh test          # compile + run the verification suite (215 expectations)
./build.sh all           # ... plus the mutation battery (15 deliberate breakages)
bash demo.sh             # scripted end-to-end walkthrough
```

## Quick start

```bash
./build.sh

# First run: bootstrap the only administrator that can be created unauthenticated.
java -cp build adminportal.AdminPortal add-user alice
#   password for alice:            <- read with echo disabled (Console.readPassword)

# Sign in and reach the admin console.
java -cp build adminportal.AdminPortal login --user alice

# Review what has been recorded.
java -cp build adminportal.AdminPortal audit --user alice --summary
java -cp build adminportal.AdminPortal audit --user alice --failures-only --format json

# Prove the trail has not been edited.
java -cp build adminportal.AdminPortal verify-log
```

Data lives in `~/.admin-portal` (override with `--home DIR` or `$ADMIN_PORTAL_HOME`). Note that
`user.home` is resolved from the passwd database on this platform, so `HOME=...` alone will **not**
relocate it -- pass `--home`.

| File | Contents | Mode |
|---|---|---|
| `administrators.dat` | `username\|state\|pbkdf2$iters$salt$hash` | `0600` |
| `audit-log.jsonl` | one JSON audit record per line | `0600` |
| `audit-log.key` | HMAC-SHA256 trail signing key | `0600` |
| `lockout-state.dat` | failed-attempt counters and lockout deadlines | `0600` |

## Commands

`login`, `audit`, `verify-log`, `add-user`, `set-password`, `enable`, `disable`, `unlock`,
`accounts`. `--help` lists every flag.

Exit codes: **0** granted/completed, **1** access denied or tampering detected, **2** usage error.

Trust model:

- `add-user` is unauthenticated **only** while the store is empty (first-run bootstrap). Once one
  administrator exists, provisioning requires a valid login, and the record names who authorised it.
- `audit` is admin functionality: reviewing the trail requires a login and is itself recorded.
- `verify-log` only recomputes integrity seals and reveals no account data, so an operator or SIEM
  may run it unauthenticated.

## How the requirements are met

### Credentials are never recoverable

`PasswordHasher` uses PBKDF2-HMAC-SHA256, 16-byte random salt per password, 310,000 iterations
(OWASP 2023 guidance), 256-bit key. Verification uses `MessageDigest.isEqual`, so comparing digests
does not short-circuit on a shared prefix.

The cost parameter is stored inside the digest, so an old low-cost digest still verifies and is
**transparently re-derived** at the current cost on the next successful login (`password.rehash`).
`--iterations` below 1,000 is refused at construction rather than silently accepted.

Passwords travel as `char[]` and are zeroed in a `finally` by every caller. `PBEKeySpec` defensively
copies its input and clears that copy only at GC -- a JDK limitation, noted in the source rather
than papered over.

### Every attempt is recorded, and reviewable

`AuditLog.append` writes one JSON record per line:

```json
{"seq":"2","ts":"2026-09-05T10:38:48.75Z","event":"auth.login","outcome":"FAILURE","actor":"cli",
 "username":"alice","detail":"BAD_PASSWORD: password mismatch after 1 consecutive failure(s)",
 "prev":"MBbASnj...","key":"audit-log","hash":"2_kUZ5O..."}
```

`audit` filters by `--username`, `--event`, `--outcome`/`--failures-only`, `--limit`, renders a
table or JSON (`--format json` for a SIEM), writes to a file (`--out`), and aggregates with
`--summary` (totals, failure reasons, accounts with failures and their lockout state).

Integrity comes from a hash chain: each record's `hash` is HMAC-SHA256 over its canonical payload
**plus** the previous record's hash, sealed with a key in a separate file. Editing, reordering, or
deleting any record invalidates every seal after it; `verify-log` reports the offending `seq`.
Because the key is a separate file, an attacker who can write the log cannot forge a valid
continuation.

**Two properties are enforced rather than merely intended:**

- **Fail closed.** If a record cannot be written (disk full, path replaced by a directory), the
  login is *refused*. An unlogged success is treated as worse than a denied login. The seq counter
  advances only after `FileChannel.force(true)` returns, so no gap can be misread as a deleted
  record.
- **Exactly one record per attempt.** Covered by the suite, including the paths that deny before any
  credential work happens.

### Brute force is slowed, and the trail says so

Five consecutive failures lock an account for 10 minutes; twenty failures across all accounts trip a
30-second global backoff, so lockout cannot be used as a shield while an attacker sprays other
accounts. Counters and deadlines live in `lockout-state.dat` because a CLI portal starts a **new JVM
per login** -- in-memory counters would be wiped every attempt and lockout could be bypassed by
re-running the command. `testLockoutSurvivesNewProcess` and the demo's five-guesses-from-five-processes
step both pin this.

`unlock` itself requires a valid login, so a locked-out attacker cannot clear their own lockout;
break-glass is a *peer* administrator.

### Denials do not leak

Callers always see `Access denied.` -- unknown account, wrong password, disabled account, and audit
failure are indistinguishable on screen. The real reason goes only to the trail, where the reviewer
needs it. Unknown usernames still cost one full PBKDF2 run (`PasswordHasher.dummyEncoded()`), so
response time does not disclose whether an account exists; the suite asserts the known/unknown cost
ratio stays within 0.75-1.35.

> This constant was written as a hard-coded base64 literal first. Java's strict decoder rejected it,
> `verify()` bailed out early, and the unknown-user path returned in **0 ms against 156 ms** -- a
> textbook user-enumeration oracle that the surrounding code looked correct for. It is now *derived*
> by one real PBKDF2 run, and a test asserts the digest decodes and costs >= 3 ms, so the same class
> of bug cannot return silently.

### Log injection cannot forge a record

Untrusted values (usernames, `--actor`, filter strings) pass through `AuditEvent.sanitize`: CR/LF and
control bytes neutralised, length bounded to 200. A username cannot contain the account store's `|`
separator, and `USERNAME_PATTERN` restricts usernames to `[A-Za-z0-9][A-Za-z0-9._@-]{0,63}`, so a
crafted name cannot forge an account line or a second log line. The parser additionally rejects a
line with duplicate keys, so two records welded together cannot masquerade as one valid record.

## Verification

`./build.sh test` -- 215 expectations, ~11 s. Coverage: digest correctness, distinct salt per encode,
malformed/foreign digests rejected, corrupt store aborts load, grant/deny decisions, disabled and
locked accounts refuse even the *correct* password, transparent rehash, lockout, cross-process
lockout, global backoff, chain contiguity and reopen, six tamper scenarios, fail-closed, injection,
session expiry/revocation, filters, CLI subprocess end-to-end, credential-leak sweep, timing parity.

`python3 mutation-check.py` breaks one security property at a time in a throwaway tree and requires
the suite to go red. A mutation that survived would mean an uncovered property. All 15 are caught:
plaintext storage, unsalted hashing, low iteration count, lockout disabled, lockout made
per-process-only, unsealed trail, unlinked chain, fail-open on audit error, failures not recorded,
reason-disclosing denials, timing oracle, unsanitized fields, world-readable store,
login-on-disabled-account, unattributed admin actions.

## Threat model and limits (read before deploying)

- **Root can delete the trail.** The chain proves *modification*; it cannot prove the file still
  exists. Ship records off-host (`--format json` piped to syslog/SIEM) or the guarantee ends with the
  host.
- **Tail truncation is undetectable.** Removing the newest records breaks no later link. The suite
  asserts this explicitly as a known limit rather than glossing it. Detect it by comparing record
  counts / seq against an external collector, not by running `verify-log`.
- **Integrity is only as strong as the key.** `audit-log.key` is `0600`, which is honest for one
  host; anything stricter belongs in a KMS or HSM. `verifyWithKeys` supports rotation, and `verify()`
  flags a log that mixes key ids.
- **Same-uid attacker can reset lockout** by deleting `lockout-state.dat`. Defend against guessing and
  against casual tampering; pair with host-level rate limiting (fail2ban, ssh-guarded jump host) for
  a determined local attacker.
- **Local attack surface only.** No network listener exists, so TLS/CSRF do not apply. If this is ever
  wrapped in a service, add transport security, per-principal rate limiting, and session cookies with
  `HttpOnly`/`Secure`.
- **Single-factor.** No MFA/TOTP. The `admin:read` / `admin:write` / `audit:read` / `user:manage`
  privilege set is granted wholesale on success; real deployments should source it from a directory.
- **Sessions are in-process.** A CLI command authenticates, acts, and closes its session, so tokens
  are not reused across processes. Extending them across a long-lived service requires server-side
  session state, which does not exist here.
- **Clock skew.** Lockout deadlines are wall-clock seconds; NTP jumps can shorten or lengthen a
  lockout window.

## Layout

```
src/adminportal/
  AdminPortal.java          CLI, command dispatch, trust model per command
  AuthenticationService.java  auth decisions, lockout wiring, mandatory recording
  PasswordHasher.java       PBKDF2-HMAC-SHA256, constant-time verify, rehash detection
  AdminUserStore.java       0600 atomic account file, digest-only, strict username grammar
  AuditLog.java             append-only JSONL, HMAC hash chain, fail-closed writes
  AuditEvent.java           record + sanitisation + JSON encode/decode
  AuditReviewer.java        filters, table, summary, export
  LockoutStore.java         durable failed-attempt state
test/adminportal/AdminPortalTests.java   the suite
build.sh  demo.sh  mutation-check.py
```
