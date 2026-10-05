# Authentication component (`com.example.auth`)

Username/password sign-in plus an append-only authentication event log. Java 17, zero third-party
dependencies, no build tool required.

Scope is deliberately narrow: **verify a credential, issue a session identifier, record the
attempt.** There is no sign-up, no password reset, no role or permission model, no admin endpoint,
no metrics or health endpoint. The service exposes no way to create or modify a credential record;
provisioning is out of band (see [Provisioning](#provisioning)).

---

## Build and test

```sh
JAVAC=/opt/jdk17/bin/javac      # any JDK 17+
JAVA=/opt/jdk17/bin/java

$JAVAC -Xlint:all -Werror -d out/main $(find src/main/java -name '*.java')
$JAVAC -Xlint:all -Werror -d out/test -cp out/main $(find src/test/java -name '*.java')

for c in Suite1Validation Suite2LoginBehavior Suite3Latency Suite4AuditDurability Suite5Concurrency; do
  $JAVA -cp out/main:out/test "com.example.auth.$c"
done
```

Both trees compile clean under `-Xlint:all -Werror`. Each suite prints `PASS`/`FAIL` per check and a
final `SUMMARY <name> passed=N failed=0` line; a nonzero exit status means at least one failure.
Suites are independent and use pid-scoped scratch directories under `$TMPDIR`, so they can run in any
order. Run them sequentially: suite 3 measures timing, and a concurrently loaded machine can make its
assertions flap for reasons unrelated to the code.

## Using it

```java
AuthConfig config = AuthConfig.fromEnvironment(TimeSource.systemUtc());  // or AuthConfig.builder()...build()
try (AuthenticationService service = AuthenticationService.builder()
        .config(config)
        .build()) {

    List<String> problems = service.selfCheck();            // operator-visible degradation
    char[] password = request.password();                   // caller owns this array
    try {
        AuthResult result = service.authenticate(
                AuthenticationService.Attempt.of(request.username(), password, request.peerAddress()));
        if (result.isSuccess()) {
            response.setHeader("Set-Cookie",
                    service.sessionCookieFor(result, "auth-session", "/app", request.isTls()));
        } else {
            response.setStatus(result.retryAfterSeconds() > 0 ? 429 : 401);
            renderToUser(result.message());                 // identical for every credential failure
        }
    } finally {
        java.util.Arrays.fill(password, (char) 0);           // required
    }
}
```

`Attempt.of` takes the password as a `char[]` precisely so the caller can erase it; the service makes
its own copy, wipes that copy after encoding to UTF-8, and wipes the UTF-8 bytes in a `finally` block.
`AuthResult.toString()` and `Attempt.toString()` never render a password or an identifier.

The peer address must be the transport's actual peer address. **Never pass an `X-Forwarded-For` value
here** unless a proxy you control set it; the per-source budget is only as trustworthy as that string.

---

## Configuration

`AuthConfig.fromEnvironment(TimeSource)` reads these keys. **Every one of them is required**: there is
no key this component will silently supply a value for, because a missing throttle or session limit
must stop startup rather than become an accidental default. Anything missing, malformed, out of range,
or pointing at a file whose permissions would expose credential material stops startup with
`InvalidConfigException`. Problem strings name keys and fixed reasons only — never a configured value,
so the keystore password cannot reach a log or a terminal through an error path.

The only values that ever have a default are the ones you set explicitly through
`AuthConfig.builder()`; that column below is what the builder starts from before you override it, not
something the environment path will fall back to.

| Key | Bounds | Builder starting value | Notes |
|---|---|---|---|
| `AUTH_ACCOUNTS_FILE` | absolute path, regular file, 0600 | — | |
| `AUTH_EVENT_LOG_FILE` | absolute path; parent dir must not be other-writable | — | |
| `AUTH_KEYSTORE_FILE` | absolute path, 0600, `.jceks`/`.p12`/`.pfx`/`.jks` | — | type taken from the suffix |
| `AUTH_KEYSTORE_PASSWORD` | 1–512 chars | — | never stored in the built config |
| `AUTH_PASSWORD_ENTRY_ALIAS` | `[A-Za-z0-9._-]{1,128}` | — | must name a `SecretKeyEntry` ≥ 16 bytes |
| `AUTH_PBKDF2_ITERATIONS` | **120 000** (hard floor) – 5 000 000 | 120 000 | the floor is compiled in, not configurable; also the **ceiling** on any stored record's count |
| `AUTH_MIN_ACCEPTED_ITERATIONS` | 10 000 – 10 000 000 | 50 000 | per-record floor, for later upgrades; must be ≤ `AUTH_PBKDF2_ITERATIONS` |
| `AUTH_ACCOUNT_LOCK_AFTER` | 3 – 100 | 5 | consecutive failures |
| `AUTH_ACCOUNT_LOCK_SECONDS` | 60 – 3600 | 300 | |
| `AUTH_SOURCE_WINDOW_SECONDS` | 60 – 3600 | 300 | |
| `AUTH_SOURCE_MAX_ATTEMPTS` | 10 – 1000 | 60 | must be ≥ `AUTH_ACCOUNT_LOCK_AFTER` |
| `AUTH_SOURCE_BLOCK_SECONDS` | 60 – 1800 | 300 | |
| `AUTH_SESSION_TTL_SECONDS` | 300 – 86400 | 1800 | sliding |
| `AUTH_MAX_ACTIVE_SESSIONS` | 16 – 100 000 | 10 000 | |
| `AUTH_MAX_EVENTS` | 100 – 200 000 | 10 000 | in-memory ring only; the file itself stops growing at a 64 MiB ceiling |
| `AUTH_MIN_FREE_BYTES` | ≥ 1 MiB | 16 MiB | |

`AuthConfig.build()` enforces two rules that relate one setting to another, and
`fromEnvironment` constructs its config **through `build()`** rather than through the constructor, so
neither is skippable by a deployment that writes the numbers into the environment:

* `sourceMaxAttempts ≥ accountLockAfter`. That rule is the one that keeps a single attacker with one
  known username from spending a whole shared NAT address's budget: with the account lock firing
  first, per-source traffic from a targeted attack stays inside the source budget. Sizing for a
  deployment behind shared egress addresses: set `AUTH_SOURCE_MAX_ATTEMPTS` to roughly
  `accountLockAfter × (legitimate accounts per address) × 3`, and keep it well above
  `AUTH_ACCOUNT_LOCK_AFTER`.
* `pbkdf2Iterations ≥ minAcceptedIterations`, and a stored record's own count must fall inside
  `[minAcceptedIterations, pbkdf2Iterations]`. The upper half is what stops a credential file from
  ordering this process to do arbitrary work per sign-in — see
  [rule 6](#6-failure-behaviour--generic-user-errors-detail-only-in-the-log-never-reveal-whether-an-account-exists-never-a-permissive-default).

---

## Rule-by-rule

### 1. Trust boundaries — validate every input before use; never let an unvalidated value decide a security outcome

Every string that arrives from a client, a file, or the environment is validated before it influences
a decision, a log field, or a filesystem path.

| Input | Validation (`InputValidator`) |
|---|---|
| username | 2–64 code points; no code point ≤ U+0020 or U+007F; must start with a letter, digit or `_`; must end with a letter or digit; `..` refused; rejects `NUL`, tab, CR, LF, and terminal escapes by the same rule |
| password | control-character scan **first** (any `c < U+0021` or `U+007F` is refused, including an all-NUL buffer), then 10–256 code points, then an encode with `CodingErrorAction.REPORT`, so a value the platform cannot represent byte-for-byte is refused instead of substituted |
| source address | ≤ 45 chars, no `%` scope id, no `/`, `@`, `#`, whitespace; strict dotted-quad (leading zeros refused, including in the last octet) or a hex/colon v6 form; resolved and returned in **one canonical form**, so one host always maps to one budget bucket |
| credential file | size ≤ 8 MiB **before** it is read, ≤ 20 000 records, ≤ 512 chars/line, exactly 4 colon-separated fields, name re-validated, salt and digest must be *canonical* Base64 (re-encoding must reproduce the text), iteration count accepted only as plain `0-9` digits with no leading zero or `+`, and inside `[minAcceptedIterations, pbkdf2Iterations]` |
| keystore path / alias / passwords | absolute regular file checked without following symlinks, not group- or other-accessible, type from an allow-listed suffix (no `file:`/jar/ZIP URL resolution), alias matched against an explicit character class and required to exist as a `SecretKeyEntry` |
| config keys | a key name outside `[A-Z0-9_]` is reported as "an unsupported configuration key" rather than echoed, so a hostile environment name cannot become a terminal-control or log-injection vector |

Two details are load-bearing rather than pedantic:

* **UTF-8 exactness.** `String.getBytes(UTF_8)` never throws — it folds unencodable code points to
  `?`. Without the round-trip check, `"café"` and `"caf?"` would hash identically and a
  constant-time comparison would report a match. Such passwords are refused with a diagnostic, not
  silently folded.
* **Canonical Base64.** `Base64.getDecoder()` accepts non-canonical tail bits, so two different texts
  can decode to the same bytes. A record could then be presented in a form that no longer matches what
  a reviewer sees in the file. Non-canonical salt *or* digest text refuses the whole store.

Unvalidated values never reach a decision path: `authenticate` normalises the source address and
refuses the attempt (`SOURCE_REQUIRED_MESSAGE`, distinct event type, zero credential work) if it is not
a canonical literal.

### 2. Secrets — none in code, never printed, logged, in argv, or in error messages or files readable by others

* No credential, key, or password appears in source. The pepper comes from a password-protected
  keystore entry at runtime; `AuthConfig.eraseSecrets()` wipes the keystore password from the built
  config before the service is constructed, and the probe that validates the keystore uses
  throw-away copies.
* Nothing writes a secret to stdout/stderr. `Attempt.toString()` reports only
  `Attempt[source=set]`; `AuthResult.toString()` omits the session identifier.
* `AuthException`, `AuditPersistenceException` and `InvalidConfigException` carry a
  [`Diagnostic`](src/main/java/com/example/auth/Diagnostic.java) category or a key name — never a
  message, never a path, never a value. Their causes are deliberately suppressed, because the JDK's
  own `IOException` and keystore exception messages quote the file path.
* Every file this component touches is owner-only, and the check **fails closed**.
  [`PosixMode`](src/main/java/com/example/auth/PosixMode.java) is the only place that asks what a mode
  is, and when a file system cannot answer — CIFS/SMB/vfat, some FUSE and overlay mounts, an entry that
  vanished between the `stat` and the read — every predicate answers *exposed*, never *safe*. Reporting
  "safe" there would make an unreadable file system the one configuration where rule 2 is silently
  dropped, which is worse than refusing to start because it looks like it passed. Concretely: the log is
  created with `CREATE_NEW` plus an explicit 0600 `FileAttribute` and the resulting permissions are read
  back and must be **exactly** `rw-------`; the mode is re-verified before *every* write, so a `chmod`
  by another process stops the trail immediately rather than at the next reopen; and the credential
  file, the keystore, the log file and the log's parent directory are all refused when group or other
  hold any access bit (write bit, for the directory — a writable directory defeats every check made
  against the file inside it). Suite 1 drives all three predicates into the unreadable branch with a
  path that cannot be `stat`ed and asserts each answers "exposed"; suite 4 refuses a loose target
  through the logger's own `open`, loosens the mode under a live handle, and refuses to write into a
  replaced inode.
* The log never contains a password (in any form), the digest, the salt, the pepper, the keystore
  path, the whole session identifier, or the username. Suite 4 reads the real log file after logging
  in with three different accounts and asserts the absence of all of those, including the salt and
  digest text taken from the credential file itself.
* Identifiers handed to a caller leave the process only through the `Set-Cookie` helper, which is
  `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, and `Max-Age`-bounded to the session TTL. It
  returns `null` rather than emitting a cookie for a plaintext request.

### 3. Authentication and access — verify against server-side state, fail closed, limit per source *and* per account without locking out a legitimate user

* **Server-side state only.** A credential is checked against the loaded record store; a session is
  valid only if present in this process's token table. Nothing is accepted from the caller as proof of
  identity: no self-contained token, no `Authorization` payload, no client-supplied session id.
* **Fail closed, in this order:** unusable source → refused; unwritable log → refused; unreadable or
  inconsistent store → refuses to start; exhausted throttle table → refused (`BLOCKED`, not
  "untracked", because an untracked key is an unlimited key); session capacity exhausted → refused;
  permit starvation → refused after 2 s.
* **Two independent budgets**, both applied to the same attempt:
  * *per source* — a sliding window consumed **before any credential work**, so an attacker cannot
    buy a PBKDF2 round per attempt beyond their budget;
  * *per account* — a consecutive-failure lock, read-only at check time.
* **The limit cannot be used against a legitimate user**, by four separate mechanisms:
  1. the per-account budget only ever counts failures against *that* account, so a flood of other
     usernames cannot consume it;
  2. the per-source budget is configured (and validated) to be at least `accountLockAfter`, so one
     targeted account cannot exhaust a shared address's budget — and the sizing rule above is stated
     for shared egress;
  3. a verified sign-in **clears** the failure state, so an attacker cannot hold an account locked by
     generating failures around the owner's logins;
  4. probing a locked account does **not** extend its lock — `checkAccountLock` consumes nothing and
     `recordAccountFailure` on an already-locked bucket leaves `blockedUntilMillis` alone. Verified in
     suite 5: a lock formed at `t` still holds at `t+599 s` and has expired at `t+601 s` no matter how
     many failures were attempted in between.
* Keyed on the ASCII-case-folded **submitted** name, not a resolved record. The store refuses to load
  if two records differ only by ASCII case, so folding cannot merge two accounts; only ASCII case is
  folded, so a Unicode look-alike (`al` + `U+00C9` + `ce`) cannot be used to lock out a real account.
* Table sizes are capped at 20 000 keys each, with an idle sweep; a full table refuses new keys.
  Idle stamps older than any legal window are pruned, so an attacker cannot make the process retain
  one timestamp per attempt per address indefinitely.

### 4. Identifiers and tokens — CSPRNG, never accepted from callers, strictly validated, cookies flagged

* 32 lower-case hex characters = 128 bits from `SecureRandom.getStrongInstance()`, generated at the
  moment a sign-in verifies. No counter, timestamp, MAC address, or account-derived material is
  involved, and no identifier is ever derived from caller input.
* Validity is presence in a server-side table. A syntactically perfect but unknown identifier is
  simply not valid, and because nothing is parsed there is nothing to forge. Lookup is exact: an
  uppercase identifier is refused rather than case-folded, and `null`/wrong-length inputs are refused
  before the map is touched.
* Sliding TTL, bounded table (`AUTH_MAX_ACTIVE_SESSIONS`). Under table pressure the oldest-expiring
  entry is evicted **only if it is at least one second old**; if nothing can be reclaimed the service
  **refuses to issue** and the sign-in fails, rather than dropping a live user's session to make room.
* An identifier that was issued but never handed to a caller is revoked in the same `finally` that
  wipes the password. Without that, a success whose event failed to persist would leave a live
  credential that authenticates as that account, was never reported as issued, and nothing downstream
  knows to sign out.
* Residual risk from externally supplied identifiers, stated plainly: the caller (the HTTP layer) is
  what reads an identifier back from a cookie. This component cannot see that request, so it documents
  the obligations below and provides the `Set-Cookie` builder that makes the flags hard to forget. It
  still validates any identifier presented to `isSessionValid` by exact table lookup.

### 5. Sensitive data — mask in logs, owner-private files, bounded stored size, clear credentials from memory

Log line grammar, and nothing else is writable:

```
seq=<n> ts=<ISO-8601 microsecond UTC> type=<login_success|login_failure|login_throttled|login_rejected_no_source|security_alert>
account_id=<sha256(name)> account_hint=<0..32> account_present=<true|false>
outcome=<success|failure|blocked|error>[ source=<canonical address>][ reason=<diagnostic>]
latency_us=<n>[ retry_after=<n>][ session=<first 6 hex>]
```

* There is no free-text field and no exception message is ever placed in an event, so no
  client-supplied string can contribute a newline, a forged second record, or a terminal escape. The
  account is a SHA-256 of the lower-cased submitted name plus a saturating distinct-code-point count;
  the name itself is never written.
* `AuthEvent.renderOrReject` is the last gate: a source that is not already in canonical form, a
  session suffix that is not six hex characters, a control character, an over-long line, or an
  out-of-range numeric field **refuses the entire event**. Dropping the offending field and writing
  the rest would record a success whose evidence was thrown away, so the event becomes a
  `security_alert` instead — one that keeps the account attribution the rejected event had already
  computed, so the attempt is still attributable.
* Suite 4 feeds names containing CR, LF, `seq=… type=login_success`, and an ANSI escape through the
  real endpoint and asserts that every line written still matches the whole-line grammar, that the
  hostile text appears nowhere, and that each attack is still recorded as an attributed failure.
* Bounded storage: in-memory ring at `AUTH_MAX_EVENTS`; line length capped at 320 characters; the
  credential file is size- and record-bounded before it is read; the log directory's free space is
  re-checked periodically (and re-armed after any failed write) and the service refuses attempts below
  the floor. The log file itself has a **64 MiB ceiling**, checked before each write: past it the logger
  refuses with `LOG_FILE_LIMIT` and the file stops within one record of the bound rather than growing
  until it fills the file system — filling it would trip the free-space floor and refuse every login for
  every user. Reviewing the trail reads back only the last 4 MiB, so a status call cannot become a heap
  incident. What the logger never does is *truncate history to make room*: an audit trail that silently
  deletes its own events is worse than one that fills up and refuses. Rotation stays an operator duty
  (see [Log rotation](#log-rotation)).
* **A record boundary is never spliced.** If the file ends in a partial record — a write interrupted by
  a full disk, a killed process, or a short `write` — the logger truncates that fragment away before
  appending anything, on both `open` and the reopen-after-a-failure path, and reports the discarded byte
  count as its own `security_alert` (`reason=log_partial_record`). An append-only writer that left the
  fragment in place would splice the *next* event onto it: the newer attempt would vanish from the trail
  and the surviving line would describe an attempt that never happened. Removing bytes from an audit file
  is itself evidence-relevant, which is why the repair is logged and counted
  (`discardedTornBytes()`) rather than done quietly; a tail that cannot be repaired stops writes instead
  of building a corrupted record on top of it.
* Credential clearing: the password `char[]` copy is wiped as soon as it is encoded, the UTF-8 `byte[]`
  is wiped in `finally` on every path, and the pepper is wiped from config after the hasher is built.
  `PasswordHasher.erase()` zeroes the pepper copy on `close()`.

### 6. Failure behaviour — generic user errors, detail only in the log, never reveal whether an account exists, never a permissive default

* One message for every credential failure: `"Invalid username or password."` Suite 2 drives seven
  distinct denial shapes (wrong password, absent account, malformed name, name with CR, too-short
  password, password with a tab, password with an unpaired surrogate) and asserts the rendered
  message set has exactly one member. A refusal that is about the *transport* uses a different,
  equally contentless text (`"Authentication is not available for this request."`) and never
  mentions passwords, so it cannot be read as an account statement either.
* **Comparable work**, measured rather than asserted. Every credential path performs exactly one full
  PBKDF2 derivation — including the malformed-name and unknown-name paths, which derive against
  server-generated decoy parameters — and every outcome is then held to a common latency floor
  (`LatencyBudget`), derived from a measurement of a real derivation on the running machine times 1.35,
  clamped to [250 ms, 4 s]. Suite 3 interleaves six paths and asserts, in microseconds:
  * whole-path wall-clock spread across all six ≤ 1.45× (measured **1.09×**);
  * an absolute wall-clock floor on every path, so deleting the work from all six paths cannot pass;
  * a `ThreadMXBean` **CPU** floor on the four deriving paths, which parking cannot fake — padding
    burns wall time and no CPU (measured CPU spread **1.01×**);
  * and, so the design's own claim stays honest, that the two shape-refusing paths burn *less* than the
    CPU floor, because their defence is the latency floor, not equal work.
* The attempt that *trips* a lock returns the plain denial with **no** retry hint, so the moment a
  lock forms is not observable in the response. The hint only appears on a later attempt that was
  refused by an already-engaged lock.
* Nothing reveals existence in the log-to-client direction either: the log is a file the caller cannot
  read, `selfCheck()` is an operator API, and `Diagnostic` categories never reach `AuthResult`.
* `WORK_UNAVAILABLE` (permit starvation) uses the same user-visible denial. It is logged distinctly,
  and it does not latch: permits are released in `finally`, and the next attempt proceeds.
* **An audit outage never locks a legitimate user out.** When the event cannot be persisted the
  attempt is refused and its session is withdrawn, but nothing is charged to the account: the wrong
  password that reached that path was already charged by the mismatch branch, while a *correct*
  password refused only because the log is broken would otherwise convert the owner's own sign-ins
  into consecutive failures — and after `accountLockAfter` of them a full file system or a
  mis-rotated log would lock every account that tried to sign in. Rule 3 forbids exactly that. The
  attacker still pays: the per-source budget is consumed before any credential work, so an outage is
  not a window of free guessing. Suite 2 asserts three separate claims about it: five correct
  passwords during an outage leave the account unlocked and succeed the moment the log returns;
  three wrong ones during the same outage still trip the lock and still spend the source budget; and
  the mismatch attempts made while the log was broken are counted *once* each — `accountLockAfter -
  1` of them must leave the next wrong password a plain denial rather than an early lock, so the
  outage catch cannot quietly double every streak.
* The work factor a credential record may ask for is bounded by the deployment's own configured
  count (`[minAcceptedIterations, pbkdf2Iterations]`), enforced twice: the store refuses such a
  record at load time, naming the line, and `PasswordHasher.derive` refuses one even if it arrives
  by another route. Without the ceiling, one record in a file could order the parser's 10 000
  000-iteration maximum against the 120 000-iteration floor every other account pays — over eighty
  times the CPU and delay on demand, which is both an account-existence oracle that survives the
  equal-work design and a cheap way to hold all four work permits.
* There is no permissive default anywhere in the failure paths. When even the alert cannot be written,
  the attempt is refused.

### 7. Concurrency — check-then-act must be atomic

* Every throttle verdict is produced **inside** a single `ConcurrentHashMap.compute` call, which the
  map runs atomically for that key. There is no read-count/decide/write-back window in which two
  concurrent failures could both see "one below the limit". `synchronized (bucket)` protects the
  bucket's fields; the decision itself never happens outside `compute`, and no lock is ever held
  across the credential check.
* Session issue/validate/revoke/capacity all happen under one monitor on the map, and expired entries
  are dropped inside the same critical section as a validation, so an expired session cannot be
  validated by one thread while another touches it.
* Audit writes hold one monitor for "render with the next sequence number, write, fsync, commit the
  counter", so two attempts cannot claim the same sequence, and the counter only advances if the bytes
  and `force(false)` succeeded.
* Suite 5 reconciles totals exactly where a lost update must change a total: 8 threads × 5 attempts
  against a shared budget of 40 admits **exactly 40**; a per-account race with `lockAfter=7` admits
  exactly `lockAfter − 1`; 8 threads issuing against a cap of 64 produce 64 distinct live identifiers;
  8 concurrent attempts produce 8 log lines with 8 distinct sequence numbers.
* Where a race would expose a defect only *sometimes*, racing threads proves nothing — the same test
  passes most runs for broken code. Those properties are checked by driving the fixed orders a broken
  implementation gets wrong (a 3-failure sequence, a reset-then-3-failures sequence, case-folded
  variants, an attempt at a lock expiry boundary from both sides) **plus** a comment-stripped
  source-text guard: the failure path must contain `accounts.compute(` and `consecutiveFailures++`,
  must contain no `accounts.get(`/`accounts.put(`, and `checkAccountLock` must contain neither
  `accounts.compute(` nor `consecutiveFailures++`.

### 8. Prefer built-in platform mechanisms

Everything security-relevant is JDK: `PBKDF2WithHmacSHA256` via `SecretKeyFactory`,
`SecureRandom.getStrongInstance()`, `MessageDigest.isEqual` for constant-time digest comparison,
`MessageDigest` (SHA-256) for the account identifier, `java.nio.file` with `PosixFilePermission` and
`BasicFileAttributes.fileKey()`, `FileChannel` with `force(false)`, `java.util.Base64`,
`KeyStore`/`SecretKeyEntry` for the pepper, `java.time` for timestamps, `Semaphore` for the work cap,
`ConcurrentHashMap` for throttle state. There are no third-party jars, so there are no downloads to
verify and no versions to pin — which is the preferred answer for this component's needs.

If a dependency ever becomes necessary, the fallback obligation is: name an exact version, download
over TLS from the vendor's own endpoint, and verify a published checksum or signature *before* the
artifact is used.

---

## Deployment contract

This component cannot enforce these; it is correct only if the caller does.

1. **TLS terminates in front of the authentication endpoint**, and the caller passes
   `secureTransport=true` only when it really did. The cookie helper refuses to build a directive
   otherwise.
2. **The session cookie** is set from `sessionCookieFor(...)`: `HttpOnly`, `Secure`,
   `SameSite=Strict`, a `Path` no broader than the application root, `Max-Age` no longer than
   `sessionTtlSeconds()`. Never put the identifier in a URL, a response body, a log line, or a link
   that a `Referrer-Policy` would permit.
3. **The third argument of `Attempt.of(...)` must be the transport peer address.** It is not readable
   back out of the `Attempt` — the component keeps it private — so the obligation is entirely at the
   call site. Behind a proxy, pass the address the proxy attests to, not a client-supplied header.
4. <a id="provisioning"></a>**Provisioning is out of band.** One record per line, UTF-8, no
   spaces: `username:base64(16-byte salt):iterations:base64(32-byte digest)` with `digest =
   HMAC-SHA-256(pepper, salt ‖ PBKDF2-HMAC-SHA-256(password, salt, iterations))` — the construction
   spelled out in `PasswordHasher`'s own header, where the pepper is the MAC *key* and not bytes
   appended to the password. `PasswordHasher` is package-private and so is `derive`, which is why
   the component exposes no record writer through its public API: to produce a record, put a small
   provisioning tool in the same package — `FixtureProvisioner` in the test tree is a worked example
   — or use any implementation that matches the construction above. Base64 must be *canonical*
   standard encoding with no line breaks; the iteration count must be plain digits with no leading
   zero and must lie inside `[AUTH_MIN_ACCEPTED_ITERATIONS, AUTH_PBKDF2_ITERATIONS]`. Deliberately,
   nothing in the shipped component writes this file or encodes a record — rendering a credential is
   provisioning, not authentication, and a shipped writer would be a way to inject records into a
   store this component is only supposed to read. Suite 1 asserts the absence by scanning every file
   in `src/main` for the encoder and the serializer, then proves the reader still accepts records
   produced out of band. Write the file with the iteration count you intend to run, `chmod 600` it,
   and `chmod 700` (or tighter) its directory. `AUTH_MIN_ACCEPTED_ITERATIONS` is how you raise the
   work factor later: raise the configured iterations, then raise the accepted floor once every
   record has been re-derived.
5. **The pepper keystore** must be `0600`, in a directory other users cannot write, and provisioned
   per environment. The keystore password must not be in an image, a repository, or a command line.
6. <a id="log-rotation"></a>**Rotate the log externally.** The component re-verifies the log target
   **before every write** and refuses the attempt rather than appending into an inode nobody will read,
   which behaves differently for the two rotation strategies:
   * **`create` mode** (rename the live file, then make a new one): the name now denotes a different
     inode, so exactly **one** attempt is refused at the rotation instant, the stale handle is closed,
     and the next attempt reopens the new file and resumes. That is not an outage, but do not be
     surprised to see one refusal plus a `security_alert` per rotation. **The new file must be created
     `0600` owned by the service user** — `create 0600 <user> <group>` — because the reopen path adopts
     only an exactly-owner-only file; a `0644` file left by the default `create` keeps every attempt
     refused. Put `olddir` somewhere not writable by other users, or the same rule applies to the
     directory. Suite 4 covers this sequence: a replacement moved in atomically under an open handle is
     refused once, then authentication resumes against the file that has the name.
   * **`copytruncate` mode**: truncation happens on the same inode with the same mode, so nothing is
     detected and nothing is refused — writes simply continue from offset 0. That is the reason this
     mode is *not* recommended here rather than a bug: the guard's whole purpose is to refuse writing
     where the trail cannot be read back, and an in-place truncation is invisible to it. It also has
     the usual gap in which events written between the copy and the truncate are lost from both copies.

   Either way `selfCheck()` reports the count of events that could not be persisted, so a rotation that
   goes wrong is visible instead of silent.
7. **Run `selfCheck()`** from your readiness/liveness probe wiring or periodically, and alert on a
   non-empty result. It reports: log closed, *N* events that could not be persisted, an empty
   credential store, a clock behind 2020, and inconsistent session accounting. `unsavedEvents` is a
   lifetime counter and intentionally stays visible after recovery — an empty log because every attempt
   was refused *is* an outage, and this is the only signal that distinguishes it from quiet.

---

## Residual risks

Named explicitly, because several of them are consequences of staying in one process without a shared
store, and pretending otherwise would be the finding.

* **State is per process.** Throttle budgets, the session table, and the log's sequence counter are
  per node. Behind a load balancer the effective attempt limit is the configured limit × node count,
  and a session issued by node A is unknown to node B. A deployment needing a shared budget or shared
  sessions must enforce it in a shared store; the limits here remain as the last line of defence. The
  `seq=` value orders events within one process, not across processes — suite 4 asserts this honestly
  rather than pretending the number is a cross-process primary key.
* **`account_id` is an unkeyed hash.** It is one-way, so a leaked log is not a list of accounts, but it
  is not a secret either: an offline dictionary of plausible names can be hashed and matched against a
  log. It is present because a log that cannot be attributed by account is not reviewable; a keyed
  identifier (an HMAC with a per-deployment key) is the upgrade path if that trade stops being
  acceptable.
* **Timing is reduced, not eliminated.** The latency floor is a wall-clock target on the machine
  serving the request. An attacker with a very large sample size, on the same host, or able to
  measure CPU rather than response time could still resolve differences the floor does not cover. A
  coarse per-source rate limit at the edge is the robust mitigation; the CPU-floor test in suite 3 is
  there to keep the claim honest about *which* differences are closed.
* **PBKDF2-SHA-256 at 120 000 iterations** is a floor, not a ceiling. It is memory-hard-light: a
  determined offline attacker with GPUs gets more parallelism per watt than Argon2id would allow.
  Migrate by raising `AUTH_PBKDF2_ITERATIONS` and `AUTH_MIN_ACCEPTED_ITERATIONS` together, or by
  re-deriving records out of band. (Argon2id is not in the JDK, which is why it is not here — see
  rule 8.)
* **Session identifiers live in the heap.** Anyone able to dump the process memory can read live
  identifiers and use them until the TTL. So can anyone with the keystore password and the pepper file.
  Heap dumping is an OS-level problem this component cannot solve; short TTLs and `revokeSession()` on
  sign-out bound the window.
* **`erase()` on a `SecretKeySpec` is a no-op** on this JDK (it throws `UnsupportedOperationException`
  and destroys nothing), and the JVM's `char[]`→`String` interning can leave copies the GC has not
  collected. Credential wiping here reduces the window in which a dump catches a password; it is not
  a guarantee against a memory reader.
* **The 2 s work budget means a saturated service denies logins.** That is the intended trade — an
  unbounded queue would be the denial of service — but it is still availability impact an attacker can
  cause by driving load. Four concurrent derivations at 120 000 iterations is roughly 20 login/s on the
  reference machine; size `AUTH_PBKDF2_ITERATIONS` and your instance count against your real peak.
* **Log integrity is integrity-of-append, not tamper evidence.** The owner-only permissions keep other
  users out, but the process's own user can rewrite the file, and there is no hash chain. If the
  threat model includes the host's own operator, ship the log off-host.
* **No brute-speed ceiling below the throttle.** A single source is limited to
  `sourceMaxAttempts` per `sourceWindowSeconds`; distributed sources each get their own window. With
  per-process state (above), a distributed attacker sees the × nodes effective rate. Strong passwords
  (10-code-point minimum here, but 4+ random words in practice) are what actually make a modest rate
  limit sufficient.

---

## Verification summary

Measured on this machine, JDK 17, `AUTH_PBKDF2_ITERATIONS=120000`:

| Suite | Checks | Focus |
|---|---|---|
| `Suite1Validation` | 380 | input shapes, canonical forms, store parsing/bounds, config refusal matrix, shipped-tree source guards |
| `Suite2LoginBehavior` | 181 | uniform denials, lockout and its isolation, per-source budget, tokens/cookies, orphaned-identifier absence, audit-outage accounting |
| `Suite3Latency` | 16 | wall spread, absolute wall floor, CPU floors |
| `Suite4AuditDurability` | 168 | 0600 creation, redaction, line grammar, injection, cross-process append, deny-and-recover, symlink refusal, inode replaced under an open handle, mode loosened under an open handle, torn-tail repair, log size ceiling, lock-line attribution, retention, rejected-event alerting |
| `Suite5Concurrency` | 55 | exact race totals, fixed lock orders, table caps, session accounting, audit totals, atomicity source guard |

From `build-logs/suite3.log`, whose `NOTE` lines report microseconds: one derivation measured at
173 982 µs wall / 174 759 µs CPU; the four deriving paths at 261.6–272.2 ms median wall
(256.8–273.7 ms across every repeat) and 175.5–176.7 ms median CPU; the two shape-refusing paths at
250.0 ms wall and 1.16–1.61 ms CPU. Whole-path wall spread **1.09×**; deriving-path CPU spread **1.01×**.

**800 checks, zero failures.**

The guards that carry weight were also checked with a mutation battery: each mutant is one textual
edit to a guard, and a mutant is counted as killed only when a suite prints a `FAIL` line. A suite that
crashed without a `FAIL` was recorded as an error and re-run, not counted as a kill. The timing suite is
excluded from that battery and the two timing-only mutants are re-checked separately. Scripts are in
[`tools/`](tools); results — **25 of 30 killed**, with every survivor explained — are in
[SECURITY.md](SECURITY.md#mutation-battery).
