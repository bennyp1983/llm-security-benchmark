# AuthService — password authentication with a security-aware audit log

A self-contained Java 17 authentication module: it accepts a username and password, verifies them
against stored account records, enforces a lockout policy, and writes an audit record of every
attempt. JDK only — no third-party dependencies, no build tool.

Files:

| File | Purpose |
| --- | --- |
| `AuthService.java` | The implementation, plus a runnable demo (`AuthService.main`). |
| `AuthServiceTest.java` | 242 verification checks, no test framework required. |

## Build and run

```bash
javac -d out AuthService.java AuthServiceTest.java     # compiles clean under -Xlint:all -Werror

java -cp out AuthService                # scripted scenario, prints the audit log as it is written
java -cp out AuthService login          # one interactive login; without a tty it says so and
                                        # runs the scripted scenario instead
java -cp out AuthServiceTest            # the verification suite; exits non-zero on failure
```

Requirements: JDK 17 or newer (`java -version` was 17.0.20.1 here). Sources are ASCII-only, so no
`-encoding` flag is needed, and the audit log is pure ASCII, so it survives any console.

`AuthService` writes the audit log to **`./auth.log`** (appending) and echoes it to stdout. Run from
a directory you don't mind that file appearing in.

## What a login does

```java
AuthService service = new AuthService(
        new AuthService.InMemoryAccountStore(),
        new AuthService.PasswordHasher(310_000),                        // PBKDF2 iterations
        new AuthService.InMemoryFailureTracker(5, Duration.ofMinutes(15)),
        new AuthService.AuthAuditLogger(),                              // java.util.logging "auth.audit"
        Clock.systemUTC());

service.register("alice", "correct-horse-battery".toCharArray());

AuthService.LoginResult result = service.login(new AuthService.LoginRequest(
        "alice", passwordChars, "203.0.113.10", "sess-42", "Mozilla/5.0 ..."));

if (result.authenticated()) {
    issueSession(result.accountId());
}
```

`login()` never throws because of a wrong password. It throws
`AuthService.AuthenticationDataException` only when a stored credential cannot be parsed — that
account cannot be judged at all, and answering "wrong password" would hide a broken import.

The subject always gets one of exactly two sentences: `Authenticated.`, or

> Authentication failed. The username and password provided could not be verified.

The real reason is never in that sentence. It is available to the caller through
`LoginResult.internalReason()` for counters and alerting, and it is on the audit line.

## What the log records

One record per attempt — including the attempt that trips a lockout, which is the same record
escalated to `WARNING` rather than a second line, so a dashboard counting records counts attempts.

```
2026-09-12T04:55:03.505Z INFO    auth.audit event=AUTH_SUCCESS outcome=SUCCESS reason=authenticated attempt=60de19bfae37 subject=alice subjectState=resolved account=acct-2470720b92 accountState=active ip=203.0.113.10 session=sess-1 agent="DemoClient/1.0 (scenario runner)" failures=0 lockedUntil=- previousSuccess=- previousSuccessIp=- policy=pbkdf2-sha256$60000 elapsedMs=88
```

That is one physical line; it is wrapped here only to fit. Every record is exactly one line, the
`CREDENTIAL_RECORD_CORRUPT` one included — no throwable is attached, so nothing spills a stack trace
into the audit file. The header is `UTC-timestamp LEVEL logger-name`, where `LEVEL` is
right-padded to 7 columns (`INFO` and `WARNING` above line up), then ordered `key=value` fields.
Absent values are written as `-` rather than omitted, so every record has the same shape and a parser
never has to guess whether a missing field means "no value" or "older format".

| Field | Why an investigator needs it |
| --- | --- |
| `event` | `AUTH_SUCCESS`, `AUTH_FAILURE`, `ACCOUNT_CREATED`, `ACCOUNT_STATUS_CHANGED`, `ACCOUNT_UNLOCKED`, `CREDENTIAL_RECORD_CORRUPT`. |
| `outcome` | `SUCCESS` / `FAILURE` / `INFO` (administrative records). Cheap filter. |
| `reason` | The precise cause. **Internal**: `password-mismatch`, `password-mismatch-locking`, `unknown-account`, `account-locked`, `account-disabled`, `account-locked-by-admin`, `username-unsupported-characters` (and siblings), `password-ends-in-nul`, `password-has-unpaired-surrogate`, `password-too-long`, `no-password-submitted`. |
| `attempt` | Correlation id, 12 hex chars. The same value the subject was shown in `LoginResult.attemptId()`, which is what lets a support ticket be matched to a line without guessing. Administrative records use an `admin-<epoch>-<micros>` id. |
| `subject` | The name that was *typed*. Normalised when it parses (`ALICE ` → `alice`), otherwise the raw input, escaped. Recording the raw attempt is what makes credential-stuffing and probe traffic visible. |
| `subjectState` | `resolved`, or `malformed(<cause>)` — `empty`, `absent`, `unsupported-characters`, `malformed-unicode`, `longer-than-256-characters`. Separates a real account miss from malformed input. |
| `account` | Account id, or `-`. The join key across accounts, devices and log files, stable across renames. |
| `accountState` | `active`, `disabled`, `locked-by-admin`, or `no-such-account`. |
| `ip`, `session`, `agent` | Where it came from. Client-supplied, so escaped like `subject`; the `ip` alone should never be trusted for a decision. |
| `failures` | Consecutive-failure counter *as it stood when the attempt was judged* (post-increment on a mismatch). `0` after a success; `-` when no account was identified. |
| `lockedUntil` | When a lockout ends — the answer to "when can the user try again", and the evidence that a lockout did *not* slide forward on every locked attempt. |
| `previousSuccess`, `previousSuccessIp` | The account's last good login **and its address**, carried on failure lines too. This is what distinguishes "the user typoed" from "someone who is not this user started trying", and it is only useful if it is on the *failure* record. |
| `policy` | The KDF and the iteration count actually charged, e.g. `pbkdf2-sha256$310000`. Makes a cost-raise rollout, or a downgraded record, visible in the log. |
| `recordError` | On `CREDENTIAL_RECORD_CORRUPT` only: the specific parse failure (`unknown-kdf`, `digest-length-20`, `non-base64-material`, …) so the operator can find the bad row. |
| `elapsedMs` | Wall time of the attempt. Operational signal, and the continuous evidence that the equal-cost derivation below really ran. |
| `fromState`/`toState`, `createdAt`, `operator` | On the administrative records: who changed what, and when the account appeared. |

Levels are chosen so a collector can alert without string matching: **INFO** for ordinary successes
and refusals, **WARNING** for the attempt that crossed the lockout threshold, **SEVERE** for a
corrupt stored credential.

### Log adequacy is checked, not asserted in prose

`AuthServiceTest` proves the log claims above rather than describing them:

- exactly one record per attempt, across five different refusal shapes, with unique attempt ids;
- the record's `attempt` equals the id in the result handed to the subject;
- every investigative field present and correct on success, wrong-password, unknown-account,
  disabled, locked and corrupt-record records;
- **no password anywhere in any emitted string**, and no stored digest either;
- a username containing `\n` plus a forged `event=AUTH_SUCCESS outcome=SUCCESS` payload produces
  **one** record, whose parsed `event`/`outcome`/`reason`/`account` are the real ones;
- non-ASCII input is recoverable byte-for-byte from the escaping, and the line is pure ASCII;
- oversized input is truncated *and says so* (`(+truncated)`).

### Escaping rules

Free-text values (`subject`, `ip`, `session`, `agent`) pass through one escaping function:

1. `%`, `"` and `\` are percent-encoded — the escape language itself cannot be forged;
2. every byte of every non-ASCII code point is percent-encoded via UTF-8, which keeps the line pure
   ASCII and keeps a look-alike Unicode username exactly reproducible;
3. that rule already covers the C1 controls, U+0085, U+00A0 and U+2028/U+2029; the C0 controls
   (CR and LF included) and DEL are encoded as well;
4. what remains is printable ASCII; if it still contains whitespace the value is quoted.

So `agent="DemoClient/1.0 (scenario runner)"` is one field, and an injected newline appears as
`%0A` inside a single value.

## Security properties, and how each is pinned

| Property | Mechanism | Check |
| --- | --- | --- |
| No plaintext passwords stored, logged or echoed | Passwords travel as `char[]`, are defensively copied, and the copy is zeroed when the attempt ends; `toString()` on request **and** stored record redacts | `noSecretInAnyEmittedString` (incl. the record `toString`), `callerOwnedBuffersAreNotClobbered`, `password-not-wiped`/`destroy-is-a-noop`/`*-leaks` mutants |
| A request never adopts the caller's buffer | `LoginRequest` copies the array it is given, so the caller can wipe its own memory while the request is alive and `destroy()` cannot reach into it | identity check in `callerOwnedBuffersAreNotClobbered`; `caller-buffer-clobbered` / `service-consumes-caller-buffer` mutants |
| No user enumeration **by response text** | One generic sentence for all seven refusal shapes | `publicMessageIsIdenticalForEveryRefusal` (also asserts the sentence contains no hint words) |
| No user enumeration **by timing** | Exactly **one** key derivation per attempt on every path: an unknown account is charged against a *real* digest that no login can match; an unusable candidate is swapped for a random password belonging to nobody | `everyRefusalShapeCostsTheSameWork` times all five early-return shapes, and asserts an absolute floor as well as a ratio window |
| No enumeration via the **log's** timing column | `elapsedMs` is written from the same measured span, and checked to be comparable | asserted directly from the parsed records |
| A corrupt credential is never "wrong password" | `AuthenticationDataException` + SEVERE `CREDENTIAL_RECORD_CORRUPT` with `recordError` | `corruptCredentialIsDataFault` |
| Distinct passwords cannot collide | `PBEKeySpec` is **not** injective over `char[]`: it drops trailing NULs and maps every unpaired surrogate to `?`, so `"pw"` and `"pw\0"` would hash identically. Such candidates are rejected, never silently trimmed | `unusableCandidatesAreRejected`; `nul-collision-allowed` / `trailing-nul-rule-removed` / `surrogate-rule-removed` mutants |
| Credentials are salted, per-record-cost, constant-compared | `pbkdf2-sha256$<iters>$<b64 salt>$<b64 digest>`, 16-byte random salt per record, `MessageDigest.isEqual` over two fixed-length 32-byte digests | `hashFormatAndSalting`, `storedDigestParsingIsStrict`, `no-per-record-iterations` / `no-salt-per-record` mutants |
| Brute force is bounded | Consecutive failures per **account id** (not username spelling), lockout for a bounded window, correct passwords refused during the window, expiry automatic, failures not counted during a lockout and the deadline does not slide | `failureCounterProgression`, `thresholdCrossingIsOneWarningRecord`, `correctPasswordDuringLockoutIsRefused`, `lockoutExpires`, `failureTrackerUnitBehaviour` |
| One username cannot be two accounts | NFKC then `toLowerCase(Locale.ROOT)`, then an explicit allow-list `[a-z0-9._+\-]{1,64}` | `usernameNormalisation` (full-width `ａｌｉｃｅ` resolves to `alice`; NBSP is refused rather than mapped to a space) |
| Log cannot be forged or polluted | The escaping rules above, plus one-record-per-attempt | `logInjectionCannotForgeASecondLine`, `nonAsciiInputIsAsciiEncodedAndReversible`, `userAgentIsEscaped`, `oversizedInputIsTruncatedAndMarked` |
| Counter is not lost under concurrency | Tracker methods synchronise on one monitor; audit writes happen outside the lock | `concurrentAttemptsAreCountedAndLogged` (16 threads, no lost increments, 16 records) |
| Admin actions are attributable | `ACCOUNT_CREATED` (with `ip`), `ACCOUNT_STATUS_CHANGED` and `ACCOUNT_UNLOCKED` (with `operator`, and the counter/deadline that were cleared) | `adminUnlockIsAuditedAndRestoresAccess` |

### Equal-cost refusal, measured on this machine

PBKDF2-HMAC-SHA256 at 60 000 iterations, median of 5 samples per shape (`AuthServiceTest` prints
this line; it uses 20 000 iterations for the functional tests to stay quick):

```
known wrong password=86ms  unknown account=88ms  unusable candidate=85ms
malformed username=87ms    locked account=87ms
```

The suite fails if any ratio leaves `[0.75, 1.4]`, or if the known-account shape costs under 20 ms —
the absolute floor is what catches a silently stubbed equaliser. Absolute numbers move between runs
(a re-run of the identical build on this machine printed 81–84 ms); what the suite pins is the
*spread across shapes*, so it is the ratio window that matters, not the value. If you change the
iteration count, expect the floor to move.

## Verification

```
$ java -cp out AuthServiceTest
...
      [timing 60000 iterations: known wrong password=86ms unknown account=88ms unusable candidate=85ms
       malformed username=87ms locked account=87ms]
RESULT: all 242 checks passed
```

The suite was additionally checked with a **mutation battery**: 46 defects injected one at a time
into `AuthService.java` by rewriting a known source anchor, recompiling and re-running all 242
checks. A mutant is *killed* only if the suite fails; a mutant that compiles and passes is a hole in
the tests, so the harness reports it by name instead of dropping it. Anchors that no longer match are
reported as `NOT-APPLIED`, never as a pass.

| Area | Injected defect | Result |
| --- | --- | --- |
| Equal-cost refusal | equaliser removed (unknown account takes no derivation) · `elapsedMs` not logged | 2 killed |
| Password-collision rules | NUL collision allowed · trailing-NUL rule removed · unpaired-surrogate rule removed | 3 killed |
| KDF and record format | `verify` skips the derivation for an unparsable record · digest-length check removed · iteration range check removed · per-record iteration count ignored · salt reused for every record · iteration floor weakened | 6 killed |
| Lockout | off-by-one at the threshold · lockout never enforced · locked attempts extend the deadline · locked attempts consume the counter · expired lock never clears · success keeps the counter | 6 killed |
| Refusal semantics | corrupt record downgraded to "wrong password" · corrupt record unlogged · refusal hands out the account id · subject-facing message leaks the lockout · internal reasons collapsed to `unknown-account` · malformed-username reason collapsed | 6 killed |
| Log completeness | `previousSuccess` not recorded · duplicate record on the locking attempt · attempt id not shared with the result · `ip` not logged · `failures` not logged · unlock not audited | 6 killed |
| Log escaping | newline not escaped · `%` escaping removed · non-ASCII emitted raw · value quoting removed · truncation marker removed | 5 killed |
| Username handling | no case folding · no NFKC · no trim · allow-list widened to any character | 4 killed |
| Secret hygiene | password not wiped after the attempt · request adopts the caller's buffer · service consumes the caller's buffer · `destroy()` made a no-op · request `toString` leaks · record `toString` leaks the digest | 6 killed |
| **Total** | 46 mutants, 0 harness problems | **45 killed, 1 survived** |

**The one survivor is an equivalent mutant, and it is reported rather than removed.**
`login-does-not-wipe-working-copy` deletes the `Arrays.fill(candidate, '\0')` in `login()`'s
`finally`. `candidate` is a local array produced by `request.passwordCopy()`; it never escapes the
method, `PasswordHasher` is `final` and cannot be subclassed to capture it, and nothing retains a
reference to it — so no assertion written against the public API can distinguish the mutated build
from the correct one. It is listed here instead of deleted from the battery: an unobservable mutant
is a fact about the design (the wipe is defence-in-depth against heap inspection, not observable
behaviour), not a passing test. The wipes that *are* observable — `destroy()` erasing the retained
copy, `destroy()` not reaching into the caller's array, the caller's buffer surviving a login — are
all killed.

## Design notes and deliberate choices

- **`char[]`, not `String`, for passwords.** A `String` cannot be erased and lands in the interned
  heap and in thread dumps. `LoginRequest` copies the array it is given, so the caller keeps
  ownership of its own buffer and can wipe it independently; `login()` wipes its own working copy
  when the attempt ends, and `LoginRequest.destroy()` zeroes the copy the request retains (after
  which the request reports an absent credential rather than presenting whatever is left in memory).
  The erasure is verified reflectively against the request's own array, not against a clone the test
  wiped itself.
- **The strength floor is an enrolment rule only.** `register()` refuses a password shorter than 12
  characters; `login()` still hashes one if an existing (migrated) account legitimately holds it.
  Turning policy into a pre-hash refusal would make "is this an old account" an enumeration channel.
- **The equalising digest is derived, never hard-coded.** A hand-written constant is the classic
  trap: if it fails to parse, the unknown-account branch takes the corrupt-record path and returns
  without ever calling the KDF — the account-enumeration leak the constant existed to close, with
  every functional assertion still green. The constructor derives the value at startup and *asserts
  it parses*; the timing test re-checks the cost. Startup pays one extra derivation.
- **`java.util.logging`** keeps the file dependency-free. `AuthAuditLogger` wraps a named logger
  (`auth.audit`) and `IsoLogFormatter` renders one ASCII line per record, so wiring in Log4j2 or
  Logback later is a handler swap, not a rewrite — and a JSON layout then gets the same field names.
- **`Clock` is injected**, which is what makes lockout expiry testable without sleeping.
- **The failure tracker is process-local.** In a real deployment it belongs in a shared store
  (database, Redis); the interface boundary is already drawn at `InMemoryFailureTracker`, and the
  counter is keyed by account id so it is already rename-proof.

## Known limitations

Deliberate boundaries, not oversights:

- **No rate limiting per source address or per session** — only per-account lockout. A slow
  credential-stuffing run spread across many usernames is not impeded. Add an IP/session budget in
  front of this.
- **No password change, reset or MFA.** `AccountStore.recordFor(username)` exists precisely so a
  rehash-on-cost-raise or reset flow can read the stored record and `store()` a replacement without
  racing another writer.
- **`InMemoryAccountStore` and `InMemoryFailureTracker` are process-local** — for the demo and the
  tests. Implement `AccountStore` (three lookups plus `store`) to put this behind a database.
- **Lockout is time-boxed, not permanent**, and the counter resets on expiry. That is a
  usability/security trade; a permanent admin unlock is a one-line policy change in
  `InMemoryFailureTracker`.
- **`ip`/`session`/`agent` are trusted inputs for *recording*, never for *deciding*.** They are
  escaped like any other input and should be populated by the transport layer, not by the client.
- **PBKDF2 is a defensible floor, not the strongest option.** The encoding carries a `kdf` field and
  a per-record cost, so migrating to Argon2id or scrypt is an additive change; `MIN_ITERATIONS`
  guards against a record importing a cost that is too cheap to accept.
- Single-file package-private layout, chosen for reviewability — no DI container, no configuration
  file. Iteration count, lockout threshold and window are constructor arguments.
