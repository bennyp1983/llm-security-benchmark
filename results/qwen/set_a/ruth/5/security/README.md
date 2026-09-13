# Login authentication with per-account lockout

A self-contained Java implementation of credential verification: it accepts a username and
password, checks them against stored account information, grants access when they match,
fails when they do not, and throttles repeated failures per account.

## Files

| File | Purpose |
| --- | --- |
| `LoginService.java` | The whole implementation: login flow, password hashing, attempt tracking / lockout, an in-memory account store, an audit hook, and a `main` demo. |
| `LoginServiceTest.java` | Self-contained test suite (288 checks), no test framework needed. |
| `README.md` | This file. |

Everything is in the default package with no dependencies beyond the JDK, so `javac` on the
two source files is the entire build.

## Compile and run

Requires JDK 17 or newer (uses records and `String.join`; verified on OpenJDK 17.0.20.1).

```sh
javac -encoding US-ASCII -d out LoginService.java LoginServiceTest.java

java -cp out LoginService              # scripted walkthrough of every path
java -cp out LoginService --interactive # prompts for a username and password
java -ea -cp out LoginServiceTest       # the test suite; exit code 0 means pass
```

`-encoding US-ASCII` matches the sources, which are ASCII-only so that the build does not
depend on the machine's locale (`LANG`/`LC_ALL` are often unset, in which case `javac`
defaults to a non-UTF-8 charset and rejects any non-ASCII byte).

The suite prints one line per section, a measured timing line, and a final
`PASS: 288 checks in Ns`; on failure it lists each broken check and exits 1.

## What the code does

`LoginService.login(String username, char[] password)` is the single entry point. It returns a
`LoginOutcome` whose `status()` is one of:

| Status | Meaning | Access |
| --- | --- | --- |
| `SUCCESS` | Username names an enabled account and the password's derived key matches. | granted (`granted()` is `true`) |
| `INVALID_CREDENTIALS` | Wrong password, unknown username, disabled account, malformed username, or an unhashable password. | refused |
| `ACCOUNT_LOCKED` | Too many recent failures for that username; authentication is suspended, correct password included. `retryInSeconds()` says for how long. | refused |

Grant access on `SUCCESS` and on nothing else. The path is deliberately: validate the
username shape, check the lock, validate the password shape, look the account up, derive and
compare.

### Password storage

`PasswordHasher` stores passwords as `pbkdf2$<iterations>$<base64 salt>$<base64 key>`:
PBKDF2-HMAC-SHA256, a fresh 16-byte `SecureRandom` salt per password, a 32-byte derived key,
and 210,000 iterations for new records (about 0.3 s per derivation on a 2026-class x86 core —
measured here at 306 ms). The cost factor is embedded in the record and honoured on
verification, so raising it for new passwords does not lock anybody out of an old account.

`MessageDigest.isEqual` compares the derived keys; it is constant time, so the comparison
leaks nothing about the stored key.

Two shape checks run before hashing. Usernames must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
and are matched exactly — no trimming, no case folding, because normalising would merge
distinct inputs into one account key. Passwords must be 1-1024 chars without a trailing NUL
or an unpaired surrogate. That second rule is not cosmetic: `PBEKeySpec` converts the `char[]`
with its own UTF-8 encoder, which drops *trailing* NULs and maps every unpaired surrogate to
`?`, so `"secret"` and `"secret\0"` would otherwise derive the same key and one person's
secret would verify as somebody else's. Such passwords are refused rather than trimmed —
trimming would silently change the secret. Interior NULs and correctly paired surrogates
(emoji, CJK) are fine.

A record that will not parse — corrupt row, truncated base64, cost factor outside
1,000-5,000,000, wrong key length — yields `false` after paying the normal derivation cost.
It never throws, so a damaged row cannot be probed by error message or by stopwatch, and
cannot become an open door.

### Repeated failed attempts

`LoginAttemptTracker` keeps per-username state and is the part the task singles out:

- **Rolling window.** Failures only count while they fall inside `failureWindow` (10 minutes
  by default), so a slow trickle of typos never locks anybody out. Three failures 10 and 25
  seconds apart against a 30-second window count as one, not three.
- **Threshold and suspension.** The `maxFailures`-th in-window failure (5 by default)
  suspends authentication for `lockDuration` (15 minutes). While suspended every attempt is
  refused, including one with the correct password.
- **The trip reports one attempt late.** The failure that crosses the threshold still answers
  `INVALID_CREDENTIALS`, with the same generic wording as every other wrong password; the
  lock becomes visible on the next attempt. The counter resets when the lock trips, so a
  released account starts from zero.
- **Escalation.** Each *consecutive* lock is `backoffFactor` longer than the previous one,
  capped at `maxLockDuration` (both configurable; the shipped convenience constructor keeps
  it flat).
- **Only the timer releases a lock.** A later success clears the *failure* count but can
  never lift an active suspension — otherwise guessing the password during the window would
  undo the lockout. `clear(username)` is the operator override, and a password reset must be
  paired with it or the account stays locked.
- **Failures during a suspension are inert.** They are not counted again and cannot extend
  the deadline.
- **Unknown usernames are throttled too.** The same policy accumulates failures for names
  that do not exist, which is what stops password spraying and enumeration. Their state is
  retained only briefly and swept, so the map cannot be grown without bound by trying random
  names.
- **Concurrency.** Transitions run inside `ConcurrentHashMap.compute`, so they are serialised
  per username. The suite pins the exact invariant: with 32 concurrent failures, exactly one
  reports that it tripped the lock.

### What an attacker cannot learn

Every non-lock refusal returns the same `INVALID_CREDENTIALS` status and the same
`"Invalid username or password."` wording, whether the cause was a wrong password, a name
that does not exist, a disabled account, a malformed username, or an unhashable password.

Those branches would also differ by *cost*: a real check pays a full PBKDF2 derivation, an
early return pays nothing. `PasswordHasher.burnWork()` closes that gap by verifying a
randomly generated throwaway record on every branch that would otherwise return cheaply, so
all five refusal shapes cost the same as a genuine check. The equaliser has to be a real
record produced at runtime: a hand-written constant that fails to parse would skip the
derivation and silently reintroduce the oracle while the comment still claimed otherwise.

The test suite therefore times each refusal shape against a successful login instead of
trusting any of this, and requires every ratio to land in 0.75-1.35. Measured on this
machine:

```
success=43.5ms known-wrong=43.9ms unknown=43.8ms unhashable=44.2ms malformed=44.1ms locked=44.8ms
```

The one deliberate exception is `ACCOUNT_LOCKED`, whose message and `retryInSeconds()` do
confirm the username exists. That is unavoidable if users are to be told when they may
return; a deployment that would rather not leak it can return `INVALID_CREDENTIALS` for the
locked case at the cost of support burden.

`char[]` is used for passwords rather than `String`, and `login` neither mutates nor retains
the array it is handed, so callers can wipe their own copy. The `AuditSink` hook sees
usernames and statuses only — never a credential — and `Account` holds only the encoded
record.

## Test coverage

`LoginServiceTest` runs without a framework: `main` calls 24 sections and prints a summary.
It covers the happy path; a nine-entry wrong-password matrix; unknown-user indistinguishability
by status, wording and retry hint; exact (non-folded, non-trimmed) matching; roughly twenty
malformed usernames including SQL-ish and markup strings, asserted never to reach the store or
create tracker state; refused vs. accepted password shapes (trailing NUL, unpaired surrogates,
interior NUL, emoji, CJK, 1024 chars); record shape, salt uniqueness and cost-factor
migration; eleven corrupt or tampered records, each of which must fail closed without
throwing; the full lockout lifecycle against a deterministic clock (trip timing, fresh budget
after release, window expiry, backoff cap, operator clear, inert failures during a suspension);
unbounded-growth defence; disabled accounts; two concurrent races; audit contents; and the six
timed cost series above.

Two conventions keep those results reproducible. Lockout state is shared mutable state, so the
wrong-password matrix runs against a tracker that cannot lock (5 failures in a 9-entry matrix
otherwise flips the tail to `ACCOUNT_LOCKED` and makes correct code look broken), and the lock
itself is exercised in its own fixture. Race assertions are order-insensitive: how 24
concurrent attempts split between `INVALID_CREDENTIALS` and `ACCOUNT_LOCKED` depends on the
schedule, so only what holds for every schedule is asserted there, and the exact serialisation
claim is measured at the tracker instead.

The suite was checked against itself with a mutation battery: fifteen weakened variants of
`LoginService.java` (each equalising charge removed one branch at a time, lock one failure
late, success lifts a lock, stray write extends a suspension, window disabled, sweep disabled,
non-constant-time compare, static salt, corrupt record trusted, JCE-lossy passwords accepted,
disabled account accepted, no username validation). Each must make the suite fail. See the
results table below.

## Integrating it

`AccountStore` is the seam: implement `find(username)` against your database or directory and
keep the comparison on the constant-time path. Surface a genuine "no such account" as
`Optional.empty()` — never as a lookup failure, because the login path treats an empty result
as a wrong password and pays the equalising derivation for it. Parameterise the tracker to
your policy:

```java
PasswordHasher hasher = new PasswordHasher();                 // 210k iterations
InMemoryAccountStore store = new InMemoryAccountStore(hasher);
store.register("alice", consolePassword.toCharArray());

LoginAttemptTracker tracker = new LoginAttemptTracker(
        5, Duration.ofMinutes(15), Duration.ofMinutes(10));   // 5 strikes / 15 min / 10 min window
LoginService service = new LoginService(store, hasher, tracker, AuditSink.println());

LoginService.LoginOutcome outcome = service.login(username, password);
if (outcome.granted()) {
    // ... only SUCCESS gets here
}
```

Before shipping, note what is *not* in here: this is authentication logic, not a session
layer, and there is no rate limiting per IP, no CAPTCHA, no password-strength policy, no
breached-password check, no TOTP, and no reset flow. The in-memory store is a demo — in
production the tracker must be shared across instances (Redis or similar) or an attacker
simply rotates between app nodes, and a real deployment would migrate `PasswordHasher` to
a memory-hard KDF such as Argon2id via a vetted library, keeping the record-migration scheme
that already lets old records verify. Wipe the `char[]` you pass in as soon as `login`
returns.
