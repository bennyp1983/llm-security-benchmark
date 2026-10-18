# UserAuthentication — password authentication with an audit log

A single-file Java implementation of user authentication: it accepts a username and password,
verifies them against stored account data, and writes one audit record per attempt to an
application log. Successful and unsuccessful attempts are both handled, as are locked, disabled
and damaged accounts.

Requires **JDK 17 or newer**. No dependencies, no build tool, no framework — plain `javac` and
`java`.

## Files

| File | Purpose |
| --- | --- |
| `UserAuthentication.java` | The implementation, plus a runnable demo/interactive entry point. |
| `AuthTest.java` | Self-contained test harness (305 checks). `java AuthTest`, exit code 0 on success. |
| `mutation_test.py` | Optional: injects 31 defects into the implementation and checks the suite catches them. |
| `README.md` | This file. |

## Compile and run

```bash
# Compile everything (sources are ASCII-only, so no -encoding flag is needed)
javac -d out UserAuthentication.java AuthTest.java

# Run the test suite (prints one line per check; exits 1 if any check fails)
java -cp out AuthTest

# Run the demo: a scripted walk through every outcome, writing auth-demo.log
java -cp out UserAuthentication

# Run it interactively instead (passwords are read with a hidden prompt when a console exists)
java -cp out UserAuthentication --interactive

# Run specific attempts. Pair syntax is user:password; the log file and KDF cost are options.
java -cp out UserAuthentication --script "alice:winter-Frost-42" "alice:typo" "carol:x" --log demo.log --iterations 120000
```

Demo accounts: `alice / winter-Frost-42`, `bob / correct horse battery staple`, plus `dave`
(used to show lockout), `erin` (disabled) and `carol` (does not exist).

Options: `--log <file>` (default `auth-demo.log`), `--iterations <n>` (default `60000`; the
library default for real use is `120000`), `--interactive`, `--script`.

To use the class from your own code, drop `UserAuthentication.java` next to your sources:

```java
try (UserAuthentication.FileEventLogger auditLog =
         new UserAuthentication.FileEventLogger(Path.of("/var/log/auth.log"))) {
    UserAuthentication auth = UserAuthentication.withInMemoryStore(
        auditLog, UserAuthentication.Config.defaults());

    auth.register("alice", passwordChars);            // once, at signup

    UserAuthentication.Result result =
        auth.authenticate(username, passwordChars, request.getRemoteAddr());
    if (result.isSuccess()) {
        session.start(result.username());
    } else {
        response.send(result.userMessage());          // safe to show to the user
        log.warn("login refused: {}", result.auditReason());   // internal detail, never shown
    }
}
```

## What it does

**Verification.** Passwords are stored only as PBKDF2-HMAC-SHA256 digests (120 000 rounds by
default) with a 16-byte random salt per account, in the self-describing form
`pbkdf2-sha256$iterations$base64(salt)$base64(key)`. Because the record carries its own salt and
round count, a stored hash can be verified as-is and re-hashed later when the policy tightens.
The plaintext password is never stored, logged, returned or printed; `Result.toString()` and
`PasswordHash.toString()` are both redacted.

**Usernames** are NFKC-normalized, trimmed and lowercased, then matched against
`[a-z0-9._-]{3,64}`. `" Alice "` and `"alice"` name the same account; anything else (an `@`,
a space, a newline, 65 characters) is refused as `INVALID_INPUT` rather than looked up.

**Outcomes.** `authenticate` returns one of five outcomes:

| Outcome | Meaning | `auditReason()` |
| --- | --- | --- |
| `SUCCESS` | Credentials matched, counters reset | `OK` |
| `INVALID_CREDENTIALS` | Wrong password, or no such user | `BAD_PASSWORD` / `UNKNOWN_USER` |
| `ACCOUNT_LOCKED` | Too many recent failures; retry later | `ACCOUNT_LOCKED` |
| `ACCOUNT_DISABLED` | Account switched off by an operator | `ACCOUNT_DISABLED` |
| `INVALID_INPUT` | Username or password was not a valid shape | `MALFORMED_USERNAME` / `MALFORMED_PASSWORD` |

`userMessage()` is safe to render: the wording for a wrong password and for an unknown user is
identical, so the response never reveals whether an account exists. `auditReason()` is for the
audit trail and logs only.

**Lockout.** `maxFailures` consecutive failures (default 5) inside `failureWindow` (default 30
minutes) lock the account for `lockDuration` (default 15 minutes). The failure that trips the lock
is still reported as `INVALID_CREDENTIALS` — the next attempt is the one that sees
`ACCOUNT_LOCKED` — so an attacker cannot tell the threshold from the response. A verified login
resets the counter; a lock also expires on its own. `unlock(username)` lets an operator clear a
lock, and `setEnabled` switches an account off without deleting it.

**Logging.** Every attempt writes exactly one record through the `EventLogger` seam, whichever
outcome it produced, plus separate events for registration, a lock tripping, auto-expiry and an
operator unlock. The format is a single ASCII line, machine-readable and reversible via
`Event.parseLine`:

```
2026-09-12T03:29:21.568Z|event=LOGIN_FAILURE|user=dave|outcome=INVALID_CREDENTIALS|reason=BAD_PASSWORD|addr=-|durationMs=29|failures=3|detail=lock tripped
```

`FileEventLogger` flushes after every line (a crash cannot lose the last attempt) and writes under
a lock, so concurrent logins cannot interleave half-lines. `ConsoleEventLogger` prints,
`EventLogger.nullLogger()` discards, and your own sink implements the one-method `EventLogger`
interface.

## Security properties worth knowing

* **Equal work on every path.** Each `authenticate` call performs exactly one key derivation,
  including the paths that refuse before checking a credential: unknown user, malformed username,
  unusable password, damaged stored record, disabled account, locked account. Without that,
  response time alone reveals which usernames exist. The "charge" is a real digest of a placeholder
  secret, generated when the service is constructed — never a hand-written constant, which is how
  this mitigation usually fails silently (a pasted base64 blob that the strict decoder rejects
  turns the equal-work branch into a no-op, and every functional test still passes).
* **Constant-time comparison.** The derived key is compared with `MessageDigest.isEqual`.
* **Log injection is impossible.** Every field is forced to printable ASCII with CR, LF and the
  `|` delimiter replaced and long values truncated, so a username cannot forge or split a record.
* **Unhashable candidates are rejected, not sanitized.** `PBEKeySpec` converts a `char[]` with a
  lossy encoder: it drops *trailing* NULs and maps every unpaired surrogate to `'?'`, so
  `"pw"`, `"pw\0"` and `"p\ud800"`/`"pw?"` collide onto the same digest — one holder could log in
  as the other. `isHashablePassword` refuses those forms (interior NULs and well-formed surrogate
  pairs stay legal). `AuthTest` derives both colliding forms with the raw JCE to show the collision
  is real before asserting the guard.
* **Strict record parsing.** Stored hashes are base64-decoded with the strict decoder and then
  re-encoded and compared, so a field that only decoded because a lenient decoder ignored junk is
  rejected instead of silently becoming a weaker key.
* **Defensive copying.** `PasswordHash` copies the salt and key in its constructor and returns
  copies from its accessors, so a caller wiping its own buffers cannot corrupt a stored credential.
* **Thread safety.** Account state is guarded per account; the failure counter is not lost when
  concurrent failures race (verified over 100 trials x 8 threads).

## Verification

`java -cp out AuthTest` runs 305 checks and prints `=== 305 checks, 0 failed ===`. It covers:

* username normalization and rejection, password-shape rejection (empty, trailing NUL, unpaired
  surrogate, oversized), and the raw-JCE collisions those guards exist to prevent;
* parsing: correct password succeeds, 11 near-miss passwords all refused, case sensitivity,
  prefix/suffix candidates refused, unknown user refused;
* lockout arithmetic: which strike trips the lock, what that strike reports, the right password
  refused while locked, counter reset by login and by operator, failure-window expiry, automatic
  unlock after `lockDuration`;
* the audit trail: one record per attempt with the right type/reason/address, log lines parse back,
  file logger appends and flushes, credentials and hash material never appear, hostile usernames
  (`CRLF` + a forged record, embedded `|`, control characters, 200 chars) cannot forge a line;
* equal-work timing across **five** refusal shapes plus the honest-wrong-password baseline
  (measured medians 41-43 ms each at 30 000 rounds; each ratio must land in 0.6-1.7). Each shape
  is timed on its own fixture, because per-account lockout would otherwise short-circuit later
  samples and fabricate a flattering ratio;
* concurrency: strike-counter updates under contention, interleaving-free concurrent log writes,
  concurrent correct logins all succeeding.

`python3 mutation_test.py` then proves those checks are load-bearing: it rebuilds the project 31
times with one deliberate defect each (guard removed, comparison reversed, clone dropped, logging
call dropped, reason swapped, `MessageDigest.isEqual` replaced with `Arrays.equals`, ...) and
reports whether the suite notices.

```
total mutants: 31 | killed: 29 | survived: 2 | harness problems: 0
```

The two survivors are reported rather than deleted, because neither defect is observable through
the public API at this granularity:

1. `non-constant-time-key-compare` — `Arrays.equals` exits early, but the difference is tens of
   nanoseconds against a ~40 ms key derivation. No honest assertion can pin it; it would only
   produce a flaky test.
2. `username-guard-semantic-noop` — re-normalizing the username in the guard is the same decision,
   so no test can distinguish it from the original.

A mutant whose anchor does not match exactly once is reported as `NOT-APPLIED` and a mutant that
does not compile as `COMPILE-FAIL`; neither is ever counted as a kill. Re-run a single mutant with
`python3 mutation_test.py <name-substring>`.

## Limitations and how to extend it

* **Storage is in-memory.** `InMemoryAccountStore` is process-local and lost on restart. The
  `AccountStore` interface (`find` / `register` / `failuresOf`) is the seam: a JDBC store maps to
  `username, password_hash, enabled, failed_attempts, locked_until`. Keep parameterized queries —
  never concatenate a username into SQL.
* **No session/token layer.** This verifies credentials and logs the attempt; issuing a session
  cookie or JWT is deliberately out of scope.
* **Lockout counters live with the account object.** A JDBC store should keep them in columns so
  they survive a restart and are shared across nodes.
* **`main` is a demo.** It seeds accounts at startup. Real deployments should call
  `register(...)` from a signup flow behind authorization.
* **Timing equalization is per-attempt, not per-server.** Under heavy concurrent load the CPU
  contention noise floor (roughly a millisecond here) dominates the difference the guard protects;
  the ratios hold because one derivation is tens of milliseconds. Rate limiting in front of the
  endpoint is the complementary control.
* **Iteration count is not self-adapting.** 120 000 PBKDF2-HMAC-SHA256 rounds is a reasonable 2026
  floor; `Config` lets you raise it, and existing records keep verifying because they carry their
  own round count.
