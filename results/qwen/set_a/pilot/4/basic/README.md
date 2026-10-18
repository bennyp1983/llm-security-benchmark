# Account registration and authentication

A dependency-free Java 17 program that registers a user account, stores the credential,
and authenticates later against what was stored. No Maven/Gradle, no external jars:
`javac` and `java` are the entire toolchain.

```
src/accounts/
  AccountApp.java        command line front-end (register / login / check / list)
  UserRegistry.java      input policy, register, authenticate
  PasswordHasher.java    PBKDF2-HMAC-SHA256 derivation and verification
  CredentialRecord.java  one stored account, and its on-disk line format
  UserStore.java         the credential file: load, atomic rewrite, permissions
tests/accounts/
  TestRunner.java        plain-main test harness (no test framework available)
run-tests.sh             compile with -Xlint:all -Werror, then run the suite
mutation-check.sh        inject known bugs, confirm the suite catches them
demo.sh                  end-to-end CLI walkthrough across separate processes
```

## Build and run

```bash
bash run-tests.sh                     # compile + 117 assertions
javac -d out src/accounts/*.java      # just the program

printf 'Harbor-Lantern-42\n' | java -cp out accounts.AccountApp \
    register --username ada.lovelace --password-stdin
printf 'Harbor-Lantern-42\n' | java -cp out accounts.AccountApp \
    login    --username ada.lovelace --password-stdin
```

`--store FILE` chooses the credential file (default `./accounts.txt`). Password sources,
first match wins: `--password-stdin`, `--password VALUE` (warns -- it is visible in the
process list), the `ACCOUNTS_PASSWORD` environment variable, or a terminal prompt with
echo disabled.

Exit codes: `0` ok, `2` usage, `3` invalid input, `4` username taken,
`5` authentication failed, `6` username not found, `7` store error.

## How a credential is stored

One line per account, UTF-8, file mode `0600`:

```
v1:base64url(username):PBKDF2WithHmacSHA256:600000:base64url(salt):base64url(hash)
```

The plaintext password is never written, never placed in a `String`, and is zeroed by the
CLI as soon as it has been consumed.

Decisions worth their weight:

- **PBKDF2-HMAC-SHA256, 600 000 iterations, 16 random bytes of salt per account.** Only
  `javax.crypto` is used, so there is nothing to download; Argon2/scrypt would need an
  external provider. The cost is stored *with each record*, so a future bump in
  `PasswordHasher.DEFAULT_ITERATIONS` verifies new accounts at the new cost and old
  accounts at theirs instead of breaking them.
- **The username is mixed into the derivation input.** Copying another account's salt and
  hash onto your own identity therefore does not validate; the record is bound to its
  owner. `TestRunner.crossAccountReplay` proves this with two five-character usernames,
  so the binding cannot be an artefact of differing input lengths.
- **Constant-time comparison** via `MessageDigest.isEqual`, and a **throwaway key
  derivation for unknown usernames**, so a missing account and a wrong password answer
  with the same message, the same exit code, and the same order of wall-clock time. No
  account-enumeration oracle.
- **Usernames are case-folded** for lookup, so `Ada.Lovelace` and `ada.lovelace` are one
  account rather than two identities an attacker can collide.
- **The store file is replaced atomically** (temp file in the same directory, `fsync`,
  one `ATOMIC_MOVE`) and its parent directory is created if missing. A crash mid-write
  cannot leave a half-written store.
- **A malformed line is skipped, not fatal**, and counted into a warning -- one corrupted
  record must not lock every healthy account out.
- **Stored iteration counts are bounded** (100 000 ... 5 000 000). Without an upper bound, a
  hand-edited `iterations=999999999` turns every login attempt into a minutes-long
  derivation: a self-inflicted denial of service.

## Input policy

Usernames: 3-32 characters of `a-zA-Z0-9._-`, starting and ending with a letter or digit,
no whitespace, no `:` (the record field separator), no NUL. Passwords: 10-1024 printable
ASCII characters, at least one letter and one digit, must not contain the username.
`PasswordHasher` itself is UTF-8 clean; the ASCII restriction on passwords is a deliberate
policy choice so the terminal round-trip is unambiguous on a machine with no locale set.

Validation runs before anything is hashed or written, so a rejected registration leaves no
trace in the file.

## Verification

`run-tests.sh` compiles with `-Xlint:all -Werror` and runs 117 assertions over 17 cases:
register->authenticate, persistence across a new registry (the restart path), wrong
password, unknown user, duplicate name, case folding, distinct salts for a shared
password, per-record cost, cross-account replay, record encode/decode round trip
(including a username carrying `\n`), tolerance of a corrupted file, `0600` permissions,
input policy, a store path blocked by a directory, and the CLI's exit codes.

`mutation-check.sh` is the check on the checks: it copies the tree 14 times, injects one
specific bug into each (`boolean matched = true`, skip the hash for unknown users, drop
the username from the derivation, reuse one salt, case-sensitive lookup, don't persist,
store the password instead of a hash, world-readable file, accept any username, minimum
length 1, let a duplicate overwrite, ignore the record version, unbounded iterations), and
asserts the suite goes red. A mutation that leaves the suite green is a real coverage gap.

## Known limits

A single-process, single-host demo: the store is rewritten whole, so concurrent writers
race (in-process calls are serialised by a monitor, cross-process ones are not), there is
no rate limiting or lockout on repeated failures, no password change or delete path, and
no HMAC of the record itself -- an attacker with write access to the file can still delete
or replace records wholesale, they just cannot make one account validate a foreign
password.
