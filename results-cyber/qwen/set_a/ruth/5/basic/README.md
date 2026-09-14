# LoginService -- password-based authentication in Java

A self-contained implementation of user login: it accepts a username and password, verifies them
against stored account information, grants access when the credentials are correct, and refuses the
attempt when they are not.

No build tool, no dependencies, no database -- plain JDK 17 (`javac` / `java`).

## Files

| Path | What it is |
| --- | --- |
| `src/LoginService.java` | The implementation plus a runnable demo (`main`) and interactive console mode |
| `src/LoginServiceTest.java` | 123 assertions covering the behaviour below; exits non-zero on failure |
| `README.md` | This file |

## Compile and run

```sh
javac -d out src/LoginService.java              # compile the implementation
java -cp out LoginService                       # scripted demo
java -cp out LoginService -i                    # interactive console (needs a terminal)

javac -d out src/LoginService.java src/LoginServiceTest.java
java -cp out LoginServiceTest                   # run the checks; exit status 1 on failure
```

Sources are pure ASCII, so no `-encoding` flag is needed on any platform default charset.

The demo registers two accounts, tries correct and incorrect credentials, drives an account into
lockout, and prints how long each attempt took. Accounts live in memory only, so nothing survives
the process and no real credentials are involved.

Sample output (work factor 60,000 PBKDF2 rounds, so each attempt costs tens of milliseconds):

```
register alice: STORED
register bob  : STORED
stored digest : pbkdf2-sha256$60000$AI9Jjqxb7I79Fvn5Z4OXig==$1FMIv4/CHCAiZew/kKX0Tqp+cUsROVjyA9bLVWphFsY=

-- credentials --
alice      correct horse    -> SUCCESS             Authenticated.
alice      Correct horse    -> INVALID_CREDENTIALS Invalid username or password.
alice      correct horses   -> INVALID_CREDENTIALS Invalid username or password.
bob        Tr0ubador&x9     -> SUCCESS             Authenticated.
dave       correct horse    -> INVALID_CREDENTIALS Invalid username or password.
accounts now: 2 (the unknown name was not created)

-- lockout after five failures --
alice      guess-1          -> INVALID_CREDENTIALS Invalid username or password.
...
alice      correct horse    -> LOCKED              Account temporarily locked after repeated failed attempts.

-- one derivation per attempt, whoever is named --
carol      Tr0ubador&x9     -> INVALID_CREDENTIALS   85 ms
carol      wrong-password   -> INVALID_CREDENTIALS   86 ms
nobody     Tr0ubador&x9     -> INVALID_CREDENTIALS   87 ms
```

## How it works

`LoginService.login(username, password)` is the entry point. It returns a `LoginOutcome` record:

- `SUCCESS` -- credentials are correct; carries a random 256-bit session token. `granted()` is true.
- `INVALID_CREDENTIALS` -- the password is wrong, the account does not exist, the stored digest is
  unreadable, or the input was rejected before hashing. `message()` is the same sentence in all of
  those cases.
- `LOCKED` -- too many recent failures for that name; access is refused even with the correct
  password until the lock expires or an operator calls `unlock(name)`.

`register(username, password)` stores an account. It keeps only a digest, and returns
`STORED`, `INVALID_USERNAME`, `PASSWORD_REJECTED` or `DUPLICATE_USERNAME`.

### What is stored

Accounts hold `pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>`: PBKDF2-HMAC-SHA256, a
fresh 16-byte `SecureRandom` salt per registration, a 256-bit key, 210,000 rounds by default. The
password itself is never stored, logged, or returned, and the `char[]` the JCE works on is wiped
after each derivation.

Because the digest carries its own salt and round count, the work factor can be raised later
without invalidating existing accounts, and a legacy digest at a lower round count still verifies.

### Why every refusal costs the same

A login always performs exactly one key derivation, whichever branch it takes:

| Attempt | Work done |
| --- | --- |
| Correct password | one derivation against the stored salt |
| Wrong password, known account | one derivation against the stored salt |
| Unknown account | one derivation against a per-process dummy digest |
| Stored digest unreadable | one derivation against the dummy digest |
| Name rejected by validation | one derivation against the dummy digest |
| Locked account | one derivation against the dummy digest |
| Password this class refuses to hash | one derivation against the dummy digest |

A fast "no such user" answer is what lets an attacker enumerate which names have accounts, so the
unknown-account path deliberately pays for a full derivation with a digest built at runtime from
random bytes -- one no password can equal. The tests measure this rather than trusting it: they
time all five refusal shapes against a known-account wrong password and require the ratios to stay
in `[0.8, 1.3]`. A hand-written dummy digest constant would be unsafe here, because a value that
fails to decode skips the work silently and every functional test still passes.

`MessageDigest.isEqual` compares digests, so the comparison does not short-circuit on the first
differing byte.

### Which inputs are refused before hashing

`PBEKeySpec` converts the candidate with a lossy UTF-8 mapping: it drops trailing NUL characters and
turns every unpaired surrogate into `'?'`. Distinct passwords therefore collide onto one digest --
`"q"` + U+D800 and `"q"` + U+DC00 and `"q?"` all derive identically -- and anyone presenting one
could sign in as a user who enrolled another. Such candidates are rejected, not trimmed, because
trimming would silently change the secret; they still pay a derivation, so they are
indistinguishable from a wrong password. Interior NULs and correctly paired surrogates (emoji and
other astral characters) are unaffected and hash normally. The test suite derives through the raw
JCE to prove the collision is real, so the guard cannot be weakened without a failure.

Names are matched byte for byte against `[A-Za-z0-9._-]{3,32}` instead of being case- or
Unicode-folded: folding is not injective, so `"Alice"` is a different account rather than a way into
`"alice"`, and a Cyrillic lookalike of a real name is rejected rather than resolving onto it.

### Lockout

`LoginAttemptTracker` counts failures per name (default: 5 within 5 minutes locks for 15). It resets
on a successful login, expires on its own after both the failure window and the lock period, and
bounds its own memory by dropping expired entries, so guessing invented names cannot grow it without
limit. Counters are guarded per account, so concurrent logins of different users do not contend.

## Verifying it

`LoginServiceTest` prints one line per check and a summary (123 checks); it exits non-zero if any
check fails. It covers: correct credentials are accepted; 12 near-miss passwords are refused
(`Correct horse`, `correct horse `, `correct horses`, ...); unknown accounts are refused and never
created; refusal wording is one identical string for every failure shape; the cleartext never reaches
storage; each registration gets its own salt; digests carry and honour their own round count;
malformed encodings are rejected outright (wrong prefix, truncation, non-numeric or sub-floor round
count, invalid base64, short salt, short digest, extra field) and a salt/digest swap or a cleartext
value never verifies; a malformed stored record is refused without throwing; registration rules;
lockout, per-window expiry, lock expiry, and success resetting the counter; unique well-formed
session tokens; failed logins leaving the store untouched; 96 concurrent attempts across 8 threads;
lookalike and mixed-case names never resolving onto another account; the lossy-password guard and the
raw-JCE collision that motivates it; and the five measured timing ratios.

The suite was itself checked with a mutation battery: 26 targeted edits that each remove one
protection (accept any password, skip the dummy derivation for unknown accounts, drop the equal-work
charge, build the dummy digest at the floor work factor, accept trailing NULs or unpaired
surrogates, fold usernames case-insensitively at the guard or at the lookup, disable lockout, keep
the failure count after a success, let the failure window and the lock never expire, answer an
unknown account differently, ignore the stored round count, vary the refusal wording per case, store
the cleartext, reuse a fixed salt, drop the digest length and round-count validation, let a duplicate
registration overwrite, skip username validation, accept short passwords, ignore the lock, reuse a
session token, accept an account with an empty digest). Each mutant had to make at least one check
fail; a mutant that survived would mean the suite does not pin that behaviour.

**25 of the 26 were killed; the one survivor is a documented limitation, not a harness gap.**
Replacing `MessageDigest.isEqual` with `Arrays.equals` leaves the suite green, because the only
difference is that the comparison stops at the first differing byte -- tens of nanoseconds, buried
under an ~85 ms key derivation. That leakage is real but not measurable at this granularity, so no
assertion can pin it honestly; `MessageDigest.isEqual` is kept because the JDK specifies it does not
short-circuit. The equal-*work* property the suite does measure is the one that actually discloses
which accounts exist.


Timing checks are the reason the suite takes ~10 seconds: at 60,000 rounds each of the 35 timed
attempts costs tens of milliseconds, and both branches are warmed before measuring. A lockout would
short-circuit later attempts and fabricate a flattering ratio, so each sample uses a fresh account
and the tracker limits are deliberately generous.

## Plugging in a real store

`AccountStore` is the only persistence boundary; `InMemoryAccountStore` is the demo
implementation. A JDBC-backed store keeps the same digest format -- `find` returns the stored
`Account` for a name or `null`, `putIfAbsent` inserts only when the name is free. Keep the lookup
byte-exact (no `LOWER()`/`COLLATE` folding) so name matching stays injective.

Session tokens here are opaque random values that a caller would put into a signed cookie or a
server-side session record; this code authenticates the user and hands back a token, it does not
manage sessions, cookies, or HTTP.

## Known limits

- PBKDF2 is a defensible, dependency-free choice; memory-hard KDFs (Argon2id, scrypt) resist
  GPU/ASIC attacks better and are worth switching to if a library is acceptable.
- The default `PasswordHasher()` uses 210,000 rounds. On the machine this was written on that is
  roughly 300 ms per attempt; the demo and tests pass a lower figure to stay quick. Calibrate to
  your hardware and target latency.
- Lockout is per process and per name. A real deployment wants shared counters and, usually, an
  additional per-source-IP limit -- per-account lockout alone lets an attacker lock a known user out.
- Registration enforces only a minimum length (8 characters). Real deployments typically add
  composition rules and a breach-password check; `PasswordHasher.enrollmentRejection` is the hook.
- No rate limiting of the *whole* endpoint, no CAPTCHA, no MFA, no password reset, no audit trail
  beyond the logging calls that are present.
