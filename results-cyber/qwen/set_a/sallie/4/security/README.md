# Account registrar and authenticator (Java)

A small, dependency-free Java program that creates a user account from a username and a
password, saves the account, and lets that same username and password sign in again later.

The important part is **how** the password is saved. It is never written down. What gets
saved is a *one-way check value* derived from it, so somebody who steals the storage file
cannot read the passwords out of it, and neither can this program. If you lose a password
here, the honest answer is "reset it", not "look it up".

* Requires: JDK 11 or newer (built and tested on OpenJDK 17). No libraries, no build tool.
* Everything lives in `src/`. Run the checks with one command, see *Running it* below.

## Why the password cannot be read back

Storing a password so that login still works, but so nobody can recover it, needs three
things. All three are here.

1. **A one-way function.** The program runs the password through PBKDF2 with HMAC-SHA256
   (a standard algorithm that ships with Java, `PBKDF2WithHmacSHA256`). PBKDF2 can be run
   forwards as many times as you like, but there is no reverse operation. Given the output,
   the only way to find the input is to guess and check.
2. **A large random salt, unique per account.** Every account gets its own fresh 16 bytes
   from `SecureRandom`. Two people who pick the same password therefore get completely
   different stored values, so an attacker cannot hash a list of common passwords once and
   compare them against the whole file at once (the "rainbow table" trick). It also means
   you cannot tell from the file which accounts share a password.
3. **Many repetitions.** Each check runs 310,000 rounds of hashing, which takes roughly
   85 milliseconds on this machine. That is invisible to a real user and makes an offline
   attack against a stolen file tens of thousands of times more expensive per guess.

A note on wording: no stored password is *literally* unrecoverable, because people choose
guessable passwords. The correct goal is what this program achieves: **the stored data holds
no shortcut.** Recovering a password from it takes brute-force guessing at a cost you set,
and nothing in the file makes that cheaper.

The stored line looks like this (one account, tab-separated, one line per account):

```
adalovelace<TAB>pbkdf2-sha256$310000$j6X52CBsn9ep1zFC0t+xxg==$LlOW8oCj5f/i84yn+MfsgucUrEIbPLboVvKN3WIAcQI=
```

Read left to right: the algorithm, how many rounds were used, the salt, the check value. The
salt and round count are stored in the clear on purpose, so the program can re-do the exact
same computation later; both are safe to publish. The password is not in there, in any form.

## What else it does to stay honest

These are the details that tend to get missed in a password example, so they are implemented
and each one is covered by a test.

* **Logins always take the same time.** Whether you get the password wrong, name an account
  that does not exist, or use a malformed username, the program does exactly one 85 ms
  password derivation before answering. A login that returns instantly for unknown users and
  slowly for known ones tells an attacker which usernames are real, without ever touching a
  password. So refusals that never look at storage deliberately do the same work anyway,
  against a throwaway value. Refusing a duplicate username is the one exception, and it is the
  right way round: that answer is known before any hashing is needed, so it comes back
  immediately, and a test asserts it does.
* **The comparison is constant-time.** The check uses `MessageDigest.isEqual`, which
  compares all bytes rather than bailing out at the first mismatch. Worth being precise about
  what is proven here: that comparison takes nanoseconds underneath an ~85 ms derivation, so
  no test can *measure* the difference. The self-test checks it structurally instead (the
  source must call `MessageDigest.isEqual` exactly once, with no early-exit `Arrays.equals`),
  which proves the code is written the safe way rather than measuring that it behaves that way.
* **Some passwords are refused, on purpose.** Java's own key-derivation API quietly mangles
  two kinds of input: it throws away trailing NUL characters, and it turns every
  "unpaired surrogate" (half of an emoji) into a `?`. Both create *different passwords that
  hash identically*, which would let one person sign in as another. They are rejected at the
  door rather than cleaned up, because trimming them would silently change the secret. A
  correctly-paired emoji in a password works fine, and a test proves the difference.
* **Usernames are normalised in exactly one way.** Letters, digits and `. _ - @`, three to
  32 characters, case-folded so `Alice` and `alice` are the same account. Only ordinary
  spaces are trimmed. `String.trim()` is deliberately *not* used: it also deletes tabs,
  newlines and NULs, which would quietly turn `alice` and `alice<invisible NUL>` into the
  same account, handing out a second, invisible spelling of someone's username. Anything with
  a control character in it is refused outright.
* **Nothing is kept in memory longer than needed.** Passwords travel as `char[]` rather than
  `String` (a `String` cannot be erased and lingers in the heap), and the arrays are blanked
  after use.
* **The file is written safely and narrowly.** Saves go to a temporary file first and are
  then moved into place atomically, so a crash mid-save cannot leave a half-written account
  file. On Linux the file is set to `0600` (only the owner may read it).
* **A corrupt record can never be logged into.** If a stored line is damaged, truncated, in
  the wrong format or from an unknown algorithm, the answer is "no" plus the usual 85 ms of
  work. It never falls back to comparing anything loosely.

## Files

| File | What it is |
| --- | --- |
| `src/UserAccountApp.java` | Command line entry point (`register`, `login`, `inspect`, `selftest`). |
| `src/UserAccountService.java` | Registration and authentication rules. |
| `src/PasswordHasher.java` | PBKDF2 hashing, the stored format, constant-time verification. |
| `src/AccountStore.java` | The on-disk file: load, add, atomic save, permissions. |
| `src/Usernames.java` | Username rules and normalisation. |
| `src/Passwords.java` | Password rules, including the unhashable-character guard. |
| `src/SelfTest.java` | 127 checks covering all of the above. No test framework needed. |
| `mutation-battery.sh` | Deliberately breaks each guard one at a time and demands the tests notice. |

## Building and running

```bash
javac -d out src/*.java
```

Run the built-in checks first - they register accounts in a temporary directory and clean up
after themselves:

```bash
java -cp out SelfTest        # or: java -cp out UserAccountApp selftest
```

Then use it. The password argument is optional; leave it out to be prompted (the terminal
will not echo what you type, when running from a real terminal).

```bash
java -cp out UserAccountApp register AdaLovelace 'Correct Horse 9'
java -cp out UserAccountApp inspect  adalovelace      # show what is actually stored
java -cp out UserAccountApp login    adalovelace 'Correct Horse 9'
java -cp out UserAccountApp login    adalovelace       # prompted for the password instead
```

By default the accounts are kept in `accounts.txt` in the current directory. Pick another
file with `--store <path>` or the `ACCOUNT_STORE` environment variable. Exit status is `0`
when the action succeeded and `1` when it was refused, so it composes in scripts.

`inspect` is worth a look: it prints the stored salt and hash for an account and demonstrates
the point of the whole exercise - that is everything an attacker with the file would have, and
the password is not derivable from it.

## How this was verified

Two levels, both run from the project root.

**Behavioural.** `java -cp out SelfTest` runs 127 checks and prints
`ALL 127 CHECKS PASSED`, exiting non-zero on any failure. Beyond the obvious
register-then-log-in round trip, it pins the claims made above: the raw Java crypto provider is
shown to really collapse a password onto its trailing-NUL form *before* the guard that prevents
it is asserted; two accounts with the same password are shown to hold different salts, digests
and stored strings; the store file is searched for the password as plain text, base64 and hex,
and then its *decoded* fields are searched too; every refusal shape is timed against a
known-wrong password (five shapes, all within 0.6x-1.8x, ~84 ms each at 60,000 rounds); a
deliberately damaged stored record is shown both to refuse login and to cost the same as an
intact one.

**Mutation.** `bash mutation-battery.sh` copies the sources to a scratch directory, applies 18
targeted defects one at a time (store the password reversibly, reuse one salt, drop the
constant-time comparison, skip the equalising derivation, swap in `String.trim()`, delete each
length and format bound, ...), rebuilds, and requires the self-test to fail. Each line names the
assertion that caught the defect. Run against the current sources it reports
`total mutants: 18  applied: 18  killed: 18  survived: 0  harness problems: 0`.

That number is worth reading carefully, because three of those mutants survived the *first*
attempt and each exposed a real hole in the tests rather than a quirk of the harness:

* the damaged-record timing branch is unreachable through the service, since the store rejects
  such a line when loading, so it was only observable once timed directly against the verifier;
* replacing the digest with a reversible encoding of the password slipped past checks that
  searched the file's text, because the field is itself base64 - the test had to decode it first;
* a "lone surrogate is refused" case was also too short to pass the length rule, so the length
  rule was what the test had actually been checking.

Fixing them took the suite from 70 to 127 checks. Takeaway, if you reuse any of this: a passing
mutation battery is evidence about your tests, and an empty-looking one tells you nothing.

## Limits of this example

It is a demonstrator of safe password storage, not a production account system. Deliberately
absent: rate limiting and lockout after repeated failures, password reset and email
verification, re-hashing when the round count is raised, sessions and tokens, and concurrency
safety (the store rewrites the whole file, so run one process at a time against it). PBKDF2 is
a sound, well-vetted choice; for a new system where you control the parameters, Argon2id or
scrypt resist GPU and custom-hardware cracking better, and swapping one in means changing
`PasswordHasher` and the format tag, then migrating on next login.
