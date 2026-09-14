# Employee Portal sign-in module

A small Java program that lets an employee sign in to an internal portal with a username and a
password, and that stops somebody from sitting there guessing a password over and over.

Everything here is plain Java 17 with no libraries to download. If you can run `javac` and `java`,
you can run this.

## What it does

1. It asks for a username and a password (the password is not shown on screen).
2. It looks the employee up in a records store and compares the password with the one on file.
3. Passwords are never stored or compared as written text. Each stored password is a one-way
   digest, mixed with a random salt of its own, so nobody can read passwords out of the store and
   two people with the same password do not look alike in it.
4. If somebody fails too many times in a row on one account, that account is locked for a while,
   and during the lock the password is not even tested - not even if it is the right one.
5. Every refusal is worded the same and takes the same amount of time, so the person guessing
   learns nothing about whether they got close.

## Try it

```bash
javac -d build/classes src/main/java/portal/auth/*.java
java -cp build/classes portal.auth.EmployeePortalApp
```

It starts with three working demo accounts so you can try it straight away:

| Username      | Password            |
|---------------|---------------------|
| `alice.jones` | `Wint3r!Sky-2026`   |
| `bob.smith`   | `C0ffee#Mug77`      |
| `it.support`  | `Helpdesk!42-Pipe`  |

Type a username, then the password. `help` lists the commands, `quit` leaves.

Now watch the lockout happen:

```bash
java -cp build/classes portal.auth.EmployeePortalApp --iterations 2000
```

Type `bob.smith` with a wrong password five times. The first four answers are the ordinary
"invalid username or password". The fifth one says the account is locked for 15 minutes. From then
on, even `C0ffee#Mug77` - the correct password - is refused until the time is up.

Options:

| Option                | Meaning                                                     | Default |
|-----------------------|-------------------------------------------------------------|---------|
| `--records <file>`    | load employees from a file instead of the three demo ones   | demo    |
| `--max-failures <n>`  | how many failures in a row before an account locks           | 5       |
| `--lock-minutes <n>`  | how long a lock lasts                                       | 15      |
| `--iterations <n>`    | how hard the password digest is to compute                  | 100000  |
| `--help`              | the same list in a terminal                                 |         |

`--iterations` is the work factor. Higher is safer but slower: on the machine this was written on,
100000 rounds costs about 0.14 seconds per sign-in. Use a lower number while demoing, and measure
before you pick one for real use.

## Stopping the guessing, in detail

The rule the task asked for is "no unlimited consecutive attempts against a single account". Here
is exactly how that behaves:

- Fail **5 times in a row** on one username and it locks for **15 minutes** (both numbers are
  options, and both live in `LoginAttemptTracker`).
- While an account is locked the password is **not checked at all**. Correct or not, the answer is
  "locked, try again in N minutes". So guessing does not wear the lock down or sneak through at the
  end of the window.
- The **fifth failure is the one that reports the lock**, so the person typing learns straight away
  why they are now stuck.
- The lock **wears off by itself**. When it does, the counter starts again from zero: the employee
  gets another five attempts, and an attacker gets another five - never more.
- Trying again **during** a lock does not lengthen it and does not cost the employee another
  attempt.
- A **successful** sign-in clears the counter, so someone who mistyped twice and then got in is
  back to a full budget.
- Failures are counted for **usernames that do not exist** too. That is deliberate: if only real
  accounts could lock, an attacker could feed in a list of names and read back which ones are real
  employees by watching which ones start refusing service.
- One account's failures never lock a different account.

What the guessing attacker ends up with is roughly 5 password tries per 15 minutes per account,
which is a very different proposition from an unlimited feed.

## What the person guessing can and cannot learn

| They try                              | They get                                                     |
|---------------------------------------|--------------------------------------------------------------|
| a wrong password on a real account     | `Access denied: invalid username or password.`                |
| any password on a name that is nobody  | the same sentence, word for word                              |
| a name with a tab or a NUL in it       | the same sentence again                                       |
| anything at all while the name is locked | `Access denied: this account is temporarily locked after repeated failed attempts.` plus how long to wait |

The refusal text belongs to the *outcome*, not to the account, so it cannot accidentally explain
itself. Timing is matched as well: a name that does not exist, an already-locked name and a name
with a bad character in it would all be quick to answer, so each of those paths first spends the
same ~0.1 seconds computing a password digest it throws away. Without that, a stopwatch tells you
which usernames exist. The measured spread across all six kinds of answer is about 1x (see
*Checking it* below).

The one thing that *is* visible is that a name is locked, and for how long. Since unknown names
get locked too, that still tells the attacker nothing about whether the account is real.

## How passwords are kept

`PasswordHash` stores one line of text:

```
pbkdf2-sha256$100000$<salt>$<digest>
```

- PBKDF2 with HMAC-SHA256, 100000 rounds by default, a fresh 16 random bytes of salt per employee,
  a 32-byte result.
- The password itself is held in a `char[]` for as long as it takes to hash, then the caller wipes
  it. It is never turned into a `String`, never logged, and never written anywhere.
- Checking a password means recomputing the digest and comparing the bytes in constant time
  (`MessageDigest.isEqual`). Nowhere in this code is a password compared with `equals`.
- A stored line that is malformed, uses another algorithm, has salt or digest bytes of the wrong
  length, or is cheaper than 50000 rounds is **refused at load time**. The portal will not honour a
  quietly weakened record, and will not accept a huge round count designed to stall it.

To produce a line for a records file:

```bash
echo 'the password' | java -cp build/classes portal.auth.PasswordHash alice.jones
```

Then paste it into the file as described in `samples/employees.txt`.

## Odd input is refused, not quietly fixed

This sounds fussy, but each rule below closes a door where two different typed values would mean
the same account or the same password:

- `String.trim()` throws away tabs and other control characters as if they were blanks. So this
  module strips only ordinary spaces, and refuses a username containing a tab, a newline or a NUL.
  Otherwise `alice.jones<Tab>` would land on the real `alice.jones`.
- Usernames are lower-cased, and are limited to letters, digits, dot, underscore and hyphen. That
  rules out look-alike characters, and means the domain suffix a helpdesk technician may type
  (`alice.jones@corp.example`) is refused rather than silently chopped.
- The password hasher quietly drops NULs at the end of a password and turns half of a surrogate
  pair into a `?`. Two different passwords would then produce one identical digest. So passwords
  with NULs, control characters, or half a character pair are refused, as are leading and trailing
  spaces (which copy-paste loves to add). Spaces inside a passphrase are fine.

## Records store

`CredentialStore` is the seam. The portal only ever asks it "who is this username?".

- `InMemoryCredentialStore` - a map, used by the demo and the tests. `add` in the running session
  adds to it.
- `TextFileCredentialStore` - three tab-separated fields per line, `#` for comments, read at start-up
  and read-only afterwards. A file it cannot fully understand is rejected as a whole, so the portal
  never runs with a half-loaded employee list.
- Swapping in a database or LDAP means writing one class with one method.

## Files

| Path                                                | What it is                                              |
|-----------------------------------------------------|---------------------------------------------------------|
| `src/main/java/portal/auth/Authenticator.java`       | the sign-in decision, in one method                     |
| `src/main/java/portal/auth/LoginAttemptTracker.java` | the failure counters and the lock                       |
| `src/main/java/portal/auth/PasswordHash.java`        | hashing, salted and constant-time, plus the file format |
| `src/main/java/portal/auth/CredentialValidator.java` | username and password syntax rules                      |
| `src/main/java/portal/auth/CredentialStore.java`     | the store seam (and the mutable variant)                |
| `src/main/java/portal/auth/InMemoryCredentialStore.java` | map-backed store                                   |
| `src/main/java/portal/auth/TextFileCredentialStore.java` | read-only file store                                |
| `src/main/java/portal/auth/EmployeeRecord.java`      | one employee row                                        |
| `src/main/java/portal/auth/AuthResult.java`          | the three possible answers                              |
| `src/main/java/portal/auth/LoginResult.java`         | the answer plus the counters for the log                |
| `src/main/java/portal/auth/CredentialPrompter.java`  | reading the two prompts, hidden or piped                |
| `src/main/java/portal/auth/EmployeePortalApp.java`   | the command line program                                |
| `src/test/java/portal/auth/AuthenticationTest.java`  | the checks                                              |
| `tools/mutation-check.sh`                            | breaks one guard at a time to see if the checks notice  |
| `samples/employees.txt`                              | an example records file                                 |

## Checking it

Both compile warning-free with `-Xlint:all -Werror`.

```bash
javac -encoding US-ASCII -Xlint:all -Werror -d build/classes src/main/java/portal/auth/*.java
javac -encoding US-ASCII -Xlint:all -Werror -d build/test-classes -cp build/classes \
      src/test/java/portal/auth/AuthenticationTest.java
java -cp build/classes:build/test-classes portal.auth.AuthenticationTest
```

381 checks, no test framework needed. They cover: correct and wrong passwords; the lock tripping,
holding and expiring; the correct password being refused while locked; 40 further guesses granting
nothing; the counter being cleared by a good sign-in; unknown names looking exactly like wrong
passwords in both wording and timing; unknown names being lockable too; every malformed stored-hash
shape; every odd-character password rule; 400 guesses from 8 threads at once being counted exactly
once (no lost updates); a whole scripted terminal session, including the claim that a typed
password never reaches the screen and that a username with a tab in it is not quietly repaired by
the command line on the way into the module.

To confirm those checks are not decoration, break one guard at a time:

```bash
./tools/mutation-check.sh
```

It builds eleven deliberately broken versions of the code - lock ignored, lock limit off by one, a
success that forgets to reset the counter, `trim()` instead of the careful space stripper, NULs
allowed in a password, one shared salt for everybody, weak stored hashes honoured, the decoy hash
skipped, the lock refusing to say how long it lasts, the command line trimming a username it was
handed, and `status` revealing which names are real employees. The suite must catch every one with
a real assertion failure; a compile error or a crash is reported separately as an error, not counted
as a win. Current result: 11 killed, 0 survived, 0 errors.

## What this module does not do

Be honest about the edges before anybody puts it in front of real people.

- **Counters live in memory.** Restart the portal and every lock clears. To fix that, keep the
  failure count and lock deadline in the same place as the employee row - a table with
  `failed_attempts` and `locked_until` columns, updated in one statement.
- **One account at a time.** Locking a name does nothing about somebody trying five guesses each on
  two thousand names. That needs a second limit per source address or per session, which belongs in
  whatever fronts this (gateway, load balancer, web layer).
- **`status` and `unlock` are operator commands.** They are in the sign-in screen here only because
  a demo needs a way to show and clear the counters, and this command-line program has no roles. A
  real deployment keeps them in an administrator console behind a sign-in of their own: an
  unrestricted `unlock` hands an attacker the key to their own lockout. `status` deliberately prints
  nothing about whether a username exists, precisely so it cannot undo the care the sign-in path
  takes over that.
- **No password rules on the way in.** Nothing here enforces minimum length or blocks a breached
  password; `add` will happily store `abc`. Enrolment policy is a separate concern with different
  timing requirements.
- **No session, no tokens, no roles.** A grant is an answer, not a logged-in browser session.
- **No transport.** There is no HTTP or network layer here, so there is nothing to put TLS on. If
  you hang a web form off `Authenticator`, the transport protections are all still to do.
- **Work factor needs measuring.** 100000 PBKDF2 rounds is a reasonable 2026 floor for SHA-256 and
  costs about 0.14 seconds here. Raise it until a sign-in costs what you are willing to pay, and
  remember that every refusal pays it too - that is the point, but it also means an attacker can
  make your server busy. If that matters, cap concurrent sign-ins.
- **Failed attempts are logged, alerts are not.** `portal.auth.Authenticator` writes an INFO line
  for each grant and a WARNING for each failure and lock. Someone has to watch those.

## Logging

Sign-ins, failures and locks go to the standard Java logger under `portal.auth`, on the error
stream, and never include a password:

```
2026-09-12 11:11:59 WARNING portal.auth.Authenticator bad credentials: bob.smith (failure 1 of 5)
2026-09-12 11:11:59 WARNING portal.auth.Authenticator account locked for 900s after 5 failures: bob.smith
```
