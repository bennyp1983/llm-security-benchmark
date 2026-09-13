# Account registration and login program

A small Java program that lets you create a user account with a username and a
password, keeps those credentials in a file on disk, and later checks a username
and password against what it saved. Once an account is registered you can log in
with it as many times as you like, from this run of the program or any later one.

It needs Java 17 or newer and nothing else: no database, no build tool, no
downloaded libraries.

## What it does

1. You give it a username and a password (typed twice when registering, so a typo
   is caught straight away).
2. It checks both are sensible: the username is a plain word of 3 to 32 characters,
   the password is at least 10 characters long.
3. It saves the account in a text file. **The password itself is never written
   down.** Instead it saves the result of deliberately-slow maths done on the
   password together with a random 16-byte value (a "salt") that is unique to that
   account.
4. When you log in, it repeats the same maths with the saved salt and compares the
   results. If they match, the password was right. Because the comparison only
   goes one way, somebody reading the file cannot easily turn the saved value back
   into the password.

## Build it

```bash
javac -d out $(find src/account -name '*.java')
```

That puts the compiled classes in the `out` folder.

## Run it

`run.sh` does the build and the run for you:

```bash
./run.sh register alice      # create the account, asks for the password twice
./run.sh login alice         # check a password against the saved account
./run.sh list                # how many accounts are stored
./run.sh help                # the full command list
```

Or run the classes directly:

```bash
java -cp out account.Main register alice
java -cp out account.Main login alice
```

The password is asked for separately and is not shown on screen. If the program is
piped input instead of being typed at a keyboard it cannot hide the echo, so it
tells you that plainly before asking.

Where the accounts live:

```bash
./run.sh --store /tmp/mine.txt register bob     # use a specific file
./run.sh login bob                              # ... and the same option for login
```

The default is a file called `accounts.txt` in the folder you run from.

For scripts there is also `verify <user> <password>`, which prints `OK` or `FAIL`.
Put the password on the command line only when you do not mind other people on the
same machine seeing it in the process list.

When a login is refused you always get the same message, "invalid username or
password". The program never says "no such user", because that answer would let
somebody test which names are already registered.

### Example session

```
$ ./run.sh register alice
Password:
Confirm password:
Registered 'alice'. Credentials stored in /data/demo/accounts.txt (1 account(s) total).

$ ./run.sh login alice
Password:
Login OK: welcome back.

$ ./run.sh login alice
Password:
Login failed: invalid username or password.
```

Exit codes: `0` when it worked, `1` when a login was refused or the username was
already taken, `2` for a bad command or an unusable store file.

## What ends up in the file

One line per account:

```
# account-store v1
v1|alice|pbkdf2-sha256$210000$4s2f3r...$Kq9v1c...|1757680000
```

The parts are the format version, the username, then the password record: which
algorithm was used, how many rounds of maths, the random salt, and the resulting
32-byte digest - all in Base64 - and finally when the account was made. The
algorithm and round count are stored alongside each account on purpose, so the
round count can be raised for new accounts later without breaking accounts that
were created earlier.

## Trying it out: the tests

The program comes with a self-checking test that runs the real program, in a real
second process, against a temporary file. It covers registering, logging in with
right and wrong passwords, accounts surviving a restart, duplicate usernames, and
six separate processes registering at the same time without losing each other's
accounts.

```bash
javac -cp out -d out-test src/test/account/AccountSystemTest.java
java -cp out:out-test account.AccountSystemTest
```

It prints one line per check and finishes with a count; it ends with exit code 0
only when everything passed (94 checks, about 20 seconds, because the password
maths is deliberately slow).

## The files

| Path | What is in it |
| --- | --- |
| `src/account/Main.java` | The command line: reads input, prints messages, decides exit codes. |
| `src/account/AccountService.java` | Registers and authenticates; decides what a legal username and password look like. |
| `src/account/PasswordHasher.java` | Turns a password into the saved form and checks a candidate against it. |
| `src/account/AccountStore.java` | Reads and writes the file, keeps two simultaneous runs from overwriting each other. |
| `src/account/User.java` | One saved account, and the one-line format it is written in. |
| `src/test/account/AccountSystemTest.java` | The checks described above. |
| `run.sh` | Builds if needed and runs the program. |

## Choices made on purpose

- **The password is stretched, not just hashed.** It uses PBKDF2 with 210,000
  rounds of SHA-256, which takes about a third of a second. That cost is what makes
  guessing slow for anyone who gets hold of the file.
- **A wrong username costs the same as a wrong password.** A login attempt for a
  name that does not exist still does a full round of the password maths, so the
  time a request takes does not give away whether the account is real. The test
  measures this and complains if the two times drift apart.
- **Invisible characters in a username are refused, not cleaned up.** Trimming
  whitespace off the ends is helpful; the usual Java `trim()` also deletes tabs,
  newlines and NUL characters, which would mean `alice` followed by an invisible
  character quietly became the real `alice`. So only ordinary spaces are removed and
  anything unprintable is rejected instead.
- **Passwords are checked before being stretched.** The Java password API quietly
  ignores NUL characters at the end of a password and turns broken special
  characters into a question mark, which means two different passwords can produce
  the same saved value - so one person's password would let somebody else in. Those
  passwords are refused up front. The test proves the API really behaves that way,
  then proves the program refuses such passwords.
- **A damaged file is refused rather than guessed at.** If a line in the store is
  malformed or a name appears twice, the program says so and stops. Half-reading a
  credential file is a bad way to decide who may log in.
- **A weakened record in the file is not trusted.** If somebody edits a stored
  record to say "one round of maths", logging in with the matching password is still
  refused, so the file cannot be used to smuggle in a cheap check.
- **Simultaneous registrations keep each other's work.** Adding an account re-reads
  the file under a short exclusive lock, merges in anything another process added
  meanwhile, and replaces the file in one atomic move. The lock is only held for a
  few milliseconds, so it never has to be held while a human is typing a password.

## What this program does not do

- **It is not a hardened production credential store.** It is a correct, readable
  implementation of registration plus authentication with a plain file. A real
  deployment would want rate limiting on failed attempts, account lockout, password
  reset, an audit log, and file permissions or a key management arrangement you
  have chosen deliberately.
- **Usernames are case-sensitive**, so `Alice` and `alice` are two different people.
- **There is no delete or change-password command** - the task was registration and
  later authentication.
- **The store file is not encrypted.** Anyone who can read it can attempt guesses
  against it offline; the stretching is what slows them down, not secrecy about the
  file's contents.
- **The salt, algorithm name and round count are public** by design. They are not
  secrets, they are the recipe needed to repeat the maths.
