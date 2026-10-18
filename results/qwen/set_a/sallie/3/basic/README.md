# Signing in with an email address and a password

A small Java program that checks a pair of credentials - an email address and a password -
against accounts saved in a SQL database, and then says one of two things:

```
Authentication successful.
```

or

```
Authentication unsuccessful.
```

It is a single Java file with no build tool and no framework. Everything it needs is in the JDK
and one JDBC driver jar.

## What is in this folder

| Path | What it is |
| --- | --- |
| `src/AuthenticationApp.java` | the program |
| `test/AuthenticationAppTests.java` | checks for the program (179 of them) |
| `tools/mutation-check.py` | injects 22 deliberate defects, to prove the checks really bite |
| `run-tests.sh` | compiles both and runs the checks |
| `README.md` | this file |

## What you need

* Java 17 or later (`javac -version`, `java -version`).
* A JDBC driver jar for the database you want to talk to. The examples here use
  [H2](https://h2database.com), a database that runs inside the program with no server to
  install. If you would rather use PostgreSQL, MySQL, MariaDB, SQL Server or anything else, drop
  that driver on the class path instead and give the program its connection URL - nothing in the
  code is H2 specific.

## Building it

```sh
mkdir -p out
javac -d out src/AuthenticationApp.java
```

That is the whole build. To run anything, put the compiled classes and the driver on the class
path:

```sh
java -cp out:/tmp/h2/h2.jar AuthenticationApp --help
```

## Setting up the database

The program expects one table:

```sql
CREATE TABLE app_user (
    email         VARCHAR(254) NOT NULL PRIMARY KEY,
    password_hash VARCHAR(512) NOT NULL
);
```

`init` creates it for you if it is not there already, and leaves it alone if it is:

```sh
export DB_URL='jdbc:h2:./auth-demo'
java -cp out:/tmp/h2/h2.jar AuthenticationApp init
```

Output:

```
Database schema is ready.
```

Email addresses cannot repeat, because the address is the table's key. If you prefer to create the
table yourself, run the SQL above - the program does not need `init`, it only needs a table called
`app_user` with those two columns.

## Saving an account

`add` takes an email address and hashes a password for it. The password is read from an environment
variable when that variable is set (handy for scripts); otherwise the program asks you to type it,
and what you type is not shown on screen.

```sh
DEMO_PASSWORD='correct horse battery staple' \
  java -cp out:/tmp/h2/h2.jar AuthenticationApp add alice@example.com
```

Output:

```
Password stored.
```

## Signing in

```sh
DEMO_PASSWORD='correct horse battery staple' \
  java -cp out:/tmp/h2/h2.jar AuthenticationApp login alice@example.com
```

```
Authentication successful.
```

Get the password wrong, or use an address nobody registered, and you get the other line:

```sh
DEMO_PASSWORD='wrong' \
  java -cp out:/tmp/h2/h2.jar AuthenticationApp login alice@example.com
```

```
Authentication unsuccessful.
```

This is on purpose: the program never tells you whether the address exists or whether just the
password was wrong. That difference is what attackers use to collect lists of real accounts.

## Options and exit status

| Option | Meaning |
| --- | --- |
| `--url <jdbc-url>` | where the database is. Also read from `DB_URL`. Default `jdbc:h2:./auth-demo` |
| `--db-user <name>` | database user. Also read from `DB_USER`. Default `sa` |
| `--password-env <VAR>` | which environment variable to read the **sign-in** password from. Default `DEMO_PASSWORD` |
| `--help` | print the list of commands |

The **database's own** password is read only from the environment variable `DB_PASSWORD`, never
from a command line argument, because arguments show up in other people's `ps` output and in shell
history.

`login` also answers through its exit status, so scripts can branch on it:

| Exit status | Meaning |
| --- | --- |
| `0` | accepted - the email address and password go together |
| `1` | refused - wrong password, unknown address, or the database could not be read |
| `2` | the address or password was not in a form the program accepts |
| `3` | usage problem, or the account could not be saved |

Anything written to standard error is for the person running the program. The decision itself is
always exactly one line on standard output.

## How the check works

1. **The address is tidied.** Spaces around it are removed and it is folded to lower case, so
   `Alice@Example.com` and `alice@example.com` are the same account. The same tidy-up happens when
   an account is saved and when it is looked up, which is what makes the two agree. Addresses that
   are not shaped like addresses are refused straight away, without touching the database.
2. **One question is asked of the database**, and only about the address:

   ```sql
   SELECT password_hash FROM app_user WHERE email = ?
   ```

   The `?` is filled in by JDBC as a *value*, never pasted into the sentence itself. That is what
   stops the classic trick where somebody types an email address of `' OR '1'='1` and talks the
   database into handing over a row. The same applies when saving an account.
3. **The password never goes to the database.** Only the email address is sent. The stored value is
   compared with the typed password here, in the program.
4. **The comparison decides it.** If the password reproduces the stored hash the answer is
   successful, otherwise unsuccessful.

## How passwords are stored

Passwords are never stored as text. What goes into `password_hash` looks like this:

```
pbkdf2-sha256$120000$<16 random bytes>$<32 byte result>
```

* **PBKDF2 with HMAC-SHA256**, run 120,000 times. It is deliberately slow, which makes guessing
  passwords from a stolen copy of the table expensive.
* **A fresh random 16 byte salt per account**, so two people who choose the same password get
  different stored values, and a list of pre-computed guesses is useless.
* **The cost is written into the stored value.** A future version can raise the number for new
  accounts while still being able to check old ones.
* Only the result is kept. There is no way to read a password back out of it.

A stored value that is not in that shape - a plain-text password someone pasted in, a truncated
hash, a made-up cost - is always refused rather than trusted.

The program refuses some input rather than quietly doing something surprising with it: an empty
password, a password longer than 1024 characters, and passwords containing a NUL character or an
unpaired half of a surrogate pair. Those last two matter because Java's password-key class maps
them onto *other* passwords, so two different passwords could end up sharing one stored value.

## Two things worth knowing about the timing

Deciding "no such account" and deciding "wrong password" take the same amount of time. When no row
matches, the program still does a full hash calculation before answering. If it answered instantly
for unknown addresses, an attacker could time the responses to find out which email addresses have
accounts here. The checks measure this: on this machine both refusals took about 176 ms.

Input that is refused before the database is asked (an empty password, a malformed address) comes
back fast, which does leak a little - it says only that what was typed is not a valid address or
password shape, which the person typing it already knows.

## If the database cannot be reached

The sign-in is refused, never granted. A database that is down, a wrong connection URL, a missing
driver - all of them end with `Authentication unsuccessful.` and exit status 1, with the reason on
standard error. Saving an account in the same situation reports exit status 3, because there the
caller needs to know the write did not happen.

## Running the checks

```sh
./run-tests.sh
```

The script compiles the program and the checks and runs them. It looks for the driver at
`/tmp/h2/h2.jar`; point it somewhere else with `H2_JAR=/path/to/your.jar ./run-tests.sh`. The last
line reads `RESULT: PASSED` and the exit status is 0 when everything holds.

The checks cover, among other things:

* the happy path and every way to get it wrong, run against real in-memory H2 databases;
* the whole program driven as a separate process, checking the exact line it prints and the exit
  status it returns;
* quoting attacks (`' OR '1'='1`, `'; DROP TABLE app_user; --`) and wildcard addresses (`%`, `_`),
  proving they cannot sign in and never reach the SQL text;
* a fake JDBC driver that records the exact SQL sentences and bound values, so a value being
  pasted into a sentence instead of bound to it is caught immediately;
* stored values in every wrong shape - plain text, truncated, wrong cost, wrong algorithm name -
  none of which may open an account;
* both refusals taking the same time, so the difference cannot be used to list accounts.

Both kinds of database check are used on purpose. The fake driver sees the SQL text; a real engine
sees a predicate that now matches too much (replacing `email = ?` with `email LIKE ?` slips past the
fake driver and is caught by H2). They catch different mistakes.

### Proving the checks actually bite

A suite that passes proves nothing until you know it would notice a broken program.
`tools/mutation-check.py` injects 22 deliberate defects - the lookup comparing with `LIKE`, the
address pasted into the SQL text instead of bound, the password stored as text, one salt for every
account, a broken database reported as a signed-in session, a refusal exiting 0, and so on - and
reports whether the suite fails because of each one:

```sh
python3 tools/mutation-check.py
```

All 22 are currently killed, so every one of those defects would be caught. Two of them were
survivors when the checks were first written, which is how two weak checks were found and replaced:
the fixtures for "stored hash of the wrong length" and "stored cost below the floor" were each broken
in a *second* way as well, so a different guard rejected them and the guard under test was never
reached. The replacement fixtures are invalid in exactly one way.

## Handy flags for demo or test databases

If you want a throwaway database that lives only while the program runs, add the H2 in-memory flag:

```sh
DB_URL='jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1' java -cp out:/tmp/h2/h2.jar AuthenticationApp init
```

To keep several test runs apart on the same machine, give each its own URL.

## Pointing it at a real database

Nothing here is H2 specific. For PostgreSQL, for example:

```sh
export DB_URL='jdbc:postgresql://db.example.com:5432/accounts'
export DB_USER='accounts_app'
export DB_PASSWORD='...'
java -cp out:/path/to/postgresql.jar AuthenticationApp login alice@example.com
```

Give that user permission on `app_user` and nothing else. The program reads one table and writes one
row at a time; it never needs to create or drop anything unless you run `init`.
