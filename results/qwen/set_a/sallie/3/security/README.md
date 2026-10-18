# Email and password login for a SQL database (Java)

A small, complete Java program that signs a person in: it takes an email address and a
password, looks the account up in a SQL database, and prints whether the login succeeded.

The point of the exercise is the way it talks to the database. The email address and password a
person types are treated as *data*. They can never become part of the SQL statement, so they
cannot change what the query asks, add an extra condition, comment out the rest of it, or run a
second statement.

Requires Java 17 or newer. No framework, no build tool: `javac` and `java` are enough.

## Files

| File | What it is |
| --- | --- |
| `AuthenticationService.java` | The program: the login check, the credential storage format, and the command line. |
| `schema.sql` | The table it expects, with a unique index on the email column. |
| `AuthDoublesTest.java` | Verification suite 1. Checks what the program hands to the database driver. |
| `AuthH2Test.java` | Verification suite 2. Runs the same checks against a real database engine and the real command line. |
| `run-mutation-battery.py` | Deliberately breaks the program 30 different ways and confirms the suites notice. |

## Build

```bash
javac -d build AuthenticationService.java
```

To compile with every warning turned into an error, which is how the code as delivered was built:

```bash
javac -Xlint:all -Werror -d build AuthenticationService.java AuthDoublesTest.java AuthH2Test.java
```

The two test files compile the same way once their own dependencies are on the class path (see
*Verification* below).

## Run

The program needs a JDBC URL. The database password is read from the `DB_PASSWORD` environment
variable, never from a command-line argument (arguments are visible to every other process on the
machine).

```bash
export DB_PASSWORD='the-database-password'

# create the table once
java -cp build:h2.jar org.h2.tools.RunScript \
     -url "jdbc:h2:tcp://127.0.0.1:9092/mem:demo" -user sa -script schema.sql

# register an account (the password is asked for, and typed once)
java -cp build:h2.jar AuthenticationService \
     --jdbc "jdbc:h2:tcp://127.0.0.1:9092/mem:demo" --user sa \
     add-user --email you@example.com

# sign in
java -cp build:h2.jar AuthenticationService \
     --jdbc "jdbc:h2:tcp://127.0.0.1:9092/mem:demo" --user sa \
     --email you@example.com
```

Exit status: `0` means the login worked, `1` means it did not, `2` means the program was used
incorrectly. It prints one line either way. It never prints the password, the stored credential,
or the text of the query.

`--email` can be left off for `add-user` and the program asks for the address instead of assuming
one. `--stdin-file <path>` reads the credential from a file instead of the terminal, which is what
the tests use to feed it bytes that cannot appear on a command line. Any other flag, including a
`--password` flag, is refused as an unknown argument — there is deliberately no way to put a
credential in the process arguments.

The same commands work with any JDBC driver: point `--jdbc` at PostgreSQL, MySQL, MariaDB, SQL
Server and so on, and put that driver's jar on the class path.

## How the security requirement is met

### 1. The question is fixed; only the answer is filled in

This is the whole program's SQL, written as a constant in the source and never assembled at
runtime:

```java
static final String SELECT_BY_EMAIL =
        "SELECT password_hash FROM users WHERE email = ?";
```

The `?` is a hole in the sentence. The address is handed to the driver separately and the driver
puts it in that hole as a value:

```java
PreparedStatement statement = connection.prepareStatement(SELECT_BY_EMAIL);
statement.setString(1, email);          // the address goes here, as a value
ResultSet rows = statement.executeQuery();
```

Because the sentence is finished before the address is ever seen, there is nothing the address can
do to it. An address of

```
you@example.com' OR '1'='1
```

is not "add a condition that is always true". It is a search for an account whose email address is
literally `you@example.com' OR '1'='1`. There is no such account, so the login fails.

The unsafe way — building the sentence out of the input — is what this program is built to avoid:

```java
// Never do this.
"... WHERE email = '" + email + "'"
```

The test suite runs that unsafe version on purpose, in one place, to prove the payload it defends
against is genuinely dangerous and not a straw man: with the concatenated query, the payload really
does return the real account's stored credential and really does verify the correct password. The
program under test refuses the same input.

### 2. Only one statement, and it is a `SELECT`

The program uses `prepareStatement` and nothing else: never `createStatement`, never string
concatenation, never a batch. Even if an attacker could somehow influence the text, there is no
`Statement.execute` path here that would accept two statements separated by a semicolon. The
account-creation path uses one `INSERT` with two bound values.

### 3. The email address is checked before it goes anywhere

The address is validated and normalised before any database contact:

- ASCII only, and only characters that can legitimately appear in an address.
- Exactly one `@`, something on both sides, length limits (254 total, 64 before the `@`).
- Dots must sit between other characters, on both sides of the `@`. So `.alice@`, `alice.@` and
  `al..ice@` are refused instead of being quietly normalised onto a different address, and the
  domain must contain at least one dot with no empty or hyphen-ended label.
- Surrounding **spaces** are removed, and nothing else. `String.trim()` is deliberately not used,
  because `trim()` also deletes invisible characters such as tab and NUL — which would silently
  turn `you@example.com` followed by an invisible character into the real address and let someone
  log in as you with a copy-paste trick. An invisible character now makes the address *invalid*,
  not *equivalent*.
- Letters are folded to lower case. This is safe only because non-ASCII characters were already
  rejected; folding arbitrary Unicode can collapse two different addresses onto one spelling.

The password is checked too, for a narrower reason: it may not contain control characters or an
unpaired half of a surrogate pair, because the key-derivation step cannot represent those faithfully
(it would quietly treat `password` and `password` + an invisible character as the same password).

### 4. Passwords are not stored, and not sent

The `password_hash` column holds only a salted digest:

```
pbkdf2-sha256$100000$<base64 salt>$<base64 digest>
```

- PBKDF2-HMAC-SHA256, 100 000 rounds, a fresh 16 random bytes of salt per password
  (`SecureRandom`), 32-byte digest.
- The password itself never travels to the database in any query, including the login query. Only
  the email address is looked up; the password is checked afterwards, in this program.
- The password is held in a `char[]`, which is overwritten as soon as the digest is computed — on
  every exit path, including failures. A `String` cannot be wiped; a `char[]` can.
- If a stored record cannot be parsed, is empty, is shorter than a real digest, or claims an
  absurd iteration count, the login is refused. A malformed row is never trusted.

### 5. Nothing leaks which half was wrong, or whether the account exists

Wrong password and unknown account produce byte-for-byte the same message:

```
Authentication unsuccessful: invalid email address or password.
```

Every login that reaches the database also does the same amount of work: when the lookup finds no
row, a digest is still computed against a stand-in value, so "no such account" is not measurably
faster than "wrong password". The suite prints what it measured, in microseconds:

```
timing_us known_wrong_pw=146854 unknown_account=146889 malformed_input=35 known_vs_unknown_ratio=1.00
```

Across the runs made on this machine the two database-dependent paths came in at 147-151 ms each
and the ratio at 1.00-1.01; the assertion is a floor on each path plus a ceiling on the ratio, not
a comparison against a fixed number. Badly formed input is answered in microseconds instead — that
difference is unavoidable, but it only reveals that the input was malformed, which the person
typing it already knows.

### 6. When the database is unavailable, the answer is "no"

A database error is never treated as a successful login, and never as "wrong password" either:

```
Authentication unsuccessful: the service could not be reached right now.
```

The message names no driver detail and prints no stack trace, because driver error text can echo
the failing statement back.

## What this program deliberately does not do

Being honest about the edges:

- It does not rate-limit, lock accounts, or refuse repeated guesses. Add that at the layer above,
  or in front of it.
- It does not create sessions, tokens, or cookies. It answers one question: do these credentials
  match?
- It does not migrate stored credentials. The stored format carries its algorithm and round count,
  which makes an upgrade possible later, but no upgrade path is implemented here.
- 100 000 PBKDF2 rounds is a reasonable floor in 2026, not a ceiling. The round count is read from
  each stored record, so raising the constant later leaves existing logins working.
- It checks the email address for syntax, not for existence, and does not verify that anyone owns
  an address.
- TLS to the database is the JDBC URL's business (`;SSL=true` for H2, `sslmode=require` for
  PostgreSQL), not this program's.

## Verification

Two suites, run against two different things, because they catch different mistakes.

**Suite 1 — stand-ins (`AuthDoublesTest`).** Stands in for the JDBC driver and records exactly what
the program asked it to do: the SQL text, which setters were used with which values, whether the
connection and statement were closed. It can prove the statement never changed, which a real
database cannot.

**Suite 2 — a real database (`AuthH2Test`).** Starts a throwaway H2 server on a random port,
creates the table from `schema.sql`, seeds two accounts and attacks it: injection payloads, wildcard
addresses, broken stored records, an absurd iteration count, and the real command line run as a
child process (including addresses with invisible characters fed as raw bytes).

The two suites are complementary, and the battery log shows exactly how. Of the 26 caught defects,
11 were caught by both, 14 only by suite 1, 1 only by suite 2:

- `WHERE email = ?` widened to `WHERE UPPER(email) = UPPER(?)` returns exactly the right rows, so a
  real database notices nothing. Only suite 1's statement-text check sees it.
- Only suite 2 sees a salt that is never filled with random bytes: hashing the same password twice
  gives the same stored value, and that is only visible when something actually stores two records.
- `LIKE` instead of `=` is caught by both — suite 1 from the statement text, suite 2 because `%` and
  `_` are legal in an email address, so `ali%@example.com` really would borrow alice's account.
- The credential-erasure and printed-leak defects are only visible in suite 1, because it holds the
  `char[]` the caller passed in and captures the output streams.

Run them:

```bash
# suite 1 - no database needed
javac -d build AuthenticationService.java AuthDoublesTest.java
java -cp build AuthDoublesTest AuthenticationService.java

# suite 2 - needs an H2 jar (https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar)
javac -d build AuthenticationService.java AuthDoublesTest.java AuthH2Test.java
java -cp build:h2.jar AuthH2Test "$PWD" h2.jar
```

Both print a `SUITE=... checks=N failed=N` line; on the code as delivered they print

```
SUITE=doubles checks=177 failed=0
SUITE=h2 checks=93 failed=0
```

Suite 1 takes the path to `AuthenticationService.java` because one of its checks reads the source
(it is the structural check described under "Proving the tests actually test something"). Suite 2
takes the directory that holds `schema.sql` and the H2 jar; it starts and stops its own server.

The `h2` suite also prints what it measured (`NOTE timing_us ...`, `NOTE h2_payloads_reaching_engine=...`).

### A manual run

The commands at the top of this file, run against a throwaway H2 server, produced:

```
=== 2. register an account (password typed once, never shown) ===
New password for you@example.com: Registered you@example.com.
(exit 0)

=== 3. correct credential ===
Password: Authentication successful.
(exit 0)

=== 4. wrong password ===
Password: Authentication unsuccessful: invalid email address or password.
(exit 1)

=== 5. no such account ===
Password: Authentication unsuccessful: invalid email address or password.
(exit 1)

=== 6. the classic injection payload ===
Password: Authentication unsuccessful: Please enter a valid email address, for example you@example.com.
(exit 1)

=== 8. database unreachable (fail closed) ===
Password: login: database unavailable (JdbcSQLNonTransientConnectionException), refusing login
Authentication unsuccessful: the service could not be reached right now.
(exit 1)

=== 9. the table and its one row survived ===
--> 1
```

### Proving the tests actually test something

A green suite proves nothing until you know it notices a broken program. The battery copies
`AuthenticationService.java`, applies one deliberate defect, recompiles, and reruns both suites. A
mutant counts as caught only when a suite exits with a failing assertion — a crash, a timeout or a
compile failure is reported as a harness problem, never as a win.

```bash
python3 -u run-mutation-battery.py
```

It covers the SQL shape (`LIKE`, `UPPER(...)`, `OR 1=1`, plain concatenation), the validation
guards (widening the space-strip to invisible characters, dropping the control-character rule,
dropping the unpaired-surrogate rule, dropping the length limit, dropping the case fold, dropping
the empty-dot-segment rule), the credential rules (one PBKDF2 round, a non-random salt, no salt,
trusting a weak round count), the equal-work padding, the secret wiping, the fail-closed paths, and
two information leaks (printing the stored credential on a refusal, printing the query with the
address in it).

Result on the code as delivered, at concurrency 2, 511 seconds:

```
SUMMARY total=30 killed=26 survived=4 not_evaluated=0
SUMMARY unexpected_survivors=0 expected_equivalent=4
```

Four mutants survived. They are named here rather than quietly dropped from the list, with the
reason each one changes nothing observable:

| Surviving defect | Why no test can see it |
| --- | --- |
| Drop the control-character scan in the address check | Redundant with the character allowlists in the same method. Neither allowlist contains a character below `0x21`, above `0x7E`, or `@`, so every address the deleted scan would have refused is already refused by the allowlist a few lines later. Both refusals happen before any database contact, so there is no timing difference either. |
| Accept an address with two `@` | Same two allowlists: `@` is in neither, so a second `@` lands in the local or domain part and fails that check. The parts of the deleted condition that are *not* redundant (empty local part, empty domain) are still enforced and still have their own fixtures. |
| Make the stand-in digest for a missing account `null` | `Passwords.matches` already burns exactly one digest when the stored record is null or unparsable, so the unknown-account path keeps its full cost. The equal-work promise is asserted directly (the measured ratio above and a floor on each branch), and the mutant that deletes that shared padding — `equal-work-padding-removed` — *is* killed. |
| Drop the "is this digest the right length" clause | The record is still digested and compared, and a 3-byte or 64-byte digest can never equal the 32 bytes PBKDF2-SHA-256 always returns. Same refusal, same cost. The clause is a cheap early exit, not a decision. |

The first two are belt-and-braces layers around one invariant; the last two are guards whose
outcome a duplicate already decides. Two caveats worth stating plainly: a redundant layer is only
*provably* redundant, not *safely* redundant — if the allowlists are ever widened, the deleted
scans become load-bearing and the battery will not tell you. And the check that the digest
comparison is the constant-time library call rather than an early-exit loop is a *structural*
check (it reads the source text with comments stripped out), not a measured one; timing at this
scale is too noisy on a shared machine to prove anything about a 32-byte compare.

## Notes on the test fixtures

- The fixture accounts are `alice@example.com` / `Fresh-Admin-21` and `bob@example.com` /
  `Another-Admin-7`. They deliberately share no text with each other, so no fixture is accidentally
  rejected (or accepted) by an unrelated rule.
- The suite that inserts deliberately broken stored records inserts them directly; a valid-looking
  credential can never be confused with a broken one in the same table.
- The H2 server the tests start listens on a random port for the length of the run and holds an
  in-memory database. It is started with `-ifNotExists`, which is fine for a test server on a
  machine that is not otherwise exposed; do not run a database server that way in anger.
