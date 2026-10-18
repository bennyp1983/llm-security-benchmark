# User account registration and authentication (JDBC)

Registers new user accounts into an SQL database and lets the stored credentials be replayed for
login later. The caller supplies an already-open JDBC `Connection`; the class never opens, commits,
rolls back or closes it.

## Files

| File | Purpose |
| --- | --- |
| `UserAccountService.java` | The implementation. Drop this single file into your project. |
| `Demo.java` | Runnable end-to-end demonstration against any JDBC URL. |
| `UserAccountServiceTest.java` | Functional verification against a real SQL engine (H2). 132 checks. |
| `UserAccountServiceJdbcContractTest.java` | Verification with hand-rolled JDBC doubles that assert the exact SQL text and bound parameters. 77 checks. |
| `README.md` | This document. |

Java 17 or newer, no dependencies beyond the JDK (`Demo` and the engine test need a JDBC driver at
runtime; see [Compile and run](#compile-and-run)).

## API

```java
UserAccountService service = new UserAccountService();      // or (algorithm, iterations, saltBytes, hashBytes)

service.ensureSchema(connection);                           // optional: CREATE TABLE IF NOT EXISTS
service.registerUser(connection, "alice", "a passphrase");  // -> Account, or throws
service.authenticate(connection, "alice", "a passphrase");  // -> boolean
service.deleteUser(connection, "alice");                    // -> boolean
service.credentialsNeedUpgrade(storedIterations);           // -> boolean, migrate flag
service.deriveMillis();                                     // -> long, for tuning the work factor
```

Both `registerUser` and `authenticate` also take `char[]` passwords, which is the better form: a
`char[]` can be wiped afterwards, a `String` cannot.

Checked exceptions:

* `UserAccountService.DuplicateUsernameException` -- the username is taken.
* `UserAccountService.InvalidValueException` (an `IllegalArgumentException`) -- the username or
  password breaks the policy below.
* `SQLException` -- the database failed.

### Policy

* Username: 3-64 characters of `[A-Za-z0-9._-]`, first character a letter or digit. Anything else
  (`'`, `;`, `--`, spaces, newlines, Unicode) is rejected at the boundary.
* Password: 10-1024 characters, no control characters. No other syntax rule -- passphrases with
  spaces and punctuation are fine, and `registerUser` never rejects a *password* for looking like
  SQL.

## What is stored

`ensureSchema` creates:

```sql
CREATE TABLE IF NOT EXISTS app_user (
    username      VARCHAR(64)   NOT NULL,
    algorithm     VARCHAR(64)   NOT NULL,
    iterations    INT           NOT NULL,
    salt          VARBINARY(128) NOT NULL,
    password_hash VARBINARY(128) NOT NULL,
    created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_app_user PRIMARY KEY (username)
)
```

`VARCHAR`/`VARBINARY`/`INT`/`TIMESTAMP` are accepted as written by H2, PostgreSQL, MySQL/MariaDB and
SQL Server. On Oracle use `RAW(n)` and on SQLite `BLOB(n)` instead of `VARBINARY(n)`; the rest of
the code is unchanged. Skip `ensureSchema` and bring your own DDL if you prefer -- the service only
needs a table shaped like the one above.

The password itself is never stored, never logged and never appears in any bound parameter or
statement text (`UserAccountServiceJdbcContractTest` asserts both).

## Design decisions

**Passwords are salted, stretched derived keys, not digests.** Each registration draws 16 fresh
random bytes from `SecureRandom` and derives a 32-byte key with `PBKDF2WithHmacSHA256` at 310 000
rounds (the OWASP 2023 figure for that construction). Same password, different salt, different
stored bytes -- so a leaked table cannot be rainbow-tabled and two users with the same password are
indistinguishable. `MessageDigest.isEqual` (constant time, and length-safe) does the comparison.

**The algorithm and iteration count are stored per row.** Raising `DEFAULT_ITERATIONS` later does not
lock anyone out: verification honours the row's own parameters, so existing accounts keep working
after the work factor changes. `credentialsNeedUpgrade(storedIterations)` is the detection hook --
call it with the iteration count you read from the row and, when it says yes, migrate that account.
This class deliberately stops at *detection*: it has no write path for an existing row, so the
re-hash (which needs the plaintext, so only ever during a successful login) is yours to place behind
whatever review and audit trail a credential change needs. Set the work factor correctly at launch
rather than planning to migrate later.

**Every statement is a `PreparedStatement` with bound parameters.** The lookup is exactly
`WHERE username = ?`. Not `LIKE`, not `UPPER(...) = UPPER(?)`, not string concatenation -- the first
two are the "it looks parameterised" rewrites that silently match several accounts, and the engine
test and the contract test each reject them (see [Tests](#tests)).

**Duplicates are settled by the database, not by a prior SELECT.** A check-then-insert races: two
concurrent requests both see "free" and both insert. Instead there is one `INSERT`, and a
unique-constraint violation (`SQLIntegrityConstraintViolationException`, or any SQLState class 23
for drivers that report a bare `SQLException`) becomes `DuplicateUsernameException`. Two real
connections racing on one username leave exactly one row -- that is a test.

**The caller's transaction stays usable after a rejected registration.** When auto-commit is off, the
`INSERT` runs inside a savepoint that is rolled back on failure. On PostgreSQL a failed statement
otherwise aborts the whole transaction, and every later statement on that connection would fail.

**The service never touches transaction state.** No `commit`, `rollback`, `close` or
`setAutoCommit` on your connection -- asserted against doubles that count every call.

**Login does not disclose which accounts exist.** A lookup that finds no row still spends one full
key derivation on a dummy credential before returning `false`. The dummy is produced by running the
real KDF at construction time, not by a hand-written constant. That distinction matters: a constant
that a decoder rejects makes the branch return early, so the account-existence oracle comes back
with no error and no failing assertion, only a timing difference. Measured with the test work factor:
unknown user 73 ms, existing user 73 ms (and 288 ms vs 282 ms at the contract suite's setting).

**Rows are validated before any work is spent on them.** A tampered row claiming `iterations = 1`,
`iterations = 999999999`, an empty salt, a truncated key or `algorithm = 'MD5'` is refused outright
rather than fed to `PBEKeySpec`, which accepts all of those. Refusal also costs a dummy derivation,
so it is not distinguishable from a wrong password either.

The bounds check is load-bearing in a way that is easy to test *wrong*: if it is missing, a row
claiming 999 999 999 iterations still fails to authenticate (the derived key does not match), it
just takes half an hour of CPU to find that out. Asserting only the boolean return value would pass.
Both suites therefore assert that the refusal happens inside a 5 s budget, on a worker thread.

### Known trade-offs

* Timing equalisation covers *response time*, not CPU load: a burst of probes against existing
  accounts still shows up in server metrics. Rate limiting belongs in front of this.
* `SecureRandom` blocks only if the platform entropy source is starved; on a headless container
  consider `-Djava.security.egd=file:/dev/urandom`.
* PBKDF2 is a sound choice, and memory-hard functions (Argon2id) are stronger if you can add a
  dependency. The `algorithm` column exists precisely so that swap is a code change, not a migration.
* Passwords are checked for length and control characters, not against a breach list. That is an
  integration point for you, not something to ship hardcoded.

## Compile and run

Nothing to build beyond `javac`. To run `Demo` and the engine test you need a JDBC driver; H2 is a
single jar:

```bash
curl -sSLo h2.jar https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar

javac -cp h2.jar *.java                    # compiles all four sources
java  -cp h2.jar:. Demo                    # in-memory database
java  -cp h2.jar:. Demo "jdbc:h2:./accounts"   # or any URL whose driver is on the path
```

`Demo` output on this machine:

```
JDBC url : jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1
one key derivation takes 579 ms at 310000 PBKDF2 rounds

registered   Account[alice, PBKDF2WithHmacSHA256, iterations=310000]
registered   Account[b.o-brien, PBKDF2WithHmacSHA256, iterations=310000]
registered   Account[chen, PBKDF2WithHmacSHA256, iterations=310000]
--- what the database actually holds -----------------------------
alice        PBKDF2WithHmacSHA256      310000 rounds  salt=f1634e58f0233515...  hash=71ebc8c81fbc2afc...
b.o-brien    PBKDF2WithHmacSHA256      310000 rounds  salt=b05e45db31750fb0...  hash=c065649a1b5d746a...
chen         PBKDF2WithHmacSHA256      310000 rounds  salt=a9508885d91e3c0e...  hash=712683973f585725...
  (no column holds the password, and no two rows share a salt)

--- authenticating -------------------------------------------
ACCEPTED     'alice' with 'correct horse battery staple'
REJECTED     'alice' with 'Correct horse battery staple'
ACCEPTED     'b.o-brien' with 'trap' or 1=1 --oracle quote'
REJECTED     'b.o-brien' with 'trap' or 1=1 --o'
REJECTED     'nobody' with 'whatever password'
REJECTED     'alic_' with 'correct horse battery staple'
REJECTED     'Alice' with 'correct horse battery staple'
--- duplicate handling ---------------------------------------
refused      username is already registered: alice
--- policy enforcement ---------------------------------------
refused      username must be 3-64 characters of [A-Za-z0-9._-] and start with a letter or digit
refused      password must be 10-1024 characters long
--- the caller owns the transaction --------------------------
rolled back  the registration of 'rolled-back'
REJECTED     'rolled-back' with 'a long enough passphrase'
```

`alic_` would match `alice` if the lookup used `LIKE`, and `Alice` would match if it case-folded;
both are rejected because the predicate is a plain `username = ?`. The `579 ms` figure is what one
derivation costs on an otherwise idle 4-core box; the same call measured 1177 ms while the mutation
battery below was saturating all four cores, so treat it as a tuning input rather than a spec.

### Tests

```bash
java -cp h2.jar:. UserAccountServiceTest             # 132 checks, ~12 s, needs h2.jar
java      UserAccountServiceJdbcContractTest         #  77 checks, ~22 s, no driver needed
```

Both print `OK <n> checks passed` and exit 0, or list the failing checks and exit 1.

`UserAccountServiceTest` runs against a real engine: registration and login round-trip, distinct
salts, the stored key equals an independently computed PBKDF2, injection payloads as passwords,
case-sensitivity and wildcard non-matching, policy boundaries, nine kinds of tampered row (each of
which must be refused *promptly*, not after deriving it), salt freshness when the same username is
re-registered, a row stored at an older work factor, two connections racing on one username, and
transaction semantics on a file-backed database (rollback visibility, surviving the failed insert,
the service not committing for you).

`UserAccountServiceJdbcContractTest` runs against `java.lang.reflect.Proxy` doubles with no driver
involved, and asserts the *contract* an engine cannot: the exact prepared statement text, that the
`INSERT` has five placeholders with the right value in each slot, that no statement text ever
contains user input, that a query returning two rows is refused instead of the first row being
trusted, that a well-formed row really does authenticate (so a build that rejects everything cannot
pass), that the salt is fresh entropy on every registration, that a corrupt row is refused *within a
time budget* rather than derived, and that
`commit`/`rollback`/`close`/`setAutoCommit` are never called.

The two suites are complementary, not redundant. A `Proxy` double replays scripted rows, so it
cannot see a predicate that matches too much (`LIKE` survives it, H2 does not); a live engine
accepts only rows it can represent, so it cannot hand the code an iteration-count bomb or a 4-byte
key (the double can). Several mutants are killed by exactly one of the two, which is why both run.

### Mutation testing

The suites were checked by injecting 18 defects into `UserAccountService.java` one at a time,
rebuilding, and confirming the tests fail. All 18 were detected; the right-hand column names the
suite(s) that caught it (`H2` = engine suite, `C` = contract suite):

| Injected defect | Caught by |
| --- | --- |
| Lookup predicate rewritten to `username LIKE ?` | H2 + C |
| Lookup case-folded: `UPPER(username) = UPPER(?)` | H2 + C |
| Username concatenated into the lookup SQL | H2 + C |
| Password stored verbatim instead of the derived key | H2 + C |
| Constant (non-random) salt | H2 + C |
| Salt derived from the username instead of the RNG | H2 + C |
| Dummy derivation removed from the unknown-user path | H2 + C |
| `==` instead of `MessageDigest.isEqual` | H2 + C |
| Verification always returns false | H2 + C |
| Stored `iterations` ignored, service default used | H2 + C |
| Duplicate error swallowed, reported as success | H2 + C |
| Any `SQLException` classified as a duplicate username | H2 + C |
| Service commits the caller's transaction | H2 + C |
| Savepoint around the guarded insert removed | C |
| Stored iteration bounds check removed | H2 + C |
| Empty stored salt accepted | C |
| Derived key truncated to 8 bytes | H2 |
| Default work factor weakened to 1 000 rounds | H2 |

Three of these are worth calling out, because each one taught me something about the tests rather
than about the code:

* **Salt derived from the username** was *not* caught by the original suite. It passes "two accounts
  have different salts", it verifies correctly, and the stored key still equals an independently
  computed PBKDF2. The check that kills it registers the *same* username twice and compares salts.
* **`==` instead of `MessageDigest.isEqual`**, and **verification always returning false**, were only
  caught once a positive-path check existed. Every other contract assertion expects a rejection, so a
  build that rejects everything looked healthy.
* **The savepoint removal is caught only by the contract suite**, and that is inherent rather than a
  gap I can close: savepoints matter because PostgreSQL aborts a transaction after a failed statement,
  which H2 does not do. No observable H2 behaviour changes, so only a JDBC-level assertion that a
  savepoint was opened and rolled back can see it. Likewise the 8-byte key and the weakened work
  factor are properties of the shipped defaults, which the contract suite deliberately overrides to
  run fast, so only the engine suite pins them.

## Using it in an application

```java
// Once, from your migration/startup path:
UserAccountService service = new UserAccountService();

// Per request, with the connection your pool or ORM already opened:
public boolean login(Connection connection, String username, char[] password) throws SQLException {
    return service.authenticate(connection, username, password);
}

public void signup(Connection connection, String username, char[] password) throws SQLException {
    boolean previous = connection.getAutoCommit();
    connection.setAutoCommit(false);
    try {
        service.registerUser(connection, username, password);
        connection.commit();                       // you decide when the account becomes real
    } catch (UserAccountService.DuplicateUsernameException taken) {
        connection.rollback();
        throw new UsernameAlreadyUsedException();  // render a form error, do not confirm existence
    } finally {
        connection.setAutoCommit(previous);
    }
}
```

Notes for production:

* Tune `iterations` so one derivation costs roughly 100-500 ms on *your* hardware
  (`service.deriveMillis()`); 310 000 measures ~580 ms on this machine and will be faster on newer
  CPUs.
* `authenticate` returning `false` and `DuplicateUsernameException` both reveal account existence to
  whoever triggered them. Return a generic failure to end users, and rate-limit.
* One connection per thread. `Connection` is not thread-safe; this class is.
