# User account registration and authentication (JDBC)

`UserRegistration.java` creates user accounts in a relational database and lets
those stored credentials authenticate a later login. It works on a JDBC
`Connection` the caller already opened and owns.

* Java 17, no dependencies beyond the JDK for the library itself.
* One source file, no build tool required.

---

## Password handling

The password is never stored, never returned by any method, and never
concatenated into SQL. What reaches the database is a salted, stretched digest:

```
pbkdf2-sha256$600000$Base64(16-byte salt)$Base64(32-byte digest)
```

| Decision | Why |
| --- | --- |
| **PBKDF2-HMAC-SHA256, 600,000 iterations** | Stretches each guess so an offline crack of a stolen table is expensive. 600,000 is OWASP's 2023 floor for this primitive; measured at **860 ms** per derivation on one core of this machine. |
| **Fresh 16-byte salt per account** (`SecureRandom`) | Two users with the same password get different rows, so one precomputed rainbow table cannot cover the table and identical rows do not leak who shares a secret. |
| **Algorithm and iteration count stored in the row** | Verification uses the cost that was in force when the account was created, so raising the default later logs nobody out and invalidates nothing. |
| **Stored-cost bounds (1,000 - 10,000,000)** | A tampered or corrupt row cannot ask for 1 round (instant cracking) or 10^9 rounds (login denial of service). |
| **`MessageDigest.isEqual` for the digest compare** | Byte comparison that does not return early on the first differing byte. |
| **Junk input fails closed** | A malformed, foreign-format, or unsupported stored digest yields "does not match", never an exception that reaches a login page and never an accidental match. |
| **`char[]` in, `clear()` available** | Callers can wipe the secret instead of parking it in an immutable `String`. The library never modifies the caller's array and zeroes its own scratch (`PBEKeySpec`, derived key bytes) as soon as it is done. |
| **Passwords the JCE would fold together are refused** | `PBEKeySpec` is not injective over `char[]`: it drops trailing NULs and maps every unpaired surrogate to a single `?`, which makes distinct passwords derive the same digest. See *Why some passwords are refused*. |
| **Unknown usernames still pay for a derivation** | The lookup-miss path runs PBKDF2 against a throwaway digest, so response time cannot be used to enumerate which usernames have accounts. Measured unknown-user / wrong-password latency ratio: **1.00-1.02** across runs. |

`String` is the wrong type for a password in Java: it is interned, may be
cached, and cannot be overwritten. `char[]` is used for that reason. Zeroing it
is still only best effort -- it narrows the window in which the secret is
reachable in heap, it cannot retract a copy the JVM or your own code already
made, and it does nothing about swap.

### Why some passwords are refused

`PBEKeySpec` converts a `char[]` password to bytes with the JCE's own UTF-8
converter, and that converter is **not injective across the whole `char[]`
domain**. Both behaviours below were measured directly on this JVM
(OpenJDK 17.0.20.1), deriving with the raw JCE:

| Password (chars) | PBKDF2 digest |
| --- | --- |
| `c a f é` | `4a93db32…f220f9d8` |
| `c a f é` + NUL | `4a93db32…f220f9d8` |
| `c a f é` + NUL + NUL | `4a93db32…f220f9d8` |
| `q` + U+D800 | `460aaca2…4b1a7b5a` |
| `q` + U+D801 | `460aaca2…4b1a7b5a` |
| `q` + U+DC00 | `460aaca2…4b1a7b5a` |
| `q` + `?` | `460aaca2…4b1a7b5a` |

Each group is a set of *different* passwords that produce *the same* digest, so
a user who registered one could be logged in by anyone who presented another.
That is precisely the failure a password digest exists to prevent, and it is not
something a hashing wrapper notices on its own.

`UserRegistration` therefore refuses both classes in `hash` and in `matches`:

* a password ending in NUL;
* a password containing an unpaired surrogate.

Refusing rather than "cleaning up" is deliberate: trimming or replacing
characters would silently change which secret the user typed. Correctly paired
supplementary characters (emoji, astral scripts) are unambiguous and remain
valid; an *interior* NUL is unambiguous too (only trailing ones are discarded)
and is also accepted. The test suite asserts both halves -- that each collapse
really occurs at the raw JCE, that the guard rejects every member of each class,
and that legitimate Unicode still round-trips -- so the guard cannot be deleted
or half-deleted without a check failing.

One consequence worth stating because it is easy to get wrong: since a refused
candidate never reaches the KDF, `authenticate` charges it the guard digest's
derivation anyway. A free refusal would be a username oracle -- present `q` +
U+D800 and a fast answer means the row exists. The suite measures that path too
(refused-candidate to wrong-password ratio **0.99-1.04**).


## SQL handling

* Every statement that carries user-supplied data is a `PreparedStatement` with
  `?` placeholders. A username such as `admin' OR '1'='1` is data, never
  statement text. The only thing concatenated into SQL is the table name, a
  compile-time constant.
* The lookup compares with `username = ?`. Not `LIKE` -- under `LIKE`, `_` is a
  single-character wildcard, so `alicex1` would satisfy a lookup for `alice_1`
  and hand out an account name to guess against.
* Usernames are matched case-sensitively and verbatim. No `UPPER()` folding
  (`alice` must not be able to log in as `Alice`) and no trimming.
* Usernames are validated against the allowlist `[A-Za-z0-9._-]{3,64}` before
  any statement is prepared. Passwords must be non-empty and no longer than
  1,024 characters, because PBKDF2 cost is linear in password length and an
  unbounded field lets anyone make registration arbitrarily expensive.
* Uniqueness is enforced by a `UNIQUE` index, not by a check-then-insert race.
  The database is the authority; the loser of a concurrent signup gets
  `USERNAME_ALREADY_EXISTS` and the existing row is left untouched.
* `Statement`, `ResultSet` and `PreparedStatement` are closed with
  try-with-resources. The caller's `Connection` is never closed.

## Schema

```sql
CREATE TABLE IF NOT EXISTS app_users (
    id            BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(200) NOT NULL,
    created_at    TIMESTAMP    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_app_users_username ON app_users (username);
```

`UserRegistry.ensureSchema()` runs exactly this DDL, so the table does not have
to pre-exist. A digest is ~90 characters, which leaves room in `VARCHAR(200)`
for longer iteration counts. The DDL is portable across H2, PostgreSQL, MariaDB
and MySQL 8; on Oracle/SQL Server adjust the identity and timestamp clauses.

## API

```java
public final class UserRegistration {
    public enum RegistrationOutcome   { CREATED, USERNAME_ALREADY_EXISTS }
    public enum AuthenticationOutcome { AUTHENTICATED, NO_SUCH_USER, BAD_PASSWORD }

    public static final class PasswordHasher {          // thread-safe
        public PasswordHasher();                        // 600,000 iterations
        public PasswordHasher(int iterations);
        public String  hash(char[] password);           // the value to store
        public boolean matches(char[] password, String storedDigest);
        public static void clear(char[] password);      // best-effort wipe
        public static boolean isVerifiableCandidate(char[] password);
    }

    public static final class UserRegistry {            // one per Connection
        public UserRegistry(Connection connection, PasswordHasher hasher);
        public UserRegistry(Connection connection, PasswordHasher hasher, boolean commitOwnWork);
        public void ensureSchema() throws SQLException;
        public RegistrationOutcome   register(String username, char[] password) throws SQLException;
        public AuthenticationOutcome authenticate(String username, char[] password) throws SQLException;
        public boolean exists(String username) throws SQLException;
    }
}
```

### Typical use

```java
// One hasher for the whole application; it is thread-safe.
UserRegistration.PasswordHasher hasher = new UserRegistration.PasswordHasher();

// One registry per connection, i.e. typically one per request.
UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(connection, hasher);

char[] password = readPasswordFromConsole();       // e.g. System.console().readPassword()
try {
    UserRegistration.RegistrationOutcome outcome = registry.register("alice", password);
    if (outcome == UserRegistration.RegistrationOutcome.USERNAME_ALREADY_EXISTS) {
        // ask for a different username
    }
} finally {
    UserRegistration.PasswordHasher.clear(password);
}
```

`IllegalArgumentException` means the input was rejected and nothing was written;
`SQLException` means the database failed.

### Login

`AuthenticationOutcome.NO_SUCH_USER` and `BAD_PASSWORD` are kept distinct for
server-side logging and migration tooling. **Show the caller one identical
message for both** ("invalid username or password"), log the distinction
server-side only, and put rate limiting and lockout in front of this call.
Distinguishable wording or response sizes turn the timing equalisation above
back into a username oracle.

### Transactions

`register` does not open or close a transaction on its own. If the connection
has manual commits and the registry was built with `commitOwnWork = true` (the
default), a successful insert is committed and a failed one rolled back. Pass
`false` when the surrounding unit of work decides when to commit; the rollback
then belongs to that unit of work too.

---

## Compile and run

Everything below was run on OpenJDK 17.0.20.1 on this machine. Sources are
ASCII-only, so no `-encoding` flag is needed (the platform default charset here
is US-ASCII).

### Run the demonstration

The demo needs a JDBC driver; H2 is used here only so the example is runnable.

```bash
javac -d out UserRegistration.java
java -cp out:h2.jar UserRegistration
```

Optionally point it at your own database:
`java -cp out:h2.jar UserRegistration <jdbc-url> <user> <password>`.

Actual output on this machine:

```
register alice            -> CREATED
register alice (twice)    -> USERNAME_ALREADY_EXISTS
register bob              -> CREATED
authenticate alice/right  -> AUTHENTICATED
authenticate alice/wrong  -> BAD_PASSWORD
authenticate carol/right  -> NO_SUCH_USER
register quoted payload -> refused by validation: username must be 3-64 characters of [A-Za-z0-9._-], got: length 16
register admin--          -> CREATED
authenticate admin--/right-> AUTHENTICATED
authenticate admin (never registered, suffix must not act as a comment) -> NO_SUCH_USER

stored rows (note: no password appears below):
  alice  ->  pbkdf2-sha256$1000$LMyzicMWQjBHbUhDk4cb7Q==$ya8biQwDyomOHfTluePSOAwLNjT3rnrrfzmlycbyEUE=
  bob  ->  pbkdf2-sha256$1000$rXRQfahOq1rNySC3awDFTg==$tKwZZpP3q1/CgsIBZ2f+ejVr7macDLAwTzJrS8ohX70=
  admin--  ->  pbkdf2-sha256$1000$6UBnVV5IM0O3QIrb1meIJw==$/MNgVr1Df4AZnCJ4l/ugxtjK1lgDC8J9nXIbXyo/hME=
```

Salts are drawn fresh on every run, so your digests will differ from these even
though the passwords are the same -- that is the salt doing its job.

The demo builds its hasher with 1,000 iterations so it finishes immediately; a
production `new PasswordHasher()` gets the 600,000-iteration default. Note that
`alice` and `bob` received different salts, and that `admin--` is stored as a
literal username -- the trailing `--` does not act as a SQL comment because it
never enters the statement text.

### Run the verification suites

Two suites, deliberately complementary:

```bash
javac -Xlint:all -Werror -d out \
    UserRegistration.java UserRegistrationH2Test.java UserRegistrationSqlContractTest.java

# 1. SQL contract suite: no database, JDBC doubles via java.lang.reflect.Proxy.
java -cp out UserRegistrationSqlContractTest

# 2. Integration suite against a real engine.
java -cp out:h2.jar UserRegistrationH2Test
```

Current results: **125 checks passed** and **86 checks passed** respectively
(exit code 0; on failure each prints every failed check and exits 1).

* `UserRegistrationSqlContractTest` records the exact statement text and every
  bound parameter, so it can assert things no database would tell you: that a
  credential appears nowhere in the statement text, that all three placeholders
  were bound, that the data path never uses a plain `Statement`, that a
  duplicate-key `SQLException` (state `23505`) becomes a conflict rather than a
  retry, that a `22001` "value too long" is *not* mistaken for a conflict even
  when the username happens to exist, that every statement is closed, and that
  the unknown-username path really does pay for a derivation (~180-220 ms
  against a doubled connection, where everything else is free). It also scripts
  results a real engine will not hand you, such as a constraint violation on
  insert.
* `UserRegistrationH2Test` runs the same calls against H2, which is what catches
  a predicate that now matches *too much*: under `username LIKE ?` a supplied
  `alice_1` matches the row of an attacker-owned `alicex1`, and the real engine
  is the only thing that can show that. It also covers transaction visibility
  from a second connection, duplicate handling on real rows, a known-answer test
  for the KDF, and the enumeration-timing equalisation as a best-of-5 ratio so
  scheduler noise cannot decide the outcome.

The two suites are complementary, not redundant: several mutants were caught by
one suite and passed by the other.

### Mutation results

Every weakening below was applied to the implementation on its own (22 mutants)
and the suites re-run. **All 22 were caught**, each by a check that names the
behaviour. A surviving mutant would have meant the tests did not really cover
that behaviour, which is the only way to know a security test is a test.

| Mutant | Caught by |
| --- | --- |
| Store the password in the clear | digest-format and no-password-in-row checks (both suites) |
| `=` -> `LIKE` in the username lookup | H2: borrowed-row test; contract: statement-text test |
| `UPPER(username) = UPPER(?)` | H2: case-sensitivity tests; contract: binding test |
| Lookup no longer keyed on the supplied username | both suites fail end to end |
| `==` instead of `MessageDigest.isEqual` | 14 checks |
| Derive a 128-bit key instead of 256-bit | known-answer test (+14 checks) |
| Drop the unknown-user timing guard | both timing checks (0 ms vs ~57 ms) |
| Refuse a bad candidate for free | refused-candidate timing ratio check |
| Unknown username authenticates | 7 checks |
| Treat any constraint violation as a duplicate | `22001`-with-existing-row check |
| Forget the commit | second-connection visibility + commit checks |
| Remove the stored iteration bounds | bounded probe reports "still deriving after 5000 ms" |
| Drop username validation | 9 checks |
| Drop the password length cap | length checks |
| Reuse one salt for every account | 3 checks |
| Verify with the current default cost, not the stored one | migration test |
| Stamp the wrong iteration count into the digest | contract timing check |
| Lax (MIME) Base64 for a stored digest | smuggled-newline digest checks |
| `clear()` stops zeroing | zeroing check |
| Drop the ambiguous-password guard entirely | 14 checks |
| Catch only the surrogate class | 7 checks |
| Catch only the trailing-NUL class | 7 checks |

Two notes on method, because each decided a verdict:

* The malformed-digest checks run each verification on a worker thread with a
  5-second budget. Without that, deleting the iteration ceiling makes the suite
  hang forever on a 999,999,999-round digest -- which is the denial of service
  itself, but not a *reported* failure.
* The timing checks compare best-of-N runs against each other as a ratio rather
  than asserting a wall-clock number, so a loaded machine cannot make them
  flake, and a guard that silently stopped deriving cannot pass a boolean-only
  assertion.


---

## What this deliberately does not include

The task scoped a connection and credential storage. These are still required
before this is a login system, and none of them belong in this file:

* **Transport security.** Digest strength is irrelevant if the password crosses
  the network in cleartext: TLS is the application's job.
* **Rate limiting, lockout, and breach detection.** Nothing here throttles
  repeated guesses against one account.
* **Password policy and strength checking.** Only emptiness and length are
  enforced; a minimum length, a common-password blocklist and a breach check
  (`haveibeenpwned` k-anonymity API) are a product decision.
* **A migration tool.** `ensureSchema()` is a convenience; run the DDL through
  Flyway/Liquibase in anything real.
* **Alternative KDFs.** Argon2id and scrypt are stronger choices when a library
  is available, since they also resist GPU and ASIC cracking. This file sticks to
  PBKDF2 because it is in every JDK and needs no third-party dependency; the
  stored format already carries an algorithm tag, so a second algorithm can be
  added to `PasswordHasher` without touching existing rows.
* **Session issuance.** `authenticate` answers a question; it does not create a
  session, cookie or token.
* **Charset normalisation of usernames.** The allowlist keeps this moot
  (ASCII-only). If you widen it to Unicode, normalise (NFKC) before storing or
  homoglyph accounts become possible.

## Files

| File | Purpose |
| --- | --- |
| `UserRegistration.java` | The implementation: `PasswordHasher`, `UserRegistry`, and a `main` demonstration. |
| `UserRegistrationH2Test.java` | Integration checks against a real H2 database. |
| `UserRegistrationSqlContractTest.java` | SQL/parameter contract checks using JDBC doubles; needs no database. |
| `README.md` | This document. |
