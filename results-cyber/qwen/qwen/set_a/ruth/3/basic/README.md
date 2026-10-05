# UserAccountLookup

Fetches one user account from a SQL database by username, over a JDBC `Connection`
that the caller already has open.

## Files

| File | Role |
| --- | --- |
| `UserAccountLookup.java` | The deliverable: the lookup, the row record, and an optional command line entry point. Needs nothing but the JDK. |
| `UserAccountLookupTest.java` | Verification harness, no JDBC driver required (stubs `java.sql` with JDK dynamic proxies). |
| `UserAccountLookupH2Test.java` | Verification harness against a real SQL engine (H2 in memory). Needs `h2.jar`. |

## What the code does

`UserAccountLookup.findByUsername(Connection, String)` runs exactly one statement:

```sql
SELECT id, username, email, full_name, status, created_at FROM users WHERE username = ?
```

and returns `Optional<UserAccount>`:

| Outcome | Result |
| --- | --- |
| One matching row | `Optional` containing the account |
| No matching row | `Optional.empty()` |
| Username is null, blank, or longer than 254 characters | `IllegalArgumentException`, before the driver is touched |
| Connection argument is null | `NullPointerException` |
| More than one row matches | `IllegalStateException` — the `users.username` unique index is missing |
| Database error | `SQLException`, propagated |

Behaviour worth knowing:

- **The username is always a bound parameter.** It never enters the SQL text, so
  `admin' OR '1'='1`, `admin' --`, `%; DROP TABLE users` and similar are matched as
  literal strings rather than parsed as SQL.
- **Surrounding whitespace is trimmed** before binding, so `"  alice "` finds `alice`.
- **Comparison is exact, including case** — whatever the database collation does for
  `=`. `LIKE` is not used, so `%` and `_` in a username are not wildcards.
- **No authentication material is read.** The column list is explicit and excludes
  `password_hash`, so `UserAccount` cannot carry a hash into a log line or a response.
- **The caller owns the connection.** Only the statement and result set created here are
  closed; the connection, the transaction and the autocommit setting are left alone.
- **A duplicate username is an error, not a silent pick.** Returning the "first" row of
  an unintended two-row match would quietly return the wrong account.
- Null columns map to null fields (`created_at` null → `createdAt == null`) instead of
  failing.

### Expected table

```sql
CREATE TABLE users (
  id            BIGINT PRIMARY KEY,
  username      VARCHAR(254) NOT NULL,
  email         VARCHAR(320),
  full_name     VARCHAR(200),
  status        VARCHAR(32)  NOT NULL,
  password_hash VARCHAR(100) NOT NULL,   -- present, deliberately never selected
  created_at    TIMESTAMP
);
CREATE UNIQUE INDEX users_username ON users (username);  -- required
```

Extra columns are fine; the statement names only the six it reads. `MAX_USERNAME_LENGTH`
(254) is a pre-flight guard, so align it with your `username` column width.

## Compile

JDK 17 or newer. No build tool, no dependencies, no network.

```bash
javac -Xlint:all -Werror -d target UserAccountLookup.java
```

## Run

An application that already has a connection calls the API directly:

```java
Optional<UserAccount> account = UserAccountLookup.findByUsername(connection, username);
account.ifPresent(a -> System.out.println(a.username() + " <" + a.email() + ">"));
```

`main` is a convenience wrapper that opens its own connection, for trying it out from a
shell. It reads the username from the first argument, or from the first line of stdin.

```bash
export DB_URL='jdbc:h2:mem:app' DB_USER=sa DB_PASSWORD=secret
java -cp target UserAccountLookup alice
java -cp target UserAccountLookup "  admin  " | pbcopy
printf 'alice\n' | java -cp target UserAccountLookup
```

```
UserAccount[id=1, username=alice, email=alice@example.com, fullName=Alice Example, status=ACTIVE, createdAt=2024-01-02T03:04:05Z]
```

Exit status: `0` the query ran (including "no account found"), `2` bad usage or input,
`3` the database failed. The JDBC driver for `DB_URL` must be on the class path, for
example `-cp target:h2.jar`.

## Tests

Driver-free unit harness — stubs `Connection`, `PreparedStatement` and `ResultSet` with
`java.lang.reflect.Proxy` and asserts the exact SQL text asked for, which placeholder got
which value, which columns were read, and which resources were closed:

```bash
javac -Xlint:all -Werror -d target UserAccountLookup.java UserAccountLookupTest.java
java -cp target UserAccountLookupTest
```

End-to-end harness against a real engine, which puts the statement in front of an actual
SQL parser and a real `users` table:

```bash
curl -sSLo h2.jar https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar
javac -Xlint:all -Werror -cp h2.jar -d target-h2 UserAccountLookup.java UserAccountLookupH2Test.java
java -cp target-h2:h2.jar UserAccountLookupH2Test
```

Both exit non-zero and name every failed check. The H2 harness deliberately creates
`users` *without* the unique index, because the duplicate-row check needs duplicates to be
possible.

## Verification actually performed

Environment: OpenJDK 17.0.20.1, `javac -Xlint:all -Werror` clean; H2 2.2.224 used only for
verification.

- **Unit harness: 47 checks passed.**
- **H2 harness: 30 checks passed** — real parse, real null columns, injection payloads
  returning no row while the table stays intact, `Alice` not matching `alice`, a
  username containing a non-ASCII letter (`re` + U+00F1 + `sumer`) round-tripping through
  the driver.
- **Command line: 10 paths exercised** — found by argument, found via stdin, padded
  argument, not found, injection payload, blank input (exit 2), empty stdin (exit 2),
  `DB_URL` unset (exit 2), unreachable database (exit 3), missing table (exit 3).

### Mutation check

Each check above was validated by deliberately breaking the code, on throwaway copies, and
confirming a check fails. A mutant that broke the build was not counted as caught.

| Deliberate defect | Caught by |
| --- | --- |
| Username spliced into the SQL text, binding removed | unit (4 checks), H2 |
| Bound value tampered with (trailing quote appended) | unit (4), H2 (6) |
| `SELECT *` instead of the explicit column list | unit |
| `password_hash` added to the select list | unit |
| Second placeholder / `OR username = ?` added | unit |
| Duplicate-row detection removed | unit, H2 |
| Statement never closed (leaked) | unit (2) |
| Caller's connection closed by the lookup | unit |
| Whitespace no longer trimmed | unit (3) |
| Null `created_at` dereferenced | unit (2) |
| Length guard removed, and length guard off by one | unit |
| Blank-username check removed | unit |
| `email` mapped from the wrong column | unit (2) |
| `SQLException` swallowed into `Optional.empty()` | unit |
| `=` replaced with `LIKE` (wildcard escalation) | H2 |
| `=` made case-insensitive (`UPPER()`) | H2 |

The last two are why both harnesses exist: a recording double replays scripted rows and so
cannot notice a predicate that now matches too much, whereas the real engine can. The
`SQLException`-swallowing mutant is the mirror image — it survives on H2 because the
closed-connection check fails first there.

One mutant was confirmed equivalent rather than a gap: replacing the null-username
exception with a coercion to `""` still raises `IllegalArgumentException` from the blank
check, changing only the message.

## Limits of these tests

- H2 is not PostgreSQL, MySQL or Oracle. The statement is plain ANSI SQL with one
  placeholder and no vendor syntax, but quoting, collation and type mapping were only
  exercised against H2. Re-run the H2 harness against your real engine before trusting it.
- Case sensitivity and trailing-space comparison follow your column collation, not this
  code. The H2 run shows the default H2 behaviour (`Alice` does not match `alice`); on a
  case-insensitive collation `alice` and `Alice` would be one account. Decide which you
  want at the schema level.
- The unique index is asserted as a requirement but cannot be created in the test schema
  (the duplicate check needs duplicates). Enforce it in your migration.
- `main`'s transaction behaviour is "whatever the connection is already doing" — nothing
  here commits or rolls back.
