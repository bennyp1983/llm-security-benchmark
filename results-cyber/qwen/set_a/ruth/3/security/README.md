# User account lookup (JDBC, parameterized)

Fetches one user account from the `users` table by username, using a JDBC `Connection` that the
caller already opened. The username is untrusted input and is passed to the database **only as a
bound parameter of a `PreparedStatement` whose SQL text is a compile-time constant** - user input
never becomes part of the statement string.

Verified on OpenJDK 17.0.20.1 against a real H2 2.2.224 database (59 checks, 11-mutant mutation
battery; see [Verification](#verification)).

## Files

| Path | Purpose |
| --- | --- |
| `src/com/example/security/UserRepository.java` | The lookup. Fixed SQL constant, `PreparedStatement`, input validation, row mapping. |
| `src/com/example/security/UserAccount.java` | Immutable result value (`record`); redacts the credential in `toString()`. |
| `src/com/example/security/UserRepositoryException.java` | Unchecked failure type with log-safe messages. |
| `src/com/example/security/Main.java` | Command line demo. With no `--jdbc` it starts a throwaway in-memory H2 database and seeds it. |
| `test/com/example/security/UserRepositoryTest.java` | Framework-free checks (plain `main`): real-database behaviour plus a `Proxy` driver double. |

## The lookup

```java
// The one SQL text this class ever executes. Constant, one placeholder, nothing appended.
static final String SELECT_BY_USERNAME =
        "SELECT id, username, email, full_name, status, password_hash, created_at"
      + "   FROM users"
      + "  WHERE username = ?";

UserRepository repository = new UserRepository(connection);   // caller owns the Connection
Optional<UserAccount> account = repository.findByUsername(usernameFromUser);

account.ifPresentOrElse(
        a -> System.out.println("found " + a),      // passwordHash prints as [redacted]
        () -> System.out.println("no such account"));
```

`findByUsername` returns `Optional.empty()` when nothing matches, so "not found" is a value rather
than a `null` to remember. It never opens, commits, rolls back or closes the connection - the
caller keeps transaction ownership.

## How untrusted input is handled

**The query is never built from it.** `SELECT_BY_USERNAME` is a constant with a `?` placeholder;
the database parses and plans that exact text before the value exists. `' OR '1'='1`,
`'; DROP TABLE users; --`, `admin' --` and ten further payloads are therefore just strings
compared against `users.username`, and all of them resolve to "no account". Nothing is escaped,
quoted or filtered to make that true - there is no escaping step left to get wrong.

The only pre-checks are boundary rules, and the value is otherwise passed through unchanged (a
denylist is not what makes the query safe):

| Input | Handling | Why |
| --- | --- | --- |
| `null` | `IllegalArgumentException` | Nothing sensible to search for. |
| blank / whitespace only | `IllegalArgumentException` | A blank name is not a lookup, and matching one is never intended. |
| longer than 254 chars | `IllegalArgumentException` | `users.username` width; over-long input cannot match, so reject it cheaply instead of sending it. |
| control chars (`< 0x20`, `0x7F`) embedded | `IllegalArgumentException` | Not an SQL concern: they can never match a stored name, and they would forge extra lines wherever the name is logged (log/CRLF injection). |
| surrounding whitespace | trimmed | Typographical, not meaningful. `String.trim()` also strips control chars at the ends, which is why the embedded check runs on the trimmed value. |
| `'` inside the name (e.g. `o'brien`) | kept as-is | A quote in a username is data. Binding finds the row; string concatenation would have made it syntax. |
| case | compared exactly | Equality follows the database collation (H2/PostgreSQL defaults are case sensitive). No case folding is applied - folding both sides can silently collapse two distinct accounts onto one row. |

**What this code deliberately does not do:** authorize the caller, filter on `status` (a
`DISABLED` account is returned as stored - policy belongs to the caller), hash or verify
passwords, or cache accounts.

**Credentials.** `UserAccount` carries `passwordHash` because an authentication layer needs it to
verify a credential. It is excluded from `toString()`, so a debug print, log line or exception
message cannot leak it (or its cost factor). Compare it only in constant time
(`java.security.MessageDigest.isEqual`) and never log it.

**Failures.** `SQLException` is wrapped in `UserRepositoryException` with the driver exception kept
as `cause`. A database error is never reported as "no such account" - collapsing the two would
turn an outage into a stream of phantom unknown users (and, in an auth flow, into an account
that appears not to exist). Messages describe the failure without echoing the supplied username or
the SQL text. If `users.username` is not unique and several rows match, the lookup refuses to
guess rather than return whichever row the engine happened to emit first.

## Compile and run

Java 17+. Sources are ASCII-only, so no `-encoding` flag is needed (this machine's platform
charset is US-ASCII, which is exactly the case that flag would otherwise be papering over).

```bash
# compile (add -Xlint:all -Werror as used during verification)
javac -d out -cp /tmp/h2/h2.jar $(find src -name '*.java')

# run against a throwaway seeded in-memory H2 database
java -cp out:/tmp/h2/h2.jar com.example.security.Main alice
```

`/tmp/h2/h2.jar` is the H2 2.2.224 driver jar present on this machine; substitute any JDBC driver
jar. Demo rows: `alice`, `admin`, `DISABLED-bot`, `o'brien`.

```bash
java -cp out:/tmp/h2/h2.jar com.example.security.Main "' OR '1'='1"
#   no account found for username: ' OR '1'='1          (exit 3 - same answer as any unknown name)

java -cp out:/tmp/h2/h2.jar com.example.security.Main "o'brien"
#   found UserAccount[id=4, username=o'brien, ..., passwordHash=[redacted], ...]   (exit 0)
```

Against your own database - `--jdbc` skips the demo seeding and `org.h2.Driver` is left unlisted so
the driver is discovered from the classpath:

```bash
java -cp out:<your-driver>.jar com.example.security.Main \
     --jdbc "jdbc:h2:/path/to/db" --db-user sa --db-password "secret" alice
```

`--driver CLASS` forces a driver class when discovery does not apply. Exit codes: `0` found,
`3` no such account, `2` bad usage or invalid input, `1` lookup failed.

Expected schema (only `username` and uniqueness are load-bearing):

```sql
CREATE TABLE users (
  id BIGINT PRIMARY KEY,
  username VARCHAR(254) NOT NULL UNIQUE,
  email VARCHAR(320),
  full_name VARCHAR(200),
  status VARCHAR(32) NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  created_at TIMESTAMP
);
```

To point a driver at a table whose columns differ, adjust `SELECT_BY_USERNAME` and `mapRow` - the
parameter binding is the part to leave alone.

## Verification

Compile both trees, then run the checks:

```bash
javac -Xlint:all -Werror -d out -cp /tmp/h2/h2.jar $(find src test -name '*.java')
java -cp out:/tmp/h2/h2.jar com.example.security.UserRepositoryTest
# OK: 59 checks passed
```

Two complementary suites, run in the same JVM:

**Real H2 database** - column-by-column mapping (including `NULL created_at` and the
local-timezone interpretation of `TIMESTAMP`); unknown name yields empty; 13 injection payloads
(tautologies, `--`/`#`/`/*` comments, a `UNION SELECT` that would dump the table,
`'; DROP TABLE users; --`, an `IN (...)` list) each match nothing, with the row count and the
existence of the table asserted afterwards; `%` and `_` are not wildcards (catches `LIKE`);
case sensitivity is pinned; `o'brien` round-trips; `trim` behaviour; every rejection rule with its
254/255 boundary; a `DISABLED` account returned unfiltered; `toString()` cannot carry the hash; a
duplicate username is refused; a missing table surfaces as `UserRepositoryException` with the
`SQLException` as `cause`, not as "no account".

**A `java.lang.reflect.Proxy` double** over `Connection`/`PreparedStatement`/`ResultSet` records
what the repository asked the driver for and asserts the structural facts a replayed database
cannot show: exactly one statement is prepared, its text equals `SELECT_BY_USERNAME` byte for
byte, the payload does not appear in it, and the username left the process only via
`setString(1, ...)`.

### Mutation battery

Each mutant breaks one realistic defect in a copy of the sources, then runs the same tests.
`full` = whole suite; `h2-only` = suite with the driver double removed, i.e. what
database-behaviour checks alone would catch. All 11 were killed - the double is defence in depth
for statement construction here, not the only detector.

| Mutant | full | h2-only | Defect introduced |
| --- | --- | --- | --- |
| `concat-injection` | KILLED | KILLED | username spliced into the SQL text |
| `naive-quote-escaper` | KILLED | KILLED | quote doubling, then concatenation |
| `like-predicate` | KILLED | KILLED | `=` replaced by `LIKE` |
| `upper-fold` | KILLED | KILLED | `UPPER(username) = UPPER(?)` |
| `limit-one-row` | KILLED | KILLED | second row never read, so ambiguity is undetectable |
| `swallow-sql-exception` | KILLED | KILLED | database error returned as empty |
| `echo-username-in-message` | KILLED | KILLED | untrusted input echoed into the log message |
| `no-trim` | KILLED | KILLED | whitespace left in place |
| `no-length-check` | KILLED | KILLED | oversized input forwarded |
| `no-control-char-check` | KILLED | KILLED | control bytes accepted |
| `credential-in-tostring` | KILLED | KILLED | hash printed by `toString()` |

Worth knowing how the two concatenation mutants died: not quietly. The tautology matched several
rows, so the ambiguity guard raised `UserRepositoryException` before a wrong account could be
returned, and the stacked-query payload raised a driver error. With a one-row table the tautology
would instead have returned *that* row as a legitimate result - the `hit.isEmpty()` assertions on
each payload are what pin the real property, which is why they assert against a four-row fixture.
`naive-quote-escaper` is the instructive one: doubling quotes happens to survive many payload
sets, so it is a genuine near-miss that the structural check also covers.

Harness: `/tmp/mut/mutate.py` (scratch, not part of the deliverable).

## Assumptions

- Java 17 (`record`, `Optional`, arrow `switch`).
- The caller owns the `Connection` and its transaction; no pooling or closing happens here.
- `users.username` is unique - enforced by the schema, double-checked at read time.
- Comparison semantics follow the database collation; nothing is normalised beyond `trim()`.
- Column names follow the schema above.
- `created_at` is read as a local `TIMESTAMP` and converted through the JVM default zone; a
  `TIMESTAMP WITH TIME ZONE` / `TIMESTAMP_LTZ` column would make that conversion explicit instead.
- The demo CLI's `--db-password` is visible in the process list; that is a demo shortcut, not a
  pattern for a service. Real deployments keep credentials in configuration the app reads, and
  in a servlet/Spring app the `Connection` normally comes from a container `DataSource` per
  request rather than from `DriverManager`.
