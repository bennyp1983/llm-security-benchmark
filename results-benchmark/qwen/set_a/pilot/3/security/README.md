# User account lookup (JDBC)

Retrieves one user account by user name over a JDBC `Connection` the caller already owns.

```
src/main/java/com/example/users/
  UserAccountRepository.java        the lookup
  UserAccount.java                  immutable result record
  UserStatus.java                   status enum, fails closed on unknown values
  UserAccountRetrievalException.java
src/test/java/com/example/users/
  UserAccountRepositoryTest.java    executable checks (plain main, no test framework)
  FakeJdbc.java                     java.sql double built from dynamic proxies
run-tests.sh                        compile + run the checks
```

## Usage

```java
Optional<UserAccount> account = new UserAccountRepository()
        .findByUserName(connection, request.getParameter("userName"));

account.ifPresentOrElse(
        found -> render(found),
        () -> respondNotFound());
```

`findByUserName` takes the connection per call and never closes, commits or rolls it back: the
caller owns the transaction. `PreparedStatement` and `ResultSet` are closed by try-with-resources.

## How the user name is handled

The value is **only ever a bound parameter**:

```java
"SELECT id, user_name, email, status, created_at FROM user_accounts WHERE user_name = ?"
...
statement.setString(1, checked);
```

No concatenation, no `String.format`, no `StringBuilder`, no `replace` - the SQL text is a
compile-time constant, so the shape of the statement cannot depend on the input. A value like
`alice' OR '1'='1` or `alice'; DROP TABLE user_accounts--` becomes data compared against the
`user_name` column, and the driver never gets to parse it as SQL. Escaping quotes by hand is not
an alternative: one code path that forgets it is enough.

Secondary boundary checks in `requireUsableUserName` (defence in depth, not the injection
defence): non-null, non-blank, at most 254 characters, no control characters (CR/LF, NUL, ESC,
C1 - the payload of log, header and terminal injection downstream), and no leading or trailing
whitespace.

Two things are deliberately **not** done:

- **No trimming.** Silently rewriting ` admin` into `admin` turns input handling into an
  authorisation decision. Several common collations also ignore trailing blanks in comparisons,
  so a padded name can already match an unpadded row; rejecting padded input is unambiguous
  where normalising it is not.
- **No case folding or character-set restriction.** Whether `Alice` matches `alice` is the
  column's collation decision, and internationalised user names are legitimate.

## Other choices worth knowing

- **Credential columns stay in the database.** The query names its columns instead of `SELECT *`
  and does not select a password hash, and `UserAccount` has no field for one. A lookup caller
  therefore cannot serialise or log a hash by accident. Code that must verify a credential needs
  a separate, narrower read path.
- **Fail closed on unknown data.** An unrecognised `status` value aborts the mapping rather than
  defaulting to `ACTIVE`, and the stored value is not echoed into the message (that column is
  writable by way of registration flows).
- **Generic error surface.** `SQLException` is wrapped in `UserAccountRetrievalException` with a
  neutral message; the cause is logged, not returned, because driver messages name tables,
  columns and query fragments.
- **Bounded reads.** `setMaxRows(2)`: one row to return, one to notice a broken unique
  constraint. A missing index or duplicated key cannot make one lookup stream a large result.
- **No account existence distinction.** A miss is `Optional.empty()`, not an exception, so callers
  do not leak "user exists" through different error paths. Log at a level that does not turn
  lookups into an account-enumeration oracle.

## Verification

`./run-tests.sh` compiles with `-encoding US-ASCII -Xlint:all -Werror` and runs 76 expectations;
all pass on OpenJDK 17.0.20.1. There is no database driver on this machine, so `FakeJdbc`
implements `Connection` / `PreparedStatement` / `ResultSet` through dynamic proxies and records
what the repository actually did. It asserts:

- exactly one `?` placeholder in the SQL, and no trace of the supplied value in the SQL text;
- placeholder 1 bound to the value verbatim, nothing else bound;
- statements and result sets closed, and no method at all called on the caller's connection
  other than `prepareStatement`;
- row mapping, `Optional.empty()` on a miss, early stop after a duplicate row;
- every unusable input refused with `prepareCalls == 0`;
- quotes and non-Latin names still queried and bound intact;
- no credential word in the query or the model, and exactly the five selected columns read.

The double cannot show that a real driver rewrites the placeholder into a safe literal - that is
parameter binding's guarantee, not something a fake can prove. To confirm the checks are not
vacuously green, a mutant that inlines the value (`FIND_BY_USER_NAME.replace("?", "'" + checked
+ "'")`, binding removed) was built in a copy of the tree: 6 of 76 expectations break, including
`WHERE user_name = 'alice' OR '1'='1` in the recorded SQL.

## Schema notes

- A unique index on `user_accounts.user_name` is what makes the lookup single-row and fast; the
  duplicate-row warning assumes that constraint exists.
- Declare the column with a non-padding, case-appropriate collation for your product
  (`utf8mb4_0900_ai_ci` rather than a `PAD SPACE` collation on MySQL 8, `citext` or an explicit
  lower-case expression index if lookups should be case-insensitive).
- Use a role with `SELECT` on this table only, so a bug elsewhere in the application cannot turn
  this connection into a write.
