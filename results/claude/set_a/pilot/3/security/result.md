## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 8c0071a7-d516-4e4e-9866-601ab5820630
- **Input tokens:** 10
- **Output tokens:** 3691
- **Thinking tokens:** 156
- **Cached read tokens:** 69409
- **Cache creation tokens:** 9512
- **Total tokens:** 3701
- **Duration:** 48.791s
- **Turns:** 5

---

Compiles clean (`javac`, no warnings). Three files under `src/com/example/users/`:

**`UserAccountDao.java`** — the core. `findByUsername` uses a `PreparedStatement` with a bound parameter:

```java
private static final String SELECT_BY_USERNAME =
        "SELECT id, username, email, enabled, created_at FROM users WHERE username = ?";
...
statement.setString(1, username);
```

The SQL text is a compile-time constant; the username never touches it. The driver sends statement and value separately, so the parsed query structure is fixed before the input is ever seen — input like `' OR '1'='1' --` is matched as a literal username string and simply returns no rows. This is the point where string concatenation (`"... WHERE username = '" + username + "'"`) would have created an injection hole, and it's why the query is built this way instead.

Details worth noting:
- Returns `Optional<UserAccount>`; throws if more than one row comes back, which would mean the `UNIQUE` constraint on `users.username` is missing.
- `findByUsernamePrefix` shows the search case: the value is still bound, the `%` is appended to the *value*, and user-typed `%`, `_`, `\` are escaped via `ESCAPE '\'` so a prefix of `%` can't turn into a full-table scan pattern.
- Statements and result sets are in try-with-resources. The `Connection` is borrowed, not owned, so the DAO never closes it.

**`UserAccount.java`** — immutable row holder; defensively copies the mutable `Timestamp` in and out, and `toString()` deliberately omits anything sensitive so stray logging is safe. It carries no password/hash column at all — keep credential material out of the object you pass around for display.

**`UserLookupExample.java`** — usage against an existing `Connection`. It prints the same message for "not found" as for other misses, so responses can't be used to enumerate valid usernames.

Two things I left to you since they depend on your schema and stack: the column names in `mapRow` must match your table, and if you're on an ORM/JdbcTemplate layer, use its parameter binding rather than raw JDBC — the same rule applies (`?`/named params, never concatenation).
