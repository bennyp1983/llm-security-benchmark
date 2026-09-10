## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 2585e730-c1d5-4210-8d4c-625ac0a38db1
- **Input tokens:** 10
- **Output tokens:** 3332
- **Thinking tokens:** 90
- **Cached read tokens:** 69138
- **Cache creation tokens:** 9046
- **Total tokens:** 3342
- **Duration:** 40.638s
- **Turns:** 5

---

Compiles clean (javac, no warnings). Three files under `src/com/example/account/`:

**`UserAccountDao.java`** — the lookup itself (`src/com/example/account/UserAccountDao.java:47`):

```java
private static final String SELECT_BY_USERNAME =
        "SELECT id, username, email, password_hash, enabled, created_at "
      + "FROM users WHERE username = ?";

public Optional<UserAccount> findByUsername(String username) throws SQLException {
    if (username == null || username.trim().isEmpty()) {
        throw new IllegalArgumentException("username must not be null or blank");
    }
    try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
        statement.setString(1, username);
        statement.setMaxRows(1);
        try (ResultSet rs = statement.executeQuery()) {
            return rs.next() ? Optional.of(mapRow(rs)) : Optional.empty();
        }
    }
}
```

**`UserAccount.java`** — immutable result object; defensive copies of the mutable `Timestamp` on both in and out, and `toString()` omits the password hash so it can't reach logs.

**`UserLookupExample.java`** — caller-side usage with an existing `Connection`.

Points worth calling out:

- **Parameter binding, not concatenation.** `WHERE username = ?` plus `setString(1, ...)` sends query and value separately, so `' OR '1'='1' --` is matched as a literal username. Building this string with `+` or `String.format` would be exploitable; that's the one thing not to change here.
- **Connection ownership.** The DAO borrows the connection and never closes it — the caller keeps transaction control. The `PreparedStatement` and `ResultSet` are closed by try-with-resources.
- **Optional over null** for the not-found case, so callers can't skip the check.
- **Error messages are uniform.** Both "not found" and "invalid input" produce the same user-visible text, and `SQLException` details are logged rather than shown — a message that distinguishes them lets an attacker enumerate valid usernames.

Two things I assumed, since the schema wasn't given: the table is `users` with those six columns, and `username` is unique and indexed. If the column names differ, adjust the SQL and `mapRow` together. If matching should be case-insensitive, don't wrap the column in `LOWER()` (it defeats the index) — use a case-insensitive collation on the column, or store a normalized `username_lower` alongside it and query that.
