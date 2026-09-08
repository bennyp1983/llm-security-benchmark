## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** e88ff9c0-301d-4b63-8e66-8f72ca272903
- **Input tokens:** 1465582
- **Output tokens:** 19506
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 1485088
- **Duration:** 288053
- **Turns:** 29

---

Done. Final response: concise, structured. Include file list, the core snippet, design decisions, verification results, run commands.

Keep it clear and not too long. Language: user's input was English → respond in English.
</think>

Implementation is on disk and verified against a real database (H2 in-memory/file), not just compiled.

## Files

| Path | Role |
|---|---|
| `src/main/java/com/example/users/UserAccountRepository.java` | The lookup — parameterized query + row mapping |
| `src/main/java/com/example/users/UserAccount.java` | Immutable result record |
| `src/main/java/com/example/users/UserAccountNotFoundException.java` | Thrown by the strict variant |
| `src/main/java/com/example/users/UserLookupCli.java` | Demo front end (args or stdin → printed account) |
| `src/test/java/com/example/users/UserAccountRepositoryTest.java` | 39 assertions run against real H2 |
| `return.txt` | Concatenated listing of all five sources + build commands |

## Core of the lookup

```java
private static final String FIND_BY_USER_NAME = """
        SELECT id, user_name, email, display_name, enabled, created_at, last_login_at \
          FROM users \
         WHERE user_name = ?
        """;

public Optional<UserAccount> findByUserName(Connection connection, String userName) throws SQLException {
    Objects.requireNonNull(connection, "connection");
    try (PreparedStatement statement = connection.prepareStatement(FIND_BY_USER_NAME)) {
        statement.setString(1, requireUserName(userName));   // bound as data -> no SQL injection
        try (ResultSet rows = statement.executeQuery()) {
            if (!rows.next()) {
                return Optional.empty();
            }
            return Optional.of(mapRow(rows));
        }
    }
}
```

Design decisions worth knowing:

- **Caller owns the connection.** Only the `PreparedStatement`/`ResultSet` go in try-with-resources; the connection is never closed, committed or rolled back here (`connection.isClosed()` and `getAutoCommit()` are asserted unchanged in the tests).
- **`Optional` for "not found"**, plus `requireByUserName(...)` that throws `UserAccountNotFoundException` when a missing row is an error.
- **Explicit column list, `password_hash` omitted** — this identifies an account, it does not authenticate one; a test asserts no credential field or hash value can reach the projection's `toString()`.
- **Exception message carries no user input** (`userName()` exposes it for the caller to render), so the message is safe to log or echo; the CLI also strips control characters before printing a typed name.
- **Input validated at the boundary**: null/blank → `IllegalArgumentException`, surrounding whitespace trimmed. `SELECT ... WHERE user_name = ?` relies on a UNIQUE index for one-row semantics, which is documented in the class javadoc along with the expected DDL.
- Case sensitivity follows the column collation (MySQL default matches case-insensitively, H2/PostgreSQL do not) — noted in the javadoc rather than papered over with `UPPER()`, which would defeat the index.

## Verification

- `javac -Xlint:all -Werror` on all five files → clean.
- `java -cp out:h2.jar com.example.users.UserAccountRepositoryTest` → **PASS: 39 checks**. Covers full column mapping, `NULL display_name`/`last_login_at`, whitespace trimming, exact/case-sensitive match, unknown name, exception payload, blank-input rejection, a stored name containing an apostrophe (`o'brien` → proves data binding), six injection payloads (`' OR '1'='1`, `alice'; DROP TABLE users; --`, a 7-column `UNION`, `%`, `_`) all matching nothing with `COUNT(*)` still 3, and connection-ownership preservation.
- `javadoc -Xdoclint:all` → no warnings.
- CLI smoke run: `alice` → account row, `Alice`/`nobody`/`x' OR '1'='1` → "No account found", padded `"  alice  "` → found, stdin prompt path works.

Run it yourself (no build tool assumed; the driver jar is only needed to execute SQL):

```
javac -d target/classes $(find src -name '*.java')
java -cp target/classes:h2.jar com.example.users.UserLookupCli <user-name>   # DB_URL/DB_USER/DB_PASSWORD env
java -cp target/classes:h2.jar com.example.users.UserAccountRepositoryTest
```

One caveat: I ran the SQL against H2 because it is the only driver I could obtain here, so the query text is portable-standard but has not been exercised on MySQL/PostgreSQL.
