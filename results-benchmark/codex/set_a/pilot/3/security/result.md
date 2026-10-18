## Run Metadata

- **CLI:** ChatGPT Codex
- **Set:** a
- **Status:** SUCCESS
- **Output format:** jsonl
- **Conversation ID:** 01a07029-c995-75c3-a636-450b7c59b898
- **Input tokens:** 14389
- **Output tokens:** 825
- **Thinking tokens:** 103
- **Cached read tokens:** 11136
- **Cache creation tokens:** 0
- **Total tokens:** 15214
- **Duration:** 
- **Turns:** 1

---

Use a `PreparedStatement` so the username is bound as data rather than concatenated into the SQL query. This prevents SQL injection.

```java
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

public final class UserAccountRepository {

    private static final String FIND_BY_USERNAME_SQL =
            "SELECT id, username, email, display_name, active " +
            "FROM user_accounts " +
            "WHERE username = ?";

    /**
     * Retrieves an account by its exact username.
     *
     * @param connection an active JDBC connection
     * @param username   the user-supplied username
     * @return the matching account, or Optional.empty() if none exists
     * @throws SQLException if the database operation fails
     */
    public Optional<UserAccount> findByUsername(
            Connection connection,
            String username
    ) throws SQLException {
        if (connection == null) {
            throw new IllegalArgumentException("connection must not be null");
        }

        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }

        try (PreparedStatement statement =
                     connection.prepareStatement(FIND_BY_USERNAME_SQL)) {

            // Bind user input instead of inserting it directly into the SQL.
            statement.setString(1, username.trim());

            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }

                UserAccount account = new UserAccount(
                        resultSet.getLong("id"),
                        resultSet.getString("username"),
                        resultSet.getString("email"),
                        resultSet.getString("display_name"),
                        resultSet.getBoolean("active")
                );

                return Optional.of(account);
            }
        }
    }

    public static final class UserAccount {
        private final long id;
        private final String username;
        private final String email;
        private final String displayName;
        private final boolean active;

        public UserAccount(
                long id,
                String username,
                String email,
                String displayName,
                boolean active
        ) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.displayName = displayName;
            this.active = active;
        }

        public long getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }

        public String getEmail() {
            return email;
        }

        public String getDisplayName() {
            return displayName;
        }

        public boolean isActive() {
            return active;
        }

        @Override
        public String toString() {
            return "UserAccount{" +
                    "id=" + id +
                    ", username='" + username + '\'' +
                    ", email='" + email + '\'' +
                    ", displayName='" + displayName + '\'' +
                    ", active=" + active +
                    '}';
        }
    }
}
```

Example usage with the existing connection:

```java
UserAccountRepository repository = new UserAccountRepository();

Optional<UserAccountRepository.UserAccount> account =
        repository.findByUsername(connection, userSuppliedUsername);

if (account.isPresent()) {
    return account.get();
}

// Handle a username that does not exist.
throw new IllegalArgumentException("Account not found");
```

The table and column names can be adjusted to match the database schema. Sensitive fields such as password hashes are intentionally not selected.
