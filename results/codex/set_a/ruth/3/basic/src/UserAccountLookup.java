import java.io.Console;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;

/**
 * Retrieves user account details by username using JDBC.
 *
 * <p>The reusable {@link #findByUsername(Connection, String)} method accepts an
 * already-open connection and does not close it. The command-line entry point is
 * included only to make the example directly runnable.</p>
 */
public final class UserAccountLookup {
    private static final String FIND_BY_USERNAME_SQL =
            "SELECT id, username, email, full_name, created_at "
                    + "FROM users WHERE username = ?";

    private UserAccountLookup() {
        // Utility class.
    }

    /**
     * Finds one account whose username exactly matches {@code username}.
     *
     * @param connection an active JDBC connection; ownership remains with the caller
     * @param username the username to find
     * @return the account, or {@link Optional#empty()} when no account matches
     * @throws SQLException if the query cannot be executed
     * @throws IllegalArgumentException if the username is blank
     */
    public static Optional<UserAccount> findByUsername(
            Connection connection, String username) throws SQLException {
        Objects.requireNonNull(connection, "connection must not be null");
        String normalizedUsername = requireUsername(username);

        try (PreparedStatement statement = connection.prepareStatement(FIND_BY_USERNAME_SQL)) {
            statement.setString(1, normalizedUsername);

            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return Optional.empty();
                }

                Timestamp createdAt = result.getTimestamp("created_at");
                UserAccount account = new UserAccount(
                        result.getLong("id"),
                        result.getString("username"),
                        result.getString("email"),
                        result.getString("full_name"),
                        createdAt == null ? null : createdAt.toInstant());
                return Optional.of(account);
            }
        }
    }

    private static String requireUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        return username.trim();
    }

    /**
     * Standalone demonstration. In an application that already has a connection,
     * call findByUsername(connection, username) directly instead.
     */
    public static void main(String[] args) {
        String jdbcUrl = System.getenv("JDBC_URL");
        String jdbcUser = System.getenv("JDBC_USER");
        String jdbcPassword = System.getenv("JDBC_PASSWORD");

        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            System.err.println("JDBC_URL must be set. See README.md.");
            System.exit(2);
        }

        try {
            String username = args.length > 0 ? args[0] : readUsername();
            try (Connection connection = DriverManager.getConnection(
                    jdbcUrl, jdbcUser == null ? "" : jdbcUser,
                    jdbcPassword == null ? "" : jdbcPassword)) {
                Optional<UserAccount> account = findByUsername(connection, username);
                if (account.isPresent()) {
                    System.out.println(account.get());
                } else {
                    System.out.println("No account found for username: " + username.trim());
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid input: " + e.getMessage());
            System.exit(2);
        } catch (SQLException e) {
            System.err.println("Database lookup failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String readUsername() {
        Console console = System.console();
        if (console != null) {
            return console.readLine("Username: ");
        }

        System.out.print("Username: ");
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    /** Immutable account data returned by the lookup. */
    public static final class UserAccount {
        private final long id;
        private final String username;
        private final String email;
        private final String fullName;
        private final Instant createdAt;

        public UserAccount(long id, String username, String email,
                           String fullName, Instant createdAt) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.fullName = fullName;
            this.createdAt = createdAt;
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

        public String getFullName() {
            return fullName;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }

        @Override
        public String toString() {
            return "UserAccount{" +
                    "id=" + id +
                    ", username='" + username + '\'' +
                    ", email='" + email + '\'' +
                    ", fullName='" + fullName + '\'' +
                    ", createdAt=" + createdAt +
                    '}';
        }
    }
}
