import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;

/**
 * Retrieves user accounts by username using an existing JDBC connection.
 *
 * <p>The query uses a PreparedStatement so the supplied username is treated as
 * data, rather than being concatenated into SQL.</p>
 */
public final class AccountLookup {
    private static final String FIND_BY_USERNAME_SQL =
            "SELECT id, username, email, display_name, active "
                    + "FROM user_accounts WHERE username = ?";

    private final Connection connection;

    /**
     * Creates an account lookup service backed by an active JDBC connection.
     * The caller remains responsible for closing the connection.
     */
    public AccountLookup(Connection connection) throws SQLException {
        this.connection = Objects.requireNonNull(connection, "connection must not be null");
        if (connection.isClosed()) {
            throw new IllegalArgumentException("connection must be open");
        }
    }

    /**
     * Finds the account whose username exactly matches {@code username}.
     *
     * @return the matching account, or {@link Optional#empty()} if none exists
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }

        try (PreparedStatement statement = connection.prepareStatement(FIND_BY_USERNAME_SQL)) {
            statement.setString(1, username);

            try (ResultSet results = statement.executeQuery()) {
                if (!results.next()) {
                    return Optional.empty();
                }

                UserAccount account = new UserAccount(
                        results.getLong("id"),
                        results.getString("username"),
                        results.getString("email"),
                        results.getString("display_name"),
                        results.getBoolean("active"));
                return Optional.of(account);
            }
        }
    }

    /** Immutable account data returned by {@link #findByUsername(String)}. */
    public static final class UserAccount {
        private final long id;
        private final String username;
        private final String email;
        private final String displayName;
        private final boolean active;

        public UserAccount(long id, String username, String email,
                           String displayName, boolean active) {
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

    /**
     * Optional command-line demonstration. Production code should normally
     * construct AccountLookup with its application's existing connection.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java ... AccountLookup <username>");
            System.exit(2);
        }

        String jdbcUrl = requireEnvironmentVariable("JDBC_URL");
        String databaseUser = requireEnvironmentVariable("DB_USER");
        String databasePassword = requireEnvironmentVariable("DB_PASSWORD");

        try (Connection connection = DriverManager.getConnection(
                jdbcUrl, databaseUser, databasePassword)) {
            AccountLookup lookup = new AccountLookup(connection);
            Optional<UserAccount> account = lookup.findByUsername(args[0]);
            if (account.isPresent()) {
                System.out.println(account.get());
            } else {
                System.out.println("No account found for that username.");
            }
        } catch (SQLException exception) {
            System.err.println("Database lookup failed: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static String requireEnvironmentVariable(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(name + " environment variable is required");
        }
        return value;
    }
}
