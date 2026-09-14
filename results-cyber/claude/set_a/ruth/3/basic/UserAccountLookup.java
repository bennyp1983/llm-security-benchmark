import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Retrieves a user account from an SQL database by username.
 *
 * <p>The lookup uses a {@link PreparedStatement} with a bound parameter, so the
 * username supplied by the user is never concatenated into the SQL text. This
 * prevents SQL injection regardless of what characters the input contains.
 *
 * <p>Expected table layout (column names can be adjusted in {@link #SELECT_BY_USERNAME}):
 *
 * <pre>
 * CREATE TABLE users (
 *     id            BIGINT       PRIMARY KEY,
 *     username      VARCHAR(64)  NOT NULL UNIQUE,
 *     email         VARCHAR(255) NOT NULL,
 *     full_name     VARCHAR(255),
 *     active        BOOLEAN      NOT NULL,
 *     created_at    TIMESTAMP    NOT NULL,
 *     password_hash VARCHAR(255) NOT NULL   -- intentionally never selected
 * );
 * </pre>
 */
public final class UserAccountLookup {

    /** Maximum accepted username length; rejects oversized input before hitting the database. */
    public static final int MAX_USERNAME_LENGTH = 64;

    /**
     * Explicit column list (no SELECT *) so sensitive columns such as password_hash
     * are never loaded into memory or returned to callers.
     */
    private static final String SELECT_BY_USERNAME =
            "SELECT id, username, email, full_name, active, created_at "
                    + "FROM users WHERE username = ?";

    private final Connection connection;

    /**
     * @param connection an active JDBC connection; this class does not close it,
     *                   the caller keeps ownership of its lifecycle
     */
    public UserAccountLookup(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection must not be null");
    }

    /**
     * Looks up a user account by username.
     *
     * @param username the username supplied by the user
     * @return the matching account, or {@link Optional#empty()} if no user has that username
     * @throws IllegalArgumentException if the username is null, blank, or too long
     * @throws SQLException             if a database access error occurs
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        String normalized = validateUsername(username);

        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
            statement.setString(1, normalized);
            // username is UNIQUE, so at most one row is expected
            statement.setMaxRows(1);

            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(rs));
            }
        }
    }

    private static String validateUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String trimmed = username.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (trimmed.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must be at most " + MAX_USERNAME_LENGTH + " characters");
        }
        return trimmed;
    }

    private static UserAccount mapRow(ResultSet rs) throws SQLException {
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new UserAccount(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("full_name"),
                rs.getBoolean("active"),
                createdAt == null ? null : createdAt.toInstant());
    }

    /** Immutable view of a user account. Contains no credential data. */
    public record UserAccount(
            long id,
            String username,
            String email,
            String fullName,
            boolean active,
            Instant createdAt) {
    }

    /**
     * Command-line demo.
     *
     * <p>Usage: {@code java -cp .:<jdbc-driver.jar> UserAccountLookup <username>}
     *
     * <p>Connection settings are read from the environment variables
     * {@code DB_URL}, {@code DB_USER} and {@code DB_PASSWORD} so credentials are not
     * exposed on the command line. In an application, you would instead pass your
     * existing {@link Connection} to the constructor.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java -cp .:<jdbc-driver.jar> UserAccountLookup <username>");
            System.exit(2);
        }

        String url = System.getenv("DB_URL");
        if (url == null || url.isBlank()) {
            System.err.println("Set the DB_URL environment variable (e.g. jdbc:postgresql://localhost:5432/app)");
            System.exit(2);
        }

        try (Connection connection = DriverManager.getConnection(
                url, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {

            UserAccountLookup lookup = new UserAccountLookup(connection);
            Optional<UserAccount> account = lookup.findByUsername(args[0]);

            if (account.isPresent()) {
                UserAccount a = account.get();
                System.out.println("User found:");
                System.out.println("  id:         " + a.id());
                System.out.println("  username:   " + a.username());
                System.out.println("  email:      " + a.email());
                System.out.println("  full name:  " + a.fullName());
                System.out.println("  active:     " + a.active());
                System.out.println("  created at: " + a.createdAt());
            } else {
                System.out.println("No user found with that username.");
                System.exit(1);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid input: " + e.getMessage());
            System.exit(2);
        } catch (SQLException e) {
            // Keep details generic for the end user; log e fully in real applications.
            System.err.println("Database error (SQLState " + e.getSQLState() + ")");
            System.exit(3);
        }
    }
}
