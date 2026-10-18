import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
 * Retrieves a user account from the SQL database behind an already open JDBC
 * {@link Connection}, using a username that came from a user.
 *
 * <p>The lookup is a single parameterized statement: the username is sent to the
 * database as a bound parameter of {@value #SELECT_BY_USERNAME}, never spliced into
 * the SQL text, so a username such as {@code admin' -- } is matched literally.
 *
 * <p>The command line entry point is a convenience wrapper. Applications that
 * already hold a connection call {@link #findByUsername(Connection, String)}
 * directly.
 */
public final class UserAccountLookup {

    /**
     * The one statement this class issues. {@code ?} is the username placeholder;
     * the column list is explicit so the mapping never depends on {@code *} ordering
     * and never reads authentication material such as a password hash.
     */
    static final String SELECT_BY_USERNAME =
            "SELECT id, username, email, full_name, status, created_at"
          + " FROM users WHERE username = ?";

    /** Usernames longer than this are rejected before the driver sees them. */
    static final int MAX_USERNAME_LENGTH = 254;

    private UserAccountLookup() {
    }

    /**
     * Looks up the account whose {@code username} equals the supplied value.
     *
     * <p>The caller owns the connection; only the statement and the result set
     * created here are closed.
     *
     * @param connection an open, already-configured JDBC connection; not closed here
     * @param username   the username to search for; surrounding whitespace is ignored
     * @return the matching account, or {@link Optional#empty()} if no row matches
     * @throws IllegalArgumentException   if {@code username} is null, blank, or longer
     *                                    than {@value #MAX_USERNAME_LENGTH} characters
     * @throws NullPointerException       if {@code connection} is null
     * @throws IllegalStateException      if more than one row matches, which means the
     *                                    {@code users.username} unique constraint is missing
     * @throws SQLException               if the database reports an error
     */
    public static Optional<UserAccount> findByUsername(Connection connection, String username)
            throws SQLException {
        Objects.requireNonNull(connection, "connection");
        String normalizedUsername = normalizeUsername(username);

        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
            statement.setString(1, normalizedUsername);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                UserAccount account = toUserAccount(rows);
                if (rows.next()) {
                    throw new IllegalStateException(
                            "More than one row matched the supplied username; users.username"
                                    + " needs a unique index");
                }
                return Optional.of(account);
            }
        }
    }

    private static String normalizeUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String trimmed = username.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (trimmed.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must not be longer than " + MAX_USERNAME_LENGTH + " characters");
        }
        return trimmed;
    }

    private static UserAccount toUserAccount(ResultSet rows) throws SQLException {
        Timestamp createdAt = rows.getTimestamp("created_at");
        return new UserAccount(
                rows.getLong("id"),
                rows.getString("username"),
                rows.getString("email"),
                rows.getString("full_name"),
                rows.getString("status"),
                createdAt == null ? null : createdAt.toInstant());
    }

    /**
     * Reads a username from the first command line argument (or from the first line of
     * standard input when no argument is given) and prints the account it resolves to.
     *
     * <p>The connection is taken from {@code DB_URL}, {@code DB_USER} and
     * {@code DB_PASSWORD}, and the JDBC driver for that URL must be on the class path.
     * Exit status: {@code 0} the query succeeded, {@code 2} bad usage, {@code 3} the
     * database failed.
     */
    public static void main(String[] args) throws IOException {
        String username = args.length > 0 ? args[0] : readUsernameFromStdin();
        if (username == null) {
            System.err.println("usage: java UserAccountLookup <username>   (or pipe it on stdin)");
            System.err.println("       set DB_URL, and optionally DB_USER and DB_PASSWORD");
            System.exit(2);
            return;
        }

        String url = System.getenv("DB_URL");
        if (url == null || url.isBlank()) {
            System.err.println("DB_URL is not set, for example jdbc:h2:mem:app");
            System.exit(2);
            return;
        }

        try (Connection connection =
                     DriverManager.getConnection(url, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {
            Optional<UserAccount> account = findByUsername(connection, username);
            if (account.isEmpty()) {
                System.out.println("No account found for username: " + username.trim());
                return;
            }
            System.out.println(account.get());
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(2);
        } catch (SQLException e) {
            System.err.println("database lookup failed: " + e.getMessage());
            System.exit(3);
        }
    }

    private static String readUsernameFromStdin() throws IOException {
        try (BufferedReader stdin =
                     new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line = stdin.readLine();
            return line == null || line.isBlank() ? null : line;
        }
    }
}

/**
 * A row of the {@code users} table, as far as this lookup reads it.
 *
 * <p>Authentication material is deliberately absent: the statement never selects a
 * password hash or a token, so this type cannot carry one into a log line or a
 * response body. Every component is immutable.
 *
 * @param id        surrogate key
 * @param username  the value that was searched for
 * @param email     address on file
 * @param fullName  display name, may be {@code null} when the column is null
 * @param status    account state as stored, for example {@code ACTIVE}
 * @param createdAt row creation time, {@code null} when the column is null
 */
record UserAccount(long id,
                   String username,
                   String email,
                   String fullName,
                   String status,
                   Instant createdAt) {
}
