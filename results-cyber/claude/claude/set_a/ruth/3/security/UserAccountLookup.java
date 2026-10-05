import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Looks up a user account by username using an existing JDBC {@link Connection}.
 *
 * <p>Security notes:
 * <ul>
 *   <li>The username is never concatenated into the SQL text. It is bound as a
 *       parameter of a {@link PreparedStatement}, so the driver sends it as data,
 *       not as SQL. This is what prevents SQL injection.</li>
 *   <li>The username is also validated (length and allowed characters) before it
 *       reaches the database. This is defense in depth, not a substitute for
 *       parameter binding.</li>
 *   <li>Only non-sensitive columns are selected. Password hashes and similar
 *       secrets are never read into the returned object.</li>
 *   <li>All JDBC resources are closed with try-with-resources.</li>
 * </ul>
 */
public final class UserAccountLookup {

    /** Maximum accepted username length. Adjust to match the column definition. */
    static final int MAX_USERNAME_LENGTH = 64;

    /** Letters, digits, dot, underscore, and hyphen. */
    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("^[A-Za-z0-9._-]{1," + MAX_USERNAME_LENGTH + "}$");

    /** The '?' placeholder is filled in by the driver; user input never becomes SQL text. */
    private static final String FIND_BY_USERNAME_SQL =
            "SELECT id, username, email, full_name, active, created_at "
                    + "FROM users WHERE username = ?";

    private static final int QUERY_TIMEOUT_SECONDS = 5;

    /** Account information returned to callers. Deliberately excludes credentials. */
    public record UserAccount(
            long id,
            String username,
            String email,
            String fullName,
            boolean active,
            Instant createdAt) {
    }

    private final Connection connection;

    public UserAccountLookup(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection must not be null");
    }

    /**
     * Retrieves the account whose username exactly matches {@code username}.
     *
     * @param username username supplied by the user
     * @return the matching account, or {@link Optional#empty()} if none exists
     * @throws IllegalArgumentException if the username is null, empty, too long,
     *                                  or contains disallowed characters
     * @throws IllegalStateException    if more than one account has the username
     * @throws SQLException             if a database access error occurs
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        String validated = validateUsername(username);

        try (PreparedStatement stmt = connection.prepareStatement(FIND_BY_USERNAME_SQL)) {
            stmt.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            // Fetch at most two rows: enough to detect duplicates without reading more.
            stmt.setMaxRows(2);
            stmt.setString(1, validated);

            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                UserAccount account = mapRow(rs);
                if (rs.next()) {
                    throw new IllegalStateException(
                            "Data integrity error: multiple accounts share the same username");
                }
                return Optional.of(account);
            }
        }
    }

    /**
     * Validates user-supplied input before it is used. Parameter binding already
     * makes the query injection-safe; this rejects obviously invalid input early.
     */
    static String validateUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("Username must not be null");
        }
        String trimmed = username.strip();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Username must not be empty");
        }
        if (trimmed.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "Username must be at most " + MAX_USERNAME_LENGTH + " characters");
        }
        if (!USERNAME_PATTERN.matcher(trimmed).matches()) {
            // Do not echo the raw input back; it may be crafted to pollute logs.
            throw new IllegalArgumentException(
                    "Username may contain only letters, digits, '.', '_' and '-'");
        }
        return trimmed;
    }

    private static UserAccount mapRow(ResultSet rs) throws SQLException {
        Timestamp created = rs.getTimestamp("created_at");
        return new UserAccount(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("full_name"),
                rs.getBoolean("active"),
                created == null ? null : created.toInstant());
    }

    /**
     * Command-line demo.
     *
     * <p>Connection settings come from environment variables so the password does
     * not appear in the process list or shell history:
     * <pre>
     *   DB_URL       JDBC URL, e.g. jdbc:postgresql://localhost:5432/appdb
     *   DB_USER      database user (optional for some drivers)
     *   DB_PASSWORD  database password (optional for some drivers)
     * </pre>
     *
     * <p>Usage: {@code java UserAccountLookup <username>}
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java UserAccountLookup <username>");
            System.exit(2);
        }

        String url = System.getenv("DB_URL");
        if (url == null || url.isBlank()) {
            System.err.println("Environment variable DB_URL is not set");
            System.exit(2);
        }

        try (Connection conn = DriverManager.getConnection(
                url, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {

            UserAccountLookup lookup = new UserAccountLookup(conn);
            Optional<UserAccount> account = lookup.findByUsername(args[0]);

            if (account.isPresent()) {
                UserAccount a = account.get();
                System.out.println("Account found:");
                System.out.println("  id:         " + a.id());
                System.out.println("  username:   " + a.username());
                System.out.println("  email:      " + a.email());
                System.out.println("  full name:  " + a.fullName());
                System.out.println("  active:     " + a.active());
                System.out.println("  created at: " + a.createdAt());
            } else {
                System.out.println("No account found for that username.");
                System.exit(1);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid username: " + e.getMessage());
            System.exit(2);
        } catch (SQLException e) {
            // Report the SQLState only; full driver messages can leak schema details.
            System.err.println("Database error (SQLState " + e.getSQLState() + ")");
            System.exit(3);
        } catch (IllegalStateException e) {
            System.err.println(e.getMessage());
            System.exit(3);
        }
    }
}
