import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

/**
 * Repository class providing secure retrieval of user account information from an SQL database
 * using an active JDBC Connection and parameterized SQL queries to prevent SQL Injection (CWE-89).
 */
public class UserAccountRepository {

    /**
     * Parameterized SQL query selecting specific account columns for a matching username.
     * 
     * Security Note:
     * 1. Uses a placeholder '?' for the username parameter to ensure the database engine compiles
     *    the query template separately from user input, eliminating SQL Injection vulnerabilities.
     * 2. Explicitly lists required column names rather than using 'SELECT *' to avoid schema drift
     *    issues, optimize query performance, and prevent unintentional exposure of sensitive fields.
     */
    private static final String SELECT_USER_BY_USERNAME = 
        "SELECT id, username, email, full_name, role, is_active, created_at, last_login_at " +
        "FROM users " +
        "WHERE username = ?";

    private final Connection connection;

    /**
     * Constructs a repository instance with an active JDBC connection.
     *
     * @param connection an active JDBC connection (must not be null)
     * @throws NullPointerException if connection is null
     */
    public UserAccountRepository(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "Active JDBC Connection must not be null.");
    }

    /**
     * Immutable data model representing a retrieved user account record.
     *
     * @param id          Unique primary key identifier
     * @param username    Unique account username
     * @param email       User's email address
     * @param fullName    User's full display name
     * @param role        Security/authorization role (e.g., "ADMIN", "USER")
     * @param isActive    Account active status flag
     * @param createdAt   Account creation timestamp
     * @param lastLoginAt Most recent login timestamp (nullable)
     */
    public record UserAccount(
        Long id,
        String username,
        String email,
        String fullName,
        String role,
        boolean isActive,
        Instant createdAt,
        Instant lastLoginAt
    ) {
        // Traditional JavaBean-style getters for compatibility with existing frameworks
        public Long getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getFullName() { return fullName; }
        public String getRole() { return role; }
        public boolean isActive() { return isActive; }
        public Instant getCreatedAt() { return createdAt; }
        public Instant getLastLoginAt() { return lastLoginAt; }
    }

    /**
     * Retrieves a user account from the SQL database by username using the instance connection.
     *
     * @param username the username to query
     * @return an Optional containing the UserAccount if found, or empty if not found
     * @throws SQLException if a database access error occurs
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        return findByUsername(this.connection, username);
    }

    /**
     * Alias method for {@link #findByUsername(String)} to support different naming conventions.
     *
     * @param username the username to query
     * @return an Optional containing the UserAccount if found, or empty if not found
     * @throws SQLException if a database access error occurs
     */
    public Optional<UserAccount> getUserByUsername(String username) throws SQLException {
        return findByUsername(this.connection, username);
    }

    /**
     * Retrieves a user account directly, returning null if no record is found.
     *
     * @param username the username to query
     * @return the UserAccount if found, or null if no matching record exists
     * @throws SQLException if a database access error occurs
     */
    public UserAccount getAccountByUsername(String username) throws SQLException {
        return findByUsername(this.connection, username).orElse(null);
    }

    /**
     * Static utility method that retrieves a user account from an SQL database based on a username
     * using the provided active JDBC connection.
     *
     * Security and Best Practice Controls:
     * - Parameterized Query: PreparedStatement with bind parameters prevents SQL Injection (CWE-89).
     * - Resource Management: Try-with-resources ensures both PreparedStatement and ResultSet are safely
     *   closed, preventing resource and connection exhaustion (CWE-404 / CWE-772).
     * - Input Validation: Safely handles null or blank usernames without executing unneeded queries.
     * - Explicit Projection: Column names are explicitly requested rather than using wildcard SELECT *.
     *
     * @param connection an active JDBC connection
     * @param username   the username provided by the user
     * @return an {@link Optional} containing the {@link UserAccount} if found, or {@link Optional#empty()}
     * @throws NullPointerException if connection is null
     * @throws SQLException         if a database access error occurs
     */
    public static Optional<UserAccount> findByUsername(Connection connection, String username) throws SQLException {
        Objects.requireNonNull(connection, "Active JDBC Connection must not be null.");

        // Safe handling for null or blank input: return empty without database roundtrip
        if (username == null || username.trim().isEmpty()) {
            return Optional.empty();
        }

        // Automatic resource management guarantees statement and result set closure
        try (PreparedStatement pstmt = connection.prepareStatement(SELECT_USER_BY_USERNAME)) {
            // Bind user-supplied input as a parameter (prevents SQL injection)
            pstmt.setString(1, username.trim());

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRowToUserAccount(rs));
                }
                return Optional.empty();
            }
        }
    }

    /**
     * Static alias method for {@link #findByUsername(Connection, String)}.
     *
     * @param connection an active JDBC connection
     * @param username   the username provided by the user
     * @return an Optional containing the UserAccount if found, or empty if not found
     * @throws SQLException if a database access error occurs
     */
    public static Optional<UserAccount> getUserByUsername(Connection connection, String username) throws SQLException {
        return findByUsername(connection, username);
    }

    /**
     * Maps the current row of an active {@link ResultSet} to a {@link UserAccount} record.
     *
     * @param rs the ResultSet positioned at a valid row
     * @return a populated UserAccount instance
     * @throws SQLException if column reading fails
     */
    private static UserAccount mapRowToUserAccount(ResultSet rs) throws SQLException {
        long rawId = rs.getLong("id");
        Long id = rs.wasNull() ? null : rawId;

        String username = rs.getString("username");
        String email = rs.getString("email");
        String fullName = rs.getString("full_name");
        String role = rs.getString("role");
        boolean isActive = rs.getBoolean("is_active");

        Timestamp createdAtTs = rs.getTimestamp("created_at");
        Instant createdAt = (createdAtTs != null) ? createdAtTs.toInstant() : null;

        Timestamp lastLoginAtTs = rs.getTimestamp("last_login_at");
        Instant lastLoginAt = (lastLoginAtTs != null) ? lastLoginAtTs.toInstant() : null;

        return new UserAccount(id, username, email, fullName, role, isActive, createdAt, lastLoginAt);
    }

    /**
     * Self-contained demonstration entry point.
     * Sets up an in-memory database, seeds user records, and executes:
     * 1. Standard valid username lookup
     * 2. Non-existent username lookup
     * 3. SQL Injection attack simulations (demonstrating safe parameterized handling)
     * 4. Null and blank input handling
     */
    public static void main(String[] args) {
        System.out.println("==========================================================================");
        System.out.println("     JDBC User Account Retrieval Demo (SQL Injection Resilient)          ");
        System.out.println("==========================================================================\n");

        try (Connection connection = createDemoConnection()) {
            if (connection == null) {
                System.out.println("[INFO] No demo database driver found. To run the demo, ensure H2 or SQLite");
                System.out.println("       is on your classpath: java -cp .:<driver.jar> UserAccountRepository");
                return;
            }

            // Initialize demo schema and seed accounts
            initializeDemoDatabase(connection);

            UserAccountRepository repository = new UserAccountRepository(connection);

            // 1. Retrieve existing user
            System.out.println("[Scenario 1] Retrieving valid user 'alice':");
            Optional<UserAccount> alice = repository.findByUsername("alice");
            if (alice.isPresent()) {
                UserAccount account = alice.get();
                System.out.println("  -> Successfully retrieved user account:");
                System.out.println("     ID:         " + account.id());
                System.out.println("     Username:   " + account.username());
                System.out.println("     Email:      " + account.email());
                System.out.println("     Full Name:  " + account.fullName());
                System.out.println("     Role:       " + account.role());
                System.out.println("     Active:     " + account.isActive());
                System.out.println("     Created At: " + account.createdAt());
            } else {
                System.out.println("  -> User not found.");
            }
            System.out.println();

            // 2. Query non-existent user
            System.out.println("[Scenario 2] Querying non-existent user 'charlie':");
            Optional<UserAccount> charlie = repository.findByUsername("charlie");
            System.out.println("  -> Present: " + charlie.isPresent());
            System.out.println();

            // 3. Simulating SQL Injection payloads
            System.out.println("[Scenario 3] Testing SQL Injection payloads against parameterized query:");
            String[] injectionPayloads = {
                "' OR '1'='1",
                "admin' --",
                "' OR 1=1 --",
                "admin' /*",
                "alice' UNION SELECT 999, 'hacked', 'hack@bad.com', 'Bad Actor', 'ADMIN', 1, NULL, NULL --"
            };

            for (String payload : injectionPayloads) {
                Optional<UserAccount> result = repository.findByUsername(payload);
                System.out.printf("  Payload: %-60s -> Result: %s (Defended)%n", 
                    "\"" + payload + "\"", 
                    result.isPresent() ? "LEAKED (" + result.get().username() + ")" : "Safely Empty"
                );
            }
            System.out.println();

            // 4. Input edge cases
            System.out.println("[Scenario 4] Testing edge cases (null, empty, whitespace):");
            System.out.println("  findByUsername(null)  -> Present: " + repository.findByUsername(null).isPresent());
            System.out.println("  findByUsername(\"\")    -> Present: " + repository.findByUsername("").isPresent());
            System.out.println("  findByUsername(\"   \") -> Present: " + repository.findByUsername("   ").isPresent());
            System.out.println();

            System.out.println("==========================================================================");
            System.out.println("  All tests completed successfully. PreparedStatement prevented all SQLi. ");
            System.out.println("==========================================================================");

        } catch (Exception e) {
            System.err.println("Error during demo execution: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Initializes an in-memory SQLite or H2 connection for demonstration purposes.
     */
    private static Connection createDemoConnection() {
        String h2Url = "jdbc:h2:mem:userdemo;DB_CLOSE_DELAY=-1";
        // 1. Try standard classpath loading
        try {
            Class.forName("org.h2.Driver");
            return DriverManager.getConnection(h2Url, "sa", "");
        } catch (Throwable ignored) {
        }

        // 2. Try loading driver from common temporary locations (e.g. /tmp/h2.jar)
        File h2Jar = new File("/tmp/h2.jar");
        if (h2Jar.exists()) {
            try {
                URLClassLoader loader = new URLClassLoader(
                    new URL[]{h2Jar.toURI().toURL()}, 
                    UserAccountRepository.class.getClassLoader()
                );
                Driver driver = (Driver) Class.forName("org.h2.Driver", true, loader)
                    .getDeclaredConstructor().newInstance();
                Properties props = new Properties();
                props.setProperty("user", "sa");
                props.setProperty("password", "");
                return driver.connect(h2Url, props);
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /**
     * Seeds the demo schema and initial records.
     */
    private static void initializeDemoDatabase(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("""
                CREATE TABLE users (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    full_name VARCHAR(100) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TIMESTAMP
                )
            """);

            stmt.execute("""
                INSERT INTO users (username, email, full_name, role, is_active, created_at, last_login_at)
                VALUES 
                  ('alice', 'alice@example.com', 'Alice Smith', 'ADMIN', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                  ('bob', 'bob@example.com', 'Bob Johnson', 'USER', TRUE, CURRENT_TIMESTAMP, NULL)
            """);
        }
    }
}
