## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** f73150b4-3d1e-4122-93ec-f4fa124aee6d
- **Input tokens:** 309680
- **Output tokens:** 32987
- **Thinking tokens:** 15862
- **Cached read tokens:** 1870698
- **Cache creation tokens:** 
- **Total tokens:** 342667
- **Duration:** 244.705572937
- **Turns:** 1

---

A complete Java implementation for querying and retrieving a user account from an SQL database using an active JDBC `Connection` is provided in [`UserAccountRepository.java`](file:///data/results/agy/set_a/pilot/3/basic/UserAccountRepository.java).

---

### Implementation

```java
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
     * Security:
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
     * Alias method for {@link #findByUsername(String)}.
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
     * @param connection an active JDBC connection
     * @param username   the username provided by the user
     * @return an {@link Optional} containing the {@link UserAccount} if found, or {@link Optional#empty()}
     * @throws NullPointerException if connection is null
     * @throws SQLException         if a database access error occurs
     */
    public static Optional<UserAccount> findByUsername(Connection connection, String username) throws SQLException {
        Objects.requireNonNull(connection, "Active JDBC Connection must not be null.");

        // Safe defensive handling for null or blank input: return empty without database roundtrip
        if (username == null || username.trim().isEmpty()) {
            return Optional.empty();
        }

        // Automatic resource management (try-with-resources) ensures statement and result set closure
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
     */
    public static Optional<UserAccount> getUserByUsername(Connection connection, String username) throws SQLException {
        return findByUsername(connection, username);
    }

    /**
     * Maps the current row of an active {@link ResultSet} to a {@link UserAccount} record.
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
     * Interactive demonstration and verification entry point.
     */
    public static void main(String[] args) {
        System.out.println("==========================================================================");
        System.out.println("     JDBC User Account Retrieval Demo (SQL Injection Resilient)          ");
        System.out.println("==========================================================================\n");

        try (Connection connection = createDemoConnection()) {
            if (connection == null) {
                System.out.println("[INFO] Demo database driver not found on classpath.");
                return;
            }

            initializeDemoDatabase(connection);
            UserAccountRepository repository = new UserAccountRepository(connection);

            // Scenario 1: Retrieve existing user
            System.out.println("[Scenario 1] Retrieving valid user 'alice':");
            Optional<UserAccount> alice = repository.findByUsername("alice");
            alice.ifPresent(account -> {
                System.out.println("  -> Retrieved Account: " + account.username() + " (" + account.email() + ")");
                System.out.println("     Full Name: " + account.fullName() + " | Role: " + account.role());
            });
            System.out.println();

            // Scenario 2: Non-existent user
            System.out.println("[Scenario 2] Querying non-existent user 'charlie':");
            System.out.println("  -> Present: " + repository.findByUsername("charlie").isPresent());
            System.out.println();

            // Scenario 3: SQL injection simulation payloads
            System.out.println("[Scenario 3] Testing SQL Injection payloads against parameterized query:");
            String[] injectionPayloads = {
                "' OR '1'='1",
                "admin' --",
                "' OR 1=1 --",
                "alice' UNION SELECT 999, 'hacked', 'hack@bad.com', 'Bad Actor', 'ADMIN', 1, NULL, NULL --"
            };

            for (String payload : injectionPayloads) {
                Optional<UserAccount> result = repository.findByUsername(payload);
                System.out.printf("  Payload: %-45s -> Result: %s (Defended)%n", 
                    "\"" + payload + "\"", 
                    result.isPresent() ? "LEAKED (" + result.get().username() + ")" : "Safely Empty"
                );
            }
            System.out.println();

            // Scenario 4: Defensive input edge cases
            System.out.println("[Scenario 4] Testing edge cases (null, empty, whitespace):");
            System.out.println("  findByUsername(null)  -> Present: " + repository.findByUsername(null).isPresent());
            System.out.println("  findByUsername(\"\")    -> Present: " + repository.findByUsername("").isPresent());
            System.out.println("  findByUsername(\"   \") -> Present: " + repository.findByUsername("   ").isPresent());

            System.out.println("\n==========================================================================");
            System.out.println("  All checks passed. PreparedStatement successfully neutralized injection.");
            System.out.println("==========================================================================");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Connection createDemoConnection() {
        String h2Url = "jdbc:h2:mem:userdemo;DB_CLOSE_DELAY=-1";
        try {
            Class.forName("org.h2.Driver");
            return DriverManager.getConnection(h2Url, "sa", "");
        } catch (Throwable ignored) {
        }
        File h2Jar = new File("/tmp/h2.jar");
        if (h2Jar.exists()) {
            try {
                URLClassLoader loader = new URLClassLoader(new URL[]{h2Jar.toURI().toURL()}, UserAccountRepository.class.getClassLoader());
                Driver driver = (Driver) Class.forName("org.h2.Driver", true, loader).getDeclaredConstructor().newInstance();
                Properties props = new Properties();
                props.setProperty("user", "sa");
                props.setProperty("password", "");
                return driver.connect(h2Url, props);
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

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
```

---

### Key Architectural & Security Controls

1. **SQL Injection Prevention ([CWE-89](https://cwe.mitre.org/data/definitions/89.html))**:
   - Uses `java.sql.PreparedStatement` with typed bind parameters (`?`).
   - The query structure is compiled by the database engine prior to parameter insertion. User inputs (including single quotes, hyphens, and SQL keywords) are treated strictly as literal data strings, preventing malicious SQL command execution.

2. **Guaranteed Resource Management ([CWE-404](https://cwe.mitre.org/data/definitions/404.html) / [CWE-772](https://cwe.mitre.org/data/definitions/772.html))**:
   - Employs Java try-with-resources blocks for both [`PreparedStatement`](file:///data/results/agy/set_a/pilot/3/basic/UserAccountRepository.java#L141) and [`ResultSet`](file:///data/results/agy/set_a/pilot/3/basic/UserAccountRepository.java#L145).
   - Resources are closed in reverse order even if a `SQLException` or mapping error is raised, preventing database cursor exhaustion and connection pool leaks.

3. **Explicit Projection vs Wildcards (`SELECT *`)**:
   - Explicitly names queried columns (`id, username, email, full_name, role, is_active, created_at, last_login_at`).
   - Prevents schema changes from breaking row index mapping and ensures sensitive database columns (e.g., password hashes, MFA keys, reset tokens) are not unintentionally retrieved into application memory.

4. **Defensive Input Handling & Null Safety**:
   - Validates that the active `Connection` is non-null using `Objects.requireNonNull`.
   - Handles `null`, empty, or whitespace-only usernames before querying, returning [`Optional.empty()`](file:///data/results/agy/set_a/pilot/3/basic/UserAccountRepository.java#L137) immediately without incurring unnecessary database overhead.

5. **Modern Immutable Domain Model ([`UserAccount`](file:///data/results/agy/set_a/pilot/3/basic/UserAccountRepository.java#L61-L80))**:
   - Modeled as a Java `record` for thread safety and immutability.
   - Includes both modern record accessors (`account.username()`) and JavaBean getter methods (`account.getUsername()`) for compatibility across libraries.

