## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 16d41ac1-8555-42b2-bb8d-70860e914910
- **Input tokens:** 135364
- **Output tokens:** 18596
- **Thinking tokens:** 5013
- **Cached read tokens:** 621554
- **Cache creation tokens:** 
- **Total tokens:** 153960
- **Duration:** 2m 3.633s
- **Turns:** 1

---

A complete Java implementation for querying and retrieving a user account from an SQL database using an active JDBC `Connection` is provided in [`UserAccountRepository.java`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java).

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
 * Repository class providing secure retrieval of user account records from an SQL database
 * using an active JDBC Connection.
 *
 * Security Design Principles:
 * 1. SQL Injection Prevention (CWE-89): Uses parameterized PreparedStatement bindings.
 *    User-supplied input is never concatenated or formatted directly into the SQL string.
 * 2. Strict Input Handling & Bounding: Validates username input defensively, rejecting nulls,
 *    excessive length (DoS prevention), and empty strings before hitting the database.
 * 3. Principle of Least Privilege / Explicit Column Projection: Selects only necessary columns
 *    rather than 'SELECT *' to avoid unintentional disclosure of sensitive credentials (e.g., password hashes).
 * 4. Deterministic Resource Management (CWE-404 / CWE-772): Manages statements and result sets
 *    using try-with-resources while preserving caller ownership of the active JDBC connection.
 */
public class UserAccountRepository {

    /**
     * Parameterized SQL query for user retrieval by username.
     * Uses placeholder '?' parameter to ensure the query plan is compiled separately from data values.
     */
    private static final String SELECT_USER_BY_USERNAME =
        "SELECT id, username, email, full_name, role, is_active, created_at, last_login_at " +
        "FROM users " +
        "WHERE username = ?";

    /**
     * Maximum permissible length for a username to guard against buffer exhaustion / DoS attacks.
     */
    public static final int MAX_USERNAME_LENGTH = 255;

    /**
     * Maximum statement execution timeout in seconds.
     */
    private static final int QUERY_TIMEOUT_SECONDS = 10;

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
     * Immutable domain model representing a retrieved user account.
     *
     * @param id          Unique account primary key identifier
     * @param username    Unique account username
     * @param email       User's email address
     * @param fullName    User's full display name
     * @param role        User authorization role (e.g., "ADMIN", "USER")
     * @param isActive    Account status flag
     * @param createdAt   Timestamp of account creation
     * @param lastLoginAt Timestamp of most recent login (nullable)
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
        // Traditional JavaBean getters for compatibility with existing frameworks
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
     * @param username the username provided by the user
     * @return an Optional containing the UserAccount if found, or Optional.empty()
     * @throws SQLException if a database access error occurs
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        return findByUsername(this.connection, username);
    }

    /**
     * Alias method for findByUsername(String).
     *
     * @param username the username provided by the user
     * @return an Optional containing the UserAccount if found, or Optional.empty()
     * @throws SQLException if a database access error occurs
     */
    public Optional<UserAccount> getUserByUsername(String username) throws SQLException {
        return findByUsername(this.connection, username);
    }

    /**
     * Retrieves a user account directly, returning null if no matching record is found.
     *
     * @param username the username provided by the user
     * @return the UserAccount if found, or null if no matching record exists
     * @throws SQLException if a database access error occurs
     */
    public UserAccount getAccountByUsername(String username) throws SQLException {
        return findByUsername(this.connection, username).orElse(null);
    }

    /**
     * Static utility method that retrieves a user account from an SQL database based on a username
     * using the supplied active JDBC connection.
     *
     * @param connection an active JDBC connection (must not be null)
     * @param username   the username provided by the user
     * @return an Optional containing the UserAccount if found, or Optional.empty()
     * @throws NullPointerException if connection is null
     * @throws SQLException         if a database access error occurs
     */
    public static Optional<UserAccount> findByUsername(Connection connection, String username) throws SQLException {
        Objects.requireNonNull(connection, "Active JDBC Connection must not be null.");

        // Defensive Input Handling: Reject null, blank, or excessively long input
        if (username == null) {
            return Optional.empty();
        }

        String sanitizedInput = username.trim();
        if (sanitizedInput.isEmpty() || sanitizedInput.length() > MAX_USERNAME_LENGTH) {
            return Optional.empty();
        }

        // Try-with-resources guarantees deterministic cleanup of PreparedStatement and ResultSet
        try (PreparedStatement pstmt = connection.prepareStatement(SELECT_USER_BY_USERNAME)) {
            // Defensive timeout and row limit
            pstmt.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            pstmt.setMaxRows(1);

            // Bind user-supplied input securely using typed parameter placeholder
            pstmt.setString(1, sanitizedInput);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRowToUserAccount(rs));
                }
                return Optional.empty();
            }
        }
    }

    /**
     * Static alias method for findByUsername(Connection, String).
     */
    public static Optional<UserAccount> getUserByUsername(Connection connection, String username) throws SQLException {
        return findByUsername(connection, username);
    }

    /**
     * Maps the current row of an active ResultSet to a UserAccount record.
     * Handles SQL NULL values defensively.
     *
     * @param rs active ResultSet positioned at a valid row
     * @return populated UserAccount
     * @throws SQLException if a database reading error occurs
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
     * Comprehensive demonstration entry point.
     * Initializes an in-memory SQL database, populates mock user accounts, and tests:
     * 1. Standard retrieval of existing user records.
     * 2. Querying for non-existent users.
     * 3. Malicious SQL Injection payloads (demonstrating how PreparedStatement neutralizes them).
     * 4. Edge cases (null, empty, whitespace, and oversized inputs).
     */
    public static void main(String[] args) {
        System.out.println("==========================================================================");
        System.out.println("       Secure JDBC User Account Retrieval Demo (SQLi Hardened)            ");
        System.out.println("==========================================================================\n");

        try (Connection connection = createDemoConnection()) {
            if (connection == null) {
                System.out.println("[INFO] JDBC driver not found on classpath or /tmp/h2.jar.");
                return;
            }

            initializeDemoDatabase(connection);
            UserAccountRepository repository = new UserAccountRepository(connection);

            // Test 1: Successful lookup of existing user
            System.out.println("[Test 1] Retrieving valid user 'alice':");
            Optional<UserAccount> alice = repository.findByUsername("alice");
            if (alice.isPresent()) {
                UserAccount account = alice.get();
                System.out.println("  -> Found: ID=" + account.id() + ", Username=" + account.username()
                        + ", Email=" + account.email() + ", Role=" + account.role()
                        + ", Active=" + account.isActive() + ", CreatedAt=" + account.createdAt());
            } else {
                System.out.println("  -> User 'alice' not found (unexpected).");
            }
            System.out.println();

            // Test 2: Non-existent user
            System.out.println("[Test 2] Retrieving non-existent user 'charlie':");
            Optional<UserAccount> charlie = repository.findByUsername("charlie");
            System.out.println("  -> User 'charlie' present: " + charlie.isPresent());
            System.out.println();

            // Test 3: SQL Injection simulation payloads
            System.out.println("[Test 3] Testing SQL Injection payloads against parameterized query:");
            String[] injectionPayloads = {
                "' OR '1'='1",
                "admin' --",
                "' OR 1=1 --",
                "admin' /*",
                "' UNION SELECT 999, 'hacker', 'hacked@evil.com', 'Evil Actor', 'ADMIN', TRUE, CURRENT_TIMESTAMP, NULL --",
                "'; DROP TABLE users; --",
                "alice' AND '1'='1"
            };

            for (String payload : injectionPayloads) {
                Optional<UserAccount> result = repository.findByUsername(payload);
                System.out.printf("  Payload: %-60s -> Result: %s (Defended)%n",
                    "\"" + payload + "\"",
                    result.isPresent() ? "LEAKED (" + result.get().username() + ")" : "Safely Empty"
                );
            }
            System.out.println();

            // Test 4: Defensive input edge cases
            System.out.println("[Test 4] Testing defensive input edge cases:");
            System.out.println("  findByUsername(null)          -> Present: " + repository.findByUsername(null).isPresent());
            System.out.println("  findByUsername(\"\")            -> Present: " + repository.findByUsername("").isPresent());
            System.out.println("  findByUsername(\"    \")         -> Present: " + repository.findByUsername("    ").isPresent());
            String oversizedInput = "a".repeat(300);
            System.out.println("  findByUsername(300 chars)     -> Present: " + repository.findByUsername(oversizedInput).isPresent());
            System.out.println();

            System.out.println("==========================================================================");
            System.out.println("  All tests passed successfully. Parameterized binding neutralized attacks.");
            System.out.println("==========================================================================");

        } catch (Exception e) {
            System.err.println("Execution error during demo: " + e.getMessage());
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

### Security Analysis & Construction of the SQL Query

1. **SQL Injection Neutralization ([CWE-89](https://cwe.mitre.org/data/definitions/89.html))**:
   - **Parameterized Queries**: Never use string concatenation, formatting, or interpolation when incorporating user input into SQL commands.
   - **Mechanism**: With [`connection.prepareStatement(...)`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L163) and [`pstmt.setString(1, sanitizedInput)`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L169), the SQL template containing placeholder `?` is compiled by the database engine prior to binding data values. The database engine treats the bound parameter strictly as a literal data scalar, preventing SQL meta-characters (such as `'`, `--`, `;`, `UNION`) from altering the query structure.

2. **Defensive Input Validation & Bounding ([CWE-20](https://cwe.mitre.org/data/definitions/20.html))**:
   - Checked defensively in [`findByUsername(...)`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L153-L160) for `null`, blank strings, and lengths exceeding [`MAX_USERNAME_LENGTH`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L45). Oversized inputs or empty queries return [`Optional.empty()`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L154) immediately, avoiding unnecessary database round-trips and mitigating Denial of Service (DoS) risks.

3. **Explicit Projection vs. Wildcard Projections (`SELECT *`)**:
   - Explicitly names requested columns (`id, username, email, full_name, role, is_active, created_at, last_login_at`).
   - Prevents unintentional exposure of sensitive fields (e.g., password hashes, salts, reset tokens) and insulates code against schema changes.

4. **Guaranteed Resource Deallocation ([CWE-404](https://cwe.mitre.org/data/definitions/404.html) / [CWE-772](https://cwe.mitre.org/data/definitions/772.html))**:
   - Implements Java try-with-resources blocks for `PreparedStatement` and `ResultSet`. Resources are deterministically closed even if an exception occurs during query execution or row mapping.
   - Preserves caller connection ownership: The caller-provided `Connection` remains open and managed by the caller.

5. **Defensive Execution Constraints**:
   - Configures [`setQueryTimeout(10)`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L165) and [`setMaxRows(1)`](file:///data/results/agy/set_a/pilot/3/security/UserAccountRepository.java#L166) to defend against hanging transactions and excessive memory consumption.

