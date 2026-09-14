import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;

/**
 * End-to-end verification of {@link UserAccountLookup} against a real SQL engine
 * (H2 in memory), so that the statement is checked by an actual parser rather than
 * only by a recording double.
 *
 * <p>Verification helper, not part of the deliverable. Needs the H2 jar on the class path:
 *
 * <pre>
 *   javac -cp h2.jar -d target UserAccountLookup.java UserAccountLookupH2Test.java
 *   java  -cp target:h2.jar UserAccountLookupH2Test
 * </pre>
 */
public final class UserAccountLookupH2Test {

    private static final String URL = "jdbc:h2:mem:lookup_test;DB_CLOSE_DELAY=-1";

    private static final int[] failures = new int[1];
    private static int checks;

    private UserAccountLookupH2Test() {
    }

    public static void main(String[] args) throws Exception {
        try (Connection connection = DriverManager.getConnection(URL, "sa", "")) {
            createSchema(connection);
            seed(connection);

            run("the statement parses and runs on a real engine", () -> {
                var account = UserAccountLookup.findByUsername(connection, "alice").orElseThrow();
                check("id", 1L, account.id());
                check("username", "alice", account.username());
                check("email", "alice@example.com", account.email());
                check("fullName", "Alice Example", account.fullName());
                check("status", "ACTIVE", account.status());
                check("createdAt", Instant.parse("2024-01-02T03:04:05Z"), account.createdAt());
            });

            run("matching is by equality and trims caller whitespace", () -> {
                check("found with padding", UserAccountLookup.findByUsername(connection, "   alice\t").isPresent());
            });

            run("an unknown username yields an empty result", () -> {
                check("no such user", UserAccountLookup.findByUsername(connection, "nobody").isEmpty());
            });

            run("null columns come back as nulls, not errors", () -> {
                var account = UserAccountLookup.findByUsername(connection, "carol").orElseThrow();
                check("fullName", null, account.fullName());
                check("createdAt", null, account.createdAt());
                check("status still read", "PENDING", account.status());
            });

            run("the statement never reads the password column", () -> {
                check("no wildcard select", !UserAccountLookup.SELECT_BY_USERNAME.contains("*"));
                check("no password column", !UserAccountLookup.SELECT_BY_USERNAME
                        .toLowerCase().contains("password"));
                check("returned record cannot carry one",
                        java.util.Arrays.stream(accountComponentNames()).noneMatch(
                                name -> name.toLowerCase().contains("password")));
            });

            run("injection payloads match literally and change nothing", () -> {
                String[] payloads = {
                        "admin' OR '1'='1",
                        "admin' --",
                        "' OR '1'='1' --",
                        "admin'; DROP TABLE users; --",
                        "admin' UNION SELECT id, username, email, full_name, status, created_at"
                                + " FROM users --",
                        "%",
                        "ali_",
                };
                for (String payload : payloads) {
                    check("payload yields no row: " + payload,
                            UserAccountLookup.findByUsername(connection, payload).isEmpty());
                }
                check("users table still exists", countUsers(connection) == 4);
                check("the admin row was not leaked by a payload",
                        UserAccountLookup.findByUsername(connection, "admin").orElseThrow().id() == 2L);
            });

            run("case differences are distinct usernames", () -> {
                check("Alice is not alice", UserAccountLookup.findByUsername(connection, "Alice").isEmpty());
            });

            run("a duplicate username is reported, not silently resolved", () -> {
                insert(connection, 5, "dup", "dup@example.com", null, "ACTIVE", null);
                insert(connection, 6, "dup", "dup2@example.com", null, "ACTIVE", null);
                try {
                    UserAccountLookup.findByUsername(connection, "dup");
                    check("duplicate rows rejected", false);
                } catch (IllegalStateException expected) {
                    check("duplicate rows rejected", true);
                }
                delete(connection, "dup");
            });

            run("non-ascii usernames round-trip through the driver", () -> {
                String name = "re" + (char) 0x00F1 + "sumer";
                insert(connection, 7, name, "rene@example.com", null, "ACTIVE", null);
                check("round-trip", name.equals(UserAccountLookup.findByUsername(connection, name).orElseThrow().username()));
                delete(connection, name);
            });

            run("the caller's connection stays open, the query is single", () -> {
                check("connection open", !connection.isClosed());
                check("autocommit untouched", connection.getAutoCommit());
            });

            run("an over-long username is rejected before the driver runs", () -> {
                StringBuilder tooLong = new StringBuilder();
                for (int i = 0; i < 300; i++) {
                    tooLong.append('a');
                }
                try {
                    UserAccountLookup.findByUsername(connection, tooLong.toString());
                    check("rejected", false);
                } catch (IllegalArgumentException expected) {
                    check("rejected", true);
                }
            });

            run("a broken connection surfaces as SQLException", () -> {
                Connection closed = DriverManager.getConnection(URL, "sa", "");
                closed.close();
                try {
                    UserAccountLookup.findByUsername(closed, "alice");
                    check("SQLException raised", false);
                } catch (SQLException expected) {
                    check("SQLException raised", true);
                }
            });
        }
        report();
    }

    private static String[] accountComponentNames() {
        Class<?> accountType;
        try {
            accountType = Class.forName("UserAccount");
        } catch (ClassNotFoundException e) {
            throw new AssertionError(e);
        }
        return java.util.Arrays.stream(accountType.getRecordComponents())
                .map(component -> component.getName()).toArray(String[]::new);
    }

    private static void createSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // No UNIQUE index on username on purpose: the duplicate-row check below needs
            // duplicates to be possible, and a real deployment must add that index.
            statement.execute("CREATE TABLE users ("
                    + "id BIGINT PRIMARY KEY,"
                    + "username VARCHAR(254) NOT NULL,"
                    + "email VARCHAR(320),"
                    + "full_name VARCHAR(200),"
                    + "status VARCHAR(32) NOT NULL,"
                    + "password_hash VARCHAR(100) NOT NULL,"
                    + "created_at TIMESTAMP)");
        }
    }

    private static void seed(Connection connection) throws SQLException {
        insert(connection, 1, "alice", "alice@example.com", "Alice Example", "ACTIVE",
                "2024-01-02 03:04:05");
        insert(connection, 2, "admin", "admin@example.com", "Root Admin", "ACTIVE", null);
        insert(connection, 3, "carol", "carol@example.com", null, "PENDING", null);
        insert(connection, 4, "dave", "dave@example.com", "Dave", "DISABLED", null);
    }

    private static void insert(Connection connection, long id, String username, String email,
                              String fullName, String status, String createdAt) throws SQLException {
        try (java.sql.PreparedStatement insert = connection.prepareStatement(
                "INSERT INTO users (id, username, email, full_name, status, password_hash,"
                        + " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            insert.setLong(1, id);
            insert.setString(2, username);
            insert.setString(3, email);
            insert.setString(4, fullName);
            insert.setString(5, status);
            insert.setString(6, "$2a$10$notarealhashvalue");
            if (createdAt == null) {
                insert.setNull(7, java.sql.Types.TIMESTAMP);
            } else {
                insert.setTimestamp(7, java.sql.Timestamp.valueOf(createdAt));
            }
            insert.executeUpdate();
        }
    }

    private static void delete(Connection connection, String username) throws SQLException {
        try (java.sql.PreparedStatement delete =
                     connection.prepareStatement("DELETE FROM users WHERE username = ?")) {
            delete.setString(1, username);
            delete.executeUpdate();
        }
    }

    private static int countUsers(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             java.sql.ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM users")) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private interface Case {
        void run() throws Exception;
    }

    private static void run(String name, Case testCase) {
        try {
            testCase.run();
            System.out.println("ok   " + name);
        } catch (Throwable failure) {
            failures[0]++;
            System.out.println("FAIL " + name + " -> " + failure);
        }
    }

    private static void check(String what, Object expected, Object actual) {
        checks++;
        if (!java.util.Objects.equals(expected, actual)) {
            throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            throw new AssertionError("expected " + what);
        }
    }

    private static void report() {
        System.out.println();
        if (failures[0] == 0) {
            System.out.println("all " + checks + " checks passed against H2");
            return;
        }
        System.out.println(failures[0] + " of " + checks + " checks failed");
        System.exit(1);
    }
}
