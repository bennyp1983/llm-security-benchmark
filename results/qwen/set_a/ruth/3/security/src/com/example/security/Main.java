package com.example.security;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;

/**
 * Command line demonstration of {@link UserRepository}.
 *
 * <p>With no {@code --jdbc} option it starts a throwaway in-memory H2 database, seeds it, and
 * opens a connection to it, so the example runs with no setup. Against your own database, pass
 * {@code --jdbc} (and optionally {@code --db-user} / {@code --db-password}); the demo seeding is
 * then skipped and the code only ever reads the {@code users} table.
 *
 * <p>The username arrives as untrusted command line input and is handed to the repository
 * verbatim - that is the point of the example. Everything else here (schema, seed rows) is fixed
 * text with no input in it.
 *
 * <p>Exit codes: 0 found, 3 no such account, 2 bad usage, 1 lookup failed.
 */
public final class Main {

    private static final String DEMO_JDBC = "jdbc:h2:mem:userdemo;DB_CLOSE_DELAY=-1";

    private Main() {
    }

    public static void main(String[] args) {
        String jdbcUrl = null;
        String driverClass = null;
        String dbUser = null;
        String dbPassword = null;
        String username = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--jdbc" -> {
                    if (++i == args.length) {
                        System.err.println("missing value for --jdbc");
                        System.exit(2);
                    }
                    jdbcUrl = args[i];
                }
                case "--driver" -> {
                    if (++i == args.length) {
                        System.err.println("missing value for --driver");
                        System.exit(2);
                    }
                    driverClass = args[i];
                }
                case "--db-user" -> {
                    if (++i == args.length) {
                        System.err.println("missing value for --db-user");
                        System.exit(2);
                    }
                    dbUser = args[i];
                }
                case "--db-password" -> {
                    if (++i == args.length) {
                        System.err.println("missing value for --db-password");
                        System.exit(2);
                    }
                    dbPassword = args[i];
                }
                case "--help", "-h" -> {
                    usage();
                    return;
                }
                default -> {
                    if (arg.startsWith("-") || username != null) {
                        System.err.println("unexpected argument: " + arg);
                        usage();
                        System.exit(2);
                    }
                    username = arg;
                }
            }
        }

        if (username == null) {
            System.err.println("a username is required");
            usage();
            System.exit(2);
        }

        boolean demo = jdbcUrl == null;
        if (demo) {
            jdbcUrl = DEMO_JDBC;
            driverClass = "org.h2.Driver";
        }

        if (driverClass != null) {
            try {
                Class.forName(driverClass);
            } catch (ClassNotFoundException ex) {
                System.err.println("JDBC driver not on the classpath: " + driverClass);
                System.exit(1);
            }
        }

        try (Connection connection = openConnection(jdbcUrl, dbUser, dbPassword)) {
            if (demo) {
                seedDemoData(connection);
            }

            UserRepository repository = new UserRepository(connection);
            Optional<UserAccount> account;
            try {
                account = repository.findByUsername(username);
            } catch (IllegalArgumentException ex) {
                // Bad input, not a database problem: report the rule that was broken and stop.
                System.err.println("invalid username: " + ex.getMessage());
                System.exit(2);
                return;
            }

            if (account.isEmpty()) {
                // Deliberately identical for "unknown name" and "name that looks like SQL":
                // the response must not reveal which form the attacker supplied.
                System.out.println("no account found for username: " + username);
                System.exit(3);
            }

            UserAccount found = account.get();
            System.out.println("found " + found);
            System.out.println("active: " + found.isActive());
            System.exit(0);
        } catch (SQLException | UserRepositoryException ex) {
            System.err.println("account lookup failed: " + ex.getMessage());
            if (ex.getCause() != null) {
                System.err.println("cause: " + ex.getCause().getMessage());
            }
            System.exit(1);
        }
    }

    private static Connection openConnection(String jdbcUrl, String dbUser, String dbPassword)
            throws SQLException {
        if (dbUser == null) {
            return DriverManager.getConnection(jdbcUrl);
        }
        return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
    }

    /**
     * Demo rows for the in-memory database only. The text is entirely static - the escaped
     * apostrophe in {@code o''brien} is there to show that a quote inside a stored username is
     * just data, which is exactly what the bound parameter preserves on the way back in.
     */
    private static void seedDemoData(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE IF NOT EXISTS users ("
                    + " id BIGINT PRIMARY KEY,"
                    + " username VARCHAR(254) NOT NULL,"
                    + " email VARCHAR(320),"
                    + " full_name VARCHAR(200),"
                    + " status VARCHAR(32) NOT NULL,"
                    + " password_hash VARCHAR(100) NOT NULL,"
                    + " created_at TIMESTAMP)");
            statement.execute("MERGE INTO users (id, username, email, full_name, status,"
                    + " password_hash, created_at) KEY (id) VALUES"
                    + " (1, 'alice', 'alice@example.com', 'Alice Example', 'ACTIVE',"
                    + " '$2a$10$notarealhashvalue', '2024-01-02 03:04:05'),"
                    + " (2, 'admin', 'admin@example.com', 'Root Admin', 'ACTIVE',"
                    + " '$2a$10$notarealhashvalue', NULL),"
                    + " (3, 'DISABLED-bot', 'bot@example.com', 'Retired Bot', 'DISABLED',"
                    + " '$2a$10$notarealhashvalue', '2025-06-07 08:09:10'),"
                    + " (4, 'o''brien', 'obrien@example.com', 'Sean O''Brien', 'ACTIVE',"
                    + " '$2a$10$notarealhashvalue', '2026-02-03 04:05:06')");
        }
    }

    private static void usage() {
        System.out.println("Usage: java -cp <classes>:<jdbc-driver.jar> "
                + Main.class.getName() + " [options] <username>");
        System.out.println();
        System.out.println("  --jdbc URL          JDBC url to connect to"
                + "   (default: throwaway in-memory H2, seeded with demo rows)");
        System.out.println("  --driver CLASS      JDBC driver class to load");
        System.out.println("  --db-user NAME      database user");
        System.out.println("  --db-password PASS  database password");
        System.out.println("  -h, --help          show this help");
    }
}
