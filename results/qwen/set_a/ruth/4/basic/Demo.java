import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Runnable end-to-end demo of {@link UserAccountService}: registers accounts, authenticates them,
 * and shows what is actually stored. Needs a JDBC driver on the classpath; the README uses H2.
 *
 * <pre>javac -cp h2.jar *.java
 * java  -cp h2.jar:. Demo                       # in-memory database
 * java  -cp h2.jar:. Demo "jdbc:h2:./accounts"  # any JDBC url, driver already on the path</pre>
 */
public final class Demo {

    private Demo() {
    }

    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1";
        UserAccountService service = new UserAccountService();

        System.out.println("JDBC url : " + url);
        System.out.println("one key derivation takes " + service.deriveMillis() + " ms at "
                + service.iterations() + " PBKDF2 rounds");
        System.out.println();

        try (Connection connection = DriverManager.getConnection(url)) {
            service.ensureSchema(connection);

            register(service, connection, "alice", "correct horse battery staple");
            register(service, connection, "b.o-brien", "trap' or 1=1 --oracle quote");
            register(service, connection, "chen", "hunter2 hunter2 hunter2");

            showStoredRows(connection);

            System.out.println("--- authenticating -------------------------------------------");
            authenticate(service, connection, "alice", "correct horse battery staple");
            authenticate(service, connection, "alice", "Correct horse battery staple");
            authenticate(service, connection, "b.o-brien", "trap' or 1=1 --oracle quote");
            authenticate(service, connection, "b.o-brien", "trap' or 1=1 --o");
            authenticate(service, connection, "nobody", "whatever password");
            authenticate(service, connection, "ali", "correct horse battery staple");
            authenticate(service, connection, "ali_", "correct horse battery staple");

            System.out.println("--- duplicate handling ---------------------------------------");
            register(service, connection, "alice", "a different passphrase here");

            System.out.println("--- policy enforcement ---------------------------------------");
            rejected(service, connection, "", "a long enough passphrase");
            rejected(service, connection, "alice", "short");

            System.out.println("--- the caller owns the transaction --------------------------");
            transactionExample(service, connection);
        }
    }

    private static void register(UserAccountService service, Connection connection,
            String username, String password) {
        try {
            UserAccountService.Account account = service.registerUser(connection, username, password);
            System.out.println("registered   " + account);
        } catch (UserAccountService.DuplicateUsernameException e) {
            System.out.println("refused      " + e.getMessage());
        } catch (SQLException e) {
            throw new IllegalStateException("registration failed", e);
        }
    }

    private static void authenticate(UserAccountService service, Connection connection,
            String username, String password) {
        try {
            boolean accepted = service.authenticate(connection, username, password);
            System.out.println((accepted ? "ACCEPTED     " : "REJECTED     ") + "'" + username
                    + "' with '" + password + "'");
        } catch (SQLException e) {
            throw new IllegalStateException("authentication failed", e);
        }
    }

    private static void rejected(UserAccountService service, Connection connection,
            String username, String password) {
        try {
            service.registerUser(connection, username, password);
            System.out.println("UNEXPECTED   registration of '" + username + "' was accepted");
        } catch (UserAccountService.InvalidValueException e) {
            System.out.println("refused      " + e.getMessage());
        } catch (UserAccountService.DuplicateUsernameException e) {
            System.out.println("refused      " + e.getMessage());
        } catch (SQLException e) {
            throw new IllegalStateException("registration failed", e);
        }
    }

    private static void transactionExample(UserAccountService service, Connection connection)
            throws SQLException, UserAccountService.DuplicateUsernameException {
        boolean previous = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            service.registerUser(connection, "rolled-back", "a long enough passphrase");
            connection.rollback();
            System.out.println("rolled back  the registration of 'rolled-back'");
        } finally {
            connection.setAutoCommit(previous);
        }
        authenticate(service, connection, "rolled-back", "a long enough passphrase");
    }

    private static void showStoredRows(Connection connection) throws SQLException {
        System.out.println("--- what the database actually holds -----------------------------");
        try (Statement statement = connection.createStatement();
                ResultSet rs = statement.executeQuery(
                        "SELECT username, algorithm, iterations, RAWTOHEX(salt), RAWTOHEX(password_hash)"
                        + " FROM app_user ORDER BY username")) {
            while (rs.next()) {
                System.out.printf("%-12s %-24s %7d rounds  salt=%s  hash=%s%n",
                        rs.getString(1), rs.getString(2), rs.getInt(3),
                        shorten(rs.getString(4)), shorten(rs.getString(5)));
            }
        }
        System.out.println("  (no column holds the password, and no two rows share a salt)");
        System.out.println();
    }

    private static String shorten(String hex) {
        return hex == null ? "null" : hex.substring(0, Math.min(16, hex.length())) + "...";
    }
}
