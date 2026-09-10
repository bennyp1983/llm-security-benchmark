package com.example.users;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Command line front end: reads a user name from the arguments (or standard input) and prints the
 * account that {@link UserAccountRepository} returns for it.
 *
 * <p>Connection settings come from the environment so no credential is baked into the source. The
 * connection handling here is harness wiring only -- a real application already owns a pooled or
 * request-scoped {@link Connection} and simply passes it to the repository.
 */
public final class UserLookupCli {

    private UserLookupCli() {
    }

    /**
     * @param args user names to look up; standard input is prompted instead when empty
     * @throws SQLException if the database cannot be reached or a query fails
     * @throws IOException  if reading standard input fails
     */
    public static void main(String[] args) throws SQLException, IOException {
        String url = env("DB_URL", "jdbc:h2:mem:demo");
        String dbUser = env("DB_USER", "sa");
        String dbPassword = System.getenv().getOrDefault("DB_PASSWORD", "");

        UserAccountRepository repository = new UserAccountRepository();

        try (Connection connection = DriverManager.getConnection(url, dbUser, dbPassword);
             BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {

            for (String userName : userNames(args, in)) {
                Optional<UserAccount> account = repository.findByUserName(connection, userName);
                if (account.isEmpty()) {
                    System.out.println("No account found for user name: " + printable(userName));
                    continue;
                }
                print(account.orElseThrow());
            }
        }
    }

    private static List<String> userNames(String[] args, BufferedReader in) throws IOException {
        if (args.length > 0) {
            return Arrays.asList(args);
        }
        System.out.print("user name> ");
        String line = in.readLine();
        return line == null ? List.of() : List.of(line);
    }

    private static void print(UserAccount account) {
        System.out.printf(
                "id=%d user_name=%s email=%s display_name=%s enabled=%s created_at=%s last_login_at=%s%n",
                account.id(),
                account.userName(),
                account.email(),
                account.displayName(),
                account.enabled(),
                account.createdAt(),
                account.lastLoginAt());
    }

    /** Strips control characters so a typed value cannot forge extra lines of terminal output. */
    private static String printable(String value) {
        return value == null ? "" : value.replaceAll("\\p{Cntrl}", "?");
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
