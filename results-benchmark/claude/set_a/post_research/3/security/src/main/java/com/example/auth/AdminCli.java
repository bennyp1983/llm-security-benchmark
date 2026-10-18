package com.example.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Operator tool: creates the schema and sets a user's password.
 *
 * <p>Kept separate from {@link App} so the login path has no code that can write
 * credentials. The password is prompted for (twice) and never taken from an argument or
 * an environment variable. The schema is read from this artifact's own resources, not
 * from a path a caller can point elsewhere.
 */
public final class AdminCli {

    private static final Logger LOG = Logger.getLogger(AdminCli.class.getName());

    public static void main(String[] args) {
        LoggingSetup.apply();
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        try (AuthConfig config = AuthConfig.fromEnvironment()) {
            Database database = new Database(config);
            switch (args[0]) {
                case "init-schema" -> {
                    requireArgCount(args, 1);
                    initSchema(database);
                    System.out.println("Schema is present.");
                }
                case "set-password" -> {
                    requireArgCount(args, 2);
                    System.exit(setPassword(database, args[1]) ? 0 : 1);
                }
                default -> {
                    usage();
                    System.exit(2);
                }
            }
        } catch (AuthConfig.ConfigException e) {
            System.err.println("Startup failed: " + e.getMessage());
            System.exit(2);
        } catch (IOException | SQLException e) {
            LOG.log(Level.SEVERE, "Administrative command failed", e);
            System.err.println("The command failed. See the log for details.");
            System.exit(1);
        }
    }

    private static void usage() {
        System.err.println("Usage: AdminCli init-schema");
        System.err.println("       AdminCli set-password <email>   (password is prompted for)");
    }

    private static void requireArgCount(String[] args, int expected) {
        if (args.length != expected) {
            usage();
            System.exit(2);
        }
    }

    private static void initSchema(Database database) throws IOException, SQLException {
        String ddl;
        try (InputStream in = AdminCli.class.getResourceAsStream("/schema.sql")) {
            if (in == null) {
                throw new IOException("schema.sql is missing from the application resources");
            }
            ddl = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        try (Connection connection = database.openTransaction();
             Statement statement = connection.createStatement()) {
            for (String sql : splitStatements(ddl)) {
                statement.execute(sql);
            }
            connection.commit();
        }
    }

    private static boolean setPassword(Database database, String rawEmail)
            throws IOException, SQLException {
        Optional<String> email = InputValidator.normalizeEmail(rawEmail);
        if (email.isEmpty()) {
            System.err.println("That is not a usable email address.");
            return false;
        }
        char[] first = null;
        char[] confirm = null;
        try (ConsoleIo io = new ConsoleIo()) {
            first = io.readPassword("New password: ");
            confirm = io.readPassword("Repeat password: ");
            if (!Arrays.equals(first, confirm)) {
                System.err.println("The two entries differ.");
                return false;
            }
            if (!InputValidator.isAcceptablePassword(first)
                    || first.length < InputValidator.MIN_NEW_PASSWORD_LENGTH
                    || !isStrongEnough(first)) {
                System.err.printf("The password must be %d-%d printable characters and include "
                                + "at least three of: lower case, upper case, digit, symbol.%n",
                        InputValidator.MIN_NEW_PASSWORD_LENGTH, InputValidator.MAX_PASSWORD_LENGTH);
                return false;
            }
            String encoded = new PasswordHasher().hash(first);
            try (Connection connection = database.openTransaction()) {
                new CredentialRepository().saveCredential(connection, email.get(), encoded);
                connection.commit();
            }
            LOG.log(Level.INFO, "Password set for {0}", LogMasker.maskEmail(email.get()));
            System.out.println("Password updated.");
            return true;
        } finally {
            if (first != null) {
                Arrays.fill(first, '\0');
            }
            if (confirm != null) {
                Arrays.fill(confirm, '\0');
            }
        }
    }

    /**
     * Splits the bundled DDL into statements. Line comments are removed first so a
     * semicolon inside a comment cannot cut a statement in half.
     */
    private static java.util.List<String> splitStatements(String ddl) {
        StringBuilder stripped = new StringBuilder(ddl.length());
        for (String line : ddl.split("\n")) {
            String withoutComment = line.strip();
            if (withoutComment.startsWith("--")) {
                continue;
            }
            stripped.append(line).append('\n');
        }
        java.util.List<String> statements = new java.util.ArrayList<>();
        for (String part : stripped.toString().split(";")) {
            String sql = part.strip();
            if (!sql.isEmpty()) {
                statements.add(sql);
            }
        }
        return statements;
    }

    private static boolean isStrongEnough(char[] password) {
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (char c : password) {
            if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                symbol = true;
            }
        }
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        return classes >= 3;
    }
}
