import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Sign-in check against credentials stored in a SQL database.
 *
 * <p>The program takes an email address and a password, looks the account up in a SQL table,
 * compares the password against the stored hash, and prints either
 * "Authentication successful." or "Authentication unsuccessful.".
 *
 * <p>Everything is in one file, in declaration order of use:
 * <ul>
 *   <li>{@link AuthenticationApp} - command line handling and the printed outcome</li>
 *   <li>{@link AuthService} - the sign-in decision</li>
 *   <li>{@link Database} - JDBC access to the account table</li>
 *   <li>{@link PasswordHasher} - turning a password into a stored hash and back again</li>
 *   <li>{@link Emails} - the small amount of email address checking</li>
 * </ul>
 */
public final class AuthenticationApp {

    private AuthenticationApp() {
    }

    public static void main(String[] args) {
        int exitCode;
        try {
            exitCode = run(args);
        } catch (IOException e) {
            System.err.println("[app] could not read the input: " + e.getMessage());
            exitCode = 3;
        }
        System.out.flush();
        System.err.flush();
        System.exit(exitCode);
    }

    private static int run(String[] args) throws IOException {
        Args a;
        try {
            a = Args.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("[app] " + e.getMessage());
            usage(System.err);
            return 3;
        }
        if (a.has("--help")) {
            usage(System.out);
            return 0;
        }
        if (a.commands.isEmpty()) {
            usage(System.err);
            return 3;
        }

        Database db = new Database(
                a.optionOrEnv("--url", "DB_URL", "jdbc:h2:./auth-demo"),
                a.optionOrEnv("--db-user", "DB_USER", "sa"),
                firstOrNull(System.getenv("DB_PASSWORD"), ""));
        String passwordEnvironmentVariable = firstOrNull(a.option("--password-env"), "DEMO_PASSWORD");
        String command = a.commands.get(0);
        String email = a.commands.size() > 1 ? a.commands.get(1) : null;

        switch (command) {
            case "init":
                try {
                    db.initSchema();
                } catch (SQLException e) {
                    return databaseError(e);
                }
                System.out.println("Database schema is ready.");
                return 0;

            case "add":
                if (email == null) {
                    System.err.println("[app] add needs an email address");
                    usage(System.err);
                    return 3;
                }
                return add(db, email, passwordEnvironmentVariable);

            case "login":
                if (email == null) {
                    System.err.println("[app] login needs an email address");
                    usage(System.err);
                    return 3;
                }
                return login(db, email, passwordEnvironmentVariable);

            default:
                System.err.println("[app] unknown command: " + command);
                usage(System.err);
                return 3;
        }
    }

    private static int add(Database db, String email, String passwordEnvironmentVariable) throws IOException {
        char[] password = readPassword(passwordEnvironmentVariable);
        try {
            if (!db.addUser(email, password)) {
                System.err.println("[app] the database did not store the credentials");
                return 3;
            }
        } catch (IllegalArgumentException e) {
            System.err.println("[app] " + e.getMessage());
            return 3;
        } catch (SQLException e) {
            return databaseError(e);
        } finally {
            wipe(password);
        }
        System.out.println("Password stored.");
        return 0;
    }

    private static int login(Database db, String email, String passwordEnvironmentVariable) throws IOException {
        char[] password = readPassword(passwordEnvironmentVariable);
        AuthResult result;
        try {
            result = new AuthService(db).authenticate(email, password);
        } finally {
            wipe(password);
        }
        switch (result) {
            case SUCCESS:
                System.out.println("Authentication successful.");
                return 0;
            case INVALID_INPUT:
                System.out.println("Authentication unsuccessful.");
                System.err.println("[auth] the email address or password is not in a form this program accepts");
                return 2;
            default:
                System.out.println("Authentication unsuccessful.");
                return 1;
        }
    }

    /**
     * Reads the password from the named environment variable when that variable is set, so the
     * program can be driven from a script. Otherwise it asks for it: through {@link Console} when
     * there is a real terminal (typing is not echoed), or from standard input as a last resort.
     */
    private static char[] readPassword(String environmentVariable) throws IOException {
        String fromEnvironment = System.getenv(environmentVariable);
        if (fromEnvironment != null) {
            return fromEnvironment.toCharArray();
        }
        Console console = System.console();
        if (console != null) {
            char[] typed = console.readPassword("Password: ");
            return typed == null ? new char[0] : typed;
        }
        System.err.print("Password: ");
        System.err.flush();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = in.readLine();
        return line == null ? new char[0] : line.toCharArray();
    }

    private static void wipe(char[] password) {
        Arrays.fill(password, (char) 0);
    }

    private static int databaseError(SQLException e) {
        String state = e.getSQLState() == null ? "" : e.getSQLState();
        if (state.startsWith("23")) {
            System.err.println("[app] that email address already has credentials stored");
        } else {
            System.err.println("[app] database error [" + state + "]: " + e.getMessage());
        }
        return 3;
    }

    private static String firstOrNull(String first, String second) {
        return first != null ? first : second;
    }

    private static void usage(PrintStream out) {
        out.println("Usage: java AuthenticationApp [options] <command> [argument]");
        out.println();
        out.println("Commands:");
        out.println("  init                 create the account table if it is not there yet");
        out.println("  add <email>          hash and store a password for an email address");
        out.println("  login <email>        check the email address and password, then print the outcome");
        out.println();
        out.println("Options:");
        out.println("  --url <jdbc-url>      database JDBC URL (env DB_URL, default jdbc:h2:./auth-demo)");
        out.println("  --db-user <name>      database user (env DB_USER, default sa)");
        out.println("                        the database's own password comes from env DB_PASSWORD only,");
        out.println("                        never from a command line argument");
        out.println("  --password-env <VAR>  read the sign-in password from this environment variable");
        out.println("                        instead of prompting for it (default DEMO_PASSWORD)");
        out.println();
        out.println("login prints exactly one line on standard output:");
        out.println("  Authentication successful.");
        out.println("  Authentication unsuccessful.");
        out.println("Exit status: 0 accepted, 1 rejected, 2 input refused, 3 usage or database problem.");
    }

    /** Parsed command line: option flags and the leftover words. */
    private static final class Args {

        private final List<String> commands = new ArrayList<>();
        private final Map<String, String> options = new HashMap<>();

        static Args parse(String[] args) {
            Args parsed = new Args();
            for (int i = 0; i < args.length; i++) {
                String token = args[i];
                if (!token.startsWith("--")) {
                    parsed.commands.add(token);
                    continue;
                }
                if (token.equals("--help")) {
                    parsed.options.put(token, "true");
                    continue;
                }
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException(token + " needs a value");
                }
                parsed.options.put(token, args[++i]);
            }
            return parsed;
        }

        boolean has(String name) {
            return options.containsKey(name);
        }

        String option(String name) {
            return options.get(name);
        }

        String optionOrEnv(String optionName, String environmentVariable, String fallback) {
            String value = options.get(optionName);
            if (value == null) {
                value = System.getenv(environmentVariable);
            }
            return value != null ? value : fallback;
        }
    }
}

/** Outcome of one sign-in attempt. */
enum AuthResult {
    SUCCESS,
    FAILURE,
    INVALID_INPUT
}

/**
 * Decides whether an email address and a password are a valid pair of credentials.
 *
 * <p>The database is asked only for the hash that belongs to the given email address. The
 * password itself is never sent to the database, so it never appears in a query, in a log file or
 * in a query log.
 */
final class AuthService {

    private final Database db;

    AuthService(Database db) {
        this.db = db;
    }

    /**
     * @param email    the address as the user typed it
     * @param password the password as the user typed it; this method does not modify or erase it
     */
    AuthResult authenticate(String email, char[] password) {
        String normalizedEmail = Emails.normalize(email);
        if (normalizedEmail == null || !PasswordHasher.isUsable(password)) {
            // Nothing is looked up for input this program will not read, so this answer cannot
            // say anything about whether a particular account exists.
            return AuthResult.INVALID_INPUT;
        }

        String storedHash;
        try {
            storedHash = db.findPasswordHash(normalizedEmail);
        } catch (SQLException e) {
            // A broken database is never reported as a successful sign-in.
            System.err.println("[auth] the account could not be looked up in the database");
            return AuthResult.FAILURE;
        }

        boolean passwordMatches;
        try {
            // storedHash is null when no account uses this address. PasswordHasher.matches then
            // still does a full hash calculation, so "no such account" and "wrong password" take
            // the same time and the difference cannot be used to list accounts.
            passwordMatches = PasswordHasher.matches(password, storedHash);
        } catch (RuntimeException e) {
            System.err.println("[auth] the stored credential could not be checked");
            return AuthResult.FAILURE;
        }
        return passwordMatches ? AuthResult.SUCCESS : AuthResult.FAILURE;
    }
}

/**
 * Reads and writes the {@code app_user} table.
 *
 * <p>Every statement that carries a value from a user is a {@link PreparedStatement}, so user
 * input is always data and never part of the SQL text.
 */
final class Database {

    private static final String TABLE = "app_user";

    private final String url;
    private final String user;
    private final String password;

    Database(String url, String user, String password) {
        this.url = url;
        this.user = user == null ? "" : user;
        this.password = password == null ? "" : password;
    }

    Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    /** Creates the table. The email address is the key, which also makes it unique. */
    void initSchema() throws SQLException {
        String createTable = "CREATE TABLE IF NOT EXISTS " + TABLE
                + " (email VARCHAR(254) NOT NULL PRIMARY KEY,"
                + " password_hash VARCHAR(512) NOT NULL)";
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            statement.execute(createTable);
        }
    }

    /**
     * Stores a new account.
     *
     * @throws SQLException if the address is already taken or the database refuses the write
     */
    boolean addUser(String email, char[] password) throws SQLException {
        String normalizedEmail = Emails.normalize(email);
        if (normalizedEmail == null) {
            throw new IllegalArgumentException("that is not an email address this program accepts");
        }
        if (!PasswordHasher.isUsable(password)) {
            throw new IllegalArgumentException("the password must be 1 to "
                    + PasswordHasher.MAX_PASSWORD_CHARS + " characters and may not contain a NUL");
        }
        String hash = PasswordHasher.hash(password);
        String sql = "INSERT INTO " + TABLE + " (email, password_hash) VALUES (?, ?)";
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalizedEmail);
            statement.setString(2, hash);
            return statement.executeUpdate() == 1;
        }
    }

    /**
     * Looks up the stored hash for one email address.
     *
     * @return the stored hash, or null when no account uses that address
     */
    String findPasswordHash(String normalizedEmail) throws SQLException {
        String sql = "SELECT password_hash FROM " + TABLE + " WHERE email = ?";
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalizedEmail);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return null;
                }
                String hash = rows.getString(1);
                if (rows.next()) {
                    throw new SQLException("the table holds more than one row for one email address");
                }
                return hash;
            }
        }
    }
}

/**
 * Turns a password into the text that is stored in the database, and checks a password against
 * that text.
 *
 * <p>A stored value looks like {@code pbkdf2-sha256$120000$<salt>$<hash>}: the name of the key
 * derivation function, how many times it ran, a random 16 byte salt and the resulting 32 byte
 * hash, all in Base64. PBKDF2 is deliberately slow, which makes guessing passwords from a stolen
 * copy of the table expensive. Only the hash is stored, never the password.
 */
final class PasswordHasher {

    static final int MAX_PASSWORD_CHARS = 1024;

    private static final String SCHEME = "pbkdf2-sha256";
    private static final String JAVA_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final int MIN_ITERATIONS = 1_000;
    private static final int MAX_ITERATIONS = 2_000_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private PasswordHasher() {
    }

    /**
     * Whether a password can be handled at all.
     *
     * <p>NUL and unpaired surrogate characters are refused because {@link PBEKeySpec} maps them
     * onto other passwords, which would let two different inputs share one stored hash. The length
     * cap keeps the cost of one sign-in attempt bounded.
     */
    static boolean isUsable(char[] password) {
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_CHARS) {
            return false;
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c == 0) {
                return false;
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    return false;
                }
                // Consume the tail of the pair so it is not read as an unpaired surrogate.
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    /** Builds a new stored value with a fresh random salt. */
    static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS, HASH_BYTES);
        try {
            return SCHEME + "$" + ITERATIONS + "$" + ENCODER.encodeToString(salt)
                    + "$" + ENCODER.encodeToString(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * Checks a password against a stored value.
     *
     * @param storedHash the value from the database, or null when the account does not exist
     * @return true only when the password reproduces the stored hash
     */
    static boolean matches(char[] password, String storedHash) {
        Params params = parse(storedHash);
        if (params == null) {
            // Unknown account or unreadable stored value: spend the same effort as a real check
            // and compare against a hash this password cannot possibly produce.
            params = EqualWork.PARAMS;
        }
        byte[] candidate = derive(password, params.salt, params.iterations, params.expectedHash.length);
        try {
            return MessageDigest.isEqual(candidate, params.expectedHash);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /** Salt, cost and expected hash read out of a stored value. */
    private static final class Params {
        final byte[] salt;
        final int iterations;
        final byte[] expectedHash;

        Params(byte[] salt, int iterations, byte[] expectedHash) {
            this.salt = salt;
            this.iterations = iterations;
            this.expectedHash = expectedHash;
        }
    }

    /** One real hash, calculated once, used as the equal-effort stand-in for a missing account. */
    private static final class EqualWork {
        static final Params PARAMS = parse(hash("this value is never a real password".toCharArray()));
    }

    /** Returns null for anything that is not a value this class would have written. */
    private static Params parse(String storedHash) {
        if (storedHash == null) {
            return null;
        }
        String[] parts = storedHash.split("\\$", -1);
        if (parts.length != 4 || !SCHEME.equals(parts[0])) {
            return null;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] expectedHash;
        try {
            salt = DECODER.decode(parts[2]);
            expectedHash = DECODER.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (salt.length < 8 || salt.length > 64 || expectedHash.length != HASH_BYTES) {
            return null;
        }
        return new Params(salt, iterations, expectedHash);
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int hashBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashBytes * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(JAVA_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the password could not be hashed on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }
}

/**
 * The little bit of email address checking that this program needs.
 *
 * <p>Addresses are compared in lower case, so {@code Alice@Example.com} and
 * {@code alice@example.com} are the same account. The same normalising step runs when an account is
 * stored and when it is looked up, which is what makes the two agree.
 */
final class Emails {

    private static final int MAX_EMAIL_CHARS = 254;
    private static final int MAX_LOCAL_PART_CHARS = 64;
    private static final Pattern ACCEPTED_SHAPE =
            Pattern.compile("[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}");

    private Emails() {
    }

    /** @return the address in the form used for storage and lookup, or null if it is unacceptable */
    static String normalize(String email) {
        if (email == null) {
            return null;
        }
        String trimmed = email.trim();
        if (trimmed.isEmpty() || trimmed.length() > MAX_EMAIL_CHARS) {
            return null;
        }
        String lowered = trimmed.toLowerCase(Locale.ROOT);
        if (!ACCEPTED_SHAPE.matcher(lowered).matches()) {
            return null;
        }
        if (lowered.indexOf('@') > MAX_LOCAL_PART_CHARS) {
            return null;
        }
        return lowered;
    }
}
