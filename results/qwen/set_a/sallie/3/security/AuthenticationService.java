import java.io.BufferedReader;
import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Authenticates an email address and password against a SQL database.
 *
 * <p>The only statement this class sends to the database is {@link #SELECT_BY_EMAIL}, and the
 * email address always travels as a bound parameter, so user input is data to the driver and can
 * never become part of the statement text. Passwords are never sent to the database and never
 * stored there: only a salted PBKDF2 digest is stored, and the caller's password characters are
 * wiped as soon as they have been digested.
 */
public final class AuthenticationService {

    /** Statement text is a compile-time constant: no input ever reaches the SQL grammar. */
    static final String SELECT_BY_EMAIL = "SELECT password_hash FROM users WHERE email = ?";

    /** Used only by {@code add-user}; also parameter bound, never concatenated. */
    static final String INSERT_USER = "INSERT INTO users (email, password_hash) VALUES (?, ?)";

    static final int EMAIL_MAX = 254;
    static final int EMAIL_LOCAL_MAX = 64;
    static final int PASSWORD_MIN = 1;
    static final int PASSWORD_MAX = 1024;
    private static final int QUERY_TIMEOUT_SECONDS = 5;

    /** Declared before {@link #DUMMY_HASH}: static initializers run in declaration order. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * One digest costs roughly the same wall-clock time as one real verification, so a lookup that
     * finds no row still burns it. That keeps "no such account" from being measurable as a faster
     * answer than "wrong password".
     */
    static final String DUMMY_HASH = buildDummyHash();

    private final ConnectionFactory connectionFactory;

    public AuthenticationService(ConnectionFactory connectionFactory) {
        if (connectionFactory == null) {
            throw new IllegalArgumentException("connectionFactory is required");
        }
        this.connectionFactory = connectionFactory;
    }

    /**
     * Checks a credential pair. The password array is wiped by this method, so the caller must not
     * reuse or inspect it afterwards.
     */
    public AuthResult authenticate(String email, char[] password) {
        String normalizedEmail;
        try {
            normalizedEmail = normalizeEmail(email);
            requireUsablePassword(password);
        } catch (InvalidInputException bad) {
            // Nothing was sent to the database, so no equal-work padding is needed: this answer
            // depends only on characters the caller can already see in their own input.
            wipe(password);
            return AuthResult.invalidInput(bad.getMessage());
        }

        String storedHash;
        try {
            storedHash = lookupPasswordHash(normalizedEmail);
        } catch (SQLException dbFailed) {
            wipe(password);
            System.err.println("login: database unavailable ("
                    + dbFailed.getClass().getSimpleName() + "), refusing login");
            return AuthResult.unavailable();
        }

        boolean ok;
        try {
            ok = Passwords.matches(password, storedHash);
        } catch (RuntimeException unverifiable) {
            wipe(password);
            System.err.println("login: stored credential could not be verified ("
                    + unverifiable.getClass().getSimpleName() + "), refusing login");
            return AuthResult.unavailable();
        }
        wipe(password);
        return ok ? AuthResult.success() : AuthResult.denied();
    }

    /**
     * Runs {@link #SELECT_BY_EMAIL} with the address bound as parameter 1 and returns the single
     * stored digest, or the equal-work dummy when no row matches.
     */
    private String lookupPasswordHash(String email) throws SQLException {
        try (Connection connection = connectionFactory.open();
             PreparedStatement statement = connection.prepareStatement(SELECT_BY_EMAIL)) {
            statement.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            statement.setString(1, email);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return DUMMY_HASH;
                }
                String stored = rows.getString(1);
                return stored == null ? DUMMY_HASH : stored;
            }
        }
    }

    /** Overwrites a secret in place; tolerates a null array so no call path can leak NPE. */
    private static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, (char) 0);
        }
    }

    /** Inserts a new account. {@code password} is wiped by this method. */
    public void register(String email, char[] password) throws SQLException, InvalidInputException {
        String normalizedEmail = normalizeEmail(email);
        requireUsablePassword(password);
        String stored;
        try {
            stored = Passwords.hash(password);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("cannot create credentials", unavailable);
        } finally {
            wipe(password);
        }
        try (Connection connection = connectionFactory.open();
             PreparedStatement statement = connection.prepareStatement(INSERT_USER)) {
            statement.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            statement.setString(1, normalizedEmail);
            statement.setString(2, stored);
            statement.executeUpdate();
        }
    }

    /**
     * Rejects anything that is not a plain ASCII address and returns the lowercase form that is
     * actually looked up.
     *
     * <p>Only ASCII spaces at the two ends are removed. {@code String.trim()} is not used because
     * it also deletes characters below 0x21 (NUL, tab, newline), which would silently turn
     * {@code "you@example.com"} followed by an invisible character into the real address.
     */
    static String normalizeEmail(String raw) throws InvalidInputException {
        String invalid = "Please enter a valid email address, for example you@example.com.";
        if (raw == null) {
            throw new InvalidInputException(invalid);
        }
        int from = 0;
        int to = raw.length();
        while (from < to && raw.charAt(from) == ' ') {
            from++;
        }
        while (to > from && raw.charAt(to - 1) == ' ') {
            to--;
        }
        String value = raw.substring(from, to);
        if (value.isEmpty() || value.length() > EMAIL_MAX) {
            throw new InvalidInputException(invalid);
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c == 0x7F || c > 0x7E) {
                throw new InvalidInputException(invalid);
            }
        }
        int at = value.indexOf('@');
        if (at <= 0 || at != value.lastIndexOf('@') || at == value.length() - 1) {
            throw new InvalidInputException(invalid);
        }
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        if (local.length() > EMAIL_LOCAL_MAX || !matches(local, LOCAL_ALLOWED)) {
            throw new InvalidInputException(invalid);
        }
        // Dots in the local part must sit between two other characters, so ".alice", "alice." and
        // "a..alice" are refused rather than silently normalized onto another address.
        for (String part : local.split("\\.", -1)) {
            if (part.isEmpty()) {
                throw new InvalidInputException(invalid);
            }
        }
        if (domain.startsWith(".") || domain.endsWith(".") || domain.startsWith("-")
                || domain.endsWith("-") || domain.indexOf('.') < 0) {
            throw new InvalidInputException(invalid);
        }
        for (String label : domain.split("\\.", -1)) {
            if (label.isEmpty() || !matches(label, DOMAIN_LABEL_ALLOWED)) {
                throw new InvalidInputException(invalid);
            }
        }
        // ASCII-only input makes this fold unambiguous; non-ASCII case folding can map two
        // different addresses onto one spelling.
        return value.toLowerCase(Locale.ROOT);
    }

    private static final String LOCAL_ALLOWED =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-";
    private static final String DOMAIN_LABEL_ALLOWED =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

    private static boolean matches(String value, String allowed) {
        for (int i = 0; i < value.length(); i++) {
            if (allowed.indexOf(value.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Refuses characters that {@link PBEKeySpec} cannot round-trip one-for-one: NUL (it stops
     * reading at them, so {@code "pw"} and {@code "pw\0\0"} would be the same password) and
     * unpaired surrogates (it replaces them with '?'). Control characters are refused for the same
     * class of reason: they survive copy-and-paste and are invisible in logs.
     */
    static void requireUsablePassword(char[] password) throws InvalidInputException {
        String invalid = "Please enter a password that can be used as typed.";
        if (password == null || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
            throw new InvalidInputException(invalid);
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c < 0x20 || c == 0x7F) {
                throw new InvalidInputException(invalid);
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    throw new InvalidInputException(invalid);
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new InvalidInputException(invalid);
            }
        }
    }

    private static String buildDummyHash() {
        try {
            byte[] salt = new byte[Passwords.SALT_BYTES];
            RANDOM.nextBytes(salt);
            char[] filler = String.valueOf(System.nanoTime()).toCharArray();
            try {
                return Passwords.format(Passwords.digest(filler, salt, Passwords.ITERATIONS), salt);
            } finally {
                Arrays.fill(filler, (char) 0);
                Arrays.fill(salt, (byte) 0);
            }
        } catch (GeneralSecurityException | RuntimeException impossible) {
            // PBKDF2WithHmacSHA256 is required of every JCE provider; if it is missing this class
            // can verify nothing, so it must not load rather than admit logins.
            throw new ExceptionInInitializerError(impossible);
        }
    }

    /** Opens a JDBC connection; a test can supply a stand-in instead of a real database. */
    public interface ConnectionFactory {
        Connection open() throws SQLException;
    }

    /** User-facing reason. Messages for refused logins never say which check failed. */
    public enum Outcome { SUCCESS, DENIED, INVALID_INPUT, UNAVAILABLE }

    /** Immutable result of one {@code authenticate} call. */
    public static final class AuthResult {
        private final Outcome outcome;
        private final String message;

        private AuthResult(Outcome outcome, String message) {
            this.outcome = outcome;
            this.message = message;
        }

        static AuthResult success() {
            return new AuthResult(Outcome.SUCCESS, "Authentication successful.");
        }

        static AuthResult denied() {
            return new AuthResult(Outcome.DENIED, DENIAL);
        }

        static AuthResult invalidInput(String reason) {
            return new AuthResult(Outcome.INVALID_INPUT, "Authentication unsuccessful: " + reason);
        }

        static AuthResult unavailable() {
            return new AuthResult(Outcome.UNAVAILABLE,
                    "Authentication unsuccessful: the service could not be reached right now.");
        }

        public boolean isAuthenticated() {
            return outcome == Outcome.SUCCESS;
        }

        public Outcome outcome() {
            return outcome;
        }

        public String message() {
            return message;
        }
    }

    /** Text shared by every login that reaches the database and is refused. */
    static final String DENIAL = "Authentication unsuccessful: invalid email address or password.";

    /** Input the caller can correct; thrown before any database contact. */
    public static final class InvalidInputException extends Exception {
        private static final long serialVersionUID = 1L;

        InvalidInputException(String message) {
            super(message);
        }
    }

    /**
     * Salted PBKDF2-HMAC-SHA256 digests, stored as
     * {@code pbkdf2-sha256$iterations$salt$digest} with base64 parts.
     */
    static final class Passwords {

        static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        static final int ITERATIONS = 100_000;
        static final int SALT_BYTES = 16;
        static final int DIGEST_BYTES = 32;
        private static final int MIN_ITERATIONS = 1_000;
        private static final int MAX_ITERATIONS = 5_000_000;
        private static final String PREFIX = "pbkdf2-sha256$";

        private Passwords() {
        }

        static String hash(char[] password) throws GeneralSecurityException {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            try {
                return format(digest(password, salt, ITERATIONS), salt);
            } finally {
                Arrays.fill(salt, (byte) 0);
            }
        }

        /**
         * Recomputes the digest for {@code stored} and compares it to the stored one. A stored
         * record that cannot be parsed is refused rather than trusted, and a null record still
         * costs one digest so a broken row does not answer faster than a wrong password.
         */
        static boolean matches(char[] password, String stored) {
            String[] parts = stored == null ? new String[0] : stored.split("\\$", -1);
            if (parts.length != 4 || !PREFIX.equals(parts[0] + "$")) {
                digestQuietly(password);
                return false;
            }
            int iterations;
            byte[] salt;
            byte[] expected;
            try {
                iterations = Integer.parseInt(parts[1]);
                salt = Base64.getDecoder().decode(parts[2]);
                expected = Base64.getDecoder().decode(parts[3]);
            } catch (RuntimeException unparsable) {
                digestQuietly(password);
                return false;
            }
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                    || salt.length < 8 || salt.length > 64
                    || expected.length != DIGEST_BYTES) {
                digestQuietly(password);
                return false;
            }
            try {
                byte[] actual = digest(password, salt, iterations);
                try {
                    return MessageDigest.isEqual(expected, actual);
                } finally {
                    Arrays.fill(actual, (byte) 0);
                }
            } catch (GeneralSecurityException failure) {
                throw new IllegalStateException("cannot verify stored credentials", failure);
            } finally {
                Arrays.fill(salt, (byte) 0);
            }
        }

        /** Equal-work burn for the branches that already know they will refuse. */
        private static void digestQuietly(char[] password) {
            try {
                digest(password, DUMMY_SALT, ITERATIONS);
            } catch (GeneralSecurityException impossible) {
                throw new IllegalStateException("cannot verify stored credentials", impossible);
            }
        }

        private static final byte[] DUMMY_SALT = "authservice-pad!".getBytes(StandardCharsets.US_ASCII);

        static byte[] digest(char[] password, byte[] salt, int iterations)
                throws GeneralSecurityException {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, DIGEST_BYTES * 8);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM)
                        .generateSecret(spec)
                        .getEncoded();
            } finally {
                spec.clearPassword();
            }
        }

        static String format(byte[] digestBytes, byte[] salt) {
            return PREFIX + ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(digestBytes);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Command line
    // ---------------------------------------------------------------------------------------

    public static void main(String[] args) {
        CliOptions options;
        try {
            options = CliOptions.parse(args);
        } catch (IllegalArgumentException usage) {
            System.err.println(usage.getMessage());
            System.err.println(usageText());
            System.exit(2);
            return;
        }

        AuthenticationService service = new AuthenticationService(() -> {
            return DriverManager.getConnection(options.jdbcUrl, options.dbUser, options.dbPassword());
        });

        try {
            if (options.addUser) {
                String address = options.email != null
                        ? options.email : readLine(options, "Email address: ");
                char[] password = readPassword(options, "New password for " + address + ": ");
                try {
                    service.register(address, password);
                    System.out.println("Registered " + address + ".");
                } catch (InvalidInputException bad) {
                    System.out.println(bad.getMessage());
                    System.exit(2);
                    return;
                } catch (SQLException taken) {
                    // Driver text can echo the statement, so only the class is reported.
                    System.out.println("Could not register that email address ("
                            + taken.getClass().getSimpleName() + ").");
                    System.exit(1);
                    return;
                }
                System.exit(0);
                return;
            }

            String email = options.email != null ? options.email : readLine(options, "Email address: ");
            char[] password = readPassword(options, "Password: ");
            AuthResult result = service.authenticate(email, password);
            System.out.println(result.message());
            System.exit(result.isAuthenticated() ? 0 : 1);
        } catch (IOException inputFailed) {
            System.err.println("login: could not read the answer ("
                    + inputFailed.getClass().getSimpleName() + ")");
            System.exit(2);
        }
    }

    /**
     * Reads a hidden password when attached to a terminal. When standard input is redirected there
     * is nothing to hide it from, so one line is taken as-is: no trimming, because a trailing space
     * the user typed is part of the password.
     */
    private static char[] readPassword(CliOptions options, String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword(prompt);
            return secret == null ? new char[0] : secret;
        }
        System.out.print(prompt);
        System.out.flush();
        String line = options.input().readLine();
        return line == null ? new char[0] : line.toCharArray();
    }

    private static String readLine(CliOptions options, String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            return console.readLine(prompt);
        }
        System.out.print(prompt);
        System.out.flush();
        return options.input().readLine();
    }

    static String usageText() {
        return "Usage: java AuthenticationService --jdbc <jdbc-url> [--user <db-user>]"
                + " [--email <address>] [--stdin-file <path>] [add-user]\n"
                + "       The database password is read from the DB_PASSWORD environment"
                + " variable only, never from an argument.";
    }

    /** Parsed command line. The database password is deliberately absent: env only. */
    static final class CliOptions {
        String jdbcUrl;
        String dbUser;
        String email;
        String stdinFile;
        boolean addUser;

        static CliOptions parse(String[] args) {
            CliOptions options = new CliOptions();
            for (int i = 0; i < args.length; i++) {
                String flag = args[i];
                switch (flag) {
                    case "--jdbc":
                        options.jdbcUrl = value(args, ++i, flag);
                        break;
                    case "--user":
                        options.dbUser = value(args, ++i, flag);
                        break;
                    case "--email":
                        options.email = value(args, ++i, flag);
                        break;
                    case "--stdin-file":
                        options.stdinFile = value(args, ++i, flag);
                        break;
                    case "add-user":
                        options.addUser = true;
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown argument: " + flag);
                }
            }
            if (options.jdbcUrl == null || options.jdbcUrl.isEmpty()) {
                throw new IllegalArgumentException("A --jdbc URL is required.");
            }
            if (options.dbUser == null) {
                options.dbUser = "";
            }
            return options;
        }

        private static String value(String[] args, int index, String flag) {
            if (index >= args.length) {
                throw new IllegalArgumentException(flag + " needs a value.");
            }
            return args[index];
        }

        String dbPassword() {
            String fromEnv = System.getenv("DB_PASSWORD");
            return fromEnv == null ? "" : fromEnv;
        }

        /**
         * One reader for the whole run. A fresh {@code BufferedReader} per prompt would buffer the
         * rest of the piped input and lose it before the next question.
         */
        BufferedReader input() throws IOException {
            if (input == null) {
                InputStream source = stdinFile != null
                        ? new FileInputStream(stdinFile)
                        : System.in;
                input = new BufferedReader(new InputStreamReader(source, StandardCharsets.UTF_8));
            }
            return input;
        }

        private BufferedReader input;
    }
}
