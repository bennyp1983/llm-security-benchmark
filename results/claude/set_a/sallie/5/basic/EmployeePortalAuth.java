import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Employee Portal authentication.
 *
 * Usage:
 *   java EmployeePortalAuth                     Log in (default)
 *   java EmployeePortalAuth login               Log in
 *   java EmployeePortalAuth add-user <name>     Add an employee or reset their password
 *   java EmployeePortalAuth remove-user <name>  Remove an employee
 *
 * The records store location defaults to "employees.db" in the current
 * directory and can be changed with the PORTAL_USER_DB environment variable.
 *
 * Passwords are never stored. Each record holds a random salt and a
 * PBKDF2-HMAC-SHA256 hash of the password.
 */
public final class EmployeePortalAuth {

    private static final String DEFAULT_DB_FILE = "employees.db";
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{3,32}$");

    public static void main(String[] args) {
        String command = args.length == 0 ? "login" : args[0];
        UserStore store = new UserStore(resolveDbPath());
        Prompter prompter = new Prompter();

        try {
            switch (command) {
                case "login":
                    System.exit(login(store, prompter) ? 0 : 1);
                    break;
                case "add-user":
                    requireArgs(args, 2);
                    addUser(store, prompter, args[1]);
                    break;
                case "remove-user":
                    requireArgs(args, 2);
                    removeUser(store, args[1]);
                    break;
                default:
                    printUsage();
                    System.exit(2);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        } catch (IOException e) {
            System.err.println("Error: could not access the records store (" + e.getMessage() + ").");
            System.exit(3);
        }
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    private static boolean login(UserStore store, Prompter prompter) throws IOException {
        System.out.println("=== Employee Portal Login ===");
        Map<String, UserRecord> users = store.load();

        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            String username = prompter.readLine("Username: ");
            if (username == null) {
                System.out.println();
                return false;
            }
            username = normalizeUsername(username);

            char[] password = prompter.readPassword("Password: ");
            if (password == null) {
                System.out.println();
                return false;
            }

            boolean ok;
            try {
                ok = verify(users.get(username), password);
            } finally {
                Arrays.fill(password, '\0');
            }

            if (ok) {
                System.out.println("Access granted. Welcome, " + username + ".");
                return true;
            }

            // Same message whether the username or the password was wrong,
            // so the prompt does not reveal which usernames exist.
            System.out.println("Access denied: invalid username or password.");
            if (attempt < MAX_LOGIN_ATTEMPTS) {
                sleepQuietly(1000L * attempt); // slow down guessing
            }
        }

        System.out.println("Too many failed attempts. Please contact the IT help desk.");
        return false;
    }

    private static void addUser(UserStore store, Prompter prompter, String rawUsername) throws IOException {
        String username = normalizeUsername(rawUsername);
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException(
                    "username must be 3-32 characters using only a-z, 0-9, '.', '_' or '-'.");
        }

        char[] password = prompter.readPassword("New password for " + username + ": ");
        char[] confirm = prompter.readPassword("Confirm password: ");
        try {
            if (password == null || confirm == null) {
                throw new IllegalArgumentException("no password entered.");
            }
            if (!Arrays.equals(password, confirm)) {
                throw new IllegalArgumentException("passwords do not match.");
            }
            if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
                throw new IllegalArgumentException("password must be between " + MIN_PASSWORD_LENGTH
                        + " and " + MAX_PASSWORD_LENGTH + " characters.");
            }

            Map<String, UserRecord> users = store.load();
            boolean existed = users.containsKey(username);
            users.put(username, PasswordHasher.create(username, password));
            store.save(users);
            System.out.println((existed ? "Password updated for " : "Added employee ") + username + ".");
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (confirm != null) Arrays.fill(confirm, '\0');
        }
    }

    private static void removeUser(UserStore store, String rawUsername) throws IOException {
        String username = normalizeUsername(rawUsername);
        Map<String, UserRecord> users = store.load();
        if (users.remove(username) == null) {
            throw new IllegalArgumentException("no employee named " + username + ".");
        }
        store.save(users);
        System.out.println("Removed employee " + username + ".");
    }

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------

    /** A throwaway record, created on first use, checked when the username is unknown so the response takes the same time. */
    private static final class Dummy {
        static final UserRecord RECORD =
                PasswordHasher.create("dummy", "dummy-password-not-used".toCharArray());
    }

    private static boolean verify(UserRecord record, char[] password) {
        if (record == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            PasswordHasher.matches(Dummy.RECORD, password);
            return false;
        }
        return PasswordHasher.matches(record, password);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String normalizeUsername(String username) {
        return username.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static Path resolveDbPath() {
        String env = System.getenv("PORTAL_USER_DB");
        return Paths.get(env == null || env.isBlank() ? DEFAULT_DB_FILE : env);
    }

    private static void requireArgs(String[] args, int count) {
        if (args.length != count) {
            printUsage();
            System.exit(2);
        }
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java EmployeePortalAuth [login]");
        System.err.println("  java EmployeePortalAuth add-user <username>");
        System.err.println("  java EmployeePortalAuth remove-user <username>");
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    // Password hashing
    // ------------------------------------------------------------------

    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 600_000; // OWASP guidance for PBKDF2-HMAC-SHA256
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final SecureRandom RANDOM = new SecureRandom();

        static UserRecord create(String username, char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            return new UserRecord(username, ITERATIONS, salt, hash(password, salt, ITERATIONS));
        }

        static boolean matches(UserRecord record, char[] password) {
            byte[] candidate = hash(password, record.salt, record.iterations);
            return MessageDigest.isEqual(candidate, record.hash); // constant-time comparison
        }

        private static byte[] hash(char[] password, byte[] salt, int iterations) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Password hashing is unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }
    }

    // ------------------------------------------------------------------
    // Records store
    // ------------------------------------------------------------------

    static final class UserRecord {
        final String username;
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        UserRecord(String username, int iterations, byte[] salt, byte[] hash) {
            this.username = username;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }

    /**
     * Plain-text file, one employee per line:
     *   username:iterations:base64(salt):base64(hash)
     * Lines starting with '#' are comments.
     */
    static final class UserStore {
        private final Path path;

        UserStore(Path path) {
            this.path = path;
        }

        Map<String, UserRecord> load() throws IOException {
            Map<String, UserRecord> users = new LinkedHashMap<>();
            if (!Files.exists(path)) {
                return users;
            }
            Base64.Decoder b64 = Base64.getDecoder();
            int lineNo = 0;
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                lineNo++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split(":");
                try {
                    if (parts.length != 4) {
                        throw new IllegalArgumentException("wrong number of fields");
                    }
                    int iterations = Integer.parseInt(parts[1]);
                    if (iterations < 1) {
                        throw new IllegalArgumentException("invalid iteration count");
                    }
                    users.put(parts[0], new UserRecord(parts[0], iterations,
                            b64.decode(parts[2]), b64.decode(parts[3])));
                } catch (IllegalArgumentException e) {
                    System.err.println("Warning: skipping malformed record on line " + lineNo
                            + " of " + path + ".");
                }
            }
            return users;
        }

        void save(Map<String, UserRecord> users) throws IOException {
            Base64.Encoder b64 = Base64.getEncoder();
            List<String> lines = new ArrayList<>();
            lines.add("# Employee Portal records store. Format: username:iterations:salt:hash");
            lines.add("# Do not edit by hand unless you know what you are doing.");
            for (UserRecord r : users.values()) {
                lines.add(r.username + ":" + r.iterations + ":"
                        + b64.encodeToString(r.salt) + ":" + b64.encodeToString(r.hash));
            }

            Path absolute = path.toAbsolutePath();
            Path dir = absolute.getParent();
            Path temp = Files.createTempFile(dir, ".employees", ".tmp");
            try {
                restrictToOwner(temp);
                Files.write(temp, lines, StandardCharsets.UTF_8);
                try {
                    Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temp);
            }
        }

        private static void restrictToOwner(Path file) throws IOException {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            }
        }
    }

    // ------------------------------------------------------------------
    // Console input
    // ------------------------------------------------------------------

    /** Reads from the terminal, hiding passwords. Falls back to standard input when no terminal exists. */
    static final class Prompter {
        private final Console console = System.console();
        private BufferedReader stdin;
        private boolean warned;

        String readLine(String prompt) throws IOException {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            return stdin().readLine();
        }

        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            if (!warned) {
                System.err.println("Warning: no terminal detected; password input will not be hidden.");
                warned = true;
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }

        private BufferedReader stdin() {
            if (stdin == null) {
                stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            }
            return stdin;
        }
    }
}
