import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Administrator portal: authenticates administrator users and grants access
 * to admin-level functionality.
 *
 * Security notes:
 *  - No hard-coded or default credentials. The first administrator is created
 *    interactively on first run.
 *  - Passwords are never stored. Only salted PBKDF2-HMAC-SHA256 hashes are kept.
 *  - Hashes are compared in constant time, and unknown usernames still go
 *    through a full hash computation, so response time does not reveal which
 *    usernames exist.
 *  - Failed logins produce one generic message and are rate-limited.
 *  - Passwords are read without echo and wiped from memory after use.
 */
public final class AdminPortal {

    private static final Path CREDENTIALS_FILE = Paths.get("admins.db");
    private static final Path AUDIT_LOG = Paths.get("admin-audit.log");

    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final long FAILURE_DELAY_MS = 2_000;
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CredentialStore store;
    private final Input input;

    private AdminPortal(CredentialStore store, Input input) {
        this.store = store;
        this.input = input;
    }

    public static void main(String[] args) {
        try {
            AdminPortal portal = new AdminPortal(CredentialStore.load(CREDENTIALS_FILE), new Input());
            portal.run();
        } catch (IOException e) {
            System.err.println("Error: could not access portal data files (" + e.getMessage() + ").");
            System.exit(1);
        }
    }

    private void run() throws IOException {
        System.out.println("=== Administrator Portal ===");

        if (store.isEmpty()) {
            System.out.println("No administrator accounts exist yet. Let's create the first one.");
            String created = createAdmin();
            if (created == null) {
                System.out.println("Setup cancelled. Exiting.");
                return;
            }
            audit("SETUP", created, "initial administrator created");
        }

        String user = login();
        if (user == null) {
            System.out.println("Access denied.");
            return;
        }

        System.out.println();
        System.out.println("Access granted. Welcome, " + user + ".");
        adminMenu(user);
    }

    // ---------------------------------------------------------------- login

    /** Returns the authenticated username, or null if access is denied. */
    private String login() throws IOException {
        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            System.out.println();
            String username = input.readLine("Username: ");
            if (username == null) {
                return null; // end of input
            }
            username = username.trim();

            char[] password = input.readPassword("Password: ");
            if (password == null) {
                return null;
            }

            boolean ok;
            try {
                ok = authenticate(username, password);
            } finally {
                Arrays.fill(password, '\0');
            }

            String logName = USERNAME_PATTERN.matcher(username).matches() ? username : "<invalid>";
            if (ok) {
                audit("LOGIN_SUCCESS", logName, "");
                return username;
            }

            audit("LOGIN_FAILURE", logName, "attempt " + attempt);
            // Same message whether the username or the password was wrong.
            System.out.println("Invalid username or password.");
            sleepQuietly(FAILURE_DELAY_MS * attempt);
        }
        System.out.println("Too many failed attempts.");
        return null;
    }

    /** Verifies credentials. Always performs a full hash to avoid timing leaks. */
    boolean authenticate(String username, char[] password) {
        StoredHash stored = USERNAME_PATTERN.matcher(username).matches() ? store.get(username) : null;
        StoredHash target = (stored != null) ? stored : StoredHash.DUMMY;

        byte[] computed = pbkdf2(password, target.salt, target.iterations);
        boolean match = MessageDigest.isEqual(computed, target.hash);
        Arrays.fill(computed, (byte) 0);

        return stored != null && match;
    }

    // ----------------------------------------------------------- admin menu

    private void adminMenu(String currentUser) throws IOException {
        while (true) {
            System.out.println();
            System.out.println("--- Admin Menu (" + currentUser + ") ---");
            System.out.println("1. List administrator accounts");
            System.out.println("2. Add administrator");
            System.out.println("3. Remove administrator");
            System.out.println("4. Change my password");
            System.out.println("5. View recent audit log");
            System.out.println("6. Log out");

            String choice = input.readLine("Choose an option: ");
            if (choice == null) {
                choice = "6";
            }

            switch (choice.trim()) {
                case "1":
                    listAdmins();
                    break;
                case "2": {
                    String created = createAdmin();
                    if (created != null) {
                        audit("ADMIN_ADDED", currentUser, "added " + created);
                    }
                    break;
                }
                case "3":
                    removeAdmin(currentUser);
                    break;
                case "4":
                    changePassword(currentUser);
                    break;
                case "5":
                    showAuditLog();
                    break;
                case "6":
                    audit("LOGOUT", currentUser, "");
                    System.out.println("Logged out. Goodbye.");
                    return;
                default:
                    System.out.println("Unknown option.");
            }
        }
    }

    private void listAdmins() {
        System.out.println("Administrator accounts:");
        for (String name : store.usernames()) {
            System.out.println("  - " + name);
        }
    }

    /** Prompts for a new admin account. Returns the username, or null if cancelled. */
    private String createAdmin() throws IOException {
        String username = input.readLine("New username (3-32 letters, digits, _ . -): ");
        if (username == null) {
            return null;
        }
        username = username.trim();
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            System.out.println("Invalid username.");
            return null;
        }
        if (store.get(username) != null) {
            System.out.println("That username already exists.");
            return null;
        }

        char[] password = promptNewPassword();
        if (password == null) {
            return null;
        }
        try {
            store.put(username, StoredHash.create(password));
            store.save();
        } finally {
            Arrays.fill(password, '\0');
        }
        System.out.println("Administrator '" + username + "' created.");
        return username;
    }

    private void removeAdmin(String currentUser) throws IOException {
        String username = input.readLine("Username to remove: ");
        if (username == null) {
            return;
        }
        username = username.trim();
        if (username.equals(currentUser)) {
            System.out.println("You cannot remove your own account while logged in.");
            return;
        }
        if (store.get(username) == null) {
            System.out.println("No such administrator.");
            return;
        }
        String confirm = input.readLine("Type the username again to confirm: ");
        if (confirm == null || !confirm.trim().equals(username)) {
            System.out.println("Cancelled.");
            return;
        }
        store.remove(username);
        store.save();
        audit("ADMIN_REMOVED", currentUser, "removed " + username);
        System.out.println("Administrator '" + username + "' removed.");
    }

    private void changePassword(String currentUser) throws IOException {
        char[] current = input.readPassword("Current password: ");
        if (current == null) {
            return;
        }
        boolean ok;
        try {
            ok = authenticate(currentUser, current);
        } finally {
            Arrays.fill(current, '\0');
        }
        if (!ok) {
            audit("PASSWORD_CHANGE_FAILURE", currentUser, "wrong current password");
            System.out.println("Current password is incorrect.");
            sleepQuietly(FAILURE_DELAY_MS);
            return;
        }

        char[] password = promptNewPassword();
        if (password == null) {
            return;
        }
        try {
            store.put(currentUser, StoredHash.create(password));
            store.save();
        } finally {
            Arrays.fill(password, '\0');
        }
        audit("PASSWORD_CHANGED", currentUser, "");
        System.out.println("Password changed.");
    }

    private void showAuditLog() throws IOException {
        if (!Files.exists(AUDIT_LOG)) {
            System.out.println("Audit log is empty.");
            return;
        }
        var lines = Files.readAllLines(AUDIT_LOG, StandardCharsets.UTF_8);
        int from = Math.max(0, lines.size() - 20);
        System.out.println("Last " + (lines.size() - from) + " audit entries:");
        for (String line : lines.subList(from, lines.size())) {
            System.out.println("  " + line);
        }
    }

    /** Prompts twice for a new password and checks the password policy. */
    private char[] promptNewPassword() throws IOException {
        System.out.println("Password must be " + MIN_PASSWORD_LENGTH + "-" + MAX_PASSWORD_LENGTH
                + " characters and include upper case, lower case, a digit and a symbol.");
        char[] first = input.readPassword("New password: ");
        if (first == null) {
            return null;
        }
        char[] second = input.readPassword("Confirm password: ");
        if (second == null) {
            Arrays.fill(first, '\0');
            return null;
        }
        try {
            if (!Arrays.equals(first, second)) {
                System.out.println("Passwords do not match.");
                Arrays.fill(first, '\0');
                return null;
            }
            String problem = checkPasswordPolicy(first);
            if (problem != null) {
                System.out.println(problem);
                Arrays.fill(first, '\0');
                return null;
            }
            return first;
        } finally {
            Arrays.fill(second, '\0');
        }
    }

    static String checkPasswordPolicy(char[] pw) {
        if (pw.length < MIN_PASSWORD_LENGTH || pw.length > MAX_PASSWORD_LENGTH) {
            return "Password must be " + MIN_PASSWORD_LENGTH + "-" + MAX_PASSWORD_LENGTH + " characters long.";
        }
        boolean upper = false, lower = false, digit = false, symbol = false;
        for (char c : pw) {
            if (Character.isUpperCase(c)) upper = true;
            else if (Character.isLowerCase(c)) lower = true;
            else if (Character.isDigit(c)) digit = true;
            else if (!Character.isWhitespace(c)) symbol = true;
        }
        if (!(upper && lower && digit && symbol)) {
            return "Password must include upper case, lower case, a digit and a symbol.";
        }
        return null;
    }

    // -------------------------------------------------------------- helpers

    static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance(HASH_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Password hashing unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Appends an entry to the audit log. Passwords are never logged. */
    private static void audit(String event, String username, String detail) {
        String line = Instant.now() + " " + event + " user=" + username
                + (detail.isEmpty() ? "" : " " + detail) + System.lineSeparator();
        try {
            if (!Files.exists(AUDIT_LOG)) {
                FileSecurity.createPrivateFile(AUDIT_LOG);
            }
            Files.writeString(AUDIT_LOG, line, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Warning: could not write audit log: " + e.getMessage());
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------- nested classes

    /** A salted password hash as stored on disk: iterations:salt:hash (Base64). */
    static final class StoredHash {
        /** Used for unknown usernames so that failed lookups take as long as real checks. */
        static final StoredHash DUMMY = new StoredHash(ITERATIONS, randomBytes(SALT_BYTES), randomBytes(HASH_BITS / 8));

        final int iterations;
        final byte[] salt;
        final byte[] hash;

        StoredHash(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }

        static StoredHash create(char[] password) {
            byte[] salt = randomBytes(SALT_BYTES);
            return new StoredHash(ITERATIONS, salt, pbkdf2(password, salt, ITERATIONS));
        }

        String encode() {
            Base64.Encoder b64 = Base64.getEncoder();
            return iterations + ":" + b64.encodeToString(salt) + ":" + b64.encodeToString(hash);
        }

        static StoredHash decode(String value) {
            String[] parts = value.split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException("malformed entry");
            }
            Base64.Decoder b64 = Base64.getDecoder();
            return new StoredHash(Integer.parseInt(parts[0]), b64.decode(parts[1]), b64.decode(parts[2]));
        }

        private static byte[] randomBytes(int n) {
            byte[] b = new byte[n];
            RANDOM.nextBytes(b);
            return b;
        }
    }

    /** Stores administrator usernames and password hashes in a properties file. */
    static final class CredentialStore {
        private final Path file;
        private final Map<String, StoredHash> entries = new TreeMap<>();

        private CredentialStore(Path file) {
            this.file = file;
        }

        static CredentialStore load(Path file) throws IOException {
            CredentialStore store = new CredentialStore(file);
            if (Files.exists(file)) {
                Properties props = new Properties();
                try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    props.load(r);
                }
                for (String name : props.stringPropertyNames()) {
                    try {
                        if (!USERNAME_PATTERN.matcher(name).matches()) {
                            throw new IllegalArgumentException("invalid username");
                        }
                        store.entries.put(name, StoredHash.decode(props.getProperty(name)));
                    } catch (IllegalArgumentException e) {
                        throw new IOException("credential file is corrupt (entry '" + name + "')");
                    }
                }
            }
            return store;
        }

        boolean isEmpty() { return entries.isEmpty(); }
        StoredHash get(String username) { return entries.get(username); }
        void put(String username, StoredHash hash) { entries.put(username, hash); }
        void remove(String username) { entries.remove(username); }
        Iterable<String> usernames() { return entries.keySet(); }

        /** Writes to a temp file and atomically replaces the old file. */
        void save() throws IOException {
            Properties props = new Properties();
            entries.forEach((name, hash) -> props.setProperty(name, hash.encode()));

            Path dir = file.toAbsolutePath().getParent();
            Path tmp = Files.createTempFile(dir, "admins", ".tmp");
            try {
                FileSecurity.restrictToOwner(tmp);
                try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                    props.store(w, "Administrator credentials (PBKDF2-HMAC-SHA256: iterations:salt:hash)");
                }
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } finally {
                Files.deleteIfExists(tmp);
            }
        }
    }

    /** Keeps data files readable only by the account running the portal. */
    static final class FileSecurity {
        static void createPrivateFile(Path path) throws IOException {
            Files.createFile(path);
            restrictToOwner(path);
        }

        static void restrictToOwner(Path path) throws IOException {
            try {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException e) {
                // Non-POSIX file system (e.g. Windows): rely on the directory's ACLs.
            }
        }
    }

    /** Reads input, hiding passwords when a real terminal is available. */
    static final class Input {
        private final Console console = System.console();
        private final BufferedReader reader =
                console == null ? new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)) : null;
        private boolean warned;

        String readLine(String prompt) throws IOException {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            return reader.readLine();
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
    }
}
