import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A small command-line authentication program for an internal employee portal. */
public final class EmployeePortal {
    private static final Path DEFAULT_STORE = Path.of("employees.db");
    private static final Pattern VALID_USERNAME = Pattern.compile("[A-Za-z0-9._-]{3,64}");
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private EmployeePortal() {
    }

    public static void main(String[] args) {
        try {
            if (args.length > 0 && "--add".equals(args[0])) {
                runAddEmployee(args);
            } else {
                runLogin(args);
            }
        } catch (IllegalArgumentException | IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void runLogin(String[] args)
            throws IOException, GeneralSecurityException {
        if (args.length > 1) {
            throw new IllegalArgumentException("Usage: java EmployeePortal [credential-file]");
        }

        Path storePath = args.length == 1 ? Path.of(args[0]) : DEFAULT_STORE;
        CredentialStore store = CredentialStore.load(storePath);
        if (store.isEmpty()) {
            throw new IllegalArgumentException(
                    "No employee records were found. Add one with: "
                            + "java EmployeePortal --add " + storePath + " <username>");
        }

        Input input = new Input();
        System.out.println("Employee Portal Login");

        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            String username = input.readLine("Username: ").trim();
            char[] password = input.readPassword("Password: ");
            boolean authenticated;
            try {
                authenticated = store.authenticate(username, password);
            } finally {
                java.util.Arrays.fill(password, '\0');
            }

            if (authenticated) {
                System.out.println("Access granted. Welcome, " + username + ".");
                return;
            }

            System.out.println("Access denied. Invalid username or password.");
        }

        System.err.println("Too many failed attempts. Please try again later.");
        System.exit(2);
    }

    private static void runAddEmployee(String[] args)
            throws IOException, GeneralSecurityException {
        if (args.length != 3) {
            throw new IllegalArgumentException(
                    "Usage: java EmployeePortal --add <credential-file> <username>");
        }

        Path storePath = Path.of(args[1]);
        String username = args[2];
        if (!VALID_USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException(
                    "Username must be 3-64 characters and use only letters, numbers, '.', '_' or '-'.");
        }

        CredentialStore store = CredentialStore.load(storePath);
        if (store.contains(username)) {
            throw new IllegalArgumentException("An employee with that username already exists.");
        }

        Input input = new Input();
        char[] password = input.readPassword("New password: ");
        char[] confirmation = input.readPassword("Confirm password: ");
        try {
            if (password.length < 12) {
                throw new IllegalArgumentException("Password must contain at least 12 characters.");
            }
            if (!java.util.Arrays.equals(password, confirmation)) {
                throw new IllegalArgumentException("The passwords do not match.");
            }
            store.add(username, password);
            store.save(storePath);
            System.out.println("Employee record added for " + username + ".");
        } finally {
            java.util.Arrays.fill(password, '\0');
            java.util.Arrays.fill(confirmation, '\0');
        }
    }

    private record EmployeeRecord(int iterations, byte[] salt, byte[] passwordHash) {
    }

    private static final class CredentialStore {
        private final Map<String, EmployeeRecord> records = new HashMap<>();

        static CredentialStore load(Path path) throws IOException {
            CredentialStore store = new CredentialStore();
            if (!Files.exists(path)) {
                return store;
            }

            int lineNumber = 0;
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                lineNumber++;
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.split(":", -1);
                if (fields.length != 4 || !VALID_USERNAME.matcher(fields[0]).matches()) {
                    throw new IOException("Invalid credential record at line " + lineNumber + ".");
                }
                try {
                    int iterations = Integer.parseInt(fields[1]);
                    if (iterations < 100_000) {
                        throw new IllegalArgumentException("iteration count is too low");
                    }
                    byte[] salt = Base64.getDecoder().decode(fields[2]);
                    byte[] hash = Base64.getDecoder().decode(fields[3]);
                    if (salt.length < 16 || hash.length < 32) {
                        throw new IllegalArgumentException("salt or hash is too short");
                    }
                    if (store.records.put(fields[0], new EmployeeRecord(iterations, salt, hash)) != null) {
                        throw new IOException("Duplicate username at line " + lineNumber + ".");
                    }
                } catch (IllegalArgumentException e) {
                    throw new IOException("Invalid credential record at line " + lineNumber + ".", e);
                }
            }
            return store;
        }

        boolean authenticate(String username, char[] password) throws GeneralSecurityException {
            EmployeeRecord record = records.get(username);
            if (record == null) {
                // Perform comparable work even for an unknown user to reduce username timing leaks.
                byte[] dummySalt = new byte[SALT_BYTES];
                hash(password, dummySalt, PBKDF2_ITERATIONS);
                return false;
            }
            byte[] candidate = hash(password, record.salt(), record.iterations());
            return MessageDigest.isEqual(candidate, record.passwordHash());
        }

        void add(String username, char[] password) throws GeneralSecurityException {
            byte[] salt = new byte[SALT_BYTES];
            new SecureRandom().nextBytes(salt);
            records.put(username,
                    new EmployeeRecord(PBKDF2_ITERATIONS, salt,
                            hash(password, salt, PBKDF2_ITERATIONS)));
        }

        void save(Path path) throws IOException {
            Path absolute = path.toAbsolutePath();
            Path parent = absolute.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            List<String> lines = new ArrayList<>();
            lines.add("# username:iterations:base64-salt:base64-pbkdf2-hash");
            records.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> {
                        EmployeeRecord record = entry.getValue();
                        lines.add(entry.getKey() + ":" + record.iterations() + ":"
                                + Base64.getEncoder().encodeToString(record.salt()) + ":"
                                + Base64.getEncoder().encodeToString(record.passwordHash()));
                    });

            Path temporary = Files.createTempFile(parent, ".employees-", ".tmp");
            try {
                Files.write(temporary, lines, StandardCharsets.UTF_8);
                try {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                    Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
        }

        boolean contains(String username) {
            return records.containsKey(username);
        }

        boolean isEmpty() {
            return records.isEmpty();
        }
    }

    private static byte[] hash(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    private static final class Input {
        private final Console console = System.console();
        private final Scanner scanner = console == null ? new Scanner(System.in) : null;

        String readLine(String prompt) {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            return scanner.nextLine();
        }

        char[] readPassword(String prompt) {
            if (console != null) {
                char[] value = console.readPassword("%s", prompt);
                return value == null ? new char[0] : value;
            }
            // Password masking is unavailable when input is redirected or run in some IDEs.
            System.out.print(prompt);
            return scanner.nextLine().toCharArray();
        }
    }
}
