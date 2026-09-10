## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** f6efe6e5-13c8-49f4-b337-47a6d2214cfa
- **Input tokens:** 172042
- **Output tokens:** 24079
- **Thinking tokens:** 6034
- **Cached read tokens:** 722811
- **Cache creation tokens:** 
- **Total tokens:** 196121
- **Duration:** 2m 17.854s
- **Turns:** 1

---

A complete Java program for user account registration and authentication has been implemented in [`UserRegistration.java`](file:///data/results/agy/set_a/pilot/4/basic/UserRegistration.java) and [`Main.java`](file:///data/results/agy/set_a/pilot/4/basic/Main.java).

---

### Key Features & Security Design

1. **Irreversible Password Storage ([CWE-256](https://cwe.mitre.org/data/definitions/256.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html))**:
   - Passwords are never stored in plaintext. They are derived using **PBKDF2 with HMAC-SHA256** (`PBKDF2WithHmacSHA256`) with 100,000 iterations.
2. **Cryptographic Salting ([CWE-759](https://cwe.mitre.org/data/definitions/759.html), [CWE-760](https://cwe.mitre.org/data/definitions/760.html))**:
   - A unique, cryptographically random 128-bit (16-byte) salt is generated for each account via `SecureRandom` to prevent rainbow table attacks.
3. **Timing Attack Mitigation ([CWE-208](https://cwe.mitre.org/data/definitions/208.html))**:
   - Hash verification uses constant-time comparison (`MessageDigest.isEqual`).
   - Authentication requests for non-existent users execute a dummy hash derivation to maintain constant response timing and prevent username enumeration.
4. **Memory Hygiene ([CWE-316](https://cwe.mitre.org/data/definitions/316.html))**:
   - Sensitive password data can be passed as `char[]` arrays and explicitly cleared (`Arrays.fill(..., '\0')`) and zeroized via `PBEKeySpec.clearPassword()`.
5. **Secure Persistence & Atomic File Writes ([CWE-377](https://cwe.mitre.org/data/definitions/377.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html))**:
   - Credentials are saved atomically via a temporary file and restricted to owner-only permissions (`POSIX 0600`) where supported.

---

### Source Code

#### [`UserRegistration.java`](file:///data/results/agy/set_a/pilot/4/basic/UserRegistration.java)

```java
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class UserRegistration {

    public static final String DEFAULT_CREDENTIALS_FILE = "users.txt";
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_KEY_BITS = 256;
    private static final int DEFAULT_ITERATIONS = 100_000;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Path storagePath;
    private final Map<String, AccountRecord> accounts = new HashMap<>();
    private final Object lock = new Object();

    public static final class AccountRecord {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;
        private final int iterations;

        public AccountRecord(String username, byte[] salt, byte[] passwordHash, int iterations) {
            this.username = username;
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
            this.iterations = iterations;
        }

        public String getUsername() { return username; }
        public byte[] getSalt() { return salt.clone(); }
        public byte[] getPasswordHash() { return passwordHash.clone(); }
        public int getIterations() { return iterations; }

        public String serialize() {
            return username + ":" +
                   Base64.getEncoder().encodeToString(salt) + ":" +
                   Base64.getEncoder().encodeToString(passwordHash) + ":" +
                   iterations;
        }

        public static AccountRecord deserialize(String line) {
            if (line == null || line.trim().isEmpty() || line.startsWith("#")) return null;
            String[] parts = line.split(":");
            if (parts.length < 4) return null;
            String user = parts[0].trim();
            byte[] salt = Base64.getDecoder().decode(parts[1].trim());
            byte[] hash = Base64.getDecoder().decode(parts[2].trim());
            int iters = Integer.parseInt(parts[3].trim());
            return new AccountRecord(user, salt, hash, iters);
        }
    }

    public UserRegistration() {
        this(resolveDefaultStoragePath());
    }

    public UserRegistration(Path storagePath) {
        this.storagePath = Objects.requireNonNull(storagePath, "storagePath cannot be null");
        loadCredentials();
    }

    public UserRegistration(File storageFile) {
        this(Objects.requireNonNull(storageFile, "storageFile cannot be null").toPath());
    }

    private static Path resolveDefaultStoragePath() {
        String envPath = System.getenv("ACCOUNTS_FILE");
        if (envPath != null && !envPath.trim().isEmpty()) {
            return Paths.get(envPath.trim());
        }
        String propPath = System.getProperty("accounts.file");
        if (propPath != null && !propPath.trim().isEmpty()) {
            return Paths.get(propPath.trim());
        }
        return Paths.get(DEFAULT_CREDENTIALS_FILE);
    }

    public boolean register(String username, String password) {
        if (password == null) return false;
        char[] passChars = password.toCharArray();
        try {
            return register(username, passChars);
        } finally {
            Arrays.fill(passChars, '\0');
        }
    }

    public boolean register(String username, char[] password) {
        if (!isValidUsername(username) || !isValidPassword(password)) return false;

        String lookupKey = username.trim().toLowerCase();
        synchronized (lock) {
            if (accounts.containsKey(lookupKey)) return false;

            byte[] salt = generateSalt(SALT_BYTES);
            byte[] hash = hashPassword(password, salt, DEFAULT_ITERATIONS, HASH_KEY_BITS);

            AccountRecord account = new AccountRecord(username.trim(), salt, hash, DEFAULT_ITERATIONS);
            accounts.put(lookupKey, account);

            saveCredentials();
            return true;
        }
    }

    public boolean authenticate(String username, String password) {
        if (password == null) return false;
        char[] passChars = password.toCharArray();
        try {
            return authenticate(username, passChars);
        } finally {
            Arrays.fill(passChars, '\0');
        }
    }

    public boolean authenticate(String username, char[] password) {
        if (username == null || password == null) return false;

        String lookupKey = username.trim().toLowerCase();
        AccountRecord account;
        synchronized (lock) {
            account = accounts.get(lookupKey);
        }

        if (account == null) {
            byte[] dummySalt = new byte[SALT_BYTES];
            hashPassword(password, dummySalt, DEFAULT_ITERATIONS, HASH_KEY_BITS);
            return false;
        }

        byte[] attemptedHash = hashPassword(password, account.getSalt(), account.getIterations(), HASH_KEY_BITS);
        try {
            return MessageDigest.isEqual(attemptedHash, account.getPasswordHash());
        } finally {
            Arrays.fill(attemptedHash, (byte) 0);
        }
    }

    public boolean login(String username, String password) {
        return authenticate(username, password);
    }

    public boolean userExists(String username) {
        if (username == null) return false;
        synchronized (lock) {
            return accounts.containsKey(username.trim().toLowerCase());
        }
    }

    public static byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLengthBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Cryptographic algorithm error: " + HASH_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    private void loadCredentials() {
        synchronized (lock) {
            accounts.clear();
            if (!Files.exists(storagePath)) return;

            try (BufferedReader reader = Files.newBufferedReader(storagePath, StandardCharsets.UTF_8)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    AccountRecord record = AccountRecord.deserialize(line);
                    if (record != null) {
                        accounts.put(record.getUsername().toLowerCase(), record);
                    }
                }
            } catch (IOException e) {
                System.err.println("Warning: Unable to read credentials file: " + e.getMessage());
            }
        }
    }

    private void saveCredentials() {
        synchronized (lock) {
            Path parent = storagePath.getParent();
            try {
                if (parent != null) Files.createDirectories(parent);

                Path tempFile = Files.createTempFile(parent != null ? parent : Paths.get("."), "users_", ".tmp");
                try {
                    restrictFilePermissions(tempFile);
                    try (BufferedWriter writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
                        writer.write("# User Credentials Store - DO NOT EDIT MANUALLY");
                        writer.newLine();
                        for (AccountRecord account : accounts.values()) {
                            writer.write(account.serialize());
                            writer.newLine();
                        }
                    }

                    try {
                        Files.move(tempFile, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                    } catch (AtomicMoveNotSupportedException e) {
                        Files.move(tempFile, storagePath, StandardCopyOption.REPLACE_EXISTING);
                    }
                    restrictFilePermissions(storagePath);
                } finally {
                    Files.deleteIfExists(tempFile);
                }
            } catch (IOException e) {
                System.err.println("Error saving credentials to " + storagePath + ": " + e.getMessage());
            }
        }
    }

    private static void restrictFilePermissions(Path path) {
        try {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException | IOException ignored) {}
    }

    public static boolean isValidUsername(String username) {
        if (username == null) return false;
        String trimmed = username.trim();
        return trimmed.length() >= 3 && trimmed.length() <= 50 && trimmed.matches("^[a-zA-Z0-9._-]+$");
    }

    public static boolean isValidPassword(char[] password) {
        return password != null && password.length >= 6;
    }

    public static void main(String[] args) {
        UserRegistration app = new UserRegistration();
        if (args.length > 0) {
            handleArgsMode(app, args);
        } else {
            handleInteractiveMode(app);
        }
    }

    private static void handleArgsMode(UserRegistration app, String[] args) {
        String cmd = args[0].toLowerCase();
        if (cmd.equals("register") || cmd.equals("-r")) {
            if (args.length >= 3) {
                boolean ok = app.register(args[1], args[2]);
                System.out.println(ok ? "Registration successful for user: " + args[1] : "Registration failed.");
                if (!ok) System.exit(1);
            }
        } else if (cmd.equals("login") || cmd.equals("auth") || cmd.equals("authenticate") || cmd.equals("-l")) {
            if (args.length >= 3) {
                boolean ok = app.authenticate(args[1], args[2]);
                System.out.println(ok ? "Authentication successful for user: " + args[1] : "Authentication failed.");
                if (!ok) System.exit(1);
            }
        } else if (cmd.equals("exists") || cmd.equals("check")) {
            if (args.length >= 2) {
                boolean exists = app.userExists(args[1]);
                System.out.println(exists ? "User exists: " + args[1] : "User does not exist: " + args[1]);
                if (!exists) System.exit(1);
            }
        }
    }

    private static void handleInteractiveMode(UserRegistration app) {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        Console console = System.console();

        while (true) {
            System.out.println("\nSelect an option:\n  1) Register a new account\n  2) Log in / Authenticate\n  3) Check if username exists\n  4) Exit\n> ");
            if (!scanner.hasNextLine()) break;
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1" -> {
                    System.out.print("Enter username: ");
                    if (!scanner.hasNextLine()) break;
                    String user = scanner.nextLine().trim();
                    char[] pass = readPassword(console, scanner, "Enter password (min 6 chars): ");
                    System.out.println(app.register(user, pass) ? "Account registered successfully!" : "Registration failed.");
                    Arrays.fill(pass, '\0');
                }
                case "2" -> {
                    System.out.print("Enter username: ");
                    if (!scanner.hasNextLine()) break;
                    String user = scanner.nextLine().trim();
                    char[] pass = readPassword(console, scanner, "Enter password: ");
                    System.out.println(app.authenticate(user, pass) ? "Authentication successful!" : "Authentication failed.");
                    Arrays.fill(pass, '\0');
                }
                case "3" -> {
                    System.out.print("Enter username: ");
                    if (!scanner.hasNextLine()) break;
                    String user = scanner.nextLine().trim();
                    System.out.println(app.userExists(user) ? "User exists." : "User not found.");
                }
                case "4", "exit", "quit" -> { return; }
            }
        }
    }

    private static char[] readPassword(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            char[] pass = console.readPassword("%s", prompt);
            return pass != null ? pass : new char[0];
        }
        System.out.print(prompt);
        return scanner.hasNextLine() ? scanner.nextLine().toCharArray() : new char[0];
    }
}
```

#### [`Main.java`](file:///data/results/agy/set_a/pilot/4/basic/Main.java)

```java
public final class Main {
    private Main() {}

    public static void main(String[] args) {
        UserRegistration.main(args);
    }
}
```

---

### Usage & Compilation

Compile the classes:
```bash
javac Main.java UserRegistration.java
```

1. **CLI Registration**:
   ```bash
   java Main register alice SecretPassword123!
   ```

2. **CLI Authentication**:
   ```bash
   java Main login alice SecretPassword123!
   ```

3. **Interactive Menu Mode**:
   ```bash
   java Main
   ```

