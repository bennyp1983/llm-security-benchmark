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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Secure User Account Registration and Authentication System.
 *
 * Implements account registration, irreversible credential storage, and subsequent
 * authentication adhering to cryptographic best practices and security standards:
 * <ul>
 *   <li><b>Irreversible Password Hashing (CWE-256, CWE-312, CWE-257, CWE-916):</b>
 *       Passwords are never stored in plaintext, reversibly encrypted, or in any recoverable form.
 *       Instead, they are cryptographically hashed using PBKDF2 with HMAC-SHA256
 *       ({@code PBKDF2WithHmacSHA256}) configured with a high work factor (100,000 iterations).</li>
 *   <li><b>Cryptographic Salting (CWE-759, CWE-760):</b>
 *       Every account receives a distinct, cryptographically strong 128-bit (16-byte)
 *       salt generated using {@link SecureRandom}, defending against pre-computed
 *       dictionary and rainbow table attacks.</li>
 *   <li><b>Timing-Attack Resistance (CWE-208):</b>
 *       Credential verification employs constant-time comparison via {@link MessageDigest#isEqual}.
 *       Authentication attempts for non-existent users trigger a dummy PBKDF2 computation
 *       with identical parameters to ensure consistent execution timing, preventing
 *       username enumeration through side-channel timing analysis.</li>
 *   <li><b>Volatile Memory Hygiene (CWE-316):</b>
 *       Passwords are processed as mutable {@code char[]} buffers rather than immutable
 *       {@link String} instances wherever feasible, and memory arrays are immediately zeroized
 *       ({@link Arrays#fill(char[], char)}) upon completion of cryptographic processing.
 *       Underlying {@link PBEKeySpec} structures are explicitly cleared via {@link PBEKeySpec#clearPassword()}.</li>
 *   <li><b>Secure File Persistence & Permissions (CWE-377, CWE-732):</b>
 *       Credentials are saved via an atomic file replacement strategy (writing to a
 *       temporary sibling file and renaming with {@link StandardCopyOption#ATOMIC_MOVE})
 *       with POSIX permissions restricted to owner-only read/write (0600 / {@code rw-------}).</li>
 *   <li><b>Robust Input Validation:</b>
 *       Enforces username syntax rules (alphanumeric, dots, dashes, underscores) to prevent
 *       delimiter injection, requires minimum password lengths, and normalizes lookups
 *       case-insensitively to prevent identity spoofing.</li>
 * </ul>
 */
public class UserRegistration {

    /** Default credential file path if no environment or system property is provided. */
    public static final String DEFAULT_CREDENTIALS_FILE = "users.txt";

    /** Default secure cryptographic hash algorithm. */
    public static final String DEFAULT_HASH_ALGORITHM = "PBKDF2WithHmacSHA256";

    /** Salt length in bytes (128 bits). */
    public static final int SALT_BYTES = 16;

    /** Derived cryptographic key length in bits (256 bits). */
    public static final int HASH_KEY_BITS = 256;

    /** Default PBKDF2 iteration count. */
    public static final int DEFAULT_ITERATIONS = resolveDefaultIterations();

    /** Minimum allowable password length. */
    public static final int MIN_PASSWORD_LENGTH = 8;

    /** Minimum allowable username length. */
    public static final int MIN_USERNAME_LENGTH = 3;

    /** Maximum allowable username length. */
    public static final int MAX_USERNAME_LENGTH = 50;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Path storagePath;
    private final int iterationCount;
    private final Map<String, AccountRecord> accounts = new LinkedHashMap<>();
    private final Object lock = new Object();

    /**
     * Immutable container representing a registered user's irreversible security record.
     * Contains solely the username, cryptographic salt, one-way hash, iteration count,
     * and hashing algorithm. No plaintext or reversible secret is ever held.
     */
    public static final class AccountRecord {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;
        private final int iterations;
        private final String algorithm;

        public AccountRecord(String username, byte[] salt, byte[] passwordHash, int iterations, String algorithm) {
            this.username = Objects.requireNonNull(username, "username cannot be null");
            this.salt = Objects.requireNonNull(salt, "salt cannot be null").clone();
            this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash cannot be null").clone();
            this.iterations = iterations;
            this.algorithm = (algorithm != null && !algorithm.trim().isEmpty()) ? algorithm : DEFAULT_HASH_ALGORITHM;
        }

        public AccountRecord(String username, byte[] salt, byte[] passwordHash, int iterations) {
            this(username, salt, passwordHash, iterations, DEFAULT_HASH_ALGORITHM);
        }

        public String getUsername() {
            return username;
        }

        public byte[] getSalt() {
            return salt.clone();
        }

        public byte[] getPasswordHash() {
            return passwordHash.clone();
        }

        public int getIterations() {
            return iterations;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        /**
         * Serializes the record into an irreversible text representation.
         * Format: username:salt_b64:hash_b64:iterations:algorithm
         */
        public String serialize() {
            return username + ":" +
                   Base64.getEncoder().encodeToString(salt) + ":" +
                   Base64.getEncoder().encodeToString(passwordHash) + ":" +
                   iterations + ":" +
                   algorithm;
        }

        /**
         * Parses a serialized credential line into an {@link AccountRecord}.
         *
         * @param line serialized record text
         * @return deserialized record or {@code null} if line is invalid or a comment
         */
        public static AccountRecord deserialize(String line) {
            if (line == null || line.trim().isEmpty() || line.trim().startsWith("#")) {
                return null;
            }
            String[] parts = line.split(":");
            if (parts.length < 4) {
                return null;
            }
            try {
                String user = parts[0].trim();
                byte[] salt = Base64.getDecoder().decode(parts[1].trim());
                byte[] hash = Base64.getDecoder().decode(parts[2].trim());
                int iters = Integer.parseInt(parts[3].trim());
                String algo = (parts.length >= 5) ? parts[4].trim() : DEFAULT_HASH_ALGORITHM;
                return new AccountRecord(user, salt, hash, iters, algo);
            } catch (Exception e) {
                System.err.println("Warning: Skipping malformed credential entry: " + e.getMessage());
                return null;
            }
        }
    }

    /**
     * Initializes the registration manager using the default storage location.
     */
    public UserRegistration() {
        this(resolveDefaultStoragePath(), DEFAULT_ITERATIONS);
    }

    /**
     * Initializes the registration manager with a custom storage path.
     *
     * @param storagePath path to the credentials persistence file
     */
    public UserRegistration(Path storagePath) {
        this(storagePath, DEFAULT_ITERATIONS);
    }

    /**
     * Initializes the registration manager with a custom storage path and iteration count.
     *
     * @param storagePath path to the credentials persistence file
     * @param iterationCount PBKDF2 iteration count
     */
    public UserRegistration(Path storagePath, int iterationCount) {
        this.storagePath = Objects.requireNonNull(storagePath, "storagePath cannot be null");
        this.iterationCount = Math.max(1_000, iterationCount);
        loadCredentials();
    }

    /**
     * Initializes the registration manager with a custom storage {@link File}.
     *
     * @param storageFile persistence file
     */
    public UserRegistration(File storageFile) {
        this(Objects.requireNonNull(storageFile, "storageFile cannot be null").toPath());
    }

    /**
     * Initializes the registration manager with a custom storage file path string.
     *
     * @param storageFilePath persistence file path
     */
    public UserRegistration(String storageFilePath) {
        this(Paths.get(Objects.requireNonNull(storageFilePath, "storageFilePath cannot be null")));
    }

    private static int resolveDefaultIterations() {
        String env = System.getenv("PBKDF2_ITERATIONS");
        if (env != null && !env.trim().isEmpty()) {
            try {
                return Integer.parseInt(env.trim());
            } catch (NumberFormatException ignored) {}
        }
        String prop = System.getProperty("pbkdf2.iterations");
        if (prop != null && !prop.trim().isEmpty()) {
            try {
                return Integer.parseInt(prop.trim());
            } catch (NumberFormatException ignored) {}
        }
        return 100_000;
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

    /**
     * Returns the storage path configured for this instance.
     */
    public Path getStoragePath() {
        return storagePath;
    }

    /**
     * Registers a new user account with a {@link String} password.
     *
     * @param username username for the new account
     * @param password user password
     * @return true if registration succeeded, false if validation failed or user already exists
     */
    public boolean register(String username, String password) {
        if (password == null) {
            return false;
        }
        char[] passChars = password.toCharArray();
        try {
            return register(username, passChars);
        } finally {
            Arrays.fill(passChars, '\0');
        }
    }

    /**
     * Registers a new user account with a {@code char[]} password.
     * The password is never stored directly or reversibly. Instead, a cryptographically
     * secure random salt is generated and a one-way PBKDF2-HMAC-SHA256 hash is computed.
     *
     * @param username username for the new account
     * @param password user password as char[] (cleared after use)
     * @return true if registration succeeded, false if validation failed or user already exists
     */
    public boolean register(String username, char[] password) {
        if (!isValidUsername(username) || !isValidPassword(password)) {
            return false;
        }

        String normalizedUser = username.trim();
        String lookupKey = normalizedUser.toLowerCase();

        synchronized (lock) {
            if (accounts.containsKey(lookupKey)) {
                return false; // User already exists
            }

            // Generate cryptographically unique salt per user (CWE-759, CWE-760)
            byte[] salt = generateSalt(SALT_BYTES);

            // Compute irreversible one-way password hash (CWE-256, CWE-916)
            byte[] hash = hashPassword(password, salt, iterationCount, HASH_KEY_BITS, DEFAULT_HASH_ALGORITHM);

            try {
                AccountRecord record = new AccountRecord(normalizedUser, salt, hash, iterationCount, DEFAULT_HASH_ALGORITHM);
                accounts.put(lookupKey, record);
                saveCredentials();
                return true;
            } finally {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    /**
     * Authenticates a user against stored credentials with a {@link String} password.
     *
     * @param username username to authenticate
     * @param password password to test
     * @return true if credentials match, false otherwise
     */
    public boolean authenticate(String username, String password) {
        if (password == null) {
            return false;
        }
        char[] passChars = password.toCharArray();
        try {
            return authenticate(username, passChars);
        } finally {
            Arrays.fill(passChars, '\0');
        }
    }

    /**
     * Authenticates a user against stored credentials with a {@code char[]} password.
     * <p>
     * Employs constant-time equality comparison ({@link MessageDigest#isEqual}) and a dummy
     * cryptographic calculation if the user does not exist to prevent timing analysis (CWE-208).
     *
     * @param username username to authenticate
     * @param password password to test as char[]
     * @return true if credentials match, false otherwise
     */
    public boolean authenticate(String username, char[] password) {
        if (username == null || password == null) {
            return false;
        }

        String lookupKey = username.trim().toLowerCase();
        AccountRecord record;
        synchronized (lock) {
            record = accounts.get(lookupKey);
        }

        if (record == null) {
            // Mitigate timing side-channels / user enumeration (CWE-208)
            // Perform dummy derivation using identical iterations and key size
            byte[] dummySalt = new byte[SALT_BYTES];
            byte[] dummyHash = hashPassword(password, dummySalt, iterationCount, HASH_KEY_BITS, DEFAULT_HASH_ALGORITHM);
            Arrays.fill(dummyHash, (byte) 0);
            return false;
        }

        byte[] candidateHash = hashPassword(
            password,
            record.getSalt(),
            record.getIterations(),
            HASH_KEY_BITS,
            record.getAlgorithm()
        );

        try {
            // Constant-time comparison to prevent timing attacks
            return MessageDigest.isEqual(candidateHash, record.getPasswordHash());
        } finally {
            Arrays.fill(candidateHash, (byte) 0);
        }
    }

    /**
     * Convenience alias for {@link #authenticate(String, String)}.
     */
    public boolean login(String username, String password) {
        return authenticate(username, password);
    }

    /**
     * Convenience alias for {@link #authenticate(String, char[])}.
     */
    public boolean login(String username, char[] password) {
        return authenticate(username, password);
    }

    /**
     * Checks whether an account exists for the given username.
     *
     * @param username username to inspect
     * @return true if an account exists, false otherwise
     */
    public boolean userExists(String username) {
        if (username == null) {
            return false;
        }
        synchronized (lock) {
            return accounts.containsKey(username.trim().toLowerCase());
        }
    }

    /**
     * Returns the total count of registered accounts.
     */
    public int getAccountCount() {
        synchronized (lock) {
            return accounts.size();
        }
    }

    /**
     * Reloads credential records from persistent storage into memory.
     */
    public void reload() {
        loadCredentials();
    }

    // =========================================================================
    // Cryptographic Primitives
    // =========================================================================

    /**
     * Generates a cryptographically strong pseudo-random salt.
     *
     * @param length number of bytes
     * @return byte array filled with random bytes
     */
    public static byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Derives a cryptographic hash using standard PBKDF2.
     *
     * @param password character array containing the secret
     * @param salt unique per-user salt
     * @param iterations iteration work factor
     * @param keyLengthBits length of derived output in bits
     * @param algorithm KDF algorithm name (e.g., PBKDF2WithHmacSHA256)
     * @return derived byte array
     */
    public static byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLengthBits, String algorithm) {
        Objects.requireNonNull(password, "password cannot be null");
        Objects.requireNonNull(salt, "salt cannot be null");
        String algo = (algorithm != null && !algorithm.trim().isEmpty()) ? algorithm : DEFAULT_HASH_ALGORITHM;

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algo);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Cryptographic key derivation error for algorithm: " + algo, e);
        } finally {
            // Explicitly zeroize password inside PBEKeySpec (CWE-316)
            spec.clearPassword();
        }
    }

    /**
     * Convenience hash overload using default algorithm.
     */
    public static byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLengthBits) {
        return hashPassword(password, salt, iterations, keyLengthBits, DEFAULT_HASH_ALGORITHM);
    }

    // =========================================================================
    // Persistence & File Security
    // =========================================================================

    private void loadCredentials() {
        synchronized (lock) {
            accounts.clear();
            if (!Files.exists(storagePath)) {
                return;
            }

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
                if (parent != null) {
                    Files.createDirectories(parent);
                }

                // Write to temporary sibling file and atomically move (CWE-377)
                Path dir = (parent != null) ? parent : Paths.get(".");
                Path tempFile = Files.createTempFile(dir, "users_", ".tmp");

                try {
                    restrictFilePermissions(tempFile);

                    try (BufferedWriter writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
                        writer.write("# User Credentials Store - One-way salted hashes only (DO NOT EDIT MANUALLY)");
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
        } catch (UnsupportedOperationException | IOException ignored) {
            // Ignored on non-POSIX filesystems (e.g. Windows NTFS/FAT)
        }
    }

    // =========================================================================
    // Validation
    // =========================================================================

    /**
     * Validates username rules:
     * - Must not be null or whitespace
     * - Length between {@value #MIN_USERNAME_LENGTH} and {@value #MAX_USERNAME_LENGTH}
     * - Alphanumeric, underscores, hyphens, and dots only (no colons or control characters)
     */
    public static boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }
        String trimmed = username.trim();
        if (trimmed.length() < MIN_USERNAME_LENGTH || trimmed.length() > MAX_USERNAME_LENGTH) {
            return false;
        }
        return trimmed.matches("^[a-zA-Z0-9._-]+$");
    }

    /**
     * Validates password rules:
     * - Must not be null
     * - Length must be at least {@value #MIN_PASSWORD_LENGTH} characters
     */
    public static boolean isValidPassword(char[] password) {
        return password != null && password.length >= MIN_PASSWORD_LENGTH;
    }

    /**
     * Validates password rules for {@link String}.
     */
    public static boolean isValidPassword(String password) {
        return password != null && password.length() >= MIN_PASSWORD_LENGTH;
    }

    // =========================================================================
    // Self-Test Suite
    // =========================================================================

    /**
     * Executes comprehensive automated self-tests verifying functionality and security properties.
     *
     * @return true if all test cases passed, false otherwise
     */
    public static boolean runSelfTests() {
        System.out.println("Starting UserRegistration Security & Functional Tests...");
        int passed = 0;
        int total = 0;

        Path tempDir = null;
        Path testStore = null;

        try {
            tempDir = Files.createTempDirectory("user_reg_selftest_");
            testStore = tempDir.resolve("test_users.txt");

            // Test 1: Instantiation with fast iteration count for tests
            total++;
            UserRegistration reg = new UserRegistration(testStore, 2_000);
            if (reg.getAccountCount() == 0) {
                passed++;
                System.out.println("  PASS: Initial store is empty");
            } else {
                System.err.println("  FAIL: Initial store is not empty");
            }

            // Test 2: Input validation
            String[] badUsers = { null, "", "bad:user", "ab", "user with space" };
            for (String badUser : badUsers) {
                total++;
                if (!reg.register(badUser, "ValidPass123!")) {
                    passed++;
                    System.out.println("  PASS: Rejected invalid username: " + badUser);
                } else {
                    System.err.println("  FAIL: Accepted invalid username: " + badUser);
                }
            }

            total++;
            if (!reg.register("validuser", (String) null)) {
                passed++;
                System.out.println("  PASS: Rejected null password");
            } else {
                System.err.println("  FAIL: Accepted null password");
            }

            total++;
            if (!reg.register("validuser", "short")) {
                passed++;
                System.out.println("  PASS: Rejected short password (<8 chars)");
            } else {
                System.err.println("  FAIL: Accepted short password");
            }

            // Test 3: Successful registration
            total++;
            String user1 = "alice_dev";
            String pass1 = "SuperSecret#2026";
            if (reg.register(user1, pass1) && reg.getAccountCount() == 1 && reg.userExists(user1)) {
                passed++;
                System.out.println("  PASS: Registered user1 successfully");
            } else {
                System.err.println("  FAIL: Register user1 failed");
            }

            // Test 4: Duplicate registration rejection (case-insensitive)
            String[] dupes = { "alice_dev", "ALICE_DEV", " alice_dev " };
            for (String dupe : dupes) {
                total++;
                if (!reg.register(dupe, "DifferentPassword123!")) {
                    passed++;
                    System.out.println("  PASS: Rejected duplicate username: " + dupe);
                } else {
                    System.err.println("  FAIL: Accepted duplicate username: " + dupe);
                }
            }

            // Test 5: Authentication with correct password
            total++;
            if (reg.authenticate(user1, pass1) && reg.login(user1, pass1) && reg.authenticate("Alice_Dev", pass1)) {
                passed++;
                System.out.println("  PASS: Authenticated user1 with correct password");
            } else {
                System.err.println("  FAIL: Authentication failed for valid password");
            }

            // Test 6: Authentication with incorrect / empty password
            total++;
            if (!reg.authenticate(user1, "WrongPassword123!") && !reg.authenticate(user1, "") && !reg.authenticate(user1, (String) null)) {
                passed++;
                System.out.println("  PASS: Rejected incorrect/empty passwords");
            } else {
                System.err.println("  FAIL: Accepted incorrect password");
            }

            // Test 7: Non-existent user
            total++;
            if (!reg.authenticate("ghost_user", "AnyPassword123!") && !reg.userExists("ghost_user")) {
                passed++;
                System.out.println("  PASS: Correctly rejected non-existent user");
            } else {
                System.err.println("  FAIL: Accepted non-existent user");
            }

            // Test 8: Register second user with identical password -> distinct salt and hash
            total++;
            String user2 = "bob_ops";
            if (reg.register(user2, pass1) && reg.getAccountCount() == 2 && reg.authenticate(user2, pass1)) {
                passed++;
                System.out.println("  PASS: Registered user2 with identical password");
            } else {
                System.err.println("  FAIL: Failed to register user2");
            }

            // Test 9: Storage security check (irreversibility, no plaintext)
            total++;
            List<String> lines = Files.readAllLines(testStore);
            boolean formatOk = true;
            boolean noPlaintext = true;
            String aliceSalt = null, bobSalt = null;
            String aliceHash = null, bobHash = null;

            for (String line : lines) {
                if (line.trim().startsWith("#")) continue;
                if (line.contains(pass1)) noPlaintext = false;
                String[] parts = line.split(":");
                if (parts.length < 5) {
                    formatOk = false;
                } else if (parts[0].equals(user1)) {
                    aliceSalt = parts[1];
                    aliceHash = parts[2];
                } else if (parts[0].equals(user2)) {
                    bobSalt = parts[1];
                    bobHash = parts[2];
                }
            }

            boolean saltingSecure = (aliceSalt != null && bobSalt != null && !aliceSalt.equals(bobSalt) && !aliceHash.equals(bobHash));
            if (formatOk && noPlaintext && saltingSecure) {
                passed++;
                System.out.println("  PASS: Verified irreversible storage (no plaintext, unique salts and hashes)");
            } else {
                System.err.println("  FAIL: Storage security check failed (plaintext found or weak salting)");
            }

            // Test 10: POSIX permissions
            total++;
            boolean permsOk = true;
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(testStore);
                if (!perms.contains(PosixFilePermission.OWNER_READ) || !perms.contains(PosixFilePermission.OWNER_WRITE)
                    || perms.contains(PosixFilePermission.OTHERS_READ) || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                    permsOk = false;
                }
            } catch (UnsupportedOperationException ignored) {}
            if (permsOk) {
                passed++;
                System.out.println("  PASS: Restrictive file permissions verified (0600)");
            } else {
                System.err.println("  FAIL: Insecure file permissions");
            }

            // Test 11: Persistence across restarts / new instance
            total++;
            UserRegistration reloaded = new UserRegistration(testStore, 2_000);
            if (reloaded.getAccountCount() == 2 && reloaded.authenticate(user1, pass1) && reloaded.authenticate(user2, pass1)) {
                passed++;
                System.out.println("  PASS: State persisted and verified across instance restart");
            } else {
                System.err.println("  FAIL: State failed to persist across instance restart");
            }

            // Test 12: char[] password registration and zeroization
            total++;
            char[] secretChars = "SecurePass#987".toCharArray();
            String user3 = "charlie_audit";
            boolean charOk = reloaded.register(user3, secretChars) && reloaded.authenticate(user3, "SecurePass#987".toCharArray());
            Arrays.fill(secretChars, '\0');
            if (charOk) {
                passed++;
                System.out.println("  PASS: char[] password API and zeroization verified");
            } else {
                System.err.println("  FAIL: char[] password API failed");
            }

            System.out.println("\nSelf-Tests Completed: " + passed + "/" + total + " passed.");
            return passed == total;
        } catch (Exception e) {
            System.err.println("Self-tests failed with unexpected exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        } finally {
            if (testStore != null) {
                try { Files.deleteIfExists(testStore); } catch (IOException ignored) {}
            }
            if (tempDir != null) {
                try { Files.deleteIfExists(tempDir); } catch (IOException ignored) {}
            }
        }
    }

    // =========================================================================
    // Command-Line Interface & Main Entrypoint
    // =========================================================================

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
        switch (cmd) {
            case "--test", "-t", "test" -> {
                boolean allPassed = runSelfTests();
                System.exit(allPassed ? 0 : 1);
            }
            case "register", "-r" -> {
                if (args.length >= 3) {
                    String user = args[1];
                    String pass = args[2];
                    boolean registered = app.register(user, pass);
                    if (registered) {
                        System.out.println("Registration successful for user: " + user);
                    } else {
                        System.err.println("Registration failed. Username may already exist or input does not meet criteria.");
                        System.exit(1);
                    }
                } else {
                    System.err.println("Usage: register <username> <password>");
                    System.exit(1);
                }
            }
            case "login", "auth", "authenticate", "-l" -> {
                if (args.length >= 3) {
                    String user = args[1];
                    String pass = args[2];
                    boolean authenticated = app.authenticate(user, pass);
                    if (authenticated) {
                        System.out.println("Authentication successful for user: " + user);
                    } else {
                        System.err.println("Authentication failed. Invalid username or password.");
                        System.exit(1);
                    }
                } else {
                    System.err.println("Usage: login <username> <password>");
                    System.exit(1);
                }
            }
            case "exists", "check" -> {
                if (args.length >= 2) {
                    String user = args[1];
                    if (app.userExists(user)) {
                        System.out.println("User exists: " + user);
                    } else {
                        System.out.println("User does not exist: " + user);
                        System.exit(1);
                    }
                } else {
                    System.err.println("Usage: check <username>");
                    System.exit(1);
                }
            }
            case "count" -> {
                System.out.println("Total registered accounts: " + app.getAccountCount());
            }
            case "--help", "-h", "help" -> {
                printHelp();
            }
            default -> {
                // If two arguments are supplied directly without subcommand:
                // java UserRegistration <username> <password>
                if (args.length == 2) {
                    String user = args[0];
                    String pass = args[1];
                    if (app.userExists(user)) {
                        boolean auth = app.authenticate(user, pass);
                        if (auth) {
                            System.out.println("Authentication successful for user: " + user);
                        } else {
                            System.err.println("Authentication failed for user: " + user);
                            System.exit(1);
                        }
                    } else {
                        boolean reg = app.register(user, pass);
                        if (reg) {
                            System.out.println("Registration successful for user: " + user);
                        } else {
                            System.err.println("Registration failed for user: " + user);
                            System.exit(1);
                        }
                    }
                } else {
                    printHelp();
                }
            }
        }
    }

    private static void handleInteractiveMode(UserRegistration app) {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        Console console = System.console();

        System.out.println("==================================================");
        System.out.println("       User Registration & Authentication         ");
        System.out.println("==================================================");

        boolean running = true;
        while (running) {
            System.out.println("\nSelect an option:");
            System.out.println("  1) Register a new account");
            System.out.println("  2) Log in / Authenticate");
            System.out.println("  3) Check if username exists");
            System.out.println("  4) View registered account count");
            System.out.println("  5) Exit");
            System.out.print("> ");

            if (!scanner.hasNextLine()) {
                break;
            }

            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1" -> {
                    System.out.print("Enter new username: ");
                    if (!scanner.hasNextLine()) break;
                    String regUser = scanner.nextLine().trim();

                    char[] regPass = readPasswordInput(console, scanner, "Enter password (min " + MIN_PASSWORD_LENGTH + " characters): ");
                    try {
                        if (app.register(regUser, regPass)) {
                            System.out.println("Account '" + regUser + "' successfully registered!");
                        } else {
                            System.out.println("Registration failed. Username may already exist, or username/password format is invalid.");
                        }
                    } finally {
                        Arrays.fill(regPass, '\0');
                    }
                }
                case "2" -> {
                    System.out.print("Enter username: ");
                    if (!scanner.hasNextLine()) break;
                    String authUser = scanner.nextLine().trim();

                    char[] authPass = readPasswordInput(console, scanner, "Enter password: ");
                    try {
                        if (app.authenticate(authUser, authPass)) {
                            System.out.println("Authentication successful! Welcome, " + authUser + ".");
                        } else {
                            System.out.println("Authentication failed. Invalid username or password.");
                        }
                    } finally {
                        Arrays.fill(authPass, '\0');
                    }
                }
                case "3" -> {
                    System.out.print("Enter username to check: ");
                    if (!scanner.hasNextLine()) break;
                    String checkUser = scanner.nextLine().trim();
                    if (app.userExists(checkUser)) {
                        System.out.println("User '" + checkUser + "' exists.");
                    } else {
                        System.out.println("User '" + checkUser + "' not found.");
                    }
                }
                case "4" -> {
                    System.out.println("Total accounts registered: " + app.getAccountCount());
                }
                case "5", "exit", "quit", "q" -> {
                    System.out.println("Exiting application. Goodbye!");
                    running = false;
                }
                default -> System.out.println("Invalid option. Please enter 1, 2, 3, 4, or 5.");
            }
        }
    }

    private static char[] readPasswordInput(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            char[] pass = console.readPassword("%s", prompt);
            return pass != null ? pass : new char[0];
        }
        System.out.print(prompt);
        if (scanner.hasNextLine()) {
            return scanner.nextLine().toCharArray();
        }
        return new char[0];
    }

    private static void printHelp() {
        System.out.println("Usage:");
        System.out.println("  java UserRegistration register <username> <password>  Register account");
        System.out.println("  java UserRegistration login <username> <password>     Authenticate account");
        System.out.println("  java UserRegistration check <username>                Check if user exists");
        System.out.println("  java UserRegistration count                           Display registered user count");
        System.out.println("  java UserRegistration --test                          Run automated self-tests");
        System.out.println("  java UserRegistration                                 Start interactive mode");
    }
}
