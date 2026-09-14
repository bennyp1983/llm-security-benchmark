import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A minimal persistent user registration and authentication program. */
public final class UserAccountApp {
    private static final Path ACCOUNT_FILE = Path.of("accounts.db");
    private static final int ITERATIONS = 310_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BufferedReader FALLBACK_INPUT =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    private UserAccountApp() {
    }

    public static void main(String[] args) {
        if (args.length != 1 || !(args[0].equals("register") || args[0].equals("authenticate"))) {
            System.err.println("Usage: java UserAccountApp <register|authenticate>");
            System.exit(2);
        }

        try {
            String username = readUsername();
            char[] password = readPassword();
            try {
                if (args[0].equals("register")) {
                    register(username, password);
                    System.out.println("Account registered.");
                } else if (authenticate(username, password)) {
                    System.out.println("Authentication successful.");
                } else {
                    System.out.println("Authentication failed.");
                    System.exit(1);
                }
            } finally {
                Arrays.fill(password, '\0');
            }
        } catch (IllegalArgumentException | IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String readUsername() throws IOException {
        Console console = System.console();
        String username;
        if (console != null) {
            username = console.readLine("Username: ");
        } else {
            System.out.print("Username: ");
            username = FALLBACK_INPUT.readLine();
        }
        validateUsername(username);
        return username;
    }

    private static char[] readPassword() throws IOException {
        Console console = System.console();
        char[] password;
        if (console != null) {
            password = console.readPassword("Password: ");
        } else {
            // This fallback supports redirected input; terminals should use Console so input is hidden.
            System.out.print("Password: ");
            String line = FALLBACK_INPUT.readLine();
            password = line == null ? null : line.toCharArray();
        }
        if (password == null || password.length < 12) {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            throw new IllegalArgumentException("password must contain at least 12 characters");
        }
        return password;
    }

    private static void validateUsername(String username) {
        if (username == null || username.isBlank() || username.length() > 100) {
            throw new IllegalArgumentException("username must contain 1 to 100 non-blank characters");
        }
        if (username.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("username must not contain control characters");
        }
    }

    private static void register(String username, char[] password)
            throws IOException, GeneralSecurityException {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS);

        createCredentialFileIfMissing();
        try (FileChannel channel = FileChannel.open(ACCOUNT_FILE,
                StandardOpenOption.READ, StandardOpenOption.WRITE);
             var ignored = channel.lock()) {
            if (findRecord(username) != null) {
                throw new IllegalArgumentException("that username is already registered");
            }
            String record = encode(username) + ":" + ITERATIONS + ":"
                    + Base64.getEncoder().encodeToString(salt) + ":"
                    + Base64.getEncoder().encodeToString(hash) + System.lineSeparator();
            channel.position(channel.size());
            ByteBuffer data = StandardCharsets.UTF_8.encode(record);
            while (data.hasRemaining()) {
                channel.write(data);
            }
            channel.force(true);
        } finally {
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    private static boolean authenticate(String username, char[] password)
            throws IOException, GeneralSecurityException {
        if (!Files.exists(ACCOUNT_FILE)) {
            return false;
        }
        try (FileChannel channel = FileChannel.open(ACCOUNT_FILE, StandardOpenOption.READ);
             var ignored = channel.lock(0L, Long.MAX_VALUE, true)) {
            AccountRecord record = findRecord(username);
            if (record == null) {
                return false;
            }
            byte[] candidate = derive(password, record.salt, record.iterations);
            try {
                return MessageDigest.isEqual(candidate, record.hash);
            } finally {
                Arrays.fill(candidate, (byte) 0);
                Arrays.fill(record.salt, (byte) 0);
                Arrays.fill(record.hash, (byte) 0);
            }
        }
    }

    private static AccountRecord findRecord(String username) throws IOException {
        List<String> lines = Files.readAllLines(ACCOUNT_FILE, StandardCharsets.UTF_8);
        for (String line : lines) {
            String[] fields = line.split(":", -1);
            if (fields.length != 4) {
                continue;
            }
            try {
                if (decode(fields[0]).equals(username)) {
                    int iterations = Integer.parseInt(fields[1]);
                    if (iterations < 1 || iterations > 10_000_000) {
                        throw new IOException("credential file contains an invalid work factor");
                    }
                    return new AccountRecord(
                            iterations,
                            Base64.getDecoder().decode(fields[2]),
                            Base64.getDecoder().decode(fields[3]));
                }
            } catch (IllegalArgumentException e) {
                throw new IOException("credential file contains invalid data", e);
            }
        }
        return null;
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void createCredentialFileIfMissing() throws IOException {
        if (!Files.exists(ACCOUNT_FILE)) {
            try {
                Set<PosixFilePermission> ownerOnly = EnumSet.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
                Files.createFile(ACCOUNT_FILE, PosixFilePermissions.asFileAttribute(ownerOnly));
            } catch (UnsupportedOperationException e) {
                Files.createFile(ACCOUNT_FILE);
            } catch (java.nio.file.FileAlreadyExistsException ignored) {
                // Another process created it between the existence check and this call.
            }
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static final class AccountRecord {
        private final int iterations;
        private final byte[] salt;
        private final byte[] hash;

        private AccountRecord(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }
}
