import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Scanner;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A small command-line administrator portal with PBKDF2 password verification
 * and an append-only authentication audit log.
 */
public final class AdminPortal {
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int MAX_USERNAME_LENGTH = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AdminPortal() {
    }

    public static void main(String[] args) {
        if (args.length == 1 && "--generate-hash".equals(args[0])) {
            generateHashForSetup();
            return;
        }
        if (args.length != 0) {
            System.err.println("Usage: java AdminPortal [--generate-hash]");
            System.exit(2);
        }

        String configuredUsername = System.getenv("ADMIN_USERNAME");
        String configuredPasswordHash = System.getenv("ADMIN_PASSWORD_HASH");
        Path auditPath = Path.of(System.getenv().getOrDefault(
                "ADMIN_AUDIT_LOG", "admin-auth-audit.jsonl"));

        if (configuredUsername == null || configuredUsername.isBlank()
                || configuredPasswordHash == null || configuredPasswordHash.isBlank()) {
            System.err.println("ADMIN_USERNAME and ADMIN_PASSWORD_HASH must be set.");
            System.err.println("See README.md for setup instructions.");
            System.exit(2);
        }

        Credentials supplied = readCredentials();
        if (supplied == null) {
            System.err.println("No credentials were supplied.");
            System.exit(2);
        }

        boolean authenticated = false;
        String reason = "invalid_credentials";
        try {
            if (supplied.username().length() > MAX_USERNAME_LENGTH) {
                reason = "invalid_username";
            } else {
                // Verify the password even when the username is wrong. This reduces
                // useful timing differences between unknown users and bad passwords.
                boolean passwordMatches = verifyPassword(
                        supplied.password(), configuredPasswordHash);
                boolean usernameMatches = MessageDigest.isEqual(
                        supplied.username().getBytes(StandardCharsets.UTF_8),
                        configuredUsername.getBytes(StandardCharsets.UTF_8));
                authenticated = usernameMatches & passwordMatches;
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            reason = "credential_configuration_error";
            System.err.println("The configured password hash is invalid.");
        } finally {
            Arrays.fill(supplied.password(), '\0');
        }

        try {
            appendAuditEvent(auditPath, supplied.username(), authenticated, reason);
        } catch (IOException e) {
            // Authentication is not complete until it has an audit record.
            System.err.println("Access denied: the authentication event could not be recorded.");
            System.exit(1);
        }

        if (!authenticated) {
            System.out.println("Access denied.");
            System.exit(1);
        }

        System.out.println("Access granted. Welcome to the administrator portal.");
        runAdminMenu();
    }

    private static Credentials readCredentials() {
        Console console = System.console();
        if (console != null) {
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return username == null || password == null ? null : new Credentials(username, password);
        }

        // Useful for redirected input and automated execution. A real terminal uses
        // Console.readPassword above so the password is not displayed.
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        System.out.print("Username: ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        String username = scanner.nextLine();
        System.out.print("Password: ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        return new Credentials(username, scanner.nextLine().toCharArray());
    }

    private static void generateHashForSetup() {
        char[] password;
        Console console = System.console();
        if (console != null) {
            password = console.readPassword("New administrator password: ");
        } else {
            Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
            System.out.print("New administrator password: ");
            password = scanner.hasNextLine() ? scanner.nextLine().toCharArray() : null;
        }
        if (password == null || password.length == 0) {
            System.err.println("A non-empty password is required.");
            System.exit(2);
        }

        try {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] derived = deriveKey(password, salt, PBKDF2_ITERATIONS, HASH_BITS);
            Base64.Encoder encoder = Base64.getEncoder();
            System.out.println(PBKDF2_ITERATIONS + ":"
                    + encoder.encodeToString(salt) + ":"
                    + encoder.encodeToString(derived));
            Arrays.fill(derived, (byte) 0);
        } catch (GeneralSecurityException e) {
            System.err.println("This Java runtime does not support PBKDF2-HMAC-SHA256.");
            System.exit(2);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static boolean verifyPassword(char[] candidate, String encoded)
            throws GeneralSecurityException {
        String[] fields = encoded.split(":", -1);
        if (fields.length != 3) {
            throw new IllegalArgumentException("Expected iterations:salt:hash");
        }
        int iterations = Integer.parseInt(fields[0]);
        if (iterations < 100_000 || iterations > 10_000_000) {
            throw new IllegalArgumentException("Unsafe iteration count");
        }
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] salt = decoder.decode(fields[1]);
        byte[] expected = decoder.decode(fields[2]);
        if (salt.length < 16 || expected.length < 32) {
            throw new IllegalArgumentException("Hash is too short");
        }

        byte[] actual = deriveKey(candidate, salt, iterations, expected.length * 8);
        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations, int bits)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void appendAuditEvent(
            Path path, String username, boolean success, String failureReason) throws IOException {
        Path absolutePath = path.toAbsolutePath();
        Path parent = absolutePath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        String event = "{\"timestamp\":\"" + Instant.now()
                + "\",\"username\":\"" + jsonEscape(username)
                + "\",\"result\":\"" + (success ? "SUCCESS" : "FAILURE") + "\""
                + (success ? "" : ",\"reason\":\"" + failureReason + "\"")
                + "}" + System.lineSeparator();

        try (FileChannel channel = FileChannel.open(absolutePath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
             FileLock lock = channel.lock()) {
            if (!lock.isValid()) {
                throw new IOException("Could not lock the audit log");
            }
            ByteBuffer buffer = StandardCharsets.UTF_8.encode(event);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        restrictToOwner(absolutePath);
    }

    private static void restrictToOwner(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Windows and some file systems do not provide POSIX permissions.
        }
    }

    private static String jsonEscape(String value) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (c < 0x20) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else {
                        result.append(c);
                    }
                }
            }
        }
        return result.toString();
    }

    private static void runAdminMenu() {
        System.out.println("Admin functions:");
        System.out.println("  1. View system status");
        System.out.println("  2. Manage users");
        System.out.println("  3. Exit");
        // These are placeholders for protected functions. Every call to a real
        // admin service should remain below the successful authentication check.
    }

    private record Credentials(String username, char[] password) {
    }
}
