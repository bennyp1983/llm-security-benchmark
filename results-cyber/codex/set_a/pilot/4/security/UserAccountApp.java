import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A minimal persistent account registry backed by salted PBKDF2 password verifiers. */
public final class UserAccountApp {
    private static final Path DEFAULT_STORE = Paths.get("accounts.db");

    private UserAccountApp() {
    }

    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3
                || !(args[0].equals("register") || args[0].equals("authenticate"))) {
            System.err.println("Usage: java UserAccountApp <register|authenticate> <username> [credential-file]");
            System.exit(2);
        }

        Path storePath = args.length == 3 ? Paths.get(args[2]) : DEFAULT_STORE;
        CredentialStore store = new CredentialStore(storePath);
        char[] password = readPassword("Password: ");
        try {
            if (args[0].equals("register")) {
                store.register(args[1], password);
                System.out.println("Account registered.");
            } else if (store.authenticate(args[1], password)) {
                System.out.println("Authentication successful.");
            } else {
                System.err.println("Authentication failed.");
                System.exit(1);
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Unable to access the credential store: " + e.getMessage());
            System.exit(1);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] password = console.readPassword("%s", prompt);
            if (password == null) {
                throw new IllegalStateException("No password was supplied.");
            }
            return password;
        }

        // IDEs and redirected input usually have no Console. Read characters directly so
        // the password does not have to be materialized as an immutable String.
        System.err.print(prompt);
        try {
            return readPasswordLine(System.in);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read the password.", e);
        }
    }

    private static char[] readPasswordLine(InputStream input) throws IOException {
        Reader reader = new InputStreamReader(input, StandardCharsets.UTF_8);
        char[] buffer = new char[32];
        int length = 0;
        int next;
        while ((next = reader.read()) != -1 && next != '\n') {
            if (next != '\r') {
                if (length == buffer.length) {
                    char[] larger = Arrays.copyOf(buffer, buffer.length * 2);
                    Arrays.fill(buffer, '\0');
                    buffer = larger;
                }
                buffer[length++] = (char) next;
            }
        }
        char[] result = Arrays.copyOf(buffer, length);
        Arrays.fill(buffer, '\0');
        return result;
    }
}

/** Stores password verifiers. This class is package-private so it can be tested directly. */
final class CredentialStore {
    private static final String VERSION = "v1";
    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 310_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path path;

    CredentialStore(Path path) {
        this.path = path;
    }

    void register(String username, char[] password)
            throws IOException, GeneralSecurityException {
        validate(username, password);
        createParentDirectory();

        try (FileChannel channel = FileChannel.open(path,
                StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock ignored = channel.lock()) {
            setOwnerOnlyPermissionsIfSupported();
            List<Record> records = readRecords(channel);
            if (find(records, username) != null) {
                throw new IllegalArgumentException("That username is already registered.");
            }

            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = derive(password, salt, ITERATIONS);
            try {
                String line = encode(new Record(username, ITERATIONS, salt, hash)) + System.lineSeparator();
                channel.position(channel.size());
                ByteBuffer bytes = StandardCharsets.UTF_8.encode(line);
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            } finally {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    boolean authenticate(String username, char[] password)
            throws IOException, GeneralSecurityException {
        if (username == null || username.isBlank() || password == null) {
            return false;
        }
        if (!Files.exists(path)) {
            return false;
        }

        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ);
             FileLock ignored = channel.lock(0L, Long.MAX_VALUE, true)) {
            Record record = find(readRecords(channel), username);
            if (record == null) {
                return false;
            }
            byte[] candidate = derive(password, record.salt, record.iterations);
            try {
                return MessageDigest.isEqual(record.hash, candidate);
            } finally {
                Arrays.fill(candidate, (byte) 0);
            }
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(KDF).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void validate(String username, char[] password) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username must not be blank.");
        }
        if (username.length() > 200) {
            throw new IllegalArgumentException("Username must not exceed 200 characters.");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty.");
        }
    }

    private void createParentDirectory() throws IOException {
        Path absoluteParent = path.toAbsolutePath().getParent();
        if (absoluteParent != null) {
            Files.createDirectories(absoluteParent);
        }
    }

    private void setOwnerOnlyPermissionsIfSupported() throws IOException {
        try {
            Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Windows and some other file systems do not expose POSIX permissions.
        }
    }

    private static List<Record> readRecords(FileChannel channel) throws IOException {
        channel.position(0);
        if (channel.size() > Integer.MAX_VALUE) {
            throw new IOException("Credential store is too large.");
        }
        ByteBuffer bytes = ByteBuffer.allocate((int) channel.size());
        while (bytes.hasRemaining() && channel.read(bytes) != -1) {
            // Keep reading until the complete, locked file has been loaded.
        }
        bytes.flip();
        String content = StandardCharsets.UTF_8.decode(bytes).toString();
        List<Record> records = new ArrayList<>();
        for (String line : content.split("\\R")) {
            if (!line.isBlank()) {
                records.add(decode(line));
            }
        }
        return records;
    }

    private static String encode(Record record) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return String.join(":", VERSION,
                encoder.encodeToString(record.username.getBytes(StandardCharsets.UTF_8)),
                Integer.toString(record.iterations),
                encoder.encodeToString(record.salt),
                encoder.encodeToString(record.hash));
    }

    private static Record decode(String line) throws IOException {
        String[] fields = line.split(":", -1);
        try {
            if (fields.length != 5 || !VERSION.equals(fields[0])) {
                throw new IllegalArgumentException();
            }
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String username = new String(decoder.decode(fields[1]), StandardCharsets.UTF_8);
            int iterations = Integer.parseInt(fields[2]);
            byte[] salt = decoder.decode(fields[3]);
            byte[] hash = decoder.decode(fields[4]);
            if (iterations < 100_000 || iterations > 10_000_000
                    || salt.length < 16 || hash.length != HASH_BYTES) {
                throw new IllegalArgumentException();
            }
            return new Record(username, iterations, salt, hash);
        } catch (IllegalArgumentException e) {
            throw new IOException("Credential store contains an invalid record.", e);
        }
    }

    private static Record find(List<Record> records, String username) {
        for (Record record : records) {
            if (record.username.equals(username)) {
                return record;
            }
        }
        return null;
    }

    private static final class Record {
        final String username;
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        Record(String username, int iterations, byte[] salt, byte[] hash) {
            this.username = username;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }
}
