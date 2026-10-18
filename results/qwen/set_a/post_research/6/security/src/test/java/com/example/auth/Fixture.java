package com.example.auth;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.crypto.spec.SecretKeySpec;

/**
 * Builds private, per-process fixtures for the test suites.
 *
 * <p>Every scratch path is scoped to the JVM pid: two suites sharing one fixed path corrupt each
 * other's accounts and log, which makes a mutation battery report real failures for the wrong
 * reason. The tree is removed by a shutdown hook, so a suite that dies part-way leaves nothing
 * behind.
 */
final class Fixture implements AutoCloseable {

    /**
     * Pepper material, mirrored into the keystore and given to the record serialiser. Exactly 32
     * ASCII characters: the keystore path pads or truncates to this length, so any other length
     * would make the provisioner and the service hash with different keys and every login would
     * fail for a reason unrelated to the guard under test.
     */
    static final char[] PEPPER = "fixture-pepper-value-32-chars-ok".toCharArray();

    /**
     * Passwords shared by no fixture username as a substring, so a future "password must not contain
     * the username" rule cannot silently satisfy a check for some other rule.
     */
    static final String PASSWORD_A = "Fresh-Ingress-21";
    static final String PASSWORD_B = "Another-Ingress-7";
    static final String PASSWORD_C = "Quiet-Witness-44";

    /** A password shorter than the accepted minimum. */
    static final String PASSWORD_SHORT = "Tiny-1";

    static final String USER_ALICE = "alice";
    static final String USER_BOB = "bob";

    private static final int KEY_BYTES = 32;

    final Path root;
    final Path accountsFile;
    final Path logFile;
    final Path keystoreFile;
    final TimeSource.Mutable time;
    private final SecureRandom random = new SecureRandom();

    Fixture(String name) throws IOException {
        this.root = Path.of(System.getProperty("java.io.tmpdir"),
                "auth-suite-" + name + "-" + ProcessHandle.current().pid());
        Check.deleteTree(root);
        Files.createDirectories(root);
        restrict(root, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE));
        this.accountsFile = root.resolve("accounts.pwd");
        this.logFile = root.resolve("auth-events.log");
        this.keystoreFile = root.resolve("pepper.jceks");
        this.time = TimeSource.mutable(1_700_000_000_000L);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> Check.deleteTree(root)));
    }

    /** Writes the keystore with a {@code SecretKeyEntry} holding {@link #PEPPER}. */
    Fixture withKeystore(char[] pepper, char[] storePassword) throws Exception {
        KeyStore store = KeyStore.getInstance("JCEKS");
        store.load(null, null);
        byte[] raw = new String(pepper).getBytes(StandardCharsets.UTF_8);
        store.setKeyEntry(AuthTestKeys.ALIAS, new SecretKeySpec(paddedKey(raw), "AES"), storePassword, null);
        try (OutputStream out = Files.newOutputStream(keystoreFile)) {
            store.store(out, storePassword);
        }
        restrict(keystoreFile, Check.OWNER_ONLY);
        return this;
    }

    private static byte[] paddedKey(byte[] raw) {
        if (raw.length != KEY_BYTES) {
            throw new IllegalStateException("fixture pepper must be exactly " + KEY_BYTES
                    + " ASCII bytes but was " + raw.length);
        }
        return raw.clone();
    }

    /** Writes the credential file with the standard three records. */
    Fixture withStandardAccounts(int iterations) throws Exception {
        writeAccounts(iterations, new String[][] {
                {USER_ALICE, PASSWORD_A},
                {USER_BOB, PASSWORD_B},
                {"carol.wu@example.com", PASSWORD_C},
        });
        return this;
    }

    /**
     * Serialises records for {@code namePasswordPairs} using the real hash path, so tests exercise
     * the same digest construction a deployment would produce out of band. The hashing itself lives
     * in {@link FixtureProvisioner}, in the test tree: the component under test must not ship a way
     * to turn a password into a stored record.
     */
    List<String> serializeRecords(int iterations, String[][] namePasswordPairs) throws AuthException {
        return FixtureProvisioner.records(PEPPER.clone(), iterations, namePasswordPairs);
    }

    byte[] randomSalt() {
        byte[] salt = new byte[PasswordHasher.SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    void writeAccounts(int iterations, String[][] namePasswordPairs) throws Exception {
        List<String> lines = serializeRecords(iterations, namePasswordPairs);
        Files.write(accountsFile, String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        restrict(accountsFile, Check.OWNER_ONLY);
    }

    /** Writes arbitrary text, for the malformed-store cases. */
    void writeAccountsRaw(String content) throws IOException {
        Files.write(accountsFile, content.getBytes(StandardCharsets.UTF_8));
        restrict(accountsFile, Check.OWNER_ONLY);
    }

    void writeAccountsRaw(List<String> lines) throws IOException {
        Files.write(accountsFile, String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        restrict(accountsFile, Check.OWNER_ONLY);
    }

    /** Creates the log file with owner-only permissions without going through the service. */
    Path createLogFileWith(Set<PosixFilePermission> permissions) throws IOException {
        Files.deleteIfExists(logFile);
        Files.createFile(logFile);
        restrict(logFile, permissions);
        return logFile;
    }

    AuthConfig.Builder config(int iterations) {
        return AuthConfig.builder()
                .accountsFile(accountsFile)
                .eventLogFile(logFile)
                .keystoreFile(keystoreFile)
                .keystorePassword(AuthTestKeys.STORE_PASSWORD.clone())
                .passwordEntryAlias(AuthTestKeys.ALIAS)
                .pbkdf2Iterations(iterations)
                .minAcceptedIterations(Math.min(50_000, iterations))
                .accountLockAfter(5)
                .accountLockSeconds(600)
                .sourceWindowSeconds(600)
                .sourceMaxAttempts(200)
                .sourceBlockSeconds(600)
                .sessionTtlSeconds(900)
                .maxActiveSessions(512)
                .maxEvents(2_000)
                .minFreeBytes(1L << 20);
    }

    AuthConfig standardConfig(int iterations) throws InvalidConfigException {
        return config(iterations).build();
    }

    /** Boots the service, writing the keystore and the standard accounts when absent. */
    AuthenticationService buildWithoutAccounts(int iterations) throws Exception {
        withKeystore(PEPPER, AuthTestKeys.STORE_PASSWORD);
        return AuthenticationService.builder()
                .config(standardConfig(iterations))
                .timeSource(time)
                .build();
    }

    AuthenticationService build(int iterations) throws Exception {
        withKeystore(PEPPER, AuthTestKeys.STORE_PASSWORD);
        if (!Files.exists(accountsFile)) {
            withStandardAccounts(iterations);
        }
        return AuthenticationService.builder()
                .config(standardConfig(iterations))
                .timeSource(time)
                .build();
    }

    AuthenticationService.Attempt attempt(String username, String password, String source) {
        return AuthenticationService.Attempt.of(username, password.toCharArray(), source);
    }

    /** Runs one attempt and wipes the caller's password array, as a caller must. */
    AuthResult tryLogin(AuthenticationService service, String username, String password, String source) {
        char[] chars = password.toCharArray();
        try {
            return service.authenticate(AuthenticationService.Attempt.of(username, chars, source));
        } finally {
            Arrays.fill(chars, (char) 0);
        }
    }

    List<String> logLines() throws IOException {
        if (!Files.exists(logFile, LinkOption.NOFOLLOW_LINKS)) {
            return List.of();
        }
        return Files.readAllLines(logFile, StandardCharsets.UTF_8);
    }

    String logText() throws IOException {
        return String.join("\n", logLines());
    }

    static void restrict(Path path, Set<PosixFilePermission> permissions) throws IOException {
        Files.setPosixFilePermissions(path, permissions);
    }

    @Override
    public void close() {
        Check.deleteTree(root);
    }
}

