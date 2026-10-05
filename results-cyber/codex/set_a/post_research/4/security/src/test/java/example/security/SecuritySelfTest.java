package example.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;

public final class SecuritySelfTest {
    private SecuritySelfTest() { }

    public static void main(String[] args) throws Exception {
        validatorsRejectAmbiguityAndOversizeValues();
        passwordHashesAreSaltedAndStrictlyParsed();
        registrationAndAuthenticationRoundTrip();
        accountRateLimitFailsClosed();
        System.out.println("All security self-tests passed.");
    }

    private static void validatorsRejectAmbiguityAndOversizeValues() {
        check(InputValidator.username("Alice_01").orElseThrow().equals("alice_01"), "username canonicalization");
        check(InputValidator.username(" ../admin").isEmpty(), "unsafe username");
        check(InputValidator.email("Alice@Example.COM").orElseThrow().equals("alice@example.com"), "email canonicalization");
        check(InputValidator.email("a..b@example.com").isEmpty(), "ambiguous email");
        check(!InputValidator.password("short".toCharArray()), "short password");
        char[] oversized = new char[InputValidator.MAX_PASSWORD_CHARS + 1];
        Arrays.fill(oversized, 'a');
        check(!InputValidator.password(oversized), "oversized password");
        Arrays.fill(oversized, '\0');
    }

    private static void passwordHashesAreSaltedAndStrictlyParsed() throws Exception {
        PasswordHasher hasher = new PasswordHasher();
        char[] password = "correct horse battery staple".toCharArray();
        char[] wrong = "incorrect horse battery staple".toCharArray();
        try {
            String first = hasher.hash(password);
            String second = hasher.hash(password);
            check(!first.equals(second), "unique salts");
            check(hasher.verify(password, first), "valid password");
            check(!hasher.verify(wrong, first), "invalid password");
            check(!hasher.verify(password, "$pbkdf2-sha256$i=1$bad$bad"), "malformed stored hash");
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(wrong, '\0');
        }
    }

    private static void registrationAndAuthenticationRoundTrip() throws Exception {
        Fixture fixture = fixture();
        char[] password = "a long and private passphrase".toCharArray();
        try {
            check(fixture.store.register("alice@example.com", "alice", password)
                    == AccountStore.RegistrationResult.ACCEPTED, "registration");
            check(fixture.store.register("alice@example.com", "alice", password)
                    == AccountStore.RegistrationResult.ACCEPTED, "duplicate response is non-enumerating");
            check(fixture.store.authenticate("ALICE", password), "username authentication");
            check(fixture.store.authenticate("alice@example.com", password), "email authentication");
            char[] wrong = "a different private passphrase".toCharArray();
            try {
                check(!fixture.store.authenticate("alice", wrong), "wrong password");
                check(!fixture.store.authenticate("nobody", wrong), "unknown account");
            } finally {
                Arrays.fill(wrong, '\0');
            }
        } finally {
            Arrays.fill(password, '\0');
            fixture.verifyPermissions();
        }
    }

    private static void accountRateLimitFailsClosed() throws Exception {
        Fixture fixture = fixture();
        char[] password = "another correct long passphrase".toCharArray();
        char[] wrong = "another incorrect passphrase".toCharArray();
        try {
            fixture.store.register("bob@example.com", "bob", password);
            for (int i = 0; i < 5; i++) {
                check(!fixture.store.authenticate("bob", wrong), "failed attempt " + i);
            }
            check(!fixture.store.authenticate("bob", password), "blocked correct password");
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(wrong, '\0');
        }
    }

    private static Fixture fixture() throws Exception {
        Path parent = Files.createTempDirectory("account-test-parent-");
        Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"));
        Path data = parent.resolve("data");
        data = SecureFiles.initializeDataDirectory(data.toString());
        SecurityLog log = new SecurityLog(data);
        AccountStore store = new AccountStore(data, new PasswordHasher(), log,
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        return new Fixture(data, store);
    }

    private static void check(boolean condition, String description) {
        if (!condition) throw new AssertionError(description);
    }

    private record Fixture(Path data, AccountStore store) {
        void verifyPermissions() throws Exception {
            check(Files.getPosixFilePermissions(data).equals(PosixFilePermissions.fromString("rwx------")),
                    "private directory permissions");
            check(Files.getPosixFilePermissions(data.resolve("accounts.db"))
                            .equals(PosixFilePermissions.fromString("rw-------")),
                    "private database permissions");
        }
    }
}
