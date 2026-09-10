package com.example.adminportal;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;

/**
 * Dependency-free test harness for the authentication path. Run with:
 * {@code java -cp out com.example.adminportal.AuthenticationTests}
 */
public final class AuthenticationTests {

    private static int failures;

    public static void main(String[] args) throws Exception {
        hashesAreSaltedAndVerifiable();
        malformedHashIsRejected();
        correctCredentialsAreGranted();
        wrongPasswordIsDenied();
        unknownUserIsDeniedWithSameMessage();
        disabledAccountIsDenied();
        usernameIsCaseInsensitive();
        lockoutTriggersAndExpires();
        successResetsFailureCount();
        weakPasswordsAreRejected();
        sessionExpiresWhenIdle();
        roleIsEnforced();
        storeNeverPersistsPlaintext();

        System.out.println(failures == 0
                ? "All tests passed."
                : failures + " test(s) FAILED.");
        System.exit(failures == 0 ? 0 : 1);
    }

    // --- tests ---------------------------------------------------------------

    private static void hashesAreSaltedAndVerifiable() {
        String a = PasswordHasher.hash("Correct-Horse-1!".toCharArray());
        String b = PasswordHasher.hash("Correct-Horse-1!".toCharArray());
        check("same password yields different hashes (salted)", !a.equals(b));
        check("hash verifies", PasswordHasher.verify("Correct-Horse-1!".toCharArray(), a));
        check("wrong password fails", !PasswordHasher.verify("wrong".toCharArray(), a));
    }

    private static void malformedHashIsRejected() {
        check("empty stored hash rejected",
                !PasswordHasher.verify("anything".toCharArray(), ""));
        check("null stored hash rejected",
                !PasswordHasher.verify("anything".toCharArray(), null));
        check("garbage stored hash rejected",
                !PasswordHasher.verify("anything".toCharArray(), "pbkdf2_sha256$x$y$z"));
    }

    private static void correctCredentialsAreGranted() throws Exception {
        Fixture f = Fixture.withUser("root", "S3cure-Passw0rd!", Set.of("ADMIN"));
        AuthenticationResult result = f.auth.authenticate("root", "S3cure-Passw0rd!".toCharArray());
        check("valid credentials granted", result.isGranted());
        check("granted result carries the user",
                result.user().map(u -> u.username().equals("root")).orElse(false));
    }

    private static void wrongPasswordIsDenied() throws Exception {
        Fixture f = Fixture.withUser("root", "S3cure-Passw0rd!", Set.of("ADMIN"));
        AuthenticationResult result = f.auth.authenticate("root", "S3cure-Passw0rd".toCharArray());
        check("wrong password denied", !result.isGranted());
        check("denied result carries no user", result.user().isEmpty());
    }

    private static void unknownUserIsDeniedWithSameMessage() throws Exception {
        Fixture f = Fixture.withUser("root", "S3cure-Passw0rd!", Set.of("ADMIN"));
        String unknown = f.auth.authenticate("nobody", "whatever".toCharArray()).message();
        String wrongPassword = f.auth.authenticate("root", "whatever".toCharArray()).message();
        check("no user enumeration via message text", unknown.equals(wrongPassword));
    }

    private static void disabledAccountIsDenied() throws Exception {
        Fixture f = Fixture.empty();
        String hash = PasswordHasher.hash("S3cure-Passw0rd!".toCharArray());
        Files.writeString(f.storeFile, "off:" + hash + ":ADMIN:false\n");
        Fixture reloaded = f.reload();
        check("disabled account denied",
                !reloaded.auth.authenticate("off", "S3cure-Passw0rd!".toCharArray()).isGranted());
    }

    private static void usernameIsCaseInsensitive() throws Exception {
        Fixture f = Fixture.withUser("Root", "S3cure-Passw0rd!", Set.of("ADMIN"));
        check("username lookup ignores case",
                f.auth.authenticate("ROOT", "S3cure-Passw0rd!".toCharArray()).isGranted());
    }

    private static void lockoutTriggersAndExpires() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-05T12:00:00Z"));
        Fixture f = Fixture.withUser("root", "S3cure-Passw0rd!", Set.of("ADMIN"), clock, 3,
                Duration.ofMinutes(15));
        for (int i = 0; i < 3; i++) {
            f.auth.authenticate("root", "bad".toCharArray());
        }
        AuthenticationResult locked = f.auth.authenticate("root", "S3cure-Passw0rd!".toCharArray());
        check("correct password refused while locked out",
                locked.status() == AuthenticationResult.Status.LOCKED_OUT);

        clock.advance(Duration.ofMinutes(16));
        check("login works once the lockout expires",
                f.auth.authenticate("root", "S3cure-Passw0rd!".toCharArray()).isGranted());
    }

    private static void successResetsFailureCount() throws Exception {
        Fixture f = Fixture.withUser("root", "S3cure-Passw0rd!", Set.of("ADMIN"));
        f.auth.authenticate("root", "bad".toCharArray());
        f.auth.authenticate("root", "bad".toCharArray());
        f.auth.authenticate("root", "S3cure-Passw0rd!".toCharArray());
        check("counter resets after a success", f.auth.remainingAttempts("root") == 5);
    }

    private static void weakPasswordsAreRejected() {
        check("short password rejected",
                !PasswordPolicy.violations("Ab1!".toCharArray()).isEmpty());
        check("no-symbol password rejected",
                !PasswordPolicy.violations("Abcdefgh1234".toCharArray()).isEmpty());
        check("strong password accepted",
                PasswordPolicy.violations("S3cure-Passw0rd!".toCharArray()).isEmpty());
    }

    private static void sessionExpiresWhenIdle() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-05T12:00:00Z"));
        AdminUser user = new AdminUser("root", "x", Set.of("ADMIN"), true);
        AdminSession session =
                new AdminSession(user, clock, Duration.ofMinutes(10), Duration.ofHours(4));
        check("new session is active", session.isActive());
        clock.advance(Duration.ofMinutes(11));
        check("idle session expires", !session.isActive());
    }

    private static void roleIsEnforced() {
        AdminUser user = new AdminUser("root", "x", Set.of("ADMIN"), true);
        AdminSession session = new AdminSession(
                user, Clock.systemUTC(), Duration.ofMinutes(10), Duration.ofHours(4));
        check("held role authorised", session.isAuthorised("ADMIN"));
        check("missing role refused", !session.isAuthorised("SUPER_ADMIN"));
        session.terminate();
        check("terminated session authorises nothing", !session.isAuthorised("ADMIN"));
    }

    private static void storeNeverPersistsPlaintext() throws Exception {
        Fixture f = Fixture.withUser("root", "S3cure-Passw0rd!", Set.of("ADMIN"));
        String contents = Files.readString(f.storeFile);
        check("plaintext password absent from the store file",
                !contents.contains("S3cure-Passw0rd!"));
        check("store holds a PBKDF2 hash", contents.contains("pbkdf2_sha256$"));
    }

    // --- helpers -------------------------------------------------------------

    private static void check(String description, boolean condition) {
        System.out.println((condition ? "PASS  " : "FAIL  ") + description);
        if (!condition) {
            failures++;
        }
    }

    private static final class Fixture {
        private final Path storeFile;
        private final Path auditFile;
        private final Clock clock;
        private final CredentialStore store;
        private final AuthenticationService auth;

        private Fixture(Path storeFile, Path auditFile, Clock clock, int maxAttempts,
                Duration lockout) throws Exception {
            this.storeFile = storeFile;
            this.auditFile = auditFile;
            this.clock = clock;
            this.store = new CredentialStore(storeFile);
            PrintStream quiet = new PrintStream(PrintStream.nullOutputStream());
            this.auth = new AuthenticationService(
                    store, new AuditLog(auditFile, clock, quiet), clock, maxAttempts, lockout);
        }

        static Fixture empty() throws Exception {
            Path dir = Files.createTempDirectory("adminportal-test");
            dir.toFile().deleteOnExit();
            return new Fixture(dir.resolve("users.txt"), dir.resolve("audit.log"),
                    Clock.systemUTC(), 5, Duration.ofMinutes(15));
        }

        static Fixture withUser(String username, String password, Set<String> roles)
                throws Exception {
            return withUser(username, password, roles, Clock.systemUTC(), 5,
                    Duration.ofMinutes(15));
        }

        static Fixture withUser(String username, String password, Set<String> roles, Clock clock,
                int maxAttempts, Duration lockout) throws Exception {
            Path dir = Files.createTempDirectory("adminportal-test");
            dir.toFile().deleteOnExit();
            Fixture f = new Fixture(dir.resolve("users.txt"), dir.resolve("audit.log"), clock,
                    maxAttempts, lockout);
            f.store.addUser(username, password.toCharArray(), roles);
            return f;
        }

        Fixture reload() throws Exception {
            return new Fixture(storeFile, auditFile, clock, 5, Duration.ofMinutes(15));
        }
    }

    /** Clock that can be moved forward, so lockout and session expiry are testable. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
