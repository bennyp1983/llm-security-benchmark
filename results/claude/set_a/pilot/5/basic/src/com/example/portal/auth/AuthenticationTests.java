package com.example.portal.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * Dependency-free test suite: {@code java com.example.portal.auth.AuthenticationTests}.
 * Exits non-zero if any check fails.
 */
public final class AuthenticationTests {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        hashingRoundTrip();
        wrongPasswordRejected();
        unknownUserRejected();
        inactiveAccountRejected();
        usernameIsCaseInsensitive();
        lockoutAfterRepeatedFailures();
        lockoutExpires();
        successResetsFailureCount();
        storeSurvivesReload();
        policyRejectsWeakPasswords();
        failureMessagesAreIndistinguishable();

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void hashingRoundTrip() {
        String hash = PasswordHasher.hash("correct horse battery".toCharArray());
        check("hash verifies", PasswordHasher.verify("correct horse battery".toCharArray(), hash));
        check("hash is salted",
                !hash.equals(PasswordHasher.hash("correct horse battery".toCharArray())));
        check("plaintext absent from hash", !hash.contains("correct"));
        check("malformed hash rejected", !PasswordHasher.verify("x".toCharArray(), "not-a-hash"));
        check("null hash rejected", !PasswordHasher.verify("x".toCharArray(), null));
    }

    private static void wrongPasswordRejected() throws IOException {
        AuthenticationService service = fixture();
        AuthenticationResult r = service.authenticate("jdoe", "wrong-password".toCharArray());
        check("wrong password denied",
                r.status() == AuthenticationResult.Status.INVALID_CREDENTIALS && !r.granted());
        check("no employee leaked on failure", r.employee().isEmpty());
    }

    private static void unknownUserRejected() throws IOException {
        AuthenticationResult r = fixture().authenticate("ghost", "Sunset-Ledger-88".toCharArray());
        check("unknown user denied",
                r.status() == AuthenticationResult.Status.INVALID_CREDENTIALS);
    }

    private static void inactiveAccountRejected() throws IOException {
        AuthenticationResult r = fixture().authenticate("rleaver", "Retired-Badge-2019".toCharArray());
        check("inactive account denied",
                r.status() == AuthenticationResult.Status.ACCOUNT_INACTIVE && !r.granted());
    }

    private static void usernameIsCaseInsensitive() throws IOException {
        AuthenticationResult r = fixture().authenticate("  JDoe  ", "Sunset-Ledger-88".toCharArray());
        check("username normalized", r.granted());
        check("employee returned on success",
                r.employee().map(EmployeeRecord::username).orElse("").equals("jdoe"));
    }

    private static void lockoutAfterRepeatedFailures() throws IOException {
        AuthenticationService service = fixture();
        for (int i = 0; i < AuthenticationService.MAX_FAILED_ATTEMPTS; i++) {
            service.authenticate("jdoe", "wrong".toCharArray());
        }
        AuthenticationResult r = service.authenticate("jdoe", "Sunset-Ledger-88".toCharArray());
        check("locked out after " + AuthenticationService.MAX_FAILED_ATTEMPTS + " failures",
                r.status() == AuthenticationResult.Status.LOCKED_OUT);
        check("correct password still refused while locked", !r.granted());
        check("lockout reports remaining time", r.lockoutRemaining().isPresent());
    }

    private static void lockoutExpires() throws IOException {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-05T09:00:00Z"));
        AuthenticationService service = new AuthenticationService(
                seededStore(), AuditLog.none(), clock, Duration.ofMinutes(15));
        for (int i = 0; i < AuthenticationService.MAX_FAILED_ATTEMPTS; i++) {
            service.authenticate("jdoe", "wrong".toCharArray());
        }
        clock.advance(Duration.ofMinutes(16));
        check("lockout lifts after the cooling-off period",
                service.authenticate("jdoe", "Sunset-Ledger-88".toCharArray()).granted());
    }

    private static void successResetsFailureCount() throws IOException {
        AuthenticationService service = fixture();
        for (int i = 0; i < AuthenticationService.MAX_FAILED_ATTEMPTS - 1; i++) {
            service.authenticate("jdoe", "wrong".toCharArray());
        }
        check("success after near-miss run",
                service.authenticate("jdoe", "Sunset-Ledger-88".toCharArray()).granted());
        service.authenticate("jdoe", "wrong".toCharArray());
        check("counter reset by success",
                service.authenticate("jdoe", "Sunset-Ledger-88".toCharArray()).granted());
    }

    private static void storeSurvivesReload() throws IOException {
        Path file = Files.createTempDirectory("portal-test").resolve("employees.tsv");
        CredentialStore store = new FileCredentialStore(file);
        new AuthenticationService(store, AuditLog.none())
                .register("nwriter", "Ledger-Persist-42".toCharArray(), "N. Writer", "clerk", true);

        CredentialStore reloaded = new FileCredentialStore(file);
        check("record persisted", reloaded.size() == 1);
        check("reloaded record authenticates",
                new AuthenticationService(reloaded, AuditLog.none())
                        .authenticate("nwriter", "Ledger-Persist-42".toCharArray()).granted());
        check("file holds no plaintext",
                !Files.readString(file).contains("Ledger-Persist-42"));
    }

    private static void policyRejectsWeakPasswords() throws IOException {
        AuthenticationService service = fixture();
        check("short password rejected",
                rejects(service, "newbie", "short".toCharArray()));
        check("common password rejected",
                rejects(service, "newbie", "password".toCharArray()));
        check("password containing username rejected",
                rejects(service, "newbie", "newbie-newbie-1".toCharArray()));
        check("blank username rejected",
                rejects(service, "   ", "Perfectly-Fine-99".toCharArray()));
    }

    private static void failureMessagesAreIndistinguishable() throws IOException {
        AuthenticationService service = fixture();
        String unknown = service.authenticate("ghost", "whatever-1234".toCharArray()).userMessage();
        String badPassword = service.authenticate("jdoe", "whatever-1234".toCharArray()).userMessage();
        String inactive = service.authenticate("rleaver", "Retired-Badge-2019".toCharArray())
                .userMessage();
        check("unknown user and bad password look identical", unknown.equals(badPassword));
        check("inactive account looks identical too", unknown.equals(inactive));
    }

    private static boolean rejects(AuthenticationService service, String user, char[] password) {
        try {
            service.register(user, password, "New Bie", "employee", true);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static AuthenticationService fixture() throws IOException {
        return new AuthenticationService(seededStore(), AuditLog.none());
    }

    /** Two employees: one active, one deactivated. */
    private static CredentialStore seededStore() throws IOException {
        Path file = Files.createTempDirectory("portal-test").resolve("employees.tsv");
        CredentialStore store = new FileCredentialStore(file);
        store.save(new EmployeeRecord("jdoe",
                PasswordHasher.hash("Sunset-Ledger-88".toCharArray()), "Jane Doe", "analyst", true));
        store.save(new EmployeeRecord("rleaver",
                PasswordHasher.hash("Retired-Badge-2019".toCharArray()), "R. Leaver", "analyst", false));
        return store;
    }

    private static void check(String name, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  ok   " + name);
        } else {
            failed++;
            System.out.println("  FAIL " + name);
        }
    }

    /** A clock the tests can move forward to exercise lockout expiry. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration amount) {
            now = now.plus(amount);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
