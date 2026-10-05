package com.example.accounts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AccountServiceTest {

    private static final String EMAIL = "alice@example.com";
    private static final String USERNAME = "Alice99";
    private static final String PASSWORD = "pewter-rhubarb-glacier-7";

    private Database database;
    private String jdbcUrl;

    @AfterEach
    void closeDatabase() {
        if (database != null) {
            database.close();
            database = null;
        }
    }

    /** A service whose clock the test controls, so expiry can be exercised without sleeping. */
    private AccountService service(Path dir, MutableClock clock, Map<String, String> overrides)
            throws SQLException {
        Config config = TestSupport.config(dir, overrides);
        jdbcUrl = config.jdbcUrl();
        database = Database.open(config, TestSupport.silentLogger());
        return new AccountService(config, database, TestSupport.silentLogger(), clock);
    }

    private AccountService service(Path dir) throws SQLException {
        return service(dir, new MutableClock(Instant.parse("2026-10-01T12:00:00Z")), Map.of());
    }

    // ---------------------------------------------------------------- registration

    @Test
    void registersAnAccountAndLogsIn(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        assertEquals(AccountService.RegistrationStatus.ACCEPTED,
                service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7"));

        AccountService.AuthResult result =
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7");
        assertEquals(AccountService.AuthStatus.AUTHENTICATED, result.status());
        assertNotNull(result.session());
        assertEquals("Alice99", result.usernameDisplay());
    }

    @Test
    void acceptsLoginByUsernameAndByEmailCaseInsensitively(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        for (String identifier : List.of(EMAIL, "ALICE@EXAMPLE.COM", "alice99", "Alice99")) {
            AccountService.AuthResult result =
                    service.authenticate(identifier, PASSWORD.toCharArray(), "198.51.100.7");
            assertEquals(AccountService.AuthStatus.AUTHENTICATED, result.status(), identifier);
        }
    }

    @Test
    void storesOnlyAnArgon2HashNeverThePassword(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        String stored = queryString("SELECT password_hash FROM account");
        assertTrue(stored.startsWith("$argon2id$v=19$"), stored);
        assertFalse(stored.contains(PASSWORD));

        // And nothing anywhere under the data directory contains the plaintext.
        for (Path file : Files.walk(dir).filter(Files::isRegularFile).toList()) {
            byte[] bytes = Files.readAllBytes(file);
            assertFalse(new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1)
                    .contains(PASSWORD), "plaintext password found in " + file);
        }
    }

    @Test
    void duplicateRegistrationIsIndistinguishableFromSuccess(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        assertEquals(AccountService.RegistrationStatus.ACCEPTED,
                service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7"));
        // Same email, different username: still ACCEPTED, so the caller learns nothing.
        assertEquals(AccountService.RegistrationStatus.ACCEPTED,
                service.register(EMAIL, "bobby7", "hazel-mortar-cobalt-3".toCharArray(),
                        "198.51.100.7"));
        // Same username, different email: likewise.
        assertEquals(AccountService.RegistrationStatus.ACCEPTED,
                service.register("carol@example.com", USERNAME,
                        "hazel-mortar-cobalt-3".toCharArray(), "198.51.100.7"));

        assertEquals(1, queryInt("SELECT COUNT(*) FROM account"));
        // The loser's password was never stored.
        assertTrue(service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7")
                .status() == AccountService.AuthStatus.AUTHENTICATED);
        assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS,
                service.authenticate(EMAIL, "hazel-mortar-cobalt-3".toCharArray(), "198.51.100.7")
                        .status());
    }

    @Test
    void concurrentRegistrationsForOneEmailCreateExactlyOneAccount(@TempDir Path dir)
            throws Exception {
        AccountService service = service(dir, new MutableClock(Instant.now()),
                Map.of("ACCOUNTS_MAX_FAILURES_PER_SOURCE", "1000"));

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        List<Throwable> failures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int index = i;
            Thread t = new Thread(() -> {
                try {
                    start.await();
                    service.register(EMAIL, "racer" + index, PASSWORD.toCharArray(),
                            "198.51.100." + index);
                } catch (Throwable e) {
                    synchronized (failures) {
                        failures.add(e);
                    }
                } finally {
                    done.countDown();
                }
            });
            t.start();
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS), "registration threads did not finish");
        synchronized (failures) {
            assertTrue(failures.isEmpty(), "unexpected failures: " + failures);
        }
        assertEquals(1, queryInt("SELECT COUNT(*) FROM account"));
    }

    @Test
    void rejectsWeakAndMalformedRegistrationInput(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        assertThrows(ValidationException.class,
                () -> service.register("not-an-email", USERNAME, PASSWORD.toCharArray(), "src"));
        assertThrows(ValidationException.class,
                () -> service.register(EMAIL, "admin", PASSWORD.toCharArray(), "src"));
        assertThrows(ValidationException.class,
                () -> service.register(EMAIL, USERNAME, "short".toCharArray(), "src"));
        assertThrows(ValidationException.class,
                () -> service.register(EMAIL, USERNAME, "password1234".toCharArray(), "src"));
        assertEquals(0, queryInt("SELECT COUNT(*) FROM account"));
    }

    // ---------------------------------------------------------------- authentication

    @Test
    void unknownAccountAndWrongPasswordAreIndistinguishable(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        AccountService.AuthResult wrongPassword =
                service.authenticate(EMAIL, "hazel-mortar-cobalt-3".toCharArray(), "198.51.100.7");
        AccountService.AuthResult unknownAccount =
                service.authenticate("nobody@example.com", PASSWORD.toCharArray(), "198.51.100.8");
        AccountService.AuthResult nonsenseIdentifier =
                service.authenticate("!!!not-valid!!!", PASSWORD.toCharArray(), "198.51.100.9");

        assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS, wrongPassword.status());
        assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS, unknownAccount.status());
        assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS, nonsenseIdentifier.status());
        assertNull(wrongPassword.session());
        assertNull(unknownAccount.session());
        assertNull(unknownAccount.usernameDisplay());
    }

    @Test
    void aDisabledAccountCannotLogInAndLooksLikeAnyOtherFailure(@TempDir Path dir)
            throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        execute("UPDATE account SET disabled = 1");

        AccountService.AuthResult result =
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7");
        assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS, result.status());
        assertNull(result.session());
    }

    @Test
    void aCorruptStoredHashFailsClosed(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        execute("UPDATE account SET password_hash = '$argon2id$v=19$m=19456,t=2,p=1$YWJj$YWJj'");

        assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
    }

    @Test
    void sqlMetacharactersInInputAreJustCharacters(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        // Classic injection payloads: rejected as invalid identifiers, and the table survives.
        for (String payload : List.of("' OR '1'='1", "alice@example.com'--", "a'; DROP TABLE account;--")) {
            assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS,
                    service.authenticate(payload, PASSWORD.toCharArray(), "198.51.100.7").status());
        }
        assertEquals(1, queryInt("SELECT COUNT(*) FROM account"));
    }

    // ---------------------------------------------------------------- throttling

    @Test
    void throttlesRepeatedFailuresForOneAccount(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT", "3",
                "ACCOUNTS_MAX_FAILURES_PER_SOURCE", "1000"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        for (int i = 0; i < 3; i++) {
            // Each attempt comes from a different source, so only the account limit can bite.
            assertEquals(AccountService.AuthStatus.INVALID_CREDENTIALS,
                    service.authenticate(EMAIL, "wrong-password-here".toCharArray(),
                            "203.0.113." + i).status());
        }
        assertEquals(AccountService.AuthStatus.THROTTLED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "203.0.113.50").status());

        // Rule 3: the limit must not become a permanent lockout. The window expires on its own.
        clock.advance(Duration.ofMinutes(16));
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "203.0.113.50").status());
    }

    @Test
    void throttlesRepeatedFailuresFromOneSourceAcrossAccounts(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_MAX_FAILURES_PER_SOURCE", "5",
                "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT", "100"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        // Credential stuffing: every guess targets a different account, so the per-account limit
        // never triggers -- the per-source limit is what stops it.
        for (int i = 0; i < 5; i++) {
            service.authenticate("victim" + i + "@example.com", "guess-guess-guess".toCharArray(),
                    "203.0.113.9");
        }
        assertEquals(AccountService.AuthStatus.THROTTLED,
                service.authenticate("victim9@example.com", "guess-guess-guess".toCharArray(),
                        "203.0.113.9").status());
        // A different source is unaffected: one attacker cannot deny service to everyone.
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
    }

    @Test
    void aSuccessfulLoginDoesNotResetTheSourceBudget(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_MAX_FAILURES_PER_SOURCE", "5",
                "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT", "100"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.1");

        // Attacker holds one valid credential and tries to launder its source budget with it.
        service.authenticate("victim1@example.com", "guess-guess-guess".toCharArray(), "203.0.113.9");
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "203.0.113.9").status());
        service.authenticate("victim2@example.com", "guess-guess-guess".toCharArray(), "203.0.113.9");
        service.authenticate("victim3@example.com", "guess-guess-guess".toCharArray(), "203.0.113.9");
        service.authenticate("victim4@example.com", "guess-guess-guess".toCharArray(), "203.0.113.9");
        assertEquals(AccountService.AuthStatus.THROTTLED,
                service.authenticate("victim5@example.com", "guess-guess-guess".toCharArray(),
                        "203.0.113.9").status());
    }

    @Test
    void anAttackerCannotBurnTheAccountCounterThroughRegistration(@TempDir Path dir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT", "3",
                "ACCOUNTS_MAX_FAILURES_PER_SOURCE", "1000"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        // Ten "register with the victim's email" attempts: these count against the source only.
        for (int i = 0; i < 10; i++) {
            service.register(EMAIL, "squatter" + i, "hazel-mortar-cobalt-3".toCharArray(),
                    "203.0.113." + i);
        }
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
    }

    @Test
    void throttlesRegistrationPerSource(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock,
                Map.of("ACCOUNTS_MAX_FAILURES_PER_SOURCE", "5"));
        for (int i = 0; i < 5; i++) {
            assertEquals(AccountService.RegistrationStatus.ACCEPTED,
                    service.register("user" + i + "@example.com", "user" + i,
                            "hazel-mortar-cobalt-3".toCharArray(), "203.0.113.9"));
        }
        assertEquals(AccountService.RegistrationStatus.THROTTLED,
                service.register("user9@example.com", "user9",
                        "hazel-mortar-cobalt-3".toCharArray(), "203.0.113.9"));
    }

    @Test
    void aSuccessfulLoginClearsTheAccountCounter(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT", "3",
                "ACCOUNTS_MAX_FAILURES_PER_SOURCE", "1000"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        service.authenticate(EMAIL, "wrong-password-here".toCharArray(), "203.0.113.1");
        service.authenticate(EMAIL, "wrong-password-here".toCharArray(), "203.0.113.2");
        // The real user gets in and their counter is wiped, so the attacker starts over.
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
        service.authenticate(EMAIL, "wrong-password-here".toCharArray(), "203.0.113.3");
        service.authenticate(EMAIL, "wrong-password-here".toCharArray(), "203.0.113.4");
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
    }

    @Test
    void recordsOnlyDigestsOfSourcesAndIdentifiers(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.authenticate(EMAIL, "wrong-password-here".toCharArray(), "203.0.113.77");
        List<String> keys = new ArrayList<>();
        try (Connection c = openConnection(); Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT scope_key FROM auth_attempt")) {
            while (rs.next()) {
                keys.add(rs.getString(1));
            }
        }
        assertFalse(keys.isEmpty());
        for (String key : keys) {
            assertEquals(64, key.length());
            assertFalse(key.contains("203.0.113.77"));
            assertFalse(key.contains("alice"));
        }
    }

    // ---------------------------------------------------------------- sessions

    @Test
    void issuesUnpredictableSessionTokensAndStoresOnlyTheirDigest(@TempDir Path dir)
            throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        char[] first = service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7")
                .session().token();
        char[] second = service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7")
                .session().token();
        assertEquals(43, first.length);
        assertNotEquals(new String(first), new String(second));

        String storedHash = queryString("SELECT token_hash FROM auth_session LIMIT 1");
        assertEquals(64, storedHash.length());
        assertFalse(storedHash.contains(new String(first)));
        assertFalse(storedHash.contains(new String(second)));
    }

    @Test
    void resolvesAValidSessionAndRejectsEverythingElse(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        SessionService.IssuedSession session =
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").session();

        assertTrue(service.resolveSession(session.token()).isPresent());
        assertTrue(service.resolveSession(null).isEmpty());
        assertTrue(service.resolveSession("too-short".toCharArray()).isEmpty());
        assertTrue(service.resolveSession("x".repeat(43).toCharArray()).isEmpty());
        // A caller-chosen value of the right shape is still not a session (no session fixation).
        assertTrue(service.resolveSession("A".repeat(43).toCharArray()).isEmpty());
        // Wrong alphabet is refused before it ever reaches a query.
        assertTrue(service.resolveSession(("'" + "a".repeat(42)).toCharArray()).isEmpty());
    }

    @Test
    void revokedSessionsStopWorkingImmediately(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        SessionService.IssuedSession session =
                service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").session();

        char[] token = session.token().clone();
        service.logout(token.clone());
        assertTrue(service.resolveSession(token).isEmpty());
    }

    @Test
    void sessionsExpireOnIdleAndAbsoluteTimeouts(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_SESSION_IDLE_SECONDS", "600",
                "ACCOUNTS_SESSION_ABSOLUTE_SECONDS", "1800"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        char[] token = service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7")
                .session().token();

        clock.advance(Duration.ofMinutes(9));
        assertTrue(service.resolveSession(token.clone()).isPresent(), "within idle window");
        clock.advance(Duration.ofMinutes(9));
        assertTrue(service.resolveSession(token.clone()).isPresent(), "idle timer was refreshed");
        clock.advance(Duration.ofMinutes(11));
        assertTrue(service.resolveSession(token.clone()).isEmpty(), "absolute timeout reached");
    }

    @Test
    void idleSessionsExpireEvenWithinTheAbsoluteWindow(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService service = service(dir, clock, Map.of(
                "ACCOUNTS_SESSION_IDLE_SECONDS", "600",
                "ACCOUNTS_SESSION_ABSOLUTE_SECONDS", "86400"));
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        char[] token = service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7")
                .session().token();

        clock.advance(Duration.ofMinutes(11));
        assertTrue(service.resolveSession(token).isEmpty());
    }

    @Test
    void sessionCookieCarriesTheRequiredAttributes(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        char[] token = service.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7")
                .session().token();

        String header = SessionCookie.setCookieHeader(token, Duration.ofMinutes(30));
        assertTrue(header.startsWith("__Host-session="), header);
        assertTrue(header.contains("; Path=/"), header);
        assertTrue(header.contains("; HttpOnly"), header);
        assertTrue(header.contains("; Secure"), header);
        assertTrue(header.contains("; SameSite=Strict"), header);
        assertTrue(header.contains("; Max-Age=1800"), header);
        assertFalse(header.contains("Domain="), header);
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookie.setCookieHeader("bogus".toCharArray(), Duration.ofMinutes(30)));
    }

    // ---------------------------------------------------------------- hash upgrade & file modes

    @Test
    void upgradesAWeakStoredHashOnSuccessfulLogin(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        AccountService weakService = service(dir, clock,
                Map.of("ACCOUNTS_ARGON2_ITERATIONS", "2"));
        weakService.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");
        String before = queryString("SELECT password_hash FROM account");
        assertTrue(before.contains("t=2,"), before);
        database.close();

        AccountService strongService = service(dir, clock,
                Map.of("ACCOUNTS_ARGON2_ITERATIONS", "4"));
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                strongService.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
        String after = queryString("SELECT password_hash FROM account");
        assertTrue(after.contains("t=4,"), after);
        // The upgraded hash still verifies the same password.
        assertEquals(AccountService.AuthStatus.AUTHENTICATED,
                strongService.authenticate(EMAIL, PASSWORD.toCharArray(), "198.51.100.7").status());
    }

    @Test
    void dataDirectoryAndDatabaseAreOwnerOnly(@TempDir Path dir) throws Exception {
        AccountService service = service(dir);
        service.register(EMAIL, USERNAME, PASSWORD.toCharArray(), "198.51.100.7");

        Path dataDir = dir.toAbsolutePath();
        if (!dataDir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        assertEquals("rwx------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(dataDir)));
        Path db = dataDir.resolve("accounts.db");
        assertEquals("rw-------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(db)));
    }

    // ---------------------------------------------------------------- helpers

    /** A plain read-only connection, used to assert on what actually landed on disk. */
    private Connection openConnection() throws SQLException {
        return java.sql.DriverManager.getConnection(jdbcUrl);
    }

    private String queryString(String sql) throws SQLException {
        try (Connection c = openConnection(); Statement s = c.createStatement();
                ResultSet rs = s.executeQuery(sql)) {
            assertTrue(rs.next(), sql);
            return rs.getString(1);
        }
    }

    private int queryInt(String sql) throws SQLException {
        try (Connection c = openConnection(); Statement s = c.createStatement();
                ResultSet rs = s.executeQuery(sql)) {
            assertTrue(rs.next(), sql);
            return rs.getInt(1);
        }
    }

    private void execute(String sql) throws SQLException {
        try (Connection c = openConnection(); Statement s = c.createStatement()) {
            s.executeUpdate(sql);
        }
    }

    /** A clock the test can move forward, so expiry logic is tested without sleeping. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration amount) {
            now = now.plus(amount);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
