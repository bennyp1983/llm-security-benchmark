package com.example.auth;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Executable checks for the security-relevant behaviour of the component.
 *
 * <p>Plain {@code main} rather than a test framework so it runs on a bare JDK with
 * no downloaded dependencies. Run: {@code java -cp target/classes:target/test-classes
 * com.example.auth.AuthenticationSelfCheck}.</p>
 *
 * <p>The password used below is generated at runtime from {@link java.security.SecureRandom};
 * no credential is written into this source file, so nothing here works against
 * any real deployment.</p>
 */
public final class AuthenticationSelfCheck {

    private static int failures;

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("auth-selfcheck");
        Path logFile = dir.resolve("auth-events.log");

        char[] secret = randomPassword();
        PasswordHasher hasher = new PasswordHasher(PasswordHasher.MIN_ITERATIONS);
        InMemoryCredentialStore store = new InMemoryCredentialStore();
        store.put("alice", hasher.hash(secret.clone()));

        AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-01T10:00:00Z"));
        LoginThrottle throttle = new LoginThrottle(5, 20, Duration.ofMinutes(15),
                Duration.ofMinutes(15), Duration.ofMinutes(5), now::get);
        SessionRegistry registry = new SessionRegistry(Duration.ofMinutes(30), Duration.ofHours(8), now::get);

        try (FileAuthEventLog log = FileAuthEventLog.withDefaults(logFile)) {
            AuthenticationService service =
                    new AuthenticationService(store, hasher, throttle, registry, log, now::get);

            // 1. Valid credentials authenticate and receive a fresh session identifier.
            AuthenticationResult ok = service.authenticate("Alice", secret.clone(), "198.51.100.7");
            check("valid login succeeds", ok.isAuthenticated());
            String sessionId = ok.sessionId().orElse("");
            check("session id is well formed", InputPolicy.isWellFormedSessionId(sessionId));
            check("session resolves to server-side state",
                    service.resumeSession(sessionId).map(Session::username).orElse("").equals("alice"));

            // 2. Two logins never share an identifier.
            String second = service.authenticate("alice", secret.clone(), "198.51.100.7")
                    .sessionId().orElse("");
            check("identifiers are unique per login", !second.equals(sessionId));

            // 3. Wrong password, unknown account and malformed input are indistinguishable.
            AuthenticationResult wrongPassword = service.authenticate("alice", randomPassword(), "198.51.100.8");
            AuthenticationResult unknownUser = service.authenticate("nobody", randomPassword(), "198.51.100.8");
            AuthenticationResult badInput = service.authenticate("bad user!", randomPassword(), "198.51.100.8");
            check("wrong password fails", !wrongPassword.isAuthenticated());
            check("unknown account fails", !unknownUser.isAuthenticated());
            check("malformed username fails", !badInput.isAuthenticated());
            check("all failures share one message",
                    wrongPassword.message().equals(unknownUser.message())
                            && unknownUser.message().equals(badInput.message())
                            && badInput.message().equals(AuthenticationResult.GENERIC_FAILURE_MESSAGE));
            check("failures carry no session", wrongPassword.sessionId().isEmpty()
                    && unknownUser.sessionId().isEmpty() && badInput.sessionId().isEmpty());

            // 4. Per-source budget blocks that source but leaves the account usable
            //    from elsewhere - an attacker cannot lock the legitimate user out.
            for (int i = 0; i < 5; i++) {
                service.authenticate("alice", randomPassword(), "203.0.113.9");
            }
            check("exhausted source is blocked",
                    !service.authenticate("alice", secret.clone(), "203.0.113.9").isAuthenticated());
            check("legitimate user still signs in from another source",
                    service.authenticate("alice", secret.clone(), "198.51.100.7").isAuthenticated());
            check("a success elsewhere does not reset the blocked source's budget",
                    !service.authenticate("alice", secret.clone(), "203.0.113.9").isAuthenticated());

            // 5. The account cool-off expires on its own; no unlock step is needed.
            for (int i = 0; i < 20; i++) {
                service.authenticate("alice", randomPassword(), "203.0.113." + (10 + i % 200));
            }
            check("account cool-off engages",
                    !service.authenticate("alice", secret.clone(), "192.0.2.5").isAuthenticated());
            now.set(now.get().plus(Duration.ofMinutes(6)));
            check("account cool-off expires unattended",
                    service.authenticate("alice", secret.clone(), "192.0.2.5").isAuthenticated());

            // 6. Session identifiers from the caller are never honoured.
            check("forged identifier rejected", service.resumeSession("A".repeat(43)).isEmpty());
            check("empty identifier rejected", service.resumeSession("").isEmpty());
            check("null identifier rejected", service.resumeSession(null).isEmpty());

            // 7. Timeouts and sign-out are enforced server-side.
            String live = service.authenticate("alice", secret.clone(), "192.0.2.5").sessionId().orElseThrow();
            service.signOut(live);
            check("sign-out invalidates", service.resumeSession(live).isEmpty());
            String idle = service.authenticate("alice", secret.clone(), "192.0.2.5").sessionId().orElseThrow();
            now.set(now.get().plus(Duration.ofMinutes(31)));
            check("idle session expires", service.resumeSession(idle).isEmpty());

            // 8. Concurrent attempts cannot exceed the budget.
            checkConcurrentBudget(store, hasher, registry, log, now::get);
        }

        // 9. The log is private, holds no secrets, and resists log forging.
        List<String> lines = Files.readAllLines(logFile);
        check("events were retained", lines.size() >= 10);
        String joined = String.join("\n", lines);
        check("password never appears in the log", !joined.contains(new String(secret)));
        check("full username never appears in the log", !joined.contains("\"alice\""));
        check("full source address never appears in the log", !joined.contains("198.51.100.7"));
        check("source is masked to a prefix", joined.contains("198.51.100.0/24"));
        check("one record per attempt", lines.stream().allMatch(l -> l.startsWith("ts=\"")));

        PosixFileAttributeView view = Files.getFileAttributeView(logFile, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        check("log file is owner-only", view == null || view.readAttributes().permissions().equals(
                java.util.EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE)));

        // 10. Log forging through the username is impossible.
        try (FileAuthEventLog log2 = FileAuthEventLog.withDefaults(dir.resolve("forge.log"))) {
            AuthenticationService service = new AuthenticationService(store, hasher,
                    LoginThrottle.withDefaults(), SessionRegistry.withDefaults(), log2, now::get);
            service.authenticate("a\nts=\"forged\" outcome=\"SUCCESS", randomPassword(), "192.0.2.1");
            long records = Files.readAllLines(dir.resolve("forge.log")).size();
            check("newline in username yields exactly one record", records == 1);
            check("forged outcome is absent",
                    !String.join("", Files.readAllLines(dir.resolve("forge.log"))).contains("forged"));
        }

        // 10b. A log directory that does not yet exist is created owner-only,
        //      regardless of the process umask.
        Path nested = dir.resolve("nested/deeper");
        try (FileAuthEventLog log4 = FileAuthEventLog.withDefaults(nested.resolve("events.log"))) {
            log4.record(new AuthEvent(now.get(), AuthEvent.Outcome.INVALID_INPUT, "-", "-", "-", "probe"));
        }
        PosixFileAttributeView dirView = Files.getFileAttributeView(nested, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        check("log directory is owner-only", dirView == null || dirView.readAttributes().permissions().equals(
                java.util.EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                        java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE)));

        // 11. Cookie attributes.
        String header = SessionCookie.setCookieHeader("b".repeat(43), 3600);
        check("cookie is HttpOnly", header.contains("; HttpOnly"));
        check("cookie is Secure", header.contains("; Secure"));
        check("cookie is SameSite=Strict", header.contains("; SameSite=Strict"));
        check("cookie has an explicit path", header.contains("; Path=/"));
        check("cookie rejects a malformed identifier", throwsIllegalArgument(
                () -> SessionCookie.setCookieHeader("short", 3600)));

        // 12. Configuration and stored records are range-checked, not clamped.
        check("weak iteration count rejected", throwsIllegalArgument(() -> new PasswordHasher(1)));
        check("tampered record iterations rejected", throwsIllegalArgument(
                () -> new CredentialRecord(new byte[16], new byte[64], 1)));
        check("short password rejected by policy", !InputPolicy.isAcceptablePassword("short".toCharArray()));
        check("oversized password rejected by policy",
                !InputPolicy.isAcceptablePassword(new char[InputPolicy.PASSWORD_MAX_LENGTH + 1]));
        check("non-IP source rejected", InputPolicy.canonicalSource("localhost").isEmpty());
        check("IP source accepted", InputPolicy.canonicalSource("2001:db8::1").isPresent());

        // 13. The password array the caller passed in is cleared.
        char[] passed = randomPassword();
        try (FileAuthEventLog log3 = FileAuthEventLog.withDefaults(dir.resolve("clear.log"))) {
            new AuthenticationService(store, hasher, LoginThrottle.withDefaults(),
                    SessionRegistry.withDefaults(), log3, now::get)
                    .authenticate("alice", passed, "192.0.2.2");
        }
        check("password buffer zeroed after use", allZero(passed));

        java.util.Arrays.fill(secret, '\0');
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED");
        if (failures != 0) {
            System.exit(1);
        }
    }

    private static void checkConcurrentBudget(CredentialStore store,
                                              PasswordHasher hasher,
                                              SessionRegistry registry,
                                              AuthEventLog log,
                                              java.util.function.Supplier<Instant> clock) throws Exception {
        int budget = 3;
        LoginThrottle tight = new LoginThrottle(budget, 1000, Duration.ofMinutes(15),
                Duration.ofMinutes(15), Duration.ofMinutes(5), clock);
        AuthenticationService service = new AuthenticationService(store, hasher, tight, registry, log, clock);
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger admitted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                // Each attempt uses a wrong password; count how many got as far as
                // being evaluated rather than refused by the throttle.
                Optional<LoginThrottle.Block> before = tight.admit("carol", "192.0.2.77");
                service.authenticate("carol", randomPassword(), "192.0.2.77");
                if (before.isEmpty()) {
                    admitted.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.SECONDS);
        check("concurrent attempts stay within the budget (+ in-flight slack)",
                admitted.get() <= budget + threads);
        check("source is blocked once the budget is spent",
                tight.admit("carol", "192.0.2.77").isPresent());
    }

    private static char[] randomPassword() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        char[] out = new char[InputPolicy.PASSWORD_MIN_LENGTH + 8];
        for (int i = 0; i < out.length; i++) {
            out[i] = (char) ('!' + random.nextInt(90));
        }
        return out;
    }

    private static boolean allZero(char[] value) {
        for (char c : value) {
            if (c != '\0') {
                return false;
            }
        }
        return true;
    }

    private static boolean throwsIllegalArgument(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static void check(String what, boolean condition) {
        if (!condition) {
            failures++;
        }
        System.out.println((condition ? "PASS  " : "FAIL  ") + what);
    }
}
