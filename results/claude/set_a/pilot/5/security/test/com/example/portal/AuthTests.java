package com.example.portal;

import com.example.portal.auth.AuthResult;
import com.example.portal.auth.AuthenticationService;
import com.example.portal.auth.InMemoryCredentialStore;
import com.example.portal.auth.LockoutPolicy;
import com.example.portal.auth.PasswordHasher;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/** Dependency-free test harness: run with {@code java AuthTests}; exits non-zero on failure. */
public final class AuthTests {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        hashRoundTrip();
        wrongPasswordDenied();
        lockoutAfterMaxAttempts();
        correctPasswordRefusedWhileLocked();
        lockExpires();
        successResetsCounter();
        caseVariationCannotEvadeLockout();
        unknownUserLocksToo();
        disabledAccountDenied();
        concurrentFailuresAllCount();

        System.out.println(failures == 0 ? "\nAll tests passed." : "\n" + failures + " test(s) FAILED.");
        System.exit(failures == 0 ? 0 : 1);
    }

    // --- cases ---------------------------------------------------------------

    static void hashRoundTrip() {
        String h = PasswordHasher.hash("s3cret-passphrase".toCharArray());
        check("correct password verifies", PasswordHasher.verify("s3cret-passphrase".toCharArray(), h));
        check("wrong password rejected", !PasswordHasher.verify("s3cret-passphras".toCharArray(), h));
        check("distinct salts per hash",
                !h.equals(PasswordHasher.hash("s3cret-passphrase".toCharArray())));
        check("malformed hash rejected", !PasswordHasher.verify("x".toCharArray(), "garbage"));
    }

    static void wrongPasswordDenied() {
        Fixture f = new Fixture(3, Duration.ofMinutes(10));
        check("bad password denied",
                f.auth.authenticate("jsmith", "nope".toCharArray()).status()
                        == AuthResult.Status.INVALID_CREDENTIALS);
        check("good password granted",
                f.auth.authenticate("jsmith", Fixture.PASSWORD.toCharArray()).authenticated());
    }

    static void lockoutAfterMaxAttempts() {
        Fixture f = new Fixture(3, Duration.ofMinutes(10));
        f.auth.authenticate("jsmith", "a".toCharArray());
        AuthResult second = f.auth.authenticate("jsmith", "b".toCharArray());
        check("counts down remaining attempts", second.remainingAttempts() == 1);
        AuthResult third = f.auth.authenticate("jsmith", "c".toCharArray());
        check("locks on the Nth failure", third.status() == AuthResult.Status.LOCKED_OUT);
    }

    static void correctPasswordRefusedWhileLocked() {
        Fixture f = new Fixture(2, Duration.ofMinutes(10));
        f.auth.authenticate("jsmith", "a".toCharArray());
        f.auth.authenticate("jsmith", "b".toCharArray());
        AuthResult r = f.auth.authenticate("jsmith", Fixture.PASSWORD.toCharArray());
        check("correct password still refused while locked", r.status() == AuthResult.Status.LOCKED_OUT);
    }

    static void lockExpires() {
        Fixture f = new Fixture(2, Duration.ofMinutes(15));
        f.auth.authenticate("jsmith", "a".toCharArray());
        f.auth.authenticate("jsmith", "b".toCharArray());
        f.now.set(f.now.get().plus(Duration.ofMinutes(14)));
        check("still locked before expiry",
                f.auth.authenticate("jsmith", Fixture.PASSWORD.toCharArray()).status()
                        == AuthResult.Status.LOCKED_OUT);
        f.now.set(f.now.get().plus(Duration.ofMinutes(2)));
        check("unlocks after the window",
                f.auth.authenticate("jsmith", Fixture.PASSWORD.toCharArray()).authenticated());
    }

    static void successResetsCounter() {
        Fixture f = new Fixture(3, Duration.ofMinutes(10));
        f.auth.authenticate("jsmith", "a".toCharArray());
        f.auth.authenticate("jsmith", "b".toCharArray());
        check("sign-in works", f.auth.authenticate("jsmith", Fixture.PASSWORD.toCharArray()).authenticated());
        AuthResult r = f.auth.authenticate("jsmith", "c".toCharArray());
        check("counter reset by success", r.remainingAttempts() == 2);
    }

    static void caseVariationCannotEvadeLockout() {
        Fixture f = new Fixture(3, Duration.ofMinutes(10));
        f.auth.authenticate("jsmith", "a".toCharArray());
        f.auth.authenticate("JSmith", "b".toCharArray());
        AuthResult r = f.auth.authenticate("  JSMITH ", "c".toCharArray());
        check("case/whitespace variants share one counter", r.status() == AuthResult.Status.LOCKED_OUT);
    }

    static void unknownUserLocksToo() {
        Fixture f = new Fixture(2, Duration.ofMinutes(10));
        f.auth.authenticate("ghost", "a".toCharArray());
        AuthResult r = f.auth.authenticate("ghost", "b".toCharArray());
        check("unknown accounts lock as well (no enumeration signal)",
                r.status() == AuthResult.Status.LOCKED_OUT);
    }

    static void disabledAccountDenied() {
        Fixture f = new Fixture(5, Duration.ofMinutes(10));
        AuthResult r = f.auth.authenticate("rgone", Fixture.DISABLED_PASSWORD.toCharArray());
        check("disabled account denied", !r.authenticated());
        check("disabled account message is generic",
                r.message().equals("Invalid username or password."));
    }

    static void concurrentFailuresAllCount() throws Exception {
        LockoutPolicy policy = new LockoutPolicy(50, Duration.ofMinutes(10));
        CountDownLatch start = new CountDownLatch(1);
        Thread[] threads = new Thread[20];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                policy.recordFailure("racer");
            });
            threads[i].start();
        }
        start.countDown();
        for (Thread t : threads) {
            t.join();
        }
        check("no failures lost under concurrency",
                policy.check("racer").consecutiveFailures() == threads.length);
    }

    // --- helpers -------------------------------------------------------------

    private static final class Fixture {
        static final String PASSWORD = "Correct-Horse-Battery-7";
        static final String DISABLED_PASSWORD = "Offboarded-2024";

        final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-09-05T09:00:00Z"));
        final AuthenticationService auth;

        Fixture(int maxAttempts, Duration lockout) {
            InMemoryCredentialStore store = new InMemoryCredentialStore();
            store.addUser("jsmith", PASSWORD.toCharArray(), true);
            store.addUser("rgone", DISABLED_PASSWORD.toCharArray(), false);
            auth = new AuthenticationService(store, new LockoutPolicy(maxAttempts, lockout, now::get));
        }
    }

    private static void check(String name, boolean condition) {
        System.out.println((condition ? "  PASS  " : "  FAIL  ") + name);
        if (!condition) {
            failures++;
        }
    }

    private AuthTests() {
    }
}
