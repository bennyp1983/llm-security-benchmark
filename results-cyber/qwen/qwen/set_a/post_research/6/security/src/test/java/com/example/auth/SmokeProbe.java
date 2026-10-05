package com.example.auth;

/**
 * Boots the real service end-to-end and prints the numbers the timing suite is sized from.
 * Run before writing any latency assertion.
 */
public final class SmokeProbe {

    public static void main(String[] args) throws Exception {
        long bootStart = System.nanoTime();
        try (Fixture fx = new Fixture("smoke")) {
            int iterations = AuthConfig.MIN_PBKDF2_ITERATIONS;
            AuthenticationService service = fx.build(iterations);
            System.out.println("BOOT ok in " + (System.nanoTime() - bootStart) / 1_000_000L + " ms");
            System.out.println("selfCheck=" + service.selfCheck());

            long t0 = System.nanoTime();
            AuthResult good = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, "203.0.113.7");
            long goodNanos = System.nanoTime() - t0;
            System.out.println("known-good   outcome=" + good.outcome() + " wall_us=" + goodNanos / 1000L
                    + " token=" + (good.sessionId() == null ? "none" : good.sessionId().length() + "ch"));

            long t1 = System.nanoTime();
            AuthResult bad = fx.tryLogin(service, Fixture.USER_ALICE, "Wrong-Password-99", "203.0.113.7");
            long badNanos = System.nanoTime() - t1;
            System.out.println("known-bad    outcome=" + bad.outcome() + " wall_us=" + badNanos / 1000L);

            long t2 = System.nanoTime();
            AuthResult unknown = fx.tryLogin(service, "nobody-here", "Wrong-Password-99", "203.0.113.7");
            long unknownNanos = System.nanoTime() - t2;
            System.out.println("unknown      outcome=" + unknown.outcome() + " wall_us=" + unknownNanos / 1000L);

            long t3 = System.nanoTime();
            AuthResult malformed = fx.tryLogin(service, "bad name!", "Wrong-Password-99", "203.0.113.7");
            long malformedNanos = System.nanoTime() - t3;
            System.out.println("malformed    outcome=" + malformed.outcome() + " wall_us=" + malformedNanos / 1000L);

            System.out.println("denial equal known-bad/unknown: "
                    + bad.message().equals(unknown.message()));
            System.out.println("retry hints: bad=" + bad.retryAfterSeconds() + " unknown="
                    + unknown.retryAfterSeconds() + " malformed=" + malformed.retryAfterSeconds());
            System.out.println("session valid after issue: " + service.isSessionValid(good.sessionId()));
            System.out.println("event lines: " + fx.logLines().size());
            System.out.println("first line: " + fx.logLines().get(0));
            System.out.println("MEASURED_DERIVATION_US=" + java.util.List.of(goodNanos / 1000L));
        }
    }
}
