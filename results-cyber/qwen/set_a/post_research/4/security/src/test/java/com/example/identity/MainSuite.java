package com.example.identity;

/**
 * The whole suite, in one process.
 *
 * <p>Deliberately not JUnit: the trustworthiness of these results is itself part of the deliverable,
 * and a hand-rolled runner means {@code sh tools/run-tests.sh} is the entire interface - no test
 * framework to fetch, pin and verify, no plugin that can silently skip a class. Every suite is
 * named here, so a suite that stops being compiled into the run shows up as a missing line rather
 * than a green bar.
 *
 * <p>Suites run in a fixed order: cheapest and most fundamental first, so a broken value object
 * reports before anything downstream that depends on it.
 */
public final class MainSuite {

    private MainSuite() {
    }

    public static void main(String[] args) {
        // tools/run-tests.sh passes an empty string when no suite was named; that must mean "all",
        // not "none" - a runner that silently runs nothing is the worst kind of green.
        String only = args.length > 0 && !args[0].isBlank() ? args[0] : null;
        long t0 = System.nanoTime();
        run(only, "identity", IdentityValidationTest::run);
        run(only, "password", PasswordTest::run);
        run(only, "config", ConfigTest::run);
        run(only, "sourceid", SourceIdTest::run);
        run(only, "outcome", OutcomeMessageTest::run);
        run(only, "session", SessionTokenTest::run);
        run(only, "storage", StorageAtomicityTest::run);
        run(only, "guard", DecisionGuardTest::run);
        run(only, "throttle", ThrottleLockoutTest::run);
        run(only, "equalwork", EqualWorkTest::run);
        run(only, "audit", AuditLogTest::run);
        run(only, "perms", FilePermissionTest::run);
        run(only, "linereader", LineReaderTest::run);
        run(only, "cli", CliEndToEndTest::run);

        Harness.printSummary();
        System.out.println("elapsed_ms=" + (System.nanoTime() - t0) / 1_000_000L);
        Harness.requireGreen();
    }

    /** A suite is a body that may throw; a thrown exception is a failure, never a skip. */
    interface Body {
        void run() throws Exception;
    }

    private static void run(String only, String name, Body body) {
        if (only != null && !only.equals(name)) {
            return;
        }
        System.out.println("\n################ suite: " + name + " ################");
        long t0 = System.nanoTime();
        try {
            body.run();
        } catch (Throwable t) {
            Harness.check("suite " + name + " completed without throwing", false);
            System.out.println("  THREW " + t.getClass().getName() + ": " + t.getMessage());
            for (StackTraceElement e : t.getStackTrace()) {
                if (e.getClassName().startsWith("com.example.identity")) {
                    System.out.println("        at " + e);
                }
            }
        }
        System.out.println("---- suite " + name + " done in "
                + ((System.nanoTime() - t0) / 1_000_000L) + " ms, failures so far="
                + Harness.failureCount());
    }
}
