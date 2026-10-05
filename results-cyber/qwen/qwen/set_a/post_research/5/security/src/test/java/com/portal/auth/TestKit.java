package com.portal.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal test harness (the program has no third-party dependencies, and its test suite
 * keeps that property). Scratch directories are named after the process id and removed by a
 * shutdown hook, because a run that dies partway through never reaches cleanup, and a
 * mutation battery that leaves one littered directory per mutant turns the next run's
 * "directory must be private" checks into false failures.
 */
public final class TestKit {

    public static final int FAST_ITERATIONS = PasswordHasher.MIN_ITERATIONS;

    /** Passwords for fixtures. None contains a fixture username (see README). */
    public static final String PW_ALICE = "Fresh-Quiver-71!";
    public static final String PW_BOB = "Another-Kindle-24?";
    public static final String PW_CAROL = "Whistle-Magenta-6@";
    public static final String PW_WRONG = "Incorrect-Sable-88!";
    public static final String PW_WRONG2 = "Incorrect-Sable-89!";

    private static final List<Path> SCRATCH = new ArrayList<>();
    private static int failures;
    private static int checks;
    private static final List<String> FAILED = new ArrayList<>();

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(TestKit::cleanScratch, "testkit-clean"));
    }

    private TestKit() {
    }

    public static Path scratchDir(String label) {
        try {
            Path root = PrivateFiles.requireDataDirectory(Files.createTempDirectory(
                    "portal-test-" + label + "-" + ProcessHandle.current().pid() + "-"));
            SCRATCH.add(root);
            return root;
        } catch (IOException cannotCreate) {
            throw new IllegalStateException("cannot-create-scratch", cannotCreate);
        }
    }

    private static void cleanScratch() {
        for (Path p : SCRATCH) {
            deleteTree(p);
        }
    }

    private static void deleteTree(Path p) {
        try {
            if (!Files.exists(p)) {
                return;
            }
            try (var walk = Files.walk(p)) {
                walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .forEach(f -> f.toFile().delete());
            }
        } catch (IOException ignored) {
            // Scratch cleanup must never fail a run.
        }
    }

    // ------------------------------------------------------------------ assertions

    // Synchronized because the cross-process concurrency cases record verdicts from the
    // writer threads that launch the subprocesses.
    public static synchronized void ok(String name, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
            FAILED.add(name);
            System.out.println("FAIL " + name);
        }
    }

    public static synchronized void eq(String name, Object expected, Object actual) {
        boolean same = expected == null ? actual == null : expected.equals(actual);
        if (!same) {
            ok(name + " (expected=" + expected + " actual=" + actual + ")", false);
        } else {
            checks++;
        }
    }

    public static void note(String message) {
        System.out.println("NOTE  " + message);
    }

    public static void measure(String name, String value) {
        System.out.println("MEAS  " + name + " " + value);
    }

    public static int report(String suite) {
        System.out.println("SUMMARY " + suite + " checks=" + checks + " failures=" + failures);
        if (failures > 0) {
            System.out.println("FAILED-CHECKS " + String.join(" | ", FAILED));
            return 1;
        }
        System.out.println("PASS " + suite);
        return 0;
    }

    /** Runs a block, converting any throwable into a recorded failure rather than a crash. */
    public static void caseOf(String name, ThrowingRunnable body) {
        try {
            body.run();
        } catch (Throwable thrown) {
            ok(name + " threw " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage(),
                    false);
        }
    }

    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    // ---------------------------------------------------------------------- fixtures

    public static void fixedClockAt(Instant when) {
        AuditClock.useForTesting(Clock.fixed(when, ZoneOffset.UTC));
    }

    public static void advancingClockFrom(Instant start, long secondsPerCall) {
        AuditClock.useForTesting(new Clock() {
            private long offset = 0;

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
                return start.plusSeconds(offset += secondsPerCall);
            }
        });
    }

    public static void systemClock() {
        AuditClock.useForTesting(null);
    }

    public static String mode(Path p) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    /** A char[] copy of a fixture password; callers wipe it via authenticate(). */
    public static char[] pw(String literal) {
        return literal.toCharArray();
    }

    public static int countChar(String haystack, String needle) {
        int n = 0;
        int i = haystack.indexOf(needle);
        while (i >= 0) {
            n++;
            i = haystack.indexOf(needle, i + needle.length());
        }
        return n;
    }

    /**
     * Render a hostile string for an assertion name. Control characters, non-ASCII and
     * long values are collapsed, because a fixture name that embeds CR/LF or NUL can forge
     * lines in the suite's own output -- which would make a passing run unreadable and a
     * failing run misleading.
     */
    public static String show(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(s.length(), 24); i++) {
            char c = s.charAt(i);
            sb.append(c < 0x21 || c > 0x7E ? '@' : c);
        }
        if (s.length() > 24) {
            sb.append("...(").append(s.length()).append(')');
        }
        return sb.toString();
    }
}
