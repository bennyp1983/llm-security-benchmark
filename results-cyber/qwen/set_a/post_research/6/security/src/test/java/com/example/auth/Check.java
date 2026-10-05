package com.example.auth;

import java.io.IOException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/** Minimal assertion and reporting helper; the project has no third-party test dependency. */
final class Check {

    static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private static int passed;
    private static int failed;

    private Check() {
    }

    static void ok(String what, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("PASS  " + what);
        } else {
            failed++;
            System.out.println("FAIL  " + what);
        }
    }

    static void eq(String what, Object expected, Object actual) {
        boolean same = expected == null ? actual == null : expected.equals(actual);
        if (same) {
            ok(what, true);
        } else {
            ok(what + " [expected=<" + expected + "> actual=<" + actual + ">]", false);
        }
    }

    static void contains(String what, String haystack, String needle) {
        ok(what, haystack != null && needle != null && haystack.contains(needle));
    }

    static void lacks(String what, String haystack, String needle) {
        ok(what, haystack != null && needle != null && !haystack.contains(needle));
    }

    /**
     * Asserts that none of {@code needles} appear in {@code haystack}, and that the haystack is
     * non-empty: an absence check against an empty capture proves nothing.
     */
    static void lacksAllNonEmpty(String what, String haystack, String... needles) {
        if (haystack == null || haystack.trim().isEmpty()) {
            ok(what + " [refused: capture is empty, so the absence check would pass vacuously]", false);
            return;
        }
        for (String needle : needles) {
            if (haystack.contains(needle)) {
                ok(what + " [found forbidden substring <" + needle + ">]", false);
                return;
            }
        }
        ok(what, true);
    }

    static void summary(String suite) {
        System.out.println("SUMMARY " + suite + " passed=" + passed + " failed=" + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static int failedCount() {
        return failed;
    }

    static void note(String message) {
        System.out.println("NOTE    " + message);
    }

    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    static void deleteTree(java.nio.file.Path root) {
        if (root == null || !java.nio.file.Files.exists(root)) {
            return;
        }
        try (java.util.stream.Stream<java.nio.file.Path> walk = java.nio.file.Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    java.nio.file.Files.deleteIfExists(p);
                } catch (IOException e) {
                    // Best effort; scratch data only.
                }
            });
        } catch (IOException e) {
            // Best effort.
        }
    }
}
