package com.example.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * Test harness and scratch-space management shared by every suite in this directory.
 *
 * <p>Scratch directories are named after the process id: a mutation battery and a CI matrix run two
 * suites at once, and a fixed path makes one run read the other's credential store, which produces
 * failures that look like code defects. Cleanup is a shutdown hook rather than the end of main,
 * because the runs that leak directories are exactly the ones that exit early.
 */
final class T {

    static int passed;
    static int failed;
    static final List<String> FAILURES = new ArrayList<>();
    private static String section = "";
    private static Path scratchRoot;

    private T() {
    }

    static void section(String name) {
        section = name;
        System.out.println("--- " + name + " ---");
    }

    static void yes(String what, boolean condition) {
        if (condition) {
            passed++;
        } else {
            fail(what);
        }
    }

    static void no(String what, boolean condition) {
        yes(what, !condition);
    }

    static void eq(String what, Object expected, Object actual) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            passed++;
        } else {
            fail(what + " (expected <" + expected + "> got <" + actual + ">)");
        }
    }

    static void inRange(String what, long value, long min, long max) {
        if (value >= min && value <= max) {
            passed++;
        } else {
            fail(what + " (" + value + " not in [" + min + "," + max + "])");
        }
    }

    private static void fail(String what) {
        failed++;
        String line = section + " / " + what;
        FAILURES.add(line);
        System.out.println("FAIL: " + line);
    }

    static int summary(String suite) {
        System.out.println("SUMMARY " + suite + " passed=" + passed + " failed=" + failed);
        for (String f : FAILURES) {
            System.out.println("FAILURE " + f);
        }
        return failed == 0 ? 0 : 1;
    }

    /** A private scratch directory, created 0700, removed when the JVM exits. */
    static Path scratch(String name) throws IOException {
        if (scratchRoot == null) {
            scratchRoot = Files.createTempDirectory("secapp-" + ProcessHandle.current().pid() + "-");
            Runtime.getRuntime().addShutdownHook(new Thread(T::deleteRecursivelyQuietly));
        }
        Path dir = scratchRoot.resolve(name);
        DbFiles.ensurePrivateDirectory(dir);
        return dir;
    }

    static Path scratchRoot() throws IOException {
        if (scratchRoot == null) {
            scratch(name0());
        }
        return scratchRoot;
    }

    private static String name0() {
        return "root";
    }

    static void deleteRecursivelyQuietly() {
        if (scratchRoot == null || !Files.exists(scratchRoot)) {
            return;
        }
        try {
            List<Path> all = new ArrayList<>();
            Files.walk(scratchRoot).forEach(all::add);
            all.sort(Comparator.reverseOrder());
            for (Path p : all) {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // Best effort at shutdown.
                }
            }
        } catch (IOException ignored) {
            // Best effort at shutdown.
        }
    }

    /** Mode of a file as a 3-character owner/group/other string, for readable assertions. */
    static String mode(Path p) throws IOException {
        Set<PosixFilePermission> m = Files.getPosixFilePermissions(p);
        StringBuilder sb = new StringBuilder(9);
        sb.append(m.contains(PosixFilePermission.OWNER_READ) ? 'r' : '-');
        sb.append(m.contains(PosixFilePermission.OWNER_WRITE) ? 'w' : '-');
        sb.append(m.contains(PosixFilePermission.OWNER_EXECUTE) ? 'x' : '-');
        sb.append(m.contains(PosixFilePermission.GROUP_READ) ? 'r' : '-');
        sb.append(m.contains(PosixFilePermission.GROUP_WRITE) ? 'w' : '-');
        sb.append(m.contains(PosixFilePermission.GROUP_EXECUTE) ? 'x' : '-');
        sb.append(m.contains(PosixFilePermission.OTHERS_READ) ? 'r' : '-');
        sb.append(m.contains(PosixFilePermission.OTHERS_WRITE) ? 'w' : '-');
        sb.append(m.contains(PosixFilePermission.OTHERS_EXECUTE) ? 'x' : '-');
        return sb.toString();
    }

    static boolean hasGroupOrWorldBits(Path p) throws IOException {
        Set<PosixFilePermission> m = Files.getPosixFilePermissions(p);
        for (PosixFilePermission perm : m) {
            String n = perm.name();
            if (n.startsWith("GROUP_") || n.startsWith("OTHERS_")) {
                return true;
            }
        }
        return false;
    }

    /** Reads a whole file as text. Fails the calling assertion if it cannot be read. */
    static String read(Path p) throws IOException {
        return new String(Files.readAllBytes(p), java.nio.charset.StandardCharsets.UTF_8);
    }

    static char[] chars(String s) {
        return s.toCharArray();
    }

    /** A long password fixture built from real characters (never {@code new char[n]}, which is NULs). */
    static char[] longPassword(int n) {
        char[] out = new char[n];
        Arrays.fill(out, 'p');
        return out;
    }

    /** Median of a sample, in the same unit as the sample. Robust to scheduler spikes. */
    static double median(long[] sample) {
        long[] c = sample.clone();
        Arrays.sort(c);
        if (c.length == 0) {
            return Double.NaN;
        }
        int mid = c.length / 2;
        return c.length % 2 == 1 ? c[mid] : (c[mid - 1] + c[mid]) / 2.0;
    }

    /** 20th percentile, used as the low-end spread measure in timing assertions. */
    static double p20(long[] sample) {
        long[] c = sample.clone();
        Arrays.sort(c);
        if (c.length == 0) {
            return Double.NaN;
        }
        return c[Math.max(0, (int) (c.length * 0.2))];
    }

    static String show(Set<PosixFilePermission> perms) {
        return Arrays.toString(perms.toArray());
    }
}
