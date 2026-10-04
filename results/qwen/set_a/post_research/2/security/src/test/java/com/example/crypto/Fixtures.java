package com.example.crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Test fixtures. Scratch directories are scoped to the process id: a fixed path passes alone and
 * produces fabricated failures the moment two suite runs overlap (a mutation battery, a CI matrix),
 * because one run recreates a roster another run is mid-way through reading.
 */
final class Fixtures {

    private static final List<Path> CREATED = new ArrayList<>();

    private Fixtures() {
    }

    /** A private ({@code 0700}) directory owned by this user, deleted when the JVM exits. */
    static synchronized Path dir(String name) throws IOException {
        Path base = Path.of(System.getProperty("java.io.tmpdir"),
                "secure-data-crypto-" + ProcessHandle.current().pid(), name);
        if (Files.exists(base)) {
            deleteRecursively(base);
        }
        Files.createDirectories(base);
        Files.setPosixFilePermissions(base, EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        if (CREATED.isEmpty()) {
            Path root = base.getParent();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    deleteRecursively(root);
                } catch (IOException ignored) {
                    // Best effort: a leaked scratch dir under /tmp is not worth failing a test run.
                }
            }, "crypto-fixtures-cleanup"));
        }
        CREATED.add(base);
        return base;
    }

    /** Everything the owner can do, so a walk can delete what it is about to remove. */
    private static final Set<PosixFilePermission> OWNER_RWX = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

    /** A file inside a private directory, with the given content and mode. */
    static Path file(String name, byte[] content, String mode) throws IOException {
        Path d = dir(name.length() % 2 == 0 ? "files-a" : "files-b");
        Path f = d.resolve(name + ".bin");
        Files.write(f, content);
        Files.setPosixFilePermissions(f, PosixFilePermissionsUtil.parse(mode));
        return f;
    }

    static void setMode(Path p, String mode) throws IOException {
        Files.setPosixFilePermissions(p, PosixFilePermissionsUtil.parse(mode));
    }

    static int mode(Path p) throws IOException {
        return (Integer) Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS);
    }

    /** Three octal digits, or four when the sticky/set-id bits matter. */
    static String modeString(Path p) throws IOException {
        return Integer.toOctalString(mode(p) & 07777);
    }

    static boolean has(Path p, PosixFilePermission perm) throws IOException {
        return Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS).contains(perm);
    }

    static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        /*
         * NOFOLLOW_LINKS matters: several tests place a symlink in the scratch directory on purpose, and
         * a walk that followed it would delete the file it points at - which, for the "symlink to a
         * passwd-shaped file" test, is a file outside the scratch tree.
         */
        try (var walk = Files.walk(root)) {
            for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) {
                try {
                    Files.setPosixFilePermissions(p, OWNER_RWX);
                } catch (IOException ignored) {
                    // A symlink has no mode to set; the delete below is what matters.
                }
                Files.deleteIfExists(p);
            }
        }
    }

    /** A high-entropy machine password, long enough to satisfy {@link KeystoreKeySource}. */
    static char[] machinePassword() {
        return "a-random-machine-secret-of-sufficient-length-9f2c".toCharArray();
    }

    /** A passphrase long enough for {@link PasswordKeySource} but obviously human-scale. */
    static char[] passphrase() {
        return "seventeen chars minimum-please-rotate-me".toCharArray();
    }

    /** Cheap but policy-legal KDF cost, so the password suite does not dominate the run time. */
    static int fastIterations() {
        return Limits.MIN_KDF_ITERATIONS;
    }

    /**
     * A classpath for a child JVM that must see the same classes this one does.
     *
     * <p>Inherit this JVM's own classpath rather than guessing {@code ./target/...}: the guess is a
     * second, independent claim about where the code lives, and it is wrong for every runner that is not
     * Maven started from the project root. A child spawned under one then dies with
     * {@code ClassNotFoundException} and the failure looks like a defect in the code under test, when the
     * only thing that went wrong is that the test assumed somebody's working directory. The inherited
     * path is also the <em>right</em> one: a harness that shadow-loads a mutated build gets the mutant in
     * the child too, instead of the child quietly testing the pristine classes.
     *
     * <p>The two {@code target} directories are appended as a fallback, so a runner that hides the real
     * classpath behind a booter jar still gets a path the child can resolve.
     */
    static String classpathForChild() {
        java.util.List<String> entries = new java.util.ArrayList<>();
        String inherited = System.getProperty("java.class.path");
        if (inherited != null && !inherited.isEmpty()) {
            for (String e : inherited.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
                if (!e.isBlank()) {
                    entries.add(e);
                }
            }
        }
        Path here = Path.of(Fixtures.class.getProtectionDomain().getCodeSource().getLocation().getPath())
                .toAbsolutePath();
        entries.add(here.toString());
        Path siblingClasses = here.getParent() == null ? null : here.getParent().resolve("classes");
        if (siblingClasses != null) {
            entries.add(siblingClasses.toString());
        }
        /* First occurrence wins, which keeps the inherited (and possibly mutated) entries in front. */
        java.util.Set<String> seen = new java.util.LinkedHashSet<>(entries);
        return String.join(java.io.File.pathSeparator, seen);
    }

    /**
     * The source of one production method, comments stripped, for the handful of invariants that live in
     * <em>structure</em> rather than behaviour and so cannot be observed through any API.
     *
     * <p>The strip is not cosmetic: the code deliberately <em>prose</em>s about the pattern a guard is
     * banning ("no does-it-exist check here on purpose"), so a naive scan finds the banned token in the
     * explanation and reports the very defect it is looking for.
     *
     * <p>Two ways this helper goes quietly wrong, both asserted against rather than assumed: it can read
     * the wrong file (so the source is located from the compiled classes, never from the working
     * directory, and an absence check over a stripped-empty corpus would pass for free), and it can read
     * the <em>pristine</em> tree while a harness mutates a copy elsewhere - which is what
     * {@code -Dsecure.data.crypto.src.main} is for. See {@link #sourceFile}.
     */
    static String methodBody(String file, String method) throws IOException {
        return methodBody(file, method, 0);
    }

    /**
     * As above, naming which match to read when the name is not unique in the file - a nested class may
     * declare the same method. {@code -1} means the last match; callers must then assert that the body
     * they got is the one they meant (a token only that method contains), or the check silently guards
     * the wrong code.
     */
    static String methodBody(String file, String method, int occurrence) throws IOException {
        String raw = Files.readString(sourceFile(file));
        String src = stripJavaComments(raw);
        assertTrue(src.length() > raw.length() / 3, "comment stripping removed almost all of " + file
                + " (" + raw.length() + " -> " + src.length() + "), so every absence check below is vacuous");
        List<Integer> hits = new ArrayList<>();
        for (int i = src.indexOf(method); i >= 0; i = src.indexOf(method, i + 1)) {
            hits.add(i);
        }
        assertTrue(!hits.isEmpty(), "method " + method + " is no longer in " + file);
        int at = occurrence < 0 ? hits.get(hits.size() + occurrence) : hits.get(occurrence);
        int brace = src.indexOf('{', at);
        assertTrue(brace > at, "no body found for " + method + " in " + file);
        int depth = 0;
        for (int i = brace; i < src.length(); i++) {
            if (src.charAt(i) == '{') {
                depth++;
            } else if (src.charAt(i) == '}') {
                depth--;
                if (depth == 0) {
                    String body = src.substring(brace, i + 1);
                    assertTrue(body.length() > 40, "suspiciously short body for " + method);
                    return body;
                }
            }
        }
        throw new AssertionError("unbalanced braces in " + file);
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    /**
     * {@code src/main/java/com/example/crypto/<file>}, found without assuming the current directory.
     *
     * <p>{@code -Dsecure.data.crypto.src.main=<dir>} overrides the location so a harness that compiles a
     * mutated copy of the sources elsewhere can point a structural guard <em>at the mutant</em>. Without
     * the override such a guard always inspects the pristine tree, and its verdict is decoration.
     */
    static Path sourceFile(String file) {
        List<Path> tried = new ArrayList<>();
        String override = System.getProperty("secure.data.crypto.src.main");
        if (override != null && !override.isBlank()) {
            tried.add(Path.of(override, "com", "example", "crypto", file));
        }
        Path here = Path.of(Fixtures.class.getProtectionDomain().getCodeSource().getLocation().getPath())
                .toAbsolutePath();
        /* .../target/test-classes -> .../target -> the project root. */
        Path parent = here.getParent();
        Path root = parent == null ? null : parent.getParent();
        if (root != null) {
            tried.add(root.resolve("src/main/java/com/example/crypto").resolve(file));
        }
        tried.add(Path.of(System.getProperty("user.dir"), "src/main/java/com/example/crypto").resolve(file));
        for (Path candidate : tried) {
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new AssertionError("cannot read the source under test, tried " + tried);
    }

    /** Removes {@code //} and {@code /* *}{@code /} comments without disturbing string or char literals. */
    static String stripJavaComments(String src) {
        StringBuilder out = new StringBuilder(src.length());
        boolean inString = false;
        boolean inChar = false;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            char n = i + 1 < src.length() ? src.charAt(i + 1) : '\0';
            if (inString) {
                out.append(c);
                if (c == '\\') {
                    if (i + 1 < src.length()) {
                        out.append(src.charAt(++i));
                    }
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (inChar) {
                out.append(c);
                if (c == '\\') {
                    if (i + 1 < src.length()) {
                        out.append(src.charAt(++i));
                    }
                } else if (c == '\'') {
                    inChar = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
                out.append(c);
            } else if (c == '\'') {
                inChar = true;
                out.append(c);
            } else if (c == '/' && n == '/') {
                while (i < src.length() && src.charAt(i) != '\n') {
                    i++;
                }
                out.append('\n');
            } else if (c == '/' && n == '*') {
                i += 2;
                while (i + 1 < src.length() && !(src.charAt(i) == '*' && src.charAt(i + 1) == '/')) {
                    i++;
                }
                i++;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    static final class PosixFilePermissionsUtil {
        private PosixFilePermissionsUtil() {
        }

        static Set<PosixFilePermission> parse(String octal) {
            int v = Integer.parseInt(octal, 8);
            Set<PosixFilePermission> out = EnumSet.noneOf(PosixFilePermission.class);
            if ((v & 0400) != 0) {
                out.add(PosixFilePermission.OWNER_READ);
            }
            if ((v & 0200) != 0) {
                out.add(PosixFilePermission.OWNER_WRITE);
            }
            if ((v & 0100) != 0) {
                out.add(PosixFilePermission.OWNER_EXECUTE);
            }
            if ((v & 0040) != 0) {
                out.add(PosixFilePermission.GROUP_READ);
            }
            if ((v & 0020) != 0) {
                out.add(PosixFilePermission.GROUP_WRITE);
            }
            if ((v & 0010) != 0) {
                out.add(PosixFilePermission.GROUP_EXECUTE);
            }
            if ((v & 0004) != 0) {
                out.add(PosixFilePermission.OTHERS_READ);
            }
            if ((v & 0002) != 0) {
                out.add(PosixFilePermission.OTHERS_WRITE);
            }
            if ((v & 0001) != 0) {
                out.add(PosixFilePermission.OTHERS_EXECUTE);
            }
            return out;
        }
    }
}
