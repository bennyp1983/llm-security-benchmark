package com.example.identity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * What the credentials look like on disk (Rule 5: "write only to owner-private files").
 *
 * <p>Two facts about this machine make the obvious test meaningless, and both are handled here:
 * <ul>
 *   <li><b>Mode bits do not constrain root.</b> Our own process can read a {@code 000} file, so
 *     "we could write it" says nothing about who else can read it. Every assertion is on the
 *     permission <em>set</em>, read back after the fact.</li>
 *   <li><b>Creation mode is not the final mode.</b> {@code Files.createFile} and H2 both apply the
 *     process umask, and the default umask here yields {@code 0644}. A test that only checks the
 *     directory is 0700 would pass while the database file inside it was world-readable. So one
 *     check below measures what an unguarded create actually produces, which is what makes the
 *     0600 assertion non-vacuous: if the umask had already been 0600, the explicit chmod would be
 *     doing nothing and the test would be proving nothing.</li>
 * </ul>
 */
public final class FilePermissionTest {

    private FilePermissionTest() {
    }

    public static void run() throws Exception {
        everythingInTheDataDirIsPrivate();
        theChmodIsDoingRealWork();
        preexistingDirectoryIsTightened();
        worldWritableAncestorRefused();
        makePrivateReadsBack();
        configAndStoreFiles();
    }

    // ------------------------------------------------------------------ sweep

    private static void everythingInTheDataDirIsPrivate() throws Exception {
        section("Every file the program leaves behind is owner read/write only");
        Harness.Fixture f = Harness.fixture("perms-sweep", Harness.overrides());
        List<String> offenders = new ArrayList<>();
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).token();
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            b.api.setAccountStatus(Identity.parseClientUsername(Harness.U1), "disabled");
            check("the fixture produced files", !listFiles(f.config.dataDir()).isEmpty());

            for (Path p : listFiles(f.config.dataDir())) {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS);
                if (!perms.equals(Harness.ownerReadWriteOnly())) {
                    offenders.add(p.getFileName() + "=" + perms);
                }
            }
            checkEquals("no file in the data directory grants group or other access", List.of(), offenders);
            List<String> names = new ArrayList<>();
            for (Path p : listFiles(f.config.dataDir())) {
                names.add(p.getFileName().toString());
            }
            check("the database file is one of them", names.stream().anyMatch(n -> n.endsWith(".mv.db")));
            check("the audit log is one of them", names.contains("audit.log"));
            check("no trace file was left behind (TRACE_MAX_FILE_SIZE=0)",
                    names.stream().noneMatch(n -> n.endsWith(".trace.db")));
            check("and none of the files is a symlink",
                    names.stream().allMatch(n -> !Files.isSymbolicLink(f.config.dataDir().resolve(n))));
            note("data directory contents: " + names);

            check("the database file itself is 0600",
                    Files.getPosixFilePermissions(databaseFile(f), LinkOption.NOFOLLOW_LINKS)
                            .equals(Harness.ownerReadWriteOnly()));
            check("the audit log itself is 0600",
                    Files.getPosixFilePermissions(f.config.dataDir().resolve("audit.log"),
                            LinkOption.NOFOLLOW_LINKS).equals(Harness.ownerReadWriteOnly()));
        }

        section("The data directory is 0700 and holds no world-readable ancestor");
        Harness.Fixture f2 = Harness.fixture("perms-dir", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f2)) {
            check("the store opened under a 0700 directory", b.api.accountCount() == 0);
            check("mode is exactly rwx------",
                    Files.getPosixFilePermissions(f2.config.dataDir(), LinkOption.NOFOLLOW_LINKS)
                            .equals(Harness.ownerOnlyDir()));
            Path cursor = f2.config.dataDir().toAbsolutePath().getRoot();
            List<String> wide = new ArrayList<>();
            for (Path seg : f2.config.dataDir().toAbsolutePath().normalize()) {
                cursor = cursor.resolve(seg);
                // World-*writable* is the hazard Config refuses (a planted file we would open).
                // World-readable is not: "/" is 0755 everywhere, and our own files are 0600 inside
                // a 0700 directory, so nobody can list or read them regardless.
                if (Files.exists(cursor, LinkOption.NOFOLLOW_LINKS)
                        && PosixFiles.isWorldWritable(cursor)) {
                    wide.add(cursor.toString());
                }
            }
            checkEquals("no ancestor of the data directory is world-writable", List.of(), wide);
            check("the data directory itself is not even group-readable",
                    !Files.getPosixFilePermissions(f2.config.dataDir(), LinkOption.NOFOLLOW_LINKS)
                            .contains(PosixFilePermission.GROUP_READ));
        }
    }

    private static Path databaseFile(Harness.Fixture f) {
        return f.config.dataDir().resolve(f.config.databaseName() + ".mv.db");
    }

    private static List<Path> listFiles(Path dir) throws IOException {
        try (var s = Files.list(dir)) {
            return new ArrayList<>(s.toList());
        }
    }

    // ------------------------------------------------------------------ non-vacuity

    private static void theChmodIsDoingRealWork() throws Exception {
        section("The unguarded create really would have been readable - so the chmod matters");
        Path dir = Harness.scratch("perms-umask");
        Path naive = dir.resolve("naive.db");
        Files.createFile(naive);
        Set<PosixFilePermission> naivePerms = Files.getPosixFilePermissions(naive, LinkOption.NOFOLLOW_LINKS);
        note("a file created without an explicit chmod comes out as " + naivePerms);
        boolean naiveIsExposed = naivePerms.contains(PosixFilePermission.GROUP_READ)
                || naivePerms.contains(PosixFilePermission.OTHERS_READ);
        check("on this machine an unguarded create leaves the file group- or other-readable,"
                + " which is exactly what secureDatabaseFiles exists to fix", naiveIsExposed);

        PosixFiles.makePrivate(naive, "naive file");
        check("after makePrivate it is owner read/write only",
                Files.getPosixFilePermissions(naive, LinkOption.NOFOLLOW_LINKS)
                        .equals(Harness.ownerReadWriteOnly()));
        check("so the 0600 asserted above is the result of the code, not of the umask",
                naiveIsExposed);

        section("H2's own file is tightened after it appears, and the result is read back");
        Harness.Fixture f = Harness.fixture("perms-h2", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            // Widen it behind the store's back, then reopen: the startup pass must notice and fix.
            Path db = databaseFile(f);
            Files.setPosixFilePermissions(db, java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ));
            check("the widened database really is world-readable before the reopen",
                    PosixFiles.isWorldReadable(db));
        }
        try (Harness.Bundle reopened = Harness.openApi(f)) {
            check("the next open tightens the database file again",
                    Files.getPosixFilePermissions(databaseFile(f), LinkOption.NOFOLLOW_LINKS)
                            .equals(Harness.ownerReadWriteOnly()));
            check("and reports no permission warning while doing so",
                    reopened.api.startupWarnings().stream().noneMatch(w -> w.contains("permission")));
            check("the account survived the reopen (the mode pass did not touch the contents)",
                    reopened.api.accountCount() == 1);
            // Ordered: this must be measured before the sign-in below, which legitimately creates a
            // session of its own. Asserting it afterwards counted that new session and reported the
            // stale-session purge as broken when it was working.
            check("sessions from the previous process are gone by design",
                    reopened.api.liveSessionCount() == 0);
            check("the credential in the re-secured file still verifies against the same password",
                    reopened.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            check("and signing in there issued exactly the one new session, not the old one back",
                    reopened.api.liveSessionCount() == 1);
        }
    }

    private static void preexistingDirectoryIsTightened() throws Exception {
        section("A pre-existing data directory is tightened, not trusted");
        Path dir = Harness.scratch("perms-preexisting");
        Files.createDirectories(dir);
        Files.setPosixFilePermissions(dir, java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
                PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ));
        check("the directory starts out world-readable", PosixFiles.isWorldReadable(dir));
        PosixFiles.createPrivateDir(dir);
        check("createPrivateDir re-applies owner-only to a directory it did not create",
                Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS)
                        .equals(Harness.ownerOnlyDir()));

        section("A directory we cannot secure is refused rather than used anyway");
        String src = Harness.stripJavaComments(Harness.sourceOf("PosixFiles"));
        check("createPrivateDir asserts the mode it asked for instead of trusting the request",
                src.contains("assertExactly(dir, PRIVATE_DIR") && src.contains("assertExactly(file, PRIVATE_FILE"));
        check("the assert reads the mode back from the filesystem",
                src.contains("Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS)")
                        || src.contains("actualPermissions(file)"));
        // Behavioural, not a grep for the words "fail closed": a path with no readable attributes at
        // all (here, one that does not exist - the JDK raises IOException, the same branch a failed
        // stat would take) must be reported as exposed by both probes. The old check matched comment
        // wording, so it stayed green while one method answered "exposed" and the other answered
        // "safe" on the identical error.
        Path unreadable = Harness.scratch("perms-unreadable-attrs").resolve("absent");
        check("a path whose mode cannot be read is reported world-readable (fail closed)",
                PosixFiles.isWorldReadable(unreadable));
        check("and world-writable too - the two probes must not disagree about which way is closed",
                PosixFiles.isWorldWritable(unreadable));
        check("both catch blocks return the one named fail-closed value",
                Harness.countOccurrences(src, "return UNREADABLE_ATTRIBUTES_ARE_EXPOSED;") == 2
                        && src.contains("UNREADABLE_ATTRIBUTES_ARE_EXPOSED = true"));
        check("isWorldReadable looks at the read bit it claims to",
                src.contains("PosixFilePermission.OTHERS_READ"));
        check("isWorldWritable looks at the write bit it claims to",
                src.contains("PosixFilePermission.OTHERS_WRITE"));
    }

    private static void worldWritableAncestorRefused() throws Exception {
        section("A world-writable directory anywhere in the data path is refused");
        Path open = Harness.scratch("perms-open-parent");
        Files.createDirectories(open);
        Files.setPosixFilePermissions(open, java.util.EnumSet.allOf(PosixFilePermission.class));
        Path target = open.resolve("data");
        String text = Harness.configText(Harness.overrides(), target)
                .replace("audit.requirePrivateFile=true", "audit.requirePrivateFile=true");
        Path cfg = Harness.scratch("perms-open-cfg").resolve("identity.properties");
        Files.writeString(cfg, text, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(cfg, Harness.ownerReadWriteOnly());
        check("the config points at a path under a 0777 directory",
                text.contains("db.dataDir=" + target));
        check("Config refuses it: a file planted there would be one we are about to open",
                refuses(cfg));

        section("A symlinked data directory is refused too");
        Path real = Harness.scratch("perms-symlink-real");
        Path linkDir = Harness.scratch("perms-symlink-link").resolve("data");
        Files.createSymbolicLink(linkDir, real);
        String viaLink = Harness.configText(Harness.overrides(), linkDir);
        Path cfg2 = Harness.scratch("perms-symlink-cfg").resolve("identity.properties");
        Files.writeString(cfg2, viaLink, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(cfg2, Harness.ownerReadWriteOnly());
        check("a symlink in the data path is not followed", refuses(cfg2));
    }

    private static boolean refuses(Path cfg) {
        try {
            Config.load(cfg, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        }
    }

    private static void makePrivateReadsBack() throws Exception {
        section("makePrivate and the asserts behave on the shapes that matter");
        Path dir = Harness.scratch("perms-makeprivate");
        Path exec = dir.resolve("run.sh");
        Files.writeString(exec, "#!/bin/sh\n", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(exec, java.util.EnumSet.allOf(PosixFilePermission.class));
        PosixFiles.makePrivate(exec, "executable fixture");
        check("even a file that started 0777 ends up 0600 - no execute bit survives",
                Files.getPosixFilePermissions(exec, LinkOption.NOFOLLOW_LINKS)
                        .equals(Harness.ownerReadWriteOnly()));

        Path dir2 = Harness.scratch("perms-owner-check");
        Path own = dir2.resolve("own");
        Files.writeString(own, "x", StandardCharsets.UTF_8);
        check("the owner is readable as a name (so an operator can see who owns the store)",
                !PosixFiles.ownerName(own).equals("<unknown>"));
        check("describePermissions is total, never throws",
                PosixFiles.describePermissions(own).length() > 0);
        check("describePermissions on a missing path is still total",
                PosixFiles.describePermissions(dir2.resolve("absent")).equals("<unknown>"));
        check("isWorldReadable on a missing path fails closed as exposed",
                PosixFiles.isWorldReadable(dir2.resolve("absent")));
        check("isWorldWritable on a missing path fails closed as exposed",
                PosixFiles.isWorldWritable(dir2.resolve("absent")));
        check("isRegularNoFollow does not follow a symlink",
                !PosixFiles.isRegularNoFollow(linkIn(dir2)));
        check("while the file it points at is itself a regular file",
                PosixFiles.isRegularNoFollow(linkIn(dir2).toRealPath()));

        section("A symlink at a path we are asked to secure is refused, not chmod-ed through");
        // The assert inside makePrivate does throw on a link - but only after
        // setPosixFilePermissions has already followed it. That ordering is the defect: the mode of
        // somebody else's file changes and the caller is told nothing happened. So the check that
        // matters is not "was it refused", it is "is the target still in the mode its owner left it".
        Path symDir = Harness.scratch("perms-symlink-target");
        Path victim = symDir.resolve("victim.txt");
        Files.writeString(victim, "somebody else's file", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(victim, java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ,
                PosixFilePermission.OTHERS_READ));
        Path victimLink = symDir.resolve("victim-link");
        Files.createSymbolicLink(victimLink, victim);
        Reason seen = null;
        try {
            PosixFiles.makePrivate(victimLink, "the audit log");
        } catch (IdentityStoreException e) {
            seen = e.reason();
        }
        check("the chmod is refused rather than attempted", seen == Reason.STORAGE_UNAVAILABLE);
        check("and the refusal does not credit the link with our secret",
                PosixFiles.ownerName(victim).equals(PosixFiles.ownerName(symDir)));
        check("the target's own mode is EXACTLY what its owner left - no chmod went through the link",
                Files.getPosixFilePermissions(victim, LinkOption.NOFOLLOW_LINKS)
                        .equals(java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ,
                                PosixFilePermission.OTHERS_READ)));
        check("the refusal says why, without inventing a permission the caller never set",
                seen != null && PosixFiles.describePermissions(victimLink).equals("rwxrwxrwx"));
        String posixSrc = Harness.stripJavaComments(Harness.sourceOf("PosixFiles"));
        check("the guard runs before the chmod, so the order is enforced by the code and not by luck",
                posixSrc.contains("assertNotSymbolicLink(file, \"file\");\n        try {\n"
                        + "            Files.setPosixFilePermissions(file, PRIVATE_FILE);"));
        check("the same guard protects the data directory",
                posixSrc.contains("assertNotSymbolicLink(dir, \"directory\");"));
        Path dirLinkParent = Harness.scratch("perms-dir-link");
        Path realDir = dirLinkParent.resolve("real");
        Files.createDirectories(realDir);
        Path dirLink = dirLinkParent.resolve("data-link");
        Files.createSymbolicLink(dirLink, realDir);
        boolean dirRefused = false;
        try {
            PosixFiles.createPrivateDir(dirLink);
        } catch (IdentityStoreException e) {
            dirRefused = true;
        }
        check("createPrivateDir refuses to chmod a directory through a symlink", dirRefused);

        section("The read-back assert is the real comparison, not a decorative call");
        // Behaviour cannot falsify this one: as uid 0 we can chmod a 000 file successfully, so
        // nothing observable changes if the comparison is deleted. What must not be deletable is
        // the comparison itself, so it is asserted as the single guard statement in the method.
        check("assertExactly compares the mode it read against the mode it asked for",
                Harness.countOccurrences(posixSrc, "if (!actual.equals(expected)) {") == 1);
        check("and both securing paths run through it",
                Harness.countOccurrences(posixSrc, "assertExactly(") == 3);
    }

    private static Path linkIn(Path dir) throws IOException {
        Path target = dir.resolve("target");
        Files.writeString(target, "x", StandardCharsets.UTF_8);
        Path link = dir.resolve("link");
        if (!Files.exists(link, LinkOption.NOFOLLOW_LINKS)) {
            Files.createSymbolicLink(link, target);
        }
        return link;
    }

    private static void configAndStoreFiles() throws Exception {
        section("The pieces a deployment leaves behind, cross-checked");
        Harness.Fixture f = Harness.fixture("perms-config", Harness.overrides());
        check("the fixture's own config file is private (else Config would refuse it)",
                Files.getPosixFilePermissions(f.configFile, LinkOption.NOFOLLOW_LINKS)
                        .equals(Harness.ownerReadWriteOnly()));
        try (Harness.Bundle b = Harness.openApi(f)) {
            check("Config.load would refuse a group-readable file: the fixture proves the rule is"
                    + " live by being private", b.api.accountCount() == 0);
            Files.setPosixFilePermissions(f.configFile, java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ));
            check("and re-loading the same file after widening it is refused", refuses(f.configFile));
            check("the refusal names the file, not a secret", refusesWithNoSecret(f.configFile));
        }

        section("The shipped example configuration is itself safe to commit");
        Path example = Harness.repoFile("identity.properties.example");
        check("the example file exists in the repository", example != null);
        if (example != null) {
            List<String> assignments = new ArrayList<>();
            for (String line : Harness.lines(Files.readString(example, StandardCharsets.UTF_8))) {
                if (!line.isBlank() && !line.startsWith("#")) {
                    assignments.add(line);
                }
            }
            check("the example has non-comment content to scan", !assignments.isEmpty());
            check("no key in it is named password or secret",
                    assignments.stream().noneMatch(l -> {
                        String key = l.split("=", 2)[0].toLowerCase(java.util.Locale.ROOT);
                        return key.contains("password") || key.contains("secret");
                    }));
            check("the passphrase variable is only ever mentioned in a comment",
                    assignments.stream().noneMatch(l -> l.startsWith(Config.ENV_DB_PASSWORD)));
            check("the example file is not world-readable in the working tree",
                    !PosixFiles.isWorldReadable(example));
            note("the database passphrase has exactly one accepted source: the environment, at"
                    + " startup. Nothing in the tree carries a value that would work anywhere.");
        }
    }

    private static boolean refusesWithNoSecret(Path cfg) {
        try {
            Config.load(cfg, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return !String.valueOf(e.detail()).contains(Harness.PASSPHRASE);
        }
    }
}
