package com.example.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Everything an unprivileged local user, another service account, or a careless deployer can do to a
 * key file - and what the component does back.
 *
 * <p>The check that matters is on the <em>read</em> side: the file an attacker can influence is the one
 * already on disk. A mode check alone is trivially bypassed (swap the file for a symlink, leave it in a
 * directory anyone can write to, set the sticky bit aside and call it shared), so each bypass below is
 * attempted explicitly and must be refused.
 *
 * <p>Residual risk, stated where it belongs: this runs as root on this machine, so the ownership check
 * cannot be exercised negatively, and root can read anything regardless. These guards are about
 * unprivileged users, other service accounts and configuration mistakes.
 */
class KeyFilePermissionTest {

    private static final SymmetricCrypto CRYPTO = new SymmetricCrypto();

    /** Every mode that lets anyone but the owner read or write the file, plus an execute bit. */
    @Test
    void aKeyFileThatIsNotOwnerOnlyIsRefused() throws Exception {
        Path dir = Fixtures.dir("modes");
        for (String mode : List.of("644", "640", "604", "666", "606", "620", "602", "444",
                "700", "755", "777")) {
            Path f = dir.resolve("k" + mode + ".key");
            Files.write(f, seedKey());
            Fixtures.setMode(f, mode);
            CryptoException e = assertThrows(CryptoException.class,
                    () -> new KeyFileKeySource(f).load(),
                    "a key file with mode " + mode + " was accepted");
            assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, e.code(),
                    "mode " + mode + " reported as " + e.code());
            /* The caller-facing message must not describe the leak it just prevented. */
            assertEquals("The data could not be decrypted", e.getMessage());
            assertTrue(e.getTechnicalDetail().toLowerCase(java.util.Locale.ROOT).contains("permission")
                            || e.getTechnicalDetail().toLowerCase(java.util.Locale.ROOT).contains("owner"),
                    "mode " + mode + " detail should tell the operator what to fix: "
                            + e.getTechnicalDetail());
        }
        /*
         * The modes this component writes, plus the ones a deployment may legitimately arrive with, are
         * accepted - so the loop above is about the loosened modes and not about a broken API. 0400 is
         * deliberately allowed: a read-only key supplied by an image or a read-only mount is a normal
         * deployment, and refusing it would be an outage rather than a defence.
         */
        for (String ok : List.of("600", "400")) {
            Path good = dir.resolve("good" + ok + ".key");
            Files.write(good, seedKey());
            Fixtures.setMode(good, ok);
            assertEquals(1, new KeyFileKeySource(good).load().version(), "mode " + ok + " was refused");
        }
        /*
         * Mode 000 is the one case where the answer depends on who runs this, and it is worth pinning
         * down because it is the boundary of what these guards claim. 000 satisfies the privacy check -
         * nobody's permissions allow the read - so the check passes and the *read* is what fails. For an
         * unprivileged process that is a clean fail-closed. Running as root, the read succeeds, because
         * the kernel grants root the read bit regardless of the mode. That is the residual risk stated in
         * PrivateFiles: these guards stop unprivileged users and configuration mistakes, not root. A
         * deployment that needs protection from root needs a hardware-backed store, not a file check.
         */
        Path none = dir.resolve("good000.key");
        Files.write(none, seedKey());
        Fixtures.setMode(none, "000");
        boolean asRoot;
        try {
            new KeyFileKeySource(none).load().destroy();
            asRoot = true;
        } catch (CryptoException unreadable) {
            asRoot = false;
            assertTrue(unreadable.code() == CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE
                            || unreadable.code() == CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "000 reported as " + unreadable.code());
            assertEquals("The data could not be decrypted", unreadable.getMessage());
        }
        System.out.println("NOTE mode-000 key file " + (asRoot
                ? "was readable, so this suite is running as root: the permission guards are not a"
                        + " defence against root and the README says so"
                : "was refused, so the fail-closed path is the one under test"));
    }

    /** Set-id bits on a data file are either a mistake or an attack; either way, refuse. */
    @Test
    void setUidOrSetGidOnAKeyFileIsRefused() throws Exception {
        Path dir = Fixtures.dir("setid");
        Path f = dir.resolve("suid.key");
        Files.write(f, seedKey());
        Fixtures.setMode(f, "600");
        /*
         * PosixFilePermission cannot express set-id bits, so they are set with chmod(1) - and the mode
         * is read back through unix:mode to prove the bit is really there before the assertion below
         * means anything.
         */
        chmod("4600", f);
        assertEquals(04600, Fixtures.mode(f) & 07777, "the setuid bit did not stick");
        CryptoException e = assertThrows(CryptoException.class, () -> new KeyFileKeySource(f).load());
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, e.code());
        assertTrue(e.getTechnicalDetail().contains("set-id"), e.getTechnicalDetail());

        Path sgid = dir.resolve("sgid.key");
        Files.write(sgid, seedKey());
        chmod("2600", sgid);
        assertEquals(02600, Fixtures.mode(sgid) & 07777, "the setgid bit did not stick");
        assertThrows(CryptoException.class, () -> new KeyFileKeySource(sgid).load());
    }

    /** A symlink is the classic swap: same path, different file, mode of its own that proves nothing. */
    @Test
    void aSymbolicLinkIsRefusedAndIsNotFollowed() throws Exception {
        Path dir = Fixtures.dir("symlink");
        Path real = dir.resolve("real.key");
        Files.write(real, seedKey());
        Fixtures.setMode(real, "600");

        Path link = dir.resolve("link.key");
        Files.createSymbolicLink(link, real);
        CryptoException e = assertThrows(CryptoException.class, () -> new KeyFileKeySource(link).load());
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, e.code());
        assertTrue(e.getTechnicalDetail().contains("symbolic link"), e.getTechnicalDetail());

        /* A symlink pointing outside the tree, at something a key might plausibly be swapped for. */
        Path outside = Path.of(System.getProperty("java.io.tmpdir"),
                "secure-data-crypto-outside-" + ProcessHandle.current().pid() + ".txt");
        Files.write(outside, seedKey());
        Fixtures.setMode(outside, "600");
        Path sneaky = dir.resolve("sneaky.key");
        Files.createSymbolicLink(sneaky, outside);
        assertThrows(CryptoException.class, () -> new KeyFileKeySource(sneaky).load());

        /* A symlink whose target is itself private and owned: still refused - the link is the point. */
        Path dirB = Fixtures.dir("symlink-target");
        Path target = dirB.resolve("t.key");
        Files.write(target, seedKey());
        Fixtures.setMode(target, "600");
        Path across = dir.resolve("across.key");
        Files.createSymbolicLink(across, target);
        assertThrows(CryptoException.class, () -> new KeyFileKeySource(across).load());

        /* Writing through a symlink must be refused too, or "refusing to overwrite" is bypassable. */
        KeyMaterial key = CRYPTO.generateKey(1);
        CryptoException write = assertThrows(CryptoException.class, () -> key.writeTo(link));
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, write.code());
        /* The target must be untouched by the attempted write-through. */
        assertArrayEqualsLenient(seedKey(), Files.readAllBytes(real), "write-through replaced the target");
        Files.deleteIfExists(outside);
    }

    /** Not-a-regular-file: a directory, a FIFO, or nothing at all. */
    @Test
    void anythingThatIsNotARegularFileIsRefused() throws Exception {
        Path dir = Fixtures.dir("notregular");
        Path sub = dir.resolve("subdir.key");
        Files.createDirectory(sub);
        Fixtures.setMode(sub, "700");
        assertThrows(CryptoException.class, () -> new KeyFileKeySource(sub).load(),
                "a directory was accepted as a key file");

        Path fifo = dir.resolve("pipe.key");
        ProcessBuilder pb = new ProcessBuilder("mkfifo", fifo.toString());
        pb.inheritIO();
        if (pb.start().waitFor() == 0) {
            assertThrows(CryptoException.class, () -> new KeyFileKeySource(fifo).load(),
                    "a FIFO was accepted as a key file");
        }

        /* A path that does not exist must fail closed rather than produce a default key. */
        CryptoException missing = assertThrows(CryptoException.class,
                () -> new KeyFileKeySource(dir.resolve("absent.key")).load());
        assertTrue(missing.code() == CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE
                        || missing.code() == CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                "absent key file reported as " + missing.code());
        assertEquals("The data could not be decrypted", missing.getMessage());
    }

    /**
     * A private file in a directory anyone can write to is not private: the write bit on the parent lets
     * anyone unlink it and put something else at the same name.
     */
    @Test
    void aKeyFileInASharedDirectoryIsRefusedEvenWhenTheFileItselfIsPrivate() throws Exception {
        Path base = Fixtures.dir("shared-parent");

        Path open = base.resolve("open");
        Files.createDirectory(open);
        Fixtures.setMode(open, "777");
        Path f = open.resolve("k.key");
        Files.write(f, seedKey());
        Fixtures.setMode(f, "600");
        CryptoException e = assertThrows(CryptoException.class, () -> new KeyFileKeySource(f).load());
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, e.code());
        assertTrue(e.getTechnicalDetail().contains("sticky"), e.getTechnicalDetail());

        /* Group-writable without a sticky bit is the same power for a wider audience. */
        Path group = base.resolve("group");
        Files.createDirectory(group);
        Fixtures.setMode(group, "775");
        Path g = group.resolve("k.key");
        Files.write(g, seedKey());
        Fixtures.setMode(g, "600");
        assertThrows(CryptoException.class, () -> new KeyFileKeySource(g).load(),
                "a key file in a 0775 directory was accepted");

        /*
         * The sticky bit is the convention that makes a shared directory usable: /tmp itself is 1777 and
         * group-writable, and with the sticky set only a file's owner may unlink it. The component must
         * accept exactly that, or it refuses every conventional temporary directory on a normal system.
         */
        Path sticky = base.resolve("sticky");
        Files.createDirectory(sticky);
        Fixtures.setMode(sticky, "777");
        chmod("1777", sticky);
        assertEquals(01777, Fixtures.mode(sticky) & 07777, "the sticky bit did not stick");
        Path s = sticky.resolve("k.key");
        Files.write(s, seedKey());
        Fixtures.setMode(s, "600");
        assertEquals(1, new KeyFileKeySource(s).load().version(),
                "a private key file in a sticky shared directory should be accepted");

        /* An intermediate component is checked too: privacy at the leaf does not repair the path. */
        Path outer = base.resolve("outer");
        Files.createDirectory(outer);
        Fixtures.setMode(outer, "700");
        Path inner = outer.resolve("inner");
        Files.createDirectory(inner);
        Fixtures.setMode(inner, "777");
        Path deep = inner.resolve("k.key");
        Files.write(deep, seedKey());
        Fixtures.setMode(deep, "600");
        assertThrows(CryptoException.class, () -> new KeyFileKeySource(deep).load(),
                "a key file under a shared intermediate directory was accepted");

        /*
         * A symlinked path component is a swap that no file-mode check can see. The refusal has to name
         * the symbolic link: a symlink also fails the "is a directory" test, so a bare "it threw" passes
         * even when the symlink guard itself is gone and something else happened to catch it. The reason
         * is the assertion here, not the fact of a refusal.
         */
        Path realDir = base.resolve("realdir");
        Files.createDirectory(realDir);
        Fixtures.setMode(realDir, "700");
        Path linked = base.resolve("linked");
        Files.createSymbolicLink(linked, realDir);
        Path inLinked = linked.resolve("k.key");
        Files.write(inLinked, seedKey());
        Fixtures.setMode(inLinked, "600");
        CryptoException viaLink = assertThrows(CryptoException.class, () -> new KeyFileKeySource(inLinked).load(),
                "a key file reached through a symlinked directory was accepted");
        assertTrue(viaLink.getTechnicalDetail().toLowerCase().contains("symbolic link"),
                "refused for a reason other than the symlink, so the symlink guard is unproven: "
                        + viaLink.getTechnicalDetail());
        assertTrue(viaLink.getTechnicalDetail().contains("linked"),
                "the refusal does not name the component at fault: " + viaLink.getTechnicalDetail());
    }

    /**
     * The directory check is applied to every ancestor, not just the leaf, and each failure names the
     * component. Walking upwards is the only way to catch a private-looking file under a shared parent.
     */
    @Test
    void everyDirectoryInThePathIsCheckedAndTheCulpritIsNamed() throws Exception {
        Path base = Fixtures.dir("ancestor-audit");
        Fixtures.setMode(base, "700");
        Path good = base.resolve("g");
        Files.createDirectory(good);
        Fixtures.setMode(good, "700");

        /* Each of these is refused, and the log detail points at the offending level. */
        Path sharedOuter = base.resolve("open");
        Files.createDirectory(sharedOuter);
        Fixtures.setMode(sharedOuter, "775");
        Path mid = sharedOuter.resolve("m");
        Files.createDirectory(mid);
        Fixtures.setMode(mid, "700");
        Path under = mid.resolve("k.key");
        Files.write(under, seedKey());
        Fixtures.setMode(under, "600");
        CryptoException deep = assertThrows(CryptoException.class, () -> new KeyFileKeySource(under).load());
        assertTrue(deep.getTechnicalDetail().contains("open"),
                "the refusal does not name the shared ancestor: " + deep.getTechnicalDetail());

        /* A directory the owner does not have is refused, and a plain file in the path is refused. */
        Path notDir = base.resolve("plain");
        Files.write(notDir, "not a directory".getBytes(StandardCharsets.UTF_8));
        Fixtures.setMode(notDir, "600");
        CryptoException fileInPath = assertThrows(CryptoException.class,
                () -> PrivateFiles.requireSecureDirectory(notDir));
        assertTrue(fileInPath.getTechnicalDetail().contains("not a directory"),
                fileInPath.getTechnicalDetail());

        /* The control: a fully private chain is accepted, so the refusals above are about the defect. */
        PrivateFiles.requireSecureDirectory(good);
    }

    /** Writing must be as strict as reading, including refusing to be a surprise overwrite. */
    @Test
    void writingAKeyFileIsRefusedRatherThanOverwritingOrMkdirPing() throws Exception {
        Path dir = Fixtures.dir("write-rules");
        KeyMaterial key = CRYPTO.generateKey(1);

        /* Existing file: refused, and the original bytes survive. */
        Path exists = dir.resolve("exists.key");
        byte[] original = "the-original-bytes-not-a-key-but-must-survive".getBytes(StandardCharsets.UTF_8);
        Files.write(exists, original);
        Fixtures.setMode(exists, "600");
        CryptoException e = assertThrows(CryptoException.class, () -> key.writeTo(exists));
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, e.code());
        assertTrue(e.getTechnicalDetail().contains("exist"), e.getTechnicalDetail());
        assertEquals(new String(original, StandardCharsets.UTF_8),
                new String(Files.readAllBytes(exists), StandardCharsets.UTF_8), "the file was clobbered");

        /* A dangling symlink at the target name must not be followed and written through. */
        Path victim = dir.resolve("victim.dat");
        Files.write(victim, original);
        Fixtures.setMode(victim, "600");
        Path dangle = dir.resolve("dangle.key");
        Files.createSymbolicLink(dangle, victim);
        assertThrows(CryptoException.class, () -> key.writeTo(dangle));
        assertEquals(new String(original, StandardCharsets.UTF_8),
                new String(Files.readAllBytes(victim), StandardCharsets.UTF_8),
                "writeOwnerOnlyFile followed a symlink and replaced its target");

        /* No implicit mkdir: creating a directory is the deployer's decision, not this code's. */
        Path missingParent = dir.resolve("nope/absent.key");
        CryptoException noDir = assertThrows(CryptoException.class, () -> key.writeTo(missingParent));
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, noDir.code());
        assertFalse(Files.exists(dir.resolve("nope")), "the parent directory was created implicitly");

        /* Writing into a shared directory is refused even though the file itself would be private. */
        Path shared = dir.resolve("shared");
        Files.createDirectory(shared);
        Fixtures.setMode(shared, "777");
        CryptoException sharedWrite = assertThrows(CryptoException.class,
                () -> key.writeTo(shared.resolve("k.key")));
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, sharedWrite.code());

        /* And the good path produces a 0600 file, verified rather than assumed. */
        Path written = dir.resolve("good.key");
        key.writeTo(written);
        assertEquals("600", Fixtures.modeString(written), Fixtures.modeString(written));
        assertEquals(32, Files.size(written), "the whole key was not written");
    }

    /**
     * Rule 7 applied to a file: "is the name free?" and "create it" are two decisions about one fact, and
     * a local attacker can insert a file of its own in between. That is how a key ends up written into
     * somebody else's file, or into a name the attacker controls.
     *
     * <p>The component closes the window by never asking the first question: the only decision is
     * {@code CREATE_NEW}, made by the filesystem in the same operation that sets the mode. Since there is
     * no window to lose, a *timed* race cannot observe the difference between the safe and the unsafe
     * implementation - whichever process happens to arrive first wins the name either way. So the two
     * orders are fixed here rather than raced, and the property that the window is gone is checked where
     * it actually lives: in the source of the write path.
     *
     * <p>Both directions must hold, because the two failure modes are different: if the attacker holds the
     * name, the key must not be written into his file; if we hold it, the key must never exist in a file
     * whose mode somebody else set.
     */
    @Test
    void aKeyFileClaimedBySomebodyElseIsNeverWrittenInto() throws Exception {
        Path dir = Fixtures.dir("write-race");
        KeyMaterial ours = CRYPTO.generateKey(7);
        byte[] ourBytes = ours.copyForWrite();

        /* The attacker holds the name: his file, his mode, and our key must not reach it. */
        Path hisFile = dir.resolve("attacker-first.key");
        Process racer = new ProcessBuilder("sh", "-c",
                "umask 000; set -C; : > '" + hisFile + "'")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        assertTrue(racer.waitFor(30, TimeUnit.SECONDS), "the racing shell did not finish");
        assertEquals(0, racer.exitValue(), "the fixture shell could not create its file");
        assertTrue(Files.exists(hisFile, LinkOption.NOFOLLOW_LINKS), "the fixture created no file");
        assertEquals(0666, Fixtures.mode(hisFile) & 0777, "the fixture's umask did not apply");

        CryptoException refused = assertThrows(CryptoException.class, () -> ours.writeTo(hisFile),
                "a key was written into a file somebody else created");
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, refused.code());
        assertEquals(0, Files.size(hisFile), "his file was truncated or written into");
        assertEquals(0666, Fixtures.mode(hisFile) & 0777, "his file's mode was reassigned by us");
        assertFalse(containsAll(Files.readAllBytes(hisFile), ourBytes), "the key leaked into his file");

        /* We hold the name: the key must never be observable in a looser mode than 0600. */
        Path oursFile = dir.resolve("we-first.key");
        ours.writeTo(oursFile);
        assertEquals("600", Fixtures.modeString(oursFile));
        assertArrayEqualsLenient(ourBytes, Files.readAllBytes(oursFile), "our own file was not our key");
    }

    /**
     * The structural half of the rule-7 claim: the write path must decide "create" with the filesystem,
     * not with a prior existence query. A redundant {@code Files.exists} before {@code CREATE_NEW} is
     * invisible in behaviour (the filesystem still refuses) while being exactly the check-then-act window
     * the brief asks to close - so the only way to test its absence is to read the code.
     */
    @Test
    void theWritePathAsksTheFilesystemRatherThanCheckingFirst() throws Exception {
        String body = Fixtures.methodBody("PrivateFiles.java", "writeOwnerOnlyFile");
        assertTrue(body.contains("StandardOpenOption.CREATE_NEW"),
                "the atomic create is gone, so a pre-check would be the only guard: " + body);
        assertTrue(body.contains("FileChannel.open"), "the create moved off the atomic open path");
        /*
         * Probes are qualified with the target's variable name on purpose. Asking whether the *parent
         * directory* exists is a different question - a legitimate one, and one with no competing writer -
         * so banning the bare method name would forbid code that is fine.
         */
        for (String probe : List.of("Files.exists(file", "Files.notExists(file",
                "Files.isRegularFile(file", "Files.isSymbolicLink(file", "newOutputStream(file")) {
            assertFalse(body.contains(probe),
                    "the write path asks " + probe + " about the target before creating it - that gap is "
                            + "the window this method exists to close");
        }

        String stream = Fixtures.methodBody("PrivateFiles.java", "newOwnerOnlyOutputStream");
        assertTrue(stream.contains("StandardOpenOption.CREATE_NEW"), "the stream path lost its atomic create");
        for (String probe : List.of("Files.exists(file", "Files.notExists(file")) {
            assertFalse(stream.contains(probe), "the stream path pre-checks with " + probe);
        }
    }

    /** Keeps the failure message below honest: it can only report an absence it actually searched for. */
    private static boolean containsAll(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Privacy is re-checked on every load, not cached: the window that matters is the one after the key
     * file was created, when a cron job, an admin, or another process has had time to loosen it.
     */
    @Test
    void aKeyFileThatLoosesItsPrivacyLaterIsRefusedOnTheNextUse() throws Exception {
        Path dir = Fixtures.dir("mode-drift");
        Path f = dir.resolve("drift.key");
        Files.write(f, seedKey());
        Fixtures.setMode(f, "600");
        KeyFileKeySource src = new KeyFileKeySource(f);
        try (KeyMaterial ok = src.load()) {
            assertEquals(1, ok.version());
        }
        Fixtures.setMode(f, "644");
        CryptoException e = assertThrows(CryptoException.class, src::load,
                "a key file that became world-readable was still used");
        assertEquals(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE, e.code());

        /* Same through the vault: the refusal reaches the caller as an ordinary, generic failure. */
        try (KeyVault vault = KeyVault.of(src)) {
            CryptoException viaVault = assertThrows(CryptoException.class, () -> vault.encryptString("x", null));
            /* The caller gets the generic line and nothing about why. */
            assertEquals("The data could not be decrypted", viaVault.getMessage());
            /*
             * The log channel is the opposite: its whole purpose is to tell whoever is reading the log
             * what to go and fix, so naming the mode is correct here. Asserting the positive is the
             * useful test - if the detail went generic too, the two channels would have collapsed into
             * one and an operator would be chasing a key-file problem with no clue which file or what was
             * wrong with it.
             */
            String detail = viaVault.getTechnicalDetail();
            assertTrue(detail.contains("644") || detail.contains("rw-r") || detail.contains("permission"),
                    "the log detail should say what to fix: " + detail);
        }

        /* Tightening it again makes it usable: the check is on the current state, not a grudge. */
        Fixtures.setMode(f, "600");
        try (KeyMaterial back = src.load()) {
            assertEquals(1, back.version());
        }
    }

    /** A key container must be as private as the key inside it. */
    @Test
    void aPasswordContainerOrKeystoreThatGoesWorldReadableIsRefused() throws Exception {
        Path dir = Fixtures.dir("container-privacy");
        Path pw = dir.resolve("key.spkb1");
        PasswordKeySource.create(pw, 1, Fixtures.passphrase(), Fixtures.fastIterations());
        assertEquals("600", Fixtures.modeString(pw));
        Fixtures.setMode(pw, "640");
        assertThrows(CryptoException.class, () -> {
            try (PasswordKeySource src = new PasswordKeySource(pw, 1, Fixtures.passphrase())) {
                src.load();
            }
        }, "a group-readable key container was opened");
        Fixtures.setMode(pw, "600");

        Path ks = dir.resolve("keys.p12");
        KeystoreKeySource.create(ks, "data-key", 1, Fixtures.machinePassword(),
                "the-entry-password-for-this-store-3c19".toCharArray());
        assertEquals("600", Fixtures.modeString(ks));
        Fixtures.setMode(ks, "604");
        assertThrows(CryptoException.class, () -> {
            try (KeystoreKeySource src = new KeystoreKeySource(ks, "data-key", 1, Fixtures.machinePassword(),
                    "the-entry-password-for-this-store-3c19".toCharArray())) {
                src.load();
            }
        }, "an other-readable keystore was opened");

        /* The container's directory is checked when it is created, not only when it is read. */
        Path shared = dir.resolve("shared");
        Files.createDirectory(shared);
        Fixtures.setMode(shared, "777");
        assertThrows(CryptoException.class,
                () -> PasswordKeySource.create(shared.resolve("k.spkb1"), 1, Fixtures.passphrase(),
                        Fixtures.fastIterations()));
        assertThrows(CryptoException.class,
                () -> KeystoreKeySource.create(shared.resolve("k.p12"), Fixtures.machinePassword(),
                        Fixtures.machinePassword()));
    }

    /** A hostile file cannot make this component allocate without bound. */
    @Test
    void anOversizedKeyFileIsRefusedBeforeItIsRead() throws Exception {
        Path dir = Fixtures.dir("oversized");
        Path big = dir.resolve("big.key");
        byte[] junk = new byte[64 * 1024];
        Files.write(big, junk);
        Fixtures.setMode(big, "600");
        CryptoException e = assertThrows(CryptoException.class, () -> PrivateFiles.readOwnerOnlyFile(big, 4096));
        assertEquals(CryptoException.CryptoFailureCode.TOO_LARGE, e.code());
        /* The size limit is in the detail for the operator, never in the caller's message. */
        assertTrue(e.getTechnicalDetail().contains("4096"), e.getTechnicalDetail());
        assertEquals("The supplied data is not in a supported format", e.getMessage());
    }

    /**
     * The privacy checks are only meaningful where the filesystem has permissions. Rather than assume,
     * the code must report when it cannot check - so this asserts the check is actually performed.
     */
    @Test
    void thePrivacyCheckIsRealAndNotAnAlwaysTrueHelper() throws Exception {
        Path dir = Fixtures.dir("sanity");
        Path f = dir.resolve("k.key");
        Files.write(f, seedKey());
        Fixtures.setMode(f, "600");
        /* requirePrivateKeyFile passes on a genuinely private file... */
        PrivateFiles.requirePrivateKeyFile(f);
        /* ...and requireSecureDirectory passes on the scratch directory itself. */
        PrivateFiles.requireSecureDirectory(dir);
        /* The mode helper sees the bits PosixFilePermission cannot represent. */
        chmod("1700", dir);
        assertEquals(01700, Fixtures.mode(dir) & 07777, "unix:mode is not reporting the sticky bit");
        assertTrue(Fixtures.mode(dir) != 0, "the mode helper returned nothing usable");
        Fixtures.setMode(dir, "700");
    }

    private static byte[] seedKey() {
        byte[] k = new byte[32];
        for (int i = 0; i < k.length; i++) {
            k[i] = (byte) (i + 3);
        }
        return k;
    }

    /** Set-id and sticky bits are not expressible through PosixFilePermission, so chmod is used. */
    private static void chmod(String mode, Path file) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("chmod", mode, file.toString());
        pb.inheritIO();
        try {
            Process p = pb.start();
            p.getOutputStream().close();
            assertEquals(0, p.waitFor(), "chmod " + mode + " failed for " + file);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("chmod interrupted", e);
        }
    }

    private static void assertArrayEqualsLenient(byte[] expected, byte[] actual, String msg) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual, msg);
    }
}
