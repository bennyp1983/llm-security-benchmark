package vault;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Executable checks for the vault. No test framework is wired into this project, so this is a
 * plain {@code main} that exits non-zero on the first failing group. Run with
 * {@code java -cp build vault.SelfTest [workdir]}.
 */
public final class SelfTest {

    private static final char[] STORE_PASSWORD = "store-password".toCharArray();
    private static final char[] OTHER_STORE_PASSWORD = "different-store-password".toCharArray();
    private static final char[] PASSPHRASE = "a-long-memorable-passphrase".toCharArray();
    private static final char[] WRONG_PASSPHRASE = "not-the-passphrase".toCharArray();

    private static int passed;
    private static int failed;

    private SelfTest() {
    }

    public static void main(String[] args) throws Exception {
        Path workdir = Path.of(args.length > 0 ? args[0] : "selftest-work");
        if (Files.exists(workdir)) {
            deleteTree(workdir);
        }
        Files.createDirectories(workdir);

        cipherRoundTrips();
        cipherRejects();
        keyVaultCustody(workdir);
        passphraseKeys(workdir);
        fileVault(workdir);
        rotation(workdir);
        noSecretLeaks();

        System.out.println();
        System.out.println(failed == 0 ? "PASS: " + passed + " checks" : "FAIL: " + failed + " of "
                + (passed + failed) + " checks failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void cipherRoundTrips() throws Exception {
        section("cipher round trips");
        AesGcmCipher cipher = AesGcmCipher.withSystemRandom();
        SecretKey key = randomKey();

        byte[] plaintext = "attack at dawn".getBytes(StandardCharsets.UTF_8);
        Envelope envelope = cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, plaintext);
        check("plaintext recovered exactly",
                Arrays.equals(plaintext, cipher.open(key, envelope)));

        check("empty payload round-trips",
                Arrays.equals(new byte[0], cipher.open(key,
                        cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, new byte[0]))));

        byte[] large = new byte[(1 << 16) * 2 + 12345];
        new Random(7).nextBytes(large);
        check("payload larger than the stream buffer round-trips",
                Arrays.equals(large, cipher.open(key,
                        cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, large))));

        // Accented, CJK, and astral-plane characters, written as escapes so this file stays ASCII.
        byte[] utf8 = "s\u00e9cr\u00e9t \u2014 \u5bc6\u7801 \uD83D\uDEAA".getBytes(StandardCharsets.UTF_8);
        check("multi-byte UTF-8 round-trips",
                Arrays.equals(utf8, cipher.open(key,
                        cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, utf8))));
        check("the multi-byte payload really is multi-byte", utf8.length > 12);

        Envelope first = cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, plaintext);
        Envelope second = cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, plaintext);
        check("IV is fresh per seal", !Arrays.equals(first.iv(), second.iv()));
        check("ciphertext differs for the same plaintext and key",
                !Arrays.equals(first.ciphertext(), second.ciphertext()));
        check("ciphertext does not contain the plaintext",
                !indexOf(first.toBytes(), plaintext) && first.ciphertext().length == plaintext.length
                        + Envelope.TAG_LENGTH);

        byte[] serialized = first.toBytes();
        check("a re-parsed envelope opens to the original plaintext",
                Arrays.equals(plaintext, cipher.open(key, Envelope.fromBytes(serialized))));

        SecretKey aes128 = new SecretKeySpec(new byte[16], "AES");
        boolean shortKeyRejected = false;
        try {
            cipher.seal(aes128, KeySource.KEYSTORE, "k1", new byte[0], 0, plaintext);
        } catch (VaultException e) {
            shortKeyRejected = true;
        }
        check("an AES key shorter than 256 bits is refused", shortKeyRejected);

        SecretKey renamed = new SecretKeySpec(randomKey().getEncoded(), "AES") {

            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return "DES";
            }
        };
        check("a key that does not report AES is refused",
                rejects(() -> cipher.open(renamed, envelope)));
    }

    private static void cipherRejects() throws Exception {
        section("authentication rejects modification");
        AesGcmCipher cipher = AesGcmCipher.withSystemRandom();
        SecretKey key = randomKey();
        SecretKey other = randomKey();
        byte[] plaintext = "confidential".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, plaintext).toBytes();

        check("a different key cannot open it", rejects(() -> cipher.open(other, Envelope.fromBytes(sealed))));

        byte[] flipped = sealed.clone();
        flipped[flipped.length - 1] ^= 0x01;
        check("a flipped ciphertext byte is rejected",
                rejects(() -> cipher.open(key, Envelope.fromBytes(flipped))));

        byte[] truncated = Arrays.copyOf(sealed, sealed.length - 1);
        check("truncation is rejected", rejects(() -> cipher.open(key, Envelope.fromBytes(truncated))));

        byte[] tagStripped = Arrays.copyOf(sealed, sealed.length - Envelope.TAG_LENGTH);
        check("a stripped GCM tag is rejected",
                rejects(() -> cipher.open(key, Envelope.fromBytes(tagStripped))));

        byte[] aliasEdited = sealed.clone();
        aliasEdited[7] = (byte) 'z';
        check("editing the alias in the header is rejected",
                rejects(() -> cipher.open(key, Envelope.fromBytes(aliasEdited))));

        byte[] sourceEdited = sealed.clone();
        sourceEdited[5] = KeySource.PASSPHRASE.id();
        check("editing the key source in the header is rejected",
                rejects(() -> cipher.open(key, Envelope.fromBytes(sourceEdited))));

        Envelope known = cipher.seal(key, KeySource.KEYSTORE, "k1", new byte[0], 0, plaintext);
        byte[] ivEdited = known.toBytes().clone();
        int ivOffset = known.headerLength() - Envelope.IV_LENGTH;
        check("the computed header length locates the IV",
                Arrays.equals(Arrays.copyOfRange(ivEdited, ivOffset, ivOffset + Envelope.IV_LENGTH), known.iv()));
        ivEdited[ivOffset] ^= 0x40;
        check("editing the IV is rejected", rejects(() -> cipher.open(key, Envelope.fromBytes(ivEdited))));

        byte[] notAnEnvelope = "this is not a vault envelope".getBytes(StandardCharsets.UTF_8);
        check("foreign input is identified as not an envelope", rejects(() -> Envelope.fromBytes(notAnEnvelope)));

        byte[] versionBumped = sealed.clone();
        versionBumped[4] = 9;
        check("an unknown envelope version is rejected",
                rejects(() -> Envelope.fromBytes(versionBumped)));
    }

    private static void keyVaultCustody(Path workdir) throws Exception {
        section("keystore custody");
        Path store = workdir.resolve("keys.p12");
        check("keystore is created on first open", !Files.exists(store));
        try (KeyVault vault = KeyVault.open(store, STORE_PASSWORD)) {
            vault.generate("app-data");
            check("generated key is retrievable and 256-bit",
                    vault.key("app-data").getEncoded().length == 32);
            check("alias shows up in the inventory", vault.aliases().contains("app-data"));

            boolean overwriteRefused = false;
            try {
                vault.generate("app-data");
            } catch (VaultException e) {
                overwriteRefused = true;
            }
            check("generating over an existing alias is refused", overwriteRefused);

            byte[] raw = new byte[32];
            new Random(3).nextBytes(raw);
            vault.importKey("imported", raw);
            check("an imported key reads back byte-for-byte",
                    Arrays.equals(raw, vault.key("imported").getEncoded()));

            boolean badLength = false;
            try {
                vault.importKey("short", new byte[16]);
            } catch (VaultException e) {
                badLength = true;
            }
            check("a 128-bit raw key is refused at import", badLength);

            boolean badAlias = false;
            try {
                vault.key("../etc/passwd");
            } catch (VaultException e) {
                badAlias = true;
            }
            check("a path-shaped alias is refused", badAlias);

            if (FilePermissions.isPosix(store)) {
                check("keystore is owner-read/write only", !FilePermissions.worldOrGroupReadable(store));
            }
        }

        try (KeyVault reopened = KeyVault.open(store, STORE_PASSWORD)) {
            check("keys survive a reopen", reopened.aliases().contains("app-data"));
            check("delete removes the alias", !tryDelete(reopened));
        }

        check("a wrong keystore password is rejected on load",
                rejects(() -> KeyVault.open(store, OTHER_STORE_PASSWORD).close()));

        byte[] storeBytes = Files.readAllBytes(store);
        byte[] tamperedStore = storeBytes.clone();
        tamperedStore[tamperedStore.length / 2] ^= 0x01;
        Path tamperedPath = workdir.resolve("tampered.p12");
        Files.write(tamperedPath, tamperedStore);
        check("an edited keystore fails its integrity check",
                rejects(() -> KeyVault.open(tamperedPath, STORE_PASSWORD).close()));

        boolean emptyPassword = false;
        try {
            KeyVault.open(workdir.resolve("empty-password.p12"), new char[0]);
        } catch (VaultException e) {
            emptyPassword = true;
        }
        check("an empty keystore password is refused", emptyPassword);

        Path absent = workdir.resolve("does-not-exist.p12");
        check("openExisting refuses a missing keystore",
                rejects(() -> KeyVault.openExisting(absent, STORE_PASSWORD).close()));
        check("openExisting does not create the file it rejected", !Files.exists(absent));
        check("open does create a missing keystore",
                Files.notExists(workdir.resolve("created-by-open.p12"))
                        && openAndClose(workdir.resolve("created-by-open.p12")));
    }

    private static boolean openAndClose(Path path) throws Exception {
        KeyVault.open(path, STORE_PASSWORD).close();
        return Files.isRegularFile(path);
    }

    private static void passphraseKeys(Path workdir) throws Exception {
        section("passphrase-derived keys");
        byte[] salt = KeyVault.newSalt();
        try (KeyVault.DerivedKey a = KeyVault.deriveFromPassphrase(PASSPHRASE, salt,
                KeyVault.PBKDF2_ITERATIONS, null);
                KeyVault.DerivedKey b = KeyVault.deriveFromPassphrase(PASSPHRASE.clone(), salt,
                        KeyVault.PBKDF2_ITERATIONS, null)) {
            check("derivation is deterministic for the same salt",
                    Arrays.equals(a.key().getEncoded(), b.key().getEncoded()));
            check("salt is returned for the envelope", Arrays.equals(salt, a.salt()));
            check("iteration count is returned", a.iterations() == KeyVault.PBKDF2_ITERATIONS);
        }

        try (KeyVault.DerivedKey a = KeyVault.deriveFromPassphrase(PASSPHRASE, salt,
                KeyVault.PBKDF2_ITERATIONS, null);
                KeyVault.DerivedKey c = KeyVault.deriveFromPassphrase(PASSPHRASE.clone(),
                        KeyVault.newSalt(), KeyVault.PBKDF2_ITERATIONS, null)) {
            check("a different salt produces a different key",
                    !Arrays.equals(a.key().getEncoded(), c.key().getEncoded()));
        }

        boolean weakKdf = false;
        try {
            KeyVault.deriveFromPassphrase(PASSPHRASE, salt, 1000, null);
        } catch (VaultException e) {
            weakKdf = true;
        }
        check("a downgrade to 1000 PBKDF2 iterations is refused", weakKdf);

        boolean emptyPassphrase = false;
        try {
            KeyVault.deriveFromPassphrase(new char[0], salt, 0, null);
        } catch (VaultException e) {
            emptyPassphrase = true;
        }
        check("an empty passphrase is refused", emptyPassphrase);

        Path store = workdir.resolve("passphrase-keys.p12");
        try (KeyVault keys = KeyVault.open(store, STORE_PASSWORD);
                DataVault vault = new DataVault(keys, () -> PASSPHRASE.clone())) {
            byte[] payload = "backup secret".getBytes(StandardCharsets.UTF_8);
            Envelope envelope = vault.sealWithPassphrase(payload);
            check("sealed envelope records the passphrase source",
                    envelope.keySource() == KeySource.PASSPHRASE);
            check("sealed envelope records the salt", envelope.salt().length == KeyVault.SALT_LENGTH);
            check("sealed envelope records iterations",
                    envelope.iterations() == KeyVault.PBKDF2_ITERATIONS);
            try (DataVault.Opened opened = vault.open(envelope)) {
                check("passphrase round-trip recovers the payload", Arrays.equals(payload, opened.data()));
            }

            try (DataVault wrong = new DataVault(keys, () -> WRONG_PASSPHRASE.clone())) {
                check("the wrong passphrase cannot open it", rejects(() -> wrong.open(envelope)));
            }

            byte[] iterationsEdited = envelope.toBytes().clone();
            int iterationsOffset = envelope.headerLength() - Envelope.IV_LENGTH - Integer.BYTES;
            iterationsEdited[iterationsOffset] = 0;
            iterationsEdited[iterationsOffset + 1] = 0;
            iterationsEdited[iterationsOffset + 2] = 0;
            iterationsEdited[iterationsOffset + 3] = 10;
            try (DataVault downgraded = new DataVault(keys, () -> PASSPHRASE.clone())) {
                check("a cost-parameter downgrade is refused",
                        rejects(() -> downgraded.open(Envelope.fromBytes(iterationsEdited))));
            }

            check("a passphrase vault refuses keystore sealing with no alias",
                    rejects(() -> new DataVault(keys, () -> PASSPHRASE.clone()).seal(payload)));
        }
    }

    private static void fileVault(Path workdir) throws Exception {
        section("file sealing");
        Path store = workdir.resolve("file-keys.p12");
        Path plaintext = workdir.resolve("payload.bin");
        byte[] content = new byte[300_000];
        new Random(11).nextBytes(content);
        Files.write(plaintext, content);

        try (KeyVault keys = KeyVault.open(store, STORE_PASSWORD); DataVault vault = new DataVault(keys, "files")) {
            keys.generate("files");
            Path sealed = workdir.resolve("payload.bin.sealed");
            Envelope envelope = vault.sealFileTo(plaintext, sealed);
            check("sealed file carries a header and a tag",
                    Files.size(sealed) == envelope.headerLength() + content.length + Envelope.TAG_LENGTH);

            Path restored = workdir.resolve("payload.bin.clear");
            vault.openFile(sealed, restored);
            check("sealed file opens to identical bytes", Arrays.equals(content, Files.readAllBytes(restored)));
            if (FilePermissions.isPosix(sealed)) {
                check("the sealed file is owner-only", !FilePermissions.worldOrGroupReadable(sealed));
                check("recovered plaintext is written owner-only",
                        !FilePermissions.worldOrGroupReadable(restored));
            }

            Path other = workdir.resolve("other.bin");
            Files.write(other, "same key, different file".getBytes(StandardCharsets.UTF_8));
            vault.sealFile(other);
            check("sealFile derives a default destination",
                    Files.exists(other.resolveSibling(other.getFileName() + ".sealed")));
            Path otherClear = workdir.resolve("other.bin.clear");
            vault.openFile(other.resolveSibling(other.getFileName() + ".sealed"), otherClear);
            check("the default-destination envelope opens",
                    Files.readString(otherClear).equals("same key, different file"));

            Path target = workdir.resolve("opened-after-tamper.bin");
            byte[] tampered = Files.readAllBytes(sealed);
            tampered[tampered.length - 5] ^= 0x20;
            Files.write(sealed, tampered);
            boolean rejected = rejects(() -> vault.openFile(sealed, target));
            check("a tampered sealed file is rejected", rejected);
            check("no plaintext is written when authentication fails", !Files.exists(target));

            Path truncated = workdir.resolve("truncated.sealed");
            Files.write(truncated, Arrays.copyOf(tampered, tampered.length - 1));
            check("a truncated sealed file is rejected",
                    rejects(() -> vault.openFile(truncated, workdir.resolve("nope.bin"))));

            boolean noLeftovers = true;
            try (var stream = Files.list(workdir)) {
                noLeftovers = stream.noneMatch(p -> p.getFileName().toString().endsWith(".part"));
            }
            check("staging files are cleaned up", noLeftovers);
        }
    }

    private static void rotation(Path workdir) throws Exception {
        section("key rotation");
        Path store = workdir.resolve("rotate-keys.p12");
        Path plaintext = workdir.resolve("rotate.txt");
        Path sealed = workdir.resolve("rotate.sealed");
        Files.writeString(plaintext, "value that must survive rotation");

        try (KeyVault keys = KeyVault.open(store, STORE_PASSWORD); DataVault vault = new DataVault(keys, "v1")) {
            keys.generate("v1");
            vault.sealFileTo(plaintext, sealed);
            keys.generate("v2");

            byte[] retargeted = Files.readAllBytes(sealed);
            int aliasAt = Envelope.MAGIC.length + 2;
            check("the header places the alias where expected",
                    new String(retargeted, aliasAt + 1, retargeted[aliasAt], StandardCharsets.UTF_8)
                            .equals("v1"));
            retargeted[aliasAt + 1] = 'v';
            retargeted[aliasAt + 2] = '2';
            Path hijacked = workdir.resolve("hijacked.sealed");
            Files.write(hijacked, retargeted);
            check("pointing a payload at a different existing key is rejected",
                    rejects(() -> vault.openFile(hijacked, workdir.resolve("hijacked.clear"))));
            check("the hijacked payload leaves no plaintext behind",
                    !Files.exists(workdir.resolve("hijacked.clear")));

            Path rotated = workdir.resolve("rotate.v2.sealed");
            vault.rekeyFile(sealed, rotated, "v2");

            AesGcmCipher reader = AesGcmCipher.withSystemRandom();
            check("the rotated envelope names the new key",
                    reader.readEnvelopeHeader(rotated).alias().equals("v2"));
            check("the original envelope still names the old key",
                    reader.readEnvelopeHeader(sealed).alias().equals("v1"));

            // vault's default alias is still v1, so this proves the key comes from the header.
            Path opened = workdir.resolve("rotate.v2.clear");
            vault.openFile(rotated, opened);
            check("the rotated payload decrypts to the original",
                    Files.readString(opened).equals("value that must survive rotation"));

            Envelope inMemory = vault.seal("rotation in memory".getBytes(StandardCharsets.UTF_8));
            Envelope rekeyed = vault.rekey(inMemory, "v2");
            check("in-memory rekey retargets the alias", rekeyed.alias().equals("v2"));
            try (DataVault.Opened opened2 = vault.open(rekeyed)) {
                check("in-memory rekeyed payload still opens",
                        new String(opened2.data(), StandardCharsets.UTF_8).equals("rotation in memory"));
            }

            keys.delete("v1");
            Path survived = workdir.resolve("still-works.bin");
            try (DataVault v2only = new DataVault(keys, "v2")) {
                v2only.openFile(rotated, survived);
                check("payload stays readable after the old key is deleted", Files.exists(survived));
            }

            keys.delete("v2");
            check("deleting every key makes the payload unopenable",
                    rejects(() -> vault.openFile(rotated, workdir.resolve("gone.bin"))));
        }
    }

    private static void noSecretLeaks() throws Exception {
        section("secret hygiene");
        AesGcmCipher cipher = AesGcmCipher.withSystemRandom();
        SecretKey key = randomKey();
        byte[] plaintext = "TOP-PLAINTEXT-MARKER".getBytes(StandardCharsets.UTF_8);
        Envelope envelope = cipher.seal(key, KeySource.KEYSTORE, "hygiene", new byte[0], 0, plaintext);

        check("envelope toString carries no plaintext", !envelope.toString().contains("TOP-PLAINTEXT"));
        check("envelope toString carries no key bytes", !envelope.toString().contains(key.toString()));

        Path store = Files.createTempDirectory("hygiene").resolve("k.p12");
        try (KeyVault vault = KeyVault.open(store, STORE_PASSWORD)) {
            vault.generate("hygiene");
            String description = vault.describe();
            check("keystore description names the store and its aliases",
                    description.contains("hygiene") && description.contains("k.p12"));
            check("keystore description holds no key material", !description.contains("=[B"));

            SecretKey fetched = vault.key("hygiene");
            byte[] before = fetched.getEncoded();
            KeyVault.zero(fetched);
            check("zero() clears the array it was handed, not the key object behind it",
                    Arrays.equals(fetched.getEncoded(), before));
            check("the raw keystore file never contains the stored key bytes",
                    !indexOf(Files.readAllBytes(store), before));
        }

        byte[] sealed = envelope.toBytes();
        try {
            Envelope.fromBytes("garbage".getBytes(StandardCharsets.UTF_8));
            check("malformed input raises a VaultException", false);
        } catch (VaultException e) {
            check("malformed input raises a VaultException", true);
            check("the message does not echo the payload", !e.getMessage().contains("garbage"));
        }
        check("sealed bytes never contain the plaintext", !indexOf(sealed, plaintext));
    }

    private static SecretKey randomKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KeyVault.KEY_LENGTH_BITS);
        return generator.generateKey();
    }

    private static boolean tryDelete(KeyVault vault) {
        vault.delete("imported");
        return vault.contains("imported");
    }

    private interface ThrowingRun {

        void run() throws Exception;
    }

    private static boolean rejects(ThrowingRun run) {
        try {
            run.run();
            return false;
        } catch (VaultException expected) {
            return true;
        } catch (Exception other) {
            System.out.println("      (unexpected " + other.getClass().getSimpleName() + ": "
                    + other.getMessage() + ")");
            return false;
        }
    }

    private static boolean indexOf(byte[] haystack, byte[] needle) {
        outer: for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static void check(String what, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            failed++;
            System.out.println("  FAIL " + what);
        }
    }

    private static void section(String name) {
        System.out.println("\n[" + name + "]");
    }

    private static void deleteTree(Path root) throws Exception {
        try (var stream = Files.walk(root)) {
            for (Path path : stream.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
