package com.example.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Where keys come from: the byte-level key parser, the environment, key files, the password-protected
 * container and the platform key store.
 *
 * <p>The recurring property is that a key source either produces a usable AES-256 key or refuses.
 * There is no path through this package where a missing, truncated, blank or malformed source yields a
 * key - above all not a zero key or a constant-derived one, which would look like a working system
 * while encrypting everything under something an attacker can guess.
 *
 * <p>Control characters appear in several tests below. They are built from character codes rather than
 * written as literals: a raw 0x00 or 0x1b inside a source file is invisible in an editor, survives
 * compilation, and turns the file into something tools treat as binary.
 */
class KeySourceTest {

    private static final char NUL = (char) 0x00;
    private static final char SOH = (char) 0x01;
    private static final char BELL = (char) 0x07;
    private static final char ESC = (char) 0x1b;
    private static final char DEL = (char) 0x7f;
    private static final char SPACE = (char) 0x20;
    private static final char TAB = (char) 0x09;
    private static final char LF = (char) 0x0a;
    private static final char E_ACUTE = (char) 0xe9;

    private static final String KEY_PASSWORD = "a-second-machine-secret-of-sufficient-len-4a71";

    private static final byte[] RAW32 = new byte[KeyMaterial.KEY_BYTES];

    /**
     * A key whose canonical base64url text is all underscores, so its standard-alphabet spelling is all
     * slashes. Needed to test the alphabet at all: a fixture whose text form happens to contain neither
     * '-' nor '_' makes "wrong alphabet" a silent no-op that passes for the wrong reason.
     */
    private static final byte[] PUNCT32 = new byte[KeyMaterial.KEY_BYTES];

    static {
        for (int i = 0; i < RAW32.length; i++) {
            RAW32[i] = (byte) (i * 7 + 1);
            PUNCT32[i] = (byte) 0xff;
        }
    }

    private static String canonical(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Only 32 raw bytes or their canonical base64url text. Everything else is refused, not repaired. */
    @Test
    void theKeyParserAcceptsNothingItHasToGuessAbout() throws Exception {
        assertArrayEquals(RAW32, KeyEncoding.decodeKeyBytes(RAW32));
        assertArrayEquals(RAW32,
                KeyEncoding.decodeKeyBytes(canonical(RAW32).getBytes(StandardCharsets.US_ASCII)));
        /* The url-safe alphabet is the one in use, punctuation and all. */
        assertArrayEquals(PUNCT32,
                KeyEncoding.decodeKeyBytes(canonical(PUNCT32).getBytes(StandardCharsets.US_ASCII)));
        assertTrue(canonical(PUNCT32).indexOf('_') >= 0, "the punctuation fixture lost its punctuation");
        /*
         * The two alphabets must not be interchangeable. A key pasted from a tool that used the standard
         * alphabet has to come out as a different key (so records simply fail to authenticate) rather than
         * as the same key: silent cross-alphabet equality would let two spellings authorise one dataset.
         */
        byte[] dashSpelling = KeyEncoding.decodeKeyBytes(
                canonical(PUNCT32).replace('_', '-').getBytes(StandardCharsets.US_ASCII));
        assertFalse(Arrays.equals(PUNCT32, dashSpelling),
                "the url and standard alphabets decoded to the same key bytes");
        /* Padding is repaired nowhere: a padded value is a deployment mistake, refused not fixed. */
        assertThrows(CryptoException.class, () -> KeyEncoding.decodeKeyBytes(
                Base64.getUrlEncoder().encodeToString(RAW32).getBytes(StandardCharsets.US_ASCII)));

        /* Wrong length: no padding, no truncation, no hashing down to size. */
        for (int n : new int[] {0, 1, 16, 31, 33, 64}) {
            byte[] wrong = new byte[n];
            Arrays.fill(wrong, (byte) 7);
            assertThrows(CryptoException.class, () -> KeyEncoding.decodeKeyBytes(wrong),
                    n + " raw bytes were accepted");
        }

        /* Padded, wrong-alphabet, whitespace-padded and prose text are all refused. */
        String c = canonical(RAW32);
        List<String> rejects = List.of(
                Base64.getUrlEncoder().encodeToString(RAW32),   // padded: this format is unpadded
                /* '/' and '+' are not in the base64url alphabet at all. */
                Base64.getEncoder().encodeToString(PUNCT32),    // standard alphabet, padded
                Base64.getEncoder().encodeToString(PUNCT32).replace("=", ""),
                "notbase64%%",                                  // not base64 at all
                /*
                 * A wrong-alphabet case has to be built from a key whose text form actually contains the
                 * url-safe punctuation. Substituting on RAW32 would be a no-op that returns the valid
                 * string unchanged, and the test would then "pass" by accepting a real key.
                 */
                canonical(PUNCT32).replace('_', '.'),
                canonical(PUNCT32).replace('_', '%'),
                SPACE + c,                                                    // leading space
                c + SPACE,                                                    // trailing space
                c.substring(0, 40),                                           // truncated text
                "",                                                           // empty
                "not-a-key-at-all",                                           // prose
                "caf" + E_ACUTE,                                              // non-ASCII
                "line" + LF + "break",                                        // embedded newline
                "tab" + TAB + "here");                                        // embedded tab
        for (String s : rejects) {
            assertThrows(CryptoException.class,
                    () -> KeyEncoding.decodeKeyBytes(s.getBytes(StandardCharsets.UTF_8)),
                    "accepted as a key: " + s.replace("\n", "\\n").replace("\t", "\\t"));
        }

        /*
         * Base64 decoders ignore trailing bits that carry no payload, so several strings decode to the
         * same 32 bytes. If more than one spelling were accepted, one key would have several textual
         * identities - which is how a "different" secret ends up authorising the same data. The
         * canonical re-encode comparison is what stops that, so the variants have to be found first:
         * an empty candidate list would make this whole block prove nothing.
         */
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int dupes = 0;
        for (int i = 0; i < alphabet.length(); i++) {
            String variant = c.substring(0, c.length() - 1) + alphabet.charAt(i);
            if (variant.equals(c)) {
                continue;
            }
            boolean sameBytes;
            try {
                sameBytes = Arrays.equals(RAW32, Base64.getUrlDecoder().decode(variant));
            } catch (IllegalArgumentException e) {
                sameBytes = false;
            }
            if (sameBytes) {
                dupes++;
                assertThrows(CryptoException.class,
                        () -> KeyEncoding.decodeKeyBytes(variant.getBytes(StandardCharsets.US_ASCII)),
                        "a non-canonical spelling of the same key was accepted: " + variant);
            }
        }
        assertTrue(dupes > 0, "the fixture found no non-canonical spelling, so it proved nothing");

        /* Control characters can never be part of a key: they are how a value spoofs a log line. */
        for (char ctrl : new char[] {NUL, SOH, BELL, ESC, DEL, LF, TAB, SPACE}) {
            String with = "A".repeat(42) + ctrl;
            assertThrows(CryptoException.class,
                    () -> KeyEncoding.decodeKeyBytes(with.getBytes(StandardCharsets.UTF_8)),
                    "control character U+" + Integer.toHexString(ctrl) + " was accepted");
        }

        /* Size is bounded before anything is decoded. */
        byte[] huge = new byte[KeyEncoding.MAX_INPUT_BYTES + 1];
        Arrays.fill(huge, (byte) 'A');
        assertEquals(CryptoException.CryptoFailureCode.TOO_LARGE,
                assertThrows(CryptoException.class, () -> KeyEncoding.decodeKeyBytes(huge)).code());

        /* Nothing is substituted for a missing value. */
        assertEquals(CryptoException.CryptoFailureCode.MISSING_INPUT,
                assertThrows(CryptoException.class, () -> KeyEncoding.decodeKeyBytes(null)).code());
    }

    /** An environment variable name ends up in log details, so it must be boring before it is used. */
    @Test
    void anEnvironmentVariableNameIsRefusedBeforeTheEnvironmentIsRead() {
        for (String bad : List.of("", "0LEADING", "has space", "has-dash", "has.dot", "semi;colon",
                "new" + LF + "line", "nul" + NUL + "char", "v" + E_ACUTE + "alue", "x".repeat(65))) {
            CryptoException e = assertThrows(CryptoException.class, () -> new EnvKeySource(bad),
                    "accepted as a variable name: " + bad);
            assertEquals(CryptoException.CryptoFailureCode.INVALID_INPUT, e.code());
        }
        assertThrows(CryptoException.class, () -> new EnvKeySource(null));
        for (String ok : List.of("A", "_", "_X9", "APP_DATA_KEY", "x".repeat(64))) {
            assertNoRefusal(() -> new EnvKeySource(ok), ok);
        }
    }

    /** A variable that is absent must fail closed, and its refusal must quote nothing useful. */
    @Test
    void anUnsetEnvironmentVariableFailsClosedAndDescribesItselfSafely() throws Exception {
        EnvKeySource missing = new EnvKeySource("SECURE_DATA_CRYPTO_ABSENT_" + ProcessHandle.current().pid());
        CryptoException e = assertThrows(CryptoException.class, missing::load);
        assertEquals(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE, e.code());
        assertEquals("The data could not be decrypted", e.getMessage());
        /* describe() goes to logs: it names the variable and can never contain its value. */
        assertEquals("env:SECURE_DATA_CRYPTO_ABSENT_" + ProcessHandle.current().pid(), missing.describe());
        assertFalse((missing.describe() + missing).contains("=EQ"), missing.describe());
    }

    /**
     * A running JVM cannot change its own environment, so the paths that need a variable to actually be
     * set run in a child JVM (see {@link EnvKeySourceChild}).
     */
    @Test
    void anEnvironmentVariableIsLoadedOnlyWhenItHoldsAKey() throws Exception {
        String b64 = canonical(RAW32);
        String fingerprint = Integer.toHexString(Arrays.hashCode(RAW32));
        assertEquals("ok " + fingerprint, runEnvChild("SECURE_DATA_CRYPTO_CHILD_KEY", b64));
        /* Padded text is refused rather than repaired, so a mis-set variable cannot silently load. */
        assertEquals("refused",
                runEnvChild("SECURE_DATA_CRYPTO_CHILD_KEY", Base64.getUrlEncoder().encodeToString(RAW32)));
        /* A value that is merely close to a key is refused rather than normalised into one. */
        assertEquals("refused", runEnvChild("SECURE_DATA_CRYPTO_CHILD_KEY", "hunter2"));
        assertEquals("refused", runEnvChild("SECURE_DATA_CRYPTO_CHILD_KEY", "" + SPACE + SPACE + SPACE));
        /* An empty variable is a deployment mistake, not a blank key. */
        assertEquals("refused", runEnvChild("SECURE_DATA_CRYPTO_CHILD_KEY", ""));
        /* Absent: the child must not fall back to a default. */
        assertEquals("absent", runEnvChild("SECURE_DATA_CRYPTO_CHILD_KEY_UNSET", null));
    }

    private static String runEnvChild(String variable, String value) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", Fixtures.classpathForChild(),
                "com.example.crypto.EnvKeySourceChild", variable));
        pb.redirectErrorStream(true);
        if (value == null) {
            pb.environment().remove(variable);
        } else {
            pb.environment().put(variable, value);
        }
        Process p = pb.start();
        /* Close the child's stdin: a child that reads would otherwise wait on us forever. */
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertTrue(p.waitFor(90, TimeUnit.SECONDS), "child JVM did not finish: " + out);
        /* The child must never print the value it was given, whatever branch it took. */
        if (value != null && !value.isEmpty()) {
            assertFalse(out.contains(value), "the child echoed its secret: " + out);
        }
        return out;
    }

    @Test
    void aKeyFileIsWrittenPrivateAndReadsBackTheSameKey() throws Exception {
        Path dir = Fixtures.dir("keyfile-roundtrip");
        Path file = dir.resolve("data.key");
        SymmetricCrypto crypto = new SymmetricCrypto();
        try (KeyMaterial original = crypto.generateKey(1)) {
            original.writeTo(file);
            /* Private from the first byte, not created readable and chmod-ed afterwards. */
            assertEquals("600", Fixtures.modeString(file), Fixtures.modeString(file));
            try (KeyMaterial reloaded = new KeyFileKeySource(file).load()) {
                assertEquals(1, reloaded.version());
                /* Prove they are the same key by using it, never by printing it. */
                EncryptedBlob blob = crypto.encrypt(original, "prove it".getBytes(StandardCharsets.UTF_8), "ctx");
                assertArrayEquals("prove it".getBytes(StandardCharsets.UTF_8), crypto.decrypt(reloaded, blob, "ctx"));
            }
        }
        /* A key file for a specific version, written by the source that reads it. */
        Path v9 = dir.resolve("v9.key");
        try (KeyMaterial k = new SymmetricCrypto().generateKey(9)) {
            k.writeTo(v9);
            try (KeyMaterial back = new KeyFileKeySource(v9).load()) {
                /* A bare key file carries no version metadata, so it loads as version 1. */
                assertEquals(1, back.version(), "a plain key file must not invent a version");
            }
        }
    }

    @Test
    void aPasswordKeyFileRoundTripsAndAWrongPassphraseRefusesLikeATamper() throws Exception {
        Path dir = Fixtures.dir("pw-roundtrip");
        Path file = dir.resolve("key.spkb1");
        long t0 = System.nanoTime();
        PasswordKeySource.create(file, 7, Fixtures.passphrase(), Fixtures.fastIterations());
        long createMs = (System.nanoTime() - t0) / 1_000_000;
        assertEquals("600", Fixtures.modeString(file), "the container must be born private");

        SymmetricCrypto crypto = new SymmetricCrypto();
        try (PasswordKeySource src = new PasswordKeySource(file, 7, Fixtures.passphrase());
             KeyMaterial k = src.load()) {
            assertEquals(7, k.version());
            EncryptedBlob blob = crypto.encrypt(k, "under a passphrase".getBytes(StandardCharsets.UTF_8), null);
            assertArrayEquals("under a passphrase".getBytes(StandardCharsets.UTF_8),
                    crypto.decrypt(k, blob, null));
            /* describe() is for logs: identity only, never the passphrase. */
            assertFalse((src.describe() + src).contains(new String(Fixtures.passphrase())),
                    src.describe() + " / " + src);
            assertTrue(src.describe().startsWith("pbkdf2:"), src.describe());
        }

        char[] bad = "a-different-passphrase-entirely-8837".toCharArray();
        CryptoException wrong = assertThrows(CryptoException.class, () -> {
            try (PasswordKeySource src = new PasswordKeySource(file, 7, bad)) {
                src.load();
            }
        });
        /*
         * A wrong passphrase and a doctored file answer the same attacker question ("does this secret
         * work?"), so both must produce the authentication code and the shared generic message.
         */
        assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, wrong.code());
        assertEquals("The data could not be decrypted", wrong.getMessage());
        assertFalse(wrong.getTechnicalDetail().contains(new String(bad)), "the detail quoted the passphrase");
        assertFalse(String.valueOf(wrong).contains(new String(bad)), "toString leaked the passphrase");

        assertTrue(createMs > 50, "the KDF was not actually run: create took " + createMs + "ms");
    }

    @Test
    void aContainerThatLowersTheKdfCostIsRefusedAndRefusedCheaply() throws Exception {
        /*
         * The iteration count lives in the file and drives the derivation, so a lowered value must be
         * refused: otherwise an attacker with write access to the file makes the next load hundreds of
         * times cheaper to brute force. The count is inside the AEAD's AAD as well, so the tag catches
         * the edit too - which makes this whitelist redundant for correctness. Redundant guards are only
         * observable through cost, and the cost that matters here is the upper bound: a raised count must
         * be refused without ever being run, or a hostile file can make one load take years.
         */
        Path dir = Fixtures.dir("pw-iters");
        Path file = dir.resolve("key.spkb1");
        PasswordKeySource.create(file, 1, Fixtures.passphrase(), Fixtures.fastIterations());

        for (int lowered : new int[] {1, 100, Limits.MIN_KDF_ITERATIONS - 1}) {
            Path tampered = dir.resolve("low-" + lowered + ".spkb1");
            writeWithIterations(file, tampered, lowered);
            long start = System.nanoTime();
            CryptoException e = assertThrows(CryptoException.class, () -> {
                try (PasswordKeySource src = new PasswordKeySource(tampered, 1, Fixtures.passphrase())) {
                    src.load();
                }
            }, "an iteration count of " + lowered + " was honoured");
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertTrue(ms < 60, "the refusal at " + lowered + " iterations cost "
                    + ms + "ms, which means the KDF ran anyway");
            assertTrue(e.getMessage() != null && !e.getMessage().isBlank());
        }

        for (int raised : new int[] {Limits.MAX_KDF_ITERATIONS + 1, Integer.MAX_VALUE}) {
            Path tampered = dir.resolve("high-" + raised + ".spkb1");
            writeWithIterations(file, tampered, raised);
            long start = System.nanoTime();
            assertThrows(CryptoException.class, () -> {
                try (PasswordKeySource src = new PasswordKeySource(tampered, 1, Fixtures.passphrase())) {
                    src.load();
                }
            }, "an iteration count of " + raised + " was honoured");
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertTrue(ms < 60, "the refusal at " + raised + " iterations cost "
                    + ms + "ms, so a hostile file can make this load take years");
        }
    }

    /** Rewrites the 4-byte big-endian iteration count at offset 6 (5 magic + 1 KDF id), nothing else. */
    private static void writeWithIterations(Path from, Path to, int iterations) throws Exception {
        byte[] raw = Files.readAllBytes(from);
        raw[6] = (byte) (iterations >>> 24);
        raw[7] = (byte) (iterations >>> 16);
        raw[8] = (byte) (iterations >>> 8);
        raw[9] = (byte) iterations;
        Files.write(to, raw);
        Fixtures.setMode(to, "600");
    }

    @Test
    void aPasswordKeyFileWithForeignContentIsRefused() throws Exception {
        Path dir = Fixtures.dir("pw-foreign");
        int i = 0;
        for (byte[] junk : List.of(
                "SPKB1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".getBytes(StandardCharsets.US_ASCII),
                new byte[4096],
                ("PK" + E_ACUTE).getBytes(StandardCharsets.UTF_8),
                RAW32)) {
            Path f = dir.resolve("junk" + (i) + ".spkb1");
            Files.write(f, junk);
            Fixtures.setMode(f, "600");
            final int n = i;
            assertThrows(CryptoException.class, () -> {
                try (PasswordKeySource src = new PasswordKeySource(f, 1, Fixtures.passphrase())) {
                    src.load();
                }
            }, "junk input " + n + " was accepted as a key container");
            i++;
        }
        /* A real container truncated anywhere in its header must be refused, not read past the end. */
        Path real = dir.resolve("real.spkb1");
        PasswordKeySource.create(real, 1, Fixtures.passphrase(), Fixtures.fastIterations());
        byte[] full = Files.readAllBytes(real);
        int refused = 0;
        for (int cut = 1; cut < 90 && cut < full.length; cut++) {
            Path f = dir.resolve("cut" + cut + ".spkb1");
            Files.write(f, Arrays.copyOf(full, full.length - cut));
            Fixtures.setMode(f, "600");
            assertThrows(CryptoException.class, () -> {
                try (PasswordKeySource src = new PasswordKeySource(f, 1, Fixtures.passphrase())) {
                    src.load();
                }
            }, "a container truncated by " + cut + " bytes was accepted");
            refused++;
        }
        assertTrue(refused > 40, "only " + refused + " truncations were exercised");
    }

    @Test
    void aKeystoreRoundTripsAndAWrongStorePasswordStaysGeneric() throws Exception {
        Path dir = Fixtures.dir("keystore");
        Path file = dir.resolve("keys.p12");
        KeystoreKeySource.create(file, "data-key", 2, Fixtures.machinePassword(), KEY_PASSWORD.toCharArray());
        /* KeyStore.store() via Files.newOutputStream would leave this 0644. */
        assertEquals("600", Fixtures.modeString(file), "a keystore must not be born world-readable");

        SymmetricCrypto crypto = new SymmetricCrypto();
        try (KeystoreKeySource src = new KeystoreKeySource(file, "data-key", 2,
                Fixtures.machinePassword(), KEY_PASSWORD.toCharArray());
             KeyMaterial k = src.load()) {
            assertEquals(2, k.version());
            EncryptedBlob blob = crypto.encrypt(k, "keystore scoped".getBytes(StandardCharsets.UTF_8), "ctx");
            assertArrayEquals("keystore scoped".getBytes(StandardCharsets.UTF_8), crypto.decrypt(k, blob, "ctx"));
            assertFalse((src.describe() + src).contains(KEY_PASSWORD), src.describe());
            assertTrue(src.describe().startsWith("pkcs12:"), src.describe());
        }

        CryptoException wrongStore = assertThrows(CryptoException.class, () -> {
            try (KeystoreKeySource src = new KeystoreKeySource(file, "data-key", 2,
                    "a-completely-wrong-store-password-try-9917".toCharArray(), KEY_PASSWORD.toCharArray())) {
                src.load();
            }
        });
        /* PKCS#12 reports a wrong store password as an IOException; it must still be classified. */
        assertEquals(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE, wrongStore.code());
        assertEquals("The data could not be decrypted", wrongStore.getMessage());
        assertFalse(wrongStore.getTechnicalDetail()
                .contains("a-completely-wrong-store-password-try-9917"), "the detail quoted the password");

        /* A wrong entry password is a different failure in the platform - same generic answer here. */
        CryptoException wrongKey = assertThrows(CryptoException.class, () -> {
            try (KeystoreKeySource src = new KeystoreKeySource(file, "data-key", 2,
                    Fixtures.machinePassword(), "a-wrong-entry-password-of-some-length-77b1".toCharArray())) {
                src.load();
            }
        });
        assertEquals("The data could not be decrypted", wrongKey.getMessage());

        /* An alias that is not in the store must fail closed, never fall through to another entry. */
        CryptoException wrongAlias = assertThrows(CryptoException.class, () -> {
            try (KeystoreKeySource src = new KeystoreKeySource(file, "other-key", 2,
                    Fixtures.machinePassword(), KEY_PASSWORD.toCharArray())) {
                src.load();
            }
        });
        assertEquals(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE, wrongAlias.code());
        assertEquals("The data could not be decrypted", wrongAlias.getMessage());

        /* Bad alias syntax is caught at construction, before the file is opened. */
        for (String badAlias : List.of("", "has space", "x".repeat(200), "up</script>Per",
                "semi;colon", "nul" + NUL + "char")) {
            assertThrows(CryptoException.class,
                    () -> new KeystoreKeySource(file, badAlias, 2, Fixtures.machinePassword(),
                            Fixtures.machinePassword()), "accepted alias: " + badAlias);
        }
        /* A passphrase below the entropy floor is refused, because PKCS#12's own KDF is cheap. */
        assertThrows(CryptoException.class, () -> new KeystoreKeySource(file, "data-key", 2,
                "short".toCharArray(), Fixtures.machinePassword()));
    }

    @Test
    void generatedPasswordsAreLongPrintableAndDistinct() throws Exception {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            char[] pw = RandomPasswords.generate();
            assertEquals(RandomPasswords.DEFAULT_LENGTH, pw.length);
            String s = new String(pw);
            for (int j = 0; j < pw.length; j++) {
                assertTrue(pw[j] >= 0x21 && pw[j] <= 0x7E,
                        "generated password contains U+" + Integer.toHexString(pw[j]));
            }
            seen.add(s);
            /* A generated password must satisfy this component's own passphrase rules. */
            assertNoRefusal(() -> KeystoreKeySource.requirePassphrase(pw.clone(), "generated"), s);
        }
        assertEquals(20, seen.size(), "the generator repeated itself, so it is not drawing at random");

        assertEquals(32, RandomPasswords.generate(32).length);
        assertEquals(RandomPasswords.MAX_LENGTH, RandomPasswords.generate(RandomPasswords.MAX_LENGTH).length);
        /* Out-of-range lengths are refused rather than silently clamped to something weaker. */
        for (int bad : new int[] {0, -1, RandomPasswords.MAX_LENGTH + 1, Integer.MIN_VALUE}) {
            assertThrows(CryptoException.class, () -> RandomPasswords.generate(bad),
                    "length " + bad + " was accepted");
        }
        /* A full printable-ASCII alphabet drawn 1024 times must show plenty of variety, or the pool is short. */
        char[] longPw = RandomPasswords.generate(RandomPasswords.MAX_LENGTH);
        Set<Character> distinct = new HashSet<>();
        for (char ch : longPw) {
            distinct.add(ch);
        }
        assertTrue(distinct.size() > 60, "the alphabet looks short: " + distinct.size() + " distinct");
    }

    /**
     * The strength stated in {@link RandomPasswords}'s javadoc has to be the strength its alphabet
     * actually has. A comment that says "93 members" beside a 94-character pool is the sort of number a
     * reviewer quotes back, so the count is pinned to the alphabet here instead of repeated.
     */
    @Test
    void theRandomSecretAlphabetIsWhatItsDocumentationCountsItAs() throws Exception {
        assertEquals(94, RandomPasswords.ALPHABET_SIZE,
                "the javadoc counts 94 printable characters excluding space");
        Set<Character> seen = new HashSet<>();
        for (char[] pw : new char[][] {RandomPasswords.generate(1024), RandomPasswords.generate(1024),
                RandomPasswords.generate(1024)}) {
            for (char ch : pw) {
                assertTrue(ch >= 0x21 && ch <= 0x7E,
                        "generated a character outside printable ASCII: " + (int) ch);
                seen.add(ch);
            }
        }
        /* 3072 draws over 94 symbols: much short of the pool and the generator is narrower than claimed. */
        assertTrue(seen.size() >= 85, "only " + seen.size() + " of 94 characters ever appeared");
        double bits = RandomPasswords.DEFAULT_LENGTH * (Math.log(RandomPasswords.ALPHABET_SIZE) / Math.log(2));
        assertTrue(bits > 300, "the documented default length carries only " + bits + " bits");
    }

    /**
     * A trailing newline is refused in both accepted key forms. The alternative is to trim, and trimming
     * is exactly what makes the two forms ambiguous: length is the only thing that says "32 raw bytes"
     * rather than "base64 text", so a value whose length turns on its last byte is a value whose form an
     * editor decided.
     */
    @Test
    void aKeyFileWithATrailingNewlineIsRefusedRatherThanTrimmed() throws Exception {
        byte[] raw = new byte[KeyMaterial.KEY_BYTES];
        new java.security.SecureRandom().nextBytes(raw);
        String text = KeyEncoding.toBase64Url(KeyMaterial.fromBytes(raw));
        String[] suffixes = {String.valueOf(LF), String.valueOf((char) 0x0d) + LF,
                String.valueOf((char) 0x0d), String.valueOf(SPACE), String.valueOf(TAB)};

        for (String suffix : suffixes) {
            int code = suffix.charAt(suffix.length() - 1);
            byte[] rawPlus = concat(raw, suffix);
            assertThrows(CryptoException.class, () -> KeyEncoding.decodeKeyBytes(rawPlus),
                    "a raw key with a trailing " + code + " was accepted");
            CryptoException e = assertThrows(CryptoException.class,
                    () -> KeyEncoding.decodeKeyBytes((text + suffix).getBytes(StandardCharsets.US_ASCII)),
                    "base64 text with a trailing " + code + " was accepted");
            /*
             * Key-side failures all share one user message, so "your key file has a stray newline" and
             * "your key file is missing" are one and the same sentence to whoever sees the error. The
             * byte-level reason is only ever in the log detail, and that detail must not quote the key.
             */
            assertEquals("The data could not be decrypted", e.getMessage());
            assertFalse(e.getTechnicalDetail().contains(text),
                    "the refusal echoes the key itself: " + e.getTechnicalDetail());
        }

        /* Both clean forms still load, so the refusals above are about the suffix and not the fixture. */
        assertArrayEquals(raw, KeyEncoding.decodeKeyBytes(raw), "the raw form regressed");
        assertArrayEquals(raw, KeyEncoding.decodeKeyBytes(text.getBytes(StandardCharsets.US_ASCII)),
                "the text form regressed");
    }

    private static byte[] concat(byte[] head, String tail) {
        byte[] extra = tail.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = Arrays.copyOf(head, head.length + extra.length);
        System.arraycopy(extra, 0, out, head.length, extra.length);
        return out;
    }

    /**
     * {@code getMessage()} is the string callers are told to render blindly, so it has to survive being
     * serialised: a JVM that passes one of these across a boundary must not answer a decrypt failure with
     * a NullPointerException raised inside the caller's own error handler.
     */
    @Test
    void theGenericMessageSurvivesSerialization() throws Exception {
        Path dir = Fixtures.dir("serialise");
        byte[] raw = new byte[KeyMaterial.KEY_BYTES];
        new java.security.SecureRandom().nextBytes(raw);
        KeyMaterial k = KeyMaterial.fromBytes(raw);
        java.util.Arrays.fill(raw, (byte) 0);
        EncryptedBlob blob = new SymmetricCrypto().encrypt(k, new byte[] {1}, null);
        k.close();

        CryptoException original = assertThrows(CryptoException.class,
                () -> new SymmetricCrypto().decrypt(k, blob, null));
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        try (java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(buf)) {
            out.writeObject(original);
        }
        CryptoException revived;
        try (java.io.ObjectInputStream in =
                new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(buf.toByteArray()))) {
            revived = (CryptoException) in.readObject();
        }

        assertEquals(original.getMessage(), revived.getMessage(), "the generic message changed in transit");
        assertEquals(original.code(), revived.code(), "the failure code did not survive");
        assertTrue(dir.getFileName().toString().length() > 0);
        /* The detail is this JVM's log channel; it must not travel, and must not be replaced by noise. */
        assertTrue(revived.getTechnicalDetail() == null, "a technical detail crossed the process boundary");
        assertEquals("The data could not be decrypted", revived.getMessage());
    }

    private static void assertNoRefusal(CryptoThrowingRunnable body, String what) {
        try {
            body.run();
        } catch (CryptoException e) {
            throw new AssertionError("unexpected refusal for " + what, e);
        }
    }

    private interface CryptoThrowingRunnable {
        void run() throws CryptoException;
    }
}
