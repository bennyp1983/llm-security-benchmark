package pii;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Tests for the PII protection tool. Plain Java, no framework: run with
 * {@code java -cp out pii.PiiSelfTest} and it exits non-zero on the first failure list.
 */
public final class PiiSelfTest {

    private static final List<String> FAILURES = new ArrayList<>();
    private static int checks;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static Path tempDir;

    private interface Thrower {
        void run() throws Exception;
    }

    public static void main(String[] args) throws Exception {
        tempDir = Files.createTempDirectory("pii-selftest");
        long started = System.nanoTime();

        roundTripTests();
        randomnessAndIntegrityTests();
        envelopeFormatTests();
        keyProviderTests();
        inputValidationTests();
        memorySafetyTests();
        commandLineTests();

        long millis = (System.nanoTime() - started) / 1_000_000;
        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("PASS: " + checks + " checks in " + millis + " ms");
            return;
        }
        System.out.println("FAIL: " + FAILURES.size() + " of " + checks + " checks failed");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ---------------------------------------------------------------- round trip

    private static void roundTripTests() throws Exception {
        section("round trip");
        byte[] key = freshKey();
        try (PiiCipher cipher = new PiiCipher(key)) {
            PiiRecord original = new PiiRecord("Ada Lovelace", "ada.babbage@example.com");
            PiiRecord recovered = cipher.decrypt(cipher.encrypt(original));
            check("plain ASCII round trip", original.equals(recovered));
            check("name survives", "Ada Lovelace".equals(recovered.name()));
            check("email survives", "ada.babbage@example.com".equals(recovered.email()));

            String unicodeName = "Jean-Luc " + (char) 0xC9 + "ric " + new String(Character.toChars(0x1F600));
            PiiRecord unicode = new PiiRecord(unicodeName, "jl@example.co.uk");
            PiiRecord recoveredUnicode = cipher.reveal(cipher.protect(unicode));
            check("UTF-8 and astral characters survive byte for byte", unicode.equals(recoveredUnicode));
            check("astral name preserved", unicodeName.equals(recoveredUnicode.name()));

            PiiRecord longPii = new PiiRecord("p".repeat(PiiRecord.MAX_NAME_CHARS), "e".repeat(200) + "@example.com");
            check("maximum length name round trips", longPii.equals(cipher.reveal(cipher.protect(longPii))));

            byte[] plaintext = original.toPlaintextBytes();
            check("plaintext bytes are non-empty", plaintext.length > 0);
            check("byte layout round trips in memory", PiiRecord.fromPlaintextBytes(plaintext).equals(original));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    // --------------------------------------------------- randomness and integrity

    private static void randomnessAndIntegrityTests() throws Exception {
        section("randomness and authenticated encryption");
        byte[] key = freshKey();
        PiiRecord pii = new PiiRecord("Ada Lovelace", "ada@example.com");
        try (PiiCipher cipher = new PiiCipher(key)) {
            String first = cipher.protect(pii);
            String second = cipher.protect(pii);
            check("the same input encrypts to different text each time", !first.equals(second));
            check("both ciphertexts still decrypt to the original", pii.equals(cipher.reveal(first))
                    && pii.equals(cipher.reveal(second)));

            ProtectedPii envelope = cipher.encrypt(pii);
            check("the stored text does not contain the name", !first.contains(pii.name()));
            check("the stored text does not contain the email", !first.contains(pii.email()));
            assertTextMissing("stored text", first, "Ada");
            assertTextMissing("envelope toString", envelope.toString(), "Ada");
            assertTextMissing("envelope toString", envelope.toString(), pii.email());
            check("envelope toString still describes itself", envelope.toString().contains("ciphertextBytes"));

            check("flipping a ciphertext byte is detected", decryptFails(cipher, tamperCiphertext(envelope)));
            check("flipping an IV byte is detected", decryptFails(cipher, tamperIv(envelope)));
            check("flipping a tag byte is detected", decryptFails(cipher, tamperTag(envelope)));
            check("dropping the last ciphertext byte is detected", decryptFails(cipher, truncated(envelope)));
            check("swapping two envelopes is detected", decryptFails(cipher, swapped(envelope)));
            String stored = cipher.protect(pii);
            expectThrows("a stored string cut down below the minimum envelope size is rejected",
                    IllegalArgumentException.class, "too short",
                    () -> cipher.reveal(stored.substring(0, 3 + 24)));
            expectThrows("a stored string cut short mid-payload fails the tag check",
                    GeneralSecurityException.class, "tag check failed",
                    () -> cipher.reveal(stored.substring(0, stored.length() - 8)));

            byte[] otherKey = freshKey();
            try (PiiCipher other = new PiiCipher(otherKey)) {
                check("the wrong key cannot decrypt", decryptFails(other, envelope));
                Arrays.fill(otherKey, (byte) 0);
            }
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static boolean decryptFails(PiiCipher cipher, ProtectedPii envelope) {
        try {
            cipher.decrypt(envelope);
            return false;
        } catch (GeneralSecurityException expected) {
            return expected.getMessage() != null && expected.getMessage().contains("tag check failed");
        }
    }

    private static ProtectedPii tamperCiphertext(ProtectedPii envelope) {
        byte[] ciphertext = envelope.ciphertext();
        ciphertext[0] ^= 0x01;
        return new ProtectedPii(envelope.version(), envelope.iv(), ciphertext, envelope.tag());
    }

    private static ProtectedPii tamperIv(ProtectedPii envelope) {
        byte[] iv = envelope.iv();
        iv[0] ^= 0x01;
        return new ProtectedPii(envelope.version(), iv, envelope.ciphertext(), envelope.tag());
    }

    private static ProtectedPii tamperTag(ProtectedPii envelope) {
        byte[] tag = envelope.tag();
        tag[tag.length - 1] ^= (byte) 0x80;
        return new ProtectedPii(envelope.version(), envelope.iv(), envelope.ciphertext(), tag);
    }

    private static ProtectedPii truncated(ProtectedPii envelope) {
        byte[] ciphertext = envelope.ciphertext();
        return new ProtectedPii(envelope.version(), envelope.iv(),
                Arrays.copyOf(ciphertext, Math.max(1, ciphertext.length - 1)), envelope.tag());
    }

    private static ProtectedPii swapped(ProtectedPii envelope) {
        byte[] foreign = new byte[PiiCipher.IV_BYTES];
        RANDOM.nextBytes(foreign);
        return new ProtectedPii(envelope.version(), foreign, envelope.ciphertext(), envelope.tag());
    }

    // ----------------------------------------------------------- envelope format

    private static void envelopeFormatTests() throws Exception {
        section("envelope format");
        byte[] key = freshKey();
        try (PiiCipher cipher = new PiiCipher(key)) {
            ProtectedPii envelope = cipher.encrypt(new PiiRecord("Ada", "ada@example.com"));
            String stored = envelope.toBase64();
            check("stored text carries the format prefix", stored.startsWith("v1:"));
            check("stored text round trips through Base64", envelope.equals(ProtectedPii.fromBase64(stored)));
            check("decoding a parsed envelope works", "Ada".equals(cipher.reveal(stored).name()));

            expectThrows("missing prefix", IllegalArgumentException.class, "must start with",
                    () -> ProtectedPii.fromBase64("deadbeef"));
            expectThrows("empty text", IllegalArgumentException.class, "must not be blank",
                    () -> ProtectedPii.fromBase64("   "));
            expectThrows("null text", IllegalArgumentException.class, "must not be blank",
                    () -> ProtectedPii.fromBase64(null));
            expectThrows("junk inside the Base64 body", IllegalArgumentException.class, "not valid Base64",
                    () -> ProtectedPii.fromBase64("v1:!!!!"));
            expectThrows("too short to hold an IV and a tag", IllegalArgumentException.class, "too short",
                    () -> ProtectedPii.fromBase64("v1:" + Base64.getEncoder().encodeToString(new byte[8])));
            expectThrows("a body with room for exactly nothing", IllegalArgumentException.class, "too short",
                    () -> ProtectedPii.fromBase64("v1:" + Base64.getEncoder()
                            .encodeToString(new byte[1 + PiiCipher.IV_BYTES + PiiCipher.TAG_BYTES])));

            byte[] futureVersion = packedWithVersion((byte) 2, envelope);
            expectThrows("unknown format version", IllegalArgumentException.class, "Unsupported protected PII format version 2",
                    () -> ProtectedPii.fromBase64("v1:" + Base64.getEncoder().encodeToString(futureVersion)));

            expectThrows("iv of the wrong length", IllegalArgumentException.class, "iv must be 12 bytes",
                    () -> new ProtectedPii(PiiCipher.VERSION, new byte[11], new byte[8], new byte[16]));
            expectThrows("tag of the wrong length", IllegalArgumentException.class, "tag must be 16 bytes",
                    () -> new ProtectedPii(PiiCipher.VERSION, new byte[12], new byte[8], new byte[15]));
            expectThrows("empty ciphertext", IllegalArgumentException.class, "ciphertext must not be empty",
                    () -> new ProtectedPii(PiiCipher.VERSION, new byte[12], new byte[0], new byte[16]));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] packedWithVersion(byte version, ProtectedPii envelope) {
        byte[] iv = envelope.iv();
        byte[] ciphertext = envelope.ciphertext();
        byte[] tag = envelope.tag();
        byte[] packed = new byte[1 + iv.length + ciphertext.length + tag.length];
        packed[0] = version;
        int offset = 1;
        System.arraycopy(iv, 0, packed, offset, iv.length);
        offset += iv.length;
        System.arraycopy(ciphertext, 0, packed, offset, ciphertext.length);
        offset += ciphertext.length;
        System.arraycopy(tag, 0, packed, offset, tag.length);
        return packed;
    }

    // -------------------------------------------------------------- key provider

    private static void keyProviderTests() throws Exception {
        section("key provider");
        byte[] key = freshKey();
        String encoded = Base64.getEncoder().encodeToString(key);
        check("a valid Base64 key loads at the right length", KeyProvider.decodeKey(encoded, "test").length == 32);
        check("wrapping and indentation are tolerated",
                KeyProvider.decodeKey("  " + encoded.substring(0, 20) + "\n\t" + encoded.substring(20) + " \n", "test").length == 32);
        check("loadKey accepts an inline key", KeyProvider.loadKey(encoded, null).length == 32);

        Path keyFile = tempDir.resolve("key-file-test.bin");
        Files.write(keyFile, (encoded + "\n").getBytes(StandardCharsets.US_ASCII));
        check("loadKey reads a key file", KeyProvider.loadKey(null, keyFile.toString()).length == 32);
        byte[] fromFile = KeyProvider.loadKey(null, keyFile.toString());
        check("the key file yields the same key", Arrays.equals(key, fromFile));

        loadKeyWithNoConfigurationIsReported();
        expectThrows("key file that does not exist", GeneralSecurityException.class, "does not exist",
                () -> KeyProvider.loadKey(null, tempDir.resolve("nope.bin").toString()));
        expectThrows("directory instead of a key file", GeneralSecurityException.class, "does not exist",
                () -> KeyProvider.loadKey(null, tempDir.toString()));

        byte[] shortKey = new byte[16];
        RANDOM.nextBytes(shortKey);
        expectThrows("a 128 bit key is refused", GeneralSecurityException.class, "must decode to exactly 32 bytes",
                () -> KeyProvider.decodeKey(Base64.getEncoder().encodeToString(shortKey), "test"));
        expectThrows("junk is not Base64", GeneralSecurityException.class, "not valid standard Base64",
                () -> KeyProvider.decodeKey("not-a-key!", "test"));
        expectThrows("the URL-safe alphabet is refused", GeneralSecurityException.class, "not valid standard Base64",
                () -> KeyProvider.decodeKey(urlSafeOnlyKey(), "test"));
        expectThrows("a body one character too long is not decodable Base64", GeneralSecurityException.class,
                "not valid standard Base64", () -> KeyProvider.decodeKey(encoded + "A", "test"));
        // The last group is a full quantum of legal alphabet characters, so this always
        // decodes - and always to 33 bytes, which is what the length check must catch.
        expectThrows("a body that decodes to 33 bytes is refused", GeneralSecurityException.class,
                "must decode to exactly 32 bytes",
                () -> KeyProvider.decodeKey(encoded.substring(0, encoded.length() - 2) + "AA", "test"));
        check("an unpadded but otherwise valid key is accepted, as the JDK decoder allows",
                KeyProvider.decodeKey(stripPadding(encoded), "test").length == 32);
        check("the lenient MIME decoder would have turned a junk key into usable-looking bytes,"
                + " which is why the code uses the strict one", mimeDecoderIsTheHazard());
        expectThrows("an empty key", GeneralSecurityException.class, "is empty",
                () -> KeyProvider.decodeKey("   ", "test"));
        expectThrows("a null key", GeneralSecurityException.class, "is empty",
                () -> KeyProvider.decodeKey(null, "test"));

        check("generated keys are 32 bytes and unique", checkGeneratedKeys());
        check("SecretKeySpec itself is lenient about key length, which is why the code checks", secretKeySpecIsLenient());
    }

    /** Drops the {@code =} padding, which the strict JDK decoder is documented to accept. */
    private static String stripPadding(String encoded) {
        int end = encoded.length();
        while (end > 0 && encoded.charAt(end - 1) == '=') {
            end--;
        }
        return encoded.substring(0, end);
    }

    /**
     * Positive control for the choice of decoder: the MIME decoder silently swallows the
     * junk in {@code "not-a-key!"} and hands back bytes instead of refusing, so a tool
     * that used it would encrypt under a 7 byte key without complaint.
     */
    private static boolean mimeDecoderIsTheHazard() {
        byte[] lenientlyDecoded = Base64.getMimeDecoder().decode("not-a-key!");
        return lenientlyDecoded.length > 0 && lenientlyDecoded.length != KeyProvider.KEY_BYTES;
    }

    /**
     * A valid 32 byte key whose URL-safe encoding differs from the standard one, so the
     * "wrong alphabet" check cannot degrade into a no-op when a random key happens to
     * contain neither '+' nor '/'.
     */
    private static String urlSafeOnlyKey() {
        for (int attempt = 0; attempt < 200; attempt++) {
            byte[] key = freshKey();
            String standard = Base64.getEncoder().encodeToString(key);
            String urlSafe = Base64.getUrlEncoder().encodeToString(key);
            if (!standard.equals(urlSafe)) {
                return urlSafe;
            }
        }
        throw new IllegalStateException("could not build a key that needs the URL-safe alphabet");
    }

    /**
     * {@code loadKey} with nothing configured can only be asserted when the ambient
     * environment really has no key set; say so instead of passing vacuously.
     */
    private static void loadKeyWithNoConfigurationIsReported() {
        if (System.getenv("PII_KEY") == null && System.getenv("PII_KEY_FILE") == null) {
            expectThrows("no key configured at all", GeneralSecurityException.class, "No AES key configured",
                    () -> KeyProvider.loadKey(null, null));
        } else {
            System.out.println("  skip no-key check - PII_KEY/PII_KEY_FILE are set in this environment");
        }
    }

    private static boolean checkGeneratedKeys() {
        byte[] a = KeyProvider.newKey(RANDOM);
        byte[] b = KeyProvider.newKey(RANDOM);
        return a.length == 32 && b.length == 32 && !Arrays.equals(a, b);
    }

    private static boolean secretKeySpecIsLenient() {
        byte[] fourteen = new byte[14];
        RANDOM.nextBytes(fourteen);
        try {
            javax.crypto.spec.SecretKeySpec spec = new javax.crypto.spec.SecretKeySpec(fourteen, "AES");
            return spec.getEncoded().length == 14;
        } catch (IllegalArgumentException rejected) {
            return false;
        }
    }

    // -------------------------------------------------------- input validation

    private static void inputValidationTests() {
        section("input validation");
        expectThrows("null name", IllegalArgumentException.class, "must not be null",
                () -> new PiiRecord(null, "ada@example.com"));
        expectThrows("empty email", IllegalArgumentException.class, "must not be blank",
                () -> new PiiRecord("Ada", ""));
        expectThrows("whitespace only name", IllegalArgumentException.class, "must not be blank",
                () -> new PiiRecord("   ", "ada@example.com"));
        expectThrows("leading space in name", IllegalArgumentException.class, "leading or trailing whitespace",
                () -> new PiiRecord(" Ada", "ada@example.com"));
        expectThrows("over-long name", IllegalArgumentException.class, "at most 200 characters",
                () -> new PiiRecord("p".repeat(201), "ada@example.com"));
        expectThrows("over-long email", IllegalArgumentException.class, "at most 320 characters",
                () -> new PiiRecord("Ada", "e".repeat(320) + "@example.com"));
        expectThrows("newline inside a name", IllegalArgumentException.class, "control or unassigned character",
                () -> new PiiRecord("Ada" + (char) 0x0A + "L", "ada@example.com"));
        expectThrows("lone surrogate in a name", IllegalArgumentException.class, "lone surrogate",
                () -> new PiiRecord("Ada" + (char) 0xD800, "ada@example.com"));
        expectThrows("email without an at sign", IllegalArgumentException.class, "exactly one '@' (none found)",
                () -> new PiiRecord("Ada", "adaexample.com"));
        expectThrows("email with two at signs", IllegalArgumentException.class, "more than one found",
                () -> new PiiRecord("Ada", "ada@@example.com"));
        expectThrows("email with no local part", IllegalArgumentException.class, "local part",
                () -> new PiiRecord("Ada", "@example.com"));
        expectThrows("email with a space in the domain", IllegalArgumentException.class, "forbidden character",
                () -> new PiiRecord("Ada", "ada@exa mple.com"));
        expectThrows("email domain without a dot", IllegalArgumentException.class, "must contain a dot",
                () -> new PiiRecord("Ada", "ada@example"));
        expectThrows("email domain ending in a dot", IllegalArgumentException.class, "top level domain",
                () -> new PiiRecord("Ada", "ada@example."));
        expectThrows("email domain with a digit top level domain", IllegalArgumentException.class, "letters only",
                () -> new PiiRecord("Ada", "ada@example.c0m"));
        expectThrows("double dot in the local part", IllegalArgumentException.class, "double up on '.'",
                () -> new PiiRecord("Ada", "ada..x@example.com"));

        check("an astral character in a name is allowed",
                new PiiRecord("Ada " + new String(Character.toChars(0x1F600)), "ada@example.com").name().length() > 4);

        // The decrypted-bytes path is fed untrusted data, so it must be as strict as the constructor.
        byte[] valid = new PiiRecord("Ada", "ada@example.com").toPlaintextBytes();
        check("a hand-built payload parses", PiiRecord.fromPlaintextBytes(valid).name().equals("Ada"));
        expectThrows("truncated payload", IllegalArgumentException.class, "truncated: it declares",
                () -> PiiRecord.fromPlaintextBytes(Arrays.copyOf(valid, valid.length - 3)));
        expectThrows("payload with a trailing extra byte", IllegalArgumentException.class, "trailing byte",
                () -> PiiRecord.fromPlaintextBytes(concat(valid, new byte[]{7})));
        expectThrows("empty payload", IllegalArgumentException.class, "truncated",
                () -> PiiRecord.fromPlaintextBytes(new byte[0]));
        expectThrows("payload declaring an impossible length", IllegalArgumentException.class, "impossible field length",
                () -> PiiRecord.fromPlaintextBytes(ByteBuffer.allocate(16).putInt(9999).array()));
        expectThrows("payload declaring a negative length", IllegalArgumentException.class, "impossible field length",
                () -> PiiRecord.fromPlaintextBytes(ByteBuffer.allocate(16).putInt(-5).array()));
        expectThrows("payload that is not valid UTF-8", IllegalArgumentException.class, "not valid UTF-8",
                () -> PiiRecord.fromPlaintextBytes(fieldBytes(new byte[]{(byte) 0xC3, (byte) 0x28},
                        "ada@example.com".getBytes(StandardCharsets.UTF_8))));
        expectThrows("payload whose name is blank", IllegalArgumentException.class, "must not be blank",
                () -> PiiRecord.fromPlaintextBytes(fieldBytes(new byte[]{0x20}, "ada@example.com".getBytes(StandardCharsets.UTF_8))));
    }

    private static byte[] fieldBytes(byte[] nameBytes, byte[] emailBytes) {
        return ByteBuffer.allocate(8 + nameBytes.length + emailBytes.length)
                .putInt(nameBytes.length).put(nameBytes)
                .putInt(emailBytes.length).put(emailBytes)
                .array();
    }

    // ------------------------------------------------------------ memory hygiene

    private static void memorySafetyTests() throws Exception {
        section("memory hygiene");
        byte[] key = freshKey();
        PiiCipher cipher = new PiiCipher(key);
        Arrays.fill(key, (byte) 0);
        PiiRecord pii = new PiiRecord("Ada", "ada@example.com");
        String stored = cipher.protect(pii);
        check("the cipher keeps its own copy of the key, so wiping the caller's array is safe",
                pii.equals(cipher.reveal(stored)));
        cipher.close();

        byte[] iv = new byte[PiiCipher.IV_BYTES];
        byte[] ciphertext = new byte[24];
        byte[] tag = new byte[PiiCipher.TAG_BYTES];
        RANDOM.nextBytes(iv);
        RANDOM.nextBytes(ciphertext);
        RANDOM.nextBytes(tag);
        ProtectedPii envelope = new ProtectedPii(PiiCipher.VERSION, iv, ciphertext, tag);
        String before = envelope.toBase64();
        Arrays.fill(iv, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);
        Arrays.fill(tag, (byte) 0);
        check("the envelope copies the arrays it was given, wiping them cannot corrupt it",
                before.equals(envelope.toBase64()));
        byte[] handedOut = envelope.ciphertext();
        Arrays.fill(handedOut, (byte) 0);
        check("mutating the array returned by an accessor cannot corrupt the envelope either",
                before.equals(envelope.toBase64()));
        check("accessors hand out copies, not the live array", !Arrays.equals(handedOut, envelope.ciphertext()));

        ProtectedPii sameByValue = new ProtectedPii(PiiCipher.VERSION, envelope.iv(), envelope.ciphertext(), envelope.tag());
        check("two envelopes holding equal bytes are equal", sameByValue.equals(envelope));
        check("and they hash alike, which the record default would not do for array components",
                sameByValue.hashCode() == envelope.hashCode());
        byte[] differentIv = envelope.iv();
        differentIv[0] ^= 0x01;
        check("an envelope with one different IV byte is not equal (equality is not always true)",
                !new ProtectedPii(PiiCipher.VERSION, differentIv, envelope.ciphertext(), envelope.tag()).equals(envelope));

        byte[] shortKey = new byte[16];
        RANDOM.nextBytes(shortKey);
        expectThrows("a 16 byte key is refused by the cipher itself", IllegalArgumentException.class,
                "must be 32 bytes for AES-256", () -> new PiiCipher(shortKey));
        expectThrows("a null key is refused", IllegalArgumentException.class, "key must not be null",
                () -> new PiiCipher(null));
    }

    // ------------------------------------------------------------------ CLI / E2E

    private static void commandLineTests() throws Exception {
        section("command line and end to end");
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
        String classpath = absoluteClasspath();
        harnessCanLaunchClasses(javaBin, classpath);

        Result noKey = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli", "--name", "Ada", "--email", "ada@example.com"),
                true);
        check("the CLI refuses to run with no key configured (exit 4)", noKey.exit == 4);
        assertContains("no-key message", noKey.output, "No AES key configured");

        Result missingName = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli", "--email", "ada@example.com"), true);
        check("the CLI rejects a missing --name (exit 2)", missingName.exit == 2);
        assertContains("missing name message", missingName.output, "Both --name and --email are required");

        Result badOption = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli", "--nope"), true);
        check("the CLI rejects an unknown option (exit 2)", badOption.exit == 2);
        assertContains("unknown option message", badOption.output, "Unknown option");

        Result badEmail = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli",
                "--key", Base64.getEncoder().encodeToString(freshKey()),
                "--name", "Ada", "--email", "not-an-email"), true);
        check("the CLI rejects an invalid email (exit 2)", badEmail.exit == 2);
        assertContains("invalid email message", badEmail.output, "Input rejected");

        Result help = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli", "--help"), true);
        check("--help succeeds", help.exit == 0);
        assertContains("help mentions the key source", help.output, "never in the code");

        Path generated = tempDir.resolve("generated-key.bin");
        Result keygen = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiKeygen", "--out", generated.toString()), true);
        check("keygen succeeds", keygen.exit == 0);
        assertContains("keygen reports the path", keygen.output, "generated-key.bin");
        check("keygen wrote a file", Files.isRegularFile(generated));
        byte[] generatedBytes = Files.readAllBytes(generated);
        byte[] decodedGenerated = Base64.getDecoder().decode(new String(generatedBytes, StandardCharsets.US_ASCII).trim());
        check("the generated key is 32 random bytes", decodedGenerated.length == 32);
        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(generated);
        check("the key file is readable and writable by the owner only",
                perms.equals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));

        Result overwrite = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiKeygen", "--out", generated.toString()), true);
        check("keygen refuses to overwrite an existing key (exit 3)", overwrite.exit == 3);
        assertContains("overwrite warning", overwrite.output, "Refusing to overwrite");
        check("the refused key file is unchanged",
                Arrays.equals(generatedBytes, Files.readAllBytes(generated)));

        Result forced = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiKeygen", "--out", generated.toString(), "--force"), true);
        check("keygen --force overwrites", forced.exit == 0);
        check("the overwritten key is different", !Arrays.equals(generatedBytes, Files.readAllBytes(generated)));

        // The key file already holds Base64 text, so it is passed through as-is: reading
        // the bytes and encoding them again would be a double encode that decodes to 44
        // bytes and fails the length check for the wrong reason.
        String keyForRun = new String(Files.readAllBytes(generated), StandardCharsets.US_ASCII).trim();
        String name = "Grace Hopper";
        String email = "grace.hopper@example.org";
        Result demo = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli",
                "--name", name, "--email", email, "--key", keyForRun), true);
        check("the demo run succeeds with an inline key (exit 0)", demo.exit == 0);
        assertContains("demo prints the original name", demo.output, name);
        assertContains("demo prints the protected prefix", demo.output, "v1:");
        assertContains("demo reports a matching round trip", demo.output, "Round trip OK");
        assertContains("demo says the second encryption differs", demo.output, "no (as expected)");
        assertTextMissing("demo output", demo.output, keyForRun);
        assertTextMissing("demo output leaks nothing else", demo.output, "at com.sun");
        check("the demo echoes the email it was given", demo.output.contains(email));

        Result viaFile = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli",
                "--name", name, "--email", email, "--key-file", generated.toString()), true);
        check("the demo run succeeds with a key file (exit 0)", viaFile.exit == 0);
        assertContains("key file run reports a matching round trip", viaFile.output, "Round trip OK");
        assertTextMissing("key file run does not print the key", viaFile.output, keyForRun);
        String inlineEnvelope = protectedLine(demo.output);
        String fileEnvelope = protectedLine(viaFile.output);
        check("both runs printed an envelope to compare", !inlineEnvelope.isEmpty() && !fileEnvelope.isEmpty());
        check("the inline key and the key file protect the same input to the same length",
                inlineEnvelope.length() == fileEnvelope.length() && inlineEnvelope.length() > 4);
    }

    /** The first stored envelope printed by the demo, so two runs can be compared. */
    private static String protectedLine(String output) {
        for (String line : output.split("\n")) {
            int start = line.indexOf("v1:");
            if (start >= 0) {
                return line.substring(start).trim();
            }
        }
        return "";
    }

    private record Result(String output, int exit) {
    }

    /**
     * The subprocess harness runs with {@code tempDir} as its working directory, so a
     * relative classpath such as {@code out} would not resolve and every CLI test would
     * fail on a missing class. Make every entry absolute.
     */
    private static String absoluteClasspath() {
        String[] entries = System.getProperty("java.class.path").split(File.pathSeparator);
        List<String> absolute = new ArrayList<>(entries.length);
        for (String entry : entries) {
            absolute.add(Path.of(entry).toAbsolutePath().toString());
        }
        return String.join(File.pathSeparator, absolute);
    }

    /**
     * Control for the subprocess harness: proves the classpath the CLI tests use really
     * resolves the classes, so a later "exit 2" can only mean the option was rejected and
     * not that the JVM could not find {@code pii.PiiCli}.
     */
    private static void harnessCanLaunchClasses(String javaBin, String classpath) throws Exception {
        Result control = runCli(List.of(javaBin, "-cp", classpath, "pii.PiiCli", "--help"), true);
        check("the subprocess harness can resolve the classes it launches (control)",
                control.exit == 0 && control.output.contains("Usage: java pii.PiiCli"));
        Result bogus = runCli(List.of(javaBin, "-cp", classpath, "pii.NotAClass"), true);
        check("a missing class really does produce a non-zero exit (control)", bogus.exit != 0);
        check("so the exit codes asserted below are meaningful (control)", bogus.output.contains("ClassNotFoundException"));
    }

    private static Result runCli(List<String> command, boolean clearKeyEnvironment) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(tempDir.toFile());
        if (clearKeyEnvironment) {
            // The tests must not be influenced by a key the developer happens to have exported.
            builder.environment().remove("PII_KEY");
            builder.environment().remove("PII_KEY_FILE");
        }
        builder.redirectErrorStream(true);
        Process process = builder.start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("command timed out: " + command);
        }
        return new Result(output, process.exitValue());
    }

    // ------------------------------------------------------------------- helpers

    private static byte[] freshKey() {
        return KeyProvider.newKey(RANDOM);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void section(String title) {
        System.out.println("== " + title);
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (condition) {
            System.out.println("  ok   " + what);
        } else {
            System.out.println("  FAIL " + what);
            FAILURES.add(what);
        }
    }

    private static void assertContains(String what, String haystack, String needle) {
        check(what + ": output is not empty", haystack != null && !haystack.isEmpty());
        check(what + ": contains \"" + needle + "\"", haystack != null && haystack.contains(needle));
    }

    /**
     * Asserts {@code needle} is absent, after proving the haystack is non-empty and that
     * the containment probe actually works on these strings - an absence check against an
     * empty capture passes vacuously and would hide a broken producer.
     */
    private static void assertTextMissing(String what, String haystack, String needle) {
        check(what + ": haystack is non-empty so absence means something", haystack != null && !haystack.isEmpty());
        check(what + ": needle is non-empty", needle != null && !needle.isEmpty());
        check(what + ": the needle really matches when present (control)", (haystack + needle).contains(needle));
        check(what + ": does not contain \"" + needle + "\"", haystack == null || !haystack.contains(needle));
    }

    private static void expectThrows(String what, Class<? extends Exception> expected, String messageNeedle, Thrower thrower) {
        checks++;
        try {
            thrower.run();
            System.out.println("  FAIL " + what + " - nothing was thrown");
            FAILURES.add(what + ": nothing was thrown");
        } catch (Exception e) {
            Class<?> actual = e.getClass();
            String message = e.getMessage() == null ? "" : e.getMessage();
            if (!expected.isInstance(e)) {
                System.out.println("  FAIL " + what + " - expected " + expected.getSimpleName() + " but got " + actual.getName() + ": " + message);
                FAILURES.add(what + ": wrong type " + actual.getName());
            } else if (!message.contains(messageNeedle)) {
                System.out.println("  FAIL " + what + " - message does not mention \"" + messageNeedle + "\" but was: " + message);
                FAILURES.add(what + ": wrong message");
            } else {
                System.out.println("  ok   " + what + " -> " + actual.getSimpleName());
            }
        }
    }
}
