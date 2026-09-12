import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Verification harness for SecureDataVault. No test framework is installed on
 * this machine, so this is a plain main() that counts assertions and exits
 * non-zero if any of them fail.
 *
 * It exercises the library API, the key-management paths (keystore, PBKDF2,
 * environment variable) and the command line end to end through real subprocess
 * invocations, because the command line is where a key leak would actually
 * happen. SecureDataVault is in the unnamed package, so its nested types have to
 * be spelled out - types in the unnamed package cannot be imported.
 *
 * Run: javac -d out SecureDataVault.java SelfTest.java && java -cp out SelfTest
 */
public final class SelfTest {

    private static int passed;
    private static final List<String> failures = new ArrayList<>();
    private static Path workDir;

    public static void main(String[] args) throws Exception {
        workDir = Files.createTempDirectory("secure-datavault-test");
        System.out.println("SecureDataVault verification harness");
        System.out.println("work directory: " + workDir);
        System.out.println("JVM AES max key bits: " + SecureDataVault.maxAllowedKeyBits());
        System.out.println();

        section("correctness");
        roundTripAscii();
        roundTripUnicode();
        roundTripEmpty();
        roundTripBinary();
        envelopeIsSelfDescribing();
        envelopeHidesPlaintext();
        ivUniqueness();
        everyKeySizeRoundTrips();

        section("integrity and authentication");
        tamperedBodyRejected();
        truncatedBodyRejected();
        tamperingInEveryRegionRejected();
        tamperedKeyIdRejected();
        versionDowngradeRejected();
        nonCanonicalKeyIdRejected();
        junkBodyRejected();
        multiLineInputRejected();
        wrongKeyRejected();
        contextIsAuthenticated();
        contextCharactersConstrained();
        aadCompositionIsUnambiguous();

        section("key material handling");
        rejectsIllegalKeyLengths();
        handleCopiesKeyBytes();
        closedHandleIsUseless();
        toStringDoesNotLeakKey();
        fingerprintIsStableAndDistinct();
        strictBase64RejectsJunk();
        kdfParameterRecordRules();
        kdfParamsCopySalt();
        passphraseDerivationProperties();
        passphraseSourceIsSingleUse();
        keystoreRoundTrip();
        keystoreRejectsWrongPassword();
        keystoreRejectsMissingAlias();
        keystoreRejectsKeyPairAlias();
        keystoreFileDoesNotHoldRawKey();
        keystoreFilePermissions();
        jceksAlsoWorks();
        generatedKeysAreDistinct();

        section("rotation");
        rotationMovesDataToNewKey();

        section("command line");
        cliKeygenEncryptDecrypt();
        cliHonoursKeySize();
        cliStdPipe();
        cliBinaryFidelity();
        cliRefusesLiteralSecretOption();
        cliWrongContextWritesNothing();
        cliTamperedEnvelopeFails();
        cliRefusesAliasOverwrite();
        cliRotateAcrossKeys();
        cliEnvironmentKeySource();
        cliEnvironmentKeyRejectsJunkWithoutEchoingIt();
        cliEnvironmentKeyRejectsWeakLength();
        cliPasswordFile();
        cliMissingPasswordIsRefused();
        cliPassphraseMode();
        cliKeyInfoLeaksNothing();
        cliUnknownCommand();
        cliHelpExitsCleanly();

        System.out.println();
        System.out.println("passed " + passed + ", failed " + failures.size());
        if (!failures.isEmpty()) {
            System.out.println();
            System.out.println("FAILURES");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.exit(1);
        }
        System.out.println("all assertions passed");
    }

    // ------------------------------------------------------------------
    // correctness
    // ------------------------------------------------------------------

    private static void roundTripAscii() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String text = "card=4111111111111111 note=call after 5pm";
            String envelope = SecureDataVault.encrypt(text, k, null);
            check("ascii round trip", text.equals(SecureDataVault.decrypt(envelope, k, null)));
        }
    }

    private static void roundTripUnicode() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            // Built from code points: the platform default charset here is
            // US-ASCII, so non-ASCII literals would not survive compilation.
            String text = "name=" + (char) 0x00E9 + (char) 0x7528 + (char) 0x6237 + " " + (char) 0x1F600;
            String envelope = SecureDataVault.encrypt(text, k, null);
            byte[] back = SecureDataVault.decryptBytes(envelope, k, null);
            check("utf-8 round trip preserves bytes",
                    Arrays.equals(text.getBytes(StandardCharsets.UTF_8), back));
            check("utf-8 round trip preserves text", text.equals(SecureDataVault.decrypt(envelope, k, null)));
        }
    }

    private static void roundTripEmpty() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String envelope = SecureDataVault.encrypt("", k, null);
            check("empty string round trip", "".equals(SecureDataVault.decrypt(envelope, k, null)));
            byte[] back = SecureDataVault.decryptBytes(
                    SecureDataVault.encryptBytes(new byte[0], k, null), k, null);
            check("empty byte array round trip", back.length == 0);
        }
    }

    private static void roundTripBinary() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            byte[] blob = new byte[1 << 20];
            for (int i = 0; i < blob.length; i++) {
                blob[i] = (byte) (i * 31 + 7);
            }
            String envelope = SecureDataVault.encryptBytes(blob, k, null);
            byte[] back = SecureDataVault.decryptBytes(envelope, k, null);
            check("1 MiB binary round trip", Arrays.equals(blob, back), back.length + " bytes back");
        }
    }

    private static void envelopeIsSelfDescribing() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String envelope = SecureDataVault.encrypt("hello", k, null);
            SecureDataVault.Envelope parsed = SecureDataVault.Envelope.parse(envelope);
            check("envelope carries the key fingerprint", k.keyId().equals(parsed.keyId()));
            check("envelope is single-line ASCII", envelope.indexOf('\n') < 0
                    && StandardCharsets.US_ASCII.newEncoder().canEncode(envelope));
            check("envelope reparses to the same text", envelope.equals(parsed.toText()));
            check("envelope body is plaintext plus a 12-byte IV and a 16-byte tag",
                    bodyBytes(envelope) == 12 + 5 + 16, bodyBytes(envelope) + " body bytes");
        }
    }

    private static void envelopeHidesPlaintext() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String secret = "customer-secret-value-0123456789";
            String envelope = SecureDataVault.encrypt(secret, k, null);
            check("envelope does not contain the plaintext", !envelope.contains(secret));
            check("envelope does not contain the plaintext base64",
                    !envelope.contains(Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8))));
        }
    }

    private static void ivUniqueness() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            int rounds = 200;
            Set<String> envelopes = new HashSet<>();
            boolean allDecrypt = true;
            for (int i = 0; i < rounds; i++) {
                String envelope = SecureDataVault.encrypt("the same plaintext every time", k, "ctx");
                envelopes.add(envelope);
                if (!"the same plaintext every time".equals(SecureDataVault.decrypt(envelope, k, "ctx"))) {
                    allDecrypt = false;
                }
            }
            check("every encryption uses a fresh IV", envelopes.size() == rounds, envelopes.size() + " distinct");
            check("every fresh envelope still decrypts", allDecrypt);
        }
    }

    private static void everyKeySizeRoundTrips() throws Exception {
        for (int bits : new int[] { 128, 192, 256 }) {
            try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(bits, "k" + bits)) {
                String text = "size-" + bits;
                String envelope = SecureDataVault.encrypt(text, k, null);
                check(bits + "-bit key round trips", text.equals(SecureDataVault.decrypt(envelope, k, null)));
                check(bits + "-bit key seals the ciphertext plus a 12-byte IV and a 16-byte tag",
                        bodyBytes(envelope) == 12 + text.length() + 16, bodyBytes(envelope) + " body bytes");
            }
        }
        check("the JVM reports a usable AES maximum", SecureDataVault.maxAllowedKeyBits() >= 128,
                "max " + SecureDataVault.maxAllowedKeyBits() + " bits");
    }

    // ------------------------------------------------------------------
    // integrity and authentication
    // ------------------------------------------------------------------

    private static void tamperedBodyRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            final String flipped = flipOneBitOfBody(
                    SecureDataVault.encrypt("transfer 500 to account 99", k, null));
            expectVaultExceptionThrows("a flipped bit in the body is rejected",
                    () -> SecureDataVault.decryptBytes(flipped, k, null), "authentication tag");
        }
    }

    private static void truncatedBodyRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            final String truncated = SecureDataVault.encrypt("some value that is long enough", k, null)
                    .substring(0, 40);
            String message = expectVaultExceptionThrows("a truncated envelope is rejected",
                    () -> SecureDataVault.decryptBytes(truncated, k, null), null);
            check("  ... and says why", message.contains("tag") || message.contains("truncated")
                    || message.contains("Base64"), message);
        }
    }

    private static void tamperingInEveryRegionRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            final String plaintext = "transfer 500 to account 99";
            final String envelope = SecureDataVault.encrypt(plaintext, k, null).trim();
            int sep = envelope.lastIndexOf(':');
            byte[] body = SecureDataVault.decodeBase64Strict(envelope.substring(sep + 1), "body");
            check("the body is IV + ciphertext + tag",
                    body.length == 12 + plaintext.length() + 16, body.length + " bytes");
            // The last base64 characters are the tag, so a bit flip in each
            // region of the payload must be caught, not just in the last byte.
            int[] offsets = { 0, 11, 12, 30, body.length - 1 };
            String[] regions = { "first IV byte", "last IV byte", "first ciphertext byte",
                    "later ciphertext byte", "final tag byte" };
            for (int i = 0; i < offsets.length; i++) {
                byte[] tampered = body.clone();
                tampered[offsets[i]] ^= 0x01;
                final String forged = envelope.substring(0, sep + 1) + Base64.getEncoder().encodeToString(tampered);
                expectVaultExceptionThrows("a flip in the " + regions[i] + " is rejected",
                        () -> SecureDataVault.decryptBytes(forged, k, null), "authentication tag");
            }
        }
    }

    private static void tamperedKeyIdRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            char[] chars = SecureDataVault.encrypt("value", k, null).toCharArray();
            chars[3] = chars[3] == 'a' ? 'b' : 'a';
            final String tampered = new String(chars);
            expectVaultExceptionThrows("a rewritten key id is rejected",
                    () -> SecureDataVault.decryptBytes(tampered, k, null), null);
        }
    }

    private static void versionDowngradeRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String envelope = SecureDataVault.encrypt("value", k, null);
            final String downgraded = "v0:" + envelope.substring(SecureDataVault.ENVELOPE_PREFIX.length());
            String message = expectVaultExceptionThrows("an unknown envelope version is rejected",
                    () -> SecureDataVault.decryptBytes(downgraded, k, null), null);
            check("  ... and names the prefix it wanted", message.contains("v1:"), message);
        }
    }

    private static void nonCanonicalKeyIdRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String envelope = SecureDataVault.encrypt("value", k, null);
            final String upperId = envelope.replace(":" + k.keyId() + ":", ":" + k.keyId().toUpperCase() + ":");
            check("test input really did get an uppercase key id", !upperId.equals(envelope));
            expectVaultExceptionThrows("an uppercase key id is refused (canonical form only)",
                    () -> SecureDataVault.decryptBytes(upperId, k, null), "lowercase hex");
        }
    }

    private static void junkBodyRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            final String junk = SecureDataVault.ENVELOPE_PREFIX + k.keyId() + ":not-a-real-body!!!";
            expectVaultExceptionThrows("a non-Base64 envelope body is rejected",
                    () -> SecureDataVault.decryptBytes(junk, k, null), "Base64");
        }
    }

    private static void multiLineInputRejected() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String envelope = SecureDataVault.encrypt("value", k, null);
            final String twoLines = envelope.substring(0, 20) + "\n" + envelope.substring(20);
            expectVaultExceptionThrows("input holding two envelopes is rejected",
                    () -> SecureDataVault.decryptBytes(twoLines, k, null), "single line");
        }
    }

    private static void wrongKeyRejected() throws Exception {
        try (SecureDataVault.KeyHandle a = SecureDataVault.generateKey(256, "a");
                SecureDataVault.KeyHandle b = SecureDataVault.generateKey(256, "b")) {
            String envelope = SecureDataVault.encrypt("value for a only", a, null);
            String message = expectVaultExceptionThrows("the wrong key is rejected",
                    () -> SecureDataVault.decryptBytes(envelope, b, null), null);
            check("  ... and reports both fingerprints",
                    message.contains(a.keyId()) && message.contains(b.keyId()), message);
        }
    }

    private static void contextIsAuthenticated() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            String envelope = SecureDataVault.encrypt("salary=99000", k, "employee-7");
            check("matching context decrypts",
                    "salary=99000".equals(SecureDataVault.decrypt(envelope, k, "employee-7")));
            String wrong = expectVaultExceptionThrows("a different context is rejected",
                    () -> SecureDataVault.decrypt(envelope, k, "employee-8"), null);
            check("  ... as an authentication-tag failure", wrong.contains("authentication tag"), wrong);
            expectVaultExceptionThrows("omitting the context is rejected",
                    () -> SecureDataVault.decrypt(envelope, k, null), null);
            String noContext = SecureDataVault.encrypt("salary=99000", k, null);
            expectVaultExceptionThrows("adding a context that was never used is rejected",
                    () -> SecureDataVault.decrypt(noContext, k, "employee-7"), null);
        }
    }

    private static void contextCharactersConstrained() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            expectVaultExceptionThrows("a context containing the AAD separator is refused",
                    () -> SecureDataVault.encrypt("x", k, "a|b"), "printable ASCII");
            expectVaultExceptionThrows("a context containing a newline is refused",
                    () -> SecureDataVault.encrypt("x", k, "a\nb"), "printable ASCII");
            expectVaultExceptionThrows("a context containing a space is refused",
                    () -> SecureDataVault.encrypt("x", k, "a b"), "printable ASCII");
        }
    }

    private static void aadCompositionIsUnambiguous() throws Exception {
        try (SecureDataVault.KeyHandle k = SecureDataVault.generateKey(256, "k1")) {
            // The key id field has a fixed width, so no context can shift the
            // field boundary and make two different (keyId, context) pairs
            // produce the same AAD.
            byte[] plain = SecureDataVault.additionalAuthenticatedData(k.keyId(), null);
            byte[] withEmpty = SecureDataVault.additionalAuthenticatedData(k.keyId(), "");
            check("null and empty context produce the same AAD", Arrays.equals(plain, withEmpty));
            check("AAD starts with the version tag",
                    new String(plain, StandardCharsets.US_ASCII).startsWith(SecureDataVault.HEADER + "|"));
            byte[] ctxA = SecureDataVault.additionalAuthenticatedData(k.keyId(), "ab");
            byte[] ctxB = SecureDataVault.additionalAuthenticatedData(k.keyId(), "ab|c".replace("|", "-"));
            check("different contexts produce different AAD", !Arrays.equals(ctxA, ctxB));
        }
    }

    // ------------------------------------------------------------------
    // key material handling
    // ------------------------------------------------------------------

    private static void rejectsIllegalKeyLengths() {
        int[] bad = {0, 1, 8, 15, 20, 31, 33, 64};
        for (int n : bad) {
            final byte[] bytes = new byte[n];
            expectThrows("a " + n + "-byte key is refused at the boundary", IllegalArgumentException.class,
                    () -> SecureDataVault.KeyHandle.of(bytes, "test"));
        }
        for (int n : new int[]{16, 24, 32}) {
            try (SecureDataVault.KeyHandle h = SecureDataVault.KeyHandle.of(new byte[n], "test")) {
                check("a " + n + "-byte key is accepted", h.keyId().length() == SecureDataVault.KEY_ID_HEX_LEN);
            }
        }
        expectThrows("a null key is refused", IllegalArgumentException.class,
                () -> SecureDataVault.KeyHandle.of(null, "test"));
    }

    private static void handleCopiesKeyBytes() throws Exception {
        byte[] raw = SecureDataVault.generateRawKey(256);
        SecureDataVault.KeyHandle handle = SecureDataVault.KeyHandle.of(raw, "copied");
        // Wipe the caller's buffer: the handle must be unaffected. A field or a
        // record component that adopted the array would have been corrupted here.
        Arrays.fill(raw, (byte) 0);
        String envelope = SecureDataVault.encrypt("still works", handle, null);
        check("the handle does not alias the caller's key array",
                "still works".equals(SecureDataVault.decrypt(envelope, handle, null)));
        handle.close();
    }

    private static void closedHandleIsUseless() throws Exception {
        SecureDataVault.KeyHandle handle = SecureDataVault.generateKey(256, "closing");
        String envelope = SecureDataVault.encrypt("value", handle, null);
        handle.close();
        check("isDestroyed is visible", handle.isDestroyed());
        expectThrows("a destroyed handle refuses to encrypt", IllegalStateException.class,
                () -> SecureDataVault.encrypt("value", handle, null));
        expectThrows("a destroyed handle refuses to decrypt", IllegalStateException.class,
                () -> SecureDataVault.decryptBytes(envelope, handle, null));
        handle.close();
        check("close is idempotent", true);
    }

    private static void toStringDoesNotLeakKey() throws Exception {
        byte[] raw = "LEAK-CHECK-KEY-0123456789ABCDEF0".getBytes(StandardCharsets.US_ASCII);
        check("the leak-check key is a legal length", raw.length == 32, raw.length + " bytes");
        try (SecureDataVault.KeyHandle handle = SecureDataVault.KeyHandle.of(raw, "leak-check")) {
            String asText = new String(raw, StandardCharsets.US_ASCII);
            String asHex = toHex(raw);
            String asBase64 = Base64.getEncoder().encodeToString(raw);
            String printed = handle.toString() + " | " + handle.source() + " | " + handle.keyId();
            check("KeyHandle.toString() omits the key",
                    !printed.contains(asText) && !printed.contains(asHex) && !printed.contains(asBase64), printed);
            check("KeyHandle says where the key came from",
                    printed.contains("leak-check") && printed.contains(handle.keyId()));
        }
    }

    private static void fingerprintIsStableAndDistinct() throws Exception {
        byte[] raw = SecureDataVault.generateRawKey(256);
        try (SecureDataVault.KeyHandle one = SecureDataVault.KeyHandle.of(raw, "a");
                SecureDataVault.KeyHandle two = SecureDataVault.KeyHandle.of(raw, "b")) {
            check("the fingerprint depends only on the key bytes", one.keyId().equals(two.keyId()));
        }
        try (SecureDataVault.KeyHandle other = SecureDataVault.generateKey(256, "c")) {
            check("fingerprint is lowercase hex of the right width",
                    other.keyId().matches("[0-9a-f]{16}"), other.keyId());
        }
        try (SecureDataVault.KeyHandle a = SecureDataVault.generateKey(256, "a");
                SecureDataVault.KeyHandle b = SecureDataVault.generateKey(256, "b")) {
            check("different random keys get different fingerprints", !a.keyId().equals(b.keyId()));
        }
    }

    private static void strictBase64RejectsJunk() {
        String[] junk = {"not-a-key!", "!!!!", "a", "YWJj!!!!", "=YWJj"};
        for (String value : junk) {
            try {
                SecureDataVault.decodeBase64Strict(value, "test value", true);
                fail("strict decoder accepted '" + collapse(value) + "'");
            } catch (SecureDataVault.VaultException expected) {
                passed++;
            }
        }
        // The point of the strict decoder: the MIME decoder silently drops every
        // character outside the alphabet, so the same string becomes a short,
        // weak "key" instead of an error.
        byte[] mime = Base64.getMimeDecoder().decode("not-a-key!");
        check("the MIME decoder would have accepted that junk as a key (why we avoid it)",
                mime.length < 16, mime.length + " bytes");
        try {
            byte[] ok = SecureDataVault.decodeBase64Strict(" YWJj\n", "test value");
            check("surrounding whitespace is tolerated",
                    Arrays.equals("abc".getBytes(StandardCharsets.US_ASCII), ok));
        } catch (SecureDataVault.VaultException e) {
            fail("whitespace-tolerant decode threw: " + e.getMessage());
        }
    }

    private static void kdfParameterRecordRules() throws Exception {
        SecureDataVault.KdfParams params = SecureDataVault.newKdfParams(200_000);
        String record = params.toRecord();
        SecureDataVault.KdfParams parsed = SecureDataVault.KdfParams.parseRecord(record);
        check("KDF record round trips", parsed.iterations() == 200_000
                && Arrays.equals(parsed.salt(), params.salt()));
        check("KDF record is ASCII and self-describing",
                record.startsWith("kdf:v1:pbkdf2-hmac-sha256:200000:"));
        final byte[] salt = new byte[32];
        final String goodSalt = Base64.getEncoder().encodeToString(salt);
        expectVaultExceptionThrows("a record that lowers the work factor is refused",
                () -> SecureDataVault.KdfParams.parseRecord("kdf:v1:pbkdf2-hmac-sha256:1000:" + goodSalt), null);
        expectVaultExceptionThrows("a record with a non-numeric iteration count is refused",
                () -> SecureDataVault.KdfParams.parseRecord("kdf:v1:pbkdf2-hmac-sha256:many:" + goodSalt), null);
        expectVaultExceptionThrows("a record with a short salt is refused",
                () -> SecureDataVault.KdfParams.parseRecord("kdf:v1:pbkdf2-hmac-sha256:600000:"
                        + Base64.getEncoder().encodeToString(new byte[8])), null);
        expectVaultExceptionThrows("a record with the wrong prefix is refused",
                () -> SecureDataVault.KdfParams.parseRecord("ssh:key:" + goodSalt), null);
        expectVaultExceptionThrows("an empty record is refused",
                () -> SecureDataVault.KdfParams.parseRecord("   "), null);
    }

    private static void kdfParamsCopySalt() {
        byte[] salt = new byte[32];
        Arrays.fill(salt, (byte) 7);
        SecureDataVault.KdfParams params = new SecureDataVault.KdfParams(100_000, salt);
        Arrays.fill(salt, (byte) 0);
        check("KdfParams does not alias the caller's salt", params.salt()[0] == 7);
        params.salt()[0] = 99;
        check("KdfParams.salt() hands out a copy", params.salt()[0] == 7);
        expectThrows("an iteration count below the floor is refused", IllegalArgumentException.class,
                () -> new SecureDataVault.KdfParams(1000, new byte[32]));
    }

    private static void passphraseDerivationProperties() throws Exception {
        SecureDataVault.KdfParams params = SecureDataVault.newKdfParams(100_000);
        char[] pass = "correct horse battery staple".toCharArray();
        String first;
        try (SecureDataVault.KeyHandle one =
                new SecureDataVault.PassphraseKeySource(pass, params, "test").load()) {
            first = one.keyId();
            check("a derived key is a full AES-256 key", first.matches("[0-9a-f]{16}"));
            check("a derived key is usable", "v".equals(SecureDataVault.decrypt(
                    SecureDataVault.encrypt("v", one, null), one, null)));
        }
        try (SecureDataVault.KeyHandle again =
                new SecureDataVault.PassphraseKeySource(pass, params, "test").load()) {
            check("the same passphrase and salt derive the same key", first.equals(again.keyId()));
        }
        wipe(pass);
        char[] other = "correct horse battery stapler".toCharArray();
        try (SecureDataVault.KeyHandle different =
                new SecureDataVault.PassphraseKeySource(other, params, "test").load()) {
            check("a different passphrase derives a different key", !first.equals(different.keyId()));
        }
        wipe(other);
        SecureDataVault.KdfParams otherSalt = SecureDataVault.newKdfParams(100_000);
        char[] same = "correct horse battery staple".toCharArray();
        try (SecureDataVault.KeyHandle rotatedSalt =
                new SecureDataVault.PassphraseKeySource(same, otherSalt, "test").load()) {
            check("a different salt derives a different key", !first.equals(rotatedSalt.keyId()));
        }
        wipe(same);
    }

    private static void passphraseSourceIsSingleUse() throws Exception {
        SecureDataVault.KdfParams params = SecureDataVault.newKdfParams(100_000);
        final char[] pass = "erase-me".toCharArray();
        final SecureDataVault.PassphraseKeySource source =
                new SecureDataVault.PassphraseKeySource(pass, params, "test");
        try (SecureDataVault.KeyHandle first = source.load()) {
            check("the passphrase source loads once", first.keyId().matches("[0-9a-f]{16}"));
        }
        String message = expectVaultExceptionThrows("a second load is refused, not silently wrong",
                source::load, null);
        check("  ... and says the secret was erased", message.contains("erased"), message);
        wipe(pass);
    }

    private static void keystoreRoundTrip() throws Exception {
        Path ks = workDir.resolve("vault.p12");
        char[] pw = "store-password".toCharArray();
        SecureDataVault.KeyGeneration made =
                SecureDataVault.storeGeneratedKey(ks, "PKCS12", "appkey", pw, 256, false);
        check("keygen wrote a keystore", made != null && Files.isRegularFile(ks));
        try (SecureDataVault.KeyHandle loaded =
                new SecureDataVault.KeyStoreKeySource(ks, "PKCS12", "appkey", pw).load()) {
            check("the stored key reads back with the same fingerprint", made.keyId.equals(loaded.keyId()));
            check("a keystore key encrypts and decrypts",
                    "sensitive".equals(SecureDataVault.decrypt(
                            SecureDataVault.encrypt("sensitive", loaded, "c"), loaded, "c")));
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) {
            store.load(in, pw.clone());
            check("the entry really is a symmetric key entry",
                    store.entryInstanceOf("appkey", KeyStore.SecretKeyEntry.class));
        }
        wipe(pw);
    }

    private static void keystoreRejectsWrongPassword() throws Exception {
        final Path ks = workDir.resolve("vault.p12");
        String message = expectVaultExceptionThrows("the wrong keystore password is refused",
                () -> new SecureDataVault.KeyStoreKeySource(ks, "PKCS12", "appkey",
                        "wrong-password".toCharArray()).load(), null);
        check("  ... and mentions the password", message.toLowerCase().contains("password"), message);
    }

    private static void keystoreRejectsMissingAlias() throws Exception {
        final Path ks = workDir.resolve("vault.p12");
        final char[] pw = "store-password".toCharArray();
        String message = expectVaultExceptionThrows("a missing alias is refused",
                () -> new SecureDataVault.KeyStoreKeySource(ks, "PKCS12", "no-such-alias", pw).load(), null);
        check("  ... and lists what is present", message.contains("appkey"), message);
        wipe(pw);
    }

    private static void keystoreRejectsKeyPairAlias() throws Exception {
        // A keystore holding a TLS-style key pair is the realistic mistake: the
        // user points the tool at the wrong keystore and expects it to work.
        // keytool cannot store a private key without a certificate chain, so this
        // fixture is generated with keytool rather than the KeyStore API.
        Path ks = workDir.resolve("keypair.p12");
        Files.deleteIfExists(ks);
        Result gen = runTool("store-password",
                "-genkeypair", "-alias", "signing", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=test-only", "-validity", "1", "-keystore", ks.toString(),
                "-storetype", "PKCS12", "-storepass:env", "T_PW");
        check("keytool produced a key-pair keystore", gen.exit == 0 && Files.isRegularFile(ks), gen.describe());
        final char[] pw = "store-password".toCharArray();
        String message = expectVaultExceptionThrows("a key-pair alias is refused for data encryption",
                () -> new SecureDataVault.KeyStoreKeySource(ks, "PKCS12", "signing", pw).load(), null);
        check("  ... and explains that it is not a symmetric entry", message.contains("symmetric"), message);
        wipe(pw);
    }

    private static void keystoreFileDoesNotHoldRawKey() throws Exception {
        Path ks = workDir.resolve("vault.p12");
        final char[] pw = "store-password".toCharArray();
        try (SecureDataVault.KeyHandle key =
                new SecureDataVault.KeyStoreKeySource(ks, "PKCS12", "appkey", pw).load()) {
            byte[] raw = key.use(spec -> spec.getEncoded());
            byte[] file = Files.readAllBytes(ks);
            check("the keystore file does not contain the raw key", !containsSequence(file, raw));
            Arrays.fill(raw, (byte) 0);
        }
        wipe(pw);
    }

    private static void keystoreFilePermissions() throws Exception {
        Path ks = workDir.resolve("vault.p12");
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(ks);
            check("the keystore is owner read/write only",
                    perms.contains(PosixFilePermission.OWNER_READ)
                            && perms.contains(PosixFilePermission.OWNER_WRITE)
                            && !perms.contains(PosixFilePermission.GROUP_READ)
                            && !perms.contains(PosixFilePermission.OTHERS_READ), perms.toString());
        } catch (UnsupportedOperationException e) {
            System.out.println("  skip posix permissions are unavailable here");
        }
    }

    private static void jceksAlsoWorks() throws Exception {
        Path ks = workDir.resolve("legacy.jceks");
        char[] pw = "store-password".toCharArray();
        SecureDataVault.KeyGeneration made =
                SecureDataVault.storeGeneratedKey(ks, "JCEKS", "appkey", pw, 128, false);
        check("a JCEKS keystore can hold the key too", made != null);
        try (SecureDataVault.KeyHandle key =
                new SecureDataVault.KeyStoreKeySource(ks, "JCEKS", "appkey", pw).load()) {
            check("a 128-bit key round trips", made.keyId.equals(key.keyId())
                    && "x".equals(SecureDataVault.decrypt(SecureDataVault.encrypt("x", key, null), key, null)));
        }
        wipe(pw);
    }

    private static void generatedKeysAreDistinct() throws Exception {
        byte[] a = SecureDataVault.generateRawKey(256);
        byte[] b = SecureDataVault.generateRawKey(256);
        check("generated keys are 32 bytes", a.length == 32 && b.length == 32);
        check("two generated keys differ", !Arrays.equals(a, b));
        expectVaultExceptionThrows("an odd key size is refused",
                () -> SecureDataVault.generateRawKey(200), null);
        expectVaultExceptionThrows("a key size above the AES maximum is refused",
                () -> SecureDataVault.generateRawKey(512), null);
    }

    // ------------------------------------------------------------------
    // rotation
    // ------------------------------------------------------------------

    private static void rotationMovesDataToNewKey() throws Exception {
        try (SecureDataVault.KeyHandle oldKey = SecureDataVault.generateKey(256, "old");
                SecureDataVault.KeyHandle newKey = SecureDataVault.generateKey(256, "new")) {
            String envelope = SecureDataVault.encrypt("account=1234", oldKey, "row-9");
            String rotated = SecureDataVault.reencrypt(envelope, oldKey, newKey, "row-9");
            check("rotation preserves the plaintext",
                    "account=1234".equals(SecureDataVault.decrypt(rotated, newKey, "row-9")));
            check("rotation stamps the new key id", rotated.contains(":" + newKey.keyId() + ":"));
            expectVaultExceptionThrows("the old key can no longer read the rotated value",
                    () -> SecureDataVault.decrypt(rotated, oldKey, "row-9"), null);
            expectVaultExceptionThrows("the rotated value still requires its context",
                    () -> SecureDataVault.decrypt(rotated, newKey, "row-10"), null);
        }
    }

    // ------------------------------------------------------------------
    // command line
    // ------------------------------------------------------------------

    private static void cliKeygenEncryptDecrypt() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli1"));
        Path ks = dir.resolve("vault.p12");
        Result keygen = cli("keygen", "--keystore", ks.toString(), "--alias", "appkey",
                "--storepass-env", "T_PW");
        expectExit("cli keygen succeeds", keygen, 0);
        check("cli keygen reports a fingerprint", keygen.stdout().matches("(?s).*key id\\s+[0-9a-f]{16}.*"),
                keygen.stdout());

        Result encrypt = cli("encrypt", "--keystore", ks.toString(), "--storepass-env", "T_PW",
                "--text", "ssn=123-45-6789", "--context", "customer-42",
                "--out", dir.resolve("a.enc").toString());
        expectExit("cli encrypt succeeds", encrypt, 0);
        check("cli encrypt prints the envelope, not the plaintext",
                encrypt.stdout().isEmpty() && !encrypt.stderr().contains("123-45-6789"), encrypt.describe());

        Result decrypt = cli("decrypt", "--keystore", ks.toString(), "--storepass-env", "T_PW",
                "--in", dir.resolve("a.enc").toString(), "--context", "customer-42");
        expectExit("cli decrypt succeeds", decrypt, 0);
        check("cli round trip returns the plaintext", "ssn=123-45-6789".equals(decrypt.stdout()), decrypt.stdout());
    }

    private static void cliHonoursKeySize() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-size"));
        Path k192 = dir.resolve("k192.p12");
        Result keygen = cli("keygen", "--keystore", k192.toString(), "--keysize", "192",
                "--storepass-env", "T_PW");
        expectExit("cli keygen --keysize 192", keygen, 0);
        check("  ... and says what it made", keygen.stdout().contains("192-bit"), keygen.stdout());
        expectExit("cli round trip under the 192-bit key",
                cli("encrypt", "--keystore", k192.toString(), "--storepass-env", "T_PW",
                        "--text", "size-192", "--out", dir.resolve("s.enc").toString()), 0);
        Result back = cli("decrypt", "--keystore", k192.toString(), "--storepass-env", "T_PW",
                "--in", dir.resolve("s.enc").toString());
        expectExit("cli decrypt under the 192-bit key", back, 0);
        check("  ... yielding the original text", "size-192".equals(back.stdout()), back.stdout());
        Result odd = cli("keygen", "--keystore", dir.resolve("bad.p12").toString(), "--keysize", "200",
                "--storepass-env", "T_PW");
        expectExitFailure("cli refuses a key size that is not 128, 192 or 256", odd);
        check("  ... naming the allowed sizes", odd.stderr().contains("128, 192 or 256"), odd.stderr());
        check("  ... and writes no keystore", !Files.exists(dir.resolve("bad.p12")));
    }

    private static void cliStdPipe() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-pipe"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (pipe setup)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        byte[] plain = "piped through stdin".getBytes(StandardCharsets.UTF_8);
        Result enc = cli(plain, "encrypt", "--keystore", ks.toString(), "--storepass-env", "T_PW");
        expectExit("cli encrypt from stdin", enc, 0);
        Result dec = cli(enc.out, "decrypt", "--keystore", ks.toString(), "--storepass-env", "T_PW");
        expectExit("cli decrypt from stdin", dec, 0);
        check("stdin/stdout round trip", Arrays.equals(plain, dec.out), dec.stdout());
    }

    private static void cliBinaryFidelity() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-bin"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (binary setup)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        byte[] blob = new byte[4096];
        for (int i = 0; i < blob.length; i++) {
            blob[i] = (byte) i;
        }
        Files.write(dir.resolve("blob.bin"), blob);
        expectExit("cli encrypts a binary file", cli("encrypt", "--keystore", ks.toString(),
                "--storepass-env", "T_PW", "--in", dir.resolve("blob.bin").toString(),
                "--out", dir.resolve("blob.enc").toString()), 0);
        Result dec = cli("decrypt", "--keystore", ks.toString(),
                "--storepass-env", "T_PW", "--in", dir.resolve("blob.enc").toString(),
                "--out", dir.resolve("blob.out").toString());
        expectExit("cli decrypts a binary file", dec, 0);
        // Read only if it is there: a missing file is one failed assertion, not a
        // crash that would hide every test after it.
        Path produced = dir.resolve("blob.out");
        check("binary file survives the round trip byte for byte",
                Files.isRegularFile(produced) && Arrays.equals(blob, Files.readAllBytes(produced)), dec.describe());
    }

    private static void cliRefusesLiteralSecretOption() throws Exception {
        Result r = cli("encrypt", "--keystore", "/tmp/nope.p12", "--storepass", "hunter2");
        expectExitFailure("a password given as an argument is refused", r);
        check("  ... with an explanation", r.stderr().contains("command line"), r.stderr());
    }

    private static void cliWrongContextWritesNothing() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-ctx"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (context setup)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        expectExit("cli encrypt with context", cli("encrypt", "--keystore", ks.toString(),
                "--storepass-env", "T_PW", "--text", "secret-value", "--context", "row-1",
                "--out", dir.resolve("c.enc").toString()), 0);
        Result wrong = cli("decrypt", "--keystore", ks.toString(), "--storepass-env", "T_PW",
                "--in", dir.resolve("c.enc").toString(), "--context", "row-2",
                "--out", dir.resolve("leak.txt").toString());
        expectExitFailure("cli decrypt with the wrong context fails", wrong);
        check("  ... and no plaintext file is written", !Files.exists(dir.resolve("leak.txt")));
        check("  ... and the error names the tag check", wrong.stderr().contains("authentication tag"),
                wrong.stderr());
    }

    private static void cliTamperedEnvelopeFails() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-tamper"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (tamper setup)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        Path enc = dir.resolve("t.enc");
        expectExit("cli encrypt (tamper setup)", cli("encrypt", "--keystore", ks.toString(),
                "--storepass-env", "T_PW", "--text", "value-to-tamper", "--out", enc.toString()), 0);
        String text = new String(Files.readAllBytes(enc), StandardCharsets.US_ASCII).trim();
        Files.write(enc, flipOneBitOfBody(text).getBytes(StandardCharsets.US_ASCII));
        Result r = cli("decrypt", "--keystore", ks.toString(), "--storepass-env", "T_PW", "--in", enc.toString());
        expectExitFailure("cli refuses a tampered envelope file", r);
        check("  ... and prints no plaintext", r.stdout().isEmpty(), r.stdout());
    }

    private static void cliRefusesAliasOverwrite() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-overwrite"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (first)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        String first = cli("keyinfo", "--keystore", ks.toString(), "--storepass-env", "T_PW").stdout();
        Result again = cli("keygen", "--keystore", ks.toString(), "--storepass-env", "T_PW");
        expectExitFailure("cli refuses to overwrite an existing alias", again);
        check("  ... and tells the user how to proceed", again.stderr().contains("--replace-alias"),
                again.stderr());
        String after = cli("keyinfo", "--keystore", ks.toString(), "--storepass-env", "T_PW").stdout();
        check("  ... leaving the original key in place", first.equals(after), first + " vs " + after);
        expectExit("cli can add a second alias", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW", "--alias", "other"), 0);
        Result replaced = cli("keygen", "--keystore", ks.toString(), "--storepass-env", "T_PW",
                "--replace-alias");
        expectExit("cli can replace an alias when told to", replaced, 0);
        check("  ... and that changes the key", !replaced.stdout().contains(first.substring(first.indexOf("key id") + 7).trim()),
                replaced.stdout());
    }

    private static void cliRotateAcrossKeys() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-rotate"));
        Path oldKs = dir.resolve("old.p12");
        Path newKs = dir.resolve("new.p12");
        expectExit("cli keygen old", cli("keygen", "--keystore", oldKs.toString(), "--storepass-env", "T_PW"), 0);
        expectExit("cli keygen new", cli("keygen", "--keystore", newKs.toString(), "--storepass-env", "T_PW"), 0);
        Path bundle = dir.resolve("values.txt");
        Path rotatedFile = dir.resolve("rotated.txt");
        // Two values bound to their own context plus one without any context.
        StringBuilder envelopes = new StringBuilder();
        for (int i = 0; i < 2; i++) {
            Result r = cli("encrypt", "--keystore", oldKs.toString(), "--storepass-env", "T_PW",
                    "--text", "value-" + i, "--context", "row-" + i);
            expectExit("cli encrypt value-" + i, r, 0);
            envelopes.append("row-").append(i).append('\t').append(r.stdout().trim()).append('\n');
        }
        Result loose = cli("encrypt", "--keystore", oldKs.toString(), "--storepass-env", "T_PW",
                "--text", "no-context-here");
        expectExit("cli encrypt a value with no context", loose, 0);
        envelopes.append(loose.stdout().trim()).append('\n');
        Files.write(bundle, envelopes.toString().getBytes(StandardCharsets.US_ASCII));

        Result rotate = cli("rotate", "--in", bundle.toString(), "--out", rotatedFile.toString(),
                "--keystore", oldKs.toString(), "--storepass-env", "T_PW",
                "--new-keystore", newKs.toString(), "--new-storepass-env", "T_PW");
        expectExit("cli rotate succeeds", rotate, 0);
        List<String> rotated = Files.readAllLines(rotatedFile, StandardCharsets.US_ASCII);
        check("cli rotate keeps the count", rotated.size() == 3, "got " + rotated.size());
        for (int i = 0; i < 2; i++) {
            check("rotated line " + i + " keeps its context prefix",
                    rotated.get(i).startsWith("row-" + i + "\t"), collapse(rotated.get(i)));
            String envelope = rotated.get(i).substring(rotated.get(i).indexOf('\t') + 1);
            Result good = cli("decrypt", "--keystore", newKs.toString(), "--storepass-env", "T_PW",
                    "--text", envelope, "--context", "row-" + i);
            expectExit("rotated value " + i + " reads with the new key", good, 0);
            check("  ... holding the original plaintext", ("value-" + i).equals(good.stdout()), good.stdout());
            Result bad = cli("decrypt", "--keystore", oldKs.toString(), "--storepass-env", "T_PW",
                    "--text", envelope, "--context", "row-" + i);
            expectExitFailure("  ... and no longer with the old key", bad);
        }
        String bare = rotated.get(2);
        check("a context-free line stays context-free", !bare.contains("\t"), collapse(bare));
        Result looseBack = cli("decrypt", "--keystore", newKs.toString(), "--storepass-env", "T_PW",
                "--text", bare);
        expectExit("the context-free value still rotates and reads", looseBack, 0);
        check("  ... holding its plaintext", "no-context-here".equals(looseBack.stdout()), looseBack.stdout());

        // One unreadable line must fail the whole batch and write nothing, rather
        // than leaving a partially rotated file behind. This line is well formed
        // but stamped with a key id that is not in either keystore.
        String foreign = "v1:0000000000000000:" + Base64.getEncoder().encodeToString(new byte[40]);
        Path mixed = dir.resolve("mixed.txt");
        Files.write(mixed, (envelopes + foreign + "\n").getBytes(StandardCharsets.US_ASCII));
        Result broken = cli("rotate", "--in", mixed.toString(), "--out", dir.resolve("never.txt").toString(),
                "--keystore", oldKs.toString(), "--storepass-env", "T_PW",
                "--new-keystore", newKs.toString(), "--new-storepass-env", "T_PW");
        expectExitFailure("one bad line fails the whole rotation", broken);
        check("  ... naming the offending line", broken.stderr().contains("line 4"), broken.stderr());
        check("  ... and writing no output file", !Files.exists(dir.resolve("never.txt")));

        Result sameKey = cli("rotate", "--in", bundle.toString(), "--out", dir.resolve("same.txt").toString(),
                "--keystore", oldKs.toString(), "--storepass-env", "T_PW",
                "--new-keystore", oldKs.toString(), "--new-storepass-env", "T_PW");
        expectExitFailure("cli rotate refuses when old and new key are the same", sameKey);
        check("  ... and says so", sameKey.stderr().contains("same key"), sameKey.stderr());
    }

    private static void cliEnvironmentKeySource() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-envkey"));
        byte[] raw = SecureDataVault.generateRawKey(256);
        String b64 = Base64.getEncoder().encodeToString(raw);
        Result enc = cliWithEnv("T_KEY", b64, "encrypt", "--key-env", "T_KEY", "--text", "env-key-value",
                "--out", dir.resolve("e.enc").toString());
        expectExit("cli encrypt with an environment key", enc, 0);
        Result dec = cliWithEnv("T_KEY", b64, "decrypt", "--key-env", "T_KEY",
                "--in", dir.resolve("e.enc").toString());
        expectExit("cli decrypt with an environment key", dec, 0);
        check("environment key round trip", "env-key-value".equals(dec.stdout()), dec.stdout());
        Result info = cliWithEnv("T_KEY", b64, "keyinfo", "--key-env", "T_KEY");
        expectExit("cli keyinfo with an environment key", info, 0);
        check("cli keyinfo leaks no key material", !info.stdout().contains(b64), info.stdout());
        Result unset = cli("keyinfo", "--key-env", "T_KEY_NOT_SET");
        expectExitFailure("cli reports a missing environment key", unset);
        check("  ... and names the variable", unset.stderr().contains("T_KEY_NOT_SET"), unset.stderr());
    }

    private static void cliEnvironmentKeyRejectsJunkWithoutEchoingIt() throws Exception {
        String junk = "not-a-key-do-not-echo-me";
        Result r = cliWithEnv("T_BAD", junk, "keyinfo", "--key-env", "T_BAD");
        expectExitFailure("cli rejects a key that is not Base64", r);
        check("  ... and does not echo the rejected secret", !r.stderr().contains(junk), r.stderr());
        check("  ... and explains the strict decoder", r.stderr().contains("Base64"), r.stderr());
    }

    private static void cliEnvironmentKeyRejectsWeakLength() throws Exception {
        String shortKey = Base64.getEncoder().encodeToString(new byte[8]);
        Result r = cliWithEnv("T_SHORT", shortKey, "keyinfo", "--key-env", "T_SHORT");
        expectExitFailure("cli refuses a 64-bit key outright", r);
        check("  ... stating the allowed lengths", r.stderr().contains("16, 24 or 32"), r.stderr());
        String okKey = Base64.getEncoder().encodeToString(SecureDataVault.generateRawKey(128));
        expectExit("cli accepts a 128-bit key", cliWithEnv("T_128", okKey, "keyinfo", "--key-env", "T_128"), 0);
    }

    private static void cliPasswordFile() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-passfile"));
        Path ks = dir.resolve("vault.p12");
        Path passFile = dir.resolve("store.pass");
        Files.write(passFile, "password-from-file\n".getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(passFile, SecureDataVault.ownerReadWrite());
        expectExit("cli keygen with a password file", cli("keygen", "--keystore", ks.toString(),
                "--storepass-file", passFile.toString()), 0);
        expectExit("cli encrypt with a password file", cli("encrypt", "--keystore", ks.toString(),
                "--storepass-file", passFile.toString(), "--text", "from-file",
                "--out", dir.resolve("f.enc").toString()), 0);
        Result dec = cli("decrypt", "--keystore", ks.toString(), "--storepass-file", passFile.toString(),
                "--in", dir.resolve("f.enc").toString());
        expectExit("cli decrypt with a password file", dec, 0);
        check("password file round trip", "from-file".equals(dec.stdout()), dec.stdout());
        Files.setPosixFilePermissions(passFile, EnumSet.allOf(PosixFilePermission.class));
        Result warn = cli("keyinfo", "--keystore", ks.toString(), "--storepass-file", passFile.toString());
        expectExit("cli still works with a loose password file", warn, 0);
        check("cli warns about a world-readable password file", warn.stderr().contains("grants access"),
                warn.stderr());
        Result quiet = cli("keyinfo", "--keystore", ks.toString(), "--storepass-file", passFile.toString(),
                "--force-insecure-fileperms");
        check("  ... and the warning can be silenced deliberately", quiet.stderr().isEmpty(), quiet.stderr());
        Files.setPosixFilePermissions(passFile, SecureDataVault.ownerReadWrite());
    }

    private static void cliMissingPasswordIsRefused() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-nopass"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (no-password setup)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        Result r = cli("keyinfo", "--keystore", ks.toString());
        expectExitFailure("cli refuses to run with no password supplied", r);
        check("  ... offering the safe channels", r.stderr().contains("pass-env") || r.stderr().contains("prompt"),
                r.stderr());
        check("  ... and saying the refusal is deliberate", r.stderr().contains("refused on purpose"), r.stderr());
        Result both = cli("keyinfo", "--keystore", ks.toString(), "--key-env", "T_PW",
                "--storepass-env", "T_PW");
        expectExitFailure("cli refuses two key sources at once", both);
        check("  ... rather than guessing", both.stderr().contains("not several"), both.stderr());
        Result badType = cli("keyinfo", "--keystore", ks.toString(), "--keystore-type", "JKS",
                "--storepass-env", "T_PW");
        expectExitFailure("cli refuses JKS as a keystore type", badType);
        check("  ... because JKS cannot hold a symmetric key", badType.stderr().contains("JKS"),
                badType.stderr());
    }

    private static void cliPassphraseMode() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-kdf"));
        Path kdf = dir.resolve("kdf.params");
        expectExit("cli saltgen", cli("saltgen", "--kdf", kdf.toString(), "--iterations", "100000"), 0);
        check("cli saltgen writes a parameter record",
                new String(Files.readAllBytes(kdf), StandardCharsets.US_ASCII).startsWith("kdf:v1:pbkdf2"),
                new String(Files.readAllBytes(kdf), StandardCharsets.US_ASCII));
        Result enc = cliWithEnv("T_PASS", "a memorised passphrase", "encrypt", "--kdf", kdf.toString(),
                "--pass-env", "T_PASS", "--text", "kdf-value", "--out", dir.resolve("k.enc").toString());
        expectExit("cli encrypt with a derived key", enc, 0);
        Result dec = cliWithEnv("T_PASS", "a memorised passphrase", "decrypt", "--kdf", kdf.toString(),
                "--pass-env", "T_PASS", "--in", dir.resolve("k.enc").toString());
        expectExit("cli decrypt with a derived key", dec, 0);
        check("derived key round trip", "kdf-value".equals(dec.stdout()), dec.stdout());
        Result wrong = cliWithEnv("T_PASS", "the wrong passphrase", "decrypt", "--kdf", kdf.toString(),
                "--pass-env", "T_PASS", "--in", dir.resolve("k.enc").toString());
        expectExitFailure("a wrong passphrase cannot decrypt", wrong);
        expectExitFailure("cli refuses to write a weak KDF record",
                cli("saltgen", "--kdf", dir.resolve("weak.params").toString(), "--iterations", "10"));
        expectExitFailure("cli reports a missing KDF record",
                cli("keyinfo", "--kdf", dir.resolve("absent.params").toString(), "--pass-env", "T_PASS"));
        expectExitFailure("cli rejects a malformed KDF record", cli("keyinfo", "--kdf",
                write(dir, "junk.params", "not a kdf record").toString(), "--pass-env", "T_PASS"));
    }

    private static void cliKeyInfoLeaksNothing() throws Exception {
        Path dir = Files.createDirectories(workDir.resolve("cli-keyinfo"));
        Path ks = dir.resolve("vault.p12");
        expectExit("cli keygen (keyinfo setup)", cli("keygen", "--keystore", ks.toString(),
                "--storepass-env", "T_PW"), 0);
        Result info = cli("keyinfo", "--keystore", ks.toString(), "--storepass-env", "T_PW", "--alias", "appkey");
        expectExit("cli keyinfo succeeds", info, 0);
        check("cli keyinfo prints a source and a fingerprint",
                info.stdout().contains("keystore") && info.stdout().matches("(?s).*key id\\s+[0-9a-f]{16}.*"),
                info.stdout());
        check("cli keyinfo output stays short", info.stdout().split("\n").length <= 4, info.stdout());
        expectExitFailure("cli keyinfo fails loudly for an unknown alias",
                cli("keyinfo", "--keystore", ks.toString(), "--storepass-env", "T_PW", "--alias", "ghost"));
    }

    private static void cliUnknownCommand() throws Exception {
        Result r = cli("decrypt-envelope");
        expectExitFailure("an unknown command fails", r);
        check("  ... and says which command it did not know", r.stderr().contains("decrypt-envelope"),
                r.stderr());
        Result bare = cli();
        check("running with no arguments prints usage and fails",
                bare.exit != 0 && bare.stderr().isEmpty() && bare.stdout().contains("Usage"), "exit " + bare.exit);
        Result stray = cli("keyinfo", "positional");
        expectExitFailure("a stray positional argument is refused", stray);
        check("  ... naming the argument", stray.stderr().contains("positional"), stray.stderr());
    }

    private static void cliHelpExitsCleanly() throws Exception {
        Result r = cli("--help");
        expectExitQuiet("help exits 0", r);
        check("help documents the refusal of argv secrets",
                r.stdout().contains("never accepted as a command-line"), "");
        check("help lists the key sources", r.stdout().contains("--key-env") && r.stdout().contains("--keystore"),
                "");
    }

    // ------------------------------------------------------------------
    // subprocess plumbing
    // ------------------------------------------------------------------

    private static final class Result {
        final int exit;
        final byte[] out;
        final String err;

        Result(int exit, byte[] out, String err) {
            this.exit = exit;
            this.out = out;
            this.err = err;
        }

        String stdout() {
            return new String(out, StandardCharsets.UTF_8).trim();
        }

        String stderr() {
            return err;
        }

        String describe() {
            return "exit=" + exit + " stdout='" + stdout() + "' stderr='" + collapse(err) + "'";
        }
    }

    private static Result cli(String... args) throws Exception {
        return cliWithEnv("T_PW", "a-test-keystore-password", new byte[0], args);
    }

    private static Result cli(byte[] stdin, String... args) throws Exception {
        return cliWithEnv("T_PW", "a-test-keystore-password", stdin, args);
    }

    private static Result cliWithEnv(String name, String value, String... args) throws Exception {
        return cliWithEnv(name, value, new byte[0], args);
    }

    private static Result cliWithEnv(String envName, String envValue, byte[] stdin, String... args)
            throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-cp");
        command.add(classPath());
        command.add("SecureDataVault");
        command.addAll(Arrays.asList(args));
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(workDir.toFile());
        pb.environment().put(envName, envValue);
        Process process = pb.start();
        try (OutputStream stdinStream = process.getOutputStream()) {
            if (stdin != null) {
                stdinStream.write(stdin);
            }
        }
        byte[] out = readFully(process.getInputStream());
        byte[] err = readFully(process.getErrorStream());
        int exit = process.waitFor();
        return new Result(exit, out, new String(err, StandardCharsets.UTF_8).trim());
    }

    /**
     * The running class path with every entry made absolute. The children run in
     * a scratch directory, so the bare "." that a plain 'java SelfTest' puts in
     * the class path would point at nothing and every command-line test would
     * report a missing main class instead of a real result.
     */
    private static String classPath() {
        List<String> entries = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            entries.add(Path.of(entry).toAbsolutePath().toString());
        }
        return String.join(File.pathSeparator, entries);
    }

    /** Runs the JDK keytool, passing the store password through the environment. */
    private static Result runTool(String password, String... toolArgs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(Arrays.asList(toolArgs));
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(workDir.toFile());
        pb.environment().put("T_PW", password);
        Process process = pb.start();
        byte[] out = readFully(process.getInputStream());
        byte[] err = readFully(process.getErrorStream());
        int exit = process.waitFor();
        return new Result(exit, out, new String(err, StandardCharsets.UTF_8).trim());
    }

    private static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = in.read(chunk)) >= 0) {
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    // ------------------------------------------------------------------
    // assertions and helpers
    // ------------------------------------------------------------------

    private interface Thrower {
        void run() throws Exception;
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("-- " + title + " " + "-".repeat(Math.max(0, 62 - title.length())));
    }

    private static void check(String name, boolean condition) {
        check(name, condition, "");
    }

    private static void check(String name, boolean condition, String detail) {
        if (condition) {
            passed++;
            System.out.println("  ok   " + name);
        } else {
            fail(name + (detail.isEmpty() ? "" : " [" + detail + "]"));
        }
    }

    private static void fail(String name) {
        failures.add(name);
        System.out.println("  FAIL " + name);
    }

    private static void expectThrows(String name, Class<? extends Throwable> expected, Thrower body) {
        try {
            body.run();
            fail(name + " [nothing thrown, expected " + expected.getSimpleName() + "]");
        } catch (Throwable t) {
            if (expected.isInstance(t)) {
                passed++;
                System.out.println("  ok   " + name);
            } else {
                fail(name + " [got " + t.getClass().getSimpleName() + ": " + t.getMessage() + "]");
            }
        }
    }

    /**
     * Asserts the body fails with VaultException, that the message mentions
     * {@code wantedPhrase} when given, and that it never echoes the rejected
     * input back (which for a key would put key material in a log).
     */
    private static String expectVaultExceptionThrows(String name, Thrower body, String wantedPhrase) {
        String message;
        try {
            body.run();
            fail(name + " [nothing thrown]");
            return "";
        } catch (SecureDataVault.VaultException expected) {
            message = String.valueOf(expected.getMessage());
        } catch (Throwable t) {
            fail(name + " [got " + t.getClass().getSimpleName() + ": " + t.getMessage() + "]");
            return String.valueOf(t.getMessage());
        }
        passed++;
        System.out.println("  ok   " + name);
        if (wantedPhrase != null) {
            check("  ... message says \"" + wantedPhrase + "\"", message.contains(wantedPhrase), message);
        }
        return message;
    }

    private static void expectExit(String name, Result result, int expected) {
        check(name + " (exit " + expected + ")", result.exit == expected, result.describe());
    }

    private static void expectExitQuiet(String name, Result result) {
        check(name, result.exit == 0, result.describe());
    }

    private static void expectExitFailure(String name, Result result) {
        check(name, result.exit != 0, result.describe());
    }

    private static int bodyBytes(String envelope) throws SecureDataVault.VaultException {
        String body = envelope.trim();
        int first = body.indexOf(':');
        int second = body.indexOf(':', first + 1);
        return SecureDataVault.decodeBase64Strict(body.substring(second + 1), "body").length;
    }

    private static Path write(Path dir, String name, String content) throws IOException {
        Path path = dir.resolve(name);
        Files.write(path, content.getBytes(StandardCharsets.US_ASCII));
        return path;
    }

    /**
     * Flips a bit in the first byte of the envelope body, leaving the header
     * alone. Done on the decoded bytes: editing a Base64 character in place is
     * not a reliable tamper, because a digit has no other case to flip to, and a
     * trailing character's low bits can be ignored by the padding anyway - either
     * way the "forged" envelope would still decrypt and the test would pass for
     * the wrong reason, or fail at random.
     */
    private static String flipOneBitOfBody(String envelope) throws SecureDataVault.VaultException {
        String trimmed = envelope.trim();
        int sep = trimmed.lastIndexOf(':');
        byte[] body = SecureDataVault.decodeBase64Strict(trimmed.substring(sep + 1), "body");
        body[0] ^= 0x01;
        return trimmed.substring(0, sep + 1) + Base64.getEncoder().encodeToString(body);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static boolean containsSequence(byte[] haystack, byte[] needle) {
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

    private static String collapse(String s) {
        return s == null ? "null" : s.replace('\n', ' ').replace('\r', ' ');
    }

    private static void wipe(char[] chars) {
        Arrays.fill(chars, (char) 0);
    }
}
