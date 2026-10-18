package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.example.crypto.SymmetricCrypto.CryptoException;
import com.example.crypto.SymmetricCrypto.KeySource;

/**
 * Executable checks over {@link SymmetricCrypto} — no test framework dependency, so the whole
 * project compiles with nothing but {@code javac}. Run with {@code java com.example.crypto.SelfTest}.
 */
public final class SelfTest {

    private static final SymmetricCrypto CRYPTO = new SymmetricCrypto();
    private static java.io.PrintStream out = System.out;
    private static int checks;
    private static int failures;

    public static void main(String[] args) throws Exception {
        System.exit(run(System.out));
    }

    static int run(java.io.PrintStream stream) throws CryptoException {
        out = stream;
        checks = 0;
        failures = 0;

        textRoundTrips();
        binaryRoundTrips();
        ivsAreUnique();
        wrongKeyIsRejected();
        wrongAadIsRejected();
        tamperingIsRejected();
        malformedInputIsRejected();
        passphraseBehaviour();
        keyValidation();

        out.println();
        out.println(failures == 0
                ? checks + " checks passed"
                : failures + " of " + checks + " checks FAILED");
        return failures == 0 ? 0 : 1;
    }

    private static void textRoundTrips() throws CryptoException {
        KeySource key = KeySource.of(SymmetricCrypto.newKey());
        String[] samples = {
                "hello world",
                "",
                "pässwörd-€-日本-😀",
                "x".repeat(100_000),
                "line one\nline two\r\nline three\ttab",
        };
        for (String sample : samples) {
            String token = CRYPTO.encryptToBase64(key, sample, "ctx");
            check("round trip " + describe(sample),
                    sample.equals(CRYPTO.decryptBase64(key, token, "ctx")));
        }
    }

    private static void binaryRoundTrips() throws CryptoException {
        KeySource key = KeySource.of(SymmetricCrypto.newKey());
        byte[] payload = new byte[70_000];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i * 31 + 7);
        }
        byte[] envelope = CRYPTO.encrypt(key, payload, null);
        check("binary payload round trip", Arrays.equals(payload, CRYPTO.decrypt(key, envelope, null)));

        byte[] wrapped = Base64.getMimeEncoder().encode(envelope);
        check("base64 with line wrapping still decrypts",
                Arrays.equals(payload, CRYPTO.decryptBase64Bytes(key,
                        new String(wrapped, StandardCharsets.UTF_8), null)));
    }

    private static void ivsAreUnique() throws CryptoException {
        KeySource key = KeySource.of(SymmetricCrypto.newKey());
        String token = "same value every time";
        Set<String> ivs = new HashSet<>();
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            byte[] envelope = CRYPTO.encrypt(key, token, null);
            ivs.add(Base64.getEncoder().encodeToString(Arrays.copyOfRange(envelope, 6, 18)));
            tokens.add(Base64.getEncoder().encodeToString(envelope));
        }
        check("500 encryptions use 500 distinct IVs", ivs.size() == 500);
        check("500 encryptions produce 500 distinct envelopes", tokens.size() == 500);
    }

    private static void wrongKeyIsRejected() throws CryptoException {
        KeySource right = KeySource.of(SymmetricCrypto.newKey());
        KeySource other = KeySource.of(SymmetricCrypto.newKey());
        byte[] envelope = CRYPTO.encrypt(right, "secret", null);
        Failure failure = expectFailure(other, envelope, null, "wrong key");
        check("wrong key reports an authentication failure", failure.authenticationFailure);
    }

    private static void wrongAadIsRejected() throws CryptoException {
        KeySource key = KeySource.of(SymmetricCrypto.newKey());
        byte[] envelope = CRYPTO.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8),
                "db.primary".getBytes(StandardCharsets.UTF_8));
        Failure failure = expectFailure(key, envelope, "db.replica".getBytes(StandardCharsets.UTF_8),
                "wrong AAD");
        check("wrong AAD reports an authentication failure", failure.authenticationFailure);

        failure = expectFailure(key, envelope, null, "missing AAD");
        check("omitting the AAD also fails", failure.authenticationFailure);
    }

    private static void tamperingIsRejected() throws CryptoException {
        KeySource key = KeySource.of(SymmetricCrypto.newKey());
        byte[] envelope = CRYPTO.encrypt(key, "transfer 500 to account 9999", null);
        // Layout: magic(4) version(1) sourceId(1) iv(12) body. The first six bytes are validated
        // structurally before a tag is computed; every byte from the IV onwards must be caught by
        // the AEAD tag itself.
        scanEveryByte(key, envelope, "raw-key envelope");
        tagRejectsRange(key, envelope, 6, envelope.length, "raw-key envelope");

        char[] password = "tamper-scan-passphrase".toCharArray();
        KeySource derived = KeySource.of(password, 110_000);
        SymmetricCrypto.wipe(password);
        byte[] sealed = CRYPTO.encrypt(derived, "value", null);
        // Layout: magic(4) version(1) sourceId(1) salt(16) iterations(4) iv(12) body.
        scanEveryByte(derived, sealed, "passphrase envelope");
        tagRejectsRange(derived, sealed, 6, 22, "passphrase envelope salt");
        tagRejectsRange(derived, sealed, 26, sealed.length, "passphrase envelope iv and body");

        byte[] truncated = Arrays.copyOf(envelope, envelope.length - 1);
        check("a truncated envelope is rejected", rejects(() -> CRYPTO.decrypt(key, truncated, null)) != null);
    }

    /** Flips every single byte of the envelope and asserts that none of them decrypts. */
    private static void scanEveryByte(KeySource source, byte[] envelope, String label) {
        int accepted = 0;
        for (int offset = 0; offset < envelope.length; offset++) {
            final int at = offset;
            byte[] tampered = envelope.clone();
            tampered[at] ^= 0x01;
            if (rejects(() -> CRYPTO.decrypt(source, tampered, null)) == null) {
                accepted++;
            }
        }
        check(label + ": all " + envelope.length + " single-byte flips are rejected", accepted == 0);
    }

    /** Asserts each flip in [from, to) is refused specifically by the AEAD tag. */
    private static void tagRejectsRange(KeySource source, byte[] envelope, int from, int to, String label) {
        int wrongReason = 0;
        for (int offset = from; offset < to; offset++) {
            final int at = offset;
            byte[] tampered = envelope.clone();
            tampered[at] ^= 0x01;
            Failure failure = rejects(() -> CRYPTO.decrypt(source, tampered, null));
            if (failure == null || !failure.authenticationFailure) {
                wrongReason++;
            }
        }
        check(label + ": byte flips in offsets " + from + ".." + (to - 1) + " fail on the AEAD tag",
                wrongReason == 0);
    }

    private static void malformedInputIsRejected() {
        byte[] junk = "not an envelope at all, not even close to one".getBytes(StandardCharsets.UTF_8);
        check("a foreign blob is rejected", rejects(() -> CRYPTO.decrypt(
                KeySource.of(SymmetricCrypto.newKey()), junk, null)) != null);
        check("an empty envelope is rejected", rejects(() -> CRYPTO.decrypt(
                KeySource.of(SymmetricCrypto.newKey()), new byte[0], null)) != null);
        check("invalid base64 is rejected", rejects(() -> CRYPTO.decryptBase64(
                KeySource.of(SymmetricCrypto.newKey()), "!!!not base64!!!", null)) != null);
    }

    private static void passphraseBehaviour() throws CryptoException {
        char[] password = "corRECT-horse#battery$staple".toCharArray();
        KeySource source = KeySource.of(password, 120_000);
        SymmetricCrypto.wipe(password);

        String first = CRYPTO.encryptToBase64(source, "api-key=abc123", "billing");
        String second = CRYPTO.encryptToBase64(source, "api-key=abc123", "billing");
        check("passphrase sealing draws a fresh salt each time", !first.equals(second));
        check("passphrase round trip after wiping the caller's array",
                "api-key=abc123".equals(CRYPTO.decryptBase64(source, first, "billing")));
        check("a second envelope from the same passphrase also opens",
                "api-key=abc123".equals(CRYPTO.decryptBase64(source, second, "billing")));

        KeySource wrong = KeySource.of("wrong-passphrase".toCharArray(), 120_000);
        Failure failure = expectFailure(wrong, CRYPTO.encrypt(source, "x", null), null,
                "wrong passphrase");
        check("wrong passphrase reports an authentication failure", failure.authenticationFailure);

        // Envelope records its own salt and iteration count, so a source configured with a different
        // work factor still decrypts: the recorded parameters are authoritative.
        KeySource otherCost = KeySource.of("corRECT-horse#battery$staple".toCharArray(), 150_000);
        check("the iteration count stored in the envelope is the one that is used",
                "api-key=abc123".equals(CRYPTO.decryptBase64(otherCost, first, "billing")));

        byte[] envelope = CRYPTO.encrypt(source, "x", null);
        int iterationsOffset = 4 + 1 + 1 + 16;
        byte[] tweaked = envelope.clone();
        tweaked[iterationsOffset + 3] = (byte) (tweaked[iterationsOffset + 3] ^ 0x01);
        check("a work factor nudged inside the allowed range breaks the tag",
                expectFailure(source, tweaked, null, "tampered iteration count").authenticationFailure);

        byte[] inflated = envelope.clone();
        inflated[iterationsOffset] = (byte) 0x7f;
        check("an absurd work factor stored in the envelope is refused outright",
                expectFailure(source, inflated, null, "inflated iteration count") != null);
    }

    private static void keyValidation() throws CryptoException {
        SecretKey key = SymmetricCrypto.newKey();
        check("newKey produces 256 bits", key.getEncoded().length == 32);
        check("keyFromBytes reproduces the same key material", Arrays.equals(key.getEncoded(),
                SymmetricCrypto.keyFromBytes(key.getEncoded()).getEncoded()));
        check("a 128-bit key is refused", rejects(() -> SymmetricCrypto.keyFromBytes(new byte[16])) != null);
        check("a raw-key source refuses a passphrase envelope", rejects(() -> CRYPTO.decrypt(
                KeySource.of(key), CRYPTO.encrypt(KeySource.of("pw".toCharArray()), "x", null), null)) != null);
        check("a passphrase source refuses a raw-key envelope", rejects(() -> CRYPTO.decrypt(
                KeySource.of("pw".toCharArray()), CRYPTO.encrypt(KeySource.of(key), "x", null), null)) != null);
        check("an iteration count below the floor is refused",
                rejects(() -> KeySource.of("pw".toCharArray(), 1_000)) != null);
        check("an empty passphrase is refused", rejects(() -> KeySource.of(new char[0])) != null);
        check("a non-AES key is refused",
                rejects(() -> KeySource.of(new SecretKeySpec(new byte[32], "DESede"))) != null);
    }

    private static Failure expectFailure(KeySource source, byte[] envelope, byte[] aad, String what) {
        Failure failure = rejects(() -> CRYPTO.decrypt(source, envelope, aad));
        if (failure == null) {
            check(what + " should have been rejected", false);
        }
        return failure;
    }

    /** Runs an action that must fail, and reports the rejection kind without failing the suite. */
    private static Failure rejects(ThrowingRunnable action) {
        try {
            action.run();
        } catch (CryptoException e) {
            return new Failure(e.isAuthenticationFailure());
        } catch (RuntimeException e) {
            return new Failure(false);
        }
        return null;
    }

    private static void check(String name, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
        }
        out.printf("%-58s %s%n", name, condition ? "PASS" : "FAIL");
    }

    private static String describe(String sample) {
        if (sample.isEmpty()) {
            return "empty string";
        }
        if (sample.length() > 24) {
            return sample.length() + "-char string";
        }
        return "'" + sample.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "'";
    }

    private static final class Failure {

        private final boolean authenticationFailure;

        Failure(boolean authenticationFailure) {
            this.authenticationFailure = authenticationFailure;
        }
    }

    private interface ThrowingRunnable {

        void run() throws CryptoException;
    }

    private SelfTest() {
    }
}
