package com.example.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AesGcmDataCipherTest {

    private static final byte[] PLAINTEXT = "4111-1111-1111-1111".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD = "record:42".getBytes(StandardCharsets.UTF_8);

    private static AesGcmDataCipher cipher(String activeId, String... allIds) {
        Map<String, ZeroizableSecretKey> keys = Arrays.stream(allIds)
                .collect(Collectors.toMap(id -> id, id -> KeyMaterial.generateKey()));
        return new AesGcmDataCipher(new KeySetSecretKeyProvider(keys, activeId));
    }

    @Test
    void roundTripsWithAssociatedData() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        assertArrayEquals(PLAINTEXT, cipher.decrypt(envelope, AAD));
    }

    @Test
    void roundTripsWithoutAssociatedData() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT, null), null));
    }

    @Test
    void roundTripsEmptyPlaintext() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        assertArrayEquals(new byte[0], cipher.decrypt(cipher.encrypt(new byte[0], AAD), AAD));
    }

    @Test
    void ciphertextDoesNotContainPlaintext() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        String envelope = Base64.getEncoder().encodeToString(cipher.encrypt(PLAINTEXT, AAD));
        assertTrue(envelope.indexOf("4111") < 0, "plaintext must not survive in the envelope");
    }

    @Test
    void nonceIsFreshForEveryEncryption() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
            // header is 6 + len("v1") = 8 bytes, then the 12-byte nonce
            byte[] nonce = Arrays.copyOfRange(envelope, 8, 20);
            assertTrue(seen.add(Base64.getEncoder().encodeToString(nonce)), "nonce reused");
        }
    }

    @Test
    void identicalPlaintextProducesDifferentCiphertext() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        assertNotEquals(
                Base64.getEncoder().encodeToString(cipher.encrypt(PLAINTEXT, AAD)),
                Base64.getEncoder().encodeToString(cipher.encrypt(PLAINTEXT, AAD)));
    }

    @Test
    void rejectsTamperedCiphertextByte() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[envelope.length - 17] ^= 0x01;
        assertEquals("unable to decrypt data",
                assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD)).getMessage());
    }

    @Test
    void rejectsTamperedTag() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[envelope.length - 1] ^= 0x01;
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD));
    }

    @Test
    void rejectsTamperedNonce() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[10] ^= 0x01;
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD));
    }

    @Test
    void rejectsSwappedKeyIdInHeader() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1", "v2");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        assertEquals('1', (char) envelope[7]);
        envelope[7] = '2'; // re-label as the other, equally valid, key
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD));
    }

    @Test
    void rejectsBumpedVersion() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[4] = 2;
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD));
    }

    @Test
    void rejectsWrongMagic() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[0] = 'X';
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD));
    }

    @Test
    void rejectsMissingAssociatedData() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, null));
    }

    @Test
    void rejectsDifferentAssociatedData() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        byte[] otherContext = "record:43".getBytes(StandardCharsets.UTF_8);
        assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, otherContext));
    }

    @Test
    void rejectsCiphertextFromAnotherKey() throws Exception {
        AesGcmDataCipher mine = cipher("v1", "v1");
        AesGcmDataCipher theirs = cipher("v1", "v1"); // same id, independent key material
        byte[] envelope = theirs.encrypt(PLAINTEXT, AAD);
        assertThrows(CryptoException.class, () -> mine.decrypt(envelope, AAD));
    }

    @Test
    void unknownKeyIdFailsIdenticallyToTamperedCiphertext() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[7] = '9'; // "v9" is not configured at all
        CryptoException unknownKey =
                assertThrows(CryptoException.class, () -> cipher.decrypt(envelope, AAD));

        byte[] tampered = cipher.encrypt(PLAINTEXT, AAD);
        tampered[tampered.length - 1] ^= 0x01;
        CryptoException badTag =
                assertThrows(CryptoException.class, () -> cipher.decrypt(tampered, AAD));

        assertEquals(badTag.getMessage(), unknownKey.getMessage());
        assertEquals(badTag.getClass(), unknownKey.getClass());
        assertNull(unknownKey.getCause(), "cause must not leak the real reason");
    }

    @Test
    void rejectsTruncatedEnvelope() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        for (int length = 0; length < envelope.length; length++) {
            byte[] truncated = Arrays.copyOf(envelope, length);
            assertThrows(CryptoException.class, () -> cipher.decrypt(truncated, AAD),
                    "accepted a truncated envelope of length " + length);
        }
    }

    @Test
    void rejectsEverySingleBitFlip() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        for (int i = 0; i < envelope.length; i++) {
            for (int bit = 0; bit < 8; bit++) {
                byte[] mutated = envelope.clone();
                mutated[i] ^= (byte) (1 << bit);
                assertThrows(CryptoException.class, () -> cipher.decrypt(mutated, AAD),
                        "accepted a mutation at byte " + i + " bit " + bit);
            }
        }
    }

    @Test
    void rejectsRandomInput() {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        for (int length : new int[] {0, 1, 19, 20, 64, 4096}) {
            byte[] junk = KeyMaterial.randomBytes(Math.max(length, 1));
            byte[] input = length == 0 ? new byte[0] : junk;
            assertThrows(CryptoException.class, () -> cipher.decrypt(input, AAD));
        }
    }

    @Test
    void rejectsOversizedPlaintext() {
        AesGcmDataCipher cipher = new AesGcmDataCipher(
                KeySetSecretKeyProvider.of("v1", KeyMaterial.generateKey()), 16);
        assertThrows(IllegalArgumentException.class,
                () -> cipher.encrypt(new byte[17], AAD));
    }

    @Test
    void rejectsOversizedAssociatedData() {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] hugeAad = new byte[AesGcmDataCipher.MAX_AAD_BYTES + 1];
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(PLAINTEXT, hugeAad));
    }

    @Test
    void rejectsNullInputs() {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(null, AAD));
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt((byte[]) null, AAD));
        assertThrows(IllegalArgumentException.class, () -> cipher.decryptFromBase64(null, AAD));
    }

    @Test
    void rejectsNonBase64Text() {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        assertThrows(CryptoException.class, () -> cipher.decryptFromBase64("not base64 !!", AAD));
    }

    @Test
    void rejectsOversizedBase64Input() {
        AesGcmDataCipher cipher = new AesGcmDataCipher(
                KeySetSecretKeyProvider.of("v1", KeyMaterial.generateKey()), 1024);
        String huge = "A".repeat(100_000);
        assertThrows(CryptoException.class, () -> cipher.decryptFromBase64(huge, AAD));
    }

    @Test
    void textRoundTripWipesTheCallersBuffer() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        char[] secret = "pass-phrase-material".toCharArray();
        String envelope = cipher.encryptText(secret, AAD);
        assertArrayEquals(new char[secret.length], secret, "input buffer must be wiped");

        char[] recovered = cipher.decryptText(envelope, AAD);
        assertArrayEquals("pass-phrase-material".toCharArray(), recovered);
        Bytes.wipe(recovered);
    }

    @Test
    void textApiHandlesNonAsciiData() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        String original = "naïve – 日本語 – 🔐";
        String envelope = cipher.encryptText(original.toCharArray(), AAD);
        assertEquals(original, new String(cipher.decryptText(envelope, AAD)));
    }

    @Test
    void decryptsCiphertextWrittenUnderARetiredKey() throws Exception {
        ZeroizableSecretKey oldKey = KeyMaterial.generateKey();
        ZeroizableSecretKey newKey = KeyMaterial.generateKey();

        AesGcmDataCipher before = new AesGcmDataCipher(
                new KeySetSecretKeyProvider(Map.of("v1", oldKey), "v1"));
        byte[] legacy = before.encrypt(PLAINTEXT, AAD);

        // After rotation v2 is active, but v1 is retained for reads.
        AesGcmDataCipher after = new AesGcmDataCipher(
                new KeySetSecretKeyProvider(Map.of("v1", oldKey, "v2", newKey), "v2"));
        assertArrayEquals(PLAINTEXT, after.decrypt(legacy, AAD));
        assertEquals("v2", after.activeKeyId());
        assertEquals('2', (char) after.encrypt(PLAINTEXT, AAD)[7]);
    }

    @Test
    void reencryptsStoredDataUnderTheNewActiveKey() throws Exception {
        ZeroizableSecretKey oldKey = KeyMaterial.generateKey();
        ZeroizableSecretKey newKey = KeyMaterial.generateKey();
        AesGcmDataCipher before = new AesGcmDataCipher(
                new KeySetSecretKeyProvider(Map.of("v1", oldKey), "v1"));
        byte[] legacy = before.encrypt(PLAINTEXT, AAD);

        AesGcmDataCipher after = new AesGcmDataCipher(
                new KeySetSecretKeyProvider(Map.of("v1", oldKey, "v2", newKey), "v2"));
        byte[] migrated = after.reencryptUnderActiveKey(legacy, AAD);

        assertEquals('2', (char) migrated[7], "migrated data must carry the new key id");
        assertArrayEquals(PLAINTEXT, after.decrypt(migrated, AAD));

        // The old key is no longer needed for this record.
        AesGcmDataCipher newOnly = new AesGcmDataCipher(
                new KeySetSecretKeyProvider(Map.of("v2", newKey), "v2"));
        assertArrayEquals(PLAINTEXT, newOnly.decrypt(migrated, AAD));
        assertThrows(CryptoException.class, () -> newOnly.decrypt(legacy, AAD));
    }

    @Test
    void reencryptionRejectsForgedInput() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        byte[] envelope = cipher.encrypt(PLAINTEXT, AAD);
        envelope[envelope.length - 1] ^= 0x01;
        assertThrows(CryptoException.class, () -> cipher.reencryptUnderActiveKey(envelope, AAD));
    }

    @Test
    void concurrentEncryptionProducesDistinctUsableEnvelopes() throws Exception {
        AesGcmDataCipher cipher = cipher("v1", "v1");
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            var tasks = IntStream.range(0, 256)
                    .<Callable<String>>mapToObj(i -> () ->
                            Base64.getEncoder().encodeToString(cipher.encrypt(PLAINTEXT, AAD)))
                    .collect(Collectors.toList());
            Set<String> envelopes = new HashSet<>();
            for (Future<String> future : pool.invokeAll(tasks)) {
                assertTrue(envelopes.add(future.get()), "duplicate envelope under concurrency");
            }
            for (String envelope : envelopes) {
                assertArrayEquals(PLAINTEXT, cipher.decryptFromBase64(envelope, AAD));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void refusesToStartWithoutAUsableActiveKey() {
        ZeroizableSecretKey key = KeyMaterial.generateKey();
        KeySetSecretKeyProvider provider = KeySetSecretKeyProvider.of("v1", key);
        provider.close(); // key material destroyed
        assertThrows(IllegalStateException.class, () -> new AesGcmDataCipher(provider));
    }

    @Test
    void refusesAbsurdSizeLimits() {
        KeySetSecretKeyProvider provider = KeySetSecretKeyProvider.of("v1", KeyMaterial.generateKey());
        assertThrows(IllegalArgumentException.class, () -> new AesGcmDataCipher(provider, 0));
        assertThrows(IllegalArgumentException.class, () -> new AesGcmDataCipher(provider,
                AesGcmDataCipher.MAX_CONFIGURABLE_PLAINTEXT_BYTES + 1));
    }
}
