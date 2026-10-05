package com.security.crypto;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite validating cryptographic correctness, security defenses,
 * attack resistance, and adherence to the 8 security rules.
 */
public class SymmetricCryptoTest {

    private InMemoryKeyProvider keyProvider;
    private AesGcmEncryptionService encryptionService;
    private String primaryKeyId;
    private SecretKey primaryKey;

    @BeforeEach
    public void setUp() {
        primaryKeyId = KeyGeneratorUtil.generateKeyId();
        primaryKey = KeyGeneratorUtil.generateAes256Key();
        keyProvider = new InMemoryKeyProvider(primaryKeyId, primaryKey);
        encryptionService = new AesGcmEncryptionService(keyProvider);
    }

    @AfterEach
    public void tearDown() {
        if (keyProvider != null) {
            keyProvider.close();
        }
    }

    // =========================================================================
    // Core Functional Tests
    // =========================================================================

    @Test
    @DisplayName("Encrypt and decrypt round-trip with byte array plaintext")
    public void testEncryptDecryptRoundTrip() {
        byte[] plaintext = "Highly sensitive medical or financial payload".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);

        assertNotNull(payload);
        assertEquals(primaryKeyId, payload.getKeyId());
        assertEquals(EncryptedPayload.CURRENT_VERSION, payload.getVersion());
        assertEquals(12, payload.getIv().length);
        assertTrue(payload.getCiphertextWithTag().length >= plaintext.length + 16);

        byte[] decrypted = encryptionService.decrypt(payload);
        assertArrayEquals(plaintext, decrypted);

        // Rule 5: Wipe plaintext after use
        CryptoUtils.wipe(decrypted);
    }

    @Test
    @DisplayName("Encrypt and decrypt with Associated Authenticated Data (AAD)")
    public void testEncryptDecryptWithAad() {
        byte[] plaintext = "Secret payload tied to user account".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "tenant_id=tenant-99;account_id=acc-12345".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload payload = encryptionService.encrypt(plaintext, aad);
        byte[] decrypted = encryptionService.decrypt(payload, aad);
        assertArrayEquals(plaintext, decrypted);

        CryptoUtils.wipe(decrypted);
    }

    @Test
    @DisplayName("Encrypt and decrypt Base64URL string round-trip")
    public void testBase64UrlRoundTrip() {
        byte[] plaintext = "Data formatted as Base64URL string".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "user=alice".getBytes(StandardCharsets.UTF_8);

        String base64Payload = encryptionService.encryptToString(plaintext, aad);
        assertNotNull(base64Payload);
        assertFalse(base64Payload.contains("+"));
        assertFalse(base64Payload.contains("/"));
        assertFalse(base64Payload.contains("="));

        byte[] decrypted = encryptionService.decryptFromString(base64Payload, aad, "client_test");
        assertArrayEquals(plaintext, decrypted);

        CryptoUtils.wipe(decrypted);
    }

    @Test
    @DisplayName("Encrypt and decrypt serialized binary wire format")
    public void testSerializedBinaryWireFormatRoundTrip() {
        byte[] plaintext = "Binary wire protocol test payload".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);
        byte[] serialized = payload.toBytes();

        byte[] decrypted = encryptionService.decrypt(serialized, null, "client_test");
        assertArrayEquals(plaintext, decrypted);

        CryptoUtils.wipe(decrypted);
    }

    @Test
    @DisplayName("Encrypt and decrypt empty plaintext")
    public void testEmptyPlaintext() {
        byte[] plaintext = new byte[0];
        EncryptedPayload payload = encryptionService.encrypt(plaintext);
        byte[] decrypted = encryptionService.decrypt(payload);
        assertEquals(0, decrypted.length);
    }

    @Test
    @DisplayName("Ensure fresh IV generated on each encryption (nonce reuse defense)")
    public void testUniqueIvPerEncryption() {
        byte[] plaintext = "Identical plaintext content".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload1 = encryptionService.encrypt(plaintext);
        EncryptedPayload payload2 = encryptionService.encrypt(plaintext);

        assertFalse(Arrays.equals(payload1.getIv(), payload2.getIv()), "IVs must never be reused");
        assertFalse(Arrays.equals(payload1.getCiphertextWithTag(), payload2.getCiphertextWithTag()),
                "Ciphertexts must differ due to unique IVs");
    }

    // =========================================================================
    // Key Rotation and Revocation Tests (Rule 1 & Rule 2)
    // =========================================================================

    @Test
    @DisplayName("Key rotation: Encrypt with old key, rotate, encrypt with new, decrypt both")
    public void testKeyRotation() {
        byte[] plaintext1 = "Payload encrypted under key 1".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload1 = encryptionService.encrypt(plaintext1);
        assertEquals(primaryKeyId, payload1.getKeyId());

        // Rotate to key 2
        String keyId2 = KeyGeneratorUtil.generateKeyId();
        SecretKey key2 = KeyGeneratorUtil.generateAes256Key();
        keyProvider.rotateKey(keyId2, key2);

        assertEquals(keyId2, keyProvider.getActiveKeyId());

        byte[] plaintext2 = "Payload encrypted under key 2".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload2 = encryptionService.encrypt(plaintext2);
        assertEquals(keyId2, payload2.getKeyId());

        // Decrypt both payloads seamlessly
        byte[] decrypted1 = encryptionService.decrypt(payload1);
        byte[] decrypted2 = encryptionService.decrypt(payload2);

        assertArrayEquals(plaintext1, decrypted1);
        assertArrayEquals(plaintext2, decrypted2);

        CryptoUtils.wipe(decrypted1);
        CryptoUtils.wipe(decrypted2);
    }

    @Test
    @DisplayName("Key revocation: Decrypting with revoked key must fail closed")
    public void testKeyRevocationFailsClosed() {
        byte[] plaintext = "Sensitive data prior to revocation".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);

        // Rotate and revoke primary key
        String newKeyId = KeyGeneratorUtil.generateKeyId();
        SecretKey newKey = KeyGeneratorUtil.generateAes256Key();
        keyProvider.rotateKey(newKeyId, newKey);
        keyProvider.revokeKey(primaryKeyId);

        CryptoException ex = assertThrows(CryptoException.class, () -> encryptionService.decrypt(payload));
        assertEquals("Decryption failed", ex.getMessage());
    }

    // =========================================================================
    // Adversarial Tampering & Cryptographic Attack Tests (Rule 1, 3, 6)
    // =========================================================================

    @Test
    @DisplayName("Tampered ciphertext bit must be rejected by GCM authentication tag")
    public void testTamperedCiphertextRejected() {
        byte[] plaintext = "Original authentic plaintext".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);

        byte[] tamperedCiphertext = payload.getCiphertextWithTag();
        tamperedCiphertext[0] ^= 0x01; // Flip 1 bit

        EncryptedPayload tamperedPayload = new EncryptedPayload(
                payload.getVersion(), payload.getKeyId(), payload.getIv(), tamperedCiphertext);

        CryptoException ex = assertThrows(CryptoException.class, () -> encryptionService.decrypt(tamperedPayload));
        assertEquals("Decryption failed", ex.getMessage());
    }

    @Test
    @DisplayName("Tampered authentication tag must be rejected")
    public void testTamperedTagRejected() {
        byte[] plaintext = "Payload with authentic tag".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);

        byte[] tamperedCiphertext = payload.getCiphertextWithTag();
        // GCM tag is the last 16 bytes
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x55;

        EncryptedPayload tamperedPayload = new EncryptedPayload(
                payload.getVersion(), payload.getKeyId(), payload.getIv(), tamperedCiphertext);

        CryptoException ex = assertThrows(CryptoException.class, () -> encryptionService.decrypt(tamperedPayload));
        assertEquals("Decryption failed", ex.getMessage());
    }

    @Test
    @DisplayName("Tampered IV must cause decryption failure")
    public void testTamperedIvRejected() {
        byte[] plaintext = "Data protected by IV".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);

        byte[] tamperedIv = payload.getIv();
        tamperedIv[0] ^= 0xFF;

        EncryptedPayload tamperedPayload = new EncryptedPayload(
                payload.getVersion(), payload.getKeyId(), tamperedIv, payload.getCiphertextWithTag());

        CryptoException ex = assertThrows(CryptoException.class, () -> encryptionService.decrypt(tamperedPayload));
        assertEquals("Decryption failed", ex.getMessage());
    }

    @Test
    @DisplayName("Mismatched AAD (Context-Binding Attack) must be rejected")
    public void testMismatchedAadRejected() {
        byte[] plaintext = "Data bound to tenant 1".getBytes(StandardCharsets.UTF_8);
        byte[] authenticAad = "tenant=tenant-1".getBytes(StandardCharsets.UTF_8);
        byte[] attackerAad = "tenant=tenant-2".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload payload = encryptionService.encrypt(plaintext, authenticAad);

        // Attempting to decrypt with different AAD or null AAD must fail
        assertThrows(CryptoException.class, () -> encryptionService.decrypt(payload, attackerAad));
        assertThrows(CryptoException.class, () -> encryptionService.decrypt(payload, null));
    }

    // =========================================================================
    // Wire Format Parsing & Boundary Attack Tests (Rule 1)
    // =========================================================================

    @Test
    @DisplayName("Malformed binary header magic rejected")
    public void testInvalidMagicRejected() {
        byte[] plaintext = "Sample data".getBytes(StandardCharsets.UTF_8);
        byte[] serialized = encryptionService.encrypt(plaintext).toBytes();

        // Corrupt magic header
        serialized[0] = 'B';
        serialized[1] = 'A';
        serialized[2] = 'D';
        serialized[3] = '!';

        CryptoException ex = assertThrows(CryptoException.class,
                () -> EncryptedPayload.fromBytes(serialized, 1024 * 1024));
        assertTrue(ex.getMessage().contains("unrecognized format header"));
    }

    @Test
    @DisplayName("Unsupported version rejected")
    public void testUnsupportedVersionRejected() {
        byte[] plaintext = "Sample data".getBytes(StandardCharsets.UTF_8);
        byte[] serialized = encryptionService.encrypt(plaintext).toBytes();

        // Version is at index 4
        serialized[4] = 0x02;

        CryptoException ex = assertThrows(CryptoException.class,
                () -> EncryptedPayload.fromBytes(serialized, 1024 * 1024));
        assertTrue(ex.getMessage().contains("unsupported version"));
    }

    @Test
    @DisplayName("Truncated payload rejected at all boundaries")
    public void testTruncatedPayloadRejected() {
        byte[] plaintext = "Boundary testing payload".getBytes(StandardCharsets.UTF_8);
        byte[] serialized = encryptionService.encrypt(plaintext).toBytes();

        // Truncate at various lengths
        for (int len = 0; len < serialized.length - 1; len += 5) {
            byte[] truncated = Arrays.copyOf(serialized, len);
            assertThrows(CryptoException.class,
                    () -> EncryptedPayload.fromBytes(truncated, 1024 * 1024));
        }
    }

    @Test
    @DisplayName("Trailing injected bytes rejected")
    public void testTrailingInjectedBytesRejected() {
        byte[] plaintext = "Payload without padding".getBytes(StandardCharsets.UTF_8);
        byte[] serialized = encryptionService.encrypt(plaintext).toBytes();

        byte[] inflated = Arrays.copyOf(serialized, serialized.length + 10);
        inflated[serialized.length] = 0x42; // Injected byte

        assertThrows(CryptoException.class,
                () -> EncryptedPayload.fromBytes(inflated, 1024 * 1024));
    }

    @Test
    @DisplayName("Key ID validation rejects dangerous input (Path traversal, command injection, oversized)")
    public void testKeyIdValidation() {
        assertThrows(CryptoException.class, () -> CryptoUtils.validateKeyId(null));
        assertThrows(CryptoException.class, () -> CryptoUtils.validateKeyId(""));
        assertThrows(CryptoException.class, () -> CryptoUtils.validateKeyId("../../../etc/passwd"));
        assertThrows(CryptoException.class, () -> CryptoUtils.validateKeyId("key; rm -rf /"));
        assertThrows(CryptoException.class, () -> CryptoUtils.validateKeyId("key with spaces"));
        assertThrows(CryptoException.class, () -> CryptoUtils.validateKeyId("a".repeat(65))); // Exceeds 64 chars

        // Valid key IDs
        assertEquals("k_12345-abc_XYZ", CryptoUtils.validateKeyId("k_12345-abc_XYZ"));
    }

    @Test
    @DisplayName("Oversized payload rejected to prevent DoS/OOM")
    public void testOversizedPayloadRejected() {
        int smallMax = 100;
        byte[] largePlaintext = new byte[200];
        AesGcmEncryptionService boundedService = new AesGcmEncryptionService(
                keyProvider, new DecryptionRateLimiter(), smallMax, smallMax, 64);

        CryptoException ex = assertThrows(CryptoException.class, () -> boundedService.encrypt(largePlaintext));
        assertTrue(ex.getMessage().contains("input exceeds maximum permitted size"));
    }

    // =========================================================================
    // Brute-Force Rate Limiting & User Lockout Prevention Tests (Rule 3 & Rule 7)
    // =========================================================================

    @Test
    @DisplayName("Decryption rate limiter blocks attacker source without locking out legitimate source")
    public void testRateLimitingPreventsLockoutOfLegitimateUser() {
        // Configure tight rate limiter: max 3 failures per source, max 10 failures per resource
        DecryptionRateLimiter tightLimiter = new DecryptionRateLimiter(60_000L, 3, 10);
        AesGcmEncryptionService rateLimitedService = new AesGcmEncryptionService(
                keyProvider, tightLimiter, 1024 * 1024, 1024 * 1024, 1024);

        byte[] validPlaintext = "Confidential data".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload validPayload = rateLimitedService.encrypt(validPlaintext);

        // Prepare invalid payload targeting the same key
        byte[] corruptedCiphertext = validPayload.getCiphertextWithTag();
        corruptedCiphertext[0] ^= 0x01;
        EncryptedPayload corruptedPayload = new EncryptedPayload(
                validPayload.getVersion(), validPayload.getKeyId(), validPayload.getIv(), corruptedCiphertext);

        String attackerSource = "192.168.1.100";
        String legitimateSource = "192.168.1.200";

        // Attacker triggers 3 consecutive failures
        for (int i = 0; i < 3; i++) {
            assertThrows(CryptoException.class,
                    () -> rateLimitedService.decrypt(corruptedPayload, null, attackerSource));
        }

        // Attacker's 4th attempt is blocked by source rate limit
        CryptoException ex = assertThrows(CryptoException.class,
                () -> rateLimitedService.decrypt(corruptedPayload, null, attackerSource));
        assertTrue(ex.getMessage().contains("rate limit exceeded"));

        // Crucial Rule 3 Test: Legitimate source decrypting valid payload MUST SUCCEED!
        // Attacker's failure flood did NOT lock out legitimate user on the same key/resource.
        byte[] legitDecrypted = rateLimitedService.decrypt(validPayload, null, legitimateSource);
        assertArrayEquals(validPlaintext, legitDecrypted);
        CryptoUtils.wipe(legitDecrypted);
    }

    // =========================================================================
    // Key Derivation Tests (Rule 1, 2, 5, 8)
    // =========================================================================

    @Test
    @DisplayName("Key derivation produces valid 256-bit AES key and zeroes password")
    public void testKeyDerivation() {
        char[] password = "StrongApplicationSecretPassphrase#2026!".toCharArray();
        byte[] salt = KeyDerivation.generateSalt(16);

        SecretKey derivedKey = KeyDerivation.deriveKey(password, salt, 210_000);
        assertNotNull(derivedKey);
        assertEquals("AES", derivedKey.getAlgorithm());
        assertEquals(32, derivedKey.getEncoded().length);

        // Passphrase char array must be wiped to '\0'
        for (char c : password) {
            assertEquals('\0', c, "Password memory must be cleared");
        }
    }

    @Test
    @DisplayName("Key derivation rejects weak parameters (short salt or low iterations)")
    public void testKeyDerivationValidation() {
        char[] password = "ValidPassword123".toCharArray();
        byte[] shortSalt = new byte[8];

        assertThrows(CryptoException.class, () -> KeyDerivation.deriveKey(password, shortSalt, 210_000));
        assertThrows(CryptoException.class, () -> KeyDerivation.deriveKey(password, KeyDerivation.generateSalt(), 50_000));
    }

    // =========================================================================
    // KeyStore Integration Tests (Rule 1, 2, 5, 8)
    // =========================================================================

    @Test
    @DisplayName("KeyStoreKeyProvider loads PKCS12 keystore from stream and decrypts")
    public void testKeyStoreProviderFromStream() throws Exception {
        // Programmatically generate a test PKCS12 keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        String alias = "my_app_key";
        SecretKey appKey = KeyGeneratorUtil.generateAes256Key();
        char[] ksPassword = "KeystoreSecretPassword123!".toCharArray();

        ks.setEntry(alias,
                new KeyStore.SecretKeyEntry(appKey),
                new KeyStore.PasswordProtection(ksPassword));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, ksPassword);
        byte[] keystoreBytes = baos.toByteArray();

        // Load into KeyStoreKeyProvider
        KeyStoreKeyProvider ksProvider = KeyStoreKeyProvider.fromInputStream(
                new ByteArrayInputStream(keystoreBytes),
                ksPassword.clone(),
                alias);

        assertEquals(alias, ksProvider.getActiveKeyId());
        assertTrue(ksProvider.hasKey(alias));

        AesGcmEncryptionService ksService = new AesGcmEncryptionService(ksProvider);
        byte[] secret = "Top secret data stored via KeyStore".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = ksService.encrypt(secret);
        byte[] decrypted = ksService.decrypt(payload);

        assertArrayEquals(secret, decrypted);

        ksProvider.close();
        CryptoUtils.wipe(decrypted);
    }

    // =========================================================================
    // Sensitive Data Masking & Information Leakage Tests (Rule 2, 5, 6)
    // =========================================================================

    @Test
    @DisplayName("EncryptedPayload toString masks ciphertext and sensitive values")
    public void testToStringMasking() {
        byte[] plaintext = "Extremely private information".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload = encryptionService.encrypt(plaintext);

        String str = payload.toString();
        assertTrue(str.contains("PROTECTED"));
        assertFalse(str.contains("Extremely private"));
        assertFalse(str.contains(Arrays.toString(payload.getCiphertextWithTag())));
    }

    @Test
    @DisplayName("Unknown Key ID produces identical generic error message")
    public void testUnknownKeyIdGenericMessage() {
        EncryptedPayload realPayload = encryptionService.encrypt("Sample".getBytes(StandardCharsets.UTF_8));

        // Craft payload with unknown key ID
        EncryptedPayload fakeKeyPayload = new EncryptedPayload(
                realPayload.getVersion(), "unknown-key-9999", realPayload.getIv(), realPayload.getCiphertextWithTag());

        CryptoException ex = assertThrows(CryptoException.class,
                () -> encryptionService.decrypt(fakeKeyPayload));
        assertEquals("Decryption failed", ex.getMessage(),
                "Error message must be identical and generic to prevent key enumeration");
    }

    // =========================================================================
    // Concurrency Stress Tests (Rule 7)
    // =========================================================================

    @Test
    @DisplayName("Multi-threaded concurrent encryption and decryption with key rotation")
    public void testConcurrencyStress() throws InterruptedException {
        int threadCount = 8;
        int operationsPerThread = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    for (int i = 0; i < operationsPerThread; i++) {
                        String msg = "Thread-" + threadId + "-Iteration-" + i;
                        byte[] plain = msg.getBytes(StandardCharsets.UTF_8);
                        byte[] aad = ("client-" + threadId).getBytes(StandardCharsets.UTF_8);

                        // Encrypt and decrypt
                        EncryptedPayload ep = encryptionService.encrypt(plain, aad);
                        byte[] dec = encryptionService.decrypt(ep, aad, "thread_" + threadId);

                        if (Arrays.equals(plain, dec)) {
                            successCount.incrementAndGet();
                        }
                        CryptoUtils.wipe(dec);

                        // Periodically rotate keys concurrently from thread 0
                        if (threadId == 0 && i % 10 == 0) {
                            keyProvider.rotateKey(KeyGeneratorUtil.generateKeyId(), KeyGeneratorUtil.generateAes256Key());
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(30, TimeUnit.SECONDS), "Concurrent execution timed out");
        executor.shutdown();
        assertEquals(threadCount * operationsPerThread, successCount.get(),
                "All concurrent cryptographic operations must succeed without race conditions");
    }
}
