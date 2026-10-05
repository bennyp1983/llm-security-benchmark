package com.security.crypto;

/**
 * High-level service interface for authenticated symmetric encryption and decryption
 * of sensitive application data.
 * <p>
 * Specifications:
 * <ul>
 *   <li>Algorithm: AES-256 in GCM mode (Galois/Counter Mode) with 128-bit authentication tag.</li>
 *   <li>Integrity &amp; Confidentiality: Authenticated Encryption with Associated Data (AEAD).</li>
 *   <li>Key Handling: Integrated key lifecycle and rotation via {@link KeyProvider}.</li>
 * </ul>
 */
public interface SymmetricEncryptionService {

    /**
     * Encrypts plaintext data using the active symmetric key.
     *
     * @param plaintext Sensitive data to encrypt.
     * @return Encrypted payload containing ciphertext, IV, version, and key identifier.
     * @throws CryptoException If validation or encryption fails.
     */
    EncryptedPayload encrypt(byte[] plaintext);

    /**
     * Encrypts plaintext data with Associated Authenticated Data (AAD) using the active symmetric key.
     *
     * @param plaintext Sensitive data to encrypt.
     * @param aad       Associated Authenticated Data bound to the ciphertext (e.g., account ID, record ID).
     * @return Encrypted payload containing ciphertext, IV, version, and key identifier.
     * @throws CryptoException If validation or encryption fails.
     */
    EncryptedPayload encrypt(byte[] plaintext, byte[] aad);

    /**
     * Encrypts plaintext and returns a URL-safe Base64 encoded payload.
     *
     * @param plaintext Sensitive data to encrypt.
     * @return URL-safe Base64 encoded string payload.
     */
    String encryptToString(byte[] plaintext);

    /**
     * Encrypts plaintext with Associated Authenticated Data (AAD) and returns a URL-safe Base64 payload.
     *
     * @param plaintext Sensitive data to encrypt.
     * @param aad       Associated Authenticated Data.
     * @return URL-safe Base64 encoded string payload.
     */
    String encryptToString(byte[] plaintext, byte[] aad);

    /**
     * Decrypts an EncryptedPayload using a default source identifier.
     *
     * @param payload The encrypted payload to decrypt.
     * @return Decrypted plaintext bytes.
     * @throws CryptoException If decryption fails, rate limit is exceeded, or payload is tampered.
     */
    byte[] decrypt(EncryptedPayload payload);

    /**
     * Decrypts an EncryptedPayload with Associated Authenticated Data (AAD) using a default source identifier.
     *
     * @param payload The encrypted payload to decrypt.
     * @param aad     Associated Authenticated Data that must match the data supplied during encryption.
     * @return Decrypted plaintext bytes.
     * @throws CryptoException If decryption fails, rate limit is exceeded, or payload is tampered.
     */
    byte[] decrypt(EncryptedPayload payload, byte[] aad);

    /**
     * Decrypts an EncryptedPayload with Associated Authenticated Data (AAD) and client source tracking.
     *
     * @param payload  The encrypted payload to decrypt.
     * @param aad      Associated Authenticated Data.
     * @param sourceId Client or source identifier used for rate-limiting brute force attacks.
     * @return Decrypted plaintext bytes.
     * @throws CryptoException If decryption fails, rate limit is exceeded, or payload is tampered.
     */
    byte[] decrypt(EncryptedPayload payload, byte[] aad, String sourceId);

    /**
     * Decrypts serialized binary wire-format payload bytes.
     *
     * @param serializedPayload Raw bytes of the serialized payload.
     * @param aad               Associated Authenticated Data.
     * @param sourceId          Client or source identifier.
     * @return Decrypted plaintext bytes.
     * @throws CryptoException If deserialization or decryption fails.
     */
    byte[] decrypt(byte[] serializedPayload, byte[] aad, String sourceId);

    /**
     * Decrypts a URL-safe Base64 encoded payload string.
     *
     * @param base64Payload URL-safe Base64 string.
     * @param aad           Associated Authenticated Data.
     * @param sourceId      Client or source identifier.
     * @return Decrypted plaintext bytes.
     * @throws CryptoException If deserialization or decryption fails.
     */
    byte[] decryptFromString(String base64Payload, byte[] aad, String sourceId);
}
