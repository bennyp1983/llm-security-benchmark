package com.security.crypto;

import javax.crypto.SecretKey;
import java.util.Optional;

/**
 * Interface representing a secure provider for symmetric keys used in encryption and decryption.
 * <p>
 * Key Lifecycle &amp; Rotation (Rules 1, 2, 3, 5):
 * <ul>
 *   <li>Supports key rotation: a single "active" key is used for new encryptions,
 *       while historical keys remain accessible for decrypting existing records.</li>
 *   <li>Keys are resolved strictly against server-side state. Unknown or revoked
 *       keys result in immediate failure closed.</li>
 *   <li>Implements {@link AutoCloseable} to guarantee zeroization and destruction
 *       of key material from memory when decommissioned.</li>
 * </ul>
 */
public interface KeyProvider extends AutoCloseable {

    /**
     * Retrieves the currently active key for performing new encryptions.
     *
     * @return The active {@link SecretKey}.
     * @throws CryptoException If no active key is configured or available.
     */
    SecretKey getActiveKey();

    /**
     * Retrieves the key identifier for the currently active key.
     *
     * @return The active key identifier.
     * @throws CryptoException If no active key is configured.
     */
    String getActiveKeyId();

    /**
     * Retrieves a key by its identifier for decryption.
     *
     * @param keyId The identifier of the key to look up.
     * @return An Optional containing the key if found, or empty if unknown/revoked.
     */
    Optional<SecretKey> getKey(String keyId);

    /**
     * Checks if a key exists and is available in this provider.
     *
     * @param keyId The identifier of the key.
     * @return true if the key is present and valid; false otherwise.
     */
    boolean hasKey(String keyId);

    /**
     * Closes the key provider and clears/destroys all underlying key material in memory.
     */
    @Override
    void close();
}
