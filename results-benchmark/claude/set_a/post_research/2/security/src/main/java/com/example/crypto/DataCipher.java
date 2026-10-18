package com.example.crypto;

/**
 * Encrypts and decrypts sensitive application data with a symmetric key.
 *
 * <p>Every method is authenticated encryption: a ciphertext that has been
 * altered in any way - including a swapped key id or mismatched associated data
 * - fails to decrypt. There is no "decrypt without verifying" entry point,
 * because that is the mistake this interface exists to prevent.
 *
 * <p>Implementations must be safe for concurrent use.
 */
public interface DataCipher {

    /** @return the key id that {@link #encrypt} is currently using. */
    String activeKeyId();

    /**
     * Encrypts {@code plaintext} with the active key.
     *
     * @param plaintext data to protect; not modified, and the caller should wipe it afterwards
     * @param aad       optional associated data that is authenticated but not
     *                  encrypted (for example a record id or tenant id, binding
     *                  the ciphertext to its context); may be {@code null}
     * @return a self-describing envelope: version, key id, nonce and ciphertext+tag
     * @throws CryptoException if encryption fails for any reason
     */
    byte[] encrypt(byte[] plaintext, byte[] aad) throws CryptoException;

    /**
     * Decrypts and verifies an envelope produced by {@link #encrypt}.
     *
     * @param envelope untrusted input - may be arbitrary attacker-chosen bytes
     * @param aad      the same associated data supplied at encryption time; may be {@code null}
     * @return the plaintext; the caller should wipe it when done
     * @throws CryptoException for every failure, with no indication of which check failed
     */
    byte[] decrypt(byte[] envelope, byte[] aad) throws CryptoException;
}
