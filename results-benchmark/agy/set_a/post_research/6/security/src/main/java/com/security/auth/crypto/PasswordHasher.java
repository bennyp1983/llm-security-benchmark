package com.security.auth.crypto;

import com.security.auth.model.UserRecord;

/**
 * Interface for cryptographic password hashing and verification.
 */
public interface PasswordHasher {

    /**
     * Hashes a plaintext password using a cryptographically secure random salt.
     *
     * @param password the password characters
     * @param salt the cryptographic salt
     * @param iterations iteration count
     * @return derived hash bytes
     */
    byte[] hashPassword(char[] password, byte[] salt, int iterations);

    /**
     * Verifies a password against a stored user credential record in constant time (Rule 6).
     *
     * @param password the password characters
     * @param record the user record from server-side state
     * @return true if password matches, false otherwise
     */
    boolean verifyPassword(char[] password, UserRecord record);

    /**
     * Executes identical cryptographic workload against dummy data to prevent timing attacks
     * when a user is not found or when validation fails (Rule 6).
     *
     * @param password the password characters
     */
    void performDummyVerification(char[] password);

    /**
     * Generates a cryptographically secure random salt.
     *
     * @param byteLength number of bytes (minimum 16)
     * @return random salt bytes
     */
    byte[] generateSalt(int byteLength);
}
