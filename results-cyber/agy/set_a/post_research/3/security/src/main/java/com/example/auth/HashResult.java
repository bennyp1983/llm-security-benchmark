package com.example.auth;

/**
 * Immutable container for password hash components.
 *
 * @param saltBase64    Base64-encoded cryptographic salt.
 * @param hashBase64    Base64-encoded PBKDF2 derived key.
 * @param iterations    Number of PBKDF2 iterations used.
 * @param algorithm     Key derivation function algorithm name.
 */
public record HashResult(
        String saltBase64,
        String hashBase64,
        int iterations,
        String algorithm
) {
    public HashResult {
        if (saltBase64 == null || hashBase64 == null || algorithm == null) {
            throw new IllegalArgumentException("Hash result components cannot be null");
        }
        if (iterations <= 0) {
            throw new IllegalArgumentException("Iterations must be positive");
        }
    }
}
