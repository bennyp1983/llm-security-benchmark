package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC-SHA256 password hashing, using the JDK's own implementation rather than a hand-rolled
 * KDF or a third-party library (rule 8).
 *
 * <p>PBKDF2 is chosen over a memory-hard KDF deliberately and within its documented limits: it is
 * FIPS 180-4/FIPS 140-3 approved, ships with the platform, and its weakness against GPU/ASIC
 * cracking is mitigated here by a 12-character minimum policy and by two independent rate limits
 * that make 100k attempts/s unaffordable against this endpoint. A memory-hard KDF (Argon2id) is the
 * better choice for a store whose dump can be taken offline; swapping it in changes only this class.
 *
 * <p>The supplied password is never wiped by this class - it is owned by the caller, and the same
 * array is deliberately used twice per login attempt (see {@link AuthService}). Callers wipe in a
 * {@code finally} block.
 */
final class PasswordHasher {

    static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    static final int SALT_BYTES = 16;
    static final int DERIVED_BITS = 256;
    static final int DERIVED_BYTES = DERIVED_BITS / 8;
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 1_500_000;
    /** Domain separator so a blind salt can never collide with a stored random salt. */
    private static final String BLIND_PREFIX = "auth-blind-v1:";

    private final int defaultIterations;

    PasswordHasher(int defaultIterations) {
        if (defaultIterations < MIN_ITERATIONS || defaultIterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iteration_range");
        }
        this.defaultIterations = defaultIterations;
    }

    int defaultIterations() {
        return defaultIterations;
    }

    byte[] newSalt() {
        return CryptoUtils.randomBytes(SALT_BYTES);
    }

    /**
     * Derives the digest for {@code pw} under {@code salt}.
     *
     * <p>{@link PBEKeySpec#clearPassword()} is called in a {@code finally} block so the factory's
     * internal copy of the password is zeroed even when the derivation throws.
     */
    byte[] derive(char[] pw, byte[] salt, int iterations) throws AuthFailure {
        if (pw == null || pw.length == 0) {
            throw new AuthFailure("kdf_empty_input");
        }
        if (salt == null || salt.length != SALT_BYTES) {
            throw new AuthFailure("kdf_salt_length");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new AuthFailure("kdf_iteration_range");
        }
        PBEKeySpec spec = new PBEKeySpec(pw, salt, iterations, DERIVED_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] out = factory.generateSecret(spec).getEncoded();
            if (out.length != DERIVED_BYTES) {
                CryptoUtils.wipe(out);
                throw new AuthFailure("kdf_output_length");
            }
            return out;
        } catch (java.security.GeneralSecurityException e) {
            throw new AuthFailure("kdf_unavailable");
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * A deterministic salt derived from the (already validated) email address, used only to hash the
     * supplied password for an address that has no account. It gives an unknown-email attempt the
     * same KDF cost as a known-email attempt without storing anything for that address.
     *
     * <p>Because it is derived from public information it provides no secrecy; it exists purely to
     * consume comparable work. See {@link AuthService} for the equal-work argument.
     */
    byte[] blindSalt(String normalisedEmail) {
        byte[] full = CryptoUtils.sha256(BLIND_PREFIX + normalisedEmail);
        return Arrays.copyOf(full, SALT_BYTES);
    }

    /**
     * Compares a candidate password with the stored digest. Both sides are fixed-length
     * ({@value #DERIVED_BYTES} bytes) so the comparison leaks nothing about the stored value beyond
     * equality.
     */
    boolean matches(char[] pw, byte[] salt, int iterations, byte[] storedDigest) {
        byte[] candidate;
        try {
            candidate = derive(pw, salt, iterations);
        } catch (AuthFailure e) {
            return false;
        }
        boolean eq = CryptoUtils.constantTimeEquals(candidate, storedDigest);
        CryptoUtils.wipe(candidate);
        return eq;
    }

    static byte[] saltFromHex(String hex) throws AuthFailure {
        byte[] salt;
        try {
            salt = CryptoUtils.fromHex(hex);
        } catch (IllegalArgumentException e) {
            throw new AuthFailure("salt_hex");
        }
        if (salt.length != SALT_BYTES) {
            CryptoUtils.wipe(salt);
            throw new AuthFailure("salt_length");
        }
        return salt;
    }

    static String hexOf(byte[] value) {
        return CryptoUtils.toHex(value);
    }

    /** Internal failure carrying a fixed code token; never contains user input. */
    static final class AuthFailure extends Exception {
        private static final long serialVersionUID = 1L;

        AuthFailure(String code) {
            super(code);
        }
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
