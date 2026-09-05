package com.example.adminportal;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Creates and verifies versioned, salted password hashes. */
final class PasswordHasher {
    private static final String ALGORITHM_NAME = "pbkdf2_sha256";
    private static final String JCA_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private PasswordHasher() { }

    static String hash(char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS, HASH_BITS);
        try {
            return ALGORITHM_NAME + "$" + ITERATIONS + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(derived);
        } finally {
            java.util.Arrays.fill(derived, (byte) 0);
        }
    }

    static boolean verify(char[] password, String encodedHash) {
        byte[] actual = null;
        try {
            String[] fields = encodedHash.split("\\$", -1);
            if (fields.length != 4 || !ALGORITHM_NAME.equals(fields[0])) {
                return false;
            }
            int iterations = Integer.parseInt(fields[1]);
            if (iterations < 100_000 || iterations > 10_000_000) {
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(fields[2]);
            byte[] expected = Base64.getDecoder().decode(fields[3]);
            if (salt.length < 16 || expected.length < 32) {
                return false;
            }
            actual = derive(password, salt, iterations, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        } finally {
            if (actual != null) {
                java.util.Arrays.fill(actual, (byte) 0);
            }
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int bits)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
        try {
            return SecretKeyFactory.getInstance(JCA_ALGORITHM).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
