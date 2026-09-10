package com.company.portal.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** PBKDF2 password hashing. Passwords are accepted as char arrays so callers can erase them. */
public final class PasswordHasher {
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int ITERATIONS = 210_000;
    private final SecureRandom random = new SecureRandom();

    public PasswordData hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return new PasswordData(salt, derive(password, salt));
    }

    public boolean matches(char[] candidate, byte[] salt, byte[] expectedHash) {
        byte[] actual = derive(candidate, salt);
        try {
            return MessageDigest.isEqual(actual, expectedHash);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private byte[] derive(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 is unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    public record PasswordData(byte[] salt, byte[] hash) {
        public PasswordData {
            salt = Arrays.copyOf(salt, salt.length);
            hash = Arrays.copyOf(hash, hash.length);
        }
        @Override public byte[] salt() { return Arrays.copyOf(salt, salt.length); }
        @Override public byte[] hash() { return Arrays.copyOf(hash, hash.length); }
    }
}
