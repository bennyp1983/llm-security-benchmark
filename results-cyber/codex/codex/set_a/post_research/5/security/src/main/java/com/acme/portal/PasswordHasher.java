package com.acme.portal;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

final class PasswordHasher {
    static final int ITERATIONS = 600_000;
    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {}

    static byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    static byte[] hash(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    static boolean verify(char[] password, CredentialStore.Record record)
            throws GeneralSecurityException {
        byte[] candidate = hash(password, record.salt());
        try {
            return MessageDigest.isEqual(candidate, record.passwordHash());
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }
}
