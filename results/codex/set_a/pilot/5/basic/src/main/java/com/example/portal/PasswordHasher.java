package com.example.portal;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PasswordHasher {
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int SALT_BYTES = 16;
    public static final int HASH_BITS = 256;

    private final SecureRandom random;

    public PasswordHasher() {
        this(new SecureRandom());
    }

    PasswordHasher(SecureRandom random) {
        this.random = random;
    }

    public EmployeeRecord createRecord(String username, char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = hash(password, salt, DEFAULT_ITERATIONS);
        return new EmployeeRecord(username, true, DEFAULT_ITERATIONS, salt, hash);
    }

    public byte[] hash(char[] password, byte[] salt, int iterations) {
        if (iterations < 100_000) {
            throw new IllegalArgumentException("PBKDF2 iteration count is too low");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("PBKDF2 is unavailable", error);
        } finally {
            spec.clearPassword();
        }
    }

    public boolean matches(char[] password, EmployeeRecord employee) {
        byte[] candidate = hash(password, employee.salt(), employee.iterations());
        try {
            return java.security.MessageDigest.isEqual(candidate, employee.passwordHash());
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }
}
