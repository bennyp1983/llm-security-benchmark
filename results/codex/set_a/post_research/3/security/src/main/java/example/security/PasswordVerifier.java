package example.security;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

final class PasswordVerifier implements AutoCloseable {
    static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    static final int ITERATIONS = 600_000;
    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;

    private final byte[] dummySalt = new byte[SALT_BYTES];
    private final byte[] dummyHash;

    PasswordVerifier() throws GeneralSecurityException {
        SecureRandom random = new SecureRandom();
        random.nextBytes(dummySalt);
        char[] randomPassword = new char[32];
        for (int i = 0; i < randomPassword.length; i++) {
            randomPassword[i] = (char) ('!' + random.nextInt(94));
        }
        try {
            dummyHash = derive(randomPassword, dummySalt, ITERATIONS);
        } finally {
            Arrays.fill(randomPassword, '\0');
        }
    }

    boolean verify(char[] password, CredentialRecord record) throws GeneralSecurityException {
        boolean validRecord = record != null && record.enabled()
                && ALGORITHM.equals(record.algorithm())
                && record.iterations() == ITERATIONS
                && record.salt() != null && record.salt().length == SALT_BYTES
                && record.passwordHash() != null && record.passwordHash().length == HASH_BYTES;
        byte[] salt = validRecord ? record.salt() : dummySalt;
        byte[] expected = validRecord ? record.passwordHash() : dummyHash;
        byte[] actual = derive(password, salt, ITERATIONS);
        try {
            return validRecord && MessageDigest.isEqual(actual, expected);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    static byte[] derive(char[] password, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    @Override
    public void close() {
        Arrays.fill(dummySalt, (byte) 0);
        Arrays.fill(dummyHash, (byte) 0);
    }
}
