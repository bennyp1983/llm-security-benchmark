package example.security.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** Password verification using the JDK's required PBKDF2-HMAC-SHA-256 implementation. */
public final class PasswordVerifier {
    public static final int MAX_PASSWORD_CHARS = 128;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    private PasswordVerifier() {}

    public static PasswordRecord hashForStorage(char[] password, SecureRandom random) {
        validatePassword(password);
        if (random == null) throw new IllegalArgumentException("SecureRandom is required");
        byte[] salt = new byte[PasswordRecord.SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, PasswordRecord.MIN_ITERATIONS);
        try {
            return new PasswordRecord(salt, hash, PasswordRecord.MIN_ITERATIONS);
        } finally {
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    static boolean verify(char[] password, PasswordRecord record) {
        byte[] candidate = derive(password, record.salt(), record.iterations());
        byte[] expected = record.hash();
        try {
            return MessageDigest.isEqual(candidate, expected);
        } finally {
            Arrays.fill(candidate, (byte) 0);
            Arrays.fill(expected, (byte) 0);
        }
    }

    static void validatePassword(char[] password) {
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException("Invalid credential input");
        }
        for (char c : password) {
            if (Character.isSurrogate(c) || c == '\0') {
                throw new IllegalArgumentException("Invalid credential input");
            }
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, PasswordRecord.HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Required password-verification primitive unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}
