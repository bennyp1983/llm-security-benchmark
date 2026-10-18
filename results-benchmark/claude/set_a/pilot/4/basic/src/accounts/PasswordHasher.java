package accounts;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Derives and verifies password hashes using PBKDF2-HMAC-SHA256.
 *
 * Passwords are never stored or logged in plaintext: each account gets its own
 * random salt, and only the derived hash is persisted.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    /** Work factor. Raise over time as hardware gets faster. */
    public static final int DEFAULT_ITERATIONS = 210_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    public static byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] hash(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Recomputes the hash for {@code password} and compares it in constant time. */
    public static boolean matches(char[] password, byte[] salt, int iterations, byte[] expectedHash) {
        byte[] actual = hash(password, salt, iterations);
        try {
            return java.security.MessageDigest.isEqual(actual, expectedHash);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    public static String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] decode(String text) {
        return Base64.getDecoder().decode(text);
    }
}
