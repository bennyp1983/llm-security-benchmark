package accounts;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Derives and verifies password hashes using PBKDF2-HMAC-SHA256.
 *
 * <p>A hash is a one-way function: the encoded value written to storage cannot be
 * reversed back into the password. Each password gets its own random salt, so two
 * users with the same password produce different stored values, and a precomputed
 * (rainbow) table cannot be reused across accounts. The iteration count makes each
 * guess expensive for anyone attempting to brute-force a stolen store.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PREFIX = "pbkdf2_sha256";

    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    /**
     * Hashes a password with a fresh random salt.
     *
     * @return an encoded string of the form {@code pbkdf2_sha256$iterations$salt$hash},
     *         safe to persist; the password is not recoverable from it
     */
    public static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] key = deriveKey(password, salt, ITERATIONS, KEY_BITS);
        try {
            Base64.Encoder enc = Base64.getEncoder().withoutPadding();
            return PREFIX + "$" + ITERATIONS + "$" + enc.encodeToString(salt) + "$" + enc.encodeToString(key);
        } finally {
            wipe(key);
        }
    }

    /**
     * Checks a candidate password against a previously encoded hash.
     *
     * @return true only if the password reproduces the stored hash
     */
    public static boolean verify(char[] password, String encoded) {
        String[] parts = encoded.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            throw new IllegalArgumentException("Unrecognized password hash format");
        }
        int iterations;
        byte[] salt;
        byte[] expected;
        try {
            iterations = Integer.parseInt(parts[1]);
            Base64.Decoder dec = Base64.getDecoder();
            salt = dec.decode(parts[2]);
            expected = dec.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Corrupt password hash", e);
        }

        byte[] actual = deriveKey(password, salt, iterations, expected.length * 8);
        try {
            // Constant-time comparison: a byte-by-byte early exit would leak, through
            // timing, how much of the hash a guess matched.
            return MessageDigest.isEqual(expected, actual);
        } finally {
            wipe(actual);
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 is unavailable on this JVM", e);
        } finally {
            // Clears the copy of the password held inside the spec.
            spec.clearPassword();
        }
    }

    private static void wipe(byte[] bytes) {
        java.util.Arrays.fill(bytes, (byte) 0);
    }
}
