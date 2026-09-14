package portal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC-SHA256 password hashing plus the equal-cost work used by the
 * branches where no credential check actually happens.
 */
public final class Pbkdf2 {

    public static final int ITERATIONS = 100_000;
    public static final int MIN_ITERATIONS = 10_000;
    public static final int MAX_ITERATIONS = 5_000_000;
    public static final int SALT_BYTES = 16;
    public static final int KEY_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] PROBE_PASSWORD =
            "portal-shadow-probe-0123456789".toCharArray();

    private Pbkdf2() {
    }

    public static byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] derive(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        if (salt == null || salt.length != SALT_BYTES) {
            throw new IllegalArgumentException("salt must be " + SALT_BYTES + " bytes");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BYTES * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Performs the same derivation cost as a real check for a username that has
     * no account, so response time cannot be used to decide whether a username
     * exists. The result is never compared against stored material.
     */
    public static byte[] shadowWork(String username, int iterations) throws GeneralSecurityException {
        byte[] salt = shadowSalt(username);
        char[] probe = PROBE_PASSWORD.clone();
        try {
            return derive(probe, salt, iterations);
        } finally {
            Arrays.fill(probe, '\0');
        }
    }

    /**
     * {@link #shadowWork} for call sites that are already refusing the login: the
     * cost is still paid, but a missing provider must not change the answer.
     */
    static void shadowWorkSafely(String username, int iterations) {
        int safe = Math.min(MAX_ITERATIONS, Math.max(MIN_ITERATIONS, iterations));
        try {
            shadowWork(username, safe);
        } catch (GeneralSecurityException | RuntimeException ignored) {
            // Nothing usable to compare against either way.
        }
    }

    static byte[] shadowSalt(String username) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256")
                    .digest(("portal-shadow:" + username).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
        return Arrays.copyOf(digest, SALT_BYTES);
    }

    /** Constant-time comparison of two derived keys. */
    public static boolean matches(byte[] expected, byte[] actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected, actual);
    }
}
