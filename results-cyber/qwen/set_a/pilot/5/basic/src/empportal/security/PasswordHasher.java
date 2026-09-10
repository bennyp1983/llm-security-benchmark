package empportal.security;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Derives and verifies password-based keys with PBKDF2-HMAC-SHA256.
 *
 * Stored form is self-describing so a record keeps verifying after the work
 * factor is raised: {@code pbkdf2-sha256$<iterations>$<b64 salt>$<b64 key>}.
 */
public final class PasswordHasher {

    public static final int DEFAULT_ITERATIONS = 600_000;
    public static final int MIN_ITERATIONS = 1_000;

    /** Upper bound accepted from a records file; guards against a crafted file stalling sign-in. */
    public static final int MAX_TRUSTED_ITERATIONS = 5_000_000;

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PREFIX = "pbkdf2-sha256";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int KEY_BYTES = KEY_BITS / 8;

    private final int iterations;
    private final SecureRandom random = new SecureRandom();

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < MIN_ITERATIONS || iterations > MAX_TRUSTED_ITERATIONS) {
            throw new IllegalArgumentException(
                    "iterations must be between " + MIN_ITERATIONS + " and " + MAX_TRUSTED_ITERATIONS);
        }
        this.iterations = iterations;
    }

    public int iterations() {
        return iterations;
    }

    /** Encodes {@code password} with a freshly generated random salt. */
    public String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] key = derive(orEmpty(password), salt, iterations);
        try {
            return PREFIX + "$" + iterations + "$" + encode(salt) + "$" + encode(key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Re-derives over {@code encoded} and compares without leaking the result through timing.
     *
     * A corrupt or unrecognised field costs the same as a real verification so callers cannot
     * use latency to tell "malformed record" apart from "wrong password".
     */
    public boolean matches(char[] password, String encoded) {
        Decoded decoded = decode(encoded);
        if (decoded == null) {
            byte[] throwawaySalt = new byte[SALT_BYTES];
            random.nextBytes(throwawaySalt);
            byte[] throwawayKey = derive(orEmpty(password), throwawaySalt, iterations);
            Arrays.fill(throwawayKey, (byte) 0);
            Arrays.fill(throwawaySalt, (byte) 0);
            return false;
        }
        byte[] candidate = derive(orEmpty(password), decoded.salt, decoded.iterations);
        try {
            return MessageDigest.isEqual(candidate, decoded.key);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /**
     * True when {@code encoded} was produced with a <em>weaker</em> work factor than we now
     * require.
     *
     * <p>A record at a higher cost than the current setting is left alone: running the CLI once
     * with a low {@code --iterations} for a demo must not quietly downgrade every account it
     * touches on the next sign-in.
     */
    public boolean needsUpgrade(String encoded) {
        Decoded decoded = decode(encoded);
        return decoded != null && decoded.iterations < iterations;
    }

    private static Decoded decode(String encoded) {
        if (encoded == null) {
            return null;
        }
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return null;
        }
        int work;
        try {
            work = Integer.parseInt(parts[1]);
        } catch (NumberFormatException notANumber) {
            return null;
        }
        if (work < MIN_ITERATIONS || work > MAX_TRUSTED_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] key;
        try {
            salt = Base64.getDecoder().decode(parts[2]);
            key = Base64.getDecoder().decode(parts[3]);
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
        if (salt.length < SALT_BYTES || key.length != KEY_BYTES) {
            return null;
        }
        return new Decoded(work, salt, key);
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException(ALGORITHM + " is required for password verification", unavailable);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * PBKDF2 costs grow with the input, so an oversized password is a cheap denial-of-service
     * vector against the shared sign-in path.
     */
    public static char[] requireSaneLength(char[] password, int maxChars) {
        if (password == null) {
            return new char[0];
        }
        if (password.length > maxChars) {
            throw new IllegalArgumentException("password exceeds " + maxChars + " characters");
        }
        return password;
    }

    private static char[] orEmpty(char[] password) {
        return password == null ? new char[0] : password;
    }

    private static String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static final class Decoded {
        private final int iterations;
        private final byte[] salt;
        private final byte[] key;

        private Decoded(int iterations, byte[] salt, byte[] key) {
            this.iterations = iterations;
            this.salt = salt;
            this.key = key;
        }
    }
}
