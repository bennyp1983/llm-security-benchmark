package account;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Turns a password into a storable PBKDF2-SHA256 encoding and checks a candidate
 * password against such an encoding.
 *
 * <p>Encoding layout: {@code pbkdf2-sha256$<iterations>$<salt base64>$<hash base64>}.
 * The iteration count travels with the hash so the cost can be raised later without
 * forcing existing users to reset their password.</p>
 */
final class PasswordHasher {

    static final String VERSION = "pbkdf2-sha256";
    static final int ITERATIONS = 210_000;

    private static final String JCE_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int MIN_ITERATIONS = 10_000;
    private static final int MAX_ITERATIONS = 20_000_000;

    static final int MIN_PASSWORD_CHARS = 10;
    static final int MAX_PASSWORD_CHARS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

    /**
     * Fixed inputs for the branch where no account matched. Doing real key
     * derivation there keeps a wrong-username attempt as slow as a wrong-password
     * attempt, so response time does not reveal whether an account exists.
     */
    private static final char[] EQUALIZING_PASSWORD = "timing equalizer placeholder secret".toCharArray();
    private static final byte[] EQUALIZING_SALT = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private PasswordHasher() {
    }

    /**
     * Rejects passwords the key derivation cannot represent one-to-one, plus the
     * obvious length bounds. Rejected rather than cleaned: trimming a password
     * would silently substitute a different secret than the one the user typed.
     *
     * @throws IllegalArgumentException with a user-safe reason
     */
    static void validatePassword(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("password is missing");
        }
        if (password.length < MIN_PASSWORD_CHARS) {
            throw new IllegalArgumentException("password must be at least " + MIN_PASSWORD_CHARS + " characters");
        }
        if (password.length > MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException("password must be at most " + MAX_PASSWORD_CHARS + " characters");
        }
        // PBEKeySpec drops trailing NUL characters, so "secret...." (with four
        // trailing NULs) would hash identically to "secret" and be accepted for it.
        if (password[password.length - 1] == 0) {
            throw new IllegalArgumentException("password must not end with a NUL character");
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    throw new IllegalArgumentException("password must not contain an unpaired surrogate character");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException("password must not contain an unpaired surrogate character");
            }
        }
    }

    /** Hashes a fresh password with a new random salt. */
    static String hash(char[] password) {
        validatePassword(password);
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS);
        try {
            return VERSION + "$" + ITERATIONS + "$" + BASE64_ENCODER.encodeToString(salt)
                    + "$" + BASE64_ENCODER.encodeToString(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * Constant-time comparison of a candidate password against a stored encoding.
     * Returns false for anything unparseable instead of throwing, so the caller
     * cannot be talked into distinguishing "no such account" from "bad store".
     */
    static boolean matches(char[] password, String storedEncoding) {
        if (password == null || storedEncoding == null) {
            return false;
        }
        String[] parts = storedEncoding.split("\\$", -1);
        if (parts.length != 4 || !VERSION.equals(parts[0])) {
            return false;
        }
        int iterations;
        byte[] salt;
        byte[] expected;
        try {
            iterations = Integer.parseInt(parts[1]);
            salt = BASE64_DECODER.decode(parts[2]);
            expected = BASE64_DECODER.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        // A stored record is only trusted if its cost is still sane: otherwise a
        // tampered file could ask for one iteration and make cracking cheap.
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                || salt.length < SALT_BYTES || expected.length != HASH_BITS / 8) {
            return false;
        }
        byte[] actual;
        try {
            actual = derive(password, salt, iterations);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return false;
        }
        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    /** Runs the same amount of key derivation as a real login attempt. */
    static void burnEquivalentWork() {
        byte[] hash = derive(EQUALIZING_PASSWORD, EQUALIZING_SALT, ITERATIONS);
        Arrays.fill(hash, (byte) 0);
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance(JCE_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("password hashing is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }
}
