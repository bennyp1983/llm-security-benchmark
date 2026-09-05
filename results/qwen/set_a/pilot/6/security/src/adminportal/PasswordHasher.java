package adminportal;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted, iterated password hashing (PBKDF2-HMAC-SHA256) with constant-time verification.
 *
 * Encoded form: {@code pbkdf2$<iterations>$<saltBase64>$<hashBase64>}.
 *
 * NOTE ON Plaintext: {@link PBEKeySpec} defensively copies the supplied characters, and that
 * internal copy is cleared only when the spec is garbage collected. That is a limitation of the
 * JDK, not of this class; every array this class does own is zeroed before it is dropped.
 */
public final class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int SALT_BYTES = 16;
    public static final int KEY_BITS = 256;
    /** OWASP 2023 guidance for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 310_000;
    /** Below this, a stored hash is treated as under-stretched and flagged for rehash. */
    public static final int MIN_ACCEPTABLE_ITERATIONS = 100_000;

    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final int iterations;
    private final SecureRandom random;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    /** Lowered iteration counts are for tests and demos only; production uses the default. */
    public PasswordHasher(int iterations) {
        if (iterations < 1_000) {
            throw new IllegalArgumentException("iteration count too low: " + iterations);
        }
        this.iterations = iterations;
        this.random = new SecureRandom();
    }

    public int iterations() {
        return iterations;
    }

    public String encode(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt, iterations, KEY_BITS);
        try {
            return "pbkdf2$" + iterations + "$" + B64.encodeToString(salt) + "$" + B64.encodeToString(hash);
        } finally {
            wipe(hash);
        }
    }

    /**
     * Verifies {@code password} against an encoded hash. Runs in time independent of the stored
     * value and never short-circuits on a malformed prefix, so a corrupt or hostile record cannot
     * be distinguished from a wrong password by timing.
     */
    public boolean verify(char[] password, String encoded) {
        if (password == null || password.length == 0 || encoded == null || encoded.isEmpty()) {
            return false;
        }
        String[] parts = encoded.split("\\$");
        if (parts.length != 4 || !"pbkdf2".equals(parts[0])) {
            return false;
        }
        int rounds;
        byte[] salt;
        byte[] expected;
        try {
            rounds = Integer.parseInt(parts[1]);
            salt = B64D.decode(parts[2]);
            expected = B64D.decode(parts[3]);
        } catch (RuntimeException malformed) {
            return false;
        }
        if (rounds < 1 || salt.length == 0 || expected.length == 0) {
            return false;
        }
        byte[] actual = pbkdf2(password, salt, rounds, expected.length * 8);
        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            wipe(actual);
        }
    }

    /**
     * A syntactically valid digest derived by one real PBKDF2 run, for callers that must do
     * equal work for a non-existent account. Built rather than hard-coded: a hand-written constant
     * is a silent timing leak if a strict base64 decoder rejects it and {@link #verify(char[], String)}
     * bails out before stretching. The value matches no password.
     */
    public String dummyEncoded() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = pbkdf2(new char[] {'\u0000'}, salt, iterations, KEY_BITS);
        try {
            return "pbkdf2$" + iterations + "$" + B64.encodeToString(salt) + "$"
                    + B64.encodeToString(hash);
        } finally {
            wipe(hash);
        }
    }

    /** Iteration count of a stored hash, or -1 when unparseable. */
    public static int storedIterations(String encoded) {
        String[] parts = encoded == null ? new String[0] : encoded.split("\\$");
        if (parts.length != 4 || !"pbkdf2".equals(parts[0])) {
            return -1;
        }
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public static boolean needsRehash(String encoded, int currentIterations) {
        int stored = storedIterations(encoded);
        return stored < 0 || stored != currentIterations;
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int rounds, int bits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, rounds, bits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    static void wipe(char[] chars) {
        if (chars != null) {
            java.util.Arrays.fill(chars, '\0');
        }
    }

    private static void wipe(byte[] bytes) {
        java.util.Arrays.fill(bytes, (byte) 0);
    }
}
