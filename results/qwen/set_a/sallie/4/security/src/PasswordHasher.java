import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Turns a password into a stored verifier string and checks a candidate password
 * against such a string.
 *
 * <p>The stored form is {@code pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>}.
 * It holds only a salted one-way derivation, so the password cannot be read back out of it.
 */
public final class PasswordHasher {

    public static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final String FORMAT_TAG = "pbkdf2-sha256";
    public static final int SALT_BYTES = 16;
    public static final int HASH_BYTES = 32;
    public static final int DEFAULT_ITERATIONS = 310_000;
    public static final int MIN_ITERATIONS = 1_000;
    public static final int MAX_ITERATIONS = 5_000_000;

    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder UNB64 = Base64.getDecoder();

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    /**
     * Cost parameters used to level the response time of a failed login. Filled in
     * lazily so that a process which never fails a login pays for one derivation only.
     */
    private char[] dummyPassword;
    private byte[] dummySalt;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException(
                    "iterations must be between " + MIN_ITERATIONS + " and " + MAX_ITERATIONS);
        }
        this.iterations = iterations;
    }

    public int iterations() {
        return iterations;
    }

    /** Hashes {@code password} with a fresh random salt. The caller's array is left intact. */
    public String hash(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("password is required");
        }
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] digest = derive(password, salt, iterations);
        return FORMAT_TAG + "$" + iterations + "$"
                + B64.encodeToString(salt) + "$" + B64.encodeToString(digest);
    }

    /**
     * Returns true only when {@code candidate} reproduces the digest stored in {@code encoded}.
     *
     * <p>A malformed or unsupported stored record is reported as a failed match, after the
     * same amount of key derivation work as a real match attempt, so that a damaged record
     * cannot be spotted by timing.
     */
    public boolean verify(char[] candidate, String encoded) {
        StoredRecord record = tryParse(encoded);
        if (candidate == null || record == null) {
            burnWork();
            return false;
        }
        byte[] actual = derive(candidate, record.salt(), record.iterations());
        return MessageDigest.isEqual(actual, record.digest());
    }

    /** Performs one throwaway derivation so refusals cost what real checks cost. */
    public void burnWork() {
        ensureDummyMaterial();
        derive(dummyPassword, dummySalt, iterations);
    }

    private synchronized void ensureDummyMaterial() {
        if (dummySalt == null) {
            dummySalt = new byte[SALT_BYTES];
            random.nextBytes(dummySalt);
            dummyPassword = new char[32];
            for (int i = 0; i < dummyPassword.length; i++) {
                dummyPassword[i] = (char) ('a' + random.nextInt(26));
            }
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(KEY_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | java.security.spec.InvalidKeySpecException e) {
            throw new IllegalStateException(KEY_ALGORITHM + " is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Parses a stored record, or returns null when it is unusable. */
    public static StoredRecord tryParse(String encoded) {
        if (encoded == null) {
            return null;
        }
        String[] part = encoded.split("\\$", -1);
        if (part.length != 4 || !FORMAT_TAG.equals(part[0])) {
            return null;
        }
        int rounds;
        try {
            rounds = Integer.parseInt(part[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        if (rounds < MIN_ITERATIONS || rounds > MAX_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] digest;
        try {
            salt = UNB64.decode(part[2]);
            digest = UNB64.decode(part[3]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (salt.length != SALT_BYTES || digest.length != HASH_BYTES) {
            return null;
        }
        return new StoredRecord(rounds, salt, digest);
    }

    /** A parsed stored record. Array components are copied, so callers cannot mutate them. */
    public static final class StoredRecord {
        private final int iterations;
        private final byte[] salt;
        private final byte[] digest;

        StoredRecord(int iterations, byte[] salt, byte[] digest) {
            this.iterations = iterations;
            this.salt = salt.clone();
            this.digest = digest.clone();
        }

        public int iterations() {
            return iterations;
        }

        public byte[] salt() {
            return salt.clone();
        }

        public byte[] digest() {
            return digest.clone();
        }
    }
}
