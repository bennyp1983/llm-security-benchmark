package secureaccount;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Turns a password into a storable, non-recoverable verifier.
 *
 * <p>Storage format is the PHC-style string
 * {@code $PBKDF2WithHmacSHA256$i=<iters>$l=<keyBits>$s=<b64 salt>$h=<b64 hash>$}.
 * The iteration count, key length and salt travel with the hash so that verifiers stay
 * readable after the policy parameters are raised, and so that a future increase never
 * invalidates an existing account.
 *
 * <p>Nothing in that string lets anyone recover the password: PBKDF2 is a one-way,
 * iterated construction, and the salt is only there to defeat precomputed (rainbow) tables
 * and to make two users with the same password produce different records. Recovery is
 * impossible by design; only a guess-and-check attack against this specific salt is left,
 * which is exactly what the iteration count is there to slow down.
 *
 * <p>Passwords are accepted as {@code char[]} rather than {@code String} so that callers can
 * erase their own copy of the secret; {@link PBEKeySpec} is always cleared before this class
 * returns.
 */
public final class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * OWASP's current minimum for PBKDF2-HMAC-SHA256. Measured on the reference machine at
     * roughly 440 ms per derivation, which is slow enough to make offline cracking expensive
     * and still fast enough for an interactive login.
     */
    public static final int DEFAULT_ITERATIONS = 310_000;

    /**
     * Stored verifiers below this iteration count are treated as corrupt rather than merely
     * weak. The floor sits well above it only so the test suite can run fast; production
     * never writes anything near it.
     */
    public static final int MIN_ACCEPTED_ITERATIONS = 1_000;

    /** Upper bound accepted from a stored record, so a hostile file cannot stall a login. */
    public static final int MAX_ACCEPTED_ITERATIONS = 5_000_000;

    public static final int SALT_BYTES = 16;
    public static final int KEY_BYTES = 32;

    /** Cap on the secret length: PBKDF2 cost scales with it, so an unbounded input is a DoS. */
    public static final int MAX_PASSWORD_CHARS = 1024;

    /**
     * URL-safe alphabet, so a record never contains characters that another tool might
     * reinterpret; values are strictly {@code [A-Za-z0-9_-]} and carry no padding.
     */
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_IN = Base64.getUrlDecoder();
    private static final String SEPARATOR = "$";

    /** Leading separator plus one before each of the five fields. */
    private static final int EXPECTED_SEPARATOR_COUNT = 6;

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    /** Produces verifiers with the production parameters. */
    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    /**
     * @param iterations PBKDF2 rounds to use for newly created verifiers; raising this only
     *     makes new accounts slower to derive, older records keep theirs until they are
     *     rehashed at a successful login.
     */
    public PasswordHasher(int iterations) {
        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
            throw new IllegalArgumentException(
                    "iterations must be between " + MIN_ACCEPTED_ITERATIONS + " and "
                            + MAX_ACCEPTED_ITERATIONS);
        }
        this.iterations = iterations;
    }

    public int iterations() {
        return iterations;
    }

    /**
     * Hashes {@code password} under a fresh 128-bit random salt.
     *
     * <p>The caller's array is left untouched; erase it yourself when you are done with it.
     */
    public String hash(char[] password) {
        requirePassword(password);
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] key = derive(password, salt, iterations, KEY_BYTES * 8);
        try {
            return encode(salt, key, iterations);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Recomputes the verifier for {@code password} using the parameters recorded in
     * {@code encoded} and compares them without leaking how many bytes agree.
     *
     * @return {@code true} only when the password matches; {@code false} for a wrong password
     * @throws IllegalArgumentException if {@code encoded} is not a well-formed record
     */
    public boolean matches(char[] password, String encoded) {
        Stored stored = decode(encoded);
        if (password == null || password.length == 0) {
            return false;
        }
        // Derive exactly the stored length, so verifiers written with a shorter key still work.
        byte[] candidate = derive(password, stored.salt, stored.iterations, stored.hash.length * 8);
        try {
            return MessageDigest.isEqual(stored.hash, candidate);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /**
     * Whether {@code encoded} was written with parameters weaker than this hasher's current
     * ones, and should therefore be replaced with a fresh hash of the same password.
     */
    public boolean needsUpgrade(String encoded) {
        Stored stored = decode(encoded);
        return stored.hash.length < KEY_BYTES
                || !ALGORITHM.equals(stored.algorithm)
                || stored.salt.length < SALT_BYTES
                || stored.iterations < iterations;
    }

    /** Fails fast on a malformed record; used when loading a store from disk. */
    public void validateStoredHash(String encoded) {
        decode(encoded);
    }

    /** Runs the KDF purely to burn the same time an honest login would, see AccountService. */
    void burnTime(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] key = derive(password, salt, iterations, KEY_BYTES * 8);
        Arrays.fill(key, (byte) 0);
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        if (password.length > MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException(
                    "password must not exceed " + MAX_PASSWORD_CHARS + " characters");
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int keyBits) {
        requirePassword(password);
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] key = factory.generateSecret(spec).getEncoded();
            if (key.length * 8 != keyBits) {
                throw new IllegalStateException(ALGORITHM + " returned an unexpected key length");
            }
            return key;
        } catch (GeneralSecurityException e) {
            // Absent provider or unsupported parameter: a configuration fault, not a user error.
            throw new IllegalStateException(ALGORITHM + " is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static String encode(byte[] salt, byte[] hash, int iters) {
        return SEPARATOR + ALGORITHM
                + SEPARATOR + "i=" + iters
                + SEPARATOR + "l=" + hash.length * 8
                + SEPARATOR + "s=" + B64.encodeToString(salt)
                + SEPARATOR + "h=" + B64.encodeToString(hash)
                + SEPARATOR;
    }

    private static Stored decode(String encoded) {
        if (encoded == null || !encoded.startsWith(SEPARATOR) || !encoded.endsWith(SEPARATOR)) {
            throw new IllegalArgumentException("malformed password record");
        }
        // Count separators rather than relying on split(): split() discards trailing empty
        // tokens, which would let a record padded with extra separators parse as valid.
        int separators = 0;
        for (int i = 0; i < encoded.length(); i++) {
            if (encoded.charAt(i) == '$') {
                separators++;
            }
        }
        if (separators != EXPECTED_SEPARATOR_COUNT) {
            throw new IllegalArgumentException("malformed password record");
        }
        String[] parts = encoded.substring(1, encoded.length() - 1).split("\\$");
        if (parts.length != 5) {
            throw new IllegalArgumentException("malformed password record");
        }
        String algorithm = parts[0];
        // Never let the file pick the primitive: a record claiming a cheaper or missing
        // algorithm must not become a way to bypass the policy.
        if (!ALGORITHM.equals(algorithm)) {
            throw new IllegalArgumentException("unsupported password algorithm: " + algorithm);
        }
        int iters = parsePositiveInt(field(parts[1], "i="), "iterations");
        int keyBits = parsePositiveInt(field(parts[2], "l="), "key length");
        byte[] salt = decodeBase64(field(parts[3], "s="), "salt");
        byte[] hash = decodeBase64(field(parts[4], "h="), "hash");
        if (iters < MIN_ACCEPTED_ITERATIONS || iters > MAX_ACCEPTED_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range: " + iters);
        }
        if (salt.length < SALT_BYTES || salt.length > 64) {
            throw new IllegalArgumentException("salt length out of range");
        }
        if (keyBits != hash.length * 8) {
            throw new IllegalArgumentException("recorded key length does not match the hash");
        }
        if (hash.length < 16 || hash.length > 64) {
            throw new IllegalArgumentException("hash length out of range");
        }
        return new Stored(algorithm, iters, salt, hash);
    }

    private static String field(String part, String expectedKey) {
        if (!part.startsWith(expectedKey)) {
            throw new IllegalArgumentException("malformed password record: expected " + expectedKey);
        }
        return part.substring(expectedKey.length());
    }

    private static int parsePositiveInt(String raw, String what) {
        if (raw.isEmpty() || !raw.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new IllegalArgumentException("malformed " + what + ": " + raw);
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("malformed " + what + ": " + raw);
        }
    }

    private static byte[] decodeBase64(String raw, String what) {
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("missing " + what + " in password record");
        }
        try {
            return B64_IN.decode(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("malformed " + what + " in password record", e);
        }
    }

    private static final class Stored {
        final String algorithm;
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        Stored(String algorithm, int iterations, byte[] salt, byte[] hash) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }
}
