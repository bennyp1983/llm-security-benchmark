package portal.security;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Salted, iterated password digests and constant-time verification.
 *
 * <p>Stored format: {@code PBKDF2-SHA256$<iterations>$<salt b64>$<digest b64>}.
 * Nothing in the format is secret; it only has to survive tampering, which is why
 * {@link #verify} re-derives using the parameters recorded in the digest and then
 * compares with {@link MessageDigest#isEqual} (which is constant time for
 * equal-length inputs, and both operands here always are).
 */
public final class PasswordHasher {

    /** OWASP 2023 cost floor for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int MIN_ITERATIONS = 1_000;
    public static final int MAX_ITERATIONS = 5_000_000;
    public static final int SALT_BYTES = 16;
    public static final int KEY_BITS = 256;

    /**
     * Fixed salt used by {@link #spendSameWork(char[])} so that a login for a name that
     * does not exist costs the same as one for a real account. Without it, response time
     * alone tells an attacker which usernames are valid.
     */
    private static final byte[] BURN_SALT = new byte[SALT_BYTES];

    private final KeyDerivation kdf;
    private final int iterations;

    public PasswordHasher() {
        this(new Pbkdf2(), DEFAULT_ITERATIONS);
    }

    /** Lower iteration counts are legitimate in tests and on first-run provisioning. */
    public PasswordHasher(KeyDerivation kdf, int iterations) {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range");
        }
        this.kdf = kdf;
        this.iterations = iterations;
    }

    public int iterations() {
        return iterations;
    }

    public String hash(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("cannot hash an empty password");
        }
        byte[] salt = new byte[SALT_BYTES];
        new java.security.SecureRandom().nextBytes(salt);
        byte[] digest = kdf.derive(password, salt, iterations, KEY_BITS);
        try {
            Base64.Encoder encoder = Base64.getEncoder();
            return kdf.algorithmId() + "$" + iterations + "$"
                    + encoder.encodeToString(salt) + "$" + encoder.encodeToString(digest);
        } finally {
            Arrays.fill(digest, (byte) 0);
        }
    }

    /** @return true only if {@code password} matches the stored digest. */
    public boolean verify(char[] password, String encoded) {
        StoredDigest stored = parse(encoded);
        if (stored == null || password == null || password.length == 0) {
            return false;
        }
        byte[] digest = kdf.derive(password, stored.salt, stored.iterations, KEY_BITS);
        try {
            return MessageDigest.isEqual(stored.digest, digest);
        } finally {
            Arrays.fill(digest, (byte) 0);
        }
    }

    /** Runs the real derivation and throws the result away, to equalise timing. */
    public void spendSameWork(char[] password) {
        char[] placeholder = password != null && password.length > 0 ? password : "x".toCharArray();
        byte[] digest = kdf.derive(placeholder, BURN_SALT, iterations, KEY_BITS);
        Arrays.fill(digest, (byte) 0);
    }

    /** @return true if a stored value is well-formed; used to reject corrupt records. */
    public static boolean isWellFormed(String encoded) {
        return parse(encoded) != null;
    }

    private static StoredDigest parse(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return null;
        }
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 4 || !"PBKDF2-SHA256".equals(parts[0])) {
            return null;
        }
        int cost;
        try {
            cost = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
        // A hostile or corrupt store could claim 2^31 iterations and turn every login
        // attempt into a denial of service, hence the sanity range.
        if (cost < MIN_ITERATIONS || cost > MAX_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] digest;
        try {
            salt = Base64.getDecoder().decode(parts[2]);
            digest = Base64.getDecoder().decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (salt.length != SALT_BYTES || digest.length != KEY_BITS / 8) {
            return null;
        }
        // Reject non-canonical encodings. Base64 ignores trailing bits, so "AB==" and
        // "AB=" decode to the same bytes; accepting both would let a stored digest be
        // silently rewritten into an equivalent-but-different string that still verifies.
        Base64.Encoder encoder = Base64.getEncoder();
        if (!encoder.encodeToString(salt).equals(parts[2]) || !encoder.encodeToString(digest).equals(parts[3])) {
            return null;
        }
        return new StoredDigest(salt, digest, cost);
    }

    private static final class StoredDigest {
        final byte[] salt;
        final byte[] digest;
        final int iterations;

        StoredDigest(byte[] salt, byte[] digest, int iterations) {
            this.salt = salt;
            this.digest = digest;
            this.iterations = iterations;
        }
    }
}
