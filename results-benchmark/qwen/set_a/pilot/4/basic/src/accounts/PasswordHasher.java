package accounts;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Derives and checks password hashes with PBKDF2-HMAC-SHA256.
 *
 * <p>Design notes that matter for security:
 * <ul>
 *   <li>Every credential gets its own random salt, so two accounts that pick the
 *       same password get different stored hashes and no attacker can amortise a
 *       brute-force run across the whole store.</li>
 *   <li>The owning username is mixed into the key-derivation salt material, so a
 *       hash cannot be replayed under a different identity by editing one field of
 *       a stored record.</li>
 *   <li>Verification recomputes at the cost recorded per account and compares with
 *       {@link MessageDigest#isEqual}, which does not short-circuit on the first
 *       differing byte.</li>
 *   <li>Passwords are passed as {@code char[]}, never concatenated into the file
 *       format, and intermediate digests are zeroed as soon as they are used.</li>
 * </ul>
 */
final class PasswordHasher {

    static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    /** Floor accepted for a stored record, and the value used for brand new accounts. */
    static final int DEFAULT_ITERATIONS = 600_000;

    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final byte DOMAIN_SEPARATOR = 0x00;

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    /**
     * @param iterations PBKDF2 rounds for newly created credentials; lower values are
     *                   allowed so tests stay fast, but they are refused outright
     *                   rather than silently weakening a production deployment.
     */
    PasswordHasher(int iterations) {
        if (iterations < CredentialRecord.ITERATIONS_MIN || iterations > CredentialRecord.ITERATIONS_MAX) {
            throw new IllegalArgumentException("iterations must be between "
                    + CredentialRecord.ITERATIONS_MIN + " and " + CredentialRecord.ITERATIONS_MAX);
        }
        this.iterations = iterations;
    }

    /** Builds a storable credential for {@code username}; leaves {@code password} untouched. */
    CredentialRecord createCredential(String username, char[] password) {
        if (username == null || password == null || password.length == 0) {
            throw new IllegalArgumentException("username and password are required");
        }
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, username, iterations);
        try {
            return new CredentialRecord(username, ALGORITHM, iterations, salt, hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /** Recomputes the hash for {@code stored} and reports whether {@code password} matches it. */
    boolean verify(char[] password, CredentialRecord stored) {
        if (password == null || password.length == 0) {
            return false;
        }
        byte[] candidate = derive(password, stored.salt(), stored.username(), stored.iterations());
        try {
            return MessageDigest.isEqual(candidate, stored.hash());
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /**
     * The salt material handed to PBKDF2 is the per-account salt, a NUL separator and the
     * username. Usernames are validated to exclude NUL, so no (salt, username) pair can be
     * confused with another one.
     */
    private static byte[] derive(char[] password, byte[] salt, String username, int iterations) {
        byte[] name = username.getBytes(StandardCharsets.UTF_8);
        byte[] saltMaterial = new byte[salt.length + 1 + name.length];
        System.arraycopy(salt, 0, saltMaterial, 0, salt.length);
        saltMaterial[salt.length] = DOMAIN_SEPARATOR;
        System.arraycopy(name, 0, saltMaterial, salt.length + 1, name.length);
        try {
            PBEKeySpec spec = new PBEKeySpec(password, saltMaterial, iterations, HASH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("password hashing is unavailable: " + ALGORITHM, e);
        } finally {
            Arrays.fill(saltMaterial, (byte) 0);
        }
    }
}
