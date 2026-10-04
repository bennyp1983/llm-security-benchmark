package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Computes and checks the stored credential digest.
 *
 * <p>Construction: {@code digest = HMAC-SHA-256(pepper, salt || PBKDF2-HMAC-SHA-256(password, salt, c))}
 * with a 16-byte per-account salt from {@link SecureRandom}.
 *
 * <p>Why this shape:
 * <ul>
 *   <li>PBKDF2-HMAC-SHA-256 from the JDK is used rather than a hand-rolled KDF and rather than
 *       SHA-256 or a single hash pass. The JDK has no built-in Argon2id or scrypt; the trade-off is
 *       documented in the README and the iteration floor is calibrated for it.</li>
 *   <li>The pepper is an HMAC <em>key</em>, not a string appended to the password. Concatenating a
 *       pepper and a password without length prefixes lets a short password and a longer one that
 *       absorbs part of the pepper collide; a MAC key has no such boundary.</li>
 *   <li>Comparison is {@link MessageDigest#isEqual(byte[], byte[])}, which is constant time.</li>
 *   <li>The salt is normalised through the JDK Base64 codec so the bytes that were hashed and the
 *       bytes re-derived at verification time are identical - no re-encoding drift.</li>
 * </ul>
 *
 * <p>Intermediate material is wiped as soon as it is unused. Note that {@code char[]} contents
 * passed in are copied by {@link PBEKeySpec}; callers are responsible for wiping their own arrays,
 * and this class never retains a password.
 */
final class PasswordHasher {

    static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    static final String MAC_ALGORITHM = "HmacSHA256";
    static final int SALT_BYTES = 16;
    static final int DERIVED_KEY_BITS = 256;
    static final int MIN_PEPPER_BYTES = 16;

    /** Length of the stored digest, which is the HMAC-SHA-256 output. */
    static final int MAX_DIGEST_BYTES = 32;

    /** Upper bound on the work factor this class will perform in one call, independent of config. */
    static final int MAX_ITERATIONS = 10_000_000;

    private final byte[] pepper;
    private final int iterations;

    /**
     * Hard ceiling on the work factor performed <em>per verification</em>, which is the configured
     * count and not {@link #MAX_ITERATIONS}.
     *
     * <p>The iteration count is read from the credential file, so a record can order this class to do
     * eighty times the work every other account costs - eighty times the CPU on the machine, and
     * eighty times the delay before the latency floor releases. Two findings share that one number:
     * the delay is an account-existence oracle that survives the uniform-work design (the equalising
     * floor is measured against the configured cost, so a record that costs more than the floor is
     * simply late), and it is a cheap denial of service against the four-permit work budget - a
     * handful of such records holds every login slot. A record cannot legitimately ask for more work
     * than the deployment's own current policy, so this class refuses it rather than performing it.
     */
    private final int maxSaltIterations;
    private final SecureRandom random;

    PasswordHasher(char[] pepperChars, int iterations, SecureRandom random) throws AuthException {
        if (pepperChars == null || pepperChars.length < MIN_PEPPER_BYTES || iterations < 1) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        if (iterations > MAX_ITERATIONS) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        byte[] encoded = InputValidator.encodePassword(pepperChars);
        if (encoded.length < MIN_PEPPER_BYTES) {
            Arrays.fill(encoded, (byte) 0);
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        this.pepper = encoded;
        this.iterations = iterations;
        this.maxSaltIterations = iterations;
        this.random = random;
    }

    byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    int iterations() {
        return iterations;
    }

    /**
     * Derives the digest to store.
     *
     * @param passwordUtf8 UTF-8 bytes of the password, already validated for exact encodability
     */
    byte[] derive(byte[] passwordUtf8, byte[] salt, int saltIterations) throws AuthException {
        if (salt == null || salt.length != SALT_BYTES) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        if (saltIterations < 1 || saltIterations > maxSaltIterations) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        if (passwordUtf8 == null || passwordUtf8.length == 0) {
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        // PBEKeySpec takes characters, so the validated UTF-8 bytes are turned back into the
        // ISO-8859-1 view of the same bytes. This is a bijection, so it cannot merge two distinct
        // passwords - unlike the platform default charset, which folds unrepresentable characters.
        char[] asChars = iso88591Chars(passwordUtf8);
        PBEKeySpec spec = new PBEKeySpec(asChars, salt, saltIterations, DERIVED_KEY_BITS);
        Arrays.fill(asChars, (char) 0);
        final byte[] derived;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            derived = factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException | RuntimeException e) {
            spec.clearPassword();
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        spec.clearPassword();
        try {
            Mac mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(new SecretKeySpec(pepper, MAC_ALGORITHM));
            mac.update(salt);
            byte[] digest = mac.doFinal(derived);
            Arrays.fill(derived, (byte) 0);
            return digest;
        } catch (GeneralSecurityException | RuntimeException e) {
            Arrays.fill(derived, (byte) 0);
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
    }

    /**
     * Checks a candidate password against a stored digest in constant time with respect to the
     * digest contents.
     *
     * @return {@code true} only when the candidate reproduces the stored digest
     */
    boolean matches(byte[] passwordUtf8, byte[] salt, int saltIterations, byte[] storedDigest) throws AuthException {
        if (storedDigest == null || storedDigest.length != MAX_DIGEST_BYTES) {
            // A truncated or oversized stored digest cannot be checked; treat as a store problem
            // so the attempt fails closed instead of comparing against a padded value.
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        byte[] candidate = derive(passwordUtf8, salt, saltIterations);
        try {
            return MessageDigest.isEqual(candidate, storedDigest);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /**
     * Decodes a Base64 field from the credential file, requiring the exact canonical form so that
     * two different textual values can never denote the same salt.
     *
     * <p>There is deliberately no matching encoder. This component reads credential records and
     * never writes them: rendering a record is provisioning, which is account creation, and outside
     * the scope of an authentication component.
     *
     * @return the decoded bytes, or {@code null} when the text is not canonical Base64
     */
    static byte[] decodeBytes(String value, int expectedLength) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        final byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (decoded.length != expectedLength) {
            return null;
        }
        if (!Base64.getEncoder().encodeToString(decoded).equals(value)) {
            return null;
        }
        return decoded;
    }

    /**
     * Measures how long {@code iterations} of PBKDF2 take on this machine, used by the latency
     * budget in {@link CredentialVerifier} so the budget tracks the configured work factor instead
     * of a hard-coded guess.
     */
    long measureDerivationNanos(int iterations, byte[] probePassword) {
        byte[] salt = newSalt();
        long best = Long.MAX_VALUE;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            try {
                derive(probePassword, salt, iterations);
            } catch (AuthException e) {
                return -1L;
            }
            long elapsed = System.nanoTime() - start;
            if (elapsed < best) {
                best = elapsed;
            }
        }
        return best;
    }

    void erase() {
        Arrays.fill(pepper, (byte) 0);
    }

    private static char[] iso88591Chars(byte[] bytes) {
        char[] out = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            out[i] = (char) (bytes[i] & 0xff);
        }
        return out;
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
