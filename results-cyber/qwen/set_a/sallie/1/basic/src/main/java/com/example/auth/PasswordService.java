package com.example.auth;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Turns passwords into verifiable records and back again.
 *
 * <p>Passwords are never stored or compared in plain form. Each password is stretched with
 * PBKDF2-HMAC-SHA256 under a fresh random salt, and verification re-runs the same stretching and
 * compares the digests in constant time.
 */
public final class PasswordService {

    static final String PBKDF2_SHA256 = "pbkdf2-sha256";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    static final int MIN_ITERATIONS = 1_000;
    static final int MAX_ITERATIONS = 5_000_000;

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    /**
     * A syntactically valid, unreachable password record. Logging in with a name that does not
     * exist spends this record's stretching time, so a rejected guess costs the same as a wrong
     * one and "is this username taken?" cannot be answered by stopwatch.
     */
    private final StoredPassword timingReference;

    public PasswordService(int iterations) {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations must be between " + MIN_ITERATIONS
                    + " and " + MAX_ITERATIONS + ", was " + iterations);
        }
        this.iterations = iterations;
        this.timingReference = new StoredPassword(PBKDF2_SHA256, iterations, randomBytes(SALT_BYTES),
                new byte[HASH_BYTES]);
    }

    public int iterations() {
        return iterations;
    }

    /** The name of the stretching function, as it appears in a stored record. */
    public String algorithm() {
        return PBKDF2_SHA256;
    }

    /**
     * Whether stretching this candidate can be trusted to mean exactly what it says. Three shapes
     * are refused, because the key factory quietly maps each of them onto a different password --
     * and two passwords that stretch to the same digest are the same password, whoever typed them:
     *
     * <ul>
     *   <li>nothing at all, which the factory would happily stretch;</li>
     *   <li>a trailing NUL, which the factory drops: {@code "abc"} and {@code "abc\0"} come out
     *       identical (a leading or interior NUL is fine, those do survive);</li>
     *   <li>an unpaired surrogate, which the factory encodes as a literal {@code ?}: {@code "p"}
     *       plus a lone high surrogate, a lone low surrogate and a plain {@code "p?"} all collide.</li>
     * </ul>
     *
     * <p>Measured against this JDK's {@code PBKDF2WithHmacSHA256}, not assumed.
     */
    public static boolean isUsableCandidate(char[] password) {
        if (password == null || password.length == 0) {
            return false;
        }
        if (password[password.length - 1] == '\0') {
            return false;
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    return false;
                }
                i++; // the low half of the pair just consumed
            } else if (Character.isLowSurrogate(c)) {
                return false; // a low half with no high half in front of it
            }
        }
        return true;
    }

    /** Stretches a password with a new random salt. The caller's array is left untouched. */
    public StoredPassword hash(char[] password) {
        Objects.requireNonNull(password, "password");
        if (!isUsableCandidate(password)) {
            throw new IllegalArgumentException("this password cannot be stored without ambiguity");
        }
        byte[] salt = randomBytes(SALT_BYTES);
        byte[] digest = derive(password, salt, iterations);
        if (digest == null) {
            throw new IllegalStateException(KEY_FACTORY_ALGORITHM + " is unavailable in this JVM");
        }
        return new StoredPassword(PBKDF2_SHA256, iterations, salt, digest);
    }

    /**
     * Re-stretches {@code password} against {@code stored}. Returns {@code false} for a wrong
     * password, for a record this service could not have produced, and for a candidate whose shape
     * {@link #isUsableCandidate} refuses -- a candidate that cannot mean one thing cannot prove
     * anything.
     */
    public boolean verify(char[] password, StoredPassword stored) {
        Objects.requireNonNull(password, "password");
        if (stored == null || !isUsableCandidate(password)) {
            return false;
        }
        byte[] digest = derive(password, stored.salt(), stored.iterations());
        try {
            return digest != null && MessageDigest.isEqual(digest, stored.hash());
        } finally {
            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }

    /**
     * Pays the stretching cost of a real attempt for an attempt that is going to be refused anyway --
     * unknown username, malformed username, a candidate shape that cannot be verified. Without it,
     * "the server gave up before touching the store" is answerable with a stopwatch, and that answer
     * narrows what is worth guessing.
     *
     * <p>The candidate itself is never used as a credential here; it is stretched against a fixed
     * unreachable record and the result is thrown away.
     */
    public void chargeRefusedAttempt(char[] password) {
        Objects.requireNonNull(password, "password");
        derive(password, timingReference.salt(), timingReference.iterations());
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // Fail closed: an unusable key factory or a rejected spec must never look like a match.
            return null;
        } finally {
            spec.clearPassword();
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * A password that has been stored: the algorithm, the stretching cost, the salt and the digest.
     * Text form is {@code pbkdf2-sha256$iterations$base64(salt)$base64(digest)} -- the same shape a
     * {@code users} table column would hold.
     */
    public record StoredPassword(String algorithm, int iterations, byte[] salt, byte[] hash) {

        public StoredPassword {
            salt = Objects.requireNonNull(salt, "salt").clone();
            hash = Objects.requireNonNull(hash, "hash").clone();
            if (!PBKDF2_SHA256.equals(algorithm)) {
                throw new IllegalArgumentException("unsupported password algorithm: " + algorithm);
            }
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations out of range: " + iterations);
            }
            if (salt.length < SALT_BYTES) {
                throw new IllegalArgumentException("salt must be at least " + SALT_BYTES + " bytes");
            }
            if (hash.length != HASH_BYTES) {
                throw new IllegalArgumentException("digest must be " + HASH_BYTES + " bytes");
            }
        }

        public String toStorableString() {
            Base64.Encoder encoder = Base64.getEncoder();
            return algorithm + "$" + iterations + "$" + encoder.encodeToString(salt) + "$"
                    + encoder.encodeToString(hash);
        }

        /**
         * Reads back {@link #toStorableString()}. The decoder is the strict one: a record with a
         * stray character in it is rejected instead of silently decoded into a different salt.
         */
        public static StoredPassword parse(String stored) {
            if (stored == null) {
                throw new IllegalArgumentException("stored password is null");
            }
            String[] parts = stored.split("\\$", -1);
            if (parts.length != 4) {
                throw new IllegalArgumentException("stored password must have 4 fields");
            }
            Base64.Decoder decoder = Base64.getDecoder();
            try {
                return new StoredPassword(parts[0], Integer.parseInt(parts[1]), decoder.decode(parts[2]),
                        decoder.decode(parts[3]));
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("unusable stored password: " + e.getMessage(), e);
            }
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof StoredPassword mine
                    && algorithm.equals(mine.algorithm)
                    && iterations == mine.iterations
                    && MessageDigest.isEqual(salt, mine.salt)
                    && MessageDigest.isEqual(hash, mine.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(algorithm, iterations, Arrays.hashCode(salt), Arrays.hashCode(hash));
        }

        @Override
        public String toString() {
            // Never let a salt or digest leak into a log line through string concatenation.
            return "StoredPassword[" + algorithm + ", " + iterations + " iterations]";
        }
    }
}
