package com.example.portal.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password hashing and verification built on the JDK's PBKDF2 implementation.
 *
 * <p>PBKDF2-HMAC-SHA256 is used rather than a hand-rolled construction because it ships with the
 * platform, is FIPS-approved, and needs no third-party dependency. Argon2id or scrypt would be
 * preferable on memory-hardness grounds; neither is in the JDK, so adopting one would mean pulling
 * in an external library. If that trade is revisited, see the note in the README.
 *
 * <p>Each password gets a fresh 16-byte random salt from {@link SecureRandom}, so identical
 * passwords produce different stored hashes and a precomputed table is useless. Comparison is
 * length-independent and constant-time via {@link MessageDigest#isEqual}.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SCHEME_ID = "pbkdf2-sha256";

    /**
     * Iteration count for newly enrolled passwords. 600,000 is the OWASP recommendation for
     * PBKDF2-HMAC-SHA256 (Password Storage Cheat Sheet, 2023 revision). Stored hashes carry their
     * own iteration count, so this can be raised without invalidating existing records.
     */
    public static final int DEFAULT_ITERATIONS = 600_000;

    /** Floor on the iteration count accepted from a stored record; see {@link #parse}. */
    static final int MIN_ACCEPTED_ITERATIONS = 100_000;
    /** Ceiling on the iteration count accepted from a stored record; see {@link #parse}. */
    static final int MAX_ACCEPTED_ITERATIONS = 10_000_000;

    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < MIN_ACCEPTED_ITERATIONS) {
            throw new IllegalArgumentException("iteration count below the accepted floor");
        }
        this.iterations = iterations;
    }

    /** Returns the iteration count this instance uses for new hashes and for decoy work. */
    public int iterations() {
        return iterations;
    }

    /**
     * Derives a storable hash string for {@code password}.
     *
     * <p>The returned value has the form {@code pbkdf2-sha256$<iterations>$<salt>$<hash>} with both
     * binary fields Base64-encoded. It contains no secret beyond the hash itself and is safe to
     * store in the credential file.
     *
     * <p>The caller retains ownership of {@code password} and is responsible for clearing it.
     */
    public String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password, salt, iterations);
        try {
            Base64.Encoder encoder = Base64.getEncoder();
            return SCHEME_ID + "$" + iterations + "$" + encoder.encodeToString(salt) + "$"
                    + encoder.encodeToString(derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /**
     * Verifies {@code password} against a parsed stored hash.
     *
     * <p>The caller retains ownership of {@code password} and is responsible for clearing it. The
     * derived key is zeroed before returning so a heap dump taken afterwards does not contain it.
     */
    public boolean verify(char[] password, StoredHash stored) {
        byte[] derived = derive(password, stored.salt(), stored.iterations());
        try {
            return MessageDigest.isEqual(derived, stored.hash());
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /**
     * Runs one derivation whose result is discarded.
     *
     * <p>Called when there is no stored hash to verify against -- an unknown username, a malformed
     * record, or an account under restriction. Without it, "no such account" would return in
     * microseconds while "wrong password" took hundreds of milliseconds, and that difference alone
     * enumerates the employee directory.
     */
    public void performDecoyWork() {
        char[] decoy = new char[24];
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        for (int i = 0; i < decoy.length; i++) {
            decoy[i] = (char) ('a' + random.nextInt(26));
        }
        byte[] derived = derive(decoy, salt, iterations);
        Arrays.fill(derived, (byte) 0);
        Arrays.fill(decoy, '\0');
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // A missing PBKDF2 provider is a broken runtime, not a bad password: fail closed and
            // loudly rather than letting the caller interpret the absence of a result as a pass.
            throw new IllegalStateException("password hashing is unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Parses a stored hash string.
     *
     * <p>The credential file is an input like any other, so every field is validated: the scheme
     * must be the one this class emits, the iteration count must parse and sit inside a sane range,
     * and both binary fields must be correctly sized Base64. An out-of-range iteration count is
     * rejected rather than clamped -- a record claiming one iteration would otherwise turn the KDF
     * off, and a record claiming two billion would be a denial of service against the portal.
     *
     * @throws ValidationException if the encoded form is not well-formed
     */
    public static StoredHash parse(String encoded) throws ValidationException {
        if (encoded == null) {
            throw new ValidationException("stored hash is absent");
        }
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 4) {
            throw new ValidationException("stored hash has the wrong number of fields");
        }
        if (!SCHEME_ID.equals(parts[0].toLowerCase(Locale.ROOT))) {
            throw new ValidationException("stored hash uses an unrecognised scheme");
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new ValidationException("stored hash has a non-numeric iteration count", e);
        }
        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
            throw new ValidationException("stored hash iteration count is out of range");
        }
        byte[] salt = decodeBase64(parts[2], "salt");
        byte[] hash = decodeBase64(parts[3], "hash");
        if (salt.length != SALT_BYTES) {
            throw new ValidationException("stored hash salt has the wrong length");
        }
        if (hash.length != KEY_BITS / 8) {
            throw new ValidationException("stored hash digest has the wrong length");
        }
        return new StoredHash(iterations, salt, hash);
    }

    private static byte[] decodeBase64(String value, String field) throws ValidationException {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new ValidationException("stored hash " + field + " is not valid Base64", e);
        }
    }

    /** A validated stored hash: the parameters needed to re-derive and compare. */
    public record StoredHash(int iterations, byte[] salt, byte[] hash) {

        public StoredHash(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.salt = salt.clone();
            this.hash = hash.clone();
        }

        @Override
        public byte[] salt() {
            return salt.clone();
        }

        @Override
        public byte[] hash() {
            return hash.clone();
        }

        /** Never renders the digest; a stored hash is still sensitive material. */
        @Override
        public String toString() {
            return "StoredHash[iterations=" + iterations + ", salt=<redacted>, hash=<redacted>]";
        }
    }
}
