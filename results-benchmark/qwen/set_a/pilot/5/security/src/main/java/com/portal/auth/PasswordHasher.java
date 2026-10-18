package com.portal.auth;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Computes and checks salted PBKDF2-HMAC-SHA256 password digests.
 *
 * <p>Plaintext passwords are only ever accepted as {@code char[]} so callers can wipe them; this
 * class never retains a copy and never writes one into the encoded form.
 */
public final class PasswordHasher {

    static final String PREFIX = "$pbkdf2-sha256$";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    /** OWASP 2023 guidance for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 600_000;

    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    /** Seed for {@link #dummyDigest}; no account is ever issued this password. */
    private static final String UNKNOWN_USER_PLACEHOLDER = "com.portal.auth.unknown-user-placeholder";

    /*
     * Bounds accepted from a stored digest. A record claiming an absurd iteration count would turn
     * every login into a denial of service, so out-of-range values are refused rather than honoured.
     */
    private static final int MIN_ITERATIONS = 1_000;
    private static final int MAX_ITERATIONS = 5_000_000;

    private final int iterations;
    private final SecureRandom random = new SecureRandom();

    /** Encoded digest of a password nobody owns, used to equalise timing for unknown usernames. */
    private final String dummyDigest;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException(
                    "iterations must be between " + MIN_ITERATIONS + " and " + MAX_ITERATIONS);
        }
        this.iterations = iterations;
        /* A fixed all-zero salt makes this digest deterministic, which is what we want: the same
           work must be burned on every unknown username. */
        byte[] fixedSalt = new byte[SALT_BYTES];
        this.dummyDigest = encode(deriveOrThrow(UNKNOWN_USER_PLACEHOLDER.toCharArray(), fixedSalt, iterations),
                fixedSalt, iterations);
    }

    /** @return encoded digest in the form {@code $pbkdf2-sha256$<iterations>$<salt>$<hash>}. */
    public String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return encode(deriveOrThrow(password, salt, iterations), salt, iterations);
    }

    /**
     * Checks {@code password} against an encoded digest.
     *
     * @return {@code false} for a mismatch and equally for a malformed digest; never throws, so a
     *     corrupt record cannot be told apart from a wrong password by a caller.
     */
    public boolean verify(char[] password, String encoded) {
        try {
            Parsed parsed = parse(encoded);
            if (parsed == null) {
                return false;
            }
            byte[] computed = derive(password, parsed.salt(), parsed.iterations());
            /*
             * MessageDigest.isEqual walks the whole array instead of exiting at the first differing
             * byte, so the comparison time does not depend on how much of the digest matched.
             */
            return MessageDigest.isEqual(computed, parsed.hash());
        } catch (RuntimeException | GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Spends the same work as a real verification on a username that does not exist. Without this,
     * an unauthenticated caller could time responses to enumerate which employee accounts are real.
     */
    public void burnEquivalentWork(char[] password) {
        verify(password, dummyDigest);
    }

    private static String encode(byte[] digest, byte[] salt, int iters) {
        Base64.Encoder encoder = Base64.getEncoder();
        return PREFIX + iters + "$" + encoder.encodeToString(salt) + "$" + encoder.encodeToString(digest);
    }

    private static byte[] deriveOrThrow(char[] password, byte[] salt, int iters) {
        try {
            return derive(password, salt, iters);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("password hashing unavailable", e);
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iters) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iters, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static Parsed parse(String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            return null;
        }
        String[] parts = encoded.substring(PREFIX.length()).split("\\$");
        if (parts.length != 3) {
            return null;
        }
        int iters;
        try {
            iters = Integer.parseInt(parts[0]);
        } catch (NumberFormatException e) {
            return null;
        }
        if (iters < MIN_ITERATIONS || iters > MAX_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] hash;
        try {
            salt = Base64.getDecoder().decode(parts[1]);
            hash = Base64.getDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (salt.length < 8 || hash.length < 16) {
            return null;
        }
        return new Parsed(iters, salt, hash);
    }

    /**
     * Copies a String password into a wipeable {@code char[]}. Prefer passing {@code char[]} from
     * its source (for example {@code Console.readPassword()}); this exists for boundaries that have
     * already handed us a String.
     */
    public static char[] toChars(String password) {
        if (password == null) {
            return new char[0];
        }
        char[] copy = new char[password.length()];
        password.getChars(0, password.length(), copy, 0);
        return copy;
    }

    /** Overwrites the array so the secret does not linger on the heap awaiting garbage collection. */
    public static void wipe(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }

    private record Parsed(int iterations, byte[] salt, byte[] hash) {}
}
