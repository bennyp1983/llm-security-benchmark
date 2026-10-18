package portal.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A stored password: a random salt plus a PBKDF2-SHA256 digest of the password.
 *
 * <p>The plain password is never kept. One instance is the immutable text
 * {@code pbkdf2-sha256$<iterations>$<salt>$<digest>}, which is what a records store persists, so
 * the same password produces a different text for every employee.
 *
 * <p>Verification always recomputes the digest and compares it in constant time
 * ({@link MessageDigest#isEqual(byte[], byte[])}); there is no code path that compares passwords
 * as text.
 *
 * <p>Run this class with the password on standard input to produce a line for a records file.
 */
public final class PasswordHash {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final String TAG = "pbkdf2-sha256";

    /** Cost used for new records. */
    public static final int DEFAULT_ITERATIONS = 100_000;
    /** Lower bound accepted when creating a hash (tests use the low end to stay quick). */
    public static final int MIN_CREATED_ITERATIONS = 1_000;
    /** A stored hash weaker than this is refused rather than honoured. */
    public static final int MIN_STORED_ITERATIONS = 50_000;
    /** Upper bound so that a hostile records file cannot stall the portal. */
    public static final int MAX_ITERATIONS = 50_000_000;

    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final String encoded;
    private final int iterations;
    private final byte[] salt;
    private final byte[] digest;

    private PasswordHash(int iterations, byte[] salt, byte[] digest) {
        this.iterations = iterations;
        this.salt = salt;
        this.digest = digest;
        this.encoded = TAG + "$" + iterations + "$" + ENCODER.encodeToString(salt) + "$"
                + ENCODER.encodeToString(digest);
    }

    /** Creates a hash with the default cost and a fresh random salt. */
    public static PasswordHash create(char[] password, SecureRandom random) {
        return create(password, random, DEFAULT_ITERATIONS);
    }

    /**
     * Creates a hash of {@code password}.
     *
     * @throws IllegalArgumentException if the password, the salt or the iteration count is unusable
     */
    public static PasswordHash create(char[] password, SecureRandom random, int iterations) {
        Objects.requireNonNull(random, "random");
        CredentialValidator.validatePassword(password);
        checkIterations(iterations, MIN_CREATED_ITERATIONS, "iteration count");
        byte[] salt = new byte[SALT_BYTES];
        return new PasswordHash(iterations, salt, derive(password, salt, iterations));
    }

    /**
     * Reads back {@link #encode()}.
     *
     * @throws IllegalArgumentException if the text is malformed, names another algorithm, carries
     *     wrong-length salt or digest bytes, or is weaker than {@link #MIN_STORED_ITERATIONS}
     */
    public static PasswordHash parse(String stored) {
        return parse(stored, MIN_STORED_ITERATIONS);
    }

    /** As {@link #parse(String)} with an explicit lower bound on the stored cost. */
    public static PasswordHash parse(String stored, int minStoredIterations) {
        if (stored == null) {
            throw new IllegalArgumentException("stored password is missing");
        }
        String[] parts = stored.split("\\$", -1);
        if (parts.length != 4 || !TAG.equals(parts[0])) {
            throw new IllegalArgumentException("stored password is not a " + TAG + " value");
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("stored password has no usable cost", e);
        }
        checkIterations(iterations, minStoredIterations, "stored iteration count");
        // The strict decoder still accepts unpadded text, so the decoded length is the check.
        byte[] salt = requireLength(decode(parts[2], "salt"), SALT_BYTES, "salt");
        byte[] digest = requireLength(decode(parts[3], "digest"), digestBytes(), "digest");
        return new PasswordHash(iterations, salt, digest);
    }

    /**
     * Recomputes the digest of {@code password} and compares it with this one.
     *
     * @return true only when {@code password} hashes to the stored digest; a password that cannot
     *     be hashed, or a failure inside the provider, yields false
     */
    public boolean matches(char[] password) {
        try {
            CredentialValidator.validatePassword(password);
            return MessageDigest.isEqual(digest, derive(password, salt, iterations));
        } catch (IllegalArgumentException unusablePassword) {
            return false;
        }
    }

    /** The text to persist in the records store. */
    public String encode() {
        return encoded;
    }

    public int iterations() {
        return iterations;
    }

    /** Never the digest or the salt, so that a stray log line stays harmless. */
    @Override
    public String toString() {
        return TAG + "$" + iterations + "$<redacted>";
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PasswordHash && encoded.equals(((PasswordHash) other).encoded);
    }

    @Override
    public int hashCode() {
        return encoded.hashCode();
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot compute " + ALGORITHM + " on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] decode(String text, String what) {
        try {
            return DECODER.decode(text);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("stored password " + what + " is not valid", e);
        }
    }

    private static byte[] requireLength(byte[] bytes, int expected, String what) {
        if (bytes.length != expected) {
            throw new IllegalArgumentException(
                    "stored password " + what + " must be " + expected + " bytes");
        }
        return bytes;
    }

    private static void checkIterations(int iterations, int minimum, String label) {
        if (iterations < minimum || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException(
                    label + " must be between " + minimum + " and " + MAX_ITERATIONS);
        }
    }

    private static int digestBytes() {
        return KEY_BITS / 8;
    }

    /**
     * Prints one records-store line for a password read from standard input, so that a real
     * password never appears in a shell history or a process list.
     */
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: echo '<password>' | java portal.auth.PasswordHash <username>");
            System.exit(2);
            return;
        }
        String line = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))
                .readLine();
        char[] password = line == null ? new char[0] : line.toCharArray();
        try {
            // Middle field is the display name, left for whoever edits the file.
            System.out.println(CredentialValidator.canonicalUsername(args[0]) + "\t\t"
                    + create(password, new SecureRandom()).encode());
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
