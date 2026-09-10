package accounts;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * One stored account: identity plus the parameters needed to re-derive and check its
 * password hash. The plaintext password is never part of this object.
 *
 * <p>On disk a record is a single line:
 * <pre>
 * v1:base64(username):algorithm:iterations:base64(salt):base64(hash)
 * </pre>
 *
 * <p>The username is base64 encoded rather than written verbatim because a record is
 * line-oriented: a raw newline inside a username would let one record masquerade as
 * two. Base64 output never contains ':', so the field split is unambiguous.
 */
final class CredentialRecord {

    static final String FILE_VERSION = "v1";

    /**
     * Cost bounds for a stored record. The lower bound is the line no deployment should
     * sit below today; the upper bound stops a crafted store file from turning every
     * login attempt into a minutes-long derivation (a denial-of-service on one's own
     * authentication endpoint).
     */
    static final int ITERATIONS_MIN = 100_000;
    static final int ITERATIONS_MAX = 5_000_000;

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final String username;
    private final String algorithm;
    private final int iterations;
    private final byte[] salt;
    private final byte[] hash;

    CredentialRecord(String username, String algorithm, int iterations, byte[] salt, byte[] hash) {
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("username is required");
        }
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("algorithm is required");
        }
        if (iterations < ITERATIONS_MIN || iterations > ITERATIONS_MAX) {
            throw new IllegalArgumentException("iterations out of range: " + iterations);
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("salt is required");
        }
        if (hash == null || hash.length == 0) {
            throw new IllegalArgumentException("hash is required");
        }
        this.username = username;
        this.algorithm = algorithm;
        this.iterations = iterations;
        this.salt = salt.clone();
        this.hash = hash.clone();
    }

    String username() {
        return username;
    }

    String algorithm() {
        return algorithm;
    }

    int iterations() {
        return iterations;
    }

    byte[] salt() {
        return salt.clone();
    }

    byte[] hash() {
        return hash.clone();
    }

    String encode() {
        return FILE_VERSION
                + ':' + ENCODER.encodeToString(username.getBytes(StandardCharsets.UTF_8))
                + ':' + algorithm
                + ':' + iterations
                + ':' + ENCODER.encodeToString(salt)
                + ':' + ENCODER.encodeToString(hash);
    }

    /** @throws IllegalArgumentException if {@code line} is not a well-formed record */
    static CredentialRecord decode(String line) {
        if (line == null) {
            throw new IllegalArgumentException("record is missing");
        }
        String[] fields = line.split(":", -1);
        if (fields.length != 6) {
            throw new IllegalArgumentException("expected 6 fields, found " + fields.length);
        }
        if (!FILE_VERSION.equals(fields[0])) {
            throw new IllegalArgumentException("unsupported record version: " + fields[0]);
        }
        String username = new String(decodeBase64(fields[1], "username"), StandardCharsets.UTF_8);
        int iterations;
        try {
            iterations = Integer.parseInt(fields[3]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("iterations is not a number: " + fields[3]);
        }
        return new CredentialRecord(username, fields[2], iterations,
                decodeBase64(fields[4], "salt"), decodeBase64(fields[5], "hash"));
    }

    private static byte[] decodeBase64(String value, String what) {
        if (value.isEmpty()) {
            throw new IllegalArgumentException(what + " is empty");
        }
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(what + " is not base64: " + e.getMessage());
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CredentialRecord)) {
            return false;
        }
        CredentialRecord that = (CredentialRecord) other;
        return iterations == that.iterations
                && username.equals(that.username)
                && algorithm.equals(that.algorithm)
                && Arrays.equals(salt, that.salt)
                && Arrays.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, algorithm, iterations, Arrays.hashCode(salt), Arrays.hashCode(hash));
    }

    /** Deliberately omits salt and hash so a record cannot leak through a log line. */
    @Override
    public String toString() {
        return "CredentialRecord[username=" + username + ", algorithm=" + algorithm
                + ", iterations=" + iterations + "]";
    }
}
