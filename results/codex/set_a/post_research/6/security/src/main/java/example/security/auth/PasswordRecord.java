package example.security.auth;

import java.util.Arrays;
import java.util.Objects;

/** A validated password verifier loaded from trusted server-side account storage. */
public final class PasswordRecord {
    public static final int SALT_BYTES = 16;
    public static final int HASH_BYTES = 32;
    public static final int MIN_ITERATIONS = 600_000;
    public static final int MAX_ITERATIONS = 2_000_000;

    private final byte[] salt;
    private final byte[] hash;
    private final int iterations;

    public PasswordRecord(byte[] salt, byte[] hash, int iterations) {
        Objects.requireNonNull(salt, "salt");
        Objects.requireNonNull(hash, "hash");
        if (salt.length != SALT_BYTES || hash.length != HASH_BYTES) {
            throw new IllegalArgumentException("Invalid stored credential format");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("Invalid stored credential work factor");
        }
        this.salt = salt.clone();
        this.hash = hash.clone();
        this.iterations = iterations;
    }

    byte[] salt() { return salt.clone(); }
    byte[] hash() { return hash.clone(); }
    int iterations() { return iterations; }

    @Override public boolean equals(Object other) {
        if (!(other instanceof PasswordRecord that)) return false;
        return iterations == that.iterations
                && Arrays.equals(salt, that.salt)
                && Arrays.equals(hash, that.hash);
    }

    @Override public int hashCode() {
        return 31 * (31 * iterations + Arrays.hashCode(salt)) + Arrays.hashCode(hash);
    }

    /** Deliberately does not expose credential material. */
    @Override public String toString() { return "PasswordRecord[REDACTED]"; }
}
