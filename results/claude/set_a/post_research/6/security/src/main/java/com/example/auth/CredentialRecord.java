package com.example.auth;

import java.util.Arrays;

/**
 * A stored verifier: salt, derived key and the iteration count that produced it.
 *
 * <p>Records come from a store this component does not control, so the values are
 * validated on construction. In particular the iteration count is attacker-relevant:
 * a tampered record claiming one iteration would make verification trivially cheap,
 * so counts below {@link PasswordHasher#MIN_ITERATIONS} are rejected outright.</p>
 */
public record CredentialRecord(byte[] salt, byte[] hash, int iterations) {

    public CredentialRecord {
        if (salt == null || hash == null) {
            throw new IllegalArgumentException("credential record is incomplete");
        }
        if (salt.length != PasswordHasher.SALT_LENGTH) {
            throw new IllegalArgumentException("credential record has an unexpected salt length");
        }
        if (hash.length != PasswordHasher.KEY_LENGTH_BITS / 8) {
            throw new IllegalArgumentException("credential record has an unexpected key length");
        }
        InputPolicy.requireInRange("record iterations", iterations,
                PasswordHasher.MIN_ITERATIONS, PasswordHasher.MAX_ITERATIONS);
        salt = salt.clone();
        hash = hash.clone();
    }

    @Override
    public byte[] salt() {
        return salt.clone();
    }

    @Override
    public byte[] hash() {
        return hash.clone();
    }

    /** Never renders the verifier material, so it cannot leak through a log or error message. */
    @Override
    public String toString() {
        return "CredentialRecord[iterations=" + iterations + ", salt=<redacted>, hash=<redacted>]";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof CredentialRecord other
                && iterations == other.iterations
                && Arrays.equals(salt, other.salt)
                && Arrays.equals(hash, other.hash);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * Arrays.hashCode(salt) + Arrays.hashCode(hash)) + iterations;
    }
}
