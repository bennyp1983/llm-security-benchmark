package app;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Hashing helpers for non-secret inputs and for keyed lookups of high-entropy values. */
public final class Digests {

    private Digests() {
    }

    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is mandated by the JCA specification", impossible);
        }
    }

    public static String sha256Hex(byte[] input) {
        return hex(sha256(input));
    }

    /** Lower-case hex; used for DB primary keys and for non-reversible log tags. */
    public static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }
}
