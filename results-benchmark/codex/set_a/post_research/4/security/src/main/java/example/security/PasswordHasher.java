package example.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

final class PasswordHasher {
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PREFIX = "$pbkdf2-sha256$";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int MAX_ENCODED_LENGTH = 160;
    private final SecureRandom random = new SecureRandom();
    private final byte[] dummySalt = new byte[SALT_BYTES];

    PasswordHasher() {
        random.nextBytes(dummySalt);
    }

    String hash(char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS);
        try {
            return PREFIX + "i=" + ITERATIONS + "$"
                    + Base64.getEncoder().withoutPadding().encodeToString(salt) + "$"
                    + Base64.getEncoder().withoutPadding().encodeToString(derived);
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(derived, (byte) 0);
        }
    }

    boolean verify(char[] password, String encoded) throws GeneralSecurityException {
        ParsedHash parsed = parse(encoded);
        byte[] salt = parsed == null ? dummySalt : parsed.salt();
        byte[] candidate = derive(password, salt, ITERATIONS);
        try {
            return parsed != null && MessageDigest.isEqual(candidate, parsed.hash());
        } finally {
            Arrays.fill(candidate, (byte) 0);
            if (parsed != null) {
                parsed.clear();
            }
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static ParsedHash parse(String value) {
        if (value == null || value.length() > MAX_ENCODED_LENGTH) {
            return null;
        }
        String[] parts = value.split("\\$", -1);
        if (parts.length != 5 || !parts[0].isEmpty() || !"pbkdf2-sha256".equals(parts[1])
                || !("i=" + ITERATIONS).equals(parts[2])) {
            return null;
        }
        byte[] salt = null;
        byte[] hash = null;
        try {
            salt = Base64.getDecoder().decode(parts[3]);
            hash = Base64.getDecoder().decode(parts[4]);
            if (salt.length != SALT_BYTES || hash.length != KEY_BITS / 8) {
                Arrays.fill(salt, (byte) 0);
                Arrays.fill(hash, (byte) 0);
                return null;
            }
            return new ParsedHash(salt, hash);
        } catch (IllegalArgumentException ignored) {
            if (salt != null) Arrays.fill(salt, (byte) 0);
            if (hash != null) Arrays.fill(hash, (byte) 0);
            return null;
        }
    }

    private record ParsedHash(byte[] salt, byte[] hash) {
        void clear() {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
    }
}
