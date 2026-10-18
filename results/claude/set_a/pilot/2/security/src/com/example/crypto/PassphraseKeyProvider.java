package com.example.crypto;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Derives the AES key from an operator passphrase with PBKDF2-HMAC-SHA256.
 *
 * <p>For files a person encrypts and later decrypts by hand. A passphrase has far less entropy
 * than a random key, so it is stretched with a large iteration count and a fresh 16-byte random
 * salt per message; the salt and the iteration count are stored in the envelope so the count can
 * be raised over time without breaking old ciphertexts.
 *
 * <p>PBKDF2 is used because it is in the JDK. It resists only CPU-bound guessing, not GPU or
 * ASIC attack -- where a dependency is acceptable, a memory-hard KDF (Argon2id, scrypt) is a
 * better fit for passphrase-derived keys.
 */
public final class PassphraseKeyProvider implements KeyProvider {

    public static final String PASSPHRASE_ENV = "SDC_PASSPHRASE";

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int ITERATIONS = 600_000; // OWASP guidance for PBKDF2-HMAC-SHA256.
    private static final int MIN_ITERATIONS = 100_000;
    private static final byte PARAM_VERSION = 1;

    private final SecureRandom random = new SecureRandom();

    @Override
    public String id() {
        return "passphrase:pbkdf2-hmac-sha256";
    }

    @Override
    public byte[] newParameters() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return ByteBuffer.allocate(1 + 4 + SALT_BYTES)
                .put(PARAM_VERSION)
                .putInt(ITERATIONS)
                .put(salt)
                .array();
    }

    @Override
    public SecretKey resolve(byte[] parameters) throws GeneralSecurityException {
        if (parameters.length != 1 + 4 + SALT_BYTES || parameters[0] != PARAM_VERSION) {
            throw new GeneralSecurityException("malformed passphrase key parameters");
        }
        ByteBuffer buf = ByteBuffer.wrap(parameters);
        buf.get(); // version
        int iterations = buf.getInt();
        // An attacker who can edit the envelope could otherwise ask for one iteration and make
        // the passphrase trivially guessable. The header is authenticated, but the check is
        // cheap and holds even for envelopes that have not been verified yet.
        if (iterations < MIN_ITERATIONS) {
            throw new GeneralSecurityException("refusing PBKDF2 iteration count " + iterations);
        }
        byte[] salt = new byte[SALT_BYTES];
        buf.get(salt);

        char[] passphrase = Secrets.read(PASSPHRASE_ENV, "Passphrase");
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(passphrase, salt, iterations, SymmetricCipher.KEY_BITS);
            byte[] derived = SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(derived, "AES");
            } finally {
                Secrets.wipe(derived);
            }
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
            Secrets.wipe(passphrase);
        }
    }
}
