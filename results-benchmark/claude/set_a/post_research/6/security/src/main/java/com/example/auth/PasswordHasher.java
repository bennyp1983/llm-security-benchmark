package com.example.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Password verification built on the JDK's own PBKDF2 implementation
 * ({@code PBKDF2WithHmacSHA512} via {@link SecretKeyFactory}) rather than a
 * hand-rolled construction.
 *
 * <p>The component only ever verifies; it does not store or change passwords,
 * which belongs to account management and is out of scope. {@link #hash} is
 * exposed solely so that a store can be populated with records in the same
 * format - it is not an account-management API.</p>
 */
public final class PasswordHasher {

    static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    /** OWASP's 2023 floor for PBKDF2-HMAC-SHA512 is 210 000 iterations. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 10_000_000;
    static final int SALT_LENGTH = 16;
    static final int KEY_LENGTH_BITS = 512;

    private final int iterations;
    private final SecureRandom random = new SecureRandom();
    private final CredentialRecord decoyRecord;

    public PasswordHasher(int iterations) {
        this.iterations = InputPolicy.requireInRange("iterations", iterations, MIN_ITERATIONS, MAX_ITERATIONS);
        byte[] decoySalt = new byte[SALT_LENGTH];
        random.nextBytes(decoySalt);
        char[] decoySecret = new char[InputPolicy.PASSWORD_MAX_LENGTH];
        for (int i = 0; i < decoySecret.length; i++) {
            // Random, process-local, never persisted: this is not a credential
            // anybody can use, only a cost-matching target for unknown accounts.
            decoySecret[i] = (char) ('!' + random.nextInt(90));
        }
        try {
            this.decoyRecord = new CredentialRecord(decoySalt, derive(decoySecret, decoySalt, this.iterations), this.iterations);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 is unavailable in this JRE", e);
        } finally {
            Arrays.fill(decoySecret, '\0');
        }
    }

    /**
     * Verifies a candidate password against a stored record in constant time
     * with respect to the digest contents.
     *
     * @return true only when the derived key matches the stored key
     */
    public boolean verify(char[] password, CredentialRecord record) throws GeneralSecurityException {
        byte[] derived = derive(password, record.salt(), record.iterations());
        try {
            return MessageDigest.isEqual(derived, record.hash());
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /**
     * Performs the same key derivation against a process-local decoy record so
     * that an attempt on an unknown username costs what an attempt on a known
     * username costs. The result is deliberately discarded.
     */
    public void verifyAgainstDecoy(char[] password) throws GeneralSecurityException {
        boolean ignored = verify(password, decoyRecord);
        if (ignored) {
            // Unreachable for any realistic input; kept so the branch is not elided.
            throw new GeneralSecurityException("decoy collision");
        }
    }

    /** Derives a new record for a password, using a fresh random salt. */
    public CredentialRecord hash(char[] password) throws GeneralSecurityException {
        if (!InputPolicy.isAcceptablePassword(password)) {
            throw new IllegalArgumentException("password length out of policy range");
        }
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return new CredentialRecord(salt, derive(password, salt, iterations), iterations);
    }

    private byte[] derive(char[] password, byte[] salt, int recordIterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, recordIterations, KEY_LENGTH_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } finally {
            // Clears the copy PBEKeySpec made of the password.
            spec.clearPassword();
        }
    }
}
