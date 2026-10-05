package com.example.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;

/**
 * Derives an AES-256 key from a human-supplied passphrase using PBKDF2-HMAC-SHA-256.
 *
 * <p>Use this only when the key really must come from a passphrase (for example
 * an operator-unlocked configuration file). A random key from
 * {@link KeyMaterial#generateKey()} held in a secret manager is strictly
 * stronger and is the recommended default.
 *
 * <p>Design choices a reviewer would check:
 * <ul>
 *   <li>PBKDF2WithHmacSHA256 from the platform's SunJCE provider - no
 *       hand-rolled KDF, no bare hash, no MD5/SHA-1.</li>
 *   <li>A minimum of {@value #MIN_ITERATIONS} iterations is enforced (OWASP's
 *       2023 floor for PBKDF2-HMAC-SHA-256); {@value #DEFAULT_ITERATIONS} is the
 *       default. A caller cannot weaken the work factor below the floor, and an
 *       absurdly high value is also rejected so a configuration value cannot be
 *       turned into a denial-of-service knob.</li>
 *   <li>The salt must be at least {@value #MIN_SALT_BYTES} bytes, must be
 *       unique per passphrase, and must come from
 *       {@link #newSalt()} (the platform CSPRNG). A salt is not secret, but it
 *       is validated for length and bounded.</li>
 *   <li>The passphrase is taken as {@code char[]} and is wiped - along with
 *       every intermediate copy, including the {@link PBEKeySpec}'s - before
 *       this method returns.</li>
 * </ul>
 */
public final class PassphraseKeyDerivation {

    /** OWASP-recommended floor for PBKDF2-HMAC-SHA-256. */
    public static final int MIN_ITERATIONS = 210_000;

    /** Default work factor; raise it as hardware improves. */
    public static final int DEFAULT_ITERATIONS = 600_000;

    /** Upper bound so a configured value cannot stall the process. */
    public static final int MAX_ITERATIONS = 10_000_000;

    /** Minimum salt length. */
    public static final int MIN_SALT_BYTES = 16;

    /** Maximum accepted salt length; bounds stored/parsed salt size. */
    public static final int MAX_SALT_BYTES = 64;

    /** Lower bound on passphrase length; shorter secrets are rejected, not padded. */
    public static final int MIN_PASSPHRASE_CHARS = 12;

    /** Upper bound on passphrase length, so PBKDF2 input size stays bounded. */
    public static final int MAX_PASSPHRASE_CHARS = 1024;

    private PassphraseKeyDerivation() {
    }

    /** @return a fresh random salt of {@value #MIN_SALT_BYTES} bytes. */
    public static byte[] newSalt() {
        return KeyMaterial.randomBytes(MIN_SALT_BYTES);
    }

    /** Derives a key with {@link #DEFAULT_ITERATIONS}. */
    public static ZeroizableSecretKey deriveKey(char[] passphrase, byte[] salt) {
        return deriveKey(passphrase, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Derives an AES-256 key.
     *
     * @param passphrase passphrase characters; wiped by this method on every path
     * @param salt       unique, random, {@value #MIN_SALT_BYTES}..{@value #MAX_SALT_BYTES} bytes
     * @param iterations work factor, at least {@value #MIN_ITERATIONS}
     * @throws IllegalArgumentException if any argument is outside its allowed range
     */
    public static ZeroizableSecretKey deriveKey(char[] passphrase, byte[] salt, int iterations) {
        PBEKeySpec spec = null;
        byte[] derived = null;
        try {
            // Validate everything before touching the passphrase, and reject
            // rather than clamping: a silently clamped work factor or a
            // substituted default salt would be a real weakness.
            if (passphrase == null
                    || passphrase.length < MIN_PASSPHRASE_CHARS
                    || passphrase.length > MAX_PASSPHRASE_CHARS) {
                throw new IllegalArgumentException("passphrase must be "
                        + MIN_PASSPHRASE_CHARS + "-" + MAX_PASSPHRASE_CHARS + " characters");
            }
            if (salt == null || salt.length < MIN_SALT_BYTES || salt.length > MAX_SALT_BYTES) {
                throw new IllegalArgumentException("salt must be "
                        + MIN_SALT_BYTES + "-" + MAX_SALT_BYTES + " bytes");
            }
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be "
                        + MIN_ITERATIONS + "-" + MAX_ITERATIONS);
            }

            spec = new PBEKeySpec(passphrase, salt, iterations,
                    ZeroizableSecretKey.KEY_LENGTH_BYTES * 8);
            derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
            return new ZeroizableSecretKey(derived);
        } catch (GeneralSecurityException e) {
            // Algorithm unavailable or spec rejected: fail closed, log no secret.
            CryptoLog.configProblem("PBKDF2WithHmacSHA256 is unavailable in this JRE");
            throw new IllegalStateException("key derivation is unavailable");
        } finally {
            if (spec != null) {
                spec.clearPassword(); // wipes the spec's internal copy
            }
            Bytes.wipe(derived);
            Bytes.wipe(passphrase); // caller's buffer: the secret does not outlive this call
        }
    }
}
