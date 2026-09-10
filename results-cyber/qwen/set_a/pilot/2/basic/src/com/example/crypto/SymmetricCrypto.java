package com.example.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Authenticated symmetric encryption of application secrets with AES-256-GCM.
 *
 * <p>An {@code encrypt} call produces a self-describing <em>envelope</em>:
 *
 * <pre>
 *   "AESG" | version(1) | keySource(1) | [salt(16) | iterations(4)] | iv(12) | ciphertext+GCM tag
 * </pre>
 *
 * The bracketed section is present only for password-derived keys. The header is fed to GCM as
 * additional authenticated data, so rewriting any header byte (iv, salt, iteration count) breaks
 * the tag just like rewriting the ciphertext would.
 *
 * <p>Keys: either a raw 256-bit AES key ({@link KeySource#of(SecretKey)}) or a passphrase stretched
 * with PBKDF2-HmacSHA256 ({@link KeySource#of(char[])}). A fresh random IV is drawn per call, so a
 * key must never be paired with a hand-rolled or reused IV — this class makes reuse impossible by
 * construction.
 *
 * <p>Instances are thread safe; the underlying {@link SecureRandom} is.
 */
public final class SymmetricCrypto {

    /** AES key length enforced for both raw keys and PBKDF2 output. */
    public static final int AES_KEY_BITS = 256;

    /** OWASP 2023+ recommendation for PBKDF2-HmacSHA256. */
    public static final int DEFAULT_PBKDF2_ITERATIONS = 310_000;

    /** Rejected outright: below this a passphrase is effectively unsalted-fast-hash territory. */
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;

    /** Ceiling for the iteration count read back from an untrusted envelope (DoS guard). */
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String KEY_ALGORITHM = "AES";
    private static final byte[] MAGIC = {'A', 'E', 'S', 'G'};
    private static final byte VERSION = 1;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int SALT_BYTES = 16;
    private static final int SOURCE_RAW_KEY = 0;
    private static final int SOURCE_PASSWORD = 1;
    private static final int AES_KEY_BYTES = AES_KEY_BITS / 8;

    private final SecureRandom random;

    public SymmetricCrypto() {
        this(new SecureRandom());
    }

    public SymmetricCrypto(SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    /** Generates a fresh 256-bit AES key from the platform {@link SecureRandom}. */
    public static SecretKey newKey() throws CryptoException {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
            generator.init(AES_KEY_BITS, new SecureRandom());
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-256 key generation is unavailable on this JVM", e);
        }
    }

    /** Wraps 32 raw key bytes (e.g. decoded from a key file) as an AES {@link SecretKey}. */
    public static SecretKey keyFromBytes(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length != AES_KEY_BYTES) {
            throw new IllegalArgumentException("expected a " + AES_KEY_BITS + "-bit key, got "
                    + (encoded.length * 8) + " bits");
        }
        return new SecretKeySpec(encoded.clone(), KEY_ALGORITHM);
    }

    /**
     * Encrypts {@code plaintext} and returns the raw envelope. A new IV and (for passwords) a new
     * salt are drawn on every call, so encrypting the same data twice yields different output.
     *
     * @param aad optional context string bound into the tag; the identical value is mandatory for
     *            decryption. Typical use is a record id or config-key name.
     */
    public byte[] encrypt(KeySource source, byte[] plaintext, byte[] aad) throws CryptoException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(plaintext, "plaintext");
        try {
            byte[] salt = source.salt(random);
            int iterations = source.iterations();
            byte[] iv = randomBytes(random, IV_BYTES);
            SecretKey key = source.derive(salt, iterations);
            byte[] header = header(source.id(), salt, iterations, iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv), random);
            cipher.updateAAD(header);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] body = cipher.doFinal(plaintext);

            byte[] envelope = new byte[header.length + body.length];
            System.arraycopy(header, 0, envelope, 0, header.length);
            System.arraycopy(body, 0, envelope, header.length, body.length);
            return envelope;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies and decrypts an envelope.
     *
     * @throws CryptoException with {@link CryptoException#isAuthenticationFailure()} set when the
     *         key, the AAD, or the bytes do not all agree — a caller cannot tell which one was wrong,
     *         which is the intended behaviour of an AEAD.
     */
    public byte[] decrypt(KeySource source, byte[] envelope, byte[] aad) throws CryptoException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(envelope, "envelope");

        int minimum = MAGIC.length + 2 + IV_BYTES + TAG_BITS / 8;
        if (envelope.length < minimum) {
            throw new CryptoException("envelope is truncated (" + envelope.length
                    + " bytes, need at least " + minimum + ")");
        }
        if (!Arrays.equals(MAGIC, Arrays.copyOf(envelope, MAGIC.length))) {
            throw new CryptoException("not an AES-GCM envelope: magic header mismatch");
        }

        int position = MAGIC.length;
        byte version = envelope[position++];
        if (version != VERSION) {
            throw new CryptoException("unsupported envelope version " + version);
        }
        int sourceId = envelope[position++] & 0xff;
        if (sourceId != SOURCE_RAW_KEY && sourceId != SOURCE_PASSWORD) {
            throw new CryptoException("unknown key source id " + sourceId);
        }
        if (sourceId != source.id()) {
            throw new CryptoException("envelope was sealed with a " + describe(sourceId)
                    + " key but a " + describe(source.id()) + " key was supplied");
        }

        byte[] salt = new byte[0];
        int iterations = 0;
        if (sourceId == SOURCE_PASSWORD) {
            if (envelope.length < position + SALT_BYTES + Integer.BYTES + IV_BYTES + TAG_BITS / 8) {
                throw new CryptoException("envelope is truncated inside the KDF parameters");
            }
            salt = Arrays.copyOfRange(envelope, position, position + SALT_BYTES);
            position += SALT_BYTES;
            iterations = ByteBuffer.wrap(envelope, position, Integer.BYTES).getInt();
            position += Integer.BYTES;
            if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
                throw new CryptoException("implausible PBKDF2 iteration count in envelope: " + iterations);
            }
        }
        if (envelope.length < position + IV_BYTES + TAG_BITS / 8) {
            throw new CryptoException("envelope is truncated inside the IV");
        }
        byte[] iv = Arrays.copyOfRange(envelope, position, position + IV_BYTES);
        int headerLength = position + IV_BYTES;
        byte[] header = Arrays.copyOf(envelope, headerLength);
        byte[] body = Arrays.copyOfRange(envelope, headerLength, envelope.length);

        try {
            SecretKey key = source.derive(salt, iterations);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(header);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(body);
        } catch (AEADBadTagException e) {
            throw new CryptoException("authentication failed: wrong key, wrong context, or the data "
                    + "was tampered with", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("decryption failed: " + e.getMessage(), e);
        }
    }

    /** {@link #encrypt(KeySource, byte[], byte[])} with the plaintext UTF-8 encoded. */
    public byte[] encrypt(KeySource source, String plaintext, String aad) throws CryptoException {
        return encrypt(source, plaintext.getBytes(StandardCharsets.UTF_8),
                aad == null ? null : aad.getBytes(StandardCharsets.UTF_8));
    }

    /** {@link #decrypt(KeySource, byte[], byte[])} with the result UTF-8 decoded. */
    public String decryptText(KeySource source, byte[] envelope, String aad) throws CryptoException {
        return new String(decrypt(source, envelope, aad == null ? null : aad.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
    }

    /** Encrypts text and returns a base64 token safe for config files, env vars, or JSON. */
    public String encryptToBase64(KeySource source, String plaintext, String aad) throws CryptoException {
        return Base64.getEncoder().encodeToString(encrypt(source, plaintext, aad));
    }

    /** Decrypts a base64 token produced by {@link #encryptToBase64}. */
    public String decryptBase64(KeySource source, String token, String aad) throws CryptoException {
        return decryptText(source, decodeBase64(token), aad);
    }

    /** Decrypts a base64 token into raw bytes (binary payloads). */
    public byte[] decryptBase64Bytes(KeySource source, String token, byte[] aad) throws CryptoException {
        return decrypt(source, decodeBase64(token), aad);
    }

    /** Clears a passphrase that is no longer needed; {@code char[]} beats {@code String} for secrets. */
    public static void wipe(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }

    private static byte[] decodeBase64(String token) throws CryptoException {
        Objects.requireNonNull(token, "token");
        try {
            // MIME decoder tolerates the line wrapping a terminal or editor may have introduced.
            return Base64.getMimeDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("input is not valid base64", e);
        }
    }

    private static byte[] header(int sourceId, byte[] salt, int iterations, byte[] iv) {
        int length = MAGIC.length + 2 + iv.length
                + (sourceId == SOURCE_PASSWORD ? salt.length + Integer.BYTES : 0);
        ByteBuffer buffer = ByteBuffer.allocate(length);
        buffer.put(MAGIC).put(VERSION).put((byte) sourceId);
        if (sourceId == SOURCE_PASSWORD) {
            buffer.put(salt).putInt(iterations);
        }
        buffer.put(iv);
        return buffer.array();
    }

    private static String describe(int sourceId) {
        return sourceId == SOURCE_PASSWORD ? "passphrase" : "raw AES key";
    }

    private static byte[] randomBytes(SecureRandom random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /** Where the AES key comes from. Obtain one via the {@code of} factories. */
    public abstract static class KeySource {

        /** Seals a 256-bit AES key; recommended for machine-held secrets. */
        public static KeySource of(SecretKey key) {
            return new RawKey(key);
        }

        /** Stretches a passphrase with PBKDF2-HmacSHA256 at {@link #DEFAULT_PBKDF2_ITERATIONS}. */
        public static KeySource of(char[] password) {
            return of(password, DEFAULT_PBKDF2_ITERATIONS);
        }

        /** Stretches a passphrase with an explicit work factor (at least {@link #MIN_PBKDF2_ITERATIONS}). */
        public static KeySource of(char[] password, int iterations) {
            return new FromPassword(password, iterations);
        }

        abstract int id();

        abstract byte[] salt(SecureRandom random);

        abstract int iterations();

        abstract SecretKey derive(byte[] salt, int iterations) throws CryptoException;
    }

    private static final class RawKey extends KeySource {

        private final byte[] encoded;

        RawKey(SecretKey key) {
            Objects.requireNonNull(key, "key");
            if (!KEY_ALGORITHM.equals(key.getAlgorithm())) {
                throw new IllegalArgumentException("expected an AES key, got " + key.getAlgorithm());
            }
            byte[] copy = key.getEncoded();
            if (copy == null) {
                throw new IllegalArgumentException("key does not expose its encoding");
            }
            if (copy.length != AES_KEY_BYTES) {
                throw new IllegalArgumentException("expected a " + AES_KEY_BITS + "-bit key, got "
                        + (copy.length * 8) + " bits");
            }
            this.encoded = copy;
        }

        @Override
        int id() {
            return SOURCE_RAW_KEY;
        }

        @Override
        byte[] salt(SecureRandom random) {
            return new byte[0];
        }

        @Override
        int iterations() {
            return 0;
        }

        @Override
        SecretKey derive(byte[] salt, int iterations) {
            return new SecretKeySpec(encoded.clone(), KEY_ALGORITHM);
        }
    }

    private static final class FromPassword extends KeySource {

        private final char[] password;
        private final int iterations;

        FromPassword(char[] password, int iterations) {
            Objects.requireNonNull(password, "password");
            if (password.length == 0) {
                throw new IllegalArgumentException("password must not be empty");
            }
            if (iterations < MIN_PBKDF2_ITERATIONS) {
                throw new IllegalArgumentException("PBKDF2 iteration count must be at least "
                        + MIN_PBKDF2_ITERATIONS + ", got " + iterations);
            }
            this.password = password.clone();
            this.iterations = iterations;
        }

        @Override
        int id() {
            return SOURCE_PASSWORD;
        }

        @Override
        byte[] salt(SecureRandom random) {
            return randomBytes(random, SALT_BYTES);
        }

        @Override
        int iterations() {
            return iterations;
        }

        @Override
        SecretKey derive(byte[] salt, int iterations) throws CryptoException {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, AES_KEY_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
                byte[] encoded = factory.generateSecret(spec).getEncoded();
                return new SecretKeySpec(encoded, KEY_ALGORITHM);
            } catch (GeneralSecurityException e) {
                throw new CryptoException("PBKDF2 key derivation failed: " + e.getMessage(), e);
            } finally {
                spec.clearPassword();
            }
        }
    }

    /** Every failure surfaced by this class, with a caller-actionable message. */
    public static final class CryptoException extends GeneralSecurityException {

        private static final long serialVersionUID = 1L;

        CryptoException(String message, Throwable cause) {
            super(message, cause);
        }

        CryptoException(String message) {
            super(message);
        }

        /**
         * True when the AEAD tag did not verify — the single most useful distinction for a caller,
         * because it means "wrong secret or corrupted data" as opposed to "malformed input".
         */
        public boolean isAuthenticationFailure() {
            return getCause() instanceof AEADBadTagException;
        }
    }
}
