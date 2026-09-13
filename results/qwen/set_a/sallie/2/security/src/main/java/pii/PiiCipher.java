package pii;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts {@link PiiRecord} with AES-256 in GCM mode.
 *
 * <p>GCM is authenticated encryption: the tag produced while encrypting is checked
 * while decrypting, so a tampered or garbled envelope fails loudly instead of
 * returning corrupt plaintext. Every call to {@link #encrypt(PiiRecord)} draws a new
 * random 12 byte IV from the JCE strong secure random source, which is what makes two
 * encryptions of the same person produce different output.
 *
 * <p>The key is supplied by the caller and is never stored in this class. The caller
 * owns the key array and should wipe it with {@code Arrays.fill(key, (byte) 0)} when
 * finished; {@link #close()} wipes only this instance's internal copy.
 */
public final class PiiCipher implements AutoCloseable {

    /** Envelope format family, the first characters of {@link ProtectedPii#toBase64()}. */
    public static final String PREFIX = "v1";

    /** Envelope format version carried inside every envelope. */
    public static final byte VERSION = 1;

    public static final int IV_BYTES = 12;
    public static final int TAG_BYTES = 16;
    public static final int TAG_BITS = TAG_BYTES * 8;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecureRandom random;
    private final byte[] keyBytes;

    /**
     * @param key the AES key, {@value KeyProvider#KEY_BYTES} bytes. This array is
     *            copied, so the caller may wipe its own copy immediately.
     */
    public PiiCipher(byte[] key) {
        this(key, new SecureRandom());
    }

    public PiiCipher(byte[] key, SecureRandom random) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        if (key.length != KeyProvider.KEY_BYTES) {
            throw new IllegalArgumentException("key must be " + KeyProvider.KEY_BYTES
                    + " bytes for AES-256 but was " + key.length
                    + " bytes. Note that SecretKeySpec accepts any non-empty array, so the length is checked here.");
        }
        this.random = random;
        this.keyBytes = key.clone();
    }

    /**
     * Encrypts a person's name and email.
     *
     * @param pii the record to protect
     * @return an envelope that can be stored, printed or transmitted
     * @throws GeneralSecurityException if the JCE provider refuses AES-GCM
     */
    public ProtectedPii encrypt(PiiRecord pii) throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, iv);
        cipher.updateAAD(associatedData(VERSION, iv));
        // GCM is a stream mode: doFinal returns the whole ciphertext followed by the tag.
        byte[] withTag = cipher.doFinal(pii.toPlaintextBytes());
        try {
            if (withTag.length <= TAG_BYTES) {
                throw new GeneralSecurityException("AES-GCM produced an impossibly short result of " + withTag.length + " bytes");
            }
            byte[] ciphertext = Arrays.copyOfRange(withTag, 0, withTag.length - TAG_BYTES);
            byte[] tag = Arrays.copyOfRange(withTag, withTag.length - TAG_BYTES, withTag.length);
            return new ProtectedPii(VERSION, iv, ciphertext, tag);
        } finally {
            Arrays.fill(withTag, (byte) 0);
        }
    }

    /**
     * Decrypts an envelope back into the original record.
     *
     * @param protectedPii the envelope
     * @return the recovered record
     * @throws GeneralSecurityException if the key is wrong or the envelope was tampered
     *                                  with (the GCM tag check fails)
     */
    public PiiRecord decrypt(ProtectedPii protectedPii) throws GeneralSecurityException {
        byte[] packed = new byte[protectedPii.ciphertext().length + TAG_BYTES];
        System.arraycopy(protectedPii.ciphertext(), 0, packed, 0, protectedPii.ciphertext().length);
        System.arraycopy(protectedPii.tag(), 0, packed, protectedPii.ciphertext().length, TAG_BYTES);
        try {
            Cipher cipher = newCipher(Cipher.DECRYPT_MODE, protectedPii.iv());
            cipher.updateAAD(associatedData(protectedPii.version(), protectedPii.iv()));
            byte[] plaintext = cipher.doFinal(packed);
            try {
                return PiiRecord.fromPlaintextBytes(plaintext);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } catch (javax.crypto.AEADBadTagException e) {
            throw new GeneralSecurityException("Authentication tag check failed: the key is wrong or the protected PII was"
                    + " altered, so the original information cannot be recovered.", e);
        } finally {
            Arrays.fill(packed, (byte) 0);
        }
    }

    /**
     * Convenience for the storage format: encrypt straight to one {@code v1:base64} string.
     *
     * @param pii the record to protect
     * @return the stored form
     */
    public String protect(PiiRecord pii) throws GeneralSecurityException {
        return encrypt(pii).toBase64();
    }

    /**
     * Convenience for the storage format: decrypt a {@code v1:base64} string.
     *
     * @param stored text produced by {@link #protect(PiiRecord)}
     * @return the recovered record
     */
    public PiiRecord reveal(String stored) throws GeneralSecurityException {
        return decrypt(ProtectedPii.fromBase64(stored));
    }

    /**
     * The version byte and the IV are authenticated along with the ciphertext. An
     * attacker who flips either one now also fails the tag check, instead of being
     * able to move an envelope's IV around unnoticed.
     */
    private static byte[] associatedData(byte version, byte[] iv) {
        byte[] aad = new byte[1 + iv.length];
        aad[0] = version;
        System.arraycopy(iv, 0, aad, 1, iv.length);
        return aad;
    }

    private Cipher newCipher(int mode, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        // SecretKeySpec does not validate the AES key length, which is why the
        // constructor above checks it; the spec itself is built only from validated bytes.
        cipher.init(mode, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        return cipher;
    }

    /** Wipes this instance's copy of the key. */
    @Override
    public void close() {
        Arrays.fill(keyBytes, (byte) 0);
    }

    static String describeKey(byte[] key) {
        return "AES-" + (key.length * 8);
    }

    static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
