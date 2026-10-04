package com.example.crypto;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Turns a passphrase into a data key with a deliberately expensive KDF, and stores the data key
 * wrapped so that a wrong passphrase is detected before the key is handed to anyone.
 *
 * <p>This is the class to use when the secret in front of the key is a <em>human</em> passphrase.
 * {@link KeystoreKeySource} is not: PKCS#12's key-derivation cost is fixed by the platform at roughly
 * {@code 10^4} iterations, measured here at about 20&nbsp;ms per guess, which is nothing against an
 * offline attack on a dictionary passphrase. Here the cost is explicit, validated and carried in the
 * file: PBKDF2-HMAC-SHA256 with {@link Limits#MIN_KDF_ITERATIONS} to
 * {@link Limits#MAX_KDF_ITERATIONS} iterations, about 0.4-2.0&nbsp;s per attempt on this hardware.
 *
 * <p>Why a wrapped key rather than "derive the key from the passphrase and use it": a derived key has
 * no way to prove it came from the right passphrase. Encrypt everything with a wrong-passphrase-derived
 * key and you get a file that decrypts to random bytes, and a later reader cannot tell corruption from
 * a failed guess. So the passphrase-derived key here is a <em>key-encryption key</em> whose only job is
 * to wrap a 256-bit random data key; the wrap is AES-256-GCM, and its tag is what proves the
 * passphrase. One crypto object, one failure mode, and the key that ever touches application data is
 * uniformly random rather than whatever the passphrase happened to hash to.
 *
 * <p>Container layout, big-endian, no padding:
 *
 * <pre>
 *   5  bytes  magic  {@code SPKB1}
 *   1  byte   KDF id, 1 = PBKDF2-HMAC-SHA256
 *   4  bytes  iteration count, validated against {@link Limits} on every read
 *   1  byte   salt length, must be 16
 *   16 bytes  KDF salt, random per container (so two stores of one passphrase differ)
 *   12 bytes  wrap nonce
 *   4  bytes  wrapped-key length, must be 48 (32 key + 16 tag)
 *   48 bytes  AES-256-GCM(data key) under the derived KEK
 * </pre>
 *
 * <p>The KDF id, iteration count, salt and length are outside the AEAD tag, so they are supplied as
 * additional authenticated data: a container cannot be edited to lower its own iteration count, swap
 * its salt, or claim a different KDF without the unwrap failing. That is what makes the cost parameter
 * safe to read from a file at all - an unauthenticated cost field is a downgrade channel, since the
 * attacker's own file then chooses how much work their guess costs.
 *
 * <p>Every field is range-checked <em>before</em> the KDF runs, and a rejected parameter never causes
 * the derivation to happen: reading {@code iterations = 2000000000} from a hostile file and then
 * obediently grinding through it is a denial of service delivered by configuration.
 *
 * <p><strong>Not a rate limiter.</strong> The KDF makes each guess expensive; it does not cap the
 * number of guesses. If an attacker can submit passphrases through your application, throttle in the
 * caller, per source and per principal, and count failures - this component has no idea who is asking.
 *
 * <p>Passphrases are {@code char[]}, copied on construction, erased by {@link #destroy()}. No
 * {@code String} overload exists, because a {@code String} passphrase cannot be erased.
 */
public final class PasswordKeySource implements KeySource, AutoCloseable {

    /** Salt length for the KDF. Random per container, so identical passphrases differ per file. */
    public static final int SALT_BYTES = 16;

    /** Default PBKDF2-HMAC-SHA256 iterations; roughly 0.8-1.0 s on this JDK. */
    public static final int DEFAULT_ITERATIONS = 600_000;

    private static final byte[] MAGIC = {'S', 'P', 'K', 'B', '1'};
    private static final byte KDF_PBKDF2_SHA256 = 1;
    private static final String KDF_NAME = "PBKDF2WithHmacSHA256";
    private static final int HEADER_BYTES = 5 + 1 + 4 + 1 + SALT_BYTES + 12 + 4;
    private static final int WRAPPED_BYTES = KeyMaterial.KEY_BYTES + (Limits.TAG_BITS / 8);
    private static final int FILE_BYTES = HEADER_BYTES + WRAPPED_BYTES;

    private final Path file;
    private final int keyVersion;
    private final char[] passphrase;
    private volatile boolean destroyed;

    /**
     * @param file an existing container written by {@link #create}
     * @param keyVersion version to tag loaded keys with, {@code 1..255}; goes into the AAD of every
     *     record encrypted with them
     * @param passphrase validated as for {@link #create}; copied, so the caller may wipe its own
     * @throws CryptoException if a parameter is invalid
     */
    public PasswordKeySource(Path file, int keyVersion, char[] passphrase) throws CryptoException {
        if (file == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key file path is missing");
        }
        String abs = file.toAbsolutePath().toString();
        if (abs.length() > 4096 || abs.indexOf('\0') >= 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key file path is invalid");
        }
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        this.file = file;
        this.keyVersion = keyVersion;
        this.passphrase = KeystoreKeySource.requirePassphrase(passphrase, "passphrase");
    }

    /**
     * Generates a random data key, wraps it under a PBKDF2-derived KEK and writes the container.
     *
     * @param file destination; must not exist and must sit in a directory that satisfies
     *     {@link PrivateFiles}
     * @param passphrase at least {@link KeystoreKeySource#MIN_PASSPHRASE_CHARS} characters. The floor
     *     is policy, not mathematics: the KDF slows guessing, it does not make a short passphrase safe.
     * @param iterations {@link Limits#MIN_KDF_ITERATIONS} to {@link Limits#MAX_KDF_ITERATIONS}; a value
     *     outside the range is rejected rather than clamped, because silently accepting a cheap cost
     *     parameter is how a hardened default becomes a weak one
     * @throws CryptoException on any invalid input or if the file cannot be written privately
     */
    public static void create(Path file, int keyVersion, char[] passphrase, int iterations) throws CryptoException {
        if (file == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key file path is missing");
        }
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        requireIterations(iterations);
        char[] pw = KeystoreKeySource.requirePassphrase(passphrase, "passphrase");
        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[Limits.IV_BYTES];
        byte[] dataKey = new byte[KeyMaterial.KEY_BYTES];
        byte[] kekBytes = null;
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent == null || !Files.exists(parent)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file directory does not exist; create it privately first");
            }
            PrivateFiles.requireSecureDirectory(parent);
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file already exists; refusing to overwrite it");
            }

            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            random.nextBytes(nonce);
            random.nextBytes(dataKey);

            kekBytes = derive(pw, salt, iterations);
            byte[] kek = kekBytes;
            byte[] aad = headerBytes(KDF_PBKDF2_SHA256, iterations, salt);
            byte[] wrapped;
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(Limits.TAG_BITS, nonce));
                c.updateAAD(aad);
                wrapped = c.doFinal(dataKey);
            } catch (GeneralSecurityException e) {
                throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                        "data key could not be wrapped: " + e.getClass().getSimpleName(), e);
            }
            if (wrapped.length != WRAPPED_BYTES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                        "unexpected wrapped key length");
            }

            byte[] out = new byte[FILE_BYTES];
            int at = 0;
            System.arraycopy(MAGIC, 0, out, at, MAGIC.length);
            at += MAGIC.length;
            out[at++] = KDF_PBKDF2_SHA256;
            putInt(out, at, iterations);
            at += 4;
            out[at++] = (byte) SALT_BYTES;
            System.arraycopy(salt, 0, out, at, SALT_BYTES);
            at += SALT_BYTES;
            System.arraycopy(nonce, 0, out, at, nonce.length);
            at += nonce.length;
            putInt(out, at, wrapped.length);
            at += 4;
            System.arraycopy(wrapped, 0, out, at, wrapped.length);
            PrivateFiles.writeOwnerOnlyFile(file, out);
        } catch (CryptoException e) {
            throw e;
        } finally {
            Arrays.fill(pw, (char) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(dataKey, (byte) 0);
            if (kekBytes != null) {
                Arrays.fill(kekBytes, (byte) 0);
            }
        }
    }

    /**
     * Reads the container, derives the KEK, verifies the wrap tag and returns the data key.
     *
     * <p>A wrong passphrase, a tampered container, a lowered iteration count and a swapped salt all
     * fail at the same place - the unwrap tag - with the same generic message. The file's privacy is
     * re-checked before every read.
     *
     * @throws CryptoException with {@code AUTHENTICATION_FAILED} for a wrong passphrase, or
     *     {@code INVALID_KEY} / {@code UNSUPPORTED_FORMAT} for a malformed or foreign container
     */
    @Override
    public KeyMaterial load() throws CryptoException {
        if (destroyed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, "key source is closed");
        }
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, FILE_BYTES + 64);
        try {
            Header h = parseHeader(raw);
            byte[] kekBytes = derive(passphrase, h.salt(), h.iterations());
            try {
                byte[] aad = headerBytes(h.kdfId(), h.iterations(), h.salt());
                byte[] dataKey;
                try {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kekBytes, "AES"),
                            new GCMParameterSpec(Limits.TAG_BITS, h.nonce()));
                    c.updateAAD(aad);
                    dataKey = c.doFinal(raw, h.offset(), WRAPPED_BYTES);
                } catch (AEADBadTagException e) {
                    /* The one expected failure: wrong passphrase, or any edit to the container. */
                    throw new CryptoException(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED,
                            "the passphrase does not match this key file", e);
                } catch (GeneralSecurityException e) {
                    throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                            "key file could not be opened: " + e.getClass().getSimpleName(), e);
                }
                try {
                    if (dataKey.length != KeyMaterial.KEY_BYTES) {
                        throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                                "unwrapped key has an unexpected length");
                    }
                    return KeyMaterial.fromBytes(dataKey, keyVersion);
                } finally {
                    Arrays.fill(dataKey, (byte) 0);
                }
            } finally {
                Arrays.fill(kekBytes, (byte) 0);
            }
        } catch (CryptoException e) {
            throw e;
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /** Erases this object's copy of the passphrase. Further {@link #load()} calls fail closed. */
    /** Same as {@link #destroy()}; lets callers use try-with-resources, which is the easy path. */
    @Override
    public void close() {
        destroy();
    }

    public synchronized void destroy() {
        Arrays.fill(passphrase, (char) 0);
        destroyed = true;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * Runs PBKDF2 and returns the derived key bytes, <em>owned by the caller</em>, who must zero them.
     *
     * <p>What is and is not erased here, measured on JDK 17.0.20 rather than assumed:
     * <ul>
     *   <li>{@code spec.clearPassword()} does drop the spec's own copy of the passphrase - its internal
     *       {@code char[]} becomes unreachable - so it runs in a {@code finally} and one live copy is
     *       removed even when the derivation throws. It deliberately leaves the caller's array alone,
     *       so erasing that is the holder's job, which {@link #destroy()} does;</li>
     *   <li>the key object returned by {@code generateSecret} cannot be erased: {@code destroy()} on it
     *       throws {@code DestroyFailedException}, leaves {@code isDestroyed()} false and zeroes neither
     *       its own copy of the passphrase nor its derived-key field. It is therefore not called -
     *       calling it would read as a control that does nothing. Its copies become unreachable when this
     *       method returns and are collected on the ordinary garbage-collector schedule, which is a
     *       residual risk stated in the README, not a fix;</li>
     *   <li>{@code getEncoded()} returns a clone, so the returned array is a copy the caller owns and
     *       can actually zero. Zeroing it does not disturb the key object.</li>
     * </ul>
     */
    private static byte[] derive(char[] passphrase, byte[] salt, int iterations) throws CryptoException {
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(passphrase, salt, iterations, KeyMaterial.KEY_BYTES * 8);
            return SecretKeyFactory.getInstance(KDF_NAME).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key derivation failed: " + e.getClass().getSimpleName(), e);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    /** The authenticated header: everything except its own length field. */
    private static byte[] headerBytes(byte kdfId, int iterations, byte[] salt) {
        byte[] out = new byte[MAGIC.length + 1 + 4 + 1 + salt.length];
        int at = 0;
        System.arraycopy(MAGIC, 0, out, at, MAGIC.length);
        at += MAGIC.length;
        out[at++] = kdfId;
        putInt(out, at, iterations);
        at += 4;
        out[at++] = (byte) salt.length;
        System.arraycopy(salt, 0, out, at, salt.length);
        return out;
    }

    private record Header(byte kdfId, int iterations, byte[] salt, byte[] nonce, int offset) {
    }

    /**
     * Validates the whole fixed-layout header and returns where the wrapped key starts.
     *
     * <p>Every value is checked against a whitelist before anything expensive happens. The magic, KDF
     * id, salt length and wrapped length must be exact; the iteration count must be inside
     * {@link Limits}. Unknown values are refused, never substituted with a default.
     */
    private static Header parseHeader(byte[] raw) throws CryptoException {
        if (raw.length != FILE_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key file has an unexpected length: " + raw.length);
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (raw[i] != MAGIC[i]) {
                throw new CryptoException(CryptoException.CryptoFailureCode.UNSUPPORTED_FORMAT,
                        "key file is not a container this component writes");
            }
        }
        int at = MAGIC.length;
        byte kdfId = raw[at++];
        if (kdfId != KDF_PBKDF2_SHA256) {
            throw new CryptoException(CryptoException.CryptoFailureCode.UNSUPPORTED_FORMAT,
                    "key file names KDF id " + (kdfId & 0xFF) + ", which is not supported");
        }
        int iterations = getInt(raw, at);
        at += 4;
        requireIterations(iterations);
        int saltLen = raw[at] & 0xFF;
        at += 1;
        if (saltLen != SALT_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key file salt length " + saltLen + " is not supported");
        }
        byte[] salt = Arrays.copyOfRange(raw, at, at + saltLen);
        at += saltLen;
        byte[] nonce = Arrays.copyOfRange(raw, at, at + Limits.IV_BYTES);
        at += Limits.IV_BYTES;
        int wrappedLen = getInt(raw, at);
        at += 4;
        if (wrappedLen != WRAPPED_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key file wraps " + wrappedLen + " bytes, expected " + WRAPPED_BYTES);
        }
        if (at + wrappedLen != raw.length) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key file has trailing data");
        }
        return new Header(kdfId, iterations, salt, nonce, at);
    }

    private static void requireIterations(int iterations) throws CryptoException {
        if (iterations < Limits.MIN_KDF_ITERATIONS || iterations > Limits.MAX_KDF_ITERATIONS) {
            /*
             * Reported as unsupported rather than "invalid" because on load this value came from the
             * file, and refusing to do a cheap derivation is the point, not a user error.
             */
            throw new CryptoException(CryptoException.CryptoFailureCode.UNSUPPORTED_FORMAT,
                    "iteration count " + iterations + " is outside the supported range "
                            + Limits.MIN_KDF_ITERATIONS + ".." + Limits.MAX_KDF_ITERATIONS);
        }
    }

    private static void putInt(byte[] out, int at, int value) {
        out[at] = (byte) (value >>> 24);
        out[at + 1] = (byte) (value >>> 16);
        out[at + 2] = (byte) (value >>> 8);
        out[at + 3] = (byte) value;
    }

    private static int getInt(byte[] in, int at) {
        return ((in[at] & 0xFF) << 24) | ((in[at + 1] & 0xFF) << 16) | ((in[at + 2] & 0xFF) << 8)
                | (in[at + 3] & 0xFF);
    }

    /** The file path. A path is not a secret; the passphrase and the key are. */
    @Override
    public String describe() {
        return "pbkdf2:" + file.toAbsolutePath() + "@" + keyVersion;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PasswordKeySource other
                && keyVersion == other.keyVersion
                && file.equals(other.file);
    }

    @Override
    public int hashCode() {
        return Objects.hash(file, keyVersion);
    }

    @Override
    public String toString() {
        return describe();
    }

}
