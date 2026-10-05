package com.example.crypto;

import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The encryption engine: AES-256-GCM with a fresh 96-bit nonce per record and the version plus
 * context bound in as additional authenticated data.
 *
 * <p>Everything about the algorithm is fixed. There is no constructor or setter that chooses a
 * transformation, a key length, a tag length, a nonce length or a padding scheme, so nothing an
 * attacker controls - a config file, a database row, a blob header, an HTTP body - can select a
 * weaker path. The only inputs this class takes are key material, data and a context string, and
 * all three are validated before use.
 *
 * <p><strong>Capacity limit.</strong> Nonces are random 96-bit values, so uniqueness is probabilistic:
 * after roughly 2<sup>32</sup> records under one key a collision becomes likely, and two records sharing a
 * nonce under one GCM key is a total loss of confidentiality for those two plus a forgery capability. This
 * component cannot observe how many records a key has produced across processes, so it cannot stop you
 * crossing the line - {@link KeyVault#rotate()} is the control, and it exists to be used routinely rather
 * than once a decade. Treat well over a hundred million records under one key as the point to rotate.
 *
 * <p>Instances are immutable and thread-safe: the single {@link SecureRandom} instance is the only
 * mutable state and {@code SecureRandom} is thread-safe.
 *
 * <pre>{@code
 * SymmetricCrypto crypto = new SymmetricCrypto();
 * KeyMaterial fresh = crypto.generateKey();
 * EncryptedBlob blob = crypto.encrypt(fresh, cardNumber, "payment-ref");
 *
 * // ...the caller persists fresh's bytes itself (KeySource.writeFile / a KMS), then later:
 * try (KeyMaterial km = keySource.load()) {
 *     String back = crypto.decryptToString(km, blob, "payment-ref"); // wrong context -> fails
 * }
 * }</pre>
 */
public final class SymmetricCrypto {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ALGORITHM = "AES";

    private final SecureRandom random;

    /**
     * Uses the platform default {@link SecureRandom} - {@code NativePRNG}, seeded from the OS entropy
     * source, on this JDK. This path cannot fail, so it declares no checked exception.
     */
    public SymmetricCrypto() {
        this.random = new SecureRandom();
    }

    /**
     * @param random the source for record nonces. Never {@code Random}, {@code ThreadLocalRandom}
     *     or anything seeded from the clock: a repeated nonce under the same key breaks every
     *     record encrypted with it, not just the colliding one.
     * @throws CryptoException if {@code random} is null - there is no fallback to a weaker source
     */
    public SymmetricCrypto(SecureRandom random) throws CryptoException {
        if (random == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "no cryptographic random source supplied");
        }
        this.random = random;
    }

    /**
     * Generates a new 256-bit key tagged with {@code keyVersion}. This is the only way keys enter the
     * system other than a caller supplying one from a secret store: the component never derives a key
     * from a passphrase unless {@link PasswordKeySource} is explicitly configured, and never has a
     * built-in, default or fallback key.
     *
     * @throws CryptoException if the version is outside {@code 1..255}
     */
    public KeyMaterial generateKey(int keyVersion) throws CryptoException {
        byte[] raw = new byte[KeyMaterial.KEY_BYTES];
        try {
            random.nextBytes(raw);
            return KeyMaterial.fromBytes(raw, keyVersion);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /** Generates a new 256-bit key at version 1. */
    public KeyMaterial generateKey() throws CryptoException {
        return generateKey(EncryptedBlob.MIN_KEY_VERSION);
    }

    /**
     * Encrypts {@code plaintext} and binds it to {@code context}.
     *
     * @param key key material; not retained by this class
     * @param plaintext at most {@link Limits#MAX_PLAINTEXT_BYTES}; never null, may be empty
     * @param context stable ASCII identifier for the record's purpose or owner (for example
     *     {@code "payment-ref"}). Authenticated as AAD: decryption with a different context fails.
     *     Passing {@code null} means "no context" and is recorded as such in the blob - it is not
     *     silently replaced with the empty string, and it does not disable the binding check.
     * @throws CryptoException on any invalid input or provider failure. The message is generic.
     */
    public EncryptedBlob encrypt(KeyMaterial key, byte[] plaintext, String context) throws CryptoException {
        return guard(() -> doEncrypt(key, plaintext, context));
    }

    private EncryptedBlob doEncrypt(KeyMaterial key, byte[] plaintext, String context) throws CryptoException {
        if (key == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key is missing");
        }
        byte[] pt = Limits.requirePayload(plaintext, Limits.MAX_PLAINTEXT_BYTES, "plaintext");
        boolean hasContext = context != null;
        if (hasContext) {
            Limits.requireAsciiText(context, Limits.MAX_CONTEXT_CHARS, "context");
        }

        byte[] nonce = new byte[Limits.IV_BYTES];
        random.nextBytes(nonce);
        int keyVersion = key.version();
        /*
         * Built before the lambda: a Function cannot throw a checked exception, and the context has
         * already been validated. At write time the record's header fields and the caller's/key's
         * fields agree by construction - the point of writing both is that a reader cannot make them
         * disagree without breaking the tag.
         */
        byte[] aadBytes = aad(EncryptedBlob.FORMAT_VERSION, hasContext ? 1 : 0, keyVersion, hasContext,
                keyVersion, context);
        byte[] body = key.use(k -> cipherOp(Cipher.ENCRYPT_MODE, k, nonce, aadBytes, pt));

        byte[] packed = new byte[EncryptedBlob.HEADER_BYTES + body.length];
        packed[0] = EncryptedBlob.FORMAT_VERSION;
        packed[1] = (byte) (hasContext ? 1 : 0);
        packed[2] = (byte) keyVersion;
        System.arraycopy(nonce, 0, packed, 3, Limits.IV_BYTES);
        System.arraycopy(body, 0, packed, EncryptedBlob.HEADER_BYTES, body.length);
        Arrays.fill(nonce, (byte) 0);
        Arrays.fill(body, (byte) 0);
        return EncryptedBlob.wrap(packed, hasContext, context);
    }

    /** Convenience overload for text, UTF-8, bounded by {@link Limits#MAX_PLAINTEXT_CHARS}. */
    public EncryptedBlob encrypt(KeyMaterial key, String plaintext, String context) throws CryptoException {
        return guard(() -> {
            if (plaintext == null) {
                throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "plaintext is missing");
            }
            if (plaintext.length() > Limits.MAX_PLAINTEXT_CHARS) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE, "plaintext is too large");
            }
            return encrypt(key, utf8(plaintext), context);
        });
    }

    /**
     * Decrypts a blob and verifies it belongs to {@code context}.
     *
     * <p>A wrong key, a modified blob, a swapped nonce and a mismatched context all produce the same
     * {@link CryptoException.CryptoFailureCode#AUTHENTICATION_FAILED} failure with the same message,
     * and the component does no additional work for any of them: it decrypts, and the tag decides.
     * There is no path that returns plaintext, or a partial plaintext, when the tag fails, and no
     * path that reports which check failed.
     *
     * @throws CryptoException if the blob is not a record this component wrote, if the key is
     *     missing or not usable, or if authentication fails
     */
    public byte[] decrypt(KeyMaterial key, EncryptedBlob blob, String context) throws CryptoException {
        return guard(() -> doDecrypt(key, blob, context));
    }

    private byte[] doDecrypt(KeyMaterial key, EncryptedBlob blob, String context) throws CryptoException {
        if (key == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key is missing");
        }
        if (blob == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "blob is missing");
        }
        boolean hasContext = context != null;
        if (hasContext) {
            Limits.requireAsciiText(context, Limits.MAX_CONTEXT_CHARS, "context");
        }

        byte[] packed = blob.ciphertext();
        byte[] nonce = Arrays.copyOfRange(packed, 3, EncryptedBlob.HEADER_BYTES);
        byte[] body = Arrays.copyOfRange(packed, EncryptedBlob.HEADER_BYTES, packed.length);
        /*
         * The AAD carries BOTH readings of the two facts that must agree: the header bytes as stored in
         * the record, and the values the caller and the key assert. There is deliberately no separate
         * "does the header match?" branch:
         *
         *   - a stored flag cleared, or a key-version byte re-stamped, makes the two readings disagree,
         *     which changes the AAD, which fails the tag. Tampering with header bytes can neither
         *     downgrade the record nor retarget it at another key;
         *   - because the disagreement is settled by the tag and not by a branch, every failure - wrong
         *     key, wrong context, absent context, edited header, flipped ciphertext byte - performs the
         *     same AES-GCM operation. An early `return` here would make "the header was edited" measurably
         *     cheaper than "the ciphertext was edited", which is an oracle over data an attacker chose.
         *
         * The context is only converted to bytes when one was actually supplied: a record that claims a
         * context while the caller passes none is a disagreement to be caught by the tag, not a
         * NullPointerException to be leaked as a provider failure.
         */
        int recordFlag = packed[1] & 0xFF;
        int recordKeyVersion = packed[2] & 0xFF;
        byte[] aad = aad(EncryptedBlob.FORMAT_VERSION, recordFlag, recordKeyVersion, hasContext,
                key.version(), hasContext ? context : null);
        try {
            /*
             * Exactly one failure path. Whether the key is wrong, the nonce was swapped, a ciphertext
             * byte was flipped, a header byte was re-stamped or the context differs, the work done is
             * identical and the outcome is the same tag mismatch. Nothing is reported about which of
             * those it was, and no partial plaintext is ever returned.
             */
            return key.use(k -> cipherOp(Cipher.DECRYPT_MODE, k, nonce, aad, body));
        } finally {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(body, (byte) 0);
        }
    }

    /**
     * Decrypts a blob presented as a string in the encoded form produced by
     * {@link EncryptedBlob#toBase64Url()} (a raw {@code "v1."} blob is also accepted). Use this for
     * anything that arrives over a network, a queue or a database column: the encoded string is the
     * shape an attacker controls, so all bounds are applied before anything is allocated.
     */
    public byte[] decrypt(KeyMaterial key, String encodedBlob, String context) throws CryptoException {
        return decrypt(key, EncryptedBlob.fromEncoded(encodedBlob), context);
    }

    /** Convenience overload returning strict UTF-8 text. */
    public String decryptToString(KeyMaterial key, EncryptedBlob blob, String context) throws CryptoException {
        return guard(() -> decodeUtf8(decrypt(key, blob, context)));
    }

    /** Convenience overload returning strict UTF-8 text. */
    public String decryptToString(KeyMaterial key, String encodedBlob, String context) throws CryptoException {
        return guard(() -> decodeUtf8(decrypt(key, EncryptedBlob.fromEncoded(encodedBlob), context)));
    }

    /** UTF-8 bytes of a string, for the text overloads. */
    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Decodes UTF-8 strictly. Text that this component encrypted with {@code encrypt(.., String, ..)}
     * always round-trips, so anything malformed here means the blob was not produced that way; it is
     * rejected instead of being returned with U+FFFD replacement characters.
     */
    public static String decodeUtf8(byte[] raw) throws CryptoException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(raw))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record does not contain well-formed UTF-8", e);
        }
    }

    private static byte[] cipherOp(int mode, SecretKey key, byte[] nonce, byte[] aad, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, key, new GCMParameterSpec(Limits.TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (AEADBadTagException e) {
            /* Expected on any tampered or wrongly-keyed blob. Never carries the exception onward. */
            throw new AuthFailure();
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            /* Includes InvalidKeyException / InvalidAlgorithmParameterException / NoSuchAlgorithmException. */
            throw new ProviderFailure(e.getClass().getName());
        }
    }

    /**
     * The AAD bound into every record: {@code format || record-context-flag || record-key-version ||
     * caller-has-context || key-version || context}. The first two header fields are what the record
     * claims and the last two are what the caller and key assert, so the tag enforces that the claim
     * and the assertion agree. A context captured under one label cannot be replayed under another,
     * and an edited header byte cannot survive re-encryption.
     */
    private static byte[] aad(int formatVersion, int recordContextFlag, int recordKeyVersion,
            boolean callerHasContext, int keyVersion, String context) throws CryptoException {
        byte[] ctx = callerHasContext ? ascii(context) : new byte[0];
        byte[] out = new byte[5 + ctx.length];
        out[0] = (byte) formatVersion;
        out[1] = (byte) recordContextFlag;
        out[2] = (byte) recordKeyVersion;
        out[3] = (byte) (callerHasContext ? 1 : 0);
        out[4] = (byte) keyVersion;
        System.arraycopy(ctx, 0, out, 5, ctx.length);
        return out;
    }

    /**
     * Encodes the context for AAD using the explicit 7-bit mapping documented on
     * {@link EncryptedBlob#toBase64Url()}: a byte in {@code [0x21,0x7E]} is itself, anything else is
     * {@code '!' + value}. Injective for every {@code String} that satisfies
     * {@link Limits#requireAsciiText}, and it cannot collide with a shorter context because no
     * encoded value equals {@code '!'} (that would require the source character {@code 0x00}, which
     * the validator rejects).
     */
    static byte[] ascii(String s) throws CryptoException {
        byte[] raw = s.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[raw.length * 2];
        int n = 0;
        for (byte b : raw) {
            int v = b & 0xFF;
            if (v >= 0x21 && v <= 0x7E) {
                out[n++] = (byte) v;
            } else {
                out[n++] = '!';
                out[n++] = (byte) v;
            }
        }
        return Arrays.copyOf(out, n);
    }

    /** Internal signal for a tag mismatch; translated at the public boundary. */
    static final class AuthFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        AuthFailure() {
            super("authentication failed", null, false, false);
        }
    }

    /** Internal signal for a provider/primitive failure; translated at the public boundary. */
    static final class ProviderFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ProviderFailure(String causeClassName) {
            super("provider failure: " + causeClassName, null, false, false);
        }
    }

    /**
     * Translates an internal signal into the public exception. Kept in one place so every public
     * method reports failures identically.
     */
    static <T> T guard(java.util.concurrent.Callable<T> body) throws CryptoException {
        try {
            return body.call();
        } catch (AuthFailure e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED,
                    "AES-GCM tag verification failed", e);
        } catch (ProviderFailure e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE, e.getMessage(), e);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "unexpected failure: " + e.getClass().getName(), e);
        }
    }

    static {
        /*
         * Fail fast at class load if the platform cannot do AES-256-GCM. Without this, a JVM with
         * restricted cryptography policy would only discover it on the first encrypt call, and a
         * caller that catches and retries could mistake that for a data problem.
         */
        try {
            int max = javax.crypto.Cipher.getMaxAllowedKeyLength(ALGORITHM);
            if (max < 256) {
                throw new IllegalStateException(
                        "AES-256 is unavailable on this JVM (max " + max + " bits); install the "
                                + "unlimited strength jurisdiction policy before using this component");
            }
            Cipher.getInstance(TRANSFORMATION);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(TRANSFORMATION + " is not available on this JVM", e);
        }
    }
}
