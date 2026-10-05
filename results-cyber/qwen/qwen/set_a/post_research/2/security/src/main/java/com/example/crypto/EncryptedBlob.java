package com.example.crypto;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * One encrypted record: format version, key version, context flag, the record nonce and the AES-GCM
 * ciphertext-with-tag, plus the context string it is bound to.
 *
 * <p>Byte layout, as produced by {@link #toBytes()}:
 *
 * <pre>
 *   offset 0   1 byte   format version, always 1
 *   offset 1   1 byte   1 if a context is bound, else 0
 *   offset 2   1 byte   key version, 1..255
 *   offset 3  12 bytes  record nonce (random per record, never reused under one key)
 *   offset 15  n bytes  AES-256-GCM ciphertext followed by the 16 byte tag
 * </pre>
 *
 * <p>The three header bytes sit outside what AES-GCM authenticates directly, so all three are bound
 * into the tag as additional authenticated data (see {@code SymmetricCrypto#aad}). Re-stamping any of
 * them on a captured record makes decryption fail instead of downgrading anything - a record cannot be
 * retargeted at another key, re-labelled as context-free, or moved to another format version. The
 * parsers re-check the header anyway, so a malformed record is rejected as malformed rather than
 * reaching the cipher.
 *
 * <p>Encoded form, for a database column, a header or a queue message:
 *
 * <pre>
 *   {@code v1.<base64url-nopadding(record)>[.<context>]}
 * </pre>
 *
 * <ul>
 *   <li>the literal prefix is always {@code v1.}, so a caller can decide which key versions to load
 *       without trusting or fully parsing the attacker's payload - see {@link #peekKeyVersion};</li>
 *   <li>base64url without padding, decoded canonically: the bytes are re-encoded and compared, so a
 *       second spelling of the same bytes is refused. Otherwise two different strings could decrypt to
 *       the same record, and anything that deduplicated, cached or rate-limited on the string would
 *       treat them as distinct;</li>
 *   <li>the context, when present, is the final field and is length-delimited, so a context that
 *       itself contains {@code '.'} cannot smuggle an extra field. The stored text is exactly the input
 *       that {@link Limits#requireAsciiText} validated, so it stays readable; what is authenticated as
 *       AAD is an injective byte mapping of it (see {@code SymmetricCrypto#ascii}).</li>
 * </ul>
 *
 * <p>Instances are immutable and hold no plaintext. {@code context} is not key material and is not
 * secret - it travels in the encoded form - so never put in it a value you are trying to protect.
 */
public final class EncryptedBlob {

    /** The only record format version this build writes or accepts. */
    public static final byte FORMAT_VERSION = 1;

    /** Key versions are a single header byte. */
    public static final int MIN_KEY_VERSION = 1;
    public static final int MAX_KEY_VERSION = 255;

    private static final String PREFIX = "v1.";
    private static final char SEP = '.';
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    static final int HEADER_BYTES = 3 + Limits.IV_BYTES;
    private static final int TAG_BYTES = Limits.TAG_BITS / 8;
    private static final int MIN_PACKED_BYTES = HEADER_BYTES + TAG_BYTES;
    static final int MAX_PACKED_BYTES = Limits.MAX_CIPHERTEXT_BYTES + HEADER_BYTES;

    private final byte[] packed;
    private final boolean hasContext;
    private final String context;

    private EncryptedBlob(byte[] packed, boolean hasContext, String context) {
        this.packed = packed;
        this.hasContext = hasContext;
        this.context = context;
    }

    /** Internal factory used by the engine. Takes ownership of {@code packed}. */
    static EncryptedBlob wrap(byte[] packed, boolean hasContext, String context) {
        return new EncryptedBlob(packed, hasContext, context);
    }

    /**
     * Parses a raw record as produced by {@link #toBytes()}, for a record that carries <em>no</em>
     * context. A record whose header says a context is bound is refused here: the context text is not
     * part of this layout, and a caller must not be able to satisfy a context-bound record on the
     * strength of an unauthenticated flag. Parse the encoded form instead, which carries it.
     *
     * @throws CryptoException if the bytes are not a well-formed record of the supported format
     */
    public static EncryptedBlob fromBytes(byte[] raw) throws CryptoException {
        byte[] copy = structural(raw);
        if (copy[1] == 1) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record is bound to a context; parse it from its encoded form, which carries it");
        }
        return new EncryptedBlob(copy, false, null);
    }

    /**
     * Parses either accepted string form: {@code v1.<b64>[.<context>]} or a bare {@code <b64>} for a
     * record with no context.
     *
     * <p>This is the entry point for strings that crossed a trust boundary. Checks, in order:
     * non-null, non-empty, length bound before any scanning or allocation, no leading or trailing
     * whitespace or control character, prefix and format version, field shape, context text validated
     * as ASCII, strict base64url alphabet, canonical re-encode comparison, then the structural checks
     * (length, format version, context flag, key version range) and finally that the context field and
     * the context flag agree.
     *
     * @throws CryptoException always with a generic user message; the reason is in
     *     {@link CryptoException#getTechnicalDetail()} for the log
     */
    public static EncryptedBlob fromEncoded(String encoded) throws CryptoException {
        if (encoded == null || encoded.isEmpty()) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "record is missing");
        }
        if (encoded.length() > Limits.MAX_ENCODED_BLOB_CHARS + Limits.MAX_CONTEXT_CHARS + 1) {
            throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE, "record string is too large");
        }
        if (encoded.charAt(0) <= ' ' || encoded.charAt(encoded.length() - 1) <= ' ') {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record has leading or trailing whitespace");
        }

        boolean hasPrefix = encoded.startsWith(PREFIX);
        String rest = hasPrefix ? encoded.substring(PREFIX.length()) : encoded;
        if (!hasPrefix && rest.indexOf(SEP) >= 0) {
            /* A context field without the version prefix is not a form this component ever wrote. */
            throw new CryptoException(CryptoException.CryptoFailureCode.UNSUPPORTED_FORMAT,
                    "record must carry the version prefix when it carries a context");
        }

        String b64;
        String ctx = null;
        int sep = rest.indexOf(SEP);
        if (sep < 0) {
            b64 = rest;
        } else {
            b64 = rest.substring(0, sep);
            ctx = rest.substring(sep + 1);
            if (ctx.indexOf(SEP) >= 0) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                        "record has a malformed context field");
            }
            try {
                Limits.requireAsciiText(ctx, Limits.MAX_CONTEXT_CHARS, "record context");
            } catch (CryptoException e) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                        "record context is not acceptable", e);
            }
        }

        if (b64.isEmpty()) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "record has no payload");
        }
        if (b64.length() > (MAX_PACKED_BYTES * 4) / 3 + 4) {
            throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE, "record payload is too large");
        }

        byte[] packed;
        try {
            packed = DECODER.decode(b64);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record payload is not valid base64url", e);
        }
        if (!ENCODER.encodeToString(packed).equals(b64)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record payload is not canonically encoded");
        }
        byte[] checked = structural(packed);
        if ((checked[1] == 1) != (ctx != null)) {
            /*
             * The flag inside the record and the presence of a context field must agree, so an
             * attacker cannot strip the field and present a context-bound record as an unbound one.
             * The cipher would reject that regardless - the flag is AAD - but keeping the two
             * representations of one fact from ever diverging beats reasoning about check ordering.
             */
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record context field does not match its header");
        }
        return new EncryptedBlob(checked, ctx != null, ctx);
    }

    /** Size bounds, format-version whitelist, context-flag encoding and key-version range. */
    private static byte[] structural(byte[] raw) throws CryptoException {
        if (raw == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "record is missing");
        }
        /*
         * Bound before copying. `clone` runs first here in the obvious ordering, which means a hostile
         * length decides how much heap is allocated before anybody checks the length - so the length
         * check has to be the thing that happens to the caller's array, not to a copy of it.
         */
        if (raw.length < MIN_PACKED_BYTES || raw.length > MAX_PACKED_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record has an impossible length: " + raw.length);
        }
        byte[] copy = raw.clone();
        if (copy[0] != FORMAT_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.UNSUPPORTED_FORMAT,
                    "record format version " + (copy[0] & 0xFF) + " is not supported");
        }
        if (copy[1] != 0 && copy[1] != 1) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record context flag is not a valid encoding");
        }
        if ((copy[2] & 0xFF) < MIN_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record key version 0 is reserved and never valid");
        }
        return copy;
    }

    /**
     * Reads the key version from an encoded string without trusting anything else in it, so a caller
     * can load exactly one candidate key instead of one per version. Returns {@code -1} when the
     * supported prefix is absent or the payload is too short to contain the header.
     *
     * <p>Remaining risk, to be documented wherever this is used: the value is attacker-chosen. It may
     * only ever narrow which key is <em>attempted</em>. It must not be treated as authorisation, and
     * the record must still be parsed and authenticated normally - the key version is inside the AAD,
     * so a record re-stamped to another version fails authentication whatever this returns. A caller
     * that has no key for the returned version must fail closed rather than fall back to others;
     * {@link KeyVault} does exactly that.
     *
     * <p>Cost is bounded against a hostile input: the string length is capped as in
     * {@link #fromEncoded}, and only the four base64 characters that cover the header are decoded, so a
     * multi-megabyte payload does not get base64-decoded in full just to read one byte that will be
     * re-checked, and authenticated, later anyway.
     */
    public static int peekKeyVersion(String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            return -1;
        }
        if (encoded.length() > Limits.MAX_ENCODED_BLOB_CHARS + Limits.MAX_CONTEXT_CHARS + 1) {
            return -1;
        }
        String rest = encoded.substring(PREFIX.length());
        int sep = rest.indexOf(SEP);
        String b64 = sep < 0 ? rest : rest.substring(0, sep);
        if (b64.length() < 4) {
            return -1;
        }
        if (b64.length() > (MAX_PACKED_BYTES * 4) / 3 + 4) {
            return -1;
        }
        /*
         * The cheapest bound on "is this record big enough to hold a header at all" is the encoded
         * length, and it costs nothing: the payload cannot be shorter than a header plus a tag.
         */
        if (b64.length() < MIN_ENCODED_RECORD_CHARS) {
            return -1;
        }
        try {
            /* 4 characters decode to exactly the 3 header bytes; the rest of the record is irrelevant here. */
            byte[] header = DECODER.decode(b64.substring(0, 4));
            if (header.length < 3 || header[0] != FORMAT_VERSION) {
                return -1;
            }
            int v = header[2] & 0xFF;
            return v < MIN_KEY_VERSION ? -1 : v;
        } catch (IllegalArgumentException e) {
            return -1;
        }
    }

    /** Base64url-without-padding length of the shortest record the format allows. */
    private static final int MIN_ENCODED_RECORD_CHARS = base64CharsFor(MIN_PACKED_BYTES);

    private static int base64CharsFor(int bytes) {
        int rem = bytes % 3;
        return (bytes / 3) * 4 + (rem == 0 ? 0 : rem + 1);
    }

    /** The whole record, header and nonce included, as a defensive copy. Not secret; safe to store. */
    public byte[] toBytes() {
        return packed.clone();
    }

    /** Internal, non-copying view used by the cipher. Callers must not mutate the result. */
    byte[] ciphertext() {
        return packed;
    }

    /** Record format version. */
    public int formatVersion() {
        return packed[0] & 0xFF;
    }

    /** The key version this record is cryptographically bound to. */
    public int keyVersion() {
        return packed[2] & 0xFF;
    }

    /** Whether this record is bound to a context string. */
    public boolean hasContext() {
        return hasContext;
    }

    /** The bound context, or {@code null}. A convenience for callers; never an authority. */
    public String context() {
        return context;
    }

    /**
     * Encodes this record for storage or transport. See the class documentation for the layout and for
     * why the encoding is canonical.
     */
    public String toBase64Url() {
        StringBuilder sb = new StringBuilder(PREFIX.length() + (packed.length * 4) / 3 + 4)
                .append(PREFIX)
                .append(ENCODER.encodeToString(packed));
        if (hasContext) {
            sb.append(SEP).append(context);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        /*
         * Never the payload. A record is opaque ciphertext, but a blob can still reach a log line
         * through a POJO's toString, and a logged record plus a leaked key is leaked data.
         */
        return "EncryptedBlob[format=" + formatVersion() + ", keyVersion=" + keyVersion()
                + ", bytes=" + packed.length + ", context=" + (hasContext ? "present" : "none") + "]";
    }

    /**
     * Equality over the whole record and its context. Two records of the same plaintext differ by
     * nonce, so this is not a "same plaintext" test and must not be used as one.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EncryptedBlob other)) {
            return false;
        }
        return hasContext == other.hasContext
                && Arrays.equals(packed, other.packed)
                && Objects.equals(context, other.context);
    }

    @Override
    public int hashCode() {
        int h = Arrays.hashCode(packed);
        h = 31 * h + (hasContext ? 1 : 0);
        h = 31 * h + (context == null ? 0 : context.hashCode());
        return h;
    }
}
