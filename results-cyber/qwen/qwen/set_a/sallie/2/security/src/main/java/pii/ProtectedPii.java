package pii;

import java.util.Arrays;
import java.util.Base64;

/**
 * Encrypted PII, ready to be stored or sent: the initialisation vector, the GCM
 * authentication tag and the ciphertext, plus a format version byte.
 *
 * <p>Everything in here is safe to write into a database or a log. It carries no
 * plaintext and no key. It is only reversible with the AES key.
 *
 * @param version the envelope format version
 * @param iv the random 12 byte initialisation vector used for this record
 * @param ciphertext AES-GCM ciphertext
 * @param tag the 16 byte GCM authentication tag
 */
public record ProtectedPii(byte version, byte[] iv, byte[] ciphertext, byte[] tag) {

    public ProtectedPii {
        // A record does not defensively copy array components, so clone here. Without
        // this, a caller that wipes its own buffers would silently corrupt envelopes
        // that were already handed out.
        version = requireVersion(version);
        iv = requireLength(iv, PiiCipher.IV_BYTES, "iv");
        tag = requireLength(tag, PiiCipher.TAG_BYTES, "tag");
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("ciphertext must not be empty");
        }
        ciphertext = ciphertext.clone();
    }

    @Override
    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public byte[] tag() {
        return tag.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ProtectedPii that)) {
            return false;
        }
        return version == that.version && Arrays.equals(iv, that.iv)
                && Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(tag, that.tag);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * (31 * version + Arrays.hashCode(iv)) + Arrays.hashCode(ciphertext)) + Arrays.hashCode(tag);
    }

    /** Never prints plaintext; it only ever holds ciphertext. */
    @Override
    public String toString() {
        return "ProtectedPii{version=" + version + ", ivBytes=" + iv.length
                + ", ciphertextBytes=" + ciphertext.length + ", tagBytes=" + tag.length + "}";
    }

    /**
     * Serialises the envelope as {@code v1:base64(version || iv || ciphertext || tag)} -
     * one printable string per protected value.
     *
     * @return text safe to store in a single column
     */
    public String toBase64() {
        byte[] packed = new byte[1 + iv.length + ciphertext.length + tag.length];
        packed[0] = version;
        int offset = 1;
        System.arraycopy(iv, 0, packed, offset, iv.length);
        offset += iv.length;
        System.arraycopy(ciphertext, 0, packed, offset, ciphertext.length);
        offset += ciphertext.length;
        System.arraycopy(tag, 0, packed, offset, tag.length);
        return PiiCipher.PREFIX + ":" + Base64.getEncoder().encodeToString(packed);
    }

    /**
     * Parses text produced by {@link #toBase64()}.
     *
     * @param text the {@code v1:base64} string
     * @return the envelope
     * @throws IllegalArgumentException if the text is malformed, truncated or uses an
     *                                  unsupported version
     */
    public static ProtectedPii fromBase64(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Protected PII text must not be blank");
        }
        String trimmed = text.trim();
        String prefix = PiiCipher.PREFIX + ":";
        if (!trimmed.startsWith(prefix)) {
            throw new IllegalArgumentException("Protected PII text must start with '" + prefix + "'");
        }
        byte[] packed;
        try {
            packed = Base64.getDecoder().decode(trimmed.substring(prefix.length()).trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Protected PII text is not valid Base64", e);
        }
        int overhead = 1 + PiiCipher.IV_BYTES + PiiCipher.TAG_BYTES;
        if (packed.length <= overhead) {
            throw new IllegalArgumentException("Protected PII text is too short to hold a version, an IV, a tag and any"
                    + " ciphertext (got " + packed.length + " bytes, needs more than " + overhead + ")");
        }
        byte version = packed[0];
        int offset = 1;
        byte[] iv = Arrays.copyOfRange(packed, offset, offset + PiiCipher.IV_BYTES);
        byte[] tag = Arrays.copyOfRange(packed, packed.length - PiiCipher.TAG_BYTES, packed.length);
        byte[] ciphertext = Arrays.copyOfRange(packed, offset + PiiCipher.IV_BYTES, packed.length - PiiCipher.TAG_BYTES);
        return new ProtectedPii(version, iv, ciphertext, tag);
    }

    private static byte requireVersion(byte version) {
        if (version != PiiCipher.VERSION) {
            throw new IllegalArgumentException("Unsupported protected PII format version " + version
                    + ", this build reads version " + PiiCipher.VERSION);
        }
        return version;
    }

    private static byte[] requireLength(byte[] value, int expected, String what) {
        if (value == null) {
            throw new IllegalArgumentException(what + " must not be null");
        }
        if (value.length != expected) {
            throw new IllegalArgumentException(what + " must be " + expected + " bytes but was " + value.length);
        }
        return value.clone();
    }
}
