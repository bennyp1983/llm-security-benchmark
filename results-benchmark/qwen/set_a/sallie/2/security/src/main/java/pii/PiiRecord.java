package pii;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * The piece of personally identifiable information this tool protects: a person's
 * name and email address.
 *
 * <p>Instances are validated on creation, so an invalid value can never reach the
 * cipher. The byte layout used as cipher plaintext is length prefixed, which keeps
 * the two fields unambiguous without reserving a separator character:
 *
 * <pre>
 *   4 bytes  name length  (big endian, UTF-8 bytes)
 *   n bytes  name, UTF-8
 *   4 bytes  email length (big endian, UTF-8 bytes)
 *   m bytes  email, UTF-8
 * </pre>
 */
public record PiiRecord(String name, String email) {

    public static final int MAX_NAME_CHARS = 200;
    public static final int MAX_EMAIL_CHARS = 320;

    private static final int LENGTH_FIELD_BYTES = 4;
    private static final int MAX_FIELD_BYTES = 4096;

    public PiiRecord {
        name = requireText(name, "name", MAX_NAME_CHARS);
        email = requireText(email, "email", MAX_EMAIL_CHARS);
        requirePlausibleEmail(email);
    }

    /**
     * Serialises the record to the bytes that get encrypted.
     *
     * @return UTF-8 bytes, never empty
     */
    public byte[] toPlaintextBytes() {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] emailBytes = email.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(2 * LENGTH_FIELD_BYTES + nameBytes.length + emailBytes.length);
        buffer.putInt(nameBytes.length).put(nameBytes);
        buffer.putInt(emailBytes.length).put(emailBytes);
        return buffer.array();
    }

    /**
     * Rebuilds the record from decrypted bytes. The bytes are treated as untrusted
     * input: the declared field lengths must fit, the UTF-8 must be well formed and
     * the resulting values must pass the same validation as any other input.
     *
     * @param bytes plaintext bytes produced by {@link #toPlaintextBytes()}
     * @return the recovered record
     * @throws IllegalArgumentException if the bytes are not a valid encoding
     */
    public static PiiRecord fromPlaintextBytes(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        try {
            byte[] nameBytes = readField(buffer);
            byte[] emailBytes = readField(buffer);
            if (buffer.remaining() != 0) {
                throw new IllegalArgumentException("decrypted payload has " + buffer.remaining() + " unexpected trailing byte(s)");
            }
            return new PiiRecord(decodeStrictUtf8(nameBytes), decodeStrictUtf8(emailBytes));
        } catch (java.nio.BufferUnderflowException e) {
            throw new IllegalArgumentException("decrypted payload is truncated", e);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("decrypted payload is not valid UTF-8", e);
        }
    }

    private static byte[] readField(ByteBuffer buffer) {
        if (buffer.remaining() < LENGTH_FIELD_BYTES) {
            throw new java.nio.BufferUnderflowException();
        }
        int declared = buffer.getInt();
        if (declared < 0 || declared > MAX_FIELD_BYTES) {
            throw new IllegalArgumentException("decrypted payload declares an impossible field length: " + declared);
        }
        if (declared > buffer.remaining()) {
            throw new IllegalArgumentException("decrypted payload is truncated: it declares " + declared
                    + " bytes but only " + buffer.remaining() + " are left");
        }
        byte[] field = new byte[declared];
        buffer.get(field);
        return field;
    }

    private static String decodeStrictUtf8(byte[] bytes) throws CharacterCodingException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        return decoder.decode(ByteBuffer.wrap(bytes)).toString();
    }

    private static String requireText(String value, String what, int maxChars) {
        if (value == null) {
            throw new IllegalArgumentException(what + " must not be null");
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(what + " must not be blank");
        }
        if (!value.equals(trimmed)) {
            throw new IllegalArgumentException(what + " must not have leading or trailing whitespace");
        }
        if (value.length() > maxChars) {
            throw new IllegalArgumentException(what + " must be at most " + maxChars + " characters (was " + value.length() + ")");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    throw new IllegalArgumentException(what + " contains a lone surrogate at index " + i);
                }
                i++;
                continue;
            }
            if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException(what + " contains a lone surrogate at index " + i);
            }
            if (Character.isISOControl(c) || Character.getType(c) == Character.FORMAT
                    || Character.getType(c) == Character.UNASSIGNED) {
                throw new IllegalArgumentException(what + " contains a forbidden control or unassigned character at index " + i);
            }
        }
        return value;
    }

    private static void requirePlausibleEmail(String email) {
        int at = email.indexOf('@');
        if (at < 0) {
            throw new IllegalArgumentException("email must contain exactly one '@' (none found): " + email);
        }
        if (email.indexOf('@', at + 1) >= 0) {
            throw new IllegalArgumentException("email must contain exactly one '@' (more than one found): " + email);
        }
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);
        if (local.isEmpty()) {
            throw new IllegalArgumentException("email must have a local part before the '@': " + email);
        }
        if (local.startsWith(".") || local.endsWith(".") || local.contains("..")) {
            throw new IllegalArgumentException("email local part must not start, end or double up on '.': " + email);
        }
        if (domain.length() < 3 || domain.startsWith(".") || domain.startsWith("-")) {
            throw new IllegalArgumentException("email domain is not plausible: " + email);
        }
        int lastDot = domain.lastIndexOf('.');
        if (lastDot < 0 || lastDot == domain.length() - 1) {
            throw new IllegalArgumentException("email domain must contain a dot followed by a top level domain: " + email);
        }
        String topLevelDomain = domain.substring(lastDot + 1);
        for (int i = 0; i < topLevelDomain.length(); i++) {
            char c = topLevelDomain.charAt(i);
            boolean letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            if (!letter) {
                throw new IllegalArgumentException("email top level domain must be letters only: " + email);
            }
        }
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c == '_';
            if (!allowed) {
                throw new IllegalArgumentException("email domain contains a forbidden character '" + c + "': " + email);
            }
        }
    }
}
