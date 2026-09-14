import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts a person's name and email address with AES.
 *
 * <p>Wire format of the returned token, before Base64 encoding:
 *
 * <pre>
 *   version(1) | salt(16) | iv(12) | AES-GCM ciphertext + 16-byte tag
 * </pre>
 *
 * <p>Choices worth knowing about, all explained in README.md:
 * <ul>
 *   <li>AES-256 in GCM mode. GCM both encrypts and authenticates, so a modified
 *       token or a wrong passphrase fails loudly instead of returning garbage.</li>
 *   <li>The key is stretched from the caller's passphrase with PBKDF2-HMAC-SHA256
 *       ({@value #PBKDF2_ITERATIONS} iterations) using a fresh random salt, so no
 *       key file is required and two tokens for the same person never match.</li>
 *   <li>A fresh salt and a fresh IV are generated for every call, which is what
 *       makes repeated encryption of the same input non-repeating and safe.</li>
 * </ul>
 *
 * <p>Only the name and email are inside the encrypted blob; the salt and IV are
 * public by design and are not secret.
 */
public final class PiiCrypto {

    /** Rejects anything this class cannot handle, with a message fit to show a user. */
    public static final class PiiCryptoException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;

        PiiCryptoException(String message) {
            super(message);
        }

        PiiCryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static final int SALT_LENGTH_BYTES = 16;
    static final int IV_LENGTH_BYTES = 12;
    static final int TAG_LENGTH_BITS = 128;
    static final int KEY_LENGTH_BITS = 256;
    static final int PBKDF2_ITERATIONS = 210_000;

    static final byte TOKEN_VERSION = 1;
    static final byte PAYLOAD_VERSION = 1;

    static final int NAME_MAX_CHARS = 200;
    static final int EMAIL_MAX_CHARS = 254;
    static final int PASSPHRASE_MAX_CHARS = 1024;

    /** version + two 2 byte lengths + at least one byte for each of the two fields. */
    private static final int MIN_PAYLOAD_BYTES = 1 + 2 + 1 + 2 + 1;
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    /** Shortest possible token: version + salt + iv + a 16 byte tag with no plaintext. */
    private static final int MIN_CONTAINER_BYTES = 1 + SALT_LENGTH_BYTES + IV_LENGTH_BYTES + (TAG_LENGTH_BITS / 8);

    private static final SecureRandom RANDOM = new SecureRandom();

    private PiiCrypto() {
    }

    /**
     * Encrypts a name and email address into a single Base64 line.
     *
     * @param name        the person's name, 1-{@value #NAME_MAX_CHARS} characters
     * @param email       the email address, 1-{@value #EMAIL_MAX_CHARS} characters
     * @param passphrase  the secret to derive the key from; never {@code null} or empty
     * @return the encrypted record as one Base64 line, safe to store in a column or file
     */
    public static String encrypt(String name, String email, char[] passphrase) throws PiiCryptoException {
        requireValidName(name);
        requireValidEmail(email);
        requireValidPassphrase(passphrase);

        byte[] salt = randomBytes(SALT_LENGTH_BYTES);
        byte[] iv = randomBytes(IV_LENGTH_BYTES);
        SecretKey key = deriveKey(passphrase, salt);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(encodePayload(name, email));

            ByteBuffer container = ByteBuffer.allocate(1 + salt.length + iv.length + ciphertext.length);
            container.put(TOKEN_VERSION);
            container.put(salt);
            container.put(iv);
            container.put(ciphertext);
            return Base64.getEncoder().withoutPadding().encodeToString(container.array());
        } catch (GeneralSecurityException e) {
            throw new PiiCryptoException("encryption failed: " + describe(e), e);
        }
    }

    /**
     * Decrypts a token produced by {@link #encrypt} and returns the original values.
     *
     * @throws PiiCryptoException if the token is malformed, was produced by a different
     *         version of this code, or if the passphrase is wrong or the token was altered
     */
    public static PiiRecord decrypt(String token, char[] passphrase) throws PiiCryptoException {
        requireValidPassphrase(passphrase);
        if (token == null) {
            throw new PiiCryptoException("the encrypted text is missing");
        }

        byte[] container = decodeToken(token);
        if (container.length < MIN_CONTAINER_BYTES) {
            throw new PiiCryptoException("the encrypted text is too short to be one of our records");
        }

        ByteBuffer buffer = ByteBuffer.wrap(container);
        byte version = buffer.get();
        if (version != TOKEN_VERSION) {
            throw new PiiCryptoException(
                    "the encrypted text was written by an incompatible version (found format " + version + ")");
        }

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        buffer.get(salt);
        byte[] iv = new byte[IV_LENGTH_BYTES];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        SecretKey key = deriveKey(passphrase, salt);
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            plaintext = cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new PiiCryptoException(
                    "cannot open this record: the passphrase is wrong, or the encrypted text was altered", e);
        } catch (GeneralSecurityException e) {
            throw new PiiCryptoException("decryption failed: " + describe(e), e);
        }

        return decodePayload(plaintext);
    }

    // ---------------------------------------------------------------- validation

    static void requireValidName(String name) throws PiiCryptoException {
        if (name == null) {
            throw new PiiCryptoException("the name is missing");
        }
        if (name.isBlank()) {
            throw new PiiCryptoException("the name must not be empty");
        }
        if (name.length() > NAME_MAX_CHARS) {
            throw new PiiCryptoException("the name is longer than " + NAME_MAX_CHARS + " characters");
        }
        requireNoControlCharacters(name, "name");
    }

    /**
     * A deliberately shallow shape check: it catches obvious typos such as a missing
     * {@code @} or an embedded space. It is not an RFC 5322 parser and it accepts
     * non-ASCII addresses, because the encryption does not depend on the address being valid.
     */
    static void requireValidEmail(String email) throws PiiCryptoException {
        if (email == null) {
            throw new PiiCryptoException("the email address is missing");
        }
        if (email.length() > EMAIL_MAX_CHARS) {
            throw new PiiCryptoException("the email address is longer than " + EMAIL_MAX_CHARS + " characters");
        }
        requireNoControlCharacters(email, "email address");

        int firstAt = email.indexOf('@');
        if (firstAt < 0) {
            throw new PiiCryptoException("the email address must contain an '@'");
        }
        if (email.indexOf('@', firstAt + 1) >= 0) {
            throw new PiiCryptoException("the email address must contain exactly one '@'");
        }

        String localPart = email.substring(0, firstAt);
        String domain = email.substring(firstAt + 1);
        if (localPart.isEmpty()) {
            throw new PiiCryptoException("the email address has nothing before the '@'");
        }
        if (domain.isEmpty()) {
            throw new PiiCryptoException("the email address has nothing after the '@'");
        }
        if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.contains("..")) {
            throw new PiiCryptoException("the part of the email address before the '@' has a badly placed '.'");
        }
        for (int i = 0; i < localPart.length(); i++) {
            char c = localPart.charAt(i);
            if (c <= ' ' || "()<>[]:;,@\\\"".indexOf(c) >= 0) {
                throw new PiiCryptoException(
                        "the email address contains a character that plain addresses may not use: '" + c + "'");
            }
        }
        if (domain.startsWith(".") || domain.endsWith(".") || !domain.contains(".")) {
            throw new PiiCryptoException("the part of the email address after the '@' is not a valid host name");
        }
        // Every label must exist and must not start or end with a hyphen. Checking
        // per label covers "b-.com" and "-b.com", which a whole-domain check misses.
        for (String label : domain.split("\\.", -1)) {
            if (label.isEmpty() || label.startsWith("-") || label.endsWith("-")) {
                throw new PiiCryptoException("the part of the email address after the '@' is not a valid host name");
            }
        }
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c > 0x7F;
            if (!allowed) {
                throw new PiiCryptoException(
                        "the email address contains a character that host names may not use: '" + c + "'");
            }
        }
    }

    static void requireValidPassphrase(char[] passphrase) throws PiiCryptoException {
        if (passphrase == null || passphrase.length == 0) {
            throw new PiiCryptoException("a passphrase is required");
        }
        if (passphrase.length > PASSPHRASE_MAX_CHARS) {
            throw new PiiCryptoException("the passphrase is longer than " + PASSPHRASE_MAX_CHARS + " characters");
        }
        boolean hasVisibleCharacter = false;
        for (int i = 0; i < passphrase.length; i++) {
            char c = passphrase[i];
            if (c == 0) {
                // PBEKeySpec silently stops at a NUL, so "abc\0" and "abc" would
                // derive the same key. Refuse rather than keep two equal passphrases.
                throw new PiiCryptoException("the passphrase must not contain a NUL character");
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= passphrase.length || !Character.isLowSurrogate(passphrase[i + 1])) {
                    // An unpaired surrogate is turned into '?' by PBEKeySpec, which
                    // would let a different passphrase derive the same key.
                    throw new PiiCryptoException("the passphrase has a broken supplementary character");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new PiiCryptoException("the passphrase has a broken supplementary character");
            }
            if (!Character.isWhitespace(c)) {
                hasVisibleCharacter = true;
            }
        }
        if (!hasVisibleCharacter) {
            throw new PiiCryptoException("the passphrase must not be only whitespace");
        }
    }

    private static void requireNoControlCharacters(String value, String what) throws PiiCryptoException {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                throw new PiiCryptoException("the " + what + " contains a control character (code " + (int) c
                        + ") that must be removed");
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    throw new PiiCryptoException(loneSurrogateMessage(what));
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new PiiCryptoException(loneSurrogateMessage(what));
            }
        }
    }

    /**
     * UTF-8 encoding turns half of a supplementary character into a '?', so such a
     * value would not survive the round trip. Better to refuse it than to hand back
     * a name that quietly changed.
     */
    private static String loneSurrogateMessage(String what) {
        return "the " + what + " contains half of a multi-plane character, which cannot be stored safely";
    }

    // ------------------------------------------------------------------- payload

    /**
     * Packs both fields as {@code version | len | name | len | email}. The two byte
     * lengths are what make the framing exact: a name that itself contains a
     * separator such as {@code "|"} or an {@code @} cannot be mistaken for the email.
     *
     * <p>The 2 byte lengths cannot overflow: the character caps above bound a record
     * at just over 900 UTF-8 bytes even in the worst case of a four byte character
     * every two chars, and PiiCryptoTest asserts that margin so the caps cannot be
     * raised unnoticed.
     */
    private static byte[] encodePayload(String name, String email) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] emailBytes = email.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(1 + 2 + nameBytes.length + 2 + emailBytes.length);
        buffer.put(PAYLOAD_VERSION);
        buffer.putShort((short) nameBytes.length);
        buffer.put(nameBytes);
        buffer.putShort((short) emailBytes.length);
        buffer.put(emailBytes);
        return buffer.array();
    }

    private static PiiRecord decodePayload(byte[] plaintext) throws PiiCryptoException {
        ByteBuffer buffer = ByteBuffer.wrap(plaintext);
        if (buffer.remaining() < MIN_PAYLOAD_BYTES) {
            throw new PiiCryptoException("the decrypted record is too short to hold a name and an email address");
        }
        if (buffer.get() != PAYLOAD_VERSION) {
            throw new PiiCryptoException("the decrypted record uses an unsupported layout");
        }
        byte[] nameBytes = readLengthPrefixed(buffer, "name");
        byte[] emailBytes = readLengthPrefixed(buffer, "email address");
        if (buffer.hasRemaining()) {
            throw new PiiCryptoException("the decrypted record has unexpected trailing bytes");
        }
        return new PiiRecord(decodeUtf8(nameBytes, "name"), decodeUtf8(emailBytes, "email address"));
    }

    private static byte[] readLengthPrefixed(ByteBuffer buffer, String what) throws PiiCryptoException {
        if (buffer.remaining() < 2) {
            throw new PiiCryptoException("the decrypted record is truncated before the " + what);
        }
        int length = buffer.getShort() & 0xFFFF;
        if (length == 0 || length > buffer.remaining()) {
            throw new PiiCryptoException("the decrypted record has a corrupt length for the " + what);
        }
        byte[] field = new byte[length];
        buffer.get(field);
        return field;
    }

    private static String decodeUtf8(byte[] field, String what) throws PiiCryptoException {
        for (byte b : field) {
            if (b == 0) {
                throw new PiiCryptoException("the decrypted " + what + " contains a NUL character");
            }
        }
        String decoded;
        try {
            // Strict on purpose: CharsetDecoder.REPORT refuses bytes that are not
            // valid UTF-8, which the lenient new String(byte[], UTF_8) hides by
            // quietly substituting a replacement character.
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(field))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new PiiCryptoException("the decrypted " + what + " is not valid text", e);
        }
        if (decoded.indexOf((char) 0xFFFD) >= 0) {
            // Either written by a tool that already lost the original characters,
            // or tampered with. Refusing beats returning a mangled name.
            throw new PiiCryptoException("the decrypted " + what + " is not valid text");
        }
        return decoded;
    }

    // ------------------------------------------------------------- key and bytes

    private static SecretKey deriveKey(char[] passphrase, byte[] salt) throws PiiCryptoException {
        byte[] keyBytes;
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            keyBytes = factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new PiiCryptoException("could not derive a key from the passphrase: " + describe(e), e);
        } finally {
            spec.clearPassword();
        }
        // SecretKeySpec accepts any non-empty array and only fails later inside
        // Cipher.init, so the length is checked here where it can be explained.
        if (keyBytes.length != KEY_LENGTH_BITS / 8) {
            throw new PiiCryptoException(
                    "the passphrase produced a " + keyBytes.length + " byte key, expected " + KEY_LENGTH_BITS / 8);
        }
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] decodeToken(String token) throws PiiCryptoException {
        String trimmed = token.trim();
        if (trimmed.isEmpty()) {
            throw new PiiCryptoException("the encrypted text is empty");
        }
        if (trimmed.chars().anyMatch(Character::isWhitespace)) {
            throw new PiiCryptoException("the encrypted text must be a single unbroken line");
        }
        try {
            // The strict decoder rejects characters outside the Base64 alphabet.
            // Base64.getMimeDecoder() would silently throw them away instead.
            return Base64.getDecoder().decode(trimmed);
        } catch (IllegalArgumentException e) {
            throw new PiiCryptoException("the encrypted text is not valid Base64", e);
        }
    }

    private static String describe(Exception e) {
        return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
    }
}
