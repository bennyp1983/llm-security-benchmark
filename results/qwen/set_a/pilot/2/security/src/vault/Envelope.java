package vault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Binary container written by {@link AesGcmCipher}.
 *
 * <pre>
 * magic   4 B   "AVL1"
 * version 1 B
 * source  1 B   key provenance, see {@link KeySource}
 * alias   1+N B length-prefixed key name (max 64 bytes)
 * salt    1+N B PBKDF2 salt, 16 B for passphrase keys, absent otherwise
 * iter    4 B   PBKDF2 iteration count, 0 for keystore keys
 * iv     12 B   GCM nonce
 * body    ...   AES-GCM ciphertext followed by its 16-byte tag
 * </pre>
 *
 * Everything before the body is fed to GCM as additional authenticated data, so
 * the key a payload was sealed under and the KDF parameters used to rebuild it
 * are bound to the ciphertext.
 */
public final class Envelope {

    static final byte[] MAGIC = {'A', 'V', 'L', '1'};
    static final byte VERSION = 1;
    static final int IV_LENGTH = 12;
    static final int TAG_LENGTH = 16;
    static final int MAX_ALIAS_BYTES = 64;
    static final int MAX_SALT_LENGTH = 16;

    private final KeySource keySource;
    private final String alias;
    private final byte[] salt;
    private final int iterations;
    private final byte[] iv;
    private final byte[] ciphertext;

    Envelope(KeySource keySource, String alias, byte[] salt, int iterations, byte[] iv, byte[] ciphertext) {
        Objects.requireNonNull(keySource, "keySource");
        Objects.requireNonNull(alias, "alias");
        Objects.requireNonNull(salt, "salt");
        Objects.requireNonNull(iv, "iv");
        Objects.requireNonNull(ciphertext, "ciphertext");
        int aliasBytes = alias.getBytes(StandardCharsets.UTF_8).length;
        if (aliasBytes == 0 || aliasBytes > MAX_ALIAS_BYTES) {
            throw new VaultException("key alias must be 1-" + MAX_ALIAS_BYTES + " UTF-8 bytes, got " + aliasBytes);
        }
        if (iv.length != IV_LENGTH) {
            throw new VaultException("IV must be " + IV_LENGTH + " bytes, got " + iv.length);
        }
        if (keySource == KeySource.PASSPHRASE) {
            if (salt.length != MAX_SALT_LENGTH || iterations < 1) {
                throw new VaultException("passphrase keys require a " + MAX_SALT_LENGTH
                        + "-byte salt and a positive iteration count");
            }
        } else if (salt.length != 0 || iterations != 0) {
            throw new VaultException("keystore keys must not carry KDF parameters");
        }
        this.keySource = keySource;
        this.alias = alias;
        this.salt = salt.clone();
        this.iterations = iterations;
        this.iv = iv.clone();
        this.ciphertext = ciphertext.clone();
    }

    /** The authenticated prefix: everything up to and including the IV. */
    byte[] header() {
        byte[] aliasBytes = alias.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeByte(keySource.id());
            out.writeByte(aliasBytes.length);
            out.write(aliasBytes);
            out.writeByte(salt.length);
            out.write(salt);
            out.writeInt(iterations);
            out.write(iv);
        } catch (IOException impossible) {
            throw new VaultException("unable to serialise envelope header", impossible);
        }
        return bytes.toByteArray();
    }

    int headerLength() {
        int aliasBytes = alias.getBytes(StandardCharsets.UTF_8).length;
        return MAGIC.length + 1 + 1 + 1 + aliasBytes + 1 + salt.length + Integer.BYTES + IV_LENGTH;
    }

    /** Serialises the envelope for storage or transport: header, then ciphertext and tag. */
    public byte[] toBytes() {
        byte[] header = header();
        byte[] sealed = new byte[header.length + ciphertext.length];
        System.arraycopy(header, 0, sealed, 0, header.length);
        System.arraycopy(ciphertext, 0, sealed, header.length, ciphertext.length);
        return sealed;
    }

    /** Parses bytes produced by {@link #toBytes()}. Throws if they are not a valid envelope. */
    public static Envelope fromBytes(byte[] sealed) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(sealed))) {
            Envelope header = readHeader(in);
            byte[] body = new byte[in.available()];
            in.readFully(body);
            return new Envelope(header.keySource, header.alias, header.salt, header.iterations, header.iv, body);
        } catch (IOException truncated) {
            throw new VaultException("sealed payload is truncated or malformed", truncated);
        }
    }

    static Envelope readHeader(DataInputStream in) throws IOException {
        byte[] magic = new byte[MAGIC.length];
        in.readFully(magic);
        if (!Arrays.equals(MAGIC, magic)) {
            throw new VaultException("input is not a vault envelope");
        }
        byte version = in.readByte();
        if (version != VERSION) {
            throw new VaultException("unsupported envelope version " + version);
        }
        KeySource keySource = KeySource.fromId(in.readByte());
        int aliasLength = in.readUnsignedByte();
        if (aliasLength == 0 || aliasLength > MAX_ALIAS_BYTES) {
            throw new VaultException("invalid key alias length " + aliasLength);
        }
        byte[] aliasBytes = new byte[aliasLength];
        in.readFully(aliasBytes);
        int saltLength = in.readUnsignedByte();
        if (saltLength > MAX_SALT_LENGTH) {
            throw new VaultException("invalid salt length " + saltLength);
        }
        byte[] salt = new byte[saltLength];
        in.readFully(salt);
        int iterations = in.readInt();
        if (iterations < 0) {
            throw new VaultException("invalid PBKDF2 iteration count " + iterations);
        }
        byte[] iv = new byte[IV_LENGTH];
        in.readFully(iv);
        return new Envelope(keySource, new String(aliasBytes, StandardCharsets.UTF_8), salt, iterations, iv,
                new byte[0]);
    }

    public KeySource keySource() {
        return keySource;
    }

    public String alias() {
        return alias;
    }

    public byte[] salt() {
        return salt.clone();
    }

    public int iterations() {
        return iterations;
    }

    public byte[] iv() {
        return iv.clone();
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public String toString() {
        return "Envelope[keySource=" + keySource + ", alias=" + alias + ", iterations=" + iterations
                + ", ciphertextBytes=" + ciphertext.length + "]";
    }
}
