package vault;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Sealing and opening with AES-256-GCM.
 *
 * <p>GCM is authenticated: a payload that was altered, truncated, or produced
 * under a different key fails the tag check instead of returning corrupted
 * plaintext. Every operation draws a fresh 12-byte nonce from
 * {@link SecureRandom} because reusing a nonce with the same key breaks both
 * confidentiality and the integrity guarantee.
 */
public final class AesGcmCipher {

    static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static final String KEY_ALGORITHM = "AES";
    private static final int TAG_BITS = 128;
    private static final int KEY_LENGTH_BITS = KeyVault.KEY_LENGTH_BITS;
    private static final int STREAM_BUFFER_BYTES = 1 << 16;

    private final SecureRandom random;

    public AesGcmCipher(SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    public static AesGcmCipher withSystemRandom() {
        return new AesGcmCipher(new SecureRandom());
    }

    public Envelope seal(SecretKey key, KeySource keySource, String alias, byte[] salt, int iterations,
            byte[] plaintext) {
        requireAes256(key);
        byte[] iv = new byte[Envelope.IV_LENGTH];
        random.nextBytes(iv);
        Envelope skeleton = new Envelope(keySource, alias, salt, iterations, iv, new byte[0]);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv), random);
            cipher.updateAAD(skeleton.header());
            return new Envelope(keySource, alias, salt, iterations, iv, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new VaultException("encryption failed", e);
        }
    }

    public byte[] open(SecretKey key, Envelope envelope) {
        requireAes256(key);
        byte[] body = envelope.ciphertext();
        if (body.length < Envelope.TAG_LENGTH) {
            throw new VaultException("sealed payload is shorter than the " + Envelope.TAG_LENGTH + "-byte GCM tag");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, envelope.iv()));
            cipher.updateAAD(envelope.header());
            return cipher.doFinal(body);
        } catch (AEADBadTagException e) {
            throw new VaultException("authentication failed: wrong key, or the payload/header was altered", e);
        } catch (GeneralSecurityException e) {
            throw new VaultException("decryption failed", e);
        }
    }

    public Envelope readEnvelopeHeader(Path sealedFile) {
        try (InputStream file = Files.newInputStream(sealedFile); DataInputStream in = new DataInputStream(file)) {
            return Envelope.readHeader(in);
        } catch (IOException e) {
            throw new VaultException("unable to read envelope header from " + sealedFile, e);
        }
    }

    /**
     * Streams {@code plaintextFile} into {@code sealedFile} without holding the whole
     * payload in memory. The result is assembled in a sibling temp file and moved into
     * place only once it is fully written.
     */
    public void sealToFile(SecretKey key, KeySource keySource, String alias, byte[] salt, int iterations,
            Path plaintextFile, Path sealedFile) {
        requireAes256(key);
        byte[] iv = new byte[Envelope.IV_LENGTH];
        random.nextBytes(iv);
        Envelope skeleton = new Envelope(keySource, alias, salt, iterations, iv, new byte[0]);
        Path partial = newPartialFile(sealedFile);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv), random);
            cipher.updateAAD(skeleton.header());
            try (OutputStream file = Files.newOutputStream(partial); InputStream in =
                    new BufferedInputStream(Files.newInputStream(plaintextFile))) {
                file.write(skeleton.header());
                pump(in, file, cipher);
            }
            moveIntoPlace(partial, sealedFile);
        } catch (GeneralSecurityException | IOException e) {
            deleteQuietly(partial);
            throw new VaultException("unable to seal " + plaintextFile, e);
        }
    }

    /**
     * Opens a sealed file. The plaintext is written to a staging file that is promoted to
     * {@code plaintextFile} only once the GCM tag verifies, so a tampered payload never
     * leaves unauthenticated plaintext at the destination path.
     */
    public void openToFile(SecretKey key, Envelope envelope, Path sealedFile, Path plaintextFile) {
        requireAes256(key);
        long bodyBytes;
        try {
            bodyBytes = Files.size(sealedFile) - envelope.headerLength();
        } catch (IOException e) {
            throw new VaultException("unable to size " + sealedFile, e);
        }
        if (bodyBytes < Envelope.TAG_LENGTH) {
            throw new VaultException("sealed file is shorter than the " + Envelope.TAG_LENGTH + "-byte GCM tag");
        }
        Path partial = newPartialFile(plaintextFile);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, envelope.iv()));
            cipher.updateAAD(envelope.header());
            try (InputStream in = new BufferedInputStream(Files.newInputStream(sealedFile));
                    OutputStream out = Files.newOutputStream(partial)) {
                skipFully(in, envelope.headerLength());
                byte[] tail = new byte[(int) bodyBytes];
                readFully(in, tail);
                out.write(cipher.doFinal(tail));
                Arrays.fill(tail, (byte) 0);
            }
            moveIntoPlace(partial, plaintextFile);
        } catch (AEADBadTagException e) {
            deleteQuietly(partial);
            throw new VaultException("authentication failed: wrong key, or the payload/header was altered", e);
        } catch (GeneralSecurityException | IOException e) {
            deleteQuietly(partial);
            throw new VaultException("unable to open " + sealedFile, e);
        }
    }

    private static void pump(InputStream in, OutputStream out, Cipher cipher)
            throws IOException, GeneralSecurityException {
        byte[] buffer = new byte[STREAM_BUFFER_BYTES];
        try {
            int read;
            while ((read = in.read(buffer)) > 0) {
                byte[] piece = cipher.update(buffer, 0, read);
                if (piece != null && piece.length > 0) {
                    out.write(piece);
                }
            }
            byte[] tail = cipher.doFinal();
            if (tail != null && tail.length > 0) {
                out.write(tail);
            }
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    private static void readFully(InputStream in, byte[] target) throws IOException {
        int offset = 0;
        while (offset < target.length) {
            int read = in.read(target, offset, target.length - offset);
            if (read < 0) {
                throw new VaultException("sealed file is truncated: " + (target.length - offset)
                        + " bytes missing");
            }
            offset += read;
        }
    }

    private static void requireAes256(SecretKey key) {
        if (key == null) {
            throw new VaultException("no key supplied");
        }
        if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
            throw new VaultException("expected an AES key but received " + key.getAlgorithm());
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new VaultException("key has been destroyed and can no longer be used");
        }
        try {
            if (encoded.length != KEY_LENGTH_BITS / 8) {
                throw new VaultException("expected a " + KEY_LENGTH_BITS + "-bit AES key but got "
                        + encoded.length * 8 + "-bit");
            }
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static void skipFully(InputStream in, long bytes) throws IOException {
        long remaining = bytes;
        byte[] sink = new byte[256];
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                int read = in.read(sink, 0, (int) Math.min(sink.length, remaining));
                if (read < 0) {
                    throw new VaultException("sealed file is shorter than its header");
                }
                remaining -= read;
            } else {
                remaining -= skipped;
            }
        }
    }

    private static Path newPartialFile(Path target) {
        Path absolute = target.toAbsolutePath();
        Path parent = absolute.getParent();
        try {
            Files.createDirectories(parent);
            Path partial = Files.createTempFile(parent, absolute.getFileName() + "-", ".part");
            FilePermissions.restrictToOwner(partial);
            return partial;
        } catch (IOException e) {
            throw new VaultException("unable to create a staging file beside " + target, e);
        }
    }

    /**
     * Publishes the staging file and tightens it to owner-only. Both the sealed output and the
     * recovered plaintext derive from sensitive material, so neither is left group/world
     * readable the way a default-umask create would leave it.
     */
    private static void moveIntoPlace(Path partial, Path target) throws IOException {
        try {
            Files.move(partial, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(partial, target, StandardCopyOption.REPLACE_EXISTING);
        }
        FilePermissions.restrictToOwner(target);
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // best effort cleanup of an unauthenticated staging file
        }
    }
}
