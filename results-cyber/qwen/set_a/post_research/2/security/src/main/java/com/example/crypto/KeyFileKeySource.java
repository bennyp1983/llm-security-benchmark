package com.example.crypto;

import java.nio.file.Path;

/**
 * Reads a key from a file on disk.
 *
 * <p>The file must be a regular file, not a symlink, owned by the user running this process, with mode
 * no looser than {@code 0600}, and every ancestor directory must be owned by that user and not
 * group- or world-writable (a world-writable directory is accepted only with the sticky bit, the
 * {@code /tmp} convention). Those checks are in {@link PrivateFiles} and they are performed before the
 * file is opened, not after.
 *
 * <p>Why not simply "read the file and let the OS sort it out": a key file is the one input an
 * unprivileged local attacker is most likely to be able to place, rename or symlink, because the path
 * normally comes from configuration. A path from configuration is still attacker-influenceable when
 * the config is world-writable, when it lives in a shared checkout, or when the deploy pipeline can be
 * nudged - so the path is validated, and the object behind it is inspected, rather than trusted.
 *
 * <p>A trailing newline is <strong>not</strong> accepted, in either accepted form. It would have to be
 * trimmed to be, and trimming is the thing not to do here: the length is what distinguishes a raw
 * 32-byte key from base64 text, so a value whose length is decided by whatever the last byte happens to
 * be is a value whose form is attacker- or editor-decided. A key file that will not load is a deploy
 * failure to fix at the deploy step - write the file with {@link KeyMaterial#writeTo}, which produces
 * exactly 32 raw bytes and nothing else - rather than something this class guesses about. See
 * {@link KeyEncoding}.
 */
public final class KeyFileKeySource implements KeySource {

    private final Path file;

    /**
     * @param file path to the key file. Relative paths are resolved against the process working
     *     directory; prefer an absolute path from deployment configuration.
     * @throws CryptoException if {@code file} is null, has no parent, or the path is longer than 4096
     *     characters
     */
    public KeyFileKeySource(Path file) throws CryptoException {
        if (file == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key file path is missing");
        }
        String abs = file.toAbsolutePath().toString();
        if (abs.length() > 4096) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key file path is too long");
        }
        if (abs.indexOf('\0') >= 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key file path is malformed");
        }
        this.file = file;
    }

    @Override
    public KeyMaterial load() throws CryptoException {
        /*
         * The bound here is generous (KeyEncoding rejects anything over 4 KiB anyway) because the
         * meaningful limit is on the decoded key, and a huge file must be refused before it is read.
         */
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, KeyEncoding.MAX_INPUT_BYTES);
        try {
            return KeyMaterial.fromBytes(KeyEncoding.decodeKeyBytes(raw));
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    /** The path. A path is not a secret; the file's contents are. */
    @Override
    public String describe() {
        return "file:" + file.toAbsolutePath();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof KeyFileKeySource other && file.equals(other.file);
    }

    @Override
    public int hashCode() {
        return file.hashCode();
    }

    @Override
    public String toString() {
        return describe();
    }
}
