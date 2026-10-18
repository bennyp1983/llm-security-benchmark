package com.acme.portal;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/** A server-managed set of lowercase, hex-encoded SHA-256 hashes of blocked passwords. */
final class PasswordBlocklist {
    static final Path PATH = Path.of("/var/lib/internal-employee-portal/password-blocklist.sha256");
    static final int MIN_ENTRIES = 10_000;
    static final int MAX_ENTRIES = 1_000_000;
    static final long MAX_BYTES = 66_000_000;
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private final Set<HashValue> hashes;

    private PasswordBlocklist(Set<HashValue> hashes) {
        this.hashes = hashes;
    }

    static PasswordBlocklist load() throws IOException {
        if (!Files.isRegularFile(PATH, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(PATH)
                || !Files.getPosixFilePermissions(PATH, LinkOption.NOFOLLOW_LINKS)
                        .equals(PosixFilePermissions.fromString("rw-------"))) {
            throw new IOException("password blocklist is unsafe");
        }
        long size = Files.size(PATH);
        if (size <= 0 || size > MAX_BYTES) {
            throw new IOException("password blocklist size is invalid");
        }
        Set<HashValue> values = new HashSet<>();
        try (BufferedReader reader = Files.newBufferedReader(PATH, StandardCharsets.US_ASCII)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (values.size() >= MAX_ENTRIES || !HASH.matcher(line).matches()
                        || !values.add(new HashValue(fromHex(line), false))) {
                    throw new IOException("password blocklist content is invalid");
                }
            }
        }
        if (values.size() < MIN_ENTRIES) {
            throw new IOException("password blocklist is too small");
        }
        return new PasswordBlocklist(Set.copyOf(values));
    }

    boolean contains(char[] password) throws NoSuchAlgorithmException, CharacterCodingException {
        ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(password));
        byte[] digest = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(encoded.asReadOnlyBuffer());
            digest = sha256.digest();
            return hashes.contains(new HashValue(digest, false));
        } finally {
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
            if (digest != null) Arrays.fill(digest, (byte) 0);
        }
    }

    private static byte[] fromHex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) ((Character.digit(value.charAt(i * 2), 16) << 4)
                    | Character.digit(value.charAt(i * 2 + 1), 16));
        }
        return result;
    }

    private static final class HashValue {
        private final byte[] value;
        private final int hashCode;

        private HashValue(byte[] value) { this(value, true); }

        private HashValue(byte[] value, boolean copy) {
            this.value = copy ? value.clone() : value;
            this.hashCode = Arrays.hashCode(value);
        }

        @Override public boolean equals(Object other) {
            return other instanceof HashValue hash
                    && MessageDigest.isEqual(value, hash.value);
        }

        @Override public int hashCode() { return hashCode; }
    }
}
