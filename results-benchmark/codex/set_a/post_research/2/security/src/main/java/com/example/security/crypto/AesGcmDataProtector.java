package com.example.security.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

/**
 * Dependency-free, thread-safe authenticated encryption for application data.
 *
 * <p>Instances own defensive copies of all key material and must be closed.
 * Callers retain ownership of input and returned arrays and should erase
 * sensitive arrays as soon as they are no longer needed.</p>
 */
public final class AesGcmDataProtector implements AutoCloseable {
    private static final byte[] MAGIC = {'D', 'P', 'E', '1'};
    private static final byte VERSION = 1;
    private static final byte ALGORITHM_AES_256_GCM = 1;
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int AES_KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / Byte.SIZE;
    private static final int FIXED_HEADER_BYTES = MAGIC.length + 3 + NONCE_BYTES;
    private static final int MAX_KEY_ID_BYTES = 64;
    private static final int MAX_KEYS = 32;
    private static final int MAX_PURPOSE_BYTES = 64;
    private static final int MAX_CONTEXT_BYTES = 64 * 1024;
    private static final int MAX_ALLOWED_PLAINTEXT_BYTES = 16 * 1024 * 1024;
    // NIST's limit for independently generated random GCM IVs under one key.
    private static final long MAX_ENCRYPTIONS_PER_KEY = 0xffff_ffffL;
    private static final Pattern SAFE_IDENTIFIER =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._/-]{0,63}");

    private final Map<String, KeyEntry> keys;
    private final String activeKeyId;
    private final byte[] purpose;
    private final int maxPlaintextBytes;
    private final SecureRandom random;
    private final byte[] unknownKey;
    private final ReentrantReadWriteLock lifecycleLock = new ReentrantReadWriteLock();
    private boolean closed;

    private AesGcmDataProtector(
            Map<String, byte[]> suppliedKeys,
            String suppliedActiveKeyId,
            String suppliedPurpose,
            int suppliedMaxPlaintextBytes) {
        validateIdentifier(suppliedActiveKeyId, "active key identifier");
        validateIdentifier(suppliedPurpose, "purpose");
        if (suppliedMaxPlaintextBytes < 1
                || suppliedMaxPlaintextBytes > MAX_ALLOWED_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("Plaintext size limit is outside the allowed range");
        }
        if (suppliedKeys == null || suppliedKeys.isEmpty() || suppliedKeys.size() > MAX_KEYS) {
            throw new IllegalArgumentException("Key ring size is outside the allowed range");
        }

        Map<String, KeyEntry> copied = new LinkedHashMap<>();
        SecureRandom createdRandom = null;
        byte[] createdUnknownKey = null;
        try {
            for (Map.Entry<String, byte[]> supplied : suppliedKeys.entrySet()) {
                if (copied.size() >= MAX_KEYS) {
                    throw new IllegalArgumentException("Key ring size is outside the allowed range");
                }
                if (supplied == null) {
                    throw new IllegalArgumentException("Key ring entries must not be null");
                }
                String id = supplied.getKey();
                validateIdentifier(id, "key identifier");
                byte[] key = supplied.getValue();
                if (key == null || key.length != AES_KEY_BYTES) {
                    throw new IllegalArgumentException("Every key must be exactly 256 bits");
                }
                if (copied.containsKey(id)) {
                    throw new IllegalArgumentException("Key identifiers must be unique");
                }
                for (KeyEntry existing : copied.values()) {
                    if (MessageDigest.isEqual(existing.bytes, key)) {
                        throw new IllegalArgumentException(
                                "Each key identifier must have distinct key material");
                    }
                }
                copied.put(id, new KeyEntry(key.clone()));
            }
            if (!copied.containsKey(suppliedActiveKeyId)) {
                throw new IllegalArgumentException("Active key must exist in the key ring");
            }
            // Initialize fallible provider state while copied keys are still under
            // this constructor's failure-cleanup guard.
            createdRandom = new SecureRandom();
            createdUnknownKey = new byte[AES_KEY_BYTES];
            createdRandom.nextBytes(createdUnknownKey);
        } catch (RuntimeException failure) {
            copied.values().forEach(KeyEntry::destroy);
            if (createdUnknownKey != null) {
                Arrays.fill(createdUnknownKey, (byte) 0);
            }
            throw failure;
        }

        this.keys = Collections.unmodifiableMap(copied);
        this.activeKeyId = suppliedActiveKeyId;
        this.purpose = suppliedPurpose.getBytes(StandardCharsets.US_ASCII);
        this.maxPlaintextBytes = suppliedMaxPlaintextBytes;
        this.random = createdRandom;
        this.unknownKey = createdUnknownKey;
    }

    /**
     * Creates a protector by defensively copying raw AES-256 keys.
     *
     * @param keys trusted server-side key IDs mapped to 32-byte random AES keys
     * @param activeKeyId trusted server-side ID used only for new encryption
     * @param purpose stable, non-secret domain separator for this data type
     * @param maxPlaintextBytes accepted size limit from 1 byte through 16 MiB
     */
    public static AesGcmDataProtector create(
            Map<String, byte[]> keys,
            String activeKeyId,
            String purpose,
            int maxPlaintextBytes) {
        return new AesGcmDataProtector(keys, activeKeyId, purpose, maxPlaintextBytes);
    }

    /** Generates a new runtime AES-256 key. The caller owns and must erase it. */
    public static byte[] generateKey() {
        byte[] key = new byte[AES_KEY_BYTES];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /** Encrypts and authenticates plaintext plus its caller-supplied context. */
    public byte[] encrypt(byte[] plaintext, byte[] context) throws DataProtectionException {
        validateOperationInput(plaintext, maxPlaintextBytes);
        validateContext(context);

        lifecycleLock.readLock().lock();
        try {
            ensureOpen();
            KeyEntry entry = keys.get(activeKeyId);
            if (!entry.reserveEncryption()) {
                throw new DataProtectionException();
            }

            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            byte[] keyId = activeKeyId.getBytes(StandardCharsets.US_ASCII);
            byte[] header = makeHeader(keyId, nonce);
            DestroyableAesKey operationKey = new DestroyableAesKey(entry.copyBytes());
            try {
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, operationKey,
                        new GCMParameterSpec(TAG_BITS, nonce));
                addAuthenticatedData(cipher, header, context);
                byte[] sealed = cipher.doFinal(plaintext);
                try {
                    byte[] envelope = new byte[header.length + sealed.length];
                    System.arraycopy(header, 0, envelope, 0, header.length);
                    System.arraycopy(sealed, 0, envelope, header.length, sealed.length);
                    return envelope;
                } finally {
                    Arrays.fill(sealed, (byte) 0);
                }
            } catch (GeneralSecurityException | RuntimeException failure) {
                throw new DataProtectionException();
            } finally {
                operationKey.destroy();
                Arrays.fill(nonce, (byte) 0);
            }
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    /**
     * Authenticates and decrypts an envelope. Every attacker-visible failure has
     * the same exception type and message.
     */
    public byte[] decrypt(byte[] envelope, byte[] context) throws DataProtectionException {
        validateContext(context);
        if (envelope == null
                || envelope.length < FIXED_HEADER_BYTES + 1 + TAG_BYTES
                || envelope.length > FIXED_HEADER_BYTES + MAX_KEY_ID_BYTES
                        + TAG_BYTES + maxPlaintextBytes) {
            throw new DataProtectionException();
        }

        lifecycleLock.readLock().lock();
        try {
            ensureOpen();
            ParsedEnvelope parsed = parseEnvelope(envelope);
            KeyEntry knownEntry = keys.get(parsed.keyId);
            boolean knownKey = knownEntry != null;
            byte[] operationBytes = knownKey ? knownEntry.copyBytes() : unknownKey.clone();
            DestroyableAesKey operationKey = new DestroyableAesKey(operationBytes);
            byte[] plaintext = null;
            try {
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, operationKey,
                        new GCMParameterSpec(TAG_BITS, parsed.nonce));
                addAuthenticatedData(cipher, parsed.header, context);
                plaintext = cipher.doFinal(envelope, parsed.header.length,
                        envelope.length - parsed.header.length);
                if (!knownKey || plaintext.length > maxPlaintextBytes) {
                    Arrays.fill(plaintext, (byte) 0);
                    throw new DataProtectionException();
                }
                return plaintext;
            } catch (DataProtectionException failure) {
                throw failure;
            } catch (GeneralSecurityException | RuntimeException failure) {
                if (plaintext != null) {
                    Arrays.fill(plaintext, (byte) 0);
                }
                throw new DataProtectionException();
            } finally {
                operationKey.destroy();
                parsed.destroy();
            }
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    /** Erases the component's in-memory key copies after current operations finish. */
    @Override
    public void close() {
        lifecycleLock.writeLock().lock();
        try {
            if (!closed) {
                keys.values().forEach(KeyEntry::destroy);
                Arrays.fill(unknownKey, (byte) 0);
                Arrays.fill(purpose, (byte) 0);
                closed = true;
            }
        } finally {
            lifecycleLock.writeLock().unlock();
        }
    }

    private ParsedEnvelope parseEnvelope(byte[] envelope) throws DataProtectionException {
        try {
            ByteBuffer input = ByteBuffer.wrap(envelope).asReadOnlyBuffer();
            byte[] magic = new byte[MAGIC.length];
            input.get(magic);
            boolean validMagic = MessageDigest.isEqual(MAGIC, magic);
            Arrays.fill(magic, (byte) 0);
            if (!validMagic || input.get() != VERSION
                    || input.get() != ALGORITHM_AES_256_GCM) {
                throw new DataProtectionException();
            }
            int keyIdLength = Byte.toUnsignedInt(input.get());
            if (keyIdLength < 1 || keyIdLength > MAX_KEY_ID_BYTES
                    || input.remaining() < keyIdLength + NONCE_BYTES + TAG_BYTES) {
                throw new DataProtectionException();
            }
            byte[] keyIdBytes = new byte[keyIdLength];
            input.get(keyIdBytes);
            String keyId = new String(keyIdBytes, StandardCharsets.US_ASCII);
            Arrays.fill(keyIdBytes, (byte) 0);
            if (!SAFE_IDENTIFIER.matcher(keyId).matches()) {
                throw new DataProtectionException();
            }
            byte[] nonce = new byte[NONCE_BYTES];
            input.get(nonce);
            int headerLength = FIXED_HEADER_BYTES + keyIdLength;
            return new ParsedEnvelope(keyId, nonce,
                    Arrays.copyOfRange(envelope, 0, headerLength));
        } catch (DataProtectionException failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw new DataProtectionException();
        }
    }

    private byte[] makeHeader(byte[] keyId, byte[] nonce) {
        ByteBuffer header = ByteBuffer.allocate(FIXED_HEADER_BYTES + keyId.length);
        header.put(MAGIC).put(VERSION).put(ALGORITHM_AES_256_GCM)
                .put((byte) keyId.length).put(keyId).put(nonce);
        return header.array();
    }

    private void addAuthenticatedData(Cipher cipher, byte[] header, byte[] context) {
        cipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(purpose.length).array());
        cipher.updateAAD(purpose);
        cipher.updateAAD(header);
        cipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(context.length).array());
        cipher.updateAAD(context);
    }

    private void ensureOpen() throws DataProtectionException {
        if (closed) {
            throw new DataProtectionException();
        }
    }

    private static void validateOperationInput(byte[] value, int maximum)
            throws DataProtectionException {
        if (value == null || value.length > maximum) {
            throw new DataProtectionException();
        }
    }

    private static void validateContext(byte[] context) throws DataProtectionException {
        if (context == null || context.length > MAX_CONTEXT_BYTES) {
            throw new DataProtectionException();
        }
    }

    private static void validateIdentifier(String value, String label) {
        if (value == null || !SAFE_IDENTIFIER.matcher(value).matches()
                || value.getBytes(StandardCharsets.US_ASCII).length > MAX_PURPOSE_BYTES) {
            throw new IllegalArgumentException("Invalid " + label);
        }
    }

    private static final class KeyEntry {
        private final byte[] bytes;
        private final AtomicLong encryptionCount = new AtomicLong();

        private KeyEntry(byte[] bytes) {
            this.bytes = bytes;
        }

        private boolean reserveEncryption() {
            long current;
            do {
                current = encryptionCount.get();
                if (current >= MAX_ENCRYPTIONS_PER_KEY) {
                    return false;
                }
            } while (!encryptionCount.compareAndSet(current, current + 1));
            return true;
        }

        private byte[] copyBytes() {
            return bytes.clone();
        }

        private void destroy() {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static final class ParsedEnvelope {
        private final String keyId;
        private final byte[] nonce;
        private final byte[] header;

        private ParsedEnvelope(String keyId, byte[] nonce, byte[] header) {
            this.keyId = keyId;
            this.nonce = nonce;
            this.header = header;
        }

        private void destroy() {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(header, (byte) 0);
        }
    }

    /** A non-serializable operation-scoped key whose owned bytes can be erased. */
    private static final class DestroyableAesKey implements SecretKey {
        private static final long serialVersionUID = 1L;
        private byte[] bytes;

        private DestroyableAesKey(byte[] ownedBytes) {
            this.bytes = Objects.requireNonNull(ownedBytes);
        }

        @Override
        public String getAlgorithm() {
            return "AES";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public synchronized byte[] getEncoded() {
            if (bytes == null) {
                throw new IllegalStateException("Key is unavailable");
            }
            return bytes.clone();
        }

        @Override
        public synchronized void destroy() {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
                bytes = null;
            }
        }

        @Override
        public synchronized boolean isDestroyed() {
            return bytes == null;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof SecretKey)) {
                return false;
            }
            byte[] mine = getEncoded();
            byte[] theirs = ((SecretKey) other).getEncoded();
            try {
                return theirs != null && MessageDigest.isEqual(mine, theirs);
            } finally {
                Arrays.fill(mine, (byte) 0);
                if (theirs != null) {
                    Arrays.fill(theirs, (byte) 0);
                }
            }
        }

        @Override
        public synchronized int hashCode() {
            if (bytes == null) {
                return 0;
            }
            return Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return "DestroyableAesKey[redacted]";
        }

        private void writeObject(ObjectOutputStream stream) throws IOException {
            throw new NotSerializableException("Secret keys cannot be serialized");
        }
    }
}
