# Security Review: secure-data-crypto

## 1. Executive Summary
The `secure-data-crypto` component is a zero-dependency Java 17 library designed for authenticated symmetric data encryption (AES-256-GCM) with key lifecycle management, including key rotation, PBKDF2-wrapped keys, PKCS#12 keystore integration, environment variable key loading, POSIX file permissions checking, and strict input validation.

A static security review of the codebase identified seven findings spanning High, Medium, and Low severities. The most critical issues are:
1. **Broken Key Rotation in File and Environment Sources (High, CWE-320):** `KeyFileKeySource` and `EnvKeySource` hardcode loaded key versions to `1` and provide no mechanism to configure a key version. When integrated with `KeyVault`, invoking `vault.rotate()` immediately causes subsequent encryption and decryption operations to fail due to version mismatch rejections.
2. **Directory Ancestry Ownership Check Forces Execution as Root (High, CWE-250):** `PrivateFiles.requireSecureDirectory` mandates that every directory ancestor up to the filesystem root `/` be owned by the running process user (`user.name`). Because standard Unix/Linux system directories (`/home`, `/tmp`, `/var`, `/etc`) are owned by `root`, non-root application execution fails whenever keys are stored in standard locations, effectively forcing execution as root.
3. **Time-of-Check to Time-of-Use (TOCTOU) Symlink Following in File Reading (Medium, CWE-367):** `PrivateFiles.readOwnerOnlyFile` checks file permissions via `LinkOption.NOFOLLOW_LINKS`, but subsequently uses `Files.size` and `Files.readAllBytes`, which follow symlinks. An attacker racing in a shared directory can replace the file with a named pipe or device, causing indefinite blocking or out-of-memory denial of service.
4. **Uncleared Sensitive Key Material in Memory (Medium, CWE-226):** `EnvKeySource.load()` fails to wipe the raw key byte array derived from environment variables in a `finally` block, leaving plaintext key material uncleared on the JVM heap.

Additional lower-severity findings include immutable string creation of secret keys during base64 decoding (CWE-316), lack of synchronization during passphrase destruction causing data races (CWE-362), and a race condition during `KeyVault.encrypt` between reading the active version and resolving its source (CWE-362).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/crypto/CryptoException.java` | Component exception model | Sanitizes exception messages, disables stack traces and suppression, keeps technical details transient to prevent secret/path leakage. |
| `src/main/java/com/example/crypto/EncryptedBlob.java` | Encrypted record container and parser | Enforces record format `v1.<b64>[.<context>]`, validates canonical base64url encoding, parses header fields, binds context to AAD. |
| `src/main/java/com/example/crypto/EnvKeySource.java` | KeySource loading keys from environment variables | Validates environment variable names with regex, decodes key bytes, lacks byte array erasure in `finally`. |
| `src/main/java/com/example/crypto/KeyEncoding.java` | Key format decoder and canonical encoder | Validates 32-byte raw or canonical base64url keys; instantiates immutable `String` objects holding key material during decoding. |
| `src/main/java/com/example/crypto/KeyFileKeySource.java` | KeySource reading raw or base64 keys from disk | Enforces owner-private file checks via `PrivateFiles`; hardcodes key version to 1, preventing rotation. |
| `src/main/java/com/example/crypto/KeyMaterial.java` | In-memory key material holder | Holds 256-bit AES key in byte array, provides `use` callback with automatic working array zeroing, implements idempotent destruction. |
| `src/main/java/com/example/crypto/KeySource.java` | Interface for key providers | Defines interface requiring fresh `load()` per operation and secret-free `describe()`. |
| `src/main/java/com/example/crypto/KeystoreKeySource.java` | KeySource loading AES keys from PKCS#12 keystores | Handles PKCS#12 keystore creation and reading with `0600` creation attributes, validates passphrases; `load()` is unsynchronized. |
| `src/main/java/com/example/crypto/KeyVault.java` | Key versioning, routing, and rotation manager | Manages active version, key rotation, version capping (64), decoy sources for unissued versions to eliminate timing/existence oracles. |
| `src/main/java/com/example/crypto/Limits.java` | Hardcoded bounds and input validators | Enforces bounds on plaintext size (1 MiB), context length (200 ASCII chars), KDF iteration range (310k-2M), and payload byte sizes. |
| `src/main/java/com/example/crypto/PasswordKeySource.java` | PBKDF2-derived KEK wrapped key store | Generates and reads AES-256-GCM wrapped key containers using PBKDF2-HMAC-SHA256, binds header to AAD; `load()` is unsynchronized. |
| `src/main/java/com/example/crypto/PrivateFiles.java` | Filesystem permission and access security checks | Enforces atomic creation (`CREATE_NEW`, `0600`), symlink rejection, ancestor directory mode/owner checks, and TOCTOU inode checks. |
| `src/main/java/com/example/crypto/RandomPasswords.java` | High-entropy random secret generator | Generates high-entropy passwords (default 48 chars) using `SecureRandom` over 94 printable ASCII characters, returns mutable `char[]`. |
| `src/main/java/com/example/crypto/SymmetricCrypto.java` | Core AES-256-GCM encryption/decryption engine | Enforces AES-256-GCM, fresh 96-bit random nonces, 128-bit tags, full header and context binding in AAD, constant-work failure paths. |
| `pom.xml` | Maven build definition | Pins JDK 17 compiler release and test-scoped JUnit dependency; zero third-party runtime dependencies. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit AES-256-GCM cipher configuration, key sizes (256 bits), nonce uniqueness and CSPRNG usage via `SecureRandom`, AAD binding integrity, and PBKDF2/PKCS#12 parameter limits.
- General OWASP Top 10 / CWE knowledge (specifically OWASP A01:2021 Broken Access Control, A02:2021 Cryptographic Failures, A04:2021 Insecure Design, A05:2021 Security Misconfiguration; CWE-226, CWE-250, CWE-316, CWE-320, CWE-324, CWE-362, CWE-367, CWE-732): Applied to review POSIX filesystem permissions and directory traversal validation, TOCTOU race conditions in file opening and reading, key lifecycle and rotation management in KeyVault, heap memory hygiene and array wiping, and thread synchronization under concurrent access.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hardcoded Key Version in KeyFileKeySource and EnvKeySource Prevents Key Rotation | High | CWE-320 | `src/main/java/com/example/crypto/KeyFileKeySource.java:60` |
| SEC-02 | Directory Ancestry Ownership Verification Forces Execution as Root | High | CWE-250 | `src/main/java/com/example/crypto/PrivateFiles.java:291-293` |
| SEC-03 | Time-of-Check to Time-of-Use (TOCTOU) and Unsafe Symlink Following in Key File Reading | Medium | CWE-367 | `src/main/java/com/example/crypto/PrivateFiles.java:144-151` |
| SEC-04 | Sensitive Key Material Left Uncleared in Heap Memory in EnvKeySource | Medium | CWE-226 | `src/main/java/com/example/crypto/EnvKeySource.java:69-80` |
| SEC-05 | Creation and Retention of Secret Key Material as Immutable Strings in KeyEncoding | Low | CWE-316 | `src/main/java/com/example/crypto/KeyEncoding.java:70-81` |
| SEC-06 | Data Race on Passphrase Arrays During Concurrent Key Loading and Destruction | Low | CWE-362 | `src/main/java/com/example/crypto/PasswordKeySource.java:208-216` |
| SEC-07 | Race Condition in KeyVault.encrypt Between Version Retrieval and Source Resolution | Low | CWE-362 | `src/main/java/com/example/crypto/KeyVault.java:257-258` |

## 5. Detailed Findings

### SEC-01: Hardcoded Key Version in KeyFileKeySource and EnvKeySource Prevents Key Rotation
- **Severity:** High
- **CWE:** CWE-320: Key Management Errors
- **Location:** `src/main/java/com/example/crypto/KeyFileKeySource.java:60`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyFileKeySource.java:58-64
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, KeyEncoding.MAX_INPUT_BYTES);
        try {
            return KeyMaterial.fromBytes(KeyEncoding.decodeKeyBytes(raw));
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
```

**Why it is a problem:** `KeyFileKeySource.load()` and `EnvKeySource.load()` (at `EnvKeySource.java:75`) invoke `KeyMaterial.fromBytes(...)` which hardcodes the key version to `EncryptedBlob.MIN_KEY_VERSION` (1). Neither class provides a constructor or parameter allowing callers to specify the version this source represents. When a caller registers a key factory in `KeyVault` (as demonstrated in `README.md` line 21: `new KeyVault(v -> new KeyFileKeySource(Path.of("/etc/app/keys/v" + v + ".key")), 1)`), invoking `vault.rotate()` increments the active version to 2. However, when `vault.encrypt(...)` or `vault.decrypt(...)` is subsequently executed, line 262/338 of `KeyVault.java` checks `if (key.version() != version)` and throws `CryptoException(CryptoFailureCode.INVALID_KEY, "key source for version 2 reported version 1")`. Consequently, key rotation cannot function with file or environment-based key sources.

**Fix:** Add constructors accepting `keyVersion` to both `KeyFileKeySource` and `EnvKeySource`, defaulting to 1 when omitted, and pass `keyVersion` to `KeyMaterial.fromBytes(bytes, keyVersion)`.
```java
package com.example.crypto;

import java.nio.file.Path;

public final class KeyFileKeySource implements KeySource {

    private final Path file;
    private final int keyVersion;

    public KeyFileKeySource(Path file) throws CryptoException {
        this(file, EncryptedBlob.MIN_KEY_VERSION);
    }

    public KeyFileKeySource(Path file, int keyVersion) throws CryptoException {
        if (file == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key file path is missing");
        }
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        String abs = file.toAbsolutePath().toString();
        if (abs.length() > 4096) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key file path is too long");
        }
        if (abs.indexOf('\0') >= 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key file path is malformed");
        }
        this.file = file;
        this.keyVersion = keyVersion;
    }

    @Override
    public KeyMaterial load() throws CryptoException {
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, KeyEncoding.MAX_INPUT_BYTES);
        try {
            return KeyMaterial.fromBytes(KeyEncoding.decodeKeyBytes(raw), keyVersion);
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    @Override
    public String describe() {
        return "file:" + file.toAbsolutePath() + "@" + keyVersion;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof KeyFileKeySource other && file.equals(other.file) && keyVersion == other.keyVersion;
    }

    @Override
    public int hashCode() {
        return 31 * file.hashCode() + keyVersion;
    }

    @Override
    public String toString() {
        return describe();
    }
}
```

---

### SEC-02: Directory Ancestry Ownership Verification Forces Execution as Root
- **Severity:** High
- **CWE:** CWE-250: Execution with Unnecessary Privileges
- **Location:** `src/main/java/com/example/crypto/PrivateFiles.java:291-293`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PrivateFiles.java:291-293
            if (!isRoot) {
                requireOwns(component, "key file directory");
            }
```

**Why it is a problem:** In `PrivateFiles.requireSecureDirectory`, the method iterates up the directory tree to the filesystem root to ensure directory security. At line 267, `boolean isRoot = component.getParent() == null;` is true exclusively for the root directory `/`. For every intermediate directory component between the key file and `/` (such as `/home/appuser`, `/home`, or `/tmp`), line 291-292 executes `requireOwns(component, "key file directory")`. Because standard Unix system directories like `/home`, `/tmp`, `/var`, and `/etc` are owned by `root`, any application running as a standard, non-root user (e.g. `user.name = "appuser"`) throws `INSECURE_KEY_STORAGE` ("key file directory is owned by root, not by the running user appuser"). This effectively forces the application to be run as `root` to store or read key files, violating the principle of least privilege and breaking standard deployment architectures.

**Fix:** Relax the ownership requirement for system-level root-owned directories. Verify that non-root users own their directory path down to system directories, and for directories owned by `root` (such as `/home` or `/tmp`), verify that they are not writable by others without the sticky bit rather than requiring the process user to own them.
```java
            if (!isRoot) {
                String owner = attrs.owner().getName();
                boolean isSystemRootOwned = "root".equals(owner);
                if (!isSystemRootOwned) {
                    requireOwns(component, "key file directory");
                }
            }
```

---

### SEC-03: Time-of-Check to Time-of-Use (TOCTOU) and Unsafe Symlink Following in Key File Reading
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/crypto/PrivateFiles.java:144-151`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PrivateFiles.java:144-151
        byte[] out;
        try {
            long size = Files.size(file);
            if (size > maxBytes) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                        "key file is larger than " + maxBytes + " bytes");
            }
            out = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key file could not be read", e);
        }
```

**Why it is a problem:** `requirePrivateKeyFile(file)` performs validation using `LinkOption.NOFOLLOW_LINKS` to ensure the file is a regular, owner-private file and not a symlink. However, lines 144-151 subsequently call `Files.size(file)` and `Files.readAllBytes(file)`. `Files.readAllBytes(Path)` resolves paths by following symbolic links. In a shared parent directory (such as `/tmp`), a race condition exists: if a competing local process replaces `file` with a symlink to a FIFO/named pipe or character device (e.g. `/dev/urandom`), `Files.readAllBytes` will read from that target, blocking indefinitely or causing an `OutOfMemoryError` denial of service before the post-read inode check at line 165 is ever reached. Furthermore, if `parentShared` is false, the post-read inode verification is skipped entirely.

**Fix:** Open the file using `FileChannel.open(file, StandardOpenOption.READ)` with `LinkOption.NOFOLLOW_LINKS` (or verifying file descriptor identity via `FileChannel`) and read into a bounded buffer directly from the open channel.
```java
        byte[] out;
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size > maxBytes) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                        "key file is larger than " + maxBytes + " bytes");
            }
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate((int) size);
            while (buf.hasRemaining()) {
                if (channel.read(buf) < 0) {
                    break;
                }
            }
            out = buf.array();
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key file could not be read", e);
        }
```

---

### SEC-04: Sensitive Key Material Left Uncleared in Heap Memory in EnvKeySource
- **Severity:** Medium
- **CWE:** CWE-226: Sensitive Information Uncleared Before Release
- **Location:** `src/main/java/com/example/crypto/EnvKeySource.java:69-80`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/EnvKeySource.java:69-80
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        if (raw.length > MAX_VALUE_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                    "environment variable " + variable + " is larger than " + MAX_VALUE_BYTES + " bytes");
        }
        try {
            return KeyMaterial.fromBytes(KeyEncoding.decodeKeyBytes(raw));
        } catch (CryptoException e) {
            /* Prefix the source, and do not let the value survive in the detail. */
            throw new CryptoException(e.code(), variable + ": " + valueShape(raw), e);
        }
```

**Why it is a problem:** `raw = value.getBytes(StandardCharsets.UTF_8)` holds raw sensitive key material. In other classes in the module (e.g., `KeyFileKeySource.java:62`, `KeystoreKeySource.java:256`, and `SymmetricCrypto.java:87`), raw key byte arrays are cleared in a `finally` block using `Arrays.fill(raw, (byte) 0)`. In `EnvKeySource.java`, `raw` is never zeroed; if decoding succeeds or fails, `raw` remains on the JVM heap until garbage collected, increasing the window of exposure during memory dumping or crash reporting.

**Fix:** Wrap the processing of `raw` in a `try ... finally` block and clear it with `Arrays.fill(raw, (byte) 0)`.
```java
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        try {
            if (raw.length > MAX_VALUE_BYTES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                        "environment variable " + variable + " is larger than " + MAX_VALUE_BYTES + " bytes");
            }
            try {
                return KeyMaterial.fromBytes(KeyEncoding.decodeKeyBytes(raw));
            } catch (CryptoException e) {
                /* Prefix the source, and do not let the value survive in the detail. */
                throw new CryptoException(e.code(), variable + ": " + valueShape(raw), e);
            }
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
```

---

### SEC-05: Creation and Retention of Secret Key Material as Immutable Strings in KeyEncoding
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/example/crypto/KeyEncoding.java:70-81`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyEncoding.java:70-81
        String text = new String(in, StandardCharsets.US_ASCII);
        byte[] decoded;
        try {
            decoded = DECODER.decode(text);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not valid base64url text", e);
        }
        if (!CANON.encodeToString(decoded).equals(text)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not canonically encoded base64url text");
        }
```

**Why it is a problem:** `String text = new String(in, StandardCharsets.US_ASCII)` and `CANON.encodeToString(decoded)` allocate immutable `String` instances containing the base64-encoded secret key. Unlike byte arrays, Java `String` characters cannot be zeroed or cleared from memory. Despite `KeyEncoding`'s Javadoc explicitly noting that string representations of keys are avoided because strings cannot be erased, decoding creates multiple string instances containing the key on the heap.

**Fix:** Utilize `Base64.Decoder.decode(byte[])` and `Base64.Encoder.encode(byte[])` to operate purely on byte arrays and compare canonical equality using `java.security.MessageDigest.isEqual` or `Arrays.equals` without allocating `String` objects.
```java
        byte[] decoded;
        try {
            decoded = DECODER.decode(in);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not valid base64url text", e);
        }
        byte[] reencoded = CANON.encode(decoded);
        try {
            if (!java.security.MessageDigest.isEqual(reencoded, in)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material is not canonically encoded base64url text");
            }
        } finally {
            java.util.Arrays.fill(reencoded, (byte) 0);
        }
```

---

### SEC-06: Data Race on Passphrase Arrays During Concurrent Key Loading and Destruction
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- **Location:** `src/main/java/com/example/crypto/PasswordKeySource.java:208-216`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PasswordKeySource.java:208-216, 260-264
    @Override
    public KeyMaterial load() throws CryptoException {
        if (destroyed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, "key source is closed");
        }
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, FILE_BYTES + 64);
        try {
            Header h = parseHeader(raw);
            byte[] kekBytes = derive(passphrase, h.salt(), h.iterations());
...
    public synchronized void destroy() {
        Arrays.fill(passphrase, (char) 0);
        destroyed = true;
    }
```

**Why it is a problem:** `destroy()` is synchronized and zeroes `passphrase` with `Arrays.fill`. However, `load()` is not synchronized. If one thread calls `destroy()` or `close()` while another thread is executing `load()`, the `passphrase` array is modified in-place while `derive(passphrase, ...)` reads it. Because Java arrays are not thread-safe, concurrent modification and reading of `passphrase` causes a data race and can lead to unexpected derivation errors or inconsistent memory reads. The same issue exists in `KeystoreKeySource.java:197-224` for `storePassword` and `keyPassword`.

**Fix:** Synchronize `load()` or clone the passphrase under lock before using it.
```java
    @Override
    public synchronized KeyMaterial load() throws CryptoException {
        if (destroyed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, "key source is closed");
        }
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, FILE_BYTES + 64);
        try {
            Header h = parseHeader(raw);
            byte[] kekBytes = derive(passphrase, h.salt(), h.iterations());
            try {
                byte[] aad = headerBytes(h.kdfId(), h.iterations(), h.salt());
                byte[] dataKey;
                try {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kekBytes, "AES"),
                            new GCMParameterSpec(Limits.TAG_BITS, h.nonce()));
                    c.updateAAD(aad);
                    dataKey = c.doFinal(raw, h.offset(), WRAPPED_BYTES);
                } catch (AEADBadTagException e) {
                    throw new CryptoException(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED,
                            "the passphrase does not match this key file", e);
                } catch (GeneralSecurityException e) {
                    throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                            "key file could not be opened: " + e.getClass().getSimpleName(), e);
                }
                try {
                    if (dataKey.length != KeyMaterial.KEY_BYTES) {
                        throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                                "unwrapped key has an unexpected length");
                    }
                    return KeyMaterial.fromBytes(dataKey, keyVersion);
                } finally {
                    Arrays.fill(dataKey, (byte) 0);
                }
            } finally {
                Arrays.fill(kekBytes, (byte) 0);
            }
        } catch (CryptoException e) {
            throw e;
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
```

---

### SEC-07: Race Condition in KeyVault.encrypt Between Version Retrieval and Source Resolution
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- **Location:** `src/main/java/com/example/crypto/KeyVault.java:257-258`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyVault.java:257-258
            int version = highestIssued.get();
            KeySource source = sourceFor(version);
```

**Why it is a problem:** `highestIssued.get()` is evaluated outside the vault's `rotationLock`, while `sourceFor` acquires `rotationLock`. If `vault.rotate()` is called concurrently between these two statements, `rotate()` places `version` into the `disabled` map (`disabled.put(previous, Boolean.TRUE)`) and increments `highestIssued`. When `sourceFor(version)` subsequently acquires the lock, it encounters the now-disabled version and throws `KEY_UNAVAILABLE`, causing an active write operation to fail prematurely rather than encrypting under the active key.

**Fix:** Obtain the active version and its corresponding source atomically under `rotationLock`.
```java
            int version;
            KeySource source;
            synchronized (rotationLock) {
                requireOpen();
                version = highestIssued.get();
                source = sourceFor(version);
            }
```

## 6. Verified Controls and Checks With No Finding
- Authenticated Symmetric Cipher Construction: Verified that `SymmetricCrypto.java` strictly enforces `AES/GCM/NoPadding` with full 128-bit authentication tags (`Limits.TAG_BITS = 128`) and 96-bit nonces (`Limits.IV_BYTES = 12`). No unauthenticated ciphertext or partial plaintext is ever returned when tag validation fails.
- Nonce Uniqueness and Entropy Source: Verified that all record nonces are generated per record using `SecureRandom.nextBytes(...)` and cannot be chosen, supplied, or overridden by external callers.
- Additional Authenticated Data (AAD) Cryptographic Binding: Verified that record format version, key version, context flag, and context strings are injected into AES-GCM AAD during both encryption and decryption (`SymmetricCrypto.aad`), preventing record retargeting or context manipulation.
- Constant-Work and Uniform Error Handling: Verified that failures arising from key version mismatches, context mismatches, corrupted ciphertexts, and unissued key versions (via `KeyVault.decoySource`) perform full AES-GCM operations and return indistinguishable, generic user messages ("The data could not be decrypted").
- Input Validation and Resource Bounds: Verified that `Limits.java` enforces strict size caps prior to allocations or crypto operations (1 MiB max plaintext, 200 printable ASCII context characters, 310,000 to 2,000,000 PBKDF2 iterations, bounded Base64URL string lengths).
- Exception and Information Leakage Prevention: Verified that `CryptoException.java` suppresses stack traces and exception suppression, strips cause messages to prevent provider/path leakage, and marks `technicalDetail` as transient so internal diagnostics do not cross serialization boundaries.
- Atomic File Creation and Permissions: Verified that `PrivateFiles.writeOwnerOnlyFile` and `newOwnerOnlyOutputStream` use `StandardOpenOption.CREATE_NEW` with `0600` POSIX creation attributes, ensuring files are never born readable or overwritten.
- Reliance on Standard Platform Cryptography: Verified that the implementation utilizes standard Java Cryptography Architecture (JCA/JCE) primitives (`javax.crypto.Cipher`, `SecretKeyFactory`, `KeyStore`, `SecureRandom`) without custom or deprecated ciphers (such as DES, RC4, or ECB mode).
