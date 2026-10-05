# Security Review: Secure Symmetric Encryption & Key Management Component

## 1. Executive Summary
This security review evaluated the reusable Java symmetric encryption and key management component located in `com.security.crypto`. The component provides Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM (`AES/GCM/NoPadding`), PBKDF2-HMAC-SHA512 key derivation, PKCS12 keystore integration, dynamic key rotation, multi-dimensional brute-force rate limiting, and filesystem access controls.

While the component implements strong cryptographic foundations—such as platform-native JCA/JCE primitives, internal 96-bit random IV generation via `SecureRandom`, constant-work dummy decryption cycles, and generic error reporting—the review identified **8 security vulnerabilities**:
1. **Unauthenticated Envelope Metadata (High / CWE-345):** Payload wire headers (`keyId` and `version`) are transmitted unauthenticated outside the AES-GCM Associated Authenticated Data (AAD), permitting key substitution and targeted denial-of-service against rate-limiting buckets.
2. **Race Condition in Active Key and Key ID Retrieval (High / CWE-362):** Encryption queries `getActiveKey()` and `getActiveKeyId()` non-atomically, allowing concurrent key rotation to produce ciphertexts encrypted under an old key but stamped with a new key ID, causing permanent data corruption.
3. **Unbounded Memory Growth and CPU Starvation in Rate Limiter (Medium / CWE-400):** The rate limiter's pruning mechanism only deletes expired entries, permitting an attacker to flood active windows with arbitrary random identifiers, leading to unbounded heap memory growth and full-map traversal CPU exhaustion.
4. **System-Wide Denial of Service via Shared Default Source ID (Medium / CWE-307):** Default decryption convenience methods aggregate failures under a shared static identifier (`"internal_client"`), allowing an attacker to lock out all internal callers across the entire application.
5. **Sensitive KeyStore Password Retained in Memory on Exception (Medium / CWE-316):** KeyStore loading from files fails to clear cleartext passwords from memory when path or permission validation throws an exception.
6. **Incomplete Filesystem Security Controls on Non-POSIX Platforms (Medium / CWE-732):** File permission and ownership checks are bypassed entirely on non-POSIX operating systems such as Windows.
7. **Improper Authorization Logic Exempting Non-Owner Root Key Files (Low / CWE-285):** File ownership validation explicitly permits files owned by `root` even when the application runs as an unprivileged service account.
8. **Unbounded Iteration Count in PBKDF2 Key Derivation (Low / CWE-400):** Key derivation enforces a minimum iteration threshold but lacks an upper bound, allowing CPU exhaustion attacks via maliciously configured iteration parameters.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/crypto/AesGcmEncryptionService.java` | Main AES-256-GCM AEAD encryption and decryption service implementation. | Cipher initialization, AAD handling, IV generation, key retrieval from provider, timing oracle defense via dummy decryption, rate limiting integration, error handling. |
| `src/main/java/com/security/crypto/CryptoException.java` | Sanitized runtime exception for cryptographic failures. | Prevents information disclosure and oracle leakage by presenting generic, caller-facing error messages while retaining diagnostic causes internally. |
| `src/main/java/com/security/crypto/CryptoUtils.java` | Cryptographic, memory zeroization, and input validation utilities. | Memory zeroization (`Arrays.fill`), `Destroyable` key destruction, constant-time byte array comparison via `MessageDigest.isEqual`, regex validation for key IDs and source IDs, buffer bounds checking. |
| `src/main/java/com/security/crypto/DecryptionRateLimiter.java` | Dual-bucket sliding window rate limiter tracking failures per source and per resource. | Atomic check-and-act failure tracking using `ConcurrentHashMap` and `AtomicInteger`, lockout prevention logic, table capacity pruning. |
| `src/main/java/com/security/crypto/EncryptedPayload.java` | Encapsulates ciphertext, IV, version, and key identifier in binary and Base64URL formats. | Binary wire format serialization and deserialization, buffer allocation bounds, header magic verification, Base64URL encoding/decoding, sensitive content masking in `toString()`. |
| `src/main/java/com/security/crypto/FileSecurityUtil.java` | Filesystem security utility for keystores and key files. | Path normalization, POSIX file permission checks (mode 0600), owner validation, world-writable directory rejection, atomic private file creation. |
| `src/main/java/com/security/crypto/InMemoryKeyProvider.java` | Thread-safe in-memory key registry supporting dynamic key rotation and revocation. | Key algorithm/length validation, thread-safe key lookup and rotation via `ConcurrentHashMap` and `AtomicReference`, memory zeroization on close/revocation. |
| `src/main/java/com/security/crypto/KeyDerivation.java` | Password-based key derivation using standard PBKDF2WithHmacSHA512. | Key derivation parameter enforcement (iterations, salt length), salt generation via `SecureRandom`, password and intermediate key buffer wiping in `finally` blocks. |
| `src/main/java/com/security/crypto/KeyGeneratorUtil.java` | Cryptographic generator for keys, nonces, and identifiers. | 256-bit AES key generation via JCA `KeyGenerator`, 12-byte GCM IV generation via `SecureRandom`, random key ID generation. |
| `src/main/java/com/security/crypto/KeyProvider.java` | Interface defining symmetric key lifecycle and lookup operations. | Contract for active key resolution, historical key lookups, and `AutoCloseable` key destruction. |
| `src/main/java/com/security/crypto/KeyStoreKeyProvider.java` | PKCS12 keystore loader and key provider. | File and stream loading of PKCS12 keystores, alias validation, password wiping in `finally`, key extraction, lifecycle destruction. |
| `src/main/java/com/security/crypto/SymmetricEncryptionService.java` | Top-level interface contract for symmetric encryption and decryption. | Defines core API boundaries, parameter overloads, and AAD context-binding requirements. |
| `src/test/java/com/security/crypto/FileSecurityTest.java` | Unit tests for filesystem security and private file validation. | Tests POSIX permission enforcement, directory validation, and keystore file loading security controls. |
| `src/test/java/com/security/crypto/SymmetricCryptoTest.java` | Comprehensive test suite for encryption, decryption, attacks, and concurrency. | Verifies round-trip encryption, tampering rejection (ciphertext, IV, tag, AAD), boundary parsing, rate limiting, and multithreaded key rotation. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives (AES-256-GCM, PBKDF2WithHmacSHA512, SecureRandom), key lengths (256-bit), GCM tag length (128-bit), IV generation, cipher transformations (`AES/GCM/NoPadding`), KDF iteration counts, salt entropy, and constant-time comparisons.
- General OWASP Top 10 / CWE knowledge (A01: Broken Access Control, A02: Cryptographic Failures, A04: Insecure Design, A05: Security Misconfiguration):
  - Audited concurrency synchronization and atomic state transitions during key rotation against race conditions (CWE-362).
  - Audited envelope wire protocol and AEAD context binding against ciphertext and metadata integrity verification requirements (CWE-345, CWE-353).
  - Audited brute-force rate-limiting architecture, shared identifier abuse, and memory exhaustion vectors against Denial of Service risks (CWE-307, CWE-400, CWE-770).
  - Audited filesystem permissions, parent directory security, cross-platform POSIX vs Windows ACL handling, and user ownership validation (CWE-732, CWE-285).
  - Audited credential zeroization and memory lifecycle guarantees during exception paths (CWE-316).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unauthenticated Envelope Metadata in AEAD Encrypted Payload | High | CWE-345 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:122-127` |
| SEC-02 | Non-Atomic Key and Key ID Retrieval in Concurrent Encryption | High | CWE-362 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:110-111` |
| SEC-03 | Denial of Service via Unbounded Memory Growth and CPU Starvation in Rate Limiter | Medium | CWE-400 | `src/main/java/com/security/crypto/DecryptionRateLimiter.java:154-157` |
| SEC-04 | System-Wide Denial of Service via Shared Static Default Source Identifier in Rate Limiter | Medium | CWE-307 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:145-153` |
| SEC-05 | Sensitive KeyStore Password Retained in Memory on Validation Exception | Medium | CWE-316 | `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-56` |
| SEC-06 | Incomplete Filesystem Security Controls and Permission Verification on Non-POSIX Platforms | Medium | CWE-732 | `src/main/java/com/security/crypto/FileSecurityUtil.java:62-93` |
| SEC-07 | Improper Authorization Logic Exempting Non-Owner Root Key Files | Low | CWE-285 | `src/main/java/com/security/crypto/FileSecurityUtil.java:74-78` |
| SEC-08 | Unbounded Iteration Count in PBKDF2 Key Derivation Permitting CPU Exhaustion | Low | CWE-400 | `src/main/java/com/security/crypto/KeyDerivation.java:105-107` |

## 5. Detailed Findings

### SEC-01: Unauthenticated Envelope Metadata in AEAD Encrypted Payload
- **Severity:** High
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:122-127` (and `src/main/java/com/security/crypto/EncryptedPayload.java:112-125`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:122-127
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            return new EncryptedPayload(EncryptedPayload.CURRENT_VERSION, activeKeyId, iv, ciphertextWithTag);
```

**Why it is a problem:**
In `EncryptedPayload.toBytes()`, the binary envelope formats the payload with a plaintext header containing magic bytes (`SEC1`), protocol version (`0x01`), key ID length, and the UTF-8 key identifier string. However, `AesGcmEncryptionService` only feeds caller-provided `aad` into `cipher.updateAAD(aad)`. The header metadata (`version` and `keyId`) is never passed to `cipher.updateAAD()` during encryption or decryption.

Because AES-GCM GHASH authenticates only the ciphertext and the explicit AAD supplied to `updateAAD()`, the envelope header fields are unauthenticated metadata:
1. **Key Substitution & Misattribution:** In multi-tenant environments or systems where multiple key aliases share key material (or during key migration/rollover), an attacker can alter the `keyId` in transit without invalidating the 128-bit authentication tag.
2. **Targeted Denial of Service via Resource Exhaustion:** An attacker can capture a valid ciphertext encrypted under `key_A`, change the `keyId` in the wire format to a victim's `key_B`, and submit it. The server attempts decryption under `key_B`, fails tag verification, and charges the failure against `key_B`'s counter in `DecryptionRateLimiter.resourceCounters`. This allows an attacker to deliberately exhaust rate limits for arbitrary victim keys/accounts without tampering with the ciphertext.
3. **Protocol Downgrade:** If subsequent protocol versions (e.g. Version 2) are introduced, an attacker can modify the version byte without failing cryptographic integrity checks.

**Fix:**
Bind the wire format header metadata (magic bytes, version byte, and key identifier) into the AES-GCM AAD calculation during both encryption and decryption before processing any application-provided AAD.
```java
            // Compute canonical header bytes
            byte[] keyIdBytes = activeKeyId.getBytes(StandardCharsets.UTF_8);
            ByteBuffer headerAad = ByteBuffer.allocate(4 + 1 + 1 + keyIdBytes.length);
            headerAad.put(EncryptedPayload.MAGIC);
            headerAad.put(EncryptedPayload.CURRENT_VERSION);
            headerAad.put((byte) keyIdBytes.length);
            headerAad.put(keyIdBytes);
            cipher.updateAAD(headerAad.array());

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            return new EncryptedPayload(EncryptedPayload.CURRENT_VERSION, activeKeyId, iv, ciphertextWithTag);
```

---

### SEC-02: Non-Atomic Key and Key ID Retrieval in Concurrent Encryption
- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:110-111`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:110-111
        SecretKey activeKey = keyProvider.getActiveKey();
        String activeKeyId = keyProvider.getActiveKeyId();
```

**Why it is a problem:**
`KeyProvider` exposes two independent methods for obtaining active encryption key material: `getActiveKey()` and `getActiveKeyId()`. In `AesGcmEncryptionService.encrypt`, these methods are invoked consecutively without mutual exclusion or atomic aggregation.

If an application thread invokes `keyProvider.rotateKey(newKeyId, newKey)` or `setActiveKeyId(newKeyId)` between lines 110 and 111:
1. Thread A calls `keyProvider.getActiveKey()`, receiving `Key_1`.
2. Thread B executes `keyProvider.rotateKey("key_2", Key_2)`.
3. Thread A resumes and calls `keyProvider.getActiveKeyId()`, receiving `"key_2"`.
4. Thread A encrypts the plaintext using `Key_1`, but packages the ciphertext into an `EncryptedPayload` stamped with `keyId = "key_2"`.

When this encrypted payload is subsequently decrypted, the service looks up `"key_2"` from `keyProvider` and attempts GCM tag verification. Because the ciphertext was encrypted under `Key_1`, decryption fails unconditionally with an authentication tag error (`AEADBadTagException`). The ciphertext is permanently corrupted and unrecoverable by normal decryption. This directly violates Rule 7 ("Where you check state and then act on it... make the check and the action atomic").

**Fix:**
Provide a unified method on `KeyProvider` that returns an immutable record or entry holding both the `SecretKey` and its corresponding `keyId` atomically, backed by an `AtomicReference` in `InMemoryKeyProvider`.
```java
        // Record defining atomic key and identifier pairing
        public record KeyEntry(String keyId, SecretKey key) {}

        // In AesGcmEncryptionService.encrypt:
        KeyProvider.KeyEntry activeEntry = keyProvider.getActiveKeyEntry();
        SecretKey activeKey = activeEntry.key();
        String activeKeyId = activeEntry.keyId();
```

---

### SEC-03: Denial of Service via Unbounded Memory Growth and CPU Starvation in Rate Limiter
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/crypto/DecryptionRateLimiter.java:154-157` (and `110-132`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/DecryptionRateLimiter.java:154-157
    private void pruneIfNecessary(ConcurrentHashMap<String, WindowCounter> map, long now) {
        if (map.size() >= MAX_MAP_ENTRIES) {
            map.entrySet().removeIf(entry -> (now - entry.getValue().windowStartMs) > windowDurationMs);
        }
    }
```

**Why it is a problem:**
`DecryptionRateLimiter` attempts to bound its internal tracker maps (`sourceCounters` and `resourceCounters`) by calling `pruneIfNecessary` before recording failures. However, `pruneIfNecessary` only purges entries where `(now - entry.getValue().windowStartMs) > windowDurationMs`.

If an attacker floods the service with decryption failures using randomly generated `sourceId` values or random `keyId` values in payload headers within a single window duration (60 seconds):
1. None of the entries in the map are older than 60 seconds.
2. `removeIf` deletes 0 entries.
3. Because `map.size() >= MAX_MAP_ENTRIES` (10,000) does not prevent new insertions, `map.compute(...)` continues inserting new entries unboundedly, defeating the memory cap and causing high heap memory consumption or `OutOfMemoryError`.
4. Once the map reaches 10,000 entries, every single subsequent failure triggers `map.entrySet().removeIf(...)`, performing an $O(N)$ linear traversal across thousands of entries while competing for thread scheduling, resulting in severe CPU spikes and starvation.
5. In addition, `AesGcmEncryptionService.decrypt` passes untrusted, non-existent `keyId` values directly into `rateLimiter.recordFailure(sourceId, keyId)`, allowing an attacker to inject arbitrary strings into `resourceCounters`.

**Fix:**
Enforce a hard capacity limit using a bounded cache with Least Recently Used (LRU) eviction, or immediately reject/evict oldest entries when the map exceeds capacity. Additionally, do not track non-existent `keyId` identifiers in `resourceCounters`.
```java
    private static final int MAX_MAP_ENTRIES = 10_000;

    private void pruneIfNecessary(ConcurrentHashMap<String, WindowCounter> map, long now) {
        if (map.size() >= MAX_MAP_ENTRIES) {
            // First pass: remove expired entries
            map.entrySet().removeIf(entry -> (now - entry.getValue().windowStartMs) > windowDurationMs);
            // Second pass: if still at or exceeding cap, remove oldest entries to enforce strict hard ceiling
            if (map.size() >= MAX_MAP_ENTRIES) {
                var iterator = map.keySet().iterator();
                int toRemove = map.size() - (MAX_MAP_ENTRIES * 3 / 4);
                while (iterator.hasNext() && toRemove-- > 0) {
                    iterator.next();
                    iterator.remove();
                }
            }
        }
    }
```

---

### SEC-04: System-Wide Denial of Service via Shared Static Default Source Identifier in Rate Limiter
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:145-153` (and line 48)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:145-153
    @Override
    public byte[] decrypt(EncryptedPayload payload) {
        return decrypt(payload, null, DEFAULT_SOURCE_ID);
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload, byte[] aad) {
        return decrypt(payload, aad, DEFAULT_SOURCE_ID);
    }
```

**Why it is a problem:**
Line 48 defines a static fallback source identifier: `public static final String DEFAULT_SOURCE_ID = "internal_client";`. The convenience overloads `decrypt(EncryptedPayload)` and `decrypt(EncryptedPayload, byte[])` automatically pass `DEFAULT_SOURCE_ID` to the underlying decryption method.

In any application where multiple components or callers use these standard convenience methods without supplying an explicit caller identity, all decryption attempts and failures share the single `"internal_client"` source quota. If an attacker submits 20 corrupted or invalid payloads to any application feature that calls `decrypt(payload)`, `sourceCounters` for `"internal_client"` hits `DEFAULT_MAX_SOURCE_FAILURES` (20).

Once this threshold is reached, `rateLimiter.checkAllowed("internal_client", ...)` throws `CryptoException("Decryption rate limit exceeded")` for all subsequent calls. As a result, every legitimate service and background job in the entire application using `decrypt(payload)` is blocked from decrypting data for the remainder of the 60-second window, resulting in a system-wide denial-of-service.

**Fix:**
Require callers to supply a caller context or source identifier, or if convenience methods are maintained for internal services, bypass source-level failure throttling when invoking internal calls without an untrusted source identity.
```java
    @Override
    public byte[] decrypt(EncryptedPayload payload) {
        return decrypt(payload, null, null);
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload, byte[] aad) {
        return decrypt(payload, aad, null);
    }

    // In DecryptionRateLimiter.checkAllowed and recordFailure:
    // If sourceId is null, skip source-level failure tracking while retaining resource-level protection.
```

---

### SEC-05: Sensitive KeyStore Password Retained in Memory on Validation Exception
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-56` (and line 76)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-56
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
        try (InputStream in = Files.newInputStream(validatedPath)) {
            return fromInputStream(in, password, activeKeyAlias);
        } catch (Exception e) {
            if (e instanceof CryptoException ce) {
                throw ce;
            }
            throw new CryptoException("Failed to load KeyStore from file", e);
        }
    }
```

**Why it is a problem:**
The Javadoc contract for `KeyStoreKeyProvider.fromFile` states: `@param password The KeyStore password as a char array (will be zeroed upon return)`. This contract is intended to satisfy Rule 2 and Rule 5 regarding secret zeroization in memory.

However, line 47 calls `FileSecurityUtil.validatePrivateFile(keyStorePath)` outside any `try-finally` block. If `validatePrivateFile` throws a `CryptoException` (for example, if the keystore file does not exist, is not a regular file, is in a world-writable directory, or has overly permissive file permissions), or if `Files.newInputStream` fails, execution aborts before `fromInputStream` is reached.

Because there is no `finally` block in `fromFile`, `CryptoUtils.wipe(password)` is never executed. The caller's sensitive `char[] password` remains in plain text on the heap indefinitely. Furthermore, inside `fromInputStream`:
```java
KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(password);
```
`KeyStore.PasswordProtection` makes an internal defensive clone of `password`. While `fromInputStream` zeroes the input `char[]` in its `finally` block, it never calls `protParam.destroy()`, leaving the cloned password in heap memory until garbage collection.

**Fix:**
Enclose the entire method body of `fromFile` in a `try-finally` block that guarantees `CryptoUtils.wipe(password)` is executed on every code path, and invoke `protParam.destroy()` in `fromInputStream`.
```java
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        try {
            Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
            try (InputStream in = Files.newInputStream(validatedPath)) {
                return fromInputStream(in, password, activeKeyAlias);
            }
        } catch (Exception e) {
            if (e instanceof CryptoException ce) {
                throw ce;
            }
            throw new CryptoException("Failed to load KeyStore from file", e);
        } finally {
            CryptoUtils.wipe(password);
        }
    }
```

---

### SEC-06: Incomplete Filesystem Security Controls and Permission Verification on Non-POSIX Platforms
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/security/crypto/FileSecurityUtil.java:62-93` (and line 29, lines 114-129)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/FileSecurityUtil.java:62-93
        // Validate POSIX file permissions and parent directory safety if supported
        if (IS_POSIX) {
            try {
                // Check parent directory is not world-writable
                Path parent = normalized.getParent();
                if (parent != null && Files.exists(parent)) {
                    Set<PosixFilePermission> parentPerms = Files.getPosixFilePermissions(parent);
                    if (parentPerms.contains(PosixFilePermission.OTHERS_WRITE)) {
                        throw new CryptoException("Key file directory is world-writable and unsafe");
                    }
                }

                // Check file owner
                UserPrincipal owner = Files.getOwner(normalized, LinkOption.NOFOLLOW_LINKS);
                String currentUser = System.getProperty("user.name");
                if (owner != null && currentUser != null && !currentUser.equals(owner.getName()) && !"root".equals(owner.getName())) {
                    throw new CryptoException("Key file is not owned by the current application user");
                }

                // Check file permissions: must not be readable/writable by group or others
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(normalized, LinkOption.NOFOLLOW_LINKS);
                if (perms.contains(PosixFilePermission.GROUP_READ)
                        || perms.contains(PosixFilePermission.GROUP_WRITE)
                        || perms.contains(PosixFilePermission.GROUP_EXECUTE)
                        || perms.contains(PosixFilePermission.OTHERS_READ)
                        || perms.contains(PosixFilePermission.OTHERS_WRITE)
                        || perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                    throw new CryptoException("Key file permissions are too open: must be readable only by the owner (mode 0600 or 0400)");
                }
            } catch (IOException e) {
                throw new CryptoException("Failed to verify key file security attributes", e);
            }
        }
```

**Why it is a problem:**
Line 29 evaluates `IS_POSIX`: `FileSystems.getDefault().supportedFileAttributeViews().contains("posix")`. On Windows systems, `IS_POSIX` evaluates to `false`.

When running on Windows:
1. `validatePrivateFile` completely skips lines 62-93. It performs no permission checks, no ownership verification, and no parent directory security validation. A key file or keystore stored in a shared directory (e.g., `C:\Users\Public` or `C:\Temp`) or readable by any domain user or group is accepted as secure and loaded.
2. In `createPrivateFile` (lines 114-129), non-POSIX platforms fall back to creating the file with default inherited permissions and calling `File.setReadable(false, false)`. On Windows, `File.setReadable` is unsupported by the platform and returns `false`, causing `createPrivateFile` to fail and delete the file, or if partially supported, it fails to enforce Windows ACL isolation.

**Fix:**
For non-POSIX operating systems (such as Windows), inspect `AclFileAttributeView` to verify that the file's Access Control Entries (ACEs) grant access exclusively to the current user's principal/SID and deny or exclude `Everyone` / `Authenticated Users`. Fail closed if the platform cannot enforce owner-private access controls.
```java
        if (IS_POSIX) {
            // Existing POSIX checks...
        } else if (FileSystems.getDefault().supportedFileAttributeViews().contains("acl")) {
            try {
                var aclView = Files.getFileAttributeView(normalized, java.nio.file.attribute.AclFileAttributeView.class);
                var acls = aclView.getAcl();
                UserPrincipal owner = Files.getOwner(normalized);
                for (var ace : acls) {
                    // Fail closed if any entry grants access to principals other than the owner
                    if (!ace.principal().equals(owner)) {
                        throw new CryptoException("Key file permissions are too open: file is accessible to non-owner users on ACL filesystem");
                    }
                }
            } catch (IOException e) {
                throw new CryptoException("Failed to verify ACL security attributes on key file", e);
            }
        } else {
            throw new CryptoException("Underlying filesystem does not support secure owner-private access controls");
        }
```

---

### SEC-07: Improper Authorization Logic Exempting Non-Owner Root Key Files
- **Severity:** Low
- **CWE:** CWE-285: Improper Authorization
- **Location:** `src/main/java/com/security/crypto/FileSecurityUtil.java:74-78`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/FileSecurityUtil.java:74-78
                UserPrincipal owner = Files.getOwner(normalized, LinkOption.NOFOLLOW_LINKS);
                String currentUser = System.getProperty("user.name");
                if (owner != null && currentUser != null && !currentUser.equals(owner.getName()) && !"root".equals(owner.getName())) {
                    throw new CryptoException("Key file is not owned by the current application user");
                }
```

**Why it is a problem:**
Line 76 verifies that the file owner matches the application user (`currentUser.equals(owner.getName())`), but appends an explicit exemption: `&& !"root".equals(owner.getName())`.

If the application is running as an unprivileged service account (e.g. `appuser`, `tomcat`, `svc_crypto`), this condition evaluates to `false` when `owner.getName()` is `"root"`, suppressing the exception. The application will accept and process key files owned by `root`. Allowing an unprivileged user process to rely on files owned by a separate administrative user breaks user isolation and trust boundaries, and can lead to runtime `AccessDeniedException` errors if the file is restricted to mode `0600` root-only. If the application is running as `root`, `currentUser.equals(owner.getName())` is already `true`, making the hardcoded `"root"` bypass redundant and unsafe for non-root execution.

**Fix:**
Require strict equality between the file owner and the running application user without hardcoded exceptions.
```java
                UserPrincipal owner = Files.getOwner(normalized, LinkOption.NOFOLLOW_LINKS);
                String currentUser = System.getProperty("user.name");
                if (owner != null && currentUser != null && !currentUser.equals(owner.getName())) {
                    throw new CryptoException("Key file is not owned by the current application user");
                }
```

---

### SEC-08: Unbounded Iteration Count in PBKDF2 Key Derivation Permitting CPU Exhaustion
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/crypto/KeyDerivation.java:105-107`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyDerivation.java:105-107
        if (iterations < MIN_ITERATIONS) {
            throw new CryptoException("Iteration count must be at least " + MIN_ITERATIONS);
        }
```

**Why it is a problem:**
`KeyDerivation.deriveKey` enforces a hard lower bound of `MIN_ITERATIONS = 210_000` to prevent weak key derivation. However, it enforces no upper bound on the iteration count.

If an untrusted caller, configuration parameter, or attacker-controlled payload specifies an excessively high iteration count (e.g., $10^8$ or `Integer.MAX_VALUE`), `SecretKeyFactory.generateSecret(spec)` will execute HMAC-SHA512 iterations in a tight CPU-bound loop on the worker thread. Because PBKDF2 is computationally intensive by design, an iteration count in the tens or hundreds of millions will lock up the CPU core for minutes or hours, facilitating a denial-of-service attack against the key derivation service.

**Fix:**
Introduce a maximum allowable iteration count threshold (`MAX_ITERATIONS`) and validate that `iterations` falls within the safe range `[MIN_ITERATIONS, MAX_ITERATIONS]`.
```java
    public static final int MAX_ITERATIONS = 5_000_000;

    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
        throw new CryptoException("Iteration count must be between " + MIN_ITERATIONS + " and " + MAX_ITERATIONS);
    }
```

## 6. Verified Controls and Checks With No Finding
- **AES-256-GCM Authenticated Encryption:** Verified in `AesGcmEncryptionService` that encryption utilizes standard AES-256 in GCM mode (`AES/GCM/NoPadding`) with a full 128-bit authentication tag (`GCM_TAG_LENGTH_BITS = 128`), effectively preventing ciphertext bit-flipping and padding oracle attacks.
- **Internal Nonce / IV Randomness:** Verified in `AesGcmEncryptionService.encrypt` that a fresh 12-byte (96-bit) IV is generated internally on every encryption invocation using `SecureRandom`. Callers cannot supply or influence IVs, eliminating nonce reuse vulnerabilities.
- **Cryptographic Key Generation:** Verified in `KeyGeneratorUtil.generateAes256Key()` that keys are generated using JCA `KeyGenerator` initialized for 256 bits with `SecureRandom`, and key identifiers are 34-character cryptographically random strings (`k_` + 16 random hex bytes).
- **PBKDF2 Password-Based Key Derivation Baseline:** Verified in `KeyDerivation` that `PBKDF2WithHmacSHA512` enforces a minimum iteration count of 210,000 (defaulting to 600,000) and requires at least 16 bytes of salt generated from `SecureRandom`, conforming to OWASP password storage guidelines.
- **Memory Zeroization on Normal Code Paths:** Verified that `CryptoUtils.wipe` is implemented to overwrite sensitive byte arrays with `(byte) 0` and char arrays with `'\0'`, and is called in `finally` blocks for plaintext buffers, KDF credentials, and intermediate key encodings.
- **Constant-Time Byte Comparison:** Verified in `CryptoUtils.constantTimeEquals` that array equality checks delegate to `java.security.MessageDigest.isEqual`, mitigating timing-based side-channel attacks on cryptographic comparison.
- **Information Disclosure & Oracle Mitigation:** Verified that `CryptoException` presents uniform, generic messages (`"Decryption failed"`, `"Invalid cryptographic request"`) without leaking internal exception causes, padding status, or tag verification details to external callers.
- **Constant-Work Timing Defense for Key Existence:** Verified in `AesGcmEncryptionService.performDummyDecryption` that when an unknown or revoked key ID is requested, the service performs a dummy AES-GCM decryption cycle matching the ciphertext length, balancing computational timing against tag mismatch failures to prevent key enumeration.
- **Input Validation & Buffer Bounds:** Verified in `CryptoUtils` and `EncryptedPayload` that plaintext sizes (`maxPlaintextBytes`), ciphertext sizes (`maxCiphertextBytes`), and AAD sizes (`maxAadBytes`) are validated against upper limits prior to buffer allocations, and key IDs and source IDs are validated against strict regex character allowlists.
- **Thread Safety of Cipher Primitives:** Verified that `javax.crypto.Cipher` instances are instantiated per operation inside `encrypt` and `decrypt`, ensuring that concurrent threads do not corrupt cipher state or share mutable cryptographic contexts.
