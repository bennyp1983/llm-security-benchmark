# Secure Symmetric Encryption & Key Management Component

A production-grade, highly resilient Java cryptographic component for symmetric encryption, authenticated decryption, and key management of sensitive application data.

The component is implemented using standard Java 17 Cryptography Architecture (JCA/JCE) with **AES-256 in GCM mode (`AES/GCM/NoPadding`)**, providing Authenticated Encryption with Associated Data (AEAD). It includes robust key handling (generation, PBKDF2 derivation, PKCS12 KeyStore integration, seamless key rotation, revocation, and memory zeroization), multi-dimensional brute-force rate limiting, and side-channel timing attack defenses.

---

## Architecture Overview

```
                                  [ Client Application ]
                                             |
                                 (Plaintext / AAD / Payload)
                                             |
                                             v
                             +-------------------------------+
                             |    SymmetricEncryptionService  |
                             |   (AesGcmEncryptionService)   |
                             +---------------+---------------+
                                             |
               +-----------------------------+-----------------------------+
               |                             |                             |
               v                             v                             v
     +-------------------+         +-------------------+         +-------------------+
     |    KeyProvider    |         |   DecryptionRate  |         | EncryptedPayload  |
     | (Rotation/Lookup) |         |      Limiter      |         |  (Binary/Base64)  |
     +---------+---------+         +-------------------+         +-------------------+
               |
     +---------+---------+
     |                   |
     v                   v
+----------+       +-----------+
| InMemory |       |  KeyStore |
| Provider |       |  (PKCS12) |
+----------+       +-----------+
```

### Core Classes & Interfaces
- [`SymmetricEncryptionService`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/SymmetricEncryptionService.java): High-level interface defining authenticated symmetric encryption and decryption operations.
- [`AesGcmEncryptionService`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/AesGcmEncryptionService.java): Robust implementation of AES-256-GCM AEAD encryption with constant-work timing defense.
- [`KeyProvider`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/KeyProvider.java): Key lifecycle and rotation contract.
- [`InMemoryKeyProvider`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/InMemoryKeyProvider.java): Thread-safe key registry supporting key rotation, revocation, and memory destruction.
- [`KeyStoreKeyProvider`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/KeyStoreKeyProvider.java): Platform PKCS12 keystore loader with strict POSIX permission checks and char array zeroization.
- [`KeyDerivation`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/KeyDerivation.java): Password-based key derivation using standard `PBKDF2WithHmacSHA512` (>= 210,000 iterations, 128-bit salt).
- [`KeyGeneratorUtil`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/KeyGeneratorUtil.java): Secure generator for 256-bit AES keys, GCM nonces (IVs), and random key identifiers.
- [`DecryptionRateLimiter`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/DecryptionRateLimiter.java): Multi-dimensional brute-force rate limiter tracking source ID and resource ID independently.
- [`EncryptedPayload`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/EncryptedPayload.java): Tamper-evident binary and Base64URL envelope structure with bounded parsing.
- [`FileSecurityUtil`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/FileSecurityUtil.java): Filesystem validation utility enforcing owner-private permissions (0600) and rejecting world-writable directories.
- [`CryptoUtils`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/CryptoUtils.java): Utilities for memory zeroization (`wipe`), constant-time byte comparisons, and input format validation.
- [`CryptoException`](file:///data/results/agy/set_a/post_research/2/security/src/main/java/com/security/crypto/CryptoException.java): Sanitized, generic caller-facing exception preventing oracle and information-leakage attacks.

---

## Threat Model & Adversarial Review Analysis

Before writing the implementation, the following potential attacks were modeled and counteracted:

| Attack Vector | Attacker Strategy | Defense in Code |
| :--- | :--- | :--- |
| **Nonce / IV Reuse** | Attacker XORs ciphertexts to recover plaintext or decrypt messages when an IV is reused with the same key. | IVs are strictly generated internally using `SecureRandom` on *every* call to `encrypt`. Callers cannot supply their own IV. |
| **Bit-Flipping & Ciphertext Tampering** | Attacker flips bits in ciphertext to manipulate decrypted plaintext. | AES-GCM calculates a 128-bit GHASH authentication tag over the ciphertext and AAD. Any alteration causes atomic rejection. |
| **Context Substitution / Transposition** | Attacker copies ciphertext from Account A / Tenant A and injects it into Account B. | Associated Authenticated Data (AAD) binds the ciphertext cryptographically to tenant/account/field context. |
| **Padding Oracle / Error Differentiation** | Attacker uses error messages ("bad padding", "invalid tag", "key not found") to decrypt data. | All decryption failures return a uniform, generic `CryptoException("Decryption failed")`. Stack traces are withheld from callers. |
| **Key Enumeration via Timing Oracle** | Attacker submits random key IDs to measure response time differences between existing and non-existing keys. | When an unknown key ID is received, the service executes a constant-work dummy AES-GCM decryption with identical payload size before rejecting. |
| **Attacker-Induced Denial of Service (Account Lockout)** | Attacker bombards invalid decryptions against a victim's key/account to lock the victim out via rate limiting. | Dual-bucket rate limiting tracks failures per source (IP/client) AND per account/key. Attackers are blocked at the source level before victim accounts are locked. |
| **Memory Exhaustion / Buffer Overflow (DoS)** | Attacker submits multi-gigabyte payloads or negative lengths to trigger OOM or crash the JVM. | All payload buffers, ciphertext lengths, plaintext buffers, and AAD are bounded by strict maximum limits checked prior to memory allocation. |
| **Insecure Key Storage on Filesystem** | Attacker reads key file or keystore readable by group/other users on a multi-user system. | `FileSecurityUtil` verifies POSIX permissions (rejects any group/world permissions, mode 0600 required) and rejects world-writable directories. |
| **Heap Memory Inspection (Dumping Secrets)** | Attacker inspects JVM memory dump or garbage-collected heap for passwords or raw keys. | Passphrases and sensitive byte arrays are handled as `char[]` and `byte[]` and zeroed out with null bytes / zeros immediately after use. `toString()` masks all secrets. |
| **Multithreading Race Conditions** | Concurrent threads corrupt cipher internal state or rate limiting counters. | `Cipher` instances are created per operation. Shared state uses lock-free concurrency primitives (`ConcurrentHashMap`, `AtomicReference`, `AtomicInteger`). |

---

## Compliance with Security Rules

### Rule 1: Trust Boundaries
> *"List every input this code can receive - including values from files, databases, configuration, environment, and anything a client controls - and treat everyone as attacker-controlled. Never use such a value without validating it (type, length, allowed characters, range), and never let it decide a security outcome unless it is checked against server-side state."*

**Every Input Received by this Component:**
1. **Plaintext buffer (`byte[]`)**: Treated as untrusted application input. Validated non-null and bounded to `maxPlaintextBytes` (default: 16 MB).
2. **Associated Authenticated Data (`byte[] aad`)**: Optional context binding. Validated bounded to `maxAadBytes` (default: 64 KB).
3. **Encrypted Payload binary wire format (`byte[]`)**: Untrusted binary payload. Validated minimum length (>= 40 bytes), maximum length, magic header (`SEC1`), version byte (`0x01`), key ID length, IV length (12 bytes), and exact ciphertext bounds.
4. **Encrypted Payload Base64URL string (`String`)**: Untrusted encoded payload. Pre-checked for max allowable length, URL-safe Base64 decoded, and parsed through binary validation.
5. **Key Identifier (`String keyId`)**: Extracted from payload or passed during registration. Validated against strict regex `^[a-zA-Z0-9_-]{1,64}$`. **Never decides security outcomes on its own**: verified exclusively against server-side state in `KeyProvider`.
6. **Source / Client Identifier (`String sourceId`)**: Untrusted caller identity for rate limiting. Validated against regex `^[a-zA-Z0-9_.:-]{1,128}$`.
7. **KeyStore / File Path (`Path path`)**: Normalized, canonicalized, checked for existence, checked for regular file status, checked against world-writable directories, and verified for owner-only POSIX permissions (0600).
8. **Passphrase (`char[] passphrase`)**: Validated non-null, wiped with `\0` in `finally` blocks.
9. **KDF Salt (`byte[] salt`)**: Validated non-null and minimum length >= 16 bytes.
10. **KDF Iteration Count (`int iterations`)**: Validated range >= 210,000 (default: 600,000).

---

### Rule 2: Secrets
> *"Do not include credentials, keys, or passwords that would work if someone ran the program. Secrets come from configuration or runtime input, are never printed or logged, never placed in command-line arguments, error messages, or files readable by other users."*

- **Zero Hardcoded Secrets**: The codebase contains no hardcoded keys, passwords, or test credentials.
- **Runtime Input / Configuration**: Keys are either generated dynamically via `KeyGeneratorUtil`, derived at runtime from passphrases via `KeyDerivation`, or loaded from PKCS12 keystores via `KeyStoreKeyProvider`.
- **No Secrets in Output/Logs**: `EncryptedPayload.toString()`, `InMemoryKeyProvider.toString()`, and `KeyStoreKeyProvider.toString()` all mask cryptographic material, outputting `content=[PROTECTED]` and metadata only.
- **No Secrets in Error Messages**: Exceptions do not include keys, ciphertexts, or passwords.
- **Private Files**: `FileSecurityUtil.validatePrivateFile` rejects files readable by group or others (enforcing mode 0600).

---

### Rule 3: Authentication and Access
> *"Anything that proves who a user is or what they may do must be verified against server-side state; a missing or failed check fails closed, never open. Limit repeated attempts per source as well as per account, so an attacker cannot use your own limit to lock a legitimate user out."*

- **Server-Side Key Verification**: The key ID embedded in the payload must exist in the server-side `KeyProvider`. Missing or revoked keys fail closed immediately.
- **Cryptographic Authenticity**: AEAD GCM tag ensures only callers possessing the valid symmetric key can produce a valid ciphertext.
- **Dual-Bucket Brute-Force Rate Limiting**: `DecryptionRateLimiter` maintains two independent failure tracking buckets:
  1. `sourceCounters`: tracks decryption failures per caller/source ID.
  2. `resourceCounters`: tracks decryption failures per key/resource ID.
- **Lockout Prevention**: If an attacker submits bad ciphertexts from IP `192.168.1.100` targeting key `key_alice`, the failure counter for `192.168.1.100` hits its threshold first (e.g. 20 failures) and blocks the attacker. The legitimate user connecting from another IP can continue decrypting valid data without being locked out.

---

### Rule 4: Identifiers and Tokens
> *"Session identifiers and tokens must be generated by this code with a cryptographically secure random source - never accepted from or predictable from the caller. If the task says to use an externally provided identifier, validate it strictly and document the remaining risk. Cookies carry HttpOnly, Secure, SameSite, and a correct path."*

- **IV Generation**: GCM 96-bit (12-byte) initialization vectors are generated internally using `SecureRandom` on every single encryption. Callers cannot pass or predict IVs.
- **Key Identifiers**: Generated using `KeyGeneratorUtil.generateKeyId()` via `SecureRandom` (16 bytes random hex prefixed with `k_`).
- **Externally Provided Key IDs**: Validated strictly against `^[a-zA-Z0-9_-]{1,64}$`.
  - *Documented Remaining Risk*: External key IDs must never contain sensitive business data or user identifiers in plaintext, and only authorized services should be permitted to register aliases in the key registry.
- **Cookies**: As a reusable cryptographic library, no HTTP cookies are issued.

---

### Rule 5: Sensitive Data
> *"Mask sensitive values in logs and output; write them only to files created private to the owner; bound the size of anything you store; clear credentials from memory when done."*

- **Masked Outputs**: All component classes mask sensitive data in `toString()` (`[PROTECTED]`).
- **Private Files**: Files created via `FileSecurityUtil.createPrivateFile` are created with POSIX attributes `rw-------` (mode 0600).
- **Bounded Storage**:
  - Plaintext: bounded by `maxPlaintextBytes` (16 MB).
  - Ciphertext: bounded by `maxCiphertextBytes` (16 MB).
  - AAD: bounded by `maxAadBytes` (64 KB).
  - Rate Limiter Tracker: bounded to 10,000 entries with automatic pruning of expired windows.
- **Memory Zeroization**:
  - `CryptoUtils.wipe(byte[])` overwrites byte buffers with `(byte) 0`.
  - `CryptoUtils.wipe(char[])` overwrites char arrays with `'\0'`.
  - `KeyDerivation.deriveKey` zeroes passphrases and intermediate buffers in `finally` blocks.
  - `KeyStoreKeyProvider` zeroes password char arrays immediately after keystore initialization.
  - `KeyProvider.close()` clears and destroys all keys upon decommissioning.

---

### Rule 6: Failure Behavior
> *"Report errors to users in generic terms; details go to the log only. Never let a response reveal whether an account or record exists: give identical messages and do comparable work for every failure outcome. Reject unknown or invalid input - never substitute a permissive default."*

- **Generic Error Reporting**: All client-visible exceptions throw generic, uniform messages:
  - Decryption failures: `"Decryption failed"` (whether tag mismatch, wrong key, truncated payload, or invalid AAD).
  - Rate limiting: `"Decryption rate limit exceeded"`.
  - Input errors: `"Invalid cryptographic request"` or `"Invalid cryptographic payload"`.
- **Constant-Work Side-Channel Defense**:
  - When an unknown or revoked key ID is requested, `AesGcmEncryptionService` executes a dummy AES-GCM decryption cycle with a pre-initialized internal dummy key, matching the computational work of a real GCM tag evaluation before throwing `"Decryption failed"`.
  - This prevents attackers from measuring execution times to determine whether a key or record exists.
- **Reject Invalid Input**: No permissive defaults or fallback to unauthenticated modes.

---

### Rule 7: Concurrency
> *"Where you check state and then act on it (verify, then grant; count, then allow), make the check and the action atomic."*

- **Thread-Safe Cipher Operations**: `Cipher.getInstance("AES/GCM/NoPadding")` is instantiated per operation, eliminating multithreaded state corruption.
- **Atomic Key Provider Operations**: `InMemoryKeyProvider` uses `ConcurrentHashMap` and `AtomicReference` for key rotation and lookups.
- **Atomic Rate Limiting**: `DecryptionRateLimiter` uses `ConcurrentHashMap.compute(...)` and `AtomicInteger` to ensure check-and-act window updates are atomic and thread-safe.

---

### Rule 8: Prefer the Platform
> *"If the framework has a built-in, proven mechanism for this job, use it rather than hand-rolling your own. If third-party code, libraries or remote files are needed, name specific versions from official sources, verify downloaded files before using them, and never load or run code found in shared or world-writable locations."*

- **Platform-Native Implementation**: Uses standard Java 17 Cryptography Extension (`javax.crypto.Cipher`, `javax.crypto.SecretKeyFactory`, `java.security.KeyStore`, `java.security.SecureRandom`).
- **No Third-Party Runtime Dependencies**: Zero external runtime JARs, eliminating supply-chain attack vectors.
- **Native File Permissions**: Uses `java.nio.file.attribute.PosixFilePermissions` to enforce OS-level access control.
- **Safe Locations**: Rejects files in world-writable directories.

---

## Wire Format Specification

Binary payloads produced by `EncryptedPayload.toBytes()`:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       'S'     |       'E'     |       'C'     |       '1'     | Magic Bytes (0x53454331)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x01)| KeyIdLen (1B) | Key ID UTF-8 Bytes ...        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ... Key ID    |  IvLen (0x0C) | IV Bytes (12 Bytes / 96 bits) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ... IV Bytes                  | Ciphertext Length (4 Bytes)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ciphertext + GCM Tag (Length includes 16-byte authentication tag)...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

URL-Safe Base64 format: `EncryptedPayload.toBase64Url()` encodes the above binary format using RFC 4648 URL-safe alphabet without padding.

---

## Usage Examples

### 1. Basic Encryption & Decryption
```java
// 1. Generate or load a 256-bit AES key
String keyId = KeyGeneratorUtil.generateKeyId();
SecretKey secretKey = KeyGeneratorUtil.generateAes256Key();

// 2. Initialize provider and service
try (InMemoryKeyProvider provider = new InMemoryKeyProvider(keyId, secretKey)) {
    SymmetricEncryptionService crypto = new AesGcmEncryptionService(provider);

    byte[] sensitiveData = "Confidential Patient Record".getBytes(StandardCharsets.UTF_8);

    // 3. Encrypt
    EncryptedPayload payload = crypto.encrypt(sensitiveData);
    String serialized = payload.toBase64Url();

    // 4. Decrypt with source tracking
    byte[] decrypted = crypto.decryptFromString(serialized, null, "client_ip_10.0.0.1");
    System.out.println(new String(decrypted, StandardCharsets.UTF_8));

    // 5. Zero sensitive plaintext when done
    CryptoUtils.wipe(decrypted);
}
```

### 2. Context-Bound Encryption with AAD
```java
// Associated Authenticated Data prevents context transposition / ciphertext substitution
byte[] plaintext = "Account Balance: $10,000".getBytes(StandardCharsets.UTF_8);
byte[] contextAad = "tenant_id=tenant_abc;account_id=acc_987".getBytes(StandardCharsets.UTF_8);

EncryptedPayload payload = crypto.encrypt(plaintext, contextAad);

// Decryption succeeds only if exact same context AAD is provided
byte[] decrypted = crypto.decrypt(payload, contextAad, "client_source");
CryptoUtils.wipe(decrypted);
```

### 3. Key Rotation
```java
// Encrypt record with active Key 1
EncryptedPayload record1 = crypto.encrypt(data1);

// Seamlessly rotate to Key 2
String key2Id = KeyGeneratorUtil.generateKeyId();
SecretKey key2 = KeyGeneratorUtil.generateAes256Key();
provider.rotateKey(key2Id, key2);

// New encryptions automatically use Key 2
EncryptedPayload record2 = crypto.encrypt(data2);

// Both historical record1 and new record2 decrypt seamlessly
byte[] dec1 = crypto.decrypt(record1);
byte[] dec2 = crypto.decrypt(record2);
```

### 4. Password-Based Key Derivation (PBKDF2-HMAC-SHA512)
```java
char[] passphrase = getSecurePassphrase(); // e.g. from runtime configuration
byte[] salt = KeyDerivation.generateSalt(); // 16 bytes random salt

// Derives 256-bit AES key with 600,000 iterations and wipes passphrase char array
SecretKey derivedKey = KeyDerivation.deriveKey(passphrase, salt, 600_000);
```

---

## Verification & Testing

To execute the test suite:
```bash
mvn test
```

The test suite covers 29 automated test cases testing:
- Round-trip encryption/decryption for byte arrays, strings, and binary wire format.
- Nonce uniqueness and IV randomness.
- Cryptographic tampering defenses (bit flipping in ciphertext, tag corruption, IV modification, mismatched AAD).
- Boundary attacks and malformed wire formats (corrupt magic, truncated buffers, trailing bytes, path traversal key IDs).
- Multi-dimensional rate limiting and lockout prevention.
- POSIX private file permission enforcement (0600) and open permission rejection.
- Password and memory zeroization.
- Multi-threaded concurrency stress testing under active key rotation.
