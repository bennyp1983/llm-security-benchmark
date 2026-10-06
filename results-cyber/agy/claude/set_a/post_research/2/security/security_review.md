# Security Review: data-crypto

## 1. Executive Summary
The `data-crypto` component is a zero-dependency Java 17 library providing authenticated symmetric encryption for sensitive application data (such as payment card data, tokens, and PII) using AES-256-GCM. It encompasses end-to-end cryptographic key handling, including key loading from environment variables or PKCS#12 keystores, strict input validation, key identifier tracking, key rotation helpers, and memory zeroization. 

A comprehensive static security audit of all source and configuration files was conducted. The component was evaluated against standard vulnerability classes including algorithm downgrade, padding oracles, key/IV reuse, error-based timing and enumeration oracles, insecure deserialization, privilege escalation/file permission flaws, and sensitive data leakage in logs or memory. 

No security vulnerabilities were identified in the codebase. The implementation strictly adheres to modern cryptographic standards and defensive programming principles, employing robust fail-closed controls, NIST SP 800-38D-compliant nonce budget capping, decoy decryption routines to prevent key existence oracles, constant-time comparisons, and comprehensive memory zeroization.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/crypto/DataCipher.java` | Main encryption/decryption interface | Enforces AEAD-only contract (`encrypt` and `decrypt` with Associated Authenticated Data); exposes active key ID. |
| `src/main/java/com/example/crypto/AesGcmDataCipher.java` | Core AES-256-GCM cipher and envelope handler | Generates 96-bit CSPRNG nonces; enforces 128-bit tag and 2^32 per-key encryption ceiling; binds version and key ID into AAD; executes decoy decryption on unknown key IDs; bounds input sizes. |
| `src/main/java/com/example/crypto/SecretKeyProvider.java` | Trust boundary interface for symmetric keys | Defines key lookup, rotation support, and memory destruction lifecycle (`close()`). |
| `src/main/java/com/example/crypto/KeySetSecretKeyProvider.java` | Immutable in-memory key set provider | Validates key IDs; bounds key count (max 64); ensures active key exists; provides fail-closed key lookup; wipes keys on `close()`. |
| `src/main/java/com/example/crypto/ZeroizableSecretKey.java` | Eraseable AES-256 SecretKey implementation | Enforces 256-bit non-zero key material; synchronizes access and zeroization; performs constant-time equality checks; prevents Java serialization/deserialization via `NotSerializableException`. |
| `src/main/java/com/example/crypto/KeyMaterial.java` | Key generation and Base64 parsing | Generates 256-bit keys via `java.security.SecureRandom`; strictly validates and decodes Base64 configuration keys with immediate buffer wiping. |
| `src/main/java/com/example/crypto/PassphraseKeyDerivation.java` | PBKDF2-HMAC-SHA-256 key derivation | Enforces a minimum floor of 210,000 iterations (default 600,000); generates 128-bit CSPRNG salts; validates passphrase lengths (12–1024 chars); clears passphrase and intermediate keys from memory. |
| `src/main/java/com/example/crypto/EnvironmentKeySource.java` | Key loader from environment variables | Parses `APP_DATA_KEY_*` variables; validates key IDs and Base64 encoding; wipes intermediate character arrays; enforces bounded key counts. |
| `src/main/java/com/example/crypto/KeyStoreKeySource.java` | Key loader from PKCS#12 keystores | Verifies keystore file safety via `SecureFiles`; extracts only 256-bit AES `SecretKeyEntry` items; wipes password and file contents from memory. |
| `src/main/java/com/example/crypto/SecureFiles.java` | Filesystem security checks for key files | Prevents symlink following (`NOFOLLOW_LINKS`); enforces owner-only permissions (chmod 600); verifies owner matches JVM user; checks that parent directory is not world-writable; bounds file size (1 B–256 KiB). |
| `src/main/java/com/example/crypto/KeyId.java` | Key identifier validator | Restricts key IDs to a strict allow-list `[A-Za-z0-9._-]{1,64}` to prevent path traversal, control character injection, and DoS. |
| `src/main/java/com/example/crypto/Bytes.java` | Memory wiping and constant-time utilities | Provides null-safe byte/char array zeroization; implements constant-time comparison via `MessageDigest.isEqual`; encodes UTF-8 without intermediate String leaks. |
| `src/main/java/com/example/crypto/CryptoLog.java` | Centralized logging funnel | Ensures plaintext, ciphertext, and key material are never logged; masks lengths (`[redacted N bytes]`); restricts diagnostic logs to `Level.FINE`. |
| `src/main/java/com/example/crypto/CryptoException.java` | Deliberately uninformative exception | Returns generic failure messages without chained causes or stack traces (`writableStackTrace = false`) to prevent error oracles. |
| `src/test/java/com/example/crypto/AesGcmDataCipherTest.java` | Unit tests for cipher and envelope operations | Validates tampering detection, bit flips, truncation, AAD mismatches, unknown key oracle resistance, and concurrency safety. |
| `src/test/java/com/example/crypto/KeyHandlingTest.java` | Unit tests for key lifecycle and loading | Validates key zeroization, non-serializability, environment/keystore loading, permission validation, and PBKDF2 parameters. |
| `pom.xml` | Maven build configuration | Validates build settings, Java 17 target, pinned dependencies (`junit-jupiter:5.10.2` in test scope only), and zero runtime dependencies. |

## 3. Skills Applied
- `implementing-aes-encryption-for-data-at-rest`: Applied to review AES-256-GCM AEAD construction, 96-bit CSPRNG nonce management, per-key nonce invocation limits (NIST SP 800-38D), 128-bit authentication tag verification, envelope formatting, and PBKDF2 key derivation parameter floors.
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, key generation randomness (`SecureRandom`), zeroization/memory erasure routines (`destroy()`, `Bytes.wipe`), constant-time comparison implementations (`MessageDigest.isEqual`), timing side-channel resistance, error oracle prevention (decoy decryption), and secure key storage.
- General OWASP Top 10 / CWE Review:
  - Input Validation & Denial-of-Service (CWE-20, CWE-129, CWE-400): Applied to review length-bounding and pre-allocation checks on envelope parsing, Base64 decoding, AAD length, and plaintext buffers.
  - Path Traversal & Filesystem Security (CWE-22, CWE-59, CWE-732): Applied to review `SecureFiles.java` POSIX permission verification, symlink prohibition (`NOFOLLOW_LINKS`), owner matching, and directory write restrictions.
  - Insecure Deserialization & Object Injection (CWE-502, CWE-312): Applied to review `ZeroizableSecretKey.java` serialization prevention (`writeObject`/`readObject` rejecting serialization).
  - Sensitive Information Leakage in Logs & Errors (CWE-209, CWE-532): Applied to review `CryptoLog.java` redaction mechanisms and `CryptoException.java` stack trace suppression.
  - Race Conditions & Thread Safety (CWE-362): Applied to review per-operation `Cipher` instantiations, `AtomicLong` counter reservations, and thread-safe collections.

## 4. Summary of Findings
No security vulnerabilities were identified in the reviewed codebase.

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| None | No vulnerabilities found | N/A | N/A | N/A |

## 5. Detailed Findings
No security vulnerabilities were found during this code review. The component demonstrates defensive architecture and adherence to security and cryptographic engineering standards across all analyzed files.

## 6. Verified Controls and Checks With No Finding
- **AES-GCM Authenticated Encryption Standard Compliance**: Verified in `AesGcmDataCipher.java` (lines 72, 165–170, 242–246) that `AES/GCM/NoPadding` with full 128-bit authentication tag (`TAG_BITS = 128`) is used exclusively. Decryption validates the tag and fails closed before returning any plaintext, eliminating unauthenticated ciphertext processing.
- **Nonce/IV Randomness & Generation**: Verified in `AesGcmDataCipher.java` (line 162) and `KeyMaterial.java` (lines 22, 28–35) that a fresh 96-bit (12-byte) nonce is generated for every encryption using a shared `java.security.SecureRandom` CSPRNG instance. Callers cannot provide or influence nonces.
- **Atomic Nonce Exhaustion Protection**: Verified in `AesGcmDataCipher.java` (lines 89, 425–434) that invocations per key are tracked with an `AtomicLong` per key ID, enforcing NIST SP 800-38D's limit of 2^32 (`MAX_ENCRYPTIONS_PER_KEY = 4_294_967_296L`) encryptions per key per process, atomically rejecting further encryptions once exhausted.
- **Envelope Header Authentication via AAD**: Verified in `AesGcmDataCipher.java` (lines 167–168, 244–245, 376–380) that the envelope header (magic `EDC1`, version byte, key ID length, and key ID) is fed into the cipher's associated authenticated data along with caller-supplied AAD. This prevents ciphertext re-labelling, format version downgrade, or context mismatch attacks.
- **Decoy Decryption Against Key Enumeration Oracles**: Verified in `AesGcmDataCipher.java` (lines 110, 231–253) that if a ciphertext specifies an unknown or unusable key ID, a decoy decryption pass is executed using an instance-unique random 256-bit key (`decoyKey`). The execution workload and failure outcome remain indistinguishable from a corrupted or forged ciphertext, preventing attackers from probing for valid key IDs.
- **Constant-Time Comparisons**: Verified in `AesGcmDataCipher.java` (line 205), `ZeroizableSecretKey.java` (line 100), and `Bytes.java` (lines 37–39) that comparisons of envelope magic bytes and key material use `MessageDigest.isEqual` (`Bytes.constantTimeEquals`), preventing timing side-channel attacks.
- **Uninformative Error Reporting & Stack Trace Suppression**: Verified in `CryptoException.java` (lines 20–25) and `AesGcmDataCipher.java` (lines 462–465) that all decryption failures return a generic error message (`"unable to decrypt data"`) without exposing internal causes, and `super(genericMessage, null, true, false)` explicitly disables stack trace generation (`writableStackTrace = false`), preventing information leakage.
- **Explicit Memory Zeroization & Hygiene**: Verified in `ZeroizableSecretKey.java` (lines 73–76), `Bytes.java` (lines 19–30), `PassphraseKeyDerivation.java` (lines 109–115), `KeyStoreKeySource.java` (lines 106–108), `KeyMaterial.java` (lines 49, 86–88), and `AesGcmDataCipher.java` (lines 180, 251, 255, 264, 284, 306–307, 335) that sensitive byte and char arrays (nonces, passphrases, keystore passwords, Base64 buffers, intermediate plaintexts, and `PBEKeySpec`) are actively zeroed in `finally` blocks.
- **Serialization Prohibition**: Verified in `ZeroizableSecretKey.java` (lines 126–132) that `writeObject` and `readObject` explicitly throw `NotSerializableException`, preventing key material from being serialized to streams, caches, or session stores.
- **Input Validation & Buffer Bounds**: Verified in `AesGcmDataCipher.java` (lines 150–153, 198–201, 357–360, 386–390) and `KeyId.java` (lines 30–45) that plaintext sizes (1 B to 64 MiB), AAD sizes (max 64 KiB), envelope sizes (min/max calculated before allocation), Base64 string lengths, and key ID strings (strictly validated against `[A-Za-z0-9._-]{1,64}`) are validated prior to allocation, preventing denial-of-service and buffer exhaustion.
- **Password-Based Key Derivation Safeguards**: Verified in `PassphraseKeyDerivation.java` (lines 35–55, 84–97) that PBKDF2-HMAC-SHA-256 enforces an iteration floor of 210,000 (meeting OWASP 2023 guidelines), defaults to 600,000, enforces salt lengths of 16–64 bytes, and requires passphrases between 12 and 1024 characters.
- **Filesystem Hardening & Permission Enforcement**: Verified in `SecureFiles.java` (lines 53–62, 75–97, 99–113) that key files must be regular files inspected with `LinkOption.NOFOLLOW_LINKS`, owned by the current JVM user (`user.name`), strictly limited to owner-only permissions (chmod 600, rejecting group/other access), bounded in size (max 256 KiB), and located in directories that are not world-writable (`OTHERS_WRITE`).
- **Logging Redaction & Sanitization**: Verified in `CryptoLog.java` (lines 27–51) that log entries only record non-secret metadata (key IDs, lengths, and fixed status messages). Sensitive data is masked using non-reversible string placeholders (`masked(byte[])`), and diagnostic messages are restricted to `Level.FINE`.
- **Concurrency & Thread Safety**: Verified in `AesGcmDataCipher.java` (lines 104, 165, 242) that cryptographic `Cipher` instances are instantiated per operation, nonce counters utilize `ConcurrentHashMap` with atomic operations, and `ZeroizableSecretKey.java` synchronizes access to key material and destruction state across threads.
- **Supply Chain & Dependency Security**: Verified in `pom.xml` (lines 23–52) that the production artifact has zero runtime third-party dependencies, test dependencies are pinned to JUnit 5.10.2, and build plugins are pinned to exact official versions without dynamic ranges.
