# Security Review: data-crypto

## 1. Executive Summary
The component is a Java 17 library for AES-256-GCM encryption of application data, including versioned ciphertext envelopes, associated data, key rotation, environment and PKCS#12 key sources, passphrase-based key derivation, and explicit key-memory cleanup. Its core cryptographic construction is sound: it uses a 96-bit CSPRNG nonce, a 128-bit authentication tag, authenticates envelope metadata, strictly bounds and validates untrusted inputs, and does not contain hardcoded key material.

Three vulnerabilities were found. Key-file security checks and the subsequent read are separate path operations, creating a time-of-check/time-of-use race. The GCM invocation budget is stored on each cipher object, so constructing another object or restarting the process resets a security limit that must apply over the key's entire lifetime. Finally, the public PBKDF2 API permits 210,000 iterations even though the applicable review guidance requires at least 600,000 for PBKDF2-HMAC-SHA-256. No Critical findings were identified.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build descriptor | Pins the Java release, test dependency, compiler plugin, and test plugin versions. |
| `README.md` | Component and operational documentation | Documents key provisioning, rotation, nonce limits, trust boundaries, and residual risks. |
| `src/main/java/com/example/crypto/AesGcmDataCipher.java` | AES-GCM encryption, decryption, envelope parsing, and re-encryption | Generates nonces, authenticates headers and caller AAD, parses attacker-controlled ciphertext, limits sizes, selects keys, and tracks per-key encryption counts. |
| `src/main/java/com/example/crypto/Bytes.java` | Sensitive-buffer utilities | Wipes byte/character arrays, performs constant-time equality, and converts characters to strict UTF-8. |
| `src/main/java/com/example/crypto/CryptoException.java` | Generic cryptographic failure type | Prevents decryption failure details and causes from reaching callers. |
| `src/main/java/com/example/crypto/CryptoLog.java` | Central cryptographic logging helper | Separates diagnostics from caller errors and masks sensitive values. |
| `src/main/java/com/example/crypto/DataCipher.java` | Public authenticated-encryption interface | Exposes only AEAD encryption and authenticated decryption. |
| `src/main/java/com/example/crypto/EnvironmentKeySource.java` | Environment-based key loader | Parses key identifiers and Base64 key material from environment variables and destroys partially loaded keys on failure. |
| `src/main/java/com/example/crypto/KeyId.java` | Key-identifier validation | Applies a bounded ASCII allow-list to configuration and attacker-controlled envelope identifiers. |
| `src/main/java/com/example/crypto/KeyMaterial.java` | AES key generation and parsing | Uses `SecureRandom`, strictly decodes Base64 keys, validates key size, and wipes intermediate buffers. |
| `src/main/java/com/example/crypto/KeySetSecretKeyProvider.java` | In-memory key provider | Bounds and validates key sets, performs fail-closed lookup, selects the active key, and destroys keys on close. |
| `src/main/java/com/example/crypto/KeyStoreKeySource.java` | PKCS#12 key loader | Reads a password-protected keystore, extracts secret keys, validates lengths and aliases, and wipes passwords and raw material. |
| `src/main/java/com/example/crypto/PassphraseKeyDerivation.java` | Passphrase-to-key derivation | Uses PBKDF2-HMAC-SHA-256 with bounded passphrase, salt, and iteration parameters and wipes secrets. |
| `src/main/java/com/example/crypto/SecretKeyProvider.java` | Key-provider trust-boundary interface | Defines active-key selection, fail-closed key lookup, enumeration, and destruction. |
| `src/main/java/com/example/crypto/SecureFiles.java` | Key-file validation and reading | Checks file type, size, ownership, POSIX permissions, symlinks, and parent-directory permissions before reading. |
| `src/main/java/com/example/crypto/ZeroizableSecretKey.java` | Destroyable AES key implementation | Defensively copies and wipes key bytes, performs constant-time equality, and blocks serialization. |
| `src/test/java/com/example/crypto/AesGcmDataCipherTest.java` | Cipher security and functional tests | Covers tampering, AAD binding, malformed input, limits, key rotation, generic failures, fresh nonces, and concurrency. |
| `src/test/java/com/example/crypto/KeyHandlingTest.java` | Key-management security tests | Covers key validation, destruction, serialization refusal, environment loading, file permissions/symlinks, keystore passwords, and KDF parameters. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory every source and test file, identify security-relevant behaviours, route those behaviours to specialized skills, and require CWE and file:line evidence.
- `performing-cryptographic-audit-of-application`: Applied to algorithms, modes, entropy, hardcoded-secret checks, KDF parameters, key storage, rotation, and lifecycle handling.
- `implementing-aes-encryption-for-data-at-rest`: Applied to AES-256-GCM mode, tag size, nonce generation and lifetime uniqueness, associated data, PBKDF2 parameters, salts, and key erasure.
- General OWASP Top 10 / CWE knowledge: Applied to filesystem path safety and TOCTOU because the available race-condition skill targets web transaction races rather than secure key-file opening.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Key file is opened after non-atomic security checks | Medium | CWE-367 | `src/main/java/com/example/crypto/SecureFiles.java:48-62` |
| SEC-02 | GCM nonce budget resets per cipher instance | Medium | CWE-323 | `src/main/java/com/example/crypto/AesGcmDataCipher.java:102-104` |
| SEC-03 | PBKDF2 API permits an insufficient work factor | Medium | CWE-916 | `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:35-39` |

## 5. Detailed Findings

### SEC-01: Key file is opened after non-atomic security checks
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/crypto/SecureFiles.java:48-62`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SecureFiles.java:48-62
    static byte[] readPrivateFile(Path path) {
        Path file = path.toAbsolutePath().normalize();
        try {
            // NOFOLLOW_LINKS: a symlink here could redirect us to a file an
            // attacker controls, or be swapped between check and read.
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("key file is not a regular file: " + file);
            }
            long size = Files.size(file);
            if (size == 0 || size > MAX_KEY_FILE_BYTES) {
                throw new IllegalStateException("key file size is out of range: " + file);
            }
            requireOwnerOnlyAccess(file);
            requireSafeParent(file.getParent());
            return Files.readAllBytes(file);
```

**Why it is a problem:** `isRegularFile`, `size`, permission/owner checks, parent checks, and `readAllBytes` each resolve the pathname independently. `NOFOLLOW_LINKS` affects only the first check (and the attribute-view check elsewhere); it does not bind the final read to the object that passed validation. A user able to modify a path component can replace the file or an ancestor between these operations. The final `readAllBytes` follows the current path, potentially reading a different object and bypassing the type, owner, permission, and size decisions. At minimum this enables denial of service, including replacing the checked small file with a large file before the unbounded read; depending on available files and credentials it can also redirect keystore loading. Checking only `OTHERS_WRITE` on the parent further leaves group-writable directories as a practical race surface.

**Fix:** Open the final component once with OS-level no-follow semantics, then obtain type, owner, mode, and size from that same open file descriptor and perform a length-bounded read through it. Java's path-based `Files` checks cannot by themselves provide this guarantee. Use a vetted secure-file helper backed by `openat(..., O_NOFOLLOW | O_CLOEXEC)` plus `fstat`, or an equivalent platform API, and reject group-writable parent directories unless a stronger ownership policy explicitly makes them safe.
```java
static byte[] readPrivateFile(Path path) {
    Path file = path.toAbsolutePath().normalize();
    // SecureFileHandle.openReadOnlyNoFollow must open first, then use fstat on
    // this same descriptor; it must not re-resolve `file` for validation.
    try (SecureFileHandle handle = SecureFileHandle.openReadOnlyNoFollow(file)) {
        PosixFileAttributes attrs = handle.readPosixAttributes();
        if (!attrs.isRegularFile()
                || attrs.size() == 0
                || attrs.size() > MAX_KEY_FILE_BYTES
                || !attrs.owner().equals(currentPrincipal())
                || hasGroupOrOtherPermissions(attrs.permissions())) {
            throw new IllegalStateException("key file failed security checks: " + file);
        }
        requireSafeDirectoryChain(file.getParent());
        return handle.readExactlyBounded(MAX_KEY_FILE_BYTES);
    } catch (IOException e) {
        CryptoLog.configProblem("unable to read key file: " + file);
        throw new UncheckedIOException("unable to read key file", e);
    }
}
```

### SEC-02: GCM nonce budget resets per cipher instance
- **Severity:** Medium
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/example/crypto/AesGcmDataCipher.java:102-104`, `src/main/java/com/example/crypto/AesGcmDataCipher.java:156-162`, `src/main/java/com/example/crypto/AesGcmDataCipher.java:425-433`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/AesGcmDataCipher.java:102-104
    private final SecretKeyProvider keyProvider;
    private final int maxPlaintextBytes;
    private final Map<String, AtomicLong> encryptionCounters = new ConcurrentHashMap<>();
```

```java
// src/main/java/com/example/crypto/AesGcmDataCipher.java:156-162
        String keyId = keyProvider.activeKeyId();
        SecretKey key = requireUsableKey(keyId);
        byte[] keyIdBytes = asciiKeyId(keyId);

        reserveNonceBudget(keyId);

        byte[] nonce = KeyMaterial.randomBytes(NONCE_BYTES);
```

```java
// src/main/java/com/example/crypto/AesGcmDataCipher.java:425-433
    private void reserveNonceBudget(String keyId) throws CryptoException {
        AtomicLong counter = encryptionCounters.computeIfAbsent(keyId, id -> new AtomicLong());
        long used = counter.incrementAndGet();
        if (used > MAX_ENCRYPTIONS_PER_KEY) {
            counter.decrementAndGet(); // keep the counter from running away
            CryptoLog.configProblem("encryption limit reached for key id " + keyId
                    + "; rotate the key");
            throw new CryptoException("unable to encrypt data");
        }
    }
```

**Why it is a problem:** GCM requires nonce uniqueness for every encryption performed with a given key. The code uses random 96-bit nonces and attempts to cap invocations at 2^32, but the counter belongs to one `AesGcmDataCipher` object. Creating another cipher around the same provider, running multiple processes, or restarting a process creates a fresh zero counter while continuing to use the same key. The documented limit is therefore not enforced even per process, and aggregate use can grow without bound. As the number of random nonces grows, birthday collisions become increasingly likely; a single GCM key/nonce reuse compromises authentication and can reveal relationships between plaintexts.

**Fix:** Make nonce allocation and accounting a property of the key's complete operational lifetime, coordinated across all threads, objects, processes, and hosts that use it. A durable atomic counter encoded into a 96-bit nonce is preferable when coordination is available; otherwise rotate keys according to a centrally enforced aggregate limit. Do not represent this as an in-object counter.
```java
private final SecretKeyProvider keyProvider;
private final NonceAllocator nonceAllocator;

public AesGcmDataCipher(SecretKeyProvider keyProvider,
                        NonceAllocator nonceAllocator,
                        int maxPlaintextBytes) {
    this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
    this.nonceAllocator = Objects.requireNonNull(nonceAllocator, "nonceAllocator");
    this.maxPlaintextBytes = checkedPlaintextLimit(maxPlaintextBytes);
    requireUsableKey(keyProvider.activeKeyId());
}

// The implementation performs a durable, atomic increment keyed by keyId and
// returns a never-repeated 96-bit value across every process using that key.
byte[] nonce = nonceAllocator.nextNonce(keyId);
```

### SEC-03: PBKDF2 API permits an insufficient work factor
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:35-39`, `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:94-103`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PassphraseKeyDerivation.java:35-39
    /** OWASP-recommended floor for PBKDF2-HMAC-SHA-256. */
    public static final int MIN_ITERATIONS = 210_000;

    /** Default work factor; raise it as hardware improves. */
    public static final int DEFAULT_ITERATIONS = 600_000;
```

```java
// src/main/java/com/example/crypto/PassphraseKeyDerivation.java:94-103
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be "
                        + MIN_ITERATIONS + "-" + MAX_ITERATIONS);
            }

            spec = new PBEKeySpec(passphrase, salt, iterations,
                    ZeroizableSecretKey.KEY_LENGTH_BYTES * 8);
            derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
```

**Why it is a problem:** Although the default is 600,000, the public overload accepts values down to 210,000. The specialized AES-at-rest review guidance requires at least 600,000 iterations for PBKDF2-HMAC-SHA-256. Callers commonly expose this parameter through configuration, so a permitted low value can materially reduce the cost of offline passphrase guessing if the salt and encrypted data are obtained. The comment incorrectly labels the weaker value as the applicable floor.

**Fix:** Raise the enforced floor to at least 600,000, keep the default at or above that floor, and version stored KDF parameters so the cost can be increased over time. For new designs, consider a calibrated memory-hard KDF such as Argon2id when platform and interoperability requirements permit it.
```java
/** Minimum permitted work factor for PBKDF2-HMAC-SHA-256. */
public static final int MIN_ITERATIONS = 600_000;

/** Default work factor; benchmark and raise it as hardware improves. */
public static final int DEFAULT_ITERATIONS = MIN_ITERATIONS;

if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new IllegalArgumentException("iterations must be "
            + MIN_ITERATIONS + "-" + MAX_ITERATIONS);
}
```

## 6. Verified Controls and Checks With No Finding
- Authenticated encryption: `AesGcmDataCipher.java:72-84` selects AES/GCM/NoPadding with a 256-bit key policy, a 96-bit nonce, and a full 128-bit tag; no ECB or unauthenticated CBC path exists.
- Envelope and context integrity: `AesGcmDataCipher.java:163-169` and `AesGcmDataCipher.java:241-246` authenticate the complete header and caller-supplied AAD before returning plaintext.
- Cryptographic randomness: `KeyMaterial.java:22-34` uses a shared `SecureRandom` for keys, salts, and nonces without caller-controlled seeds.
- Untrusted ciphertext parsing: `AesGcmDataCipher.java:192-229` bounds the envelope before parsing and validates magic, version, key-id length, and the minimum authenticated-ciphertext size.
- Input and allocation bounds: plaintext, envelope, Base64, AAD, key count, key-file size, passphrase, salt, and KDF iteration values all have explicit limits in their respective parsing paths.
- Key-identifier injection prevention: `KeyId.java:30-44` permits only 1-64 ASCII characters from `[A-Za-z0-9._-]`, blocking path separators, control characters, Unicode ambiguity, and log newlines in attacker-controlled envelope IDs.
- Fail-closed key lookup: `KeySetSecretKeyProvider.java:75-84` returns no key for invalid or unknown identifiers and does not derive or load keys based on ciphertext input.
- Decryption oracle resistance: `AesGcmDataCipher.java:231-265` uses a decoy key for unknown IDs, and `CryptoException.java:20-23` exposes one generic message with no chained cause or stack trace.
- Secret logging: `CryptoLog.java:26-49` centralizes diagnostics and masks sensitive inputs; reviewed call sites log metadata rather than plaintext, passphrases, passwords, ciphertext, or key bytes.
- Key generation and import: `KeyMaterial.java:44-88` generates 32 random bytes or strictly decodes bounded Base64 input, and `ZeroizableSecretKey.java:37-51` rejects wrong-length and all-zero keys.
- Memory hygiene: sensitive temporary arrays are wiped in `finally` blocks; `ZeroizableSecretKey.java:65-76` clones exports and destroys its owned bytes, and `ZeroizableSecretKey.java:120-132` blocks serialization and deserialization.
- Keystore integrity and password handling: `KeyStoreKeySource.java:55-60` uses PKCS#12 password verification, while `KeyStoreKeySource.java:100-107` destroys partial keys and wipes file contents and the supplied password on every exit path. The non-atomic file opening is reported separately as SEC-01.
- Key-source failure handling: `EnvironmentKeySource.java:62-100` has no default key, requires active-key material, strictly parses configuration, bounds the number of keys, and destroys partially loaded keys after failure.
- Passphrase derivation construction: aside from SEC-03's floor, `PassphraseKeyDerivation.java:90-114` uses PBKDF2-HMAC-SHA-256, a 256-bit output, a 16-64 byte salt, bounded inputs, and clears both the `PBEKeySpec` and caller passphrase.
- Dependency surface: `pom.xml:23-49` declares no runtime dependency, scopes JUnit to tests, and pins dependency and plugin versions without ranges or snapshots.
- Security regression tests: the two test classes cover ciphertext/tag/nonce/header tampering, AAD mismatch, truncation, arbitrary input, oversized input, key rotation, concurrency, key erasure, serialization refusal, malformed configuration, weak file modes, symlinks, wrong passwords, and weak KDF parameters. The review remained static and did not execute these tests or any untrusted project code.
