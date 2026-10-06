# Security Review: Secure Symmetric Encryption & Key Management Component

## 1. Executive Summary
This Java 17 component provides AES-256-GCM encryption, a bounded binary/Base64URL envelope, PBKDF2 key derivation, in-memory and PKCS12-backed key providers, key rotation/revocation, private-file helpers, and decryption-failure throttling. The cryptographic primitives are well chosen: encryption uses a fresh 96-bit `SecureRandom` nonce, a 128-bit GCM tag, defensive copies, and strict envelope length checks. However, seven vulnerabilities remain. The most important are denial-of-service through an unbounded rate-limit map despite its stated 10,000-entry cap, source-limit bypass through caller-controlled identities, and a key/key-ID race that can make newly encrypted data permanently undecryptable during rotation. The keystore path also has a validation-to-open race, concurrent requests can overrun failure thresholds, attacker-influenced KDF work factors have no upper bound, and some early failures skip promised password wiping.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and dependency configuration | Targets Java 17 and pins compiler, test runner, and JUnit versions; no runtime third-party dependency is introduced. |
| `src/main/java/com/security/crypto/AesGcmEncryptionService.java` | Implements authenticated encryption and decryption | Selects keys, generates IVs, invokes AES-GCM, applies AAD, parses untrusted payloads, and invokes throttling. |
| `src/main/java/com/security/crypto/CryptoException.java` | Component exception type | Carries caller-facing errors and optional internal causes. |
| `src/main/java/com/security/crypto/CryptoUtils.java` | Validation, comparison, copying, and wiping helpers | Validates key/source identifiers and input sizes; performs defensive copies and best-effort zeroization. |
| `src/main/java/com/security/crypto/DecryptionRateLimiter.java` | Tracks decryption failures | Maintains per-source and per-resource fixed-window counters in process memory. |
| `src/main/java/com/security/crypto/EncryptedPayload.java` | Defines and parses the ciphertext envelope | Parses attacker-controlled binary/Base64URL data with magic, version, identifier, IV, and length validation. |
| `src/main/java/com/security/crypto/FileSecurityUtil.java` | Validates and creates private files | Checks file type, ownership, POSIX permissions, and parent-directory writability. |
| `src/main/java/com/security/crypto/InMemoryKeyProvider.java` | Stores and rotates keys in memory | Registers, selects, rotates, revokes, and attempts to destroy AES keys concurrently. |
| `src/main/java/com/security/crypto/KeyDerivation.java` | Derives AES keys from passphrases | Uses PBKDF2-HMAC-SHA-512 and accepts configurable salt sizes and iteration counts. |
| `src/main/java/com/security/crypto/KeyGeneratorUtil.java` | Generates keys, IVs, and key IDs | Uses `SecureRandom` and JCA `KeyGenerator` for security-sensitive random values. |
| `src/main/java/com/security/crypto/KeyProvider.java` | Key-provider contract | Exposes active-key and key-ID lookup as separate operations. |
| `src/main/java/com/security/crypto/KeyStoreKeyProvider.java` | Loads AES keys from PKCS12 | Opens validated filesystem paths or caller-provided streams, consumes a password, and imports key entries. |
| `src/main/java/com/security/crypto/SymmetricEncryptionService.java` | Public encryption-service API | Exposes plaintext, AAD, serialized payload, and source-identity trust boundaries. |
| `src/test/java/com/security/crypto/FileSecurityTest.java` | Tests private-file controls | Covers owner-only creation, permissive file rejection, and basic keystore loading, but not path-swap races. |
| `src/test/java/com/security/crypto/SymmetricCryptoTest.java` | Tests crypto and concurrency behaviour | Covers round trips, tampering, parsing bounds, rotation, rate limiting, KDF validation, and concurrency, but not synchronized race windows or upper resource bounds. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every code file and map each security-relevant behaviour to specialized checks.
- `performing-cryptographic-audit-of-application`: Applied to algorithms, cipher mode, key sizes, entropy, secrets, PBKDF2 parameters, key storage, and rotation.
- `implementing-aes-encryption-for-data-at-rest`: Applied to AES-GCM tag handling, 96-bit nonce generation, AEAD/AAD use, payload metadata, and key lifecycle.
- `exploiting-race-condition-vulnerabilities`: Applied statically to key selection, filesystem validation/opening, and rate-limit check/use sequences.
- `implementing-api-rate-limiting-and-throttling`: Applied to counter atomicity, identifier choice, storage bounds, and enforcement semantics.
- `performing-api-rate-limiting-bypass`: Applied to caller-controlled source rotation, resource-identifier rotation, concurrent bursts, and lockout/DoS paths.
- General OWASP Top 10 / CWE knowledge: Applied to custom binary parsing, filesystem permissions, error handling, sensitive-data exposure, dependency scope, defensive copying, and resource-exhaustion cases not fully covered by a specialized skill.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate-limit tracker grows beyond its advertised hard cap | Medium | CWE-400 | `src/main/java/com/security/crypto/DecryptionRateLimiter.java:153-156` |
| SEC-02 | Caller-controlled and shared source IDs defeat source isolation | Medium | CWE-799 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:145-163` |
| SEC-03 | Non-atomic active-key selection can produce undecryptable ciphertext | Medium | CWE-362 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:109-127` |
| SEC-04 | Keystore validation and opening are vulnerable to a path-swap race | Medium | CWE-367 | `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-49` |
| SEC-05 | Separate rate-limit check and failure recording allows concurrent limit overruns | Medium | CWE-362 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:162-191` |
| SEC-06 | KDF cost and salt allocation have no upper bounds | Low | CWE-400 | `src/main/java/com/security/crypto/KeyDerivation.java:61-66` |
| SEC-07 | Early failures skip promised passphrase wiping | Low | CWE-316 | `src/main/java/com/security/crypto/KeyDerivation.java:98-112` |

## 5. Detailed Findings

### SEC-01: Rate-limit tracker grows beyond its advertised hard cap
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/crypto/DecryptionRateLimiter.java:153-156`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/DecryptionRateLimiter.java:153-156
    private void pruneIfNecessary(ConcurrentHashMap<String, WindowCounter> map, long now) {
        if (map.size() >= MAX_MAP_ENTRIES) {
            map.entrySet().removeIf(entry -> (now - entry.getValue().windowStartMs) > windowDurationMs);
        }
    }
```

**Why it is a problem:** Reaching 10,000 entries only triggers removal of expired entries. If those entries are still inside the window, nothing is removed and `recordFailure` immediately inserts the next unique source or resource ID. An attacker can rotate syntactically valid source IDs and payload key IDs to grow both maps without limit, retaining attacker-controlled strings and counter objects until heap pressure or JVM failure. This directly contradicts the class's claimed hard storage bound.

**Fix:** Use an actually bounded cache with expiry, or make pruning and admission one atomic operation that rejects a new identifier when no expired slot is available. A production implementation should also place an upstream request limit on unknown identifiers.
```java
private void recordBounded(ConcurrentHashMap<String, WindowCounter> map,
                           String id, long now) {
    synchronized (map) {
        map.entrySet().removeIf(entry ->
                (now - entry.getValue().windowStartMs) > windowDurationMs);
        if (!map.containsKey(id) && map.size() >= MAX_MAP_ENTRIES) {
            throw new CryptoException("Decryption rate limit capacity exceeded");
        }
        map.compute(id, (key, counter) -> {
            if (counter == null) {
                return new WindowCounter(now, 1);
            }
            counter.count.incrementAndGet();
            return counter;
        });
    }
}
```

### SEC-02: Caller-controlled and shared source IDs defeat source isolation
- **Severity:** Medium
- **CWE:** CWE-799: Improper Control of Interaction Frequency
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:145-163`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:145-163
    public byte[] decrypt(EncryptedPayload payload) {
        return decrypt(payload, null, DEFAULT_SOURCE_ID);
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload, byte[] aad) {
        return decrypt(payload, aad, DEFAULT_SOURCE_ID);
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload, byte[] aad, String sourceId) {
        Objects.requireNonNull(payload, "Payload must not be null");
        String validatedSourceId = CryptoUtils.validateSourceId(sourceId);
        CryptoUtils.validateAad(aad, maxAadBytes);

        String keyId = payload.getKeyId();

        // Rule 3 & 7: Check failure limits atomically per source and per key/resource
        rateLimiter.checkAllowed(validatedSourceId, keyId);
```

**Why it is a problem:** A regular expression proves only the shape of `sourceId`, not who supplied it. A caller can rotate valid values and evade the per-source bucket. Conversely, overloads without a source ID place every caller in `internal_client`, allowing one caller's failures to throttle unrelated callers. The per-resource bucket limits brute-force work against one known key, but source rotation still permits attacks across keys/unknown IDs and lets an attacker deliberately consume a victim key's shared failure allowance.

**Fix:** Derive a stable source identity at a trusted boundary (for example, an authenticated principal or a client address set by a trusted proxy), and remove public overloads that silently merge independent callers. The service should receive a non-forgeable context rather than arbitrary text.
```java
public byte[] decrypt(EncryptedPayload payload, byte[] aad,
                      TrustedCallerContext caller) {
    Objects.requireNonNull(caller, "Trusted caller context must not be null");
    String sourceId = CryptoUtils.validateSourceId(caller.stableRateLimitId());
    String keyId = payload.getKeyId();
    rateLimiter.checkAllowed(sourceId, keyId);
    return decryptAfterRateLimit(payload, aad, sourceId, keyId);
}
```

### SEC-03: Non-atomic active-key selection can produce undecryptable ciphertext
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:109-127`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:109-127
        // Retrieve server-side active key
        SecretKey activeKey = keyProvider.getActiveKey();
        String activeKeyId = keyProvider.getActiveKeyId();

        // Rule 4: Cryptographically secure fresh IV generated internally; caller cannot specify IV
        byte[] iv = KeyGeneratorUtil.generateGcmIv();

        try {
            // Rule 7 & 8: Per-operation Cipher instance avoids concurrency race conditions
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, activeKey, spec);

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            return new EncryptedPayload(EncryptedPayload.CURRENT_VERSION, activeKeyId, iv, ciphertextWithTag);
```

**Why it is a problem:** The key and its identifier are read in separate operations. If `rotateKey` runs between those calls, encryption can use the old key while labeling the payload with the new key ID. Later decryption selects the new key and rejects the tag, causing durable loss of access to successfully returned ciphertext. Thread-safe fields do not make this multi-step invariant atomic.

**Fix:** Resolve the identifier first and then fetch that exact key, or change `KeyProvider` to return an immutable `(keyId, key)` snapshot in one operation. Historical keys must remain available while in-flight encryption completes.
```java
String activeKeyId = keyProvider.getActiveKeyId();
SecretKey activeKey = keyProvider.getKey(activeKeyId)
        .orElseThrow(() -> new CryptoException(
                "Invalid cryptographic request: active key not found"));

byte[] iv = KeyGeneratorUtil.generateGcmIv();
Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
cipher.init(Cipher.ENCRYPT_MODE, activeKey,
        new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
if (aad != null && aad.length > 0) {
    cipher.updateAAD(aad);
}
byte[] ciphertextWithTag = cipher.doFinal(plaintext);
return new EncryptedPayload(
        EncryptedPayload.CURRENT_VERSION, activeKeyId, iv, ciphertextWithTag);
```

### SEC-04: Keystore validation and opening are vulnerable to a path-swap race
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-49`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-49
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
        try (InputStream in = Files.newInputStream(validatedPath)) {
            return fromInputStream(in, password, activeKeyAlias);
```

**Why it is a problem:** File type, ownership, permissions, and the immediate parent are checked before a separate pathname-based open. A local attacker able to modify a parent directory can replace the checked entry between those operations. This is made more reachable because `FileSecurityUtil` rejects only `OTHERS_WRITE` on the parent and accepts group-writable directories. `Files.newInputStream` then follows the current path, not necessarily the object that passed validation, allowing an attacker-controlled keystore to be loaded or causing reliable service failure.

**Fix:** Require every directory in the configured path to be non-writable by group/others, open with `NOFOLLOW_LINKS`, and bind validation to the opened file descriptor/inode using an OS-backed secure directory/file API. If descriptor-bound attribute validation is unavailable, copy the keystore at deployment into an application-owned, non-writable configuration directory and open only there.
```java
Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
Set<OpenOption> options = Set.of(
        StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
try (SeekableByteChannel channel = Files.newByteChannel(validatedPath, options);
     InputStream in = Channels.newInputStream(channel)) {
    // The configured directory and all ancestors must be application-owned
    // and not writable by group/others before this descriptor-bound open.
    return fromInputStream(in, password, activeKeyAlias);
}
```

### SEC-05: Separate rate-limit check and failure recording allows concurrent limit overruns
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:162-191`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:162-191
        // Rule 3 & 7: Check failure limits atomically per source and per key/resource
        rateLimiter.checkAllowed(validatedSourceId, keyId);

        // Rule 1 & 6: Verify key ID against server-side state
        Optional<SecretKey> optKey = keyProvider.getKey(keyId);
        if (optKey.isEmpty()) {
            // Rule 6: Neutralize timing oracle attacks.
            // Perform identical computational work using a dummy key before rejecting.
            performDummyDecryption(payload.getIv(), payload.getCiphertextWithTag(), aad);
            rateLimiter.recordFailure(validatedSourceId, keyId);
            LOGGER.log(Level.FINE, "Decryption failed: unknown or revoked key identifier");
            throw new CryptoException("Decryption failed");
        }

        SecretKey decryptionKey = optKey.get();

        try {
            // Rule 7 & 8: Dedicated Cipher instance per invocation guarantees thread-safety
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.getIv());
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, spec);

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(payload.getCiphertextWithTag());
        } catch (GeneralSecurityException e) {
            // Record failure in rate limiter to throttle brute-force attacks
            rateLimiter.recordFailure(validatedSourceId, keyId);
```

**Why it is a problem:** `checkAllowed` and `recordFailure` are individually thread-safe but do not form one atomic admission decision. Many requests can all observe a count below the threshold, perform the costly cryptographic operation, and only then increment the counter. A synchronized burst can therefore exceed the configured threshold by an arbitrary number of concurrent requests, weakening brute-force and resource-exhaustion protection.

**Fix:** Atomically reserve an attempt before performing cryptographic work. A successful operation may refund/reset the reservation according to policy. For multi-instance deployments, perform the reservation in a shared atomic store rather than a process-local map.
```java
// Atomically checks the window and increments the attempt count in one operation.
rateLimiter.acquireAttempt(validatedSourceId, keyId);
try {
    Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, decryptionKey,
            new GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.getIv()));
    if (aad != null && aad.length > 0) {
        cipher.updateAAD(aad);
    }
    byte[] plaintext = cipher.doFinal(payload.getCiphertextWithTag());
    rateLimiter.recordSuccess(validatedSourceId, keyId);
    return plaintext;
} catch (GeneralSecurityException e) {
    throw new CryptoException("Decryption failed");
}
```

### SEC-06: KDF cost and salt allocation have no upper bounds
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/crypto/KeyDerivation.java:61-66`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyDerivation.java:61-66
    public static byte[] generateSalt(int length) {
        if (length < MIN_SALT_BYTES) {
            throw new CryptoException("Salt length must be at least " + MIN_SALT_BYTES + " bytes");
        }
        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
```

**Why it is a problem:** `generateSalt` accepts any positive `int` above the minimum and allocates it directly. Similarly, `deriveKey` rejects low iteration counts but permits values up to `Integer.MAX_VALUE`. If configuration or an API passes attacker-influenced values, these operations can cause very large allocations or monopolize CPU for an extended period. This is lower severity because safe use normally keeps these parameters under trusted application control.

**Fix:** Define deployment-appropriate maximums and validate both lower and upper bounds before allocating or invoking PBKDF2.
```java
public static final int MAX_SALT_BYTES = 64;
public static final int MAX_ITERATIONS = 2_000_000;

public static byte[] generateSalt(int length) {
    if (length < MIN_SALT_BYTES || length > MAX_SALT_BYTES) {
        throw new CryptoException("Salt length is outside the permitted range");
    }
    byte[] salt = new byte[length];
    SECURE_RANDOM.nextBytes(salt);
    return salt;
}

if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new CryptoException("Iteration count is outside the permitted range");
}
```

### SEC-07: Early failures skip promised passphrase wiping
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/security/crypto/KeyDerivation.java:98-112`; `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-49`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyDerivation.java:98-112
    public static SecretKey deriveKey(char[] passphrase, byte[] salt, int iterations) {
        Objects.requireNonNull(passphrase, "Passphrase must not be null");
        Objects.requireNonNull(salt, "Salt must not be null");

        if (salt.length < MIN_SALT_BYTES) {
            throw new CryptoException("Salt must be at least " + MIN_SALT_BYTES + " bytes");
        }
        if (iterations < MIN_ITERATIONS) {
            throw new CryptoException("Iteration count must be at least " + MIN_ITERATIONS);
        }

        PBEKeySpec spec = null;
        byte[] encodedKey = null;
        try {
```
```java
// src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-49
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
        try (InputStream in = Files.newInputStream(validatedPath)) {
            return fromInputStream(in, password, activeKeyAlias);
```

**Why it is a problem:** Both APIs promise to zero caller-supplied character arrays. In `deriveKey`, null/short salt and low-iteration failures occur before the `finally` block that wipes `passphrase`. In `fromFile`, path-validation or file-open failure occurs before `fromInputStream` reaches its password-wiping `finally`. Passwords therefore remain in the caller's mutable array on predictable error paths, increasing their exposure in heap dumps and later accidental reuse.

**Fix:** Put every operation that can fail after accepting the secret inside an outer `try/finally`. Nested code may wipe the array again safely.
```java
public static SecretKey deriveKey(char[] passphrase, byte[] salt, int iterations) {
    Objects.requireNonNull(passphrase, "Passphrase must not be null");
    try {
        Objects.requireNonNull(salt, "Salt must not be null");
        validateKdfParameters(salt, iterations);
        return deriveValidatedKey(passphrase, salt, iterations);
    } finally {
        CryptoUtils.wipe(passphrase);
    }
}

public static KeyStoreKeyProvider fromFile(
        Path path, char[] password, String activeAlias) {
    Objects.requireNonNull(password, "Password must not be null");
    try {
        Path validated = FileSecurityUtil.validatePrivateFile(path);
        try (InputStream in = Files.newInputStream(validated)) {
            return fromInputStream(in, password, activeAlias);
        }
    } catch (Exception e) {
        throw normalizeKeyStoreException(e);
    } finally {
        CryptoUtils.wipe(password);
    }
}
```

## 6. Verified Controls and Checks With No Finding
- AES primitive and mode: `AesGcmEncryptionService.java:42-43,118-126,180-188` uses AES-GCM with a 128-bit authentication tag; no ECB, CBC, weak cipher, or unauthenticated decryption path was found.
- Nonce generation: `KeyGeneratorUtil.java:22,60-63` generates a fresh 96-bit IV with `SecureRandom`, and the public encryption API does not accept caller-supplied IVs.
- Key generation and size validation: `KeyGeneratorUtil.java:33-37`, `InMemoryKeyProvider.java:54-68`, and `KeyStoreKeyProvider.java:83-94` generate or accept only 256-bit AES keys when encoded key material is available.
- Password-based derivation baseline: `KeyDerivation.java:27-47,102-124` uses PBKDF2-HMAC-SHA-512, requires at least a 128-bit salt and 210,000 iterations, and clears the passphrase and intermediate encoded key in a `finally` block.
- No production hardcoded secrets: Main sources contain no embedded working keys or passwords; literal passwords occur only in isolated test fixtures.
- Envelope parsing bounds: `EncryptedPayload.java:144-207,218-235` validates minimum/maximum size, magic, version, key-ID length and character set, exact IV length, ciphertext/tag length, trailing bytes, and Base64 length before material allocation.
- Defensive copying: `EncryptedPayload.java:82-88,99-104` copies IV and ciphertext arrays on construction and access, preventing callers from mutating authenticated payload state through retained references.
- Tamper and context detection: `AesGcmEncryptionService.java:122-126,184-188` authenticates ciphertext and optional AAD; tests at `SymmetricCryptoTest.java:191-252` cover ciphertext, tag, IV, and AAD modification.
- Decryption failure disclosure: `AesGcmEncryptionService.java:167-194` returns the same `Decryption failed` message for unknown keys and GCM verification failures and performs dummy GCM work for unknown key IDs.
- Identifier syntax validation: `CryptoUtils.java:27-33,99-118` constrains key and source identifiers to short allow-listed character sets, preventing their direct use as traversal or command-injection strings.
- Sensitive output handling: `EncryptedPayload.java:242-248`, `InMemoryKeyProvider.java:180-184`, and `KeyStoreKeyProvider.java:179-183` omit key bytes, plaintext, IV contents, and ciphertext contents from `toString()` output.
- Private file creation: `FileSecurityUtil.java:105-128` atomically creates owner-only files on POSIX and fails closed if non-POSIX permission restriction fails; SEC-04 concerns validation/opening of an existing path, not creation.
- Runtime dependency surface: `pom.xml:21-28` has no third-party runtime dependency; JUnit is test-scoped, reducing production supply-chain exposure.
- Native deserialization: No Java native object deserialization, XML entity processing, reflection-based polymorphic binding, command execution, SQL construction, network request, or dynamic code loading was found in scope.
