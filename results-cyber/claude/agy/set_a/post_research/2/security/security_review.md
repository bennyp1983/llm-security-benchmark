# Security Review: Secure Symmetric Encryption & Key Management Component (`com.security.crypto`)

## 1. Executive Summary

The component under review is a self-contained Java 17 library that encrypts and decrypts sensitive application data with AES-256-GCM and manages the symmetric keys for both directions. It provides a service facade (`AesGcmEncryptionService`), a tamper-evident wire envelope (`EncryptedPayload`), two key providers (in-memory and PKCS12 keystore), a PBKDF2-HMAC-SHA512 key-derivation helper, a CSPRNG-backed key/IV/key-id generator, a dual-bucket decryption failure limiter, filesystem permission checks, and memory-wiping utilities. There are no runtime third-party dependencies and no network, SQL, deserialization, template or command-execution surface.

The core cryptography is sound: AES-256/GCM with a 128-bit tag, per-operation `Cipher` instances, a fresh `SecureRandom` 96-bit IV on every encryption that callers cannot influence, PBKDF2-HMAC-SHA512 with a 600,000-iteration default and a 210,000 hard floor, 128-bit random salts, strictly bounded and exactly-length-checked envelope parsing, and no hardcoded production secrets. No weak algorithm, ECB mode, predictable IV, or static key was found.

The weaknesses are concentrated in the defensive machinery that surrounds the cipher, and in several cases a control the README claims to provide does not actually hold:

- **The anti-lockout design is inverted (SEC-01, High).** `sourceId` is an unvalidated caller-supplied string, so an attacker rotates it freely to stay under the 20-failure source bucket while the per-key bucket accumulates to 50 and denies decryption of that key to every legitimate user - exactly the attacker-induced lockout the README says is prevented.
- **Rate limiting is not atomic (SEC-02, Medium)** despite the README's "check-and-act ... atomic" claim: `checkAllowed` reads a counter and acts on it with no lock, so concurrent callers overshoot both thresholds.
- **The "hard bound" on limiter memory is not enforced (SEC-03, Medium):** pruning only removes *expired* windows, so a burst of distinct identifiers grows both maps without limit and adds an O(n) sweep to every failure.
- **Key and password zeroization is largely a no-op (SEC-05, SEC-06, Medium):** `wipe(SecretKey)` swallows the `UnsupportedOperationException`/`DestroyFailedException` that `SecretKeySpec` always throws, and the keystore password is cloned into a `KeyStore.PasswordProtection` that is never destroyed.
- **The keystore file is validated and then re-opened by path (SEC-04, Medium),** a TOCTOU/symlink window between the `NOFOLLOW_LINKS` check and the link-following open.

Lower-severity findings cover the unauthenticated envelope header, differentiated (and un-throttled) parser error messages that contradict the uniform-failure design, incomplete filesystem checks, the shared default source bucket, and the absence of a per-key encryption budget for random GCM nonces. Eleven findings in total: one High, five Medium, five Low.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/crypto/SymmetricEncryptionService.java` | Public encrypt/decrypt interface. | Defines the trust boundary: untrusted plaintext, AAD, serialized payloads, Base64 strings and `sourceId` all enter here. No logic. |
| `src/main/java/com/security/crypto/AesGcmEncryptionService.java` | AES-256-GCM AEAD implementation. | Cipher selection and tag length, internal IV generation, server-side key lookup, rate-limiter invocation, constant-work dummy decryption, generic error mapping, logging, buffer bounds. |
| `src/main/java/com/security/crypto/EncryptedPayload.java` | Binary / Base64URL envelope. | Untrusted wire-format parsing: magic, version, key-id length, IV length, exact ciphertext length, max size pre-checks, defensive copies, masked `toString()`. |
| `src/main/java/com/security/crypto/KeyProvider.java` | Key lifecycle contract. | Mandates fail-closed `Optional` lookup and `AutoCloseable` destruction semantics. |
| `src/main/java/com/security/crypto/InMemoryKeyProvider.java` | Thread-safe key registry. | Key registration/rotation/revocation, AES-256 algorithm and length enforcement, closed-state gating, attempted key destruction. |
| `src/main/java/com/security/crypto/KeyStoreKeyProvider.java` | PKCS12 keystore loader. | Keystore path validation, password handling and wiping, alias enumeration and filtering, key destruction on close. |
| `src/main/java/com/security/crypto/KeyDerivation.java` | PBKDF2 key derivation. | Algorithm/iteration/salt-length floors, passphrase and derived-buffer zeroization in `finally`. |
| `src/main/java/com/security/crypto/KeyGeneratorUtil.java` | Key, IV and key-id generation. | `SecureRandom` entropy source for AES-256 keys, 12-byte GCM nonces, and 128-bit random key identifiers. |
| `src/main/java/com/security/crypto/DecryptionRateLimiter.java` | Dual-bucket failure limiter. | Brute-force throttling per source and per key, fixed-window counters, map pruning - the component's only anti-automation and anti-lockout control. |
| `src/main/java/com/security/crypto/CryptoUtils.java` | Validation and memory utilities. | Key-id/source-id regexes, plaintext/AAD bounds, `MessageDigest.isEqual` constant-time compare, byte/char/key wiping, defensive copies. |
| `src/main/java/com/security/crypto/FileSecurityUtil.java` | Filesystem trust boundary. | Path normalization, existence/regular-file checks with `NOFOLLOW_LINKS`, world-writable parent rejection, owner check, 0600 permission enforcement, private file creation. |
| `src/main/java/com/security/crypto/CryptoException.java` | Caller-facing exception. | Intended to carry only sanitized messages; retains internal cause for server-side logging. |
| `src/test/java/com/security/crypto/SymmetricCryptoTest.java` | Unit tests (round-trip, tampering, bounds, rate limiting, concurrency). | Test-only passphrases; exercises tamper rejection and limiter behaviour. No production code path. |
| `src/test/java/com/security/crypto/FileSecurityTest.java` | Permission and keystore tests. | Creates a temporary PKCS12 keystore with a test-only password; asserts 0600 enforcement. No production code path. |
| `pom.xml` | Build definition. | Pins JUnit 5.11.4 (test scope), compiler plugin 3.13.0, surefire 3.5.2; no runtime dependencies. |
| `README.md`, `prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`, `target/**` | Documentation, generation inputs, and build output. | Reviewed for leaked secrets and for control claims to verify against the code; no secrets present. Compiled artifacts under `target/` were not executed. |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied its weakness-category table and validation criteria to every cryptographic call site - algorithm and mode (`AesGcmEncryptionService.java:42`), key size (`KeyGeneratorUtil.java:21`, `InMemoryKeyProvider.java:25`), KDF parameters (`KeyDerivation.java:27-47`), entropy source (`KeyGeneratorUtil.java:22`, `KeyDerivation.java:49`), hardcoded-secret scan across `src/main`, and key storage/rotation practice (`InMemoryKeyProvider.java:104-125`, `KeyStoreKeyProvider.java:66-118`). Produced SEC-05, SEC-06 and SEC-11; confirmed no weak algorithm, no ECB, no hardcoded production key.
- `implementing-aes-encryption-for-data-at-rest`: applied its AEAD, nonce-management and key-derivation criteria to `AesGcmEncryptionService.encrypt` (`:104-132`), the `EncryptedPayload` wire format (`:112-125`), and `KeyDerivation.deriveKey` (`:98-126`). Confirmed 12-byte CSPRNG nonce per operation, nonce stored beside ciphertext, 128-bit tag, PBKDF2 iteration floor; produced SEC-07 (metadata outside the authenticated data) and SEC-11 (no nonce-reuse budget per key).
- `exploiting-race-condition-vulnerabilities`: applied its TOCTOU / limit-overrun model to the limiter's check-then-act sequence (`DecryptionRateLimiter.java:83-99` against `:107-133`) and to the file-validate-then-open sequence (`FileSecurityUtil.java:43-96` against `KeyStoreKeyProvider.java:47-49`). Produced SEC-02 and SEC-04.
- `performing-api-rate-limiting-bypass`: applied its identifier-rotation / spoofed-client-identity bypass techniques to the caller-supplied `sourceId` dimension (`AesGcmEncryptionService.java:155-163`, `CryptoUtils.java:113-118`). Produced SEC-01 and SEC-10.
- `testing-for-sensitive-data-exposure`: applied its insecure-storage and leakage checks to all `toString()` implementations, all `LOGGER` calls, all exception messages, and the file-permission enforcement path (`FileSecurityUtil.java:80-89`). Produced SEC-08 and SEC-09; confirmed no key, ciphertext or passphrase reaches logs or caller-visible messages.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill matched these behaviours: untrusted binary wire-format parsing and integer/bounds handling in `EncryptedPayload.fromBytes` and `fromBase64Url` (CWE-130, CWE-190, CWE-789); fail-closed state gating in the key providers (CWE-636); error-message differentiation and uncontrolled resource consumption in the parser (CWE-209, CWE-400); dependency pinning in `pom.xml` (CWE-1104). There is no SQL, XSS, SSRF, deserialization, authentication/session, access-control, cookie, or OS-command surface in this component, so those OWASP categories are not applicable.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Per-key failure bucket keyed on unverified caller-supplied `sourceId` lets an attacker lock legitimate users out of a key | High | CWE-645 | `src/main/java/com/security/crypto/DecryptionRateLimiter.java:93-98` |
| SEC-02 | Rate-limit check and failure record are not atomic, so concurrent callers overrun both thresholds | Medium | CWE-367 | `src/main/java/com/security/crypto/DecryptionRateLimiter.java:83-99` |
| SEC-03 | Limiter maps are not actually bounded; pruning only removes expired windows and adds an O(n) sweep per failure | Medium | CWE-770 | `src/main/java/com/security/crypto/DecryptionRateLimiter.java:153-157` |
| SEC-04 | Keystore file is validated with `NOFOLLOW_LINKS` then re-opened by path (TOCTOU / symlink race) | Medium | CWE-367 | `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:47-49` |
| SEC-05 | Key zeroization is a silent no-op for `SecretKeySpec`; keys survive `close()` in the heap | Medium | CWE-316 | `src/main/java/com/security/crypto/CryptoUtils.java:66-76` |
| SEC-06 | Keystore password retained in an undestroyed `PasswordProtection` clone and not wiped when path validation fails | Medium | CWE-316 | `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:76` |
| SEC-07 | Envelope header (version, key id, lengths) is outside the AEAD authenticated data | Low | CWE-345 | `src/main/java/com/security/crypto/EncryptedPayload.java:112-125` |
| SEC-08 | Differentiated parser error messages, raised before any rate limiting, contradict the uniform-failure design | Low | CWE-209 | `src/main/java/com/security/crypto/EncryptedPayload.java:158-200` |
| SEC-09 | Private-file validation checks only the immediate parent, accepts any root-owned file, and silently skips all checks off POSIX | Low | CWE-732 | `src/main/java/com/security/crypto/FileSecurityUtil.java:62-78` |
| SEC-10 | Shared constant default source bucket means one caller's failures throttle all internal callers | Low | CWE-770 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:48` |
| SEC-11 | No per-key encryption budget for random 96-bit GCM nonces | Low | CWE-323 | `src/main/java/com/security/crypto/AesGcmEncryptionService.java:114` |

## 5. Detailed Findings

### SEC-01: Per-key failure bucket keyed on unverified caller-supplied `sourceId` lets an attacker lock legitimate users out of a key
- **Severity:** High
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/security/crypto/DecryptionRateLimiter.java:93-98` (with `AesGcmEncryptionService.java:155-163` and `CryptoUtils.java:113-118`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/DecryptionRateLimiter.java:83-99
    public void checkAllowed(String sourceId, String resourceId) {
        long now = System.currentTimeMillis();

        if (sourceId != null) {
            WindowCounter sourceCounter = sourceCounters.get(sourceId);
            if (sourceCounter != null && sourceCounter.isExceeded(now, windowDurationMs, maxSourceFailures)) {
                throw new CryptoException("Decryption rate limit exceeded");
            }
        }

        if (resourceId != null) {
            WindowCounter resourceCounter = resourceCounters.get(resourceId);
            if (resourceCounter != null && resourceCounter.isExceeded(now, windowDurationMs, maxResourceFailures)) {
                throw new CryptoException("Decryption rate limit exceeded");
            }
        }
    }
```
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:155-163
    public byte[] decrypt(EncryptedPayload payload, byte[] aad, String sourceId) {
        Objects.requireNonNull(payload, "Payload must not be null");
        String validatedSourceId = CryptoUtils.validateSourceId(sourceId);
        CryptoUtils.validateAad(aad, maxAadBytes);

        String keyId = payload.getKeyId();

        // Rule 3 & 7: Check failure limits atomically per source and per key/resource
        rateLimiter.checkAllowed(validatedSourceId, keyId);
```

**Why it is a problem:** `sourceId` is an opaque string supplied by the caller and only syntactically validated (`CryptoUtils.java:113-118` checks a 1-128 character regex); it is never corroborated against server-side state, and the component gives the caller no way to bind it to an authenticated identity. The per-resource bucket, however, is keyed on the key id lifted straight out of the attacker-supplied envelope (`AesGcmEncryptionService.java:160`), and exceeding it hard-fails *every* decryption for that key regardless of who asks. An attacker therefore pays nothing for the source dimension and gets full effect on the resource dimension: send a new `sourceId` with each request so no source counter ever reaches 20, and 50 forged ciphertexts carrying the victim's key id within one 60-second window block all decryption under that key - for every tenant, service and user that shares it. Because `maxResourceFailures` (50) is only 2.5x `maxSourceFailures` (20), the resource threshold is reached with trivial volume. This is the precise attack the README claims to defeat ("Attackers are blocked at the source level before victim accounts are locked", README.md:66,112); in practice the control is inverted into a denial-of-service amplifier against the data the component exists to protect, and since one key typically encrypts a whole column or tenant, the blast radius is the entire dataset.

**Fix:** Do not let a counter driven by attacker-controlled input produce a hard deny on a shared resource. Require the embedding application to pass a `sourceId` it has itself authenticated (document it as a trust requirement, and reject the ambient default - see SEC-10), make the resource dimension degrade rather than deny by counting per source-and-resource pair so a single source can only exhaust its own share, and keep a hard deny only for the source bucket.

```java
    /**
     * @param sourceId   Caller identity that the embedding application has ALREADY authenticated.
     *                   Never pass a value taken unverified from a client request.
     */
    public void checkAllowed(String sourceId, String resourceId) {
        if (sourceId == null) {
            // Fail closed: an unattributable request cannot be rate limited.
            throw new CryptoException("Decryption rate limit exceeded");
        }
        long now = System.currentTimeMillis();

        WindowCounter sourceCounter = sourceCounters.get(sourceId);
        if (sourceCounter != null && sourceCounter.isExceeded(now, windowDurationMs, maxSourceFailures)) {
            throw new CryptoException("Decryption rate limit exceeded");
        }

        if (resourceId != null) {
            // Count per (source, resource) pair so one source cannot exhaust a shared key's budget.
            WindowCounter pairCounter = resourceCounters.get(resourceId + " " + sourceId);
            if (pairCounter != null && pairCounter.isExceeded(now, windowDurationMs, maxResourceFailures)) {
                throw new CryptoException("Decryption rate limit exceeded");
            }
        }
    }
```

### SEC-02: Rate-limit check and failure record are not atomic, so concurrent callers overrun both thresholds
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/security/crypto/DecryptionRateLimiter.java:83-99` and `:107-133`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/DecryptionRateLimiter.java:86-91
        if (sourceId != null) {
            WindowCounter sourceCounter = sourceCounters.get(sourceId);
            if (sourceCounter != null && sourceCounter.isExceeded(now, windowDurationMs, maxSourceFailures)) {
                throw new CryptoException("Decryption rate limit exceeded");
            }
        }
```
```java
// src/main/java/com/security/crypto/DecryptionRateLimiter.java:110-120
        if (sourceId != null) {
            pruneIfNecessary(sourceCounters, now);
            sourceCounters.compute(sourceId, (k, counter) -> {
                if (counter == null || (now - counter.windowStartMs) > windowDurationMs) {
                    return new WindowCounter(now, 1);
                } else {
                    counter.count.incrementAndGet();
                    return counter;
                }
            });
        }
```

**Why it is a problem:** The individual map operations are thread-safe, but the security decision is not. `checkAllowed` performs a read (`get` plus `isExceeded`) and the caller then acts on that stale verdict; the matching increment happens later, in a separate `recordFailure` call, after the AES-GCM `doFinal` has run (`AesGcmEncryptionService.java:188-191`). Nothing serializes the interval between them. N threads that all enter `checkAllowed` while the counter sits at `maxSourceFailures - 1` all observe "allowed" and all proceed, so the effective number of permitted failures per window is bounded by the attacker's concurrency, not by `maxSourceFailures`. The window is wide - it spans a full GCM decryption of up to 16 MB of attacker-supplied ciphertext - which makes it comfortably exploitable with ordinary parallel requests, no precise timing needed. This directly contradicts Rule 7 and the README's claim that "check-and-act window updates are atomic" (README.md:165), and it weakens every other limit in the component, including the brute-force ceiling the dual-bucket design rests on.

**Fix:** Make reserve-and-check one atomic operation on a single map entry and drop the separate read-only check. Reserve an attempt slot inside `compute`, which holds the per-bin lock, and release it on success so only failures consume budget.

```java
    /**
     * Atomically reserves an attempt slot. Throws if the window budget is already spent.
     * Call releaseAttempt(...) on success so only failures consume budget.
     */
    public void checkAllowed(String sourceId, String resourceId) {
        long now = System.currentTimeMillis();
        reserve(sourceCounters, sourceId, now, maxSourceFailures);
        reserve(resourceCounters, resourceId, now, maxResourceFailures);
    }

    private void reserve(ConcurrentHashMap<String, WindowCounter> map,
                         String id, long now, int maxFailures) {
        if (id == null) {
            return;
        }
        pruneIfNecessary(map, now);
        // compute() holds the per-bin lock, so test and increment cannot interleave.
        boolean[] rejected = new boolean[1];
        map.compute(id, (k, counter) -> {
            if (counter == null || (now - counter.windowStartMs) > windowDurationMs) {
                return new WindowCounter(now, 1);
            }
            if (counter.count.get() >= maxFailures) {
                rejected[0] = true;
                return counter; // Budget exhausted; do not grow the counter further.
            }
            counter.count.incrementAndGet();
            return counter;
        });
        if (rejected[0]) {
            throw new CryptoException("Decryption rate limit exceeded");
        }
    }
```

### SEC-03: Limiter maps are not actually bounded; pruning only removes expired windows and adds an O(n) sweep per failure
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/security/crypto/DecryptionRateLimiter.java:153-157`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/DecryptionRateLimiter.java:153-157
    private void pruneIfNecessary(ConcurrentHashMap<String, WindowCounter> map, long now) {
        if (map.size() >= MAX_MAP_ENTRIES) {
            map.entrySet().removeIf(entry -> (now - entry.getValue().windowStartMs) > windowDurationMs);
        }
    }
```

**Why it is a problem:** `MAX_MAP_ENTRIES` is documented as a "hard bound" on memory (`:41-43`, README.md:136), but nothing enforces it. Once the map reaches 10,000 entries the only action taken is to delete entries whose window has *expired*; if the attacker keeps arriving faster than the 60-second window retires entries - which is exactly what the SEC-01 `sourceId`-rotation attack does - `removeIf` deletes nothing and `compute` inserts anyway, so `sourceCounters` grows without limit. Each entry is a 128-character key plus a `WindowCounter`, so a sustained stream of distinct identifiers is a straightforward heap-exhaustion path. There is a second cost: once `size() >= 10_000`, *every subsequent* `recordFailure` triggers a full O(n) traversal of the map before the increment, so the attacker converts each failed decryption into a scan of a growing structure - CPU amplification on top of the memory growth. Both effects are driven purely by unauthenticated input.

**Fix:** Enforce the cap for real. Prune expired entries first, and if the map is still at capacity, refuse to insert a new tracking entry and fail closed for the untracked identifier rather than growing. Time-based eviction (a bounded LRU, or a cache with `expireAfterWrite`) is the better long-term shape; the minimal correction is below.

```java
    /**
     * Enforces the hard entry bound. Returns false if no slot is available for a new key,
     * in which case the caller must fail closed instead of inserting.
     */
    private boolean reserveSlot(ConcurrentHashMap<String, WindowCounter> map, String id, long now) {
        if (map.containsKey(id)) {
            return true; // Existing entry: no growth.
        }
        if (map.size() >= MAX_MAP_ENTRIES) {
            map.entrySet().removeIf(e -> (now - e.getValue().windowStartMs) > windowDurationMs);
        }
        return map.size() < MAX_MAP_ENTRIES;
    }

    public void recordFailure(String sourceId, String resourceId) {
        long now = System.currentTimeMillis();
        if (sourceId != null && reserveSlot(sourceCounters, sourceId, now)) {
            bump(sourceCounters, sourceId, now);
        }
        if (resourceId != null && reserveSlot(resourceCounters, resourceId, now)) {
            bump(resourceCounters, resourceId, now);
        }
    }
```

### SEC-04: Keystore file is validated with `NOFOLLOW_LINKS` then re-opened by path (TOCTOU / symlink race)
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition (with CWE-59: Improper Link Resolution Before File Access)
- **Location:** `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:47-49`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-55
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

**Why it is a problem:** `validatePrivateFile` carefully inspects the path with `LinkOption.NOFOLLOW_LINKS` - existence, regular-file status, owner, and 0600 permissions (`FileSecurityUtil.java:51-89`) - and then returns a `Path`. `Files.newInputStream` re-resolves that path from scratch and, unlike the checks, **follows symlinks**. Every property that was verified refers to a filesystem state that no longer necessarily holds at open time. An attacker with write access to the containing directory (the code only rejects a world-*writable* immediate parent, see SEC-09) can replace the validated regular file with a symlink between the two operations, causing the process to open and parse an attacker-chosen file as a PKCS12 keystore - attacker-controlled key material fed into the service under the guise of a validated path, or the keystore password offered up against a file the attacker can observe. The same validated-path-then-reopen shape applies to any future writer built on `FileSecurityUtil`.

**Fix:** Open the file once and validate the handle, not the name. Open with `LinkOption.NOFOLLOW_LINKS` so a substituted symlink fails the open outright, then read the security attributes from the already-open channel so check and use refer to the same inode.

```java
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        Objects.requireNonNull(keyStorePath, "KeyStore path must not be null");
        Path normalized = keyStorePath.toAbsolutePath().normalize();
        try (FileChannel channel = FileChannel.open(normalized,
                        EnumSet.of(StandardOpenOption.READ), LinkOption.NOFOLLOW_LINKS);
             InputStream in = Channels.newInputStream(channel)) {
            // Validate the attributes of the inode we actually hold open, not of the path.
            FileSecurityUtil.validateOpenPrivateFile(channel, normalized);
            return fromInputStream(in, password, activeKeyAlias);
        } catch (CryptoException ce) {
            CryptoUtils.wipe(password);
            throw ce;
        } catch (IOException e) {
            CryptoUtils.wipe(password); // Do not leave the secret in the heap on the error path.
            throw new CryptoException("Failed to load KeyStore from file", e);
        }
    }
```

### SEC-05: Key zeroization is a silent no-op for `SecretKeySpec`; keys survive `close()` in the heap
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/security/crypto/CryptoUtils.java:66-76` (consumed at `InMemoryKeyProvider.java:123` and `:174`, `KeyStoreKeyProvider.java:174`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/CryptoUtils.java:66-76
    public static void wipe(SecretKey key) {
        if (key != null) {
            try {
                if (!key.isDestroyed()) {
                    key.destroy();
                }
            } catch (DestroyFailedException | UnsupportedOperationException ignored) {
                // SecretKey implementations (e.g. SecretKeySpec) may not support destruction
            }
        }
    }
```

**Why it is a problem:** `javax.crypto.spec.SecretKeySpec` does not override `Destroyable.destroy()` in Java 17, so the default implementation throws `DestroyFailedException` every time - and that is precisely the key type this component produces and stores: `KeyDerivation.deriveKey` returns `new SecretKeySpec(encodedKey, "AES")` (`KeyDerivation.java:116`), and derived keys are what callers register with `InMemoryKeyProvider`. The exception is swallowed, so `revokeKey` (`InMemoryKeyProvider.java:117-125`) and `close()` (`:169-178`) report success while the raw 256-bit key bytes remain intact in the heap, reachable until garbage collection and recoverable from any core dump, hibernation image, or `jmap` capture for the lifetime of the process. The README states that "`KeyProvider.close()` clears and destroys all keys upon decommissioning" (README.md:142) and the threat model lists heap inspection as countered (README.md:69); neither holds for the component's own key type. The silent catch is what makes this a security issue rather than a platform limitation: no caller, log line, or test can tell that the control did nothing.

**Fix:** Keep key material in a `byte[]` the component owns and can actually overwrite, constructing a short-lived `SecretKeySpec` per cipher operation, and make a zeroization failure observable instead of silent.

```java
    /**
     * Attempts to destroy a SecretKey. Logs when the platform key type cannot be
     * zeroized, so a silent no-op is never mistaken for a successful wipe.
     */
    public static void wipe(SecretKey key) {
        if (key == null) {
            return;
        }
        try {
            if (!key.isDestroyed()) {
                key.destroy();
            }
        } catch (DestroyFailedException | UnsupportedOperationException e) {
            // SecretKeySpec cannot be destroyed: the caller must hold raw bytes it can wipe itself.
            LOGGER.log(Level.WARNING,
                    "Key material of type {0} is not destroyable; raw bytes remain in the heap",
                    key.getClass().getName());
        }
    }

    /** Preferred path: the component owns the bytes and can genuinely overwrite them. */
    public static SecretKey keyFromOwnedBytes(byte[] owned) {
        return new DestroyableAesKey(owned); // destroy() -> Arrays.fill(owned, (byte) 0)
    }
```

### SEC-06: Keystore password retained in an undestroyed `PasswordProtection` clone and not wiped when path validation fails
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:76` (and the `fromFile` error path, `:46-55`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/KeyStoreKeyProvider.java:76-81
            KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(password);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    KeyStore.Entry entry = keyStore.getEntry(alias, protParam);
```

**Why it is a problem:** The `KeyStore.PasswordProtection` constructor stores `password.clone()`. The `finally` block wipes only the caller's array (`:116`); the clone inside `protParam` is never destroyed, because `protParam.destroy()` is never called. The keystore passphrase - the single secret guarding all key material in the store - therefore remains in cleartext on the heap after loading completes, defeating the stated control that passwords are "cleared from memory immediately after loading" (`:22-23`, README.md:141). The same secret also survives the `fromFile` failure paths: if `FileSecurityUtil.validatePrivateFile` throws at `:47`, or `Files.newInputStream` throws at `:48`, control never reaches the `finally` in `fromInputStream`, so the caller's array is not wiped either - and these are attacker-reachable paths (a missing file or tightened permissions are enough to trigger them). Separately, `:104` interpolates the caller-supplied alias into an exception message, which contradicts the generic-message policy.

**Fix:** Scope the `PasswordProtection` so it is always destroyed, and wipe the password on every exit path from `fromFile`, including the pre-open failures (shown in SEC-04's fix).

```java
            KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(password);
            try {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (keyStore.isKeyEntry(alias)) {
                        KeyStore.Entry entry = keyStore.getEntry(alias, protParam);
                        // ... unchanged entry filtering ...
                    }
                }
            } finally {
                try {
                    // Destroys PasswordProtection's internal clone of the passphrase.
                    protParam.destroy();
                } catch (DestroyFailedException ignored) {
                    // Nothing further can be done; the wipe below still clears the caller's copy.
                }
            }

            CryptoUtils.validateKeyId(activeKeyAlias);
            if (!provider.keys.containsKey(activeKeyAlias)) {
                provider.close();
                // Generic message: do not echo the caller-supplied alias.
                throw new CryptoException("Failed to initialize KeyStore: active key alias not found");
            }
```

### SEC-07: Envelope header (version, key id, lengths) is outside the AEAD authenticated data
- **Severity:** Low
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `src/main/java/com/security/crypto/EncryptedPayload.java:112-125` (with `AesGcmEncryptionService.java:122-127`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/EncryptedPayload.java:112-125
    public byte[] toBytes() {
        byte[] keyIdBytes = keyId.getBytes(StandardCharsets.UTF_8);
        int totalLength = 4 + 1 + 1 + keyIdBytes.length + 1 + iv.length + 4 + ciphertextWithTag.length;
        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.put(MAGIC);
        buffer.put(version);
        buffer.put((byte) keyIdBytes.length);
        buffer.put(keyIdBytes);
        buffer.put((byte) iv.length);
        buffer.put(iv);
        buffer.putInt(ciphertextWithTag.length);
        buffer.put(ciphertextWithTag);
        return buffer.array();
    }
```

**Why it is a problem:** The GCM tag covers the ciphertext, the IV and any caller-supplied AAD, but not the envelope metadata. Only the ciphertext bytes and the IV are cryptographically bound; the magic, version byte, key identifier and the two length fields are unauthenticated, attacker-malleable plaintext. Today the practical consequences are contained - a swapped key id makes the tag check fail, and `CURRENT_VERSION` is the only accepted version - but the design leaves two live edges. First, the key identifier is the input to the resource rate-limit bucket (`AesGcmEncryptionService.java:160`), so an attacker can retarget a captured ciphertext at any key id at will, which is the enabling primitive for SEC-01 and for key-existence probing. Second, the moment a version 2 is introduced, an unauthenticated version byte becomes a downgrade lever: the parser will route a tampered envelope to whichever weaker rules version 1 permits, and nothing in the tag will object. Binding the header costs one `updateAAD` call and closes both.

**Fix:** Build the header once, feed it to `updateAAD` on both encryption and decryption ahead of any caller AAD, so header tampering fails the tag check.

```java
    /** Serializes the header fields that must be bound into the AEAD computation. */
    public byte[] headerBytes() {
        byte[] keyIdBytes = keyId.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + 1 + keyIdBytes.length + 1 + iv.length + 4);
        buffer.put(MAGIC);
        buffer.put(version);
        buffer.put((byte) keyIdBytes.length);
        buffer.put(keyIdBytes);
        buffer.put((byte) iv.length);
        buffer.put(iv);
        buffer.putInt(ciphertextWithTag.length);
        return buffer.array();
    }
```
```java
            // AesGcmEncryptionService: bind the header on BOTH encrypt and decrypt.
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, spec);
            cipher.updateAAD(payload.headerBytes()); // Any header tampering now fails the tag check.
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(payload.getCiphertextWithTag());
```

### SEC-08: Differentiated parser error messages, raised before any rate limiting, contradict the uniform-failure design
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/com/security/crypto/EncryptedPayload.java:158-200`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/EncryptedPayload.java:193-200
            int cipherLen = buffer.getInt();
            if (cipherLen < GCM_TAG_LENGTH || cipherLen > maxCiphertextSize) {
                throw new CryptoException("Invalid cryptographic payload: invalid ciphertext length");
            }
            if (buffer.remaining() != cipherLen) {
                // Must match exactly: reject extra trailing bytes or truncation
                throw new CryptoException("Invalid cryptographic payload: payload length mismatch");
            }
```

**Why it is a problem:** `fromBytes` emits eight distinguishable caller-visible messages - "unrecognized format header", "unsupported version", "invalid key identifier length", "invalid key identifier format", "truncated payload header", "invalid IV length", "invalid ciphertext length", "payload length mismatch" - each pinpointing which structural check failed. Rule 6 and `CryptoException`'s own contract (`CryptoException.java:9-13`) state that callers receive a uniform message "regardless of whether the root cause was a malformed payload, invalid tag, unknown key, or tampering"; if the embedding application propagates these to a remote client, as the generic-message design anticipates, the attacker gets a free field-by-field oracle for constructing valid envelopes. Compounding it, every one of these rejections happens in `AesGcmEncryptionService.decrypt(byte[], ...)` at `:201` - *before* `rateLimiter.checkAllowed` is ever reached - so structural probing is entirely unthrottled and unrecorded, and nothing in the component counts it. The leak is structural metadata rather than key material, hence Low, but it undercuts two controls the component advertises.

**Fix:** Return one message to the caller and route the discriminating detail to the log, and run the rate-limit check before parsing so malformed submissions are throttled and counted like any other failure.

```java
    private static CryptoException reject(String internalDetail) {
        // Detail goes to the log only; the caller always sees the same string.
        LOGGER.log(Level.FINE, "Payload rejected: {0}", internalDetail);
        return new CryptoException("Invalid cryptographic payload");
    }

    // ... at every rejection site:
            if (buffer.remaining() != cipherLen) {
                throw reject("payload length mismatch");
            }
```
```java
    // AesGcmEncryptionService: throttle before parsing so structural probing is counted.
    public byte[] decrypt(byte[] serializedPayload, byte[] aad, String sourceId) {
        Objects.requireNonNull(serializedPayload, "Serialized payload must not be null");
        String validatedSourceId = CryptoUtils.validateSourceId(sourceId);
        rateLimiter.checkAllowed(validatedSourceId, null);
        try {
            EncryptedPayload payload = EncryptedPayload.fromBytes(serializedPayload, maxCiphertextBytes);
            return decrypt(payload, aad, validatedSourceId);
        } catch (CryptoException e) {
            rateLimiter.recordFailure(validatedSourceId, null);
            throw e;
        }
    }
```

### SEC-09: Private-file validation checks only the immediate parent, accepts any root-owned file, and silently skips all checks off POSIX
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/security/crypto/FileSecurityUtil.java:62-78`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/FileSecurityUtil.java:62-78
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
```

**Why it is a problem:** Three gaps in a control that is the component's only defence for key material at rest. (1) Only the immediate parent is tested for world-writability; any higher ancestor may be world-writable, and that is sufficient for an attacker to rename or replace an intermediate directory and substitute the whole subtree - the check gives the appearance of path safety without establishing it, and it is the same weak perimeter that widens SEC-04's race window. (2) `!"root".equals(owner.getName())` unconditionally accepts root-owned files. For an unprivileged service this is a blanket exemption for files it does not own, granted on the basis of the *file's* owner string rather than any relationship to the running identity. (3) `currentUser` comes from the `user.name` system property, which anyone able to pass `-Duser.name=` on the JVM command line controls, so the owner comparison can be satisfied by configuration rather than by fact. On top of that, when `IS_POSIX` is false the entire block - permissions, owner, directory safety - is skipped silently and the path is returned as validated (`:93-95`), a fail-open default on Windows that contradicts Rule 6.

**Fix:** Walk every ancestor for world-writability (allowing the sticky bit, which makes `/tmp`-style directories safe against cross-user renames), compare against the real process owner rather than `user.name`, drop the blanket root exemption, and fail closed when POSIX attributes are unavailable.

```java
        if (!IS_POSIX) {
            // Fail closed: we cannot establish that the key file is private.
            throw new CryptoException("Key file security attributes cannot be verified on this filesystem");
        }
        try {
            // Every ancestor must be safe, not just the immediate parent.
            for (Path dir = normalized.getParent(); dir != null; dir = dir.getParent()) {
                Set<PosixFilePermission> dirPerms = Files.getPosixFilePermissions(dir);
                if (dirPerms.contains(PosixFilePermission.OTHERS_WRITE) && !isStickyBitSet(dir)) {
                    throw new CryptoException("Key file path contains a world-writable directory");
                }
            }

            // Compare against the real process owner; user.name is attacker-settable via -D.
            UserPrincipal owner = Files.getOwner(normalized, LinkOption.NOFOLLOW_LINKS);
            UserPrincipal self = normalized.getFileSystem()
                    .getUserPrincipalLookupService()
                    .lookupPrincipalByName(ProcessHandle.current().info().user().orElseThrow());
            if (!self.equals(owner)) {
                throw new CryptoException("Key file is not owned by the current application user");
            }
```

### SEC-10: Shared constant default source bucket means one caller's failures throttle all internal callers
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:48` (used at `:146` and `:151`)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:48
    public static final String DEFAULT_SOURCE_ID = "internal_client";
```
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:144-152
    @Override
    public byte[] decrypt(EncryptedPayload payload) {
        return decrypt(payload, null, DEFAULT_SOURCE_ID);
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload, byte[] aad) {
        return decrypt(payload, aad, DEFAULT_SOURCE_ID);
    }
```

**Why it is a problem:** The two convenience overloads silently attribute every call to one constant identifier, so all traffic that uses them shares a single 20-failure-per-minute bucket. Any path that reaches these overloads with attacker-influenced data - a decrypt driven by a user-supplied record, a retry loop, a batch job over a partly corrupted table - needs only 20 failures in a minute to make `checkAllowed` throw for *every other* caller of the default overloads, including entirely unrelated healthy workloads. The README's usage examples (README.md:257-258) call exactly these overloads, so the ambient default is the expected path rather than an edge case. This is a permissive default substituted for a required security input, which Rule 1 and Rule 6 both prohibit; the fix is cheap because the explicit three-argument overload already exists.

**Fix:** Do not invent an identity. Require the caller to attribute the request, and keep an unattributed path only for genuinely internal, non-attacker-reachable use by naming it accordingly and keeping it out of the shared bucket.

```java
    @Override
    public byte[] decrypt(EncryptedPayload payload) {
        // No ambient identity: callers handling attacker-reachable data must attribute the request.
        throw new CryptoException("Invalid cryptographic request: source identifier is required");
    }

    /**
     * Trusted-path decryption for callers that are provably not attacker-reachable
     * (e.g. startup self-tests). Attribution is explicit and per-component, so one
     * caller's failures never throttle another's.
     */
    public byte[] decryptTrustedInternal(EncryptedPayload payload, byte[] aad, String callerComponentName) {
        return decrypt(payload, aad, CryptoUtils.validateSourceId(callerComponentName));
    }
```

### SEC-11: No per-key encryption budget for random 96-bit GCM nonces
- **Severity:** Low
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:114`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:113-114
            // Rule 4: Cryptographically secure fresh IV generated internally; caller cannot specify IV
            byte[] iv = KeyGeneratorUtil.generateGcmIv();
```

**Why it is a problem:** Random 96-bit nonces are the right construction, but they are only safe within a bounded number of encryptions per key. By the birthday bound, collision probability reaches roughly 2^-32 at 2^32 messages under one key, and NIST SP 800-38D consequently caps a single key with random nonces at 2^32 invocations. Nothing here counts invocations: `InMemoryKeyProvider` keeps an active key until a caller happens to call `rotateKey` (`InMemoryKeyProvider.java:104-110`), and `KeyStoreKeyProvider` never rotates at all, so a long-lived high-throughput deployment can quietly exceed the limit. A GCM nonce collision under the same key is catastrophic - it leaks the XOR of two plaintexts and compromises the GHASH authentication subkey, enabling forgery - which is exactly the first attack row of the README's own threat model (README.md:61). The component supplies the rotation mechanism but no trigger, leaving a cryptographic limit to operator discipline.

**Fix:** Count encryptions per key inside the service and refuse to encrypt past a conservative threshold, so exceeding the nonce budget fails closed and forces rotation instead of silently degrading.

```java
    /** NIST SP 800-38D caps one key with random nonces at 2^32 invocations; stop well below it. */
    private static final long MAX_ENCRYPTIONS_PER_KEY = 1L << 31;

    private final ConcurrentHashMap<String, AtomicLong> encryptionCounts = new ConcurrentHashMap<>();

    private void reserveNonceBudget(String keyId) {
        long used = encryptionCounts.computeIfAbsent(keyId, k -> new AtomicLong())
                                    .incrementAndGet();
        if (used > MAX_ENCRYPTIONS_PER_KEY) {
            LOGGER.log(Level.SEVERE, "Nonce budget exhausted for active key; rotation required");
            throw new CryptoException("Encryption failed");
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **Cipher and mode:** `AES/GCM/NoPadding` with a 128-bit tag is the only transformation in the codebase (`AesGcmEncryptionService.java:42-43`). No ECB/CBC, no unauthenticated mode, no fallback transformation, and no caller-supplied algorithm string anywhere.
- **Key size:** AES-256 enforced at generation (`KeyGeneratorUtil.java:21`), at registration and rotation (`InMemoryKeyProvider.java:54-69`, 32-byte check), at keystore load (`KeyStoreKeyProvider.java:88`), and at derivation (`KeyDerivation.java:47`). Non-AES or wrong-length keys are rejected rather than coerced.
- **IV generation and caller control:** a fresh 12-byte `SecureRandom` nonce is produced on every `encrypt` (`AesGcmEncryptionService.java:114`, `KeyGeneratorUtil.java:60-64`). No public API accepts an IV; the `EncryptedPayload` constructor enforces exactly 12 bytes (`EncryptedPayload.java:79-81`). No nonce reuse within a key is possible by caller action (budget caveat in SEC-11).
- **Entropy source:** `java.security.SecureRandom` exclusively (`KeyGeneratorUtil.java:22`, `KeyDerivation.java:49`). No `java.util.Random`, no time-based or predictable seeding, no self-seeding; key identifiers carry 128 bits of randomness (`KeyGeneratorUtil.java:49-53`).
- **Key derivation parameters:** `PBKDF2WithHmacSHA512`, default 600,000 iterations with a hard 210,000 floor and a 128-bit minimum salt, all enforced before use (`KeyDerivation.java:27-47`, `:102-107`). Salts are CSPRNG-generated (`:61-68`). Derived key length is 256 bits. Meets current OWASP guidance for PBKDF2-HMAC-SHA512.
- **No hardcoded secrets:** grepped `src/main` for key, password and high-entropy literals - none found. Keys arrive only from `KeyGeneratorUtil`, `KeyDerivation`, or a PKCS12 keystore. The only credential literals are test-scoped passphrases in `FileSecurityTest.java:81` and `SymmetricCryptoTest.java:391,408`, used for the test's own temporary keystore; they grant no access to anything.
- **Secret masking in output:** all three `toString()` implementations emit metadata only - `EncryptedPayload.java:243-249` (`content=[PROTECTED]`), `InMemoryKeyProvider.java:181-185`, `KeyStoreKeyProvider.java:180-184` (counts and key ids, no key bytes). No `System.out` or `printStackTrace` in `src/main`.
- **Logging hygiene:** the four `LOGGER` calls (`AesGcmEncryptionService.java:129,172,192`) log a fixed string plus an exception, never plaintext, key material, ciphertext or AAD. Decryption failures log at `FINE`, keeping routine failures out of default-level logs.
- **Bounded allocation on untrusted input:** plaintext and AAD are length-checked before any cipher call (`CryptoUtils.java:127-145`); the wire parser enforces a minimum length, a maximum total size, a 1-64 byte key-id length, an exact 12-byte IV length, a ciphertext length between 16 bytes and the configured maximum, and `buffer.remaining() != cipherLen` to reject both truncation and trailing bytes before allocating (`EncryptedPayload.java:145-202`); the Base64 string length is pre-checked before decoding (`:222-226`); `BufferUnderflowException` is caught and converted (`:205-207`). No length field drives an allocation before validation.
- **AEAD tamper rejection:** ciphertext, tag, IV and AAD modifications all surface as `AEADBadTagException` from `doFinal` and are converted to a uniform `"Decryption failed"` (`AesGcmEncryptionService.java:188-195`). No partial plaintext is returned on tag failure, and there is no unauthenticated-decrypt path.
- **AAD context binding:** `encrypt`/`decrypt` accept AAD and pass it via `cipher.updateAAD` symmetrically (`:122-124`, `:184-186`), giving callers a working defence against ciphertext transposition between tenants or records (header-binding caveat in SEC-07).
- **Fail-closed key resolution:** key ids from untrusted payloads are regex-validated (`CryptoUtils.java:99-104`, which also rejects path-traversal and injection characters) and resolved only against server-side provider state; an empty `Optional` throws (`AesGcmEncryptionService.java:166-174`). Both providers return `Optional.empty()` for null or unknown ids and gate every accessor behind `ensureOpen()`, so a closed provider cannot serve keys (`InMemoryKeyProvider.java:48-52,127-167`; `KeyStoreKeyProvider.java:120-166`).
- **Timing-oracle defence for key existence:** an unknown key id triggers a dummy AES-GCM decryption with an internally generated key over the same payload before rejection (`AesGcmEncryptionService.java:217-230`), so the unknown-key and bad-tag paths perform comparable work and return the same message.
- **Constant-time comparison:** `CryptoUtils.constantTimeEquals` delegates to `MessageDigest.isEqual` (`CryptoUtils.java:85-90`), the correct platform primitive. No `Arrays.equals` or `String.equals` is used on secret material; the one `Arrays.equals` call compares the public magic header (`EncryptedPayload.java:158`).
- **Defensive copying:** IV and ciphertext are copied on both construction and accessor return (`EncryptedPayload.java:82,88,99-105`, `CryptoUtils.java:153-158`), so the immutable envelope cannot be mutated by a caller after validation.
- **Passphrase zeroization on the derivation path:** `KeyDerivation.deriveKey` clears the `PBEKeySpec`, the caller's `char[]`, and the intermediate encoded key in a `finally` block that runs on every path including failure (`KeyDerivation.java:119-125`). This is the one wipe path that does work as documented.
- **Per-operation cipher state:** a new `Cipher` is obtained inside each encrypt/decrypt call (`AesGcmEncryptionService.java:118,180,219`); no `Cipher`, `SecretKeyFactory` or `MessageDigest` instance is shared across threads, so the component's cipher usage is free of the usual JCA thread-safety defect. Provider state uses `ConcurrentHashMap`/`AtomicReference`/`AtomicBoolean`, and `close()` is idempotent via `compareAndSet` (`InMemoryKeyProvider.java:170`, `KeyStoreKeyProvider.java:170`).
- **Private file creation:** `createPrivateFile` applies `rw-------` atomically as a creation attribute on POSIX, and on other filesystems sets owner-only read/write and fails closed by deleting the file if any permission call fails (`FileSecurityUtil.java:105-130`).
- **Key rotation and revocation mechanics:** rotation registers and activates in one call while retaining historical keys for decryption (`InMemoryKeyProvider.java:104-110`); `setActiveKeyId` refuses an unregistered id (`:89-96`); `revokeKey` removes the key and clears the active pointer with `compareAndSet` so a revoked key cannot remain active (`:117-125`).
- **Error-type discipline at the caller boundary:** every failure path throws `CryptoException`; no `GeneralSecurityException`, `AEADBadTagException`, provider name, or stack trace is propagated to callers (`CryptoException.java:18-41`, `AesGcmEncryptionService.java:128-131,189-195`).
- **Integer-overflow behaviour in size pre-checks:** the `maxCiphertextSize + 1024` and `(maxCiphertextSize + 1024) * 4 / 3` expressions (`EncryptedPayload.java:148,223`) can overflow only for an operator-configured limit near `Integer.MAX_VALUE`, and the resulting negative bound rejects all payloads - fail-closed, not attacker-reachable, so no finding.
- **Dependencies and supply chain:** `pom.xml` declares no runtime dependencies; JUnit 5.11.4 is test-scoped and the compiler (3.13.0) and surefire (3.5.2) plugins are version-pinned. No remote code or resource loading, no classpath manipulation, and no dynamic class loading anywhere in `src/main`.
- **Not applicable to this component (confirmed absent, not merely unreviewed):** SQL/ORM query construction, HTML/template rendering, XML or object deserialization, HTTP clients or TLS configuration, OS command execution, cookie or session issuance, and user-facing authentication or authorization logic. No such call site exists in any reviewed file.
- **Build artifacts:** `target/classes`, `target/test-classes` and the surefire reports were treated as untrusted output and reviewed only by file listing. No `.class` file was executed, decompiled, loaded, or imported.
