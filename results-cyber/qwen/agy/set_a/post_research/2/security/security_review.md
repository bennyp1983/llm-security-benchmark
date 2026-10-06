# Security Review: Secure Symmetric Crypto Component (com.security.crypto)

## 1. Executive Summary

The component is a dependency-free Java 17 library for AES-256-GCM symmetric encryption at rest: an encrypt/decrypt service with per-message random IVs, an authenticated custom wire format (`SEC1` magic + version + keyId + IV + ciphertext‖tag), pluggable in-memory and PKCS#12 KeyStore key providers with rotation/revocation, PBKDF2-HMAC-SHA512 key derivation, key-file permission hardening, and a dual-bucket decryption-failure rate limiter. Core cryptography is sound: AES-256-GCM with 128-bit tags, `SecureRandom` for all nonces/keys/salts, defensive copies, uniform post-lookup decryption errors, and best-effort key zeroization.

The most important findings are in the **control layer around** the cryptography, not in the primitives:

1. **`encrypt()` reads the active key and its ID in two unsynchronized steps**, so a concurrent `rotateKey()` (documented as "atomic" but implemented as two writes) can produce a ciphertext permanently mislabeled with the wrong keyId — silent, unrecoverable data loss (SEC-01).
2. **Key-file validation is lexical, not canonical**: permission/ownership checks are applied to a `normalize()`-ed path while the file is later opened through symlink-following I/O, so the file that is validated and the file that is read can be different objects; on non-POSIX filesystems the permission checks are silently skipped entirely (SEC-02).
3. **The anti-brute-force throttle is keyed on attacker-influenced identifiers**: the per-source bucket key is a caller-supplied string (trivially rotated to reset limits), the shared default source bucket `"internal_client"` lets anyone lock out all anonymous callers with 20 forged decrypts/minute, and failures recorded against a victim `keyId` (taken from the untrusted payload) let an attacker deny decryption for a legitimate key (SEC-03). A pruning flaw additionally allows unbounded counter-map growth and memory exhaustion (SEC-04).

Lower-severity issues: fail-open key-length validation for non-extractable keys (SEC-05), no per-key nonce-budget bound for random GCM IVs (SEC-06), a permission-setting window on non-POSIX file creation (SEC-07), a public mutable static `MAGIC` array (SEC-08), and integer overflow in two size pre-checks (SEC-09).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/crypto/SymmetricEncryptionService.java` | Service interface | Defines encrypt/decrypt contract incl. `sourceId`-aware decrypt |
| `src/main/java/com/security/crypto/AesGcmEncryptionService.java` | AES-256-GCM encrypt/decrypt service | Per-op `Cipher`, random IV, AAD binding, size caps, rate-limiter integration, dummy-decryption timing defense, active-key selection (SEC-01, SEC-03, SEC-06) |
| `src/main/java/com/security/crypto/EncryptedPayload.java` | Immutable payload + wire format | Base64/binary parse with strict bounds checks (SEC-08, SEC-09), defensive copies, `toString` masking of secret material |
| `src/main/java/com/security/crypto/KeyProvider.java` | Key-provider interface | Key lookup / active-key selection contract |
| `src/main/java/com/security/crypto/InMemoryKeyProvider.java` | Heap key store with rotation/revocation | Key validation (SEC-05), non-atomic `rotateKey`/`setActiveKeyId` (SEC-01), key destruction on revoke |
| `src/main/java/com/security/crypto/KeyStoreKeyProvider.java` | PKCS#12 KeyStore provider | File loading gated on `FileSecurityUtil` validation (SEC-02), PKCS12 MAC verification, accepts only 32-byte AES entries |
| `src/main/java/com/security/crypto/KeyDerivation.java` | PBKDF2-HMAC-SHA512 KDF | Enforces ≥210 000 (default 600 000) iterations, ≥16-byte random salt, zeroizes password/spec/key material |
| `src/main/java/com/security/crypto/KeyGeneratorUtil.java` | AES-256 key, keyId and 96-bit IV generation | All randomness from `SecureRandom`; no per-key encryption budget (SEC-06) |
| `src/main/java/com/security/crypto/FileSecurityUtil.java` | Key-file permission validation and private creation | `normalize()`-only validation, `NOFOLLOW_LINKS` checks vs. link-following open (SEC-02), non-POSIX creation window (SEC-07), POSIX 0600 atomic create |
| `src/main/java/com/security/crypto/DecryptionRateLimiter.java` | Fixed-window dual-bucket failure throttle | Buckets keyed by caller-supplied sourceId and payload-derived keyId (SEC-03); pruning cannot evict fresh entries (SEC-04); fail-closed on threshold |
| `src/main/java/com/security/crypto/CryptoUtils.java` | Shared validation/hygiene helpers | Regex allowlists for keyId/sourceId, `MessageDigest.isEqual` constant-time compare, `wipe()` for byte[]/char[]/SecretKey, defensive copies |
| `src/main/java/com/security/crypto/CryptoException.java` | Unified runtime exception | Generic user-facing messages; retains cause for logging only |
| `src/test/java/com/security/crypto/SymmetricCryptoTest.java` | 25 unit tests | Tamper/AAD/truncation/rotation/rate-limit/concurrency coverage; synthetic test passwords only |
| `src/test/java/com/security/crypto/FileSecurityTest.java` | 4 POSIX permission tests | Verifies 0600/ownership enforcement on Linux/macOS |
| `pom.xml` | Maven build | Java 17; JUnit 5.11.4 test-scoped only — zero runtime dependencies (no supply-chain CVE surface) |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: whole component — algorithm/mode selection, key sizes, KDF parameters, entropy sources, hardcoded secrets, key storage and rotation practice. Basis for SEC-01, SEC-02, SEC-05, SEC-06 and the verified-primitives list in §6.
- `implementing-aes-encryption-for-data-at-rest`: `AesGcmEncryptionService`, `KeyGeneratorUtil`, `EncryptedPayload` wire format — AEAD usage, 96-bit nonce lifecycle, key zeroization, rotation policy. Basis for SEC-06 ("nonces never reused for the same key" cannot be guaranteed or enforced as designed).
- `performing-directory-traversal-testing`: `FileSecurityUtil` / `KeyStoreKeyProvider` key-file path handling — canonicalisation gaps and alternate-path (symlink) forms that make validation and access diverge. Basis for SEC-02. (No web path parameter exists; URL-encoding bypass vectors are not applicable to a `java.nio.file.Path` API.)
- `implementing-api-rate-limiting-and-throttling`: `DecryptionRateLimiter` — limiter-key selection (identity must be non-spoofable), fixed- vs sliding-window behaviour, check/record atomicity. Basis for SEC-03 and SEC-04.
- `implementing-api-abuse-detection-with-rate-limiting`: same classes — atomic check-and-decrement (the skill's Lua-script pattern) vs. the non-atomic `checkAllowed`/`recordFailure` split here, and adaptive/abuse-key design. Basis for SEC-03/SEC-04.
- `exploiting-insecure-deserialization`: checked `EncryptedPayload.fromBytes`/`fromBase64Url` parsing and KeyStore loading for native Java deserialization surface — grep for `ObjectInputStream`, `readObject`, `Serializable`, `XMLDecoder`, gadget JSON/YAML libs and `ac ed 00 05`/`rO0AB` markers returned **no matches**; the wire format is hand-parsed with explicit bounds checks and PKCS#12 load is MAC-verified. **No finding** (see §6).
- `implementing-secret-scanning-with-gitleaks` (knowledge only — the tool was not executed against this code): grep-equivalent scan for hardcoded credentials across `src/main` (none) and `src/test` (only synthetic test vectors such as `SymmetricCryptoTest.java:391`, `FileSecurityTest.java:81`). **No production finding** (see §6).

**Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched the behaviour:** check-to-use races and rotation atomicity (OWASP A04 / CWE-367 — SEC-01), unbounded in-memory growth of the limiter maps (OWASP A05 / CWE-770 — SEC-04), timing-oracle countermeasures (dummy decryption, constant-time compare — verified, §6), integer overflow in allocation pre-checks (CWE-190 — SEC-09), mutable public static array exposure (CWE-582 — SEC-08).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Active key and key ID read non-atomically — concurrent rotation mislabels ciphertext (permanent data loss) | High | CWE-367 | `AesGcmEncryptionService.java:110-111` |
| SEC-02 | Key-file validation is lexical; file is later opened through symlinks; checks skipped on non-POSIX | High | CWE-59 | `KeyStoreKeyProvider.java:47-48` |
| SEC-03 | Decryption throttle keyed on spoofable caller-supplied and payload-derived identities — limit bypass and lock-out DoS | High | CWE-799 | `DecryptionRateLimiter.java:83-133` |
| SEC-04 | Rate-limiter pruning cannot evict fresh entries — unbounded map growth / memory exhaustion | Medium | CWE-770 | `DecryptionRateLimiter.java:153-157` |
| SEC-05 | Key length validation fails open for non-extractable keys | Medium | CWE-754 | `InMemoryKeyProvider.java:59-68` |
| SEC-06 | No per-key encryption budget for random 96-bit GCM IVs (nonce-collision risk grows with key lifetime) | Low | CWE-323 | `AesGcmEncryptionService.java:112-113` |
| SEC-07 | Non-POSIX `createPrivateFile` grants a permission-setting window after creation | Low | CWE-276 | `FileSecurityUtil.java:115-121` |
| SEC-08 | Public static mutable `MAGIC` byte array | Low | CWE-582 | `EncryptedPayload.java:36` |
| SEC-09 | Integer overflow in wire-size pre-checks defeats the oversized-input guard for large configured limits | Low | CWE-190 | `EncryptedPayload.java:148` |

## 5. Detailed Findings

### SEC-01: Active key and key ID read non-atomically — concurrent rotation mislabels ciphertext (permanent data loss)

- **Severity:** High
- **CWE:** CWE-367: Concurrent Execution using Shared Resource with Inadequate Synchronization ('Race Condition')
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:110-111` (reader) and `src/main/java/com/security/crypto/InMemoryKeyProvider.java:104-109` (writer)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:110-111
        SecretKey activeKey = keyProvider.getActiveKey();
        String activeKeyId = keyProvider.getActiveKeyId();
```
```java
// src/main/java/com/security/crypto/InMemoryKeyProvider.java:104-109
    public void rotateKey(String newKeyId, SecretKey newKey) {
        ensureOpen();
        CryptoUtils.validateKeyId(newKeyId);
        validateKey(newKey);
        keys.put(newKeyId, newKey);
        activeKeyId.set(newKeyId);
    }
```

**Why it is a problem:** `encrypt()` resolves the key and the key ID through two separate provider calls, and `rotateKey()` (whose Javadoc claims it registers and activates "atomically") performs two independent writes: `keys.put(...)` then `activeKeyId.set(...)`. An interleaving is straightforward on a running service: thread A calls `getActiveKey()` and receives the *old* key; `rotateKey()` then completes; thread A calls `getActiveKeyId()` and receives the *new* ID. The returned payload is therefore encrypted under the old key but labeled with the new keyId. Every later `decrypt()` looks up the new key, fails GCM tag verification, and throws the uniform "Decryption failed" — the ciphertext is unrecoverable, and no error anywhere points at the cause. The same non-atomic read pattern exists between `setActiveKeyId()` (`InMemoryKeyProvider.java:89-96`) and `encrypt()`, and in `KeyStoreKeyProvider`. Silent loss of encrypted data is an integrity/availability failure of the component's core promise.

**Fix:** Resolve the active key and its ID from a single read of `activeKeyId`, exposed as one atomic snapshot accessor used by `encrypt()`:
```java
// InMemoryKeyProvider — add an atomic snapshot accessor
public record ActiveKeySnapshot(String keyId, SecretKey key) {}

public ActiveKeySnapshot getActiveKeySnapshot() {
    ensureOpen();
    String id = activeKeyId.get();               // read the volatile ONCE
    if (id == null) {
        throw new CryptoException("No active key is configured");
    }
    SecretKey key = keys.get(id);
    if (key == null) {
        throw new CryptoException("Active key is no longer available");
    }
    return new ActiveKeySnapshot(id, key);
}
```
```java
// AesGcmEncryptionService.encrypt — replace lines 110-111
        KeyProvider.ActiveKeySnapshot active = keyProvider.getActiveKeySnapshot();
        SecretKey activeKey = active.key();
        String activeKeyId = active.keyId();
```

### SEC-02: Key-file validation is lexical; file is later opened through symlinks; checks skipped on non-POSIX

- **Severity:** High
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following')
- **Location:** `src/main/java/com/security/crypto/FileSecurityUtil.java:50-95` and `src/main/java/com/security/crypto/KeyStoreKeyProvider.java:47-48`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/FileSecurityUtil.java:50-56
            normalized = path.toAbsolutePath().normalize();
            if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw new CryptoException("Key file does not exist");
            }
            if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw new CryptoException("Key file is not a regular file");
            }
```
```java
// src/main/java/com/security/crypto/KeyStoreKeyProvider.java:46-49
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
        try (InputStream in = Files.newInputStream(validatedPath)) {
            return fromInputStream(in, password, activeKeyAlias);
```

**Why it is a problem:** `toAbsolutePath().normalize()` is a purely **lexical** operation — it never resolves symlinks and is not the canonical path the README claims ("canonicalized"). All hardening (existence, regular-file, parent-directory world-writable check at lines 65-72, owner check at lines 74-78, mode-0600 permission check at lines 81-90) is applied to that lexical path using `NOFOLLOW_LINKS` for the *final* component only; intermediate path components are still followed. The file is then opened at line 48 with `Files.newInputStream(validatedPath)`, which **follows** symlinks. A local attacker who can write anywhere in the path (the world-writable check covers only the *direct* parent) can place a symlink at the validated location — or swap the validated file for a symlink in the window between validation and open (classic check-to-use race) — so the permission/ownership verdict is applied to one file while the KeyStore is loaded from a different one, enabling keystore substitution or reference to an unintended file. Two further gaps weaken the same control: (a) when `IS_POSIX` is false (line 62), *no* permission, ownership, or parent-directory check runs at all — on Windows the keystore may silently be world-readable; (b) the owner check at line 76 explicitly tolerates `root`-owned files, so a file planted by a privileged attacker passes the ownership gate on hosts where the application can still read it (e.g., permissive mounts, NFS id-squash configurations).

**Fix:** Canonicalise with `toRealPath()` before validating, validate the *resolved* path, and open that same resolved path; additionally run an ACL-based check on non-POSIX platforms:
```java
// FileSecurityUtil.validatePrivateFile — resolve, then validate the real path
        Path normalized = path.toAbsolutePath().normalize();
        Path real;
        try {
            real = normalized.toRealPath();              // resolves ALL symlinks
        } catch (NoSuchFileException e) {
            throw new CryptoException("Key file does not exist");
        }
        if (!Files.isRegularFile(real)) {
            throw new CryptoException("Key file is not a regular file");
        }
        // ... perform parent/owner/permission checks against `real` ...
        // Non-POSIX: check AclFileAttributeView denies GROUP/EVERYONE read instead of skipping.
        return real;
```
```java
// KeyStoreKeyProvider.fromFile — open exactly the validated, resolved file
        Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
        try (InputStream in = Files.newInputStream(validatedPath)) {   // validatedPath is now the real path
            return fromInputStream(in, password, activeKeyAlias);
        }
```

### SEC-03: Decryption throttle keyed on spoofable caller-supplied and payload-derived identities — limit bypass and lock-out DoS

- **Severity:** High
- **CWE:** CWE-799: Improper Control or Management of Interaction Frequency
- **Location:** `src/main/java/com/security/crypto/DecryptionRateLimiter.java:83-133` (buckets), `src/main/java/com/security/crypto/AesGcmEncryptionService.java:155-171` (key selection), `:48` (shared default bucket)

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:155-171
    public byte[] decrypt(EncryptedPayload payload, byte[] aad, String sourceId) {
        Objects.requireNonNull(payload, "Payload must not be null");
        String validatedSourceId = CryptoUtils.validateSourceId(sourceId);
        CryptoUtils.validateAad(aad, maxAadBytes);

        String keyId = payload.getKeyId();

        // Rule 3 & 7: Check failure limits atomically per source and per key/resource
        rateLimiter.checkAllowed(validatedSourceId, keyId);

        // Rule 1 & 6: Verify key ID against server-side state
        Optional<SecretKey> optKey = keyProvider.getKey(keyId);
        if (optKey.isEmpty()) {
            // Rule 6: Neutralize timing oracle attacks.
            // Perform identical computational work using a dummy key before rejecting.
            performDummyDecryption(payload.getIv(), payload.getCiphertextWithTag(), aad);
            rateLimiter.recordFailure(validatedSourceId, keyId);
```

**Why it is a problem:** The limiter's own Javadoc (`DecryptionRateLimiter.java:12-15`) justifies the dual bucket by assuming the source identity is *not* attacker-chosen ("an attacker submitting … will exhaust their own source bucket before exhausting the account limit"). In this component both throttle keys violate that assumption:

1. **Per-source bypass.** `sourceId` is a plain caller-supplied string (any `^[a-zA-Z0-9_.:-]{1,128}$` value, `CryptoUtils.java:33`). An integrator that forwards a request attribute or client header into `sourceId` — the obvious usage — hands the attacker a fresh 20-failures/minute bucket for every distinct value, so the per-source cap never constrains a determined adversary and every failed attempt still burns a full dummy decryption of attacker-sized data (`performDummyDecryption` runs the entire GCM decrypt), an CPU-amplification DoS.
2. **Shared default bucket = trivial lock-out.** The convenience overloads (`AesGcmEncryptionService.java:145-151`) route every anonymous caller into one `"internal_client"` bucket capped at 20 failures/minute (line 48). Any single party feeding 20 garbage payloads per minute blocks `checkAllowed` for **all** users of the no-`sourceId` API for the rest of the window.
3. **Per-resource (keyId) bucket = targeted key lock-out.** `keyId` comes from the *untrusted payload* (line 160). An attacker who can submit garbage can spray 50 failures against any legitimate `keyId` — including well-formed-but-tampered ciphertexts for a *known valid* key — and thereby deny decryption of that key to all users every window, distributed across unlimited spoofed sources. This is exactly the attacker-induced denial-of-service the design claims to prevent.
4. **Non-atomic check/record and fixed window.** `checkAllowed` is read-only (lines 83-100) and `recordFailure` is a separate call (lines 107-133); concurrent requests interleave and can overshoot both caps by the in-flight request count before any bucket trips.

**Fix:** Throttle on identities the service — not the caller — controls, never block a shared/global bucket on failures with an unresolvable key, and make the check-and-record step atomic. Illustrative service-side change:
```java
// Do not take the throttle identity from the payload or a spoofable default.
// Require an authenticated principal from the embedding service, and never
// fail-closed the *global* bucket on unknown-keyId failures (they are not
// attributable to a real resource):
public byte[] decrypt(EncryptedPayload payload, byte[] aad, CallerIdentity caller) {
    String principal = caller.authenticatedName();   // bound by the host service
    rateLimiter.recordAttemptAndCheck(principal, payload.getKeyId()); // atomic incr+check
    Optional<SecretKey> optKey = keyProvider.getKey(payload.getKeyId());
    if (optKey.isEmpty()) {
        // Unknown keyId: charge the PRINCIPAL only — not the resource bucket,
        // which must only accumulate failures against keys that actually resolve.
        rateLimiter.recordFailure(principal, null);
        throw new CryptoException("Decryption failed");
    }
    // ... on tag failure: rateLimiter.recordFailure(principal, payload.getKeyId()); ...
}
```
```java
// DecryptionRateLimiter — fuse check+record into one atomic operation and drop
// the shared "internal_client" default: require an explicit per-caller bucket.
public void recordAttemptAndCheck(String sourceId, String resourceId) {
    long now = System.currentTimeMillis();
    int src = bumpAndGet(sourceCounters, sourceId, now);
    if (resourceId != null && keyExistsLocally(resourceId)) {   // resolved keys only
        int res = bumpAndGet(resourceCounters, resourceId, now);
        if (res > maxResourceFailures) throw new CryptoException("Decryption rate limit exceeded");
    }
    if (src > maxSourceFailures) throw new CryptoException("Decryption rate limit exceeded");
}
```

### SEC-04: Rate-limiter pruning cannot evict fresh entries — unbounded map growth / memory exhaustion

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

**Why it is a problem:** `MAX_MAP_ENTRIES = 10_000` (line 43) is presented as the memory bound, but pruning only removes counters whose window has *expired*. Combined with the attacker-chosen `sourceId` (SEC-03) and the unconditional `compute(...)` insert in `recordFailure` (lines 111-121), an attacker submitting failures with 10 001+, freshly-generated distinct source IDs within the 60-second window drives the map past the cap with entries that `removeIf` will never match — `compute` then keeps inserting. The bound is advisory only, and each entry is a live `WindowCounter` retained as long as it keeps being refreshed, yielding sustained heap growth to OOM on a long-lived JVM. This is a straightforward memory-DoS amplifier for the same throttle the component relies on for availability.

**Fix:** Enforce the cap hard: if pruning expired entries does not bring the map below the threshold, evict the oldest-window entries (or refuse to track new keys) so the map can never exceed `MAX_MAP_ENTRIES`:
```java
    private void pruneIfNecessary(ConcurrentHashMap<String, WindowCounter> map, long now) {
        if (map.size() >= MAX_MAP_ENTRIES) {
            map.entrySet().removeIf(e -> (now - e.getValue().windowStartMs) > windowDurationMs);
            // Cap is not advisory: if nothing expired, evict oldest-window entries
            // (Caffeine/LinkedHashMap LRU is the durable fix).
            map.entrySet().stream()
                .sorted(Comparator.comparingLong(e -> e.getValue().windowStartMs))
                .limit(map.size() - MAX_MAP_ENTRIES / 2)
                .forEach(e -> map.remove(e.getKey()));
        }
    }
```

### SEC-05: Key length validation fails open for non-extractable keys

- **Severity:** Medium
- **CWE:** CWE-754: Improper Check or Handling of Exceptional Conditions
- **Location:** `src/main/java/com/security/crypto/InMemoryKeyProvider.java:54-69`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/InMemoryKeyProvider.java:59-68
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            try {
                if (encoded.length != REQUIRED_KEY_LENGTH_BYTES) {
                    throw new CryptoException("Invalid cryptographic key: key size must be 256 bits (32 bytes)");
                }
            } finally {
                CryptoUtils.wipe(encoded);
            }
        }
```

**Why it is a problem:** `SecretKey.getEncoded()` returns `null` for non-extractable keys — a normal, expected property of HSM- and smartcard-backed JCA providers (`SunPKCS11` keys typically return null). In those cases the entire 256-bit length check is silently skipped and a 128-bit (or any AES-sized) key is accepted under the component's "AES-256" contract, downgrading every payload encrypted with it. A validation control that disappears precisely for the most security-sensitive key class is fail-open at exactly the wrong boundary; the component's promise of uniform 256-bit protection becomes provider-dependent. (`KeyStoreKeyProvider.fromInputStream` has a structurally similar skip at its load loop, but there the file content is already a trust input and skipping silently *drops* such keys — this entry point, `registerKey`/`rotateKey`, is the public API where it matters.)

**Fix:** Fail closed on non-extractable keys (or verify size via an explicit provider attribute) instead of skipping the check:
```java
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new CryptoException(
                "Invalid cryptographic key: non-extractable keys are not accepted; "
              + "verify 256-bit strength out-of-band and wrap via a supported provider");
        }
        try {
            if (encoded.length != REQUIRED_KEY_LENGTH_BYTES) {
                throw new CryptoException("Invalid cryptographic key: key size must be 256 bits (32 bytes)");
            }
        } finally {
            CryptoUtils.wipe(encoded);
        }
```

### SEC-06: No per-key encryption budget for random 96-bit GCM IVs (nonce-collision risk grows with key lifetime)

- **Severity:** Low
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/security/crypto/AesGcmEncryptionService.java:112-113`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/AesGcmEncryptionService.java:112-113
        // Rule 4: Cryptographically secure fresh IV generated internally; caller cannot specify IV
        byte[] iv = KeyGeneratorUtil.generateGcmIv();
```

**Why it is a problem:** IVs are fresh 96-bit random values from `SecureRandom`, which is correct practice, but with *random* nonces GCM security holds only while the number of encryptions under one key stays far below the birthday bound — NIST SP 800-38D caps a key at 2³² messages when random IVs are used; a collision irreversibly breaks both confidentiality and authentication for the two colliding messages. The component never counts encryptions per key and never triggers or even warns on rekeying: rotation is purely operator-initiated (`rotateKey`), so a long-lived active key on a busy service can drift toward the bound with no signal. The skill checklist item "nonces are never reused for the same key" is therefore unverifiable as designed — nothing enforces or monitors the invariant.

**Fix:** Track per-key encryption usage and force rotation (or alert) before the 2³²-message bound:
```java
// AesGcmEncryptionService — bound random-IV usage per key
private static final long MAX_ENVELOPES_PER_KEY = 1L << 32;
private final ConcurrentHashMap<String, AtomicLong> envelopesPerKey = new ConcurrentHashMap<>();

// in encrypt(), after obtaining the active key snapshot:
long used = envelopesPerKey
        .computeIfAbsent(active.keyId(), k -> new AtomicLong())
        .incrementAndGet();
if (used > MAX_ENVELOPES_PER_KEY) {
    throw new CryptoException("Active key has reached its random-IV usage bound; rotate the key");
}
```

### SEC-07: Non-POSIX `createPrivateFile` grants a permission-setting window after creation

- **Severity:** Low
- **CWE:** CWE-276: Incorrect Default Permissions
- **Location:** `src/main/java/com/security/crypto/FileSecurityUtil.java:114-126`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/FileSecurityUtil.java:114-121
        } else {
            Path created = Files.createFile(normalized);
            File file = created.toFile();
            // Restrict on non-POSIX filesystems
            boolean ok = file.setReadable(false, false)
                    && file.setReadable(true, true)
                    && file.setWritable(false, false)
                    && file.setWritable(true, true)
                    && file.setExecutable(false, false);
```

**Why it is a problem:** On POSIX the file is created atomically with mode 0600 via the `PosixFilePermissions` file attribute (lines 111-113) — correct. On the non-POSIX branch the file is first created with the platform's inherited default ACL and only *afterwards* tightened through four separate `File.set*` calls. Between creation and the last call, another local principal whose default-inherited ACE permits read (typical on misconfigured Windows shares, FAT/exFAT volumes, or network mounts where `setReadable` is a silent no-op returning `true`) can open and copy the freshly written key material. The fail-closed deletion at lines 122-125 covers only outright API failure, not the exposure window and not platforms where the flags "succeed" without applying an owner-only ACL.

**Fix:** On non-POSIX platforms create the file inside an owner-only directory and verify the effective ACL on the created file before returning it — never trust the boolean return of `File.set*`:
```java
            Path created = Files.createFile(normalized);
            // Verify the effective ACL is owner-only before handing the path back.
            AclFileAttributeView acl = Files.getFileAttributeView(
                    created, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (acl != null) {
                String owner = acl.getOwner().getName();
                boolean ownerOnly = acl.getAcl().stream().allOf(
                        e -> e.getPrincipal().getName().equals(owner)
                          && e.getPermissions().size() > 0);
                if (!ownerOnly) {
                    Files.deleteIfExists(created);
                    throw new IOException("Failed to restrict file ACL on created file");
                }
            }
            return created;
```

### SEC-08: Public static mutable `MAGIC` byte array

- **Severity:** Low
- **CWE:** CWE-582: Array Held in Public Static Field
- **Location:** `src/main/java/com/security/crypto/EncryptedPayload.java:36`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/EncryptedPayload.java:36
    public static final byte[] MAGIC = new byte[]{'S', 'E', 'C', '1'};
```

**Why it is a problem:** `MAGIC` is the format-identity constant used both when serializing (`toBytes()`, line 116) and when rejecting foreign formats in the untrusted-input parser (`fromBytes`, line 158). `final` freezes only the reference — the array contents are mutable by any code in the JVM that can name the field. Any co-resident (or later-added, e.g. via a transitive dependency) class can execute `EncryptedPayload.MAGIC[0] = 'X';` to silently break the format gate: every legitimate payload the process later serializes carries a corrupted header, and previously stored payloads fail parsing — an integrity/availability failure of the component's own trust check. The parser also reads from this shared mutable array while untrusted input is being processed, so a mid-parse mutation produces inconsistent verdicts.

**Fix:** Keep the constant private and expose only copies where the value is genuinely needed publicly:
```java
    private static final byte[] MAGIC = new byte[]{'S', 'E', 'C', '1'};

    /** Returns a defensive copy of the format magic header ("SEC1"). */
    public static byte[] magicHeader() {
        return MAGIC.clone();
    }
```

### SEC-09: Integer overflow in wire-size pre-checks defeats the oversized-input guard for large configured limits

- **Severity:** Low
- **CWE:** CWE-190: Integer Overflow or Wraparound
- **Location:** `src/main/java/com/security/crypto/EncryptedPayload.java:148` and `:223`

**Vulnerable code:**
```java
// src/main/java/com/security/crypto/EncryptedPayload.java:148
        if (data.length > maxCiphertextSize + 1024) {
```
```java
// src/main/java/com/security/crypto/EncryptedPayload.java:222-225
        // Basic pre-check on base64 string length to avoid allocating oversized arrays
        int maxBase64Len = ((maxCiphertextSize + 1024) * 4) / 3 + 4;
        if (base64Url.length() > maxBase64Len) {
            throw new CryptoException("Invalid cryptographic payload: input exceeds maximum allowable size");
        }
```

**Why it is a problem:** Both limits are computed with `int` arithmetic on a **caller-configurable** value: the `AesGcmEncryptionService` constructors validate only that `maxCiphertextBytes > 0`, with no upper bound. For an `int` limit above `Integer.MAX_VALUE - 1024`, `maxCiphertextSize + 1024` wraps negative and the line-148 guard passes *any* input; likewise `(maxCiphertextSize + 1024) * 4` overflows in `fromBase64Url`, letting arbitrarily large Base64 strings reach `Base64.getUrlDecoder().decode(...)` and a full array allocation before any structural check runs — the exact oversized-allocation that the pre-check exists to prevent. Default configuration (16 MB) is safe, so this is a hardening gap rather than an out-of-the-box vulnerability, but the component cannot assume integrators use the defaults.

**Fix:** Perform both comparisons in `long` arithmetic:
```java
        if (data.length > (long) maxCiphertextSize + 1024L) {
            throw new CryptoException("Invalid cryptographic payload: payload exceeds maximum allowable size");
        }
```
```java
        // Basic pre-check on base64 string length to avoid allocating oversized arrays
        long maxBase64Len = (((long) maxCiphertextSize + 1024L) * 4L) / 3L + 4L;
        if (base64Url.length() > maxBase64Len) {
            throw new CryptoException("Invalid cryptographic payload: input exceeds maximum allowable size");
        }
```

## 6. Verified Controls and Checks With No Finding

- **Cipher choice and parameters:** `AesGcmEncryptionService` uses `AES/GCM/NoPadding` exclusively with a 128-bit tag (`GCM_TAG_LENGTH_BITS`), and GCM IVs are always 12 bytes (enforced both at generation and parse time). No ECB/CBC/CTR, no unauthenticated mode, no deprecated primitive (MD5/SHA-1/DES/RC4) appears anywhere in the source (grep over `src/`).
- **Nonce generation:** `KeyGeneratorUtil.generateGcmIv()` draws every IV from a shared `SecureRandom`; the caller cannot supply an IV (API exposes no IV parameter) — random-IV *quality* is correct (lifetime budget handled as SEC-06).
- **Key generation and entropy:** `KeyGeneratorUtil.generateAes256Key()` initializes a JCA `KeyGenerator` with `SecureRandom`; `KeyDerivation.generateSalt` uses `SecureRandom` with a 16-byte minimum; key IDs are 16 random bytes hex-encoded.
- **KDF strength:** `KeyDerivation` pins `PBKDF2WithHmacSHA512`, rejects fewer than 210 000 iterations (default 600 000) and salts under 16 bytes, and zeroizes the `PBEKeySpec`, passphrase, and derived key material in `finally` blocks — meets current OWASP guidance.
- **Decryption failure oracle:** for both unknown-key and tag-verification failures, callers receive the identical `CryptoException("Decryption failed")` message (`AesGcmEncryptionService.java:175, 194`) with comparable constant work via `performDummyDecryption` on a per-instance dummy key (`:217-231`), eliminating key-validity enumeration through response text; parse-stage format errors occur only before any key lookup.
- **No native Java deserialization surface:** grep for `ObjectInputStream`, `readObject`, `Serializable`, `XMLDecoder`, and gadget-prone JSON/YAML libraries over `src/` returned no matches; the `SEC1` wire format is parsed manually via `ByteBuffer` with explicit bounds checks (magic, version, keyId length 1-64 + regex, `ivLen == 12`, ciphertext range, exact remaining-length match rejecting trailing bytes), and `KeyStore.load` verifies the PKCS#12 MAC before any key is read (`KeyStoreKeyProvider.java:74`).
- **KeyStore key ingestion hygiene:** `fromInputStream` accepts only AES entries of exactly 32 bytes, wipes the encoded form in `finally`, wipes the password char array in `finally`, and fails closed if the configured active alias is absent (`KeyStoreKeyProvider.java:102-107`).
- **Input validation at trust boundaries:** every externally supplied string is regex-allowlisted before use — key IDs `^[a-zA-Z0-9_-]{1,64}$`, source IDs `^[a-zA-Z0-9_.:-]{1,128}$` (`CryptoUtils.java:27,33`) — and plaintext/AAD/IV/ciphertext sizes are bounds-checked on every entry path.
- **Secret handling in memory:** defensive copies on `EncryptedPayload` construction and getters (`getIv`, `getCiphertextWithTag` return `copyDefensive` clones); `toString` masks secret content; `CryptoUtils.wipe` zeroizes `byte[]`, `char[]`, and best-effort destroys `SecretKey` (catching `DestroyFailedException`/`UnsupportedOperationException`); `revokeKey` and `close` destroy key material; plaintext wipe helper exposed (`wipePlaintext`). (Residual string/heap immutability residue is an inherent JVM limitation, mitigated here by `char[]`/`byte[]` APIs throughout.)
- **Constant-time comparison:** `CryptoUtils.constantTimeEquals` delegates to `MessageDigest.isEqual` (`CryptoUtils.java:85-89`), the JCE-constant-time primitive.
- **Thread safety of cipher state:** a fresh `Cipher` instance is created per operation in both encrypt and decrypt paths, avoiding shared mutable cipher state; the concurrent-encryption test suite exercises this.
- **Rate limiter fail-closed direction:** `checkAllowed` throws before any crypto work once a threshold is tripped, and `WindowCounter.isExceeded` treats an expired window as zero rather than carrying counts over (weaknesses in *which* keys are counted are SEC-03/SEC-04; the throttle direction itself is fail-closed).
- **POSIX private-file creation:** on POSIX, `createPrivateFile` creates the file atomically with mode `rw-------` via `PosixFilePermissions.asFileAttribute` (no exposure window), and `FileSecurityTest` verifies 0600 enforcement and rejection of group/other access.
- **Logging hygiene:** no key bytes, plaintext, or ciphertext content is ever passed to the logger; log messages are static strings and unknown-keyId detail is restricted to `FINE` (`AesGcmEncryptionService.java:172, 192`).
- **No hardcoded secrets in production code:** gitleaks-style grep-equivalent over `src/main` found no credentials; the only literal passwords are synthetic unit-test vectors confined to `src/test` (`SymmetricCryptoTest.java:391,408,428`, `FileSecurityTest.java:81`), acceptable as test fixtures.
- **Supply-chain exposure:** `pom.xml` declares zero runtime dependencies (JUnit 5.11.4 test-scoped only), so the crypto core has no transitive CVE surface to audit.
- **Test coverage of adversarial inputs:** the 29-test suite verifies tag-tamper rejection, AAD-binding enforcement, truncated/oversized/malformed-wire rejection, wrong-key failure uniformity, rate-limit trip behaviour, POSIX permission enforcement, and concurrent encrypt/decrypt operation — consistent with the controls claimed above (though it does not exercise the SEC-01 rotation-interleaving window).
