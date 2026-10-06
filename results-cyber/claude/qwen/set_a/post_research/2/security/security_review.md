# Security Review: `com.example.crypto` symmetric data-encryption component

## 1. Executive Summary

The component under review is a self-contained Java library (Maven artifact `secure-data-crypto-1.0.0`) that
encrypts and decrypts sensitive application data with AES-256-GCM and manages the keys needed for both
directions. It consists of an encryption engine (`SymmetricCrypto`), a record format (`EncryptedBlob`), a
versioned key facade with rotation (`KeyVault`), an owning/wiping key holder (`KeyMaterial`), four key
sources (environment variable, raw key file, PKCS#12 key store, PBKDF2-wrapped key container), filesystem
privacy guards (`PrivateFiles`), a strict key parser (`KeyEncoding`), input bounds (`Limits`), a random
secret generator (`RandomPasswords`) and a two-message exception type (`CryptoException`).

The cryptographic core is sound and unusually well defended. AES-256-GCM with a 128-bit tag and a fresh
random 96-bit nonce per record; the format version, context flag, key version and context string are all
bound into the AAD, so header re-stamping, context swapping and key-version retargeting all fail the tag;
decoding is canonical, so a record has exactly one string spelling; every external input is bounded before
allocation; there are no hardcoded keys or passwords anywhere in `src/main`; and all randomness comes from
`SecureRandom`. Error reporting is split into a fixed generic user message and a secret-free log detail.

The important findings are in the key-management layer rather than the cipher:

- **SEC-01 (High)** — `KeyVault.sourceFor` hands out a *decoy* key source (a fresh random key that is
  discarded immediately) whenever the version table is full. That branch is also reachable for the **active**
  version on the **encrypt** path, so the vault can report a successful encryption of production data under a
  throwaway key that nothing can ever recover. It fails open, silently, in the one direction where failing
  open destroys data.
- **SEC-02 (Medium)** — the accepted PBKDF2 floor (310 000 iterations) is below current guidance for
  PBKDF2-HMAC-SHA256 (600 000), and a container file may legitimately declare that floor, so the deployed
  cost can be roughly half of the component's own default.
- **SEC-03 (Medium)** — the environment/base64 key path materialises key bytes into a non-erasable `String`
  and leaves the intermediate byte buffers unwiped, which contradicts the design rule the rest of the
  component follows rigorously.
- Four further Low findings: a race that can erase a passphrase another thread is using, no attempt
  throttling on passphrase unwrap, no rejection of degenerate key material, decrypted plaintext left in the
  heap by the `String` overloads, and an unlocked read of the active version on the encrypt path.

No injection, deserialization, SSRF, access-control or hardcoded-secret issues were found.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/crypto/SymmetricCrypto.java` | AES-256-GCM encrypt/decrypt engine and key generation | Fixed transformation, 96-bit random nonce per record, 128-bit tag, AAD construction, single uniform failure path, `SecureRandom`, plaintext bounds, strict UTF-8 decoding |
| `src/main/java/com/example/crypto/EncryptedBlob.java` | Immutable record: header + nonce + ciphertext/tag, plus its encoded string form | Parsing of attacker-controlled strings, length bounds before allocation, canonical base64url re-encode check, header whitelisting, `peekKeyVersion` on untrusted input, `toString` that never prints the payload |
| `src/main/java/com/example/crypto/KeyVault.java` | Versioned keys, rotation, enable/disable, encrypt/decrypt facade | Routing on an attacker-chosen key-version byte, decoy sources for unprovisionable versions, source caching under a lock, rotation atomicity, version-table ceiling, fail-closed teardown |
| `src/main/java/com/example/crypto/KeyMaterial.java` | Owns the 32 raw key bytes and wipes them | Copy-on-import, length enforcement (AES-256 only), `use()` with `finally` wipe, `destroy()`, identity-only `equals`, secret-free `toString` |
| `src/main/java/com/example/crypto/KeySource.java` | Interface for "where a key comes from" | Contract: fresh material per call, no caching, fail closed, `describe()` must never contain a secret |
| `src/main/java/com/example/crypto/EnvKeySource.java` | Loads a key from an environment variable | Variable-name whitelist, value size bound, strict parsing, error detail that reports only shape; key passes through a `String` |
| `src/main/java/com/example/crypto/KeyFileKeySource.java` | Loads a key from a file | Path validation (length, NUL), delegates privacy checks to `PrivateFiles`, wipes the read buffer |
| `src/main/java/com/example/crypto/KeystoreKeySource.java` | PKCS#12 store holding a random AES-256 key | Password validation (length floor, trailing NUL, unpaired surrogates), alias whitelist, store size/entry caps, permission re-check per load, store created `0600` from the first byte, `char[]` passwords erased on `destroy()` |
| `src/main/java/com/example/crypto/PasswordKeySource.java` | PBKDF2-HMAC-SHA256 KEK wrapping a random AES-256 data key in a file container | KDF cost read from a file and range-checked *before* derivation, header authenticated as AAD, wrap tag as the passphrase check, per-container random salt, `char[]` passphrase erased on `destroy()` |
| `src/main/java/com/example/crypto/PrivateFiles.java` | Filesystem privacy guards for anything holding a secret | Create-with-mode (`CREATE_NEW` + `0600`), symlink refusal via `NOFOLLOW_LINKS`, owner and mode checks, ancestry walk with sticky-bit rule, post-read inode/mode re-validation in shared directories, refusal when POSIX attributes are unavailable |
| `src/main/java/com/example/crypto/KeyEncoding.java` | Parses key bytes from a file/config buffer; base64url export | Only two accepted forms, strict (non-MIME) decoder, canonical re-encode check, no whitespace trimming, no pad/truncate/hash fallback; builds a `String` of the encoded key |
| `src/main/java/com/example/crypto/Limits.java` | Hard bounds for every external value | Plaintext/ciphertext/encoded-string caps, nonce and tag sizes, context charset whitelist, PBKDF2 iteration floor and ceiling |
| `src/main/java/com/example/crypto/RandomPasswords.java` | Generates high-entropy `char[]` secrets | `SecureRandom`, full printable-ASCII alphabet minus space, length range enforced, returns erasable `char[]` not `String` |
| `src/main/java/com/example/crypto/CryptoException.java` | The single failure type | Generic fixed-vocabulary `getMessage()`, separate transient technical detail, stack traces disabled, cause message stripped, `printStackTrace` overridden |
| `src/test/java/com/example/crypto/*.java` (7 files) | JUnit suites: cipher behaviour, key sources, vault, file permissions, no-secret-leak | Test-only fixtures and sample passphrases; no production credential material |
| `pom.xml`, `README.md`, `prompt.txt`, `result.md`, `return.txt`, `target/**` | Build file, documentation, generation prompt/transcript, compiled output | No executable logic reviewed; `target/**` is build output and was not decompiled |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `SymmetricCrypto`, `PasswordKeySource`,
  `KeystoreKeySource`, `KeyEncoding`, `RandomPasswords` and `Limits` — checked for deprecated algorithms
  (none: AES-256-GCM and PBKDF2-HMAC-SHA256 only; no MD5/SHA-1/DES/RC4), insecure modes (no ECB; GCM with a
  128-bit tag), insufficient key size (32 bytes enforced at `KeyMaterial.java:81`), hardcoded secrets (none in
  `src/main`), weak KDF parameters (**SEC-02**), entropy/RNG quality (`SecureRandom` throughout;
  `SymmetricCrypto.java:56`, `RandomPasswords.java:60`), and key storage/rotation practice (`KeyVault`,
  `PrivateFiles`).
- `implementing-aes-encryption-for-data-at-rest`: applied to `SymmetricCrypto` and `EncryptedBlob` against the
  skill's validation criteria — AEAD mode, tag-detects-modification, 96-bit never-reused nonce from a CSPRNG,
  nonce stored alongside ciphertext, metadata in the record format, key derivation parameters
  (**SEC-02**), "securely wipe keys from memory after use" (**SEC-03**, **SEC-07**), and key rotation
  (`KeyVault.rotate`, where **SEC-01** was found).
- `testing-for-sensitive-data-exposure`: applied to `CryptoException`, every `describe()`/`toString()`, and all
  exception detail strings — checked for secrets, key bytes, plaintext, passwords and internal paths in
  messages, logs and error responses; the generic/technical message split holds (see section 6).
- `implementing-secrets-management-with-vault` and `configuring-hsm-for-key-storage`: consulted for key-storage
  expectations; both describe external platforms this library intentionally defers to, so no finding is drawn
  from them beyond confirming that the component never persists an unwrapped key itself.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill matched these behaviours:
  - concurrency and shared-mutable-state handling in `KeyVault`, `PasswordKeySource` and `KeystoreKeySource`
    (CWE-362) — **SEC-04**, **SEC-08**;
  - filesystem TOCTOU, symlink following and permission/ownership validation in `PrivateFiles` (CWE-367,
    CWE-59, CWE-732) — no finding, see section 6;
  - untrusted-input parsing and resource bounds in `EncryptedBlob.fromEncoded`/`peekKeyVersion` and
    `PasswordKeySource.parseHeader` (CWE-20, CWE-400, CWE-789) — no finding, see section 6;
  - authentication-attempt throttling for the passphrase path (CWE-307) — **SEC-05**;
  - error-message and timing side channels on the decrypt path (CWE-203, CWE-209) — no finding, see section 6;
  - Java serialization surface of `CryptoException` (CWE-502) — no finding, see section 6.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Vault can silently encrypt production data under a throwaway decoy key | High | CWE-636 | `src/main/java/com/example/crypto/KeyVault.java:385` |
| SEC-02 | PBKDF2 iteration floor (310 000) is below current guidance and is accepted from the container file | Medium | CWE-916 | `src/main/java/com/example/crypto/Limits.java:35` |
| SEC-03 | Key material placed in a non-erasable `String` and left in unwiped buffers on the env/base64 path | Medium | CWE-316 | `src/main/java/com/example/crypto/KeyEncoding.java:70` |
| SEC-04 | Race lets one thread erase a passphrase another thread is actively using | Low | CWE-362 | `src/main/java/com/example/crypto/KeyVault.java:520` |
| SEC-05 | No throttling or lockout for repeated passphrase attempts against a key container | Low | CWE-307 | `src/main/java/com/example/crypto/PasswordKeySource.java:209` |
| SEC-06 | Degenerate key material (all-zero / single repeated byte) is accepted as a valid AES-256 key | Low | CWE-331 | `src/main/java/com/example/crypto/KeyMaterial.java:81` |
| SEC-07 | Decrypted plaintext is never wiped by the `String` convenience overloads | Low | CWE-316 | `src/main/java/com/example/crypto/SymmetricCrypto.java:235` |
| SEC-08 | Active key version read outside the rotation lock, so a concurrent rotate makes encryption fail | Low | CWE-362 | `src/main/java/com/example/crypto/KeyVault.java:257` |

## 5. Detailed Findings

### SEC-01: Vault can silently encrypt production data under a throwaway decoy key
- **Severity:** High
- **CWE:** CWE-636: Not Failing Securely ('Failing Open')
- **Location:** `src/main/java/com/example/crypto/KeyVault.java:385-387` (reached from `KeyVault.java:255-276`)

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyVault.java:385-387
            if (keyVersion > highestIssued.get() || sources.size() >= MAX_VERSIONS) {
                return decoySource(keyVersion);
            }
```
```java
// src/main/java/com/example/crypto/KeyVault.java:255-266
    public EncryptedBlob encrypt(byte[] plaintext, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> {
            int version = highestIssued.get();
            KeySource source = sourceFor(version);
            KeyMaterial key = null;
            try {
                key = source.load();
                if (key.version() != version) {
                    throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                            "key source for version " + version + " reported version " + key.version());
                }
                return crypto.encrypt(key, plaintext, context);
```

**Why it is a problem:** `decoySource` returns a `DecoySource` whose `load()` draws a fresh random 32 bytes,
tags them with the requested version, and keeps nothing (`KeyVault.java:440-448`). That is the right answer on
the *read* path for a version that can never exist — the forged record simply fails the tag. But the second
half of the condition, `sources.size() >= MAX_VERSIONS`, does not test whether the version is impossible; it
tests whether the cache table is full. The active version is only in `sources` if `rotate()` or
`of(KeySource)` put it there, so a vault whose active version has never been provisioned while 64 older
versions are registered takes the decoy branch for `keyVersion == highestIssued`. Concretely:
`new KeyVault(factory, 65)` followed by `addReadableKey(1..64, …)` leaves `sources.size() == 64` with no entry
for version 65; the next `encrypt(...)` call then obtains a decoy, `key.version()` matches (the decoy carries
the requested version, by design, `KeyVault.java:414-416`), and `crypto.encrypt` succeeds. The caller receives
a well-formed `EncryptedBlob`, stores it, and the key that produced it was zeroed inside `load()`'s `finally`
and never existed anywhere else. The record is permanently undecryptable by anyone, including the legitimate
owner, and nothing in the API reports a problem — the same mechanism that is a correct fail-closed answer for
reads becomes a silent fail-open for writes. The impact is irreversible loss of availability (and integrity)
of the protected data, triggered by configuration rather than by an attacker, with no error to alert on.

**Fix:** Use a decoy only for versions that provably cannot name a real key (`keyVersion > highestIssued`), and
on the write path fail closed when the active version cannot be provisioned. The anti-oracle argument in the
original comment still holds for the read path, where the version byte is attacker-chosen; it does not apply to
the active version, which is the deployment's own number.
```java
            if (keyVersion > highestIssued.get()) {
                /*
                 * No legitimate record can name this version, so answer exactly as for a tampered
                 * record: a random key the tag will reject. Nothing is cached and no KDF runs.
                 */
                return decoySource(keyVersion);
            }
            if (sources.size() >= MAX_VERSIONS) {
                if (keyVersion == highestIssued.get()) {
                    /*
                     * This is the key new records would be written under. Encrypting with a decoy here
                     * would produce ciphertext nobody can ever decrypt, and report success while doing
                     * it, so the write must fail instead.
                     */
                    throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                            "the active key version is not provisioned and the version table is full");
                }
                return decoySource(keyVersion);
            }
```

### SEC-02: PBKDF2 iteration floor (310 000) is below current guidance and is accepted from the container file
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/crypto/Limits.java:35`; enforced at `src/main/java/com/example/crypto/PasswordKeySource.java:370-380`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/Limits.java:34-38
    /** Lower bound for PBKDF2. Values below this are rejected rather than honoured. */
    public static final int MIN_KDF_ITERATIONS = 310_000;

    /** Upper bound for PBKDF2: above this a wrong-password attempt becomes a cheap DoS. */
    public static final int MAX_KDF_ITERATIONS = 2_000_000;
```

**Why it is a problem:** `PasswordKeySource` is the component's answer for a *human* passphrase, and its own
class documentation states that the KDF cost is the entire offline-brute-force defence
(`PasswordKeySource.java:59-61`). The default of `600_000` (`PasswordKeySource.java:72`) matches current
guidance for PBKDF2-HMAC-SHA256, but the accepted floor is 310 000 — roughly half the work factor — and the
iteration count is read from the container header and accepted whenever it sits inside the range
(`PasswordKeySource.java:344-346`). A container created with `create(file, v, pw, Limits.MIN_KDF_ITERATIONS)`,
or one written by an older deployment, therefore halves the cost of every offline guess against a passphrase
that is already assumed to be human-scale and dictionary-reachable. The authentication of the header as AAD
correctly stops an attacker *lowering* an existing container's cost, so this is a weak-policy issue rather than
a downgrade channel, but the floor is the value that governs what a deployment can legally ship.

**Fix:** Raise the floor to current guidance for the chosen PRF, and keep the stricter value for newly created
containers so a legacy container can still be read while nothing new is written below the current bar.
```java
    /**
     * Lower bound for PBKDF2-HMAC-SHA256, per current OWASP guidance (600 000). Values below this are
     * rejected rather than honoured. Raise this, never lower it: the only cost of a higher floor is that
     * containers written under an older floor must be re-created with PasswordKeySource.create.
     */
    public static final int MIN_KDF_ITERATIONS = 600_000;

    /** Upper bound for PBKDF2: above this a wrong-password attempt becomes a cheap DoS. */
    public static final int MAX_KDF_ITERATIONS = 2_000_000;
```

### SEC-03: Key material placed in a non-erasable `String` and left in unwiped buffers on the env/base64 path
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/example/crypto/KeyEncoding.java:70` (and `src/main/java/com/example/crypto/EnvKeySource.java:69-79`)

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyEncoding.java:70-73
        String text = new String(in, StandardCharsets.US_ASCII);
        byte[] decoded;
        try {
            decoded = DECODER.decode(text);
```
```java
// src/main/java/com/example/crypto/EnvKeySource.java:69-79
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

**Why it is a problem:** `KeyEncoding`'s own documentation states that there is "deliberately no counterpart
that renders key material as a `String`" because "a `String` cannot be zeroed"
(`KeyEncoding.java:33-36`) — yet the text branch of `decodeKeyBytes` constructs exactly that: a `String`
holding the base64url spelling of the AES key, which is unreachable for wiping and survives in the heap until
garbage collection, where it is recoverable from a core dump, a heap dump, swap or a `/proc/<pid>/mem` read by
the same uid. `EnvKeySource` compounds it: the value arrives from `System.getenv` as a `String` it never owns,
is copied into `raw`, and `raw` is never zeroed on the success path (nor is `decoded` inside `decodeKeyBytes`
after `in.clone()` at `KeyEncoding.java:57`). This is the one deviation from the wiping discipline that
`KeyMaterial`, `PrivateFiles` and `KeyFileKeySource` otherwise apply consistently (compare
`KeyFileKeySource.java:58-63`, which does wipe its buffer), and it defeats `KeyMaterial.destroy()` for every
deployment that uses base64 text or an environment variable as its key source.

**Fix:** Decode base64url from the byte buffer without ever creating a `String`, and wipe every intermediate
buffer. `java.util.Base64.Decoder.decode(byte[])` accepts bytes directly, and the canonical re-encode check can
be done byte-for-byte.
```java
    public static byte[] decodeKeyBytes(byte[] raw) throws CryptoException {
        byte[] in = Limits.requirePayload(raw, MAX_INPUT_BYTES, "key material");
        if (in.length == KeyMaterial.KEY_BYTES) {
            return in.clone();
        }
        if (in.length == 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY, "key material is empty");
        }
        for (byte b : in) {
            int v = b & 0xFF;
            if (v <= 0x20 || v > 0x7E) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material is neither " + KeyMaterial.KEY_BYTES
                                + " raw bytes nor printable base64url text");
            }
        }
        /* No String: a String of the encoded key cannot be zeroed and outlives the operation. */
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
            if (decoded.length != KeyMaterial.KEY_BYTES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material decodes to " + decoded.length + " bytes, expected "
                                + KeyMaterial.KEY_BYTES);
            }
            return decoded.clone();
        } finally {
            java.util.Arrays.fill(reencoded, (byte) 0);
            java.util.Arrays.fill(decoded, (byte) 0);
        }
    }
```
and in `EnvKeySource.load()`, wipe the copy and document that the `String` from `System.getenv` cannot be
erased (prefer a file- or KMS-backed source where that matters):
```java
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        try {
            if (raw.length > MAX_VALUE_BYTES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                        "environment variable " + variable + " is larger than " + MAX_VALUE_BYTES + " bytes");
            }
            byte[] decoded = KeyEncoding.decodeKeyBytes(raw);
            try {
                return KeyMaterial.fromBytes(decoded);
            } finally {
                java.util.Arrays.fill(decoded, (byte) 0);
            }
        } catch (CryptoException e) {
            throw new CryptoException(e.code(), variable + ": " + valueShape(raw), e);
        } finally {
            /* Residual risk: the String returned by System.getenv is not erasable. */
            java.util.Arrays.fill(raw, (byte) 0);
        }
```

### SEC-04: Race lets one thread erase a passphrase another thread is actively using
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/crypto/KeyVault.java:520-525` (callers at `KeyVault.java:198-199` and `KeyVault.java:160-161`); the unsynchronised reader is `src/main/java/com/example/crypto/PasswordKeySource.java:209-216`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyVault.java:520-525
    private void releaseIfUnreferenced(KeySource prior) {
        if (prior == null || sources.containsValue(prior)) {
            return;
        }
        release(prior);
    }
```
```java
// src/main/java/com/example/crypto/PasswordKeySource.java:209-216
    public KeyMaterial load() throws CryptoException {
        if (destroyed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, "key source is closed");
        }
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, FILE_BYTES + 64);
        try {
            Header h = parseHeader(raw);
            byte[] kekBytes = derive(passphrase, h.salt(), h.iterations());
```

**Why it is a problem:** `sourceFor` returns the cached `KeySource` while holding `rotationLock`, but the
subsequent `source.load()` in `encrypt`/`decryptWith` runs *outside* the lock — deliberately, since a PBKDF2
derivation takes about a second. If another thread calls `addReadableKey` (or `rotate`, or `close`) for that
version in that window, `releaseIfUnreferenced` → `release` calls `PasswordKeySource.destroy()` /
`KeystoreKeySource.destroy()`, which zeroes the `char[]` passphrase the first thread is in the middle of
feeding to `PBEKeySpec`. `destroy()` is `synchronized` but `load()` is not, and the `destroyed` flag is read
once at entry (`PasswordKeySource.java:210`, `KeystoreKeySource.java:198`), so there is no mutual exclusion
between the two. The in-flight operation then derives a key from a partially zeroed passphrase and fails at
the unwrap tag, surfacing as `AUTHENTICATION_FAILED` — the same code as "wrong passphrase" — so the symptom is
an unexplained decryption failure on good data rather than a leak. Impact is a transient denial of service
plus a misleading audit trail; there is no confidentiality loss, which is why this is Low.

**Fix:** Make the secret's lifetime cover its use. Guard `load()` with the same monitor `destroy()` takes so a
release cannot interleave with a derivation, and defer release until in-flight users are done (a reference
count, or simply holding the monitor).
```java
    @Override
    public synchronized KeyMaterial load() throws CryptoException {
        /*
         * synchronized, like destroy(): without it a concurrent release() zeroes the passphrase
         * mid-derivation and a good key reports AUTHENTICATION_FAILED, which reads as a wrong passphrase.
         */
        if (destroyed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, "key source is closed");
        }
        byte[] raw = PrivateFiles.readOwnerOnlyFile(file, FILE_BYTES + 64);
        /* ... unchanged ... */
    }
```

### SEC-05: No throttling or lockout for repeated passphrase attempts against a key container
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/crypto/PasswordKeySource.java:209-251` (and `src/main/java/com/example/crypto/KeystoreKeySource.java:197-266`)

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PasswordKeySource.java:226-229
                } catch (AEADBadTagException e) {
                    /* The one expected failure: wrong passphrase, or any edit to the container. */
                    throw new CryptoException(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED,
                            "the passphrase does not match this key file", e);
```

**Why it is a problem:** Each `load()` is an unmetered passphrase verification oracle: construct a
`PasswordKeySource` with a guess, call `load()`, and `AUTHENTICATION_FAILED` versus success tells you whether
the guess was right. The component counts nothing and remembers nothing across attempts, so an application
that exposes this path to a caller (an unlock endpoint, an admin console, a queue consumer that takes the
passphrase from a request) inherits an unlimited online guessing surface. The class documents this and
delegates it to the caller (`PasswordKeySource.java:59-61`), and PBKDF2 at 600 000 iterations caps the rate at
roughly one guess per second per core, which is why this is Low rather than higher — but the cost is paid by
the server, so repeated attempts are simultaneously a CPU-exhaustion vector. `KeystoreKeySource` is in the same
position with a far cheaper KDF (~20 ms per guess, by its own measurement at `KeystoreKeySource.java:28-30`).

**Fix:** Keep the policy decision in the caller, but give the component a usable primitive instead of only a
warning: count consecutive failures per container and apply an increasing delay, while never locking the
container out permanently (a permanent lockout on a shared key file is itself a denial of service, and the
brief requires limits that cannot be used to lock a legitimate user out).
```java
    /** Consecutive failed unwraps for this source, and when the next attempt is permitted. */
    private int consecutiveFailures;
    private long nextAttemptMillis;

    private synchronized void beforeAttempt() throws CryptoException {
        if (System.currentTimeMillis() < nextAttemptMillis) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "too many failed unwrap attempts for this container; backing off");
        }
    }

    private synchronized void afterAttempt(boolean ok) {
        if (ok) {
            consecutiveFailures = 0;
            nextAttemptMillis = 0L;
            return;
        }
        consecutiveFailures = Math.min(consecutiveFailures + 1, 16);
        /* Exponential back-off capped at 30 s: slows guessing without locking the key out for good. */
        long delay = Math.min(30_000L, 250L * (1L << Math.min(consecutiveFailures, 7)));
        nextAttemptMillis = System.currentTimeMillis() + delay;
    }
```
with `beforeAttempt()` called at the top of `load()` and `afterAttempt(...)` on both exits. Keep documenting
that per-source and per-principal limits still belong to the caller, which alone knows who is asking.

### SEC-06: Degenerate key material (all-zero / single repeated byte) is accepted as a valid AES-256 key
- **Severity:** Low
- **CWE:** CWE-331: Insufficient Entropy
- **Location:** `src/main/java/com/example/crypto/KeyMaterial.java:81-87`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyMaterial.java:81-87
        if (rawKey.length != KEY_BYTES) {
            /* Security: only AES-256. A shorter key is a downgrade, not a configuration option. */
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "expected a " + KEY_BYTES + "-byte key, got " + rawKey.length);
        }
        this.key = rawKey.clone();
```

**Why it is a problem:** Length is the only property checked. Any 32 bytes become a key, so a misconfigured
`EnvKeySource` whose variable holds `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, a key file of 32 NULs left by a
truncated write or a half-finished template, or a placeholder committed to a config repository, all load
successfully and are used to protect real data. The component's documentation states that the key touching
application data is "uniformly random rather than whatever the passphrase happened to hash to"
(`PasswordKeySource.java:33-34`), which holds for keys this library generates but not for imported ones — and
imports are the main path (`KeyMaterial.fromBytes` is public and is what all three file/env sources call). A
key an attacker can guess from a finite set of obvious placeholders removes the entire confidentiality
guarantee for every record written under it. Entropy cannot be measured from 32 bytes in general, so this is
Low: the realistic win is refusing the specific degenerate patterns that indicate a configuration accident.

**Fix:** Reject the patterns that are never a real key — all bytes equal (covers all-zero and all-`A`) — at the
single boundary every source passes through.
```java
    KeyMaterial(byte[] rawKey, int version) throws CryptoException {
        this.version = version;
        if (rawKey == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY, "key material is missing");
        }
        if (rawKey.length != KEY_BYTES) {
            /* Security: only AES-256. A shorter key is a downgrade, not a configuration option. */
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "expected a " + KEY_BYTES + "-byte key, got " + rawKey.length);
        }
        /*
         * A constant key is never the product of a CSPRNG; it is a truncated write, a template, or a
         * placeholder that reached production. Refuse it here, where every source passes through, rather
         * than protect real data with a guessable key. This is not an entropy test - 32 bytes cannot be
         * tested for entropy - it is a configuration-accident check.
         */
        boolean constant = true;
        for (byte b : rawKey) {
            if (b != rawKey[0]) {
                constant = false;
                break;
            }
        }
        if (constant) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is a single repeated byte, which is never a generated key");
        }
        this.key = rawKey.clone();
    }
```

### SEC-07: Decrypted plaintext is never wiped by the `String` convenience overloads
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/example/crypto/SymmetricCrypto.java:235-242` and `src/main/java/com/example/crypto/SymmetricCrypto.java:146-156`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SymmetricCrypto.java:234-242
    /** Convenience overload returning strict UTF-8 text. */
    public String decryptToString(KeyMaterial key, EncryptedBlob blob, String context) throws CryptoException {
        return guard(() -> decodeUtf8(decrypt(key, blob, context)));
    }

    /** Convenience overload returning strict UTF-8 text. */
    public String decryptToString(KeyMaterial key, String encodedBlob, String context) throws CryptoException {
        return guard(() -> decodeUtf8(decrypt(key, EncryptedBlob.fromEncoded(encodedBlob), context)));
    }
```

**Why it is a problem:** The payload these methods return is, by the component's own example, data such as a
card number (`SymmetricCrypto.java:36`). The intermediate `byte[]` produced by `decrypt` is handed to
`decodeUtf8` and then dropped unreferenced, never zeroed, so each decryption leaves one copy of the cleartext
in the heap for the collector to deal with — alongside the returned `String`, which cannot be erased at all.
The same applies in reverse at `SymmetricCrypto.java:154`, where `utf8(plaintext)` allocates a buffer that is
never wiped, and at `KeyVault.java:317` / `KeyVault.java:322`. This is a weaker exposure than SEC-03 (plaintext
rather than a key, and the `String` is inherent to the API's signature), but the array is wipeable and is not
wiped, which is inconsistent with the care taken over `nonce`, `body` and `working` elsewhere in the same file.

**Fix:** Wipe the intermediate buffer, and document that the returned `String` is not erasable so callers
handling long-lived secrets use the `byte[]` form.
```java
    /**
     * Convenience overload returning strict UTF-8 text. The returned String cannot be erased; for a
     * secret that must not linger in the heap, use the byte[] overload and wipe it yourself.
     */
    public String decryptToString(KeyMaterial key, EncryptedBlob blob, String context) throws CryptoException {
        return guard(() -> {
            byte[] plain = decrypt(key, blob, context);
            try {
                return decodeUtf8(plain);
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        });
    }
```

### SEC-08: Active key version read outside the rotation lock, so a concurrent rotate makes encryption fail
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/crypto/KeyVault.java:256-258`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyVault.java:256-258
        return SymmetricCrypto.guard(() -> {
            int version = highestIssued.get();
            KeySource source = sourceFor(version);
```

**Why it is a problem:** `encrypt` samples `highestIssued` without the lock, then `sourceFor` takes the lock and
re-reads vault state. If `rotate()` commits in between, it has already executed
`disabled.put(previous, Boolean.TRUE)` (`KeyVault.java:162`), so `sourceFor` finds the sampled version in the
`disabled` table and throws `KEY_UNAVAILABLE` (`KeyVault.java:360-362`). The encryption fails even though both
the old and the new key were usable at every instant — the two reads straddle the rotation and describe a vault
state that never existed. `KeyVault.toString()` already takes the lock for exactly this reason
(`KeyVault.java:550-563`), so the pattern is understood elsewhere in the class. Impact is a spurious failure on
the write path during routine rotation; a caller that treats `KEY_UNAVAILABLE` as fatal drops the record.

**Fix:** Select the version and its source as one atomic decision under the rotation lock.
```java
    /** The active version and its source, chosen as one decision so a rotate cannot split them. */
    private record ActiveKey(int version, KeySource source) {
    }

    private ActiveKey activeKey() throws CryptoException {
        synchronized (rotationLock) {
            int version = highestIssued.get();
            return new ActiveKey(version, sourceFor(version));
        }
    }

    public EncryptedBlob encrypt(byte[] plaintext, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> {
            ActiveKey active = activeKey();
            int version = active.version();
            KeySource source = active.source();
            /* ... unchanged from here ... */
        });
    }
```

## 6. Verified Controls and Checks With No Finding

- **Cipher, mode and tag length:** `AES/GCM/NoPadding` with a 128-bit tag is hardcoded; there is no
  constructor, setter, config value or record field that can select a transformation, key length, tag length or
  padding scheme (`SymmetricCrypto.java:46`, `SymmetricCrypto.java:267-280`, `Limits.java:26`). No ECB, CBC,
  DES/3DES, RC4, MD5 or SHA-1 anywhere in `src/main`.
- **Key size:** AES-256 only; 32 bytes enforced at the single import boundary (`KeyMaterial.java:81-85`), and
  the class initialiser refuses to load on a JVM that cannot do AES-256 rather than silently weakening
  (`SymmetricCrypto.java:364-381`).
- **Nonce management:** a fresh 12-byte nonce per record from `SecureRandom`
  (`SymmetricCrypto.java:121-122`), stored in the clear in the header and bound by the tag. The
  birthday-bound consequence of random nonces (~2^32 records per key) is documented with rotation named as the
  control (`SymmetricCrypto.java:23-28`), which is the correct trade for a stateless component — no finding,
  but the rotation obligation is real and `KeyVault.rotate()` must actually be used.
- **Randomness:** every security-relevant random value comes from `java.security.SecureRandom` —
  record nonces (`SymmetricCrypto.java:56`), data keys and salts (`PasswordKeySource.java:146-149`), key-store
  keys (`KeystoreKeySource.java:161`), generated passwords (`RandomPasswords.java:60`), decoy keys
  (`KeyVault.java:429`). No `java.util.Random`, no `ThreadLocalRandom`, no clock seeding, no caller-supplied
  seed, and the `SecureRandom`-accepting constructor rejects `null` instead of falling back
  (`SymmetricCrypto.java:65-71`).
- **Hardcoded secrets:** none. No key, password, passphrase, salt or token literal exists in `src/main`; every
  secret arrives as a `char[]` or `byte[]` parameter, a file or an environment variable. The sample passphrases
  in `src/test` (`Fixtures.java:101-111`, `KeySourceTest.java:295`) are test fixtures for locally created
  temporary containers and are not credentials for anything that ships.
- **AAD / record binding:** format version, context flag, key version and the context string are all
  authenticated (`SymmetricCrypto.java:289-300`). Re-stamping the key-version byte, clearing the context flag,
  stripping the context field or changing the format version all fail the tag; the parsers additionally reject
  the malformed shapes up front (`EncryptedBlob.java:188-215`, `EncryptedBlob.java:174-183`). The context is
  mapped injectively before use, so one context cannot be spelled as another
  (`SymmetricCrypto.java:310-324`).
- **Uniform decrypt failure:** wrong key, wrong context, absent context, edited header and flipped ciphertext
  byte all take the same code path and produce `AUTHENTICATION_FAILED` with an identical user-facing message;
  there is no early return that would make one case cheaper than another, and no partial plaintext is ever
  returned (`SymmetricCrypto.java:186-222`). The vault never tries other keys on failure, so decrypt is not a
  key-confirmation oracle (`KeyVault.java:326-351`).
- **Untrusted-input parsing and resource bounds:** `EncryptedBlob.fromEncoded` checks null/empty, total length,
  leading/trailing whitespace, prefix, field shape, context charset, strict base64url alphabet and canonical
  re-encoding *before* the structural checks, and bounds the length before any copy is allocated
  (`EncryptedBlob.java:115-185`, `EncryptedBlob.java:197-201`). `peekKeyVersion` decodes only the four
  characters covering the header (`EncryptedBlob.java:234-268`). `PasswordKeySource.parseHeader` validates
  magic, KDF id, salt length, iteration range and wrapped length, and rejects trailing data, all before the KDF
  runs (`PasswordKeySource.java:327-368`) — so a hostile `iterations` value cannot become a DoS.
  `Limits` caps plaintext, ciphertext, encoded strings, context length and KDF cost (`Limits.java:11-57`).
- **Attacker-chosen key version treated as routing, not authorisation:** documented and implemented as such;
  the version only narrows which key is attempted and the tag settles whether it was the right one
  (`EncryptedBlob.java:217-232`, `KeyVault.java:326-333`).
- **File privacy:** secrets are written through `FileChannel.open` with `CREATE_NEW` plus `0600` in the
  creation attributes, so the file never exists in a readable state and an existing file is never overwritten
  (`PrivateFiles.java:94-119`, `PrivateFiles.java:307-327`); `KeyStore.store` is given such a stream rather
  than being allowed to create a `0644` file (`KeystoreKeySource.java:166-170`). Reads require a regular,
  non-symlink, owner-only, owner-matching file with a private ancestry, re-checked on every load
  (`PrivateFiles.java:215-245`, `KeystoreKeySource.java:201`, `PasswordKeySource.java:213`).
- **TOCTOU on key-file reads:** the check-then-read window is closed for the only case where another user can
  swap the directory entry: `requireSecureDirectory` refuses any ancestor writable by others without the sticky
  bit, and when the parent *is* shared-but-sticky the read is re-validated afterwards against the parent's
  mode and the file's `(st_dev, st_ino)`, mode and owner, discarding the bytes if anything moved
  (`PrivateFiles.java:127-176`, `PrivateFiles.java:254-296`). Refusal when POSIX attributes are unavailable is
  fail-closed (`PrivateFiles.java:359-388`). Note that the ancestry ownership rule is strict enough to reject
  otherwise legitimate layouts (for example a key under `/home/<user>/…`, since `/home` is normally
  root-owned); that is a fail-closed availability trade-off, documented at `PrivateFiles.java:402-411`, not a
  weakness.
- **Key-material lifetime:** `KeyMaterial` copies on import, hands out a `SecretKey` only inside
  `use(...)` and zeroes its working copy in a `finally`, and `destroy()`/`close()` erase the master copy
  (`KeyMaterial.java:95-107`, `KeyMaterial.java:150-163`). `KeyVault` holds sources rather than keys and
  destroys the loaded key before each call returns (`KeyVault.java:267-274`, `KeyVault.java:343-350`). The
  un-erasable JDK-internal copy inside `SecretKeySpec` and `SecretKeyFactory` is disclosed rather than glossed
  over (`KeyMaterial.java:20-25`, `PasswordKeySource.java:269-286`) — accurate, and outside this code's reach.
- **Password handling:** `char[]` only, with no `String` overload anywhere; copied on construction, erased by
  `destroy()` (`KeystoreKeySource.java:275-279`, `PasswordKeySource.java:260-263`). Validation rejects
  short, over-long, trailing-NUL and unpaired-surrogate passphrases because the JCE silently normalises those
  into collisions (`KeystoreKeySource.java:299-326`). `RandomPasswords` exists so no one hand-composes one,
  and returns an erasable `char[]` with the quoting obligation documented (`RandomPasswords.java:39-97`).
- **Key wrapping instead of direct passphrase-derived keys:** the PBKDF2 output is a KEK whose only job is to
  wrap a random data key, so the key protecting application data is uniformly random and the wrap tag proves
  the passphrase (`PasswordKeySource.java:28-34`, `PasswordKeySource.java:151-167`). KDF parameters are
  authenticated as AAD, so a container cannot be edited to lower its own cost
  (`PasswordKeySource.java:153`, `PasswordKeySource.java:218`).
- **Error handling and information disclosure:** `getMessage()` returns a fixed generic string per failure
  category, the technical detail is `transient` and never reachable from `getMessage()`/`toString()`, stack
  traces are disabled, `printStackTrace` is overridden, and `getCause()` returns a message-stripped stand-in so
  that generic logging cannot surface a provider message (`CryptoException.java:29-156`). No `describe()` or
  `toString()` returns a key, password, plaintext or file content — they return the source identity only
  (`EnvKeySource.java:96-99`, `KeyFileKeySource.java:66-70`, `KeystoreKeySource.java:328-332`,
  `PasswordKeySource.java:394-398`, `KeyMaterial.java:180-184`, `EncryptedBlob.java:322-330`,
  `KeyVault.java:550-564`). Absolute paths do appear in technical details and `describe()`, which is a
  deliberate log-only trade; `EnvKeySource.valueShape` reports a rejected value's length and printability
  (`EnvKeySource.java:83-93`), a very small leak on the failure path only.
- **Log injection:** every externally supplied string that can reach a message is restricted to printable
  US-ASCII with no control characters, newlines or bidi overrides before use (`Limits.java:65-79`), and
  environment-variable names and key-store aliases are whitelisted by regex (`EnvKeySource.java:32`,
  `KeystoreKeySource.java:63`).
- **Fail-closed behaviour:** no default, fallback, zero or constant-derived key exists on any path; a missing
  environment variable, an unreadable file, an unprovisionable version, a destroyed `KeyMaterial`, a closed
  source and a closed vault all throw (`KeySource.java:12-15`, `EnvKeySource.java:61-68`,
  `KeyVault.java:493-498`, `KeyMaterial.java:97-100`). Decrypting disabled versions is refused rather than
  retried with another key (`KeyVault.java:360-362`).
- **Rotation integrity:** version numbers strictly increase, are never reused after `disable`, and are capped
  at 255 and at `MAX_VERSIONS` tracked sources, under the rotation lock (`KeyVault.java:141-166`,
  `KeyVault.java:176-202`). `releaseIfUnreferenced` correctly avoids destroying a source still registered under
  another version (`KeyVault.java:509-525`) — see SEC-04 for the in-flight case it does not cover.
- **Injection and deserialization classes with no applicable surface:** there is no SQL, no shell or process
  execution, no reflection on caller input, no XML/YAML/JSON parsing, no `ObjectInputStream`, no network I/O or
  TLS configuration, and no HTTP/cookie/session handling anywhere in the component — so CWE-89, CWE-78, CWE-79,
  CWE-611, CWE-918 and the cookie/TLS items of the brief have no reachable instance. `CryptoException` is the
  only `Serializable` type; it carries just an enum and keeps the technical detail `transient`
  (`CryptoException.java:65-73`), so there is no deserialization gadget surface (CWE-502).
- **Path handling:** paths are bounded at 4096 characters and rejected if they contain a NUL
  (`KeyFileKeySource.java:42-48`, `KeystoreKeySource.java:91-94`, `PasswordKeySource.java:97-100`), and no path
  is ever assembled from caller-supplied name fragments, so there is no traversal primitive (CWE-22).
- **Build configuration:** `pom.xml` declares only `junit-jupiter` (test scope) and the compiler/surefire/jar
  plugins — no third-party cryptographic or serialization dependency, so there is no transitive supply-chain
  surface to triage for this component.
