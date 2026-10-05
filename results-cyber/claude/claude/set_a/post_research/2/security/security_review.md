# Security Review: data-crypto (com.example.crypto AES-256-GCM data encryption component)

## 1. Executive Summary

`data-crypto` is a dependency-free Java 17 library that encrypts and decrypts sensitive
application data with AES-256-GCM, plus the key handling needed for both directions:
an in-memory key set with rotation support (`KeySetSecretKeyProvider`), three key
sources (environment variables, a PKCS#12 keystore, a PBKDF2 passphrase), a wipeable
`SecretKey` implementation, and a self-describing ciphertext envelope whose header is
bound into the GCM associated data.

The core cryptography is sound and unusually careful. AES-256/GCM with a full 128-bit
tag and a fresh 96-bit `SecureRandom` nonce per message; the nonce is never caller-
supplied; the envelope header (magic, version, key id) is authenticated so a ciphertext
cannot be re-labelled; decryption treats its input as hostile, bounds length before
allocating, validates the key id against an allow-list, and funnels every failure into
one generic `CryptoException` with a decoy-key decryption so unknown key ids are not an
oracle. There are no hardcoded keys, no ECB, no unauthenticated mode, no MD5/SHA-1, no
`Random`, and key material is wiped on the paths this component owns. **No critical or
high-severity vulnerability was found.**

The findings that remain are in the key-loading and key-lifetime periphery, not in the
cipher itself. The most significant is a time-of-check/time-of-use gap in `SecureFiles`:
the keystore file is validated with `NOFOLLOW_LINKS` and then re-opened by path with a
symlink-following read (SEC-01), and the weakened parent-directory check (only
`OTHERS_WRITE`, only the immediate parent) widens the window in which an attacker could
substitute the keystore (SEC-02). The remainder are hardening issues: the GCM nonce
budget is per-process and silently resets on restart (SEC-03), keystore entries are not
checked to actually be AES keys (SEC-04), JCE-owned intermediate `SecretKey` objects are
never destroyed (SEC-05), the configurable PBKDF2 floor sits below the 600k the
data-at-rest guidance calls for (SEC-06), and absolute key-file paths are placed in
exception messages (SEC-07).

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/crypto/AesGcmDataCipher.java` | AES-256-GCM encrypt/decrypt, envelope format, Base64/text helpers, re-encrypt for rotation | Cipher mode and tag length, nonce generation and per-key budget, AAD binding of the header, parsing of wholly untrusted ciphertext, decoy-key path, uniform error reporting, plaintext/AAD size bounds |
| `src/main/java/com/example/crypto/DataCipher.java` | Interface for the cipher | API shape: no "decrypt without verifying" entry point |
| `src/main/java/com/example/crypto/SecretKeyProvider.java` | Interface for key sources | Documents the key trust boundary; `keyFor` receives attacker-controlled ids and must fail closed |
| `src/main/java/com/example/crypto/KeySetSecretKeyProvider.java` | Immutable in-memory key set with an active key | Key-id validation, bounded key count, fail-closed lookup, `close()` destroys material |
| `src/main/java/com/example/crypto/KeyMaterial.java` | CSPRNG and strict Base64 key parsing | `SecureRandom` usage, length-bounded strict decode, generic rejection messages, wiping of intermediates |
| `src/main/java/com/example/crypto/ZeroizableSecretKey.java` | AES key whose bytes can really be erased | Length and all-zero validation, synchronized destroy, constant-time `equals`, serialization refused, `toString` never renders material |
| `src/main/java/com/example/crypto/KeyId.java` | Key-id allow-list validation | `[A-Za-z0-9._-]{1,64}`; prevents log injection and path/shell metacharacters from the envelope |
| `src/main/java/com/example/crypto/EnvironmentKeySource.java` | Builds the key set from environment variables | Treats environment as untrusted, no default key, bounded key count, wipes its own copies, destroys partial state on failure |
| `src/main/java/com/example/crypto/KeyStoreKeySource.java` | Builds the key set from a PKCS#12 keystore | File permission gate, store MAC verification via password, alias validation, entry length check, password wiped, partial state destroyed |
| `src/main/java/com/example/crypto/PassphraseKeyDerivation.java` | PBKDF2-HMAC-SHA-256 key derivation | Work factor floor/ceiling, salt length bounds, passphrase length bounds, wiping of passphrase and derived bytes |
| `src/main/java/com/example/crypto/SecureFiles.java` | Permission guard rails for key files | Regular-file/symlink check, size bound, owner-only mode check, owner check, parent-directory writability check, file read |
| `src/main/java/com/example/crypto/Bytes.java` | Byte/char helpers for secret material | Wiping, constant-time comparison, strict UTF-8 encoding |
| `src/main/java/com/example/crypto/CryptoLog.java` | Single logging funnel | Masking helper, FINE-level diagnostics, no secrets as arguments |
| `src/main/java/com/example/crypto/CryptoException.java` | Single generic failure type | No cause, no writable stack trace, no distinguishing message |
| `src/test/java/com/example/crypto/AesGcmDataCipherTest.java` | Cipher tests | Tamper/AAD/key-id negative cases |
| `src/test/java/com/example/crypto/KeyHandlingTest.java` | Key handling tests | Key parsing and provider behaviour |
| `pom.xml` | Build descriptor | Pinned plugin/dependency versions, no ranges/snapshots, zero runtime dependencies, JUnit test-scope only |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied its weakness-category table
  (weak hashing, insecure encryption, bad cipher mode, insufficient key size, hardcoded
  secrets, weak KDF, poor entropy) and its key-management/key-storage review points
  against `AesGcmDataCipher`, `KeyMaterial`, `PassphraseKeyDerivation`,
  `ZeroizableSecretKey` and the three key sources. Produced SEC-03, SEC-05 and SEC-06.
- `implementing-aes-encryption-for-data-at-rest`: applied its AES-GCM mode table,
  nonce/IV management rules (96-bit, CSPRNG, never reused, stored with ciphertext), key
  derivation guidance (PBKDF2 minimum 600,000 iterations as of 2024), and its validation
  criteria to `AesGcmDataCipher` and `PassphraseKeyDerivation`. Produced SEC-03 and
  SEC-06.
- `testing-for-sensitive-data-exposure`: applied its secret-leakage, data-masking and
  information-leakage checks to `CryptoLog`, `CryptoException`, `ZeroizableSecretKey.toString`,
  `KeyMaterial`'s rejection paths and every exception message in the component. Produced
  SEC-07; confirmed the masking and generic-error controls listed in section 6.
- `exploiting-insecure-deserialization`: applied its Java `readObject` magic-method
  analysis to `ZeroizableSecretKey`, which is `Serializable` by virtue of extending
  `javax.crypto.SecretKey` and holds raw key bytes in a non-transient field. No finding —
  see section 6.
- `configuring-hsm-for-key-storage`: used as the comparison point for key-at-rest
  storage when reviewing `KeyStoreKeySource` and `EnvironmentKeySource`. Produced SEC-04.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill
  matched these behaviours:
  - Filesystem TOCTOU and permission validation in `SecureFiles` (CWE-367, CWE-732) —
    the library's file-related skills are forensic/offensive (`performing-directory-traversal-testing`,
    `performing-file-carving-with-foremost`) and do not cover secure local file opening.
    Produced SEC-01 and SEC-02.
  - Untrusted binary envelope parsing in `AesGcmDataCipher.decrypt` (CWE-20, CWE-1284,
    CWE-130) — reviewed against general input-validation and memory-allocation-bound
    knowledge; no finding.
  - Concurrency of the check-then-act nonce budget in `AesGcmDataCipher.reserveNonceBudget`
    (CWE-367 race) — reviewed against general knowledge; no finding.
  - Error-oracle / observable-discrepancy behaviour on the decryption path (CWE-203,
    CWE-208) — reviewed against general knowledge; no finding.
  - Build/supply-chain hygiene in `pom.xml` (CWE-1104, CWE-829) — reviewed against
    general knowledge; no finding.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Keystore file re-opened by path after validation (symlink TOCTOU) | Medium | CWE-367 | `src/main/java/com/example/crypto/SecureFiles.java:53-62` |
| SEC-02 | Parent-directory check only rejects world-writable and only the immediate parent | Medium | CWE-732 | `src/main/java/com/example/crypto/SecureFiles.java:100-113` |
| SEC-03 | GCM nonce budget is per-process and silently resets on restart | Medium | CWE-323 | `src/main/java/com/example/crypto/AesGcmDataCipher.java:425-434` |
| SEC-04 | Keystore entries are accepted on length alone and relabelled as AES | Low | CWE-20 | `src/main/java/com/example/crypto/KeyStoreKeySource.java:74-81` |
| SEC-05 | JCE-owned intermediate `SecretKey` objects are never destroyed | Low | CWE-316 | `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:101-103` |
| SEC-06 | Configurable PBKDF2 floor (210k) is below the 600k data-at-rest guidance | Low | CWE-916 | `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:36` |
| SEC-07 | Absolute key-file paths placed in exception messages | Low | CWE-209 | `src/main/java/com/example/crypto/SecureFiles.java:54,58,87,95,111` |

## 5. Detailed Findings

### SEC-01: Keystore file re-opened by path after validation (symlink TOCTOU)

- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/crypto/SecureFiles.java:53-62`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SecureFiles.java:50-62
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
        } catch (IOException e) {
```

**Why it is a problem:** Every check is performed on the *path*, and then the file is
opened again by that same path. `Files.readAllBytes` follows symbolic links (there is no
`NOFOLLOW_LINKS` variant of it), so the `NOFOLLOW_LINKS` guarantee established at line 53
and line 77 does not carry over to the actual read at line 62. The comment claims the
`NOFOLLOW_LINKS` flag protects against a file "swapped between check and read"; it does
not — it only makes the *check* refuse to traverse a link that exists at check time.

Concrete failure: the keystore lives at `/var/lib/app/keys.p12` in a directory the
attacker can write to (a group-writable deployment directory, which SEC-02 lets through,
or any directory the attacker has compromised a same-group account in). The attacker
loops on `rename("evil.p12.link", "/var/lib/app/keys.p12")`. The reviewing process calls
`isRegularFile(NOFOLLOW_LINKS)` and the POSIX mode/owner checks while the real
owner-only file is in place, they pass, and before `readAllBytes` at line 62 runs the
attacker swaps the path to a symlink pointing at their own PKCS#12 file. The process
loads attacker-chosen AES keys, and every record it subsequently encrypts is readable by
the attacker, while records they feed back in decrypt under keys they control. The same
race also defeats the size bound — the substituted target can be arbitrarily large.

**Fix:** Open the file once with `NOFOLLOW_LINKS` and perform every check against the
open handle, so there is no second path resolution. `Files.newByteChannel` accepts
`LinkOption.NOFOLLOW_LINKS` and `Files.readAttributes` on the same descriptor-backed
stream removes the window entirely.

```java
    static byte[] readPrivateFile(Path path) {
        Path file = path.toAbsolutePath().normalize();
        try {
            requireSafeParent(file.getParent());
            // Open once, with NOFOLLOW_LINKS, and validate the opened object.
            // There is no second path resolution, so nothing can be swapped
            // between the checks and the read.
            try (SeekableByteChannel channel = Files.newByteChannel(
                    file, EnumSet.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
                PosixFileAttributes attrs =
                        Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!attrs.isRegularFile()) {
                    throw new IllegalStateException("key file is not a regular file");
                }
                long size = channel.size();
                if (size == 0 || size > MAX_KEY_FILE_BYTES) {
                    throw new IllegalStateException("key file size is out of range");
                }
                requireOwnerOnlyAccess(attrs);
                ByteBuffer buffer = ByteBuffer.allocate((int) size);
                while (buffer.hasRemaining() && channel.read(buffer) >= 0) {
                    // read to completion
                }
                if (buffer.hasRemaining()) {
                    throw new IllegalStateException("key file was truncated while being read");
                }
                return buffer.array();
            }
        } catch (IOException e) {
            CryptoLog.configProblem("unable to read key file: " + file);
            throw new UncheckedIOException("unable to read key file", e);
        }
    }
```

### SEC-02: Parent-directory check only rejects world-writable and only the immediate parent

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/crypto/SecureFiles.java:100-113`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SecureFiles.java:99-113
    /** A world-writable parent directory lets an attacker replace the key file. */
    private static void requireSafeParent(Path parent) throws IOException {
        if (parent == null) {
            return;
        }
        PosixFileAttributeView view = Files.getFileAttributeView(parent, PosixFileAttributeView.class);
        if (view == null) {
            return; // non-POSIX filesystem; the file check above already failed closed
        }
        Set<PosixFilePermission> permissions = view.readAttributes().permissions();
        if (permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
            CryptoLog.configProblem("key file directory is world-writable: " + parent);
            throw new IllegalStateException("key file directory must not be world-writable: " + parent);
        }
    }
```

**Why it is a problem:** On POSIX, the ability to unlink and recreate a file is governed
by write permission on the *containing directory*, not by the file's own mode. The file
itself is correctly required to be `0600` and owner-owned (lines 30-36, 83-96), but the
directory check only rejects `OTHERS_WRITE`. Three gaps follow:

1. `GROUP_WRITE` on the parent is accepted. A directory at mode `0770` owned by group
   `app` lets any member of `app` — a second service account, a CI runner, a compromised
   sidecar — `unlink` the `0600` keystore and drop in their own. The replacement file can
   be created `0600` and owned by the attacker's uid, but it only has to survive the
   window described in SEC-01 to be read; and if the attacker's uid happens to equal the
   reader's (the common "two processes, one service user" case) the owner check passes
   outright.
2. Only the immediate parent is examined. If `/opt/app` is world-writable but
   `/opt/app/conf` is `0755`, an attacker renames `/opt/app/conf` aside and substitutes a
   directory tree of their own; the check on `/opt/app/conf` then inspects the attacker's
   directory and passes.
3. The sticky bit is not considered, so a correctly-configured `/tmp`-style directory
   (`1777`) is rejected while a plain group-writable one is allowed — the check is both
   too strict and too permissive in the wrong directions.

Combined with SEC-01 this is the realistic path to key substitution: SEC-02 supplies the
writable directory, SEC-01 supplies the race.

**Fix:** Walk every ancestor from the root down, reject group-write as well as
others-write unless the sticky bit is set, and require each ancestor to be owned by the
current user or root.

```java
    /** Any writable ancestor directory lets an attacker replace the key file. */
    private static void requireSafeParent(Path parent) throws IOException {
        for (Path dir = parent; dir != null; dir = dir.getParent()) {
            PosixFileAttributeView view =
                    Files.getFileAttributeView(dir, PosixFileAttributeView.class);
            if (view == null) {
                // Cannot verify: fail closed rather than assume the path is safe.
                throw new IllegalStateException("cannot verify key file directory permissions");
            }
            PosixFileAttributes attrs = view.readAttributes();
            Set<PosixFilePermission> perms = attrs.permissions();
            boolean sticky = isSticky(dir); // Files.getAttribute(dir, "unix:mode") & 01000
            if (!sticky && (perms.contains(PosixFilePermission.OTHERS_WRITE)
                    || perms.contains(PosixFilePermission.GROUP_WRITE))) {
                CryptoLog.configProblem("key file directory is writable by others");
                throw new IllegalStateException(
                        "key file directories must not be group- or world-writable");
            }
            String owner = attrs.owner().getName();
            if (!owner.equals(System.getProperty("user.name", "")) && !owner.equals("root")) {
                CryptoLog.configProblem("key file directory is owned by another user");
                throw new IllegalStateException(
                        "key file directories must be owned by the current user or root");
            }
        }
    }
```

### SEC-03: GCM nonce budget is per-process and silently resets on restart

- **Severity:** Medium
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/example/crypto/AesGcmDataCipher.java:425-434` (counter), `:104` (state), `:34-38` (claim)

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/AesGcmDataCipher.java:104
    private final Map<String, AtomicLong> encryptionCounters = new ConcurrentHashMap<>();
```

```java
// src/main/java/com/example/crypto/AesGcmDataCipher.java:425-434
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

**Why it is a problem:** The counter is instance state in a `ConcurrentHashMap`, so it is
scoped to one `AesGcmDataCipher` object in one JVM. The class javadoc at lines 34-38
states the ceiling "keep[s] the probability of a random 96-bit nonce collision
negligible" — but the quantity that governs that probability is the total number of
messages ever encrypted under a given *key*, not the number encrypted by one object.
Every process restart, every redeploy, and every additional `AesGcmDataCipher` instance
(two instances over the same `SecretKeyProvider` is a perfectly legal construction)
starts the count at zero while the long-lived key from the environment or keystore stays
the same.

Concrete failure: a service holds key id `v2` in `APP_DATA_KEY_MATERIAL_v2` for a year
across rolling deploys, with 40 pods each restarted several times a day. Each pod-life
encrypts well under 2^32 messages, so the guard never fires once, yet the cumulative
count under `v2` passes 2^40. At 2^40 random 96-bit nonces the birthday probability of a
repeat is roughly 2^80/2^96 ≈ 2^-16 — a one-in-65,000 chance, per key, that two
ciphertexts share a nonce. A GCM nonce repeat under one key leaks the XOR of the two
plaintexts and, worse, allows recovery of the GHASH authentication subkey, which lets an
attacker forge arbitrary valid ciphertexts under that key for the lifetime of the key.
The guard as written gives the reviewer confidence it has prevented this when it has not.

**Fix:** Either enforce the budget against durable state, or stop claiming a bound the
code cannot hold and base the ceiling on something the process actually owns. The
cheapest correct change is to make the counter per *key instance* and expose the
remaining budget so the deployment can persist and reload it; the strongest is to derive
a per-message key, removing the single-key message limit altogether.

```java
    /**
     * Atomically claims one nonce from this key's budget.
     *
     * <p>IMPORTANT: this counter is per {@code AesGcmDataCipher} instance and is
     * lost on restart, so it cannot by itself bound the lifetime message count
     * of a long-lived key. The durable bound is supplied by the key source: it
     * must provide the number of messages already encrypted under this key id
     * and persist the updated value, so that redeploys do not reset the budget.
     */
    private void reserveNonceBudget(String keyId) throws CryptoException {
        AtomicLong counter = encryptionCounters.computeIfAbsent(
                keyId, id -> new AtomicLong(keyProvider.messagesAlreadyEncrypted(id)));
        long used = counter.incrementAndGet();
        if (used > MAX_ENCRYPTIONS_PER_KEY) {
            counter.decrementAndGet(); // keep the counter from running away
            CryptoLog.configProblem("encryption limit reached for key id " + keyId
                    + "; rotate the key");
            throw new CryptoException("unable to encrypt data");
        }
        keyProvider.recordEncryption(keyId, used);
    }
```

### SEC-04: Keystore entries are accepted on length alone and relabelled as AES

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/main/java/com/example/crypto/KeyStoreKeySource.java:74-81`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/KeyStoreKeySource.java:74-84
                SecretKey entry = (SecretKey) store.getKey(alias, storePassword);
                byte[] raw = entry == null ? null : entry.getEncoded();
                try {
                    if (raw == null || raw.length != ZeroizableSecretKey.KEY_LENGTH_BYTES) {
                        throw new IllegalStateException(
                                "keystore entry is not a 256-bit AES key: " + alias);
                    }
                    keys.put(alias, new ZeroizableSecretKey(raw));
                } finally {
                    Bytes.wipe(raw);
                }
```

**Why it is a problem:** The check is on encoded length only; `entry.getAlgorithm()` is
never consulted. `ZeroizableSecretKey.getAlgorithm()` unconditionally returns `"AES"`
(line 56), so any 32-byte `SecretKeyEntry` in the store — an HMAC-SHA256 key, a ChaCha20
key, a wrapped KEK, a 32-byte password blob stored with `keytool -importpassword` — is
silently promoted to an AES-256 data-encryption key. The defence-in-depth check in
`AesGcmDataCipher.isUsable` (line 447) that verifies `"AES".equalsIgnoreCase(key.getAlgorithm())`
is therefore guaranteed to pass and provides nothing here. The error message at line 79
claims a check that was not performed.

Concrete failure: an operator's `keys.p12` holds both `v2` (the AES data key) and
`hmac-v2`, a 32-byte HMAC key used for signing elsewhere. Both are loaded as valid AES
data keys. Because the alias is bound into the GCM AAD, data genuinely encrypted under
`hmac-v2` decrypts correctly, so the mistake is invisible — but the HMAC key is now a
data-encryption key, and the key-separation property the operator relied on (an HMAC key
that can be rotated independently, or exported to a verifier) is gone. Anyone holding the
HMAC key for verification purposes can now decrypt application data.

**Fix:** Require the algorithm to be AES before accepting the entry, and keep the error
message consistent with the checks actually performed.

```java
                SecretKey entry = (SecretKey) store.getKey(alias, storePassword);
                byte[] raw = entry == null ? null : entry.getEncoded();
                try {
                    if (entry == null || !"AES".equalsIgnoreCase(entry.getAlgorithm())) {
                        throw new IllegalStateException(
                                "keystore entry is not an AES key: " + alias);
                    }
                    if (raw == null || raw.length != ZeroizableSecretKey.KEY_LENGTH_BYTES) {
                        throw new IllegalStateException(
                                "keystore entry is not a 256-bit AES key: " + alias);
                    }
                    keys.put(alias, new ZeroizableSecretKey(raw));
                } finally {
                    Bytes.wipe(raw);
                }
```

### SEC-05: JCE-owned intermediate `SecretKey` objects are never destroyed

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:101-103`; same pattern at `src/main/java/com/example/crypto/KeyStoreKeySource.java:74`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PassphraseKeyDerivation.java:99-104
            spec = new PBEKeySpec(passphrase, salt, iterations,
                    ZeroizableSecretKey.KEY_LENGTH_BYTES * 8);
            derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
            return new ZeroizableSecretKey(derived);
```

**Why it is a problem:** `generateSecret(spec)` returns a `javax.crypto.spec.PBEKey`
(`com.sun.crypto.provider.PBKDF2KeyImpl`) that holds its own copy of the derived 32-byte
key *and* a copy of the passphrase. The code calls `.getEncoded()` on it and discards the
object without a reference, so that copy is never destroyed — only the `derived` array
the component owns is wiped at line 113. `PBKDF2KeyImpl` implements `Destroyable` and its
`destroy()` genuinely zeroes its internal arrays, so the clean-up is available and simply
not performed. The whole point of this class's careful `clearPassword()` / `Bytes.wipe`
discipline (lines 109-115) is defeated by the one copy it does not hold.

Concrete failure: the service derives its data key from an operator passphrase at
start-up, then runs for weeks. A heap dump — taken by an ops engineer debugging a leak, by
an OOM `-XX:+HeapDumpOnOutOfMemoryError` handler writing to a world-readable temp path,
or by an attacker with `ptrace`/`jmap` rights on the host — contains the orphaned
`PBKDF2KeyImpl` with both the AES-256 data key and the operator passphrase in cleartext,
long after the component believes both were erased. The same applies to the `SecretKey entry`
read from the keystore in `KeyStoreKeySource.java:74`, once per configured alias.

**Fix:** Keep a reference to the provider-returned key and destroy it in the `finally`
block, alongside the existing wipes.

```java
        PBEKeySpec spec = null;
        javax.crypto.SecretKey providerKey = null;
        byte[] derived = null;
        try {
            // ... validation unchanged ...
            spec = new PBEKeySpec(passphrase, salt, iterations,
                    ZeroizableSecretKey.KEY_LENGTH_BYTES * 8);
            providerKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec);
            derived = providerKey.getEncoded();
            return new ZeroizableSecretKey(derived);
        } catch (GeneralSecurityException e) {
            CryptoLog.configProblem("PBKDF2WithHmacSHA256 is unavailable in this JRE");
            throw new IllegalStateException("key derivation is unavailable");
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
            destroyQuietly(providerKey); // PBKDF2KeyImpl holds the key AND the passphrase
            Bytes.wipe(derived);
            Bytes.wipe(passphrase);
        }
```

### SEC-06: Configurable PBKDF2 floor (210k) is below the 600k data-at-rest guidance

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:36`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/PassphraseKeyDerivation.java:35-39
    /** OWASP-recommended floor for PBKDF2-HMAC-SHA-256. */
    public static final int MIN_ITERATIONS = 210_000;

    /** Default work factor; raise it as hardware improves. */
    public static final int DEFAULT_ITERATIONS = 600_000;
```

**Why it is a problem:** The default of 600,000 is correct and matches the data-at-rest
guidance applied in this review. But `deriveKey(passphrase, salt, iterations)` is public
and accepts anything at or above `MIN_ITERATIONS`, so a caller — or a value plumbed
through from a configuration file, which rule 1 of the component's own design notes says
must be treated as attacker-influenced — can lower the work factor to 210,000 with no
warning logged. 210k is the OWASP *absolute minimum* for interactive password
verification, not the figure for a long-lived key that protects data at rest; the
data-at-rest standard calls for 600,000 as of 2024. The comment labelling 210k as "the"
recommended floor overstates it.

Concrete failure: a deployment sets `kdf.iterations=210000` to shave start-up time on a
small instance. An attacker who obtains the salt and a single ciphertext (the salt is not
secret and is typically stored beside the data) can run offline PBKDF2 guessing at
roughly 2.9x the rate the 600,000 default would allow — a direct 2.9x reduction in the
cost of cracking the operator passphrase, which is the sole protection for every record
the component has ever encrypted.

**Fix:** Raise the enforced floor to the data-at-rest figure, and keep a separate,
explicitly-named constant if a lower interactive floor is ever genuinely needed.

```java
    /**
     * Enforced floor for key-at-rest derivation: the 2024 guidance for
     * PBKDF2-HMAC-SHA-256 protecting data at rest, not the lower figure used
     * for interactive password verification. A caller cannot go below this.
     */
    public static final int MIN_ITERATIONS = 600_000;

    /** Default work factor; raise it as hardware improves. */
    public static final int DEFAULT_ITERATIONS = 600_000;
```

### SEC-07: Absolute key-file paths placed in exception messages

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/com/example/crypto/SecureFiles.java:54,58,87,95,111`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SecureFiles.java:53-59
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("key file is not a regular file: " + file);
            }
            long size = Files.size(file);
            if (size == 0 || size > MAX_KEY_FILE_BYTES) {
                throw new IllegalStateException("key file size is out of range: " + file);
            }
```

**Why it is a problem:** `file` is the absolute, normalised path to the keystore, and it
is concatenated into five `IllegalStateException` messages that leave the component.
Everywhere else this codebase is scrupulous about this: `CryptoException` carries a fixed
generic string with no cause and no writable stack trace (`CryptoException.java:20-24`),
`KeyId.require` deliberately keeps an attacker-controlled id out of the exception and
logs only its length (`KeyId.java:50-56`), and `KeyStoreKeySource` collapses every load
failure into `"encryption key configuration is incomplete"` (lines 96, 99). `SecureFiles`
is the one place that breaks the pattern, and unlike `CryptoLog.configProblem` — which
also logs the path, but into a log the operator controls — these strings travel to the
caller.

Concrete failure: `KeyStoreKeySource.load` is called during application start-up. The
`IllegalStateException` from line 54 propagates past the `catch (GeneralSecurityException | IOException)`
handler at line 97, which does not catch `IllegalStateException`, so it is never
converted into the generic message. A framework start-up handler or health endpoint
renders it, and the response discloses `/opt/app/secure/keys/prod-keystore-v2.p12` —
telling an attacker exactly which file to target with the race in SEC-01, and confirming
the deployment layout and key-rotation naming.

**Fix:** Log the path through `CryptoLog` (where it already goes) and keep it out of the
exception, matching `KeyId.require` and `CryptoException`.

```java
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                CryptoLog.configProblem("key file is not a regular file: " + file);
                throw new IllegalStateException("key file configuration is invalid");
            }
            long size = Files.size(file);
            if (size == 0 || size > MAX_KEY_FILE_BYTES) {
                CryptoLog.configProblem("key file size is out of range: " + file);
                throw new IllegalStateException("key file configuration is invalid");
            }
```

## 6. Verified Controls and Checks With No Finding

- **Cipher and mode**: `AES/GCM/NoPadding` only, via the JDK's SunJCE provider —
  `AesGcmDataCipher.java:72`. No ECB, no unauthenticated CBC/CTR, no custom
  construction, and no "decrypt without verifying" entry point anywhere in
  `DataCipher.java`. Checked against the mode table in
  `implementing-aes-encryption-for-data-at-rest` and the "bad cipher mode" row of
  `performing-cryptographic-audit-of-application`.
- **Tag length**: full 128-bit GCM tag, never truncated — `AesGcmDataCipher.java:83-84`,
  used on both the encrypt (`:166`) and decrypt (`:243`) paths.
- **Key size**: AES-256 enforced structurally. `ZeroizableSecretKey` rejects anything but
  exactly 32 bytes at construction (`ZeroizableSecretKey.java:39-45`), and
  `AesGcmDataCipher.isUsable` re-checks the length of every key the provider hands back
  (`AesGcmDataCipher.java:446-456`).
- **Nonce generation**: 12-byte (96-bit) nonce from the shared `SecureRandom`, freshly
  generated per encryption, never derived from the plaintext and never accepted from the
  caller — `AesGcmDataCipher.java:80`, `:162`, `KeyMaterial.java:22,28-35`. The nonce is
  stored in the envelope, which is correct (it is not secret). The API exposes no overload
  that would let a caller supply one. Checked against the nonce/IV management rules of
  `implementing-aes-encryption-for-data-at-rest`; see SEC-03 for the separate issue of the
  *total* message count per key.
- **Randomness source**: one shared `java.security.SecureRandom` for all key material,
  nonces and salts — `KeyMaterial.java:22`. No `java.util.Random`, no time-based or
  counter-based seeding, no hand-rolled PRNG anywhere in the tree. Checked against the
  "poor entropy" row of `performing-cryptographic-audit-of-application`.
- **Weak primitives**: no MD5, SHA-1, DES, 3DES, RC4, Blowfish or RSA anywhere in the
  component. The only hash use is `MessageDigest.isEqual` for constant-time comparison
  (`Bytes.java:38`), which is not a hashing use at all.
- **Hardcoded secrets**: none. Grepped the whole tree — no key, password, passphrase,
  token or salt constant exists; `KeyMaterial.java:9-12` and `SecretKeyProvider.java:9-14`
  make the "no embedded default" rule explicit, and every key source fails closed when
  configuration is absent (`EnvironmentKeySource.java:62-66,91-95`,
  `KeyStoreKeySource.java:86-89`). Checked against the "hardcoded secrets" (Critical) row
  of `performing-cryptographic-audit-of-application` and against
  `testing-for-sensitive-data-exposure`'s secret-leakage checks.
- **AAD binding of the envelope header**: magic, format version, key-id length and key id
  are all fed to `updateAAD` before the caller's own AAD, on both sides —
  `AesGcmDataCipher.java:167-168` and `:244-245`. A ciphertext therefore cannot be
  re-labelled as a different key id or format version, and cannot be moved to a different
  record/tenant context, without failing the tag check.
- **Untrusted envelope parsing**: length is bounded *before* any parsing or allocation
  (`AesGcmDataCipher.java:197-201`), magic is compared in constant time (`:205`), unknown
  versions are rejected rather than guessed (`:208-211`), the declared key-id length is
  range-checked (`:213-216`), and the envelope is re-checked against the declared header
  length before any offset arithmetic (`:217-220`). Every allocation derives from an
  already-validated bound. No integer overflow is reachable: `maxEnvelopeBytes()`
  (`:372-374`) sums values capped at 64 MiB. Reviewed against general CWE-20/CWE-130/CWE-1284
  knowledge.
- **Key-id allow-list**: `[A-Za-z0-9._-]{1,64}` enforced by `KeyId.isValid`
  (`KeyId.java:30-45`) on every path — the envelope (`AesGcmDataCipher.java:398-408`), the
  provider lookup (`KeySetSecretKeyProvider.java:80-82`), configuration
  (`EnvironmentKeySource.java:67,77`) and keystore aliases (`KeyStoreKeySource.java:70`).
  This closes log injection (no CR/LF reaches `CryptoLog` at
  `AesGcmDataCipher.java:260`), path traversal (no `/` or `..` can reach a filesystem
  call), and Unicode-normalisation tricks. Specifically checked for traversal against
  general CWE-22 knowledge, since the key id is the only envelope field that is ever
  rendered as text.
- **Error oracle on decryption**: every failure — wrong length, bad magic, unknown
  version, malformed key id, unknown key id, wrong key, forged tag, wrong AAD, invalid
  UTF-8 — returns the identical `CryptoException("unable to decrypt data")` via the single
  `fail()` funnel (`AesGcmDataCipher.java:462-465`). `CryptoException` attaches no cause
  and no writable stack trace (`CryptoException.java:20-24`), so a caller that prints it
  cannot recover which check failed. Reviewed against general CWE-203 knowledge.
- **Timing/behavioural equalisation for unknown key ids**: a lookup miss does not
  short-circuit; it substitutes a per-instance random `decoyKey`
  (`AesGcmDataCipher.java:110`) and performs a full GCM decryption
  (`:233-239`), so the work done and the error raised are indistinguishable from a forged
  ciphertext. The belt-and-braces `if (!knownKey)` check at `:247-253` means that even an
  impossible decoy-key tag match cannot return data. This removes the "which key ids
  exist" oracle. Reviewed against general CWE-208 knowledge.
- **Check-then-act atomicity of the nonce budget**: `reserveNonceBudget`
  (`AesGcmDataCipher.java:425-434`) claims a slot with a single `incrementAndGet`, so two
  threads cannot both observe the last slot. Traced the compensating `decrementAndGet` on
  the rejection path (`:429`) under concurrent interleavings: it can never let the
  cumulative number of successful encryptions exceed `MAX_ENCRYPTIONS_PER_KEY`, because a
  decrement only ever follows a failed increment by the same thread. No finding.
- **Thread safety**: `AesGcmDataCipher` obtains a fresh `Cipher` per operation
  (`:165`, `:242`) rather than sharing a non-thread-safe one; `encryptionCounters` is a
  `ConcurrentHashMap` of `AtomicLong`; `KeySetSecretKeyProvider` is immutable after
  construction with an `unmodifiableMap` (`KeySetSecretKeyProvider.java:61`); every read
  and the mutation of `ZeroizableSecretKey.key` are `synchronized`
  (`ZeroizableSecretKey.java:65,73,79`).
- **Key material wiping on the paths the component owns**: nonces
  (`AesGcmDataCipher.java:180,264`), intermediate plaintext in `reencryptUnderActiveKey`
  (`:284`) and `decryptText` (`:335`), the UTF-8 buffer and caller text in `encryptText`
  (`:306-307`), the encoder's over-allocated backing array (`Bytes.java:60-63`), the
  decoder's char buffer (`AesGcmDataCipher.java:326-328`), the transient `getEncoded()`
  clone in `isUsable` (`:454`), the Base64/ASCII intermediates and raw key bytes in
  `KeyMaterial.fromBase64` (`KeyMaterial.java:85-88`), the generated key's source array
  (`KeyMaterial.java:46-50`), the keystore password and file contents
  (`KeyStoreKeySource.java:106-107`), and the passphrase and `PBEKeySpec`
  (`PassphraseKeyDerivation.java:109-115`). `ZeroizableSecretKey.destroy()` genuinely
  zeroes its only copy, unlike `SecretKeySpec` — the gap is only the provider-owned copies
  noted in SEC-05.
- **Fail-closed on destroyed keys**: `getEncoded()` returns `null` once destroyed
  (`ZeroizableSecretKey.java:66-68`), which `isUsable` treats as unusable
  (`AesGcmDataCipher.java:452`), so a key destroyed by `close()` mid-flight causes a clean
  failure rather than encryption under zeroed material.
- **All-zero and short key rejection**: `ZeroizableSecretKey` rejects both
  (`:39-50`), catching the classic unset/truncated-configuration symptom rather than
  "working" with a predictable key. `isAllZero` (`:134-140`) is branch-free.
- **Constant-time comparison where operands could be secret**: `MessageDigest.isEqual`
  in `Bytes.constantTimeEquals` (`Bytes.java:37-39`) and in `ZeroizableSecretKey.equals`
  (`ZeroizableSecretKey.java:100`), with both operand clones wiped afterwards (`:101-104`).
- **Secrets never rendered**: `ZeroizableSecretKey.toString` emits only the algorithm and
  destroyed flag (`:116-118`); `hashCode` is deliberately independent of key material
  (`:108-112`) so a key cannot leak through a collection's or a logger's hash output;
  `CryptoLog.masked` reduces a value to a length placeholder
  (`CryptoLog.java:43-50`) and is the only way a sensitive value reaches a log line
  (`AesGcmDataCipher.java:176`, `KeyMaterial.java:83`). Checked against
  `testing-for-sensitive-data-exposure`'s data-masking and information-leakage steps.
- **Logging discipline**: all logging funnels through `CryptoLog`
  (`CryptoLog.java:19-50`); diagnostics are `FINE` (off by default) and only configuration
  problems reach `WARNING`; no key, passphrase, plaintext or ciphertext is ever passed as
  an argument at any of the call sites (`AesGcmDataCipher.java:175,430,440,463`,
  `KeyId.java:52`, `KeyMaterial.java:73,83`, `EnvironmentKeySource.java:64,92`,
  `KeyStoreKeySource.java:71,87,95,98`, `PassphraseKeyDerivation.java:107`,
  `SecureFiles.java:64,85,94,110`).
- **Java serialization of key material**: `ZeroizableSecretKey` is `Serializable` only
  because `javax.crypto.SecretKey` extends it, and both directions are refused by
  `writeObject`/`readObject` throwing `NotSerializableException`
  (`ZeroizableSecretKey.java:126-132`). The signatures are the exact ones the JDK's
  serialization machinery looks up (private, correct parameter type, `NotSerializableException`
  being an `IOException`), the class is `final` so no subclass can reintroduce a path, and
  there is no `readResolve`/`readObjectNoData` gap. The component performs no
  deserialization of untrusted data at all — the only parsing is the binary envelope,
  which is hand-written and allocates nothing reflective. Checked against
  `exploiting-insecure-deserialization`'s Java `readObject` magic-method analysis.
- **Key rotation support**: multiple keys are loadable at once with a named active key
  (`KeySetSecretKeyProvider.java:41-63`), new data always uses `activeKeyId()`
  (`AesGcmDataCipher.java:156`), old data stays decryptable under its own id, and
  `reencryptUnderActiveKey` (`:279-286`) migrates records while requiring the same AAD on
  both sides so a record cannot be silently re-bound to a different context during
  migration. The intermediate plaintext is wiped on both the success and failure path
  (`:283-285`). Checked against the key-management review points of
  `performing-cryptographic-audit-of-application`.
- **Fail-fast and fail-closed configuration**: the constructor validates the active key at
  start-up rather than on first use (`AesGcmDataCipher.java:128-130`);
  `KeySetSecretKeyProvider` rejects an active id with no matching key
  (`KeySetSecretKeyProvider.java:56-60`); `EnvironmentKeySource` refuses to start with no
  variables set and invents nothing (`EnvironmentKeySource.java:62-66,91-95`);
  `KeyStoreKeySource` requires the active alias to be present
  (`KeyStoreKeySource.java:86-89`). Unknown key ids never cause a key to be derived or
  created on demand (`KeySetSecretKeyProvider.java:76-84`). No permissive default is
  substituted anywhere.
- **Partial key state destroyed on failed start-up**: `EnvironmentKeySource.java:97-101`
  and `KeyStoreKeySource.java:100-105` both destroy any keys already built before
  rethrowing, so a failed load leaves no readable material behind.
- **Resource-exhaustion bounds**: plaintext capped at 1 MiB by default and 64 MiB by
  configuration (`AesGcmDataCipher.java:92-95,123-126,150-153`), AAD at 64 KiB
  (`:98,382-391`), Base64 input bounded before decoding so the 4/3 inflation cannot be
  used to exhaust memory (`:351-366`), key count at 64
  (`KeySetSecretKeyProvider.java:32,44-46`, `EnvironmentKeySource.java:78-81`,
  `KeyStoreKeySource.java:62-65`), configured key text at 43-48 chars
  (`KeyMaterial.java:72-75`), key file at 256 KiB (`SecureFiles.java:28,56-59`), PBKDF2
  iterations capped at 10,000,000 so a configuration value cannot stall the process
  (`PassphraseKeyDerivation.java:42,94-97`), passphrase at 1024 chars and salt at 64 bytes
  (`:48,54,84-93`). The `encryptionCounters` map is keyed only by the provider's own
  active key id, so it cannot be grown by an attacker.
- **Strict decoding, no permissive fallback**: `Base64.getDecoder()` (the strict decoder,
  not MIME) at `AesGcmDataCipher.java:362` and `KeyMaterial.java:80`; non-ASCII rejected
  before Base64 decoding (`KeyMaterial.java:91-103`); UTF-8 encode and decode both use
  `CodingErrorAction.REPORT` rather than silent replacement (`Bytes.java:48-50`,
  `AesGcmDataCipher.java:320-322`).
- **Key derivation**: PBKDF2WithHmacSHA256 from the platform provider — no hand-rolled
  KDF, no bare hash, no MD5/SHA-1 (`PassphraseKeyDerivation.java:101`). 256-bit output
  (`:99-100`), random salt from the CSPRNG with an enforced 16-byte minimum
  (`:45,60-62,90-93`), and parameters rejected rather than clamped when out of range
  (`:84-97`). Checked against the key-derivation guidance in
  `implementing-aes-encryption-for-data-at-rest` and the "weak KDF" row of
  `performing-cryptographic-audit-of-application`; see SEC-06 for the one gap.
- **Keystore integrity**: the PKCS#12 store's MAC is verified by passing the password to
  `KeyStore.load` (`KeyStoreKeySource.java:58-60`), so a tampered store is rejected before
  any entry is read. A wrong password produces the same generic message as any other load
  failure, with no indication of which alias (`:93-99`).
- **Key file permissions**: owner-only mode required, with group and other read/write/execute
  all forbidden (`SecureFiles.java:30-36,83-89`), ownership by the current user required
  (`:90-96`), symlinks refused at check time (`:53,77`), and a non-POSIX filesystem fails
  closed rather than assuming privacy (`:78-81`). The gaps are SEC-01 and SEC-02; the
  controls themselves are present and correct as far as they go.
- **Secrets not passed on the command line**: no key, password or passphrase is read from
  `args` or from a system property anywhere; the keystore password arrives as a `char[]`
  parameter and is wiped (`KeyStoreKeySource.java:46,107`). The environment-variable
  residual risk (`/proc/<pid>/environ`, inheritance by child processes, JVM-owned `String`s
  that cannot be wiped) is documented honestly at `EnvironmentKeySource.java:23-26,86-88`
  with the keystore/KMS alternative named — an accepted and disclosed risk, not a finding.
- **Scope discipline**: the component contains no CLI, no UI, no admin surface, no network
  I/O, no TLS configuration, no SQL, no HTML/template rendering, no OS command execution,
  no reflection and no dynamic class loading. The injection, SSRF, XSS, access-control and
  session/cookie categories of the OWASP Top 10 have no attack surface here; confirmed by
  grepping the tree for `Runtime.exec`, `ProcessBuilder`, `Class.forName`, JDBC, socket and
  HTTP APIs, all absent.
- **Build and supply chain**: `pom.xml` pins every dependency and plugin to an exact
  version from Maven Central with no ranges, snapshots or `LATEST`/`RELEASE`
  (`pom.xml:28-56`); the component has zero runtime dependencies and uses only the JDK's
  own SunJCE/SunPKCS12 providers, with JUnit 5.10.2 at test scope only. Nothing is
  downloaded at runtime and no code is loaded from a shared or world-writable location.
  Reviewed against general CWE-1104/CWE-829 knowledge.
