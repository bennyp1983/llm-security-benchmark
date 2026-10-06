# Security Review: AES-GCM Authenticated Data Protection Component (Java)

## 1. Executive Summary

The component under review is a small, dependency-free Java 17 library that provides
authenticated symmetric encryption of application data. `AesGcmDataProtector` wraps the
JDK's `AES/GCM/NoPadding` cipher with a 256-bit key ring, a fresh 96-bit `SecureRandom`
nonce per operation, a full 128-bit tag, and a self-describing envelope
(`magic | version | algorithm | keyIdLen | keyId | nonce | ciphertext+tag`) whose header,
a configured `purpose` domain separator, and a caller-supplied `context` are all bound in
as length-delimited AAD. `DataProtectionException` is the single, uniform failure type.

The cryptographic core is sound. The algorithm, mode, key size, tag length, nonce source
and nonce length all match NIST SP 800-38D; AAD is canonically length-prefixed so no
ambiguity attack exists across `purpose`/`header`/`context` boundaries; every
attacker-reachable failure path throws the same exception with the same message, no cause
and no stack trace; unknown key IDs trigger a dummy authenticated decryption so the
unknown-key path is not a cheap oracle; all attacker-controlled sizes are bounded before
allocation; and there are no hardcoded keys, no logging, no file or network I/O, no
string-to-key parsing, and no hand-rolled primitives. Key material is defensively copied on
entry and zeroed on close under a read/write lifecycle lock that makes close-versus-use
atomic.

No critical or high-severity vulnerability was found. Four issues are reported. The most
important (SEC-01) is that the GCM nonce-reuse safety counter is scoped to a single
`AesGcmDataProtector` instance, so it resets on every re-instantiation, restart, or
additional process and therefore does not actually enforce the 2^32 limit it advertises for
a key's real lifetime. The remaining three are low-severity defects in the private
`DestroyableAesKey` class: `equals` zeroes a byte array returned by the *other* key object,
`hashCode` publishes a value derived directly from secret key bytes, and the class blocks
serialization but not deserialization.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/security/crypto/AesGcmDataProtector.java` | The whole component: key-ring construction and validation, AES-256-GCM encrypt/decrypt, envelope format, lifecycle and key zeroization | Cryptography (cipher/mode/key size/tag), nonce generation and reuse limits, key handling and defensive copying, key rotation and attacker-controlled key-ID selection, untrusted ciphertext parsing, input bounds, AAD binding, uniform error behaviour, concurrency (read/write lock, atomic counter), in-memory secret erasure, `SecretKey` implementation (`equals`/`hashCode`/`toString`/serialization) |
| `src/main/java/com/example/security/crypto/DataProtectionException.java` | The single runtime failure type for the component | Error handling: one fixed generic message, no cause, suppression and stack trace disabled (`DataProtectionException.java:12-14`) |
| `src/test/java/com/example/security/crypto/AesGcmDataProtectorTest.java` | Dependency-free `main`-based verification harness (round trip, tampering, rotation, bounds, lifecycle, invalid configuration) | Not production code and not on any trust boundary; generates keys only via `AesGcmDataProtector.generateKey()` and contains no hardcoded secret key material |
| `README.md` | Usage documentation, trust-boundary table, and the author's rule-by-rule self-assessment | Documents the key-sourcing requirement, caller-side authorization requirement, and the residual JVM-memory limitation |
| `prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Generation metadata for the sample; not shipped code | No executable content; reviewed only to establish intent and scope |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied its weakness table (weak hashing, insecure encryption, bad cipher mode, insufficient key size, hardcoded secrets, weak KDF, poor entropy, deprecated protocols) to the cipher selection, key sizing, randomness, and secret-sourcing in `AesGcmDataProtector.java:31-57` and `AesGcmDataProtector.java:143-147`.
- `implementing-aes-encryption-for-data-at-rest`: applied its AES-256-GCM, nonce/IV management, authenticated-encryption and key-rotation criteria to the encrypt/decrypt paths and envelope format (`AesGcmDataProtector.java:150-240`, `AesGcmDataProtector.java:258-306`). Its "nonces are never reused for the same key" criterion is what SEC-01 reports against.
- `exploiting-insecure-deserialization`: applied its Java-serialization knowledge (`ac ed 00 05` object graphs, gadget surface, the need to block both directions) to `DestroyableAesKey`, which implements the `Serializable`-derived `SecretKey` interface (`AesGcmDataProtector.java:380-381`, `AesGcmDataProtector.java:452-454`). Its tooling steps (ysoserial, Burp) were not executed; the code was not run.
- `testing-for-sensitive-data-exposure`: applied its secret-leakage checks to every place secret bytes can escape the component - `toString`, `hashCode`, exception messages, returned arrays, and logging (`AesGcmDataProtector.java:399-450`, `DataProtectionException.java:10-14`). This is the basis of SEC-03.
- `configuring-hsm-for-key-storage`: used only as a reference point for the residual risk that raw keys live in JVM heap; the component explicitly documents this limitation in `README.md` and the finding is not raised as a defect.
- Behaviours reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched: untrusted binary envelope parsing and bounds checking (CWE-20, CWE-125, CWE-789) at `AesGcmDataProtector.java:196-291`; AAD canonicalisation and cross-context ciphertext substitution (CWE-345) at `AesGcmDataProtector.java:300-306`; uniform error responses and absence of a padding/existence oracle (CWE-203, CWE-209) at `AesGcmDataProtector.java:209-232`; check-then-act atomicity and lifecycle race conditions (CWE-367, CWE-362) at `AesGcmDataProtector.java:154-156`, `AesGcmDataProtector.java:244-256` and `AesGcmDataProtector.java:342-351`; and in-memory secret erasure (CWE-226, CWE-316) at `AesGcmDataProtector.java:248-249` and `AesGcmDataProtector.java:357-359`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | GCM nonce-reuse limit is enforced per object instance, so it resets on every restart or second instance | Medium | CWE-323 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:336-351` |
| SEC-02 | `DestroyableAesKey.equals` zeroes the byte array returned by the other key object and throws on a destroyed key | Low | CWE-404 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:420-437` |
| SEC-03 | `DestroyableAesKey.hashCode` publishes a value computed directly from the raw key bytes | Low | CWE-200 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:440-445` |
| SEC-04 | Serialization of the key class is blocked, but deserialization is not | Low | CWE-502 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:380-381, 452-454` |

## 5. Detailed Findings

### SEC-01: GCM nonce-reuse limit is enforced per object instance, so it resets on every restart or second instance
- **Severity:** Medium
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:336-351` (counter definition and reservation), with the constant at `AesGcmDataProtector.java:45-46` and the per-instance key copy created at `AesGcmDataProtector.java:100`

**Vulnerable code:**
```java
// src/main/java/com/example/security/crypto/AesGcmDataProtector.java:334-351
    private static final class KeyEntry {
        private final byte[] bytes;
        private final AtomicLong encryptionCount = new AtomicLong();

        private KeyEntry(byte[] bytes) {
            this.bytes = bytes;
        }

        private boolean reserveEncryption() {
            long current;
            do {
                current = encryptionCount.get();
                if (current >= MAX_ENCRYPTIONS_PER_KEY) {
                    return false;
                }
            } while (!encryptionCount.compareAndSet(current, current + 1));
            return true;
        }
```

**Why it is a problem:** `KeyEntry` - and therefore `encryptionCount` - is created fresh inside the
constructor for each `AesGcmDataProtector` (`AesGcmDataProtector.java:100`), and the count
lives only in heap memory. The limit it guards, `MAX_ENCRYPTIONS_PER_KEY = 0xffff_ffffL`
(`AesGcmDataProtector.java:46`), is a property of the *key*, not of the object: NIST SP
800-38D bounds the number of invocations of random 96-bit IVs under a single key, so the
budget must be tracked for the key's whole lifetime across all processes and restarts. As
written, every JVM restart, every redeploy, every replica, and even a second
`AesGcmDataProtector.create(...)` call over the same key bytes in the same JVM starts the
counter at zero. The test harness demonstrates exactly this: `oldProtector` and
`newProtector` are built from the same `keys` map and each get an independent counter
(`AesGcmDataProtectorTest.java:68-71`). A deployment that encrypts heavily under one key ID
can therefore pass 2^32 encryptions with no component-level signal at all, and the counter
contributes nothing toward the limit it names. Once that budget is exceeded, the birthday
probability of a repeated 96-bit random nonce under the same key becomes non-negligible,
and a GCM nonce collision is catastrophic: XORing the two ciphertexts recovers the XOR of
the plaintexts, and the repeated counter-0 block lets an attacker recover the GHASH
authentication subkey and forge valid tags, destroying both confidentiality and integrity
for that key. The README is candid that cross-process tracking is the caller's job, but the
in-code control creates a false impression of enforcement while silently doing nothing in
the only scenario that matters.

**Fix:** Either make the budget durable, or stop pretending to enforce it and push the
responsibility explicitly onto the caller. The cleanest fix that stays inside the
component's scope is to let the caller inject the already-consumed count for each key ID
from durable, shared state (a counter row, a KMS usage record, a monotonic per-key
allocation grant), and to expose the remaining budget so the caller can persist progress and
trigger rotation. A deployment that cannot supply durable state should be steered to a
deterministic/counter-based nonce construction with an externally allocated, never-reused
device-and-epoch prefix rather than relying on a per-instance tally.

```java
    /**
     * Creates a protector, seeding each key's invocation budget from durable,
     * cross-process state. {@code consumedEncryptions} must be the total number
     * of encryptions already performed under each key ID by every instance and
     * process that has ever used it; a missing entry is rejected rather than
     * defaulted to zero, so a caller cannot silently reset the budget.
     */
    public static AesGcmDataProtector create(
            Map<String, byte[]> keys,
            Map<String, Long> consumedEncryptions,
            String activeKeyId,
            String purpose,
            int maxPlaintextBytes) {
        return new AesGcmDataProtector(
                keys, consumedEncryptions, activeKeyId, purpose, maxPlaintextBytes);
    }

    /** Encryptions still available under the active key, for durable persistence. */
    public long remainingActiveKeyEncryptions() throws DataProtectionException {
        lifecycleLock.readLock().lock();
        try {
            ensureOpen();
            return keys.get(activeKeyId).remaining();
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    private static final class KeyEntry {
        private final byte[] bytes;
        private final AtomicLong encryptionCount;

        private KeyEntry(byte[] bytes, long alreadyConsumed) {
            if (alreadyConsumed < 0 || alreadyConsumed > MAX_ENCRYPTIONS_PER_KEY) {
                throw new IllegalArgumentException("Key invocation budget is out of range");
            }
            this.bytes = bytes;
            this.encryptionCount = new AtomicLong(alreadyConsumed);
        }

        private long remaining() {
            return MAX_ENCRYPTIONS_PER_KEY - encryptionCount.get();
        }

        private boolean reserveEncryption() {
            long current;
            do {
                current = encryptionCount.get();
                if (current >= MAX_ENCRYPTIONS_PER_KEY) {
                    return false;
                }
            } while (!encryptionCount.compareAndSet(current, current + 1));
            return true;
        }
```
In the constructor, replace `copied.put(id, new KeyEntry(key.clone()));` with a lookup that
fails closed when the durable count is absent:
```java
                Long consumed = consumedEncryptions == null ? null : consumedEncryptions.get(id);
                if (consumed == null) {
                    throw new IllegalArgumentException(
                            "Every key must carry a durable invocation count");
                }
                copied.put(id, new KeyEntry(key.clone(), consumed));
```

### SEC-02: `DestroyableAesKey.equals` zeroes the byte array returned by the other key object and throws on a destroyed key
- **Severity:** Low
- **CWE:** CWE-404: Improper Resource Shutdown or Release
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:420-437`

**Vulnerable code:**
```java
// src/main/java/com/example/security/crypto/AesGcmDataProtector.java:419-437
        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof SecretKey)) {
                return false;
            }
            byte[] mine = getEncoded();
            byte[] theirs = ((SecretKey) other).getEncoded();
            try {
                return theirs != null && MessageDigest.isEqual(mine, theirs);
            } finally {
                Arrays.fill(mine, (byte) 0);
                if (theirs != null) {
                    Arrays.fill(theirs, (byte) 0);
                }
            }
        }
```

**Why it is a problem:** `equals` takes ownership of an array it does not own. The
`SecretKey`/`Key` contract does not require `getEncoded()` to return a fresh copy - it only
says the encoded form may be returned, and `null` is permitted for keys that do not support
encoding. `javax.crypto.spec.SecretKeySpec` does clone, which is why this is low severity in
practice, but a hardware-backed, cached, or third-party `SecretKey` that returns its live
internal buffer will be silently destroyed by a comparison, turning a read-only predicate
into a destructive operation on another component's key. A caller that then uses that key
encrypts under an all-zero key, which is a confidentiality failure rather than a clean error.
The same method also breaks the `equals` contract in two ways that matter for a key that may
be destroyed mid-life: `getEncoded()` on a destroyed `DestroyableAesKey` throws
`IllegalStateException` (`AesGcmDataProtector.java:399-404`), so `equals` propagates an
exception instead of returning `false`, and the comparison is asymmetric because the other
key's `equals` has no such behaviour. `DestroyableAesKey` is private and the component never
compares keys today, so this is currently latent, but it is a trap for any future use and for
any JCE provider that compares keys internally.

**Fix:** Treat the other key's encoded form as borrowed, not owned: never zero it, return
`false` instead of throwing when either side is destroyed, and keep the constant-time
comparison for the copy this class does own.

```java
        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof SecretKey)) {
                return false;
            }
            byte[] mine;
            synchronized (this) {
                if (bytes == null) {
                    return false; // a destroyed key equals nothing but itself
                }
                mine = bytes.clone();
            }
            try {
                // Borrowed: the other key owns this array and may hand back its
                // live internal buffer, so it must never be cleared here.
                byte[] theirs = ((SecretKey) other).getEncoded();
                return theirs != null && MessageDigest.isEqual(mine, theirs);
            } catch (IllegalStateException destroyedPeer) {
                return false;
            } finally {
                Arrays.fill(mine, (byte) 0);
            }
        }
```

### SEC-03: `DestroyableAesKey.hashCode` publishes a value computed directly from the raw key bytes
- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:440-445`

**Vulnerable code:**
```java
// src/main/java/com/example/security/crypto/AesGcmDataProtector.java:439-445
        @Override
        public synchronized int hashCode() {
            if (bytes == null) {
                return 0;
            }
            return Arrays.hashCode(bytes);
        }
```

**Why it is a problem:** The class is careful everywhere else that key material never
escapes - `toString` is redacted (`AesGcmDataProtector.java:447-450`), `getEncoded` hands
back a clone the caller is expected to erase, exception messages are fixed
(`DataProtectionException.java:10`), and nothing is logged. `hashCode` is the one hole:
`Arrays.hashCode` is a non-cryptographic, invertible-by-search polynomial over the 32 secret
bytes, and unlike the other accessors its result is an `int` that routinely leaves the
security boundary without anyone thinking of it as secret - into a `HashMap` bucket layout, a
debugger view, a heap-dump analysis, an `Objects.hash` of an enclosing object, a diagnostic
`String.format("%08x", obj.hashCode())`, or an identity line in a crash report. Thirty-two
bits is not enough to recover a 256-bit key, but it is a direct, stable fingerprint of the key
that confirms whether two components hold the same key, detects whether a rotation actually
changed the material, and survives into artefacts that are not treated as key-bearing. It also
inverts the normal zeroization story: the value remains correct and quotable after
`destroy()` has been called elsewhere, because whoever read it kept the `int`.

**Fix:** Do not derive the hash from the secret. Identity-based hashing is correct here
because the class owns a mutable buffer and is not a value type that belongs in hash-based
collections; if a content-based hash is genuinely required later, derive it from a keyed or
truncated cryptographic digest rather than from the raw bytes.

```java
        @Override
        public int hashCode() {
            // Never derive a published value from secret key material: the result
            // escapes into collections, dumps and diagnostics as a stable key
            // fingerprint. Identity hashing is sufficient for this owned buffer.
            return System.identityHashCode(this);
        }
```
Note that this makes `hashCode` inconsistent with the content-based `equals` of SEC-02; if
both are needed, drop `equals` as well, since the component never compares keys and the
JCE never requires it.

### SEC-04: Serialization of the key class is blocked, but deserialization is not
- **Severity:** Low
- **CWE:** CWE-502: Deserialization of Untrusted Data
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:380-381` and `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:452-454`

**Vulnerable code:**
```java
// src/main/java/com/example/security/crypto/AesGcmDataProtector.java:379-386
    /** A non-serializable operation-scoped key whose owned bytes can be erased. */
    private static final class DestroyableAesKey implements SecretKey {
        private static final long serialVersionUID = 1L;
        private byte[] bytes;

        private DestroyableAesKey(byte[] ownedBytes) {
            this.bytes = Objects.requireNonNull(ownedBytes);
        }
```
```java
// src/main/java/com/example/security/crypto/AesGcmDataProtector.java:452-454
        private void writeObject(ObjectOutputStream stream) throws IOException {
            throw new NotSerializableException("Secret keys cannot be serialized");
        }
```

**Why it is a problem:** `SecretKey` extends `java.security.Key`, which extends
`Serializable`, so `DestroyableAesKey` is a serializable type whatever the class comment and
the README's claim that it "cannot be serialized" say. Only the outbound direction is
blocked. A stable `serialVersionUID = 1L` is declared, no `readObject`,
`readObjectNoData` or `readResolve` guard exists, and the class has no fields that would
make a hand-crafted stream fail - so an application that deserializes untrusted data with a
classloader that can see this class can materialise a `DestroyableAesKey` holding
attacker-chosen bytes, entirely bypassing the constructor's `Objects.requireNonNull` and the
32-byte key validation the component applies everywhere else
(`AesGcmDataProtector.java:88-90`). That object is a fully functional `SecretKey` that any
`Cipher.init` will accept. The class is private to `AesGcmDataProtector` and is never written
to a stream by this library, and reaching it still requires a pre-existing unsafe
`ObjectInputStream` in the host application, which is why this is Low rather than higher. But
blocking one direction of Java serialization while leaving the other open is precisely the
gap this control is supposed to close, and the defence is one method away from complete.

**Fix:** Close the inbound direction too, and drop the `serialVersionUID` that implies the
type is a supported serial form. Applications should additionally install an
`ObjectInputFilter` on any `ObjectInputStream` that reads untrusted data.

```java
    /** A non-serializable operation-scoped key whose owned bytes can be erased. */
    private static final class DestroyableAesKey implements SecretKey {
        private byte[] bytes;

        // ... unchanged members ...

        private void writeObject(ObjectOutputStream stream) throws IOException {
            throw new NotSerializableException("Secret keys cannot be serialized");
        }

        private void readObject(ObjectInputStream stream) throws IOException {
            throw new NotSerializableException("Secret keys cannot be deserialized");
        }

        private void readObjectNoData() throws ObjectStreamException {
            throw new NotSerializableException("Secret keys cannot be deserialized");
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **Algorithm, mode and key size:** `AES/GCM/NoPadding` with a 256-bit key and no provider-specific fallback (`AesGcmDataProtector.java:34-35`, `AesGcmDataProtector.java:168`, `AesGcmDataProtector.java:215`). No ECB, CBC, DES/3DES, RC4, MD5 or SHA-1 appears anywhere in the component; `MessageDigest` is used only as a constant-time array comparator (`AesGcmDataProtector.java:95`, `AesGcmDataProtector.java:263`), never as a hash.
- **Authentication tag length:** the full 128-bit tag is required on both encryption and decryption, with no caller-tunable or truncated-tag path (`AesGcmDataProtector.java:37-38`, `AesGcmDataProtector.java:170`, `AesGcmDataProtector.java:217`).
- **Nonce generation:** 96-bit nonces come from `SecureRandom.nextBytes` on every single encryption, are never accepted from a caller or derived from a counter/timestamp, and are stored in the clear inside the authenticated header (`AesGcmDataProtector.java:36`, `AesGcmDataProtector.java:162-165`). The test harness asserts two encryptions of identical input differ (`AesGcmDataProtectorTest.java:26-28`). The only nonce concern is the lifetime budget reported as SEC-01.
- **No hardcoded secrets:** no key, password, token or credential literal exists in any file. `generateKey()` uses `SecureRandom` (`AesGcmDataProtector.java:143-147`), keys enter only as runtime `byte[]` (`AesGcmDataProtector.java:134-140`), and the tests generate keys at runtime rather than embedding them (`AesGcmDataProtectorTest.java:21`, `AesGcmDataProtectorTest.java:62-63`).
- **Defensive copying of key material:** supplied keys are cloned into private `KeyEntry` instances so later mutation of the caller's array cannot affect the component, and the map is wrapped unmodifiable (`AesGcmDataProtector.java:100`, `AesGcmDataProtector.java:118`). Each operation works on its own clone that is destroyed in a `finally` block (`AesGcmDataProtector.java:166`, `AesGcmDataProtector.java:184`, `AesGcmDataProtector.java:211-212`, `AesGcmDataProtector.java:234`).
- **Key-ring validation:** non-null, exactly 32 bytes, at most 32 keys, unique identifiers, and rejection of the same key material under two identifiers via a constant-time comparison (`AesGcmDataProtector.java:70-99`). The active key ID must exist in the trusted server-side ring (`AesGcmDataProtector.java:102-104`). Keys already copied are zeroed if construction fails partway (`AesGcmDataProtector.java:110-116`).
- **Identifier allowlisting:** `purpose`, the active key ID, and the key-ID extracted from an attacker-supplied envelope must all match a strict 1-64 character ASCII allowlist anchored with `matches()` (`AesGcmDataProtector.java:47-48`, `AesGcmDataProtector.java:278`, `AesGcmDataProtector.java:327-332`). The pattern has no nested quantifier and cannot backtrack catastrophically.
- **Attacker-controlled key ID cannot escalate:** an envelope's key ID only selects from the already-trusted ring; an unmatched ID never causes key loading, derivation, or a permissive default (`AesGcmDataProtector.java:209-211`). It is also covered by the GCM tag because it is inside the authenticated header, so it cannot be swapped silently.
- **Envelope parsing bounds:** total length is range-checked against the configured limits *before* parsing (`AesGcmDataProtector.java:198-203`), the key-ID length byte is read unsigned and bounded, and remaining-length is verified to cover key ID, nonce and tag before any further read (`AesGcmDataProtector.java:269-273`). The buffer is read-only and every `RuntimeException` from a malformed read is converted to the generic failure (`AesGcmDataProtector.java:260`, `AesGcmDataProtector.java:286-290`). No unchecked index arithmetic reaches `doFinal` (`AesGcmDataProtector.java:219-220`).
- **Version and algorithm downgrade:** magic, version byte and algorithm byte are all compared against fixed constants, with exactly one accepted combination and no legacy branch (`AesGcmDataProtector.java:261-268`).
- **AAD canonicalisation and cross-context substitution:** `purpose` and `context` are each prefixed with a 4-byte big-endian length before being fed to `updateAAD`, with the fixed-layout header in between, so no concatenation ambiguity exists between the three segments and a ciphertext cannot be replayed into a different purpose, tenant, record or field (`AesGcmDataProtector.java:300-306`). The test asserts a changed context fails (`AesGcmDataProtectorTest.java:53`).
- **Tamper detection:** GCM authentication is verified before any plaintext is returned, and the test flips bytes in the header, key ID region and tag region and requires a generic failure for each (`AesGcmDataProtectorTest.java:48-52`).
- **Uniform failure behaviour and absence of an oracle:** every runtime failure - null input, oversize input, bad magic, bad version, bad key-ID characters, unknown key, failed tag, closed instance, exhausted key budget - throws `DataProtectionException` with one fixed message, no cause, no suppression and no writable stack trace (`DataProtectionException.java:12-14`; thrown at `AesGcmDataProtector.java:159`, `:202`, `:223`, `:232`, `:267`, `:272`, `:279`, `:289`, `:310`, `:317`, `:323`). Unknown key IDs perform a full dummy authenticated decryption under a random key rather than returning early, so the unknown-key path does comparable work to the wrong-tag path (`AesGcmDataProtector.java:211`, `AesGcmDataProtector.java:221-224`). The test asserts the exact message for every failure mode (`AesGcmDataProtectorTest.java:115-120`).
- **No information disclosure through logs or output:** the component performs no logging, no `System.out`/`System.err` writes, no file or network I/O, and no exception carries input, key, context or envelope data. `toString` on the key class is redacted (`AesGcmDataProtector.java:447-450`). Configuration-time `IllegalArgumentException` messages interpolate only a fixed label constant, never an attacker value (`AesGcmDataProtector.java:330`).
- **Input size bounds (resource-exhaustion):** plaintext is bounded by a validated 1 byte-16 MiB limit with no permissive default (`AesGcmDataProtector.java:44`, `AesGcmDataProtector.java:66-69`, `AesGcmDataProtector.java:151`), context by 64 KiB (`AesGcmDataProtector.java:43`, `AesGcmDataProtector.java:321-325`), key IDs by 64 bytes, and the key ring by 32 entries. Decrypted output is re-checked against the limit and zeroed if it exceeds it (`AesGcmDataProtector.java:221-224`).
- **Concurrency and check-then-act atomicity:** a `ReentrantReadWriteLock` makes use-versus-close atomic, so `close()` waits for in-flight operations before erasing keys and subsequent operations fail closed via `ensureOpen()` (`AesGcmDataProtector.java:56`, `AesGcmDataProtector.java:154-156`, `AesGcmDataProtector.java:205-207`, `AesGcmDataProtector.java:244-256`, `AesGcmDataProtector.java:308-312`). The `closed` flag is written under the write lock and read under the read lock, giving correct visibility. The invocation-budget check-and-increment is a single CAS loop with no gap between test and reservation (`AesGcmDataProtector.java:342-351`). `close()` is idempotent (`AesGcmDataProtector.java:247`).
- **In-memory secret erasure:** stored key copies, the dummy unknown key and the purpose buffer are zeroed on close (`AesGcmDataProtector.java:248-249`, `AesGcmDataProtector.java:357-359`); per-operation key copies, nonces, parsed headers and intermediate ciphertext buffers are zeroed in `finally` blocks (`AesGcmDataProtector.java:179`, `:185`, `:234-235`, `:373-376`); plaintext is zeroed on every failure path before the generic exception is thrown (`AesGcmDataProtector.java:222`, `:229-231`). The irreducible JVM/provider copy problem is acknowledged in `README.md` rather than glossed over.
- **Prefer-the-platform:** all cryptography and randomness come from the Java 17 JCA/JCE (`Cipher`, `GCMParameterSpec`, `SecureRandom`, `MessageDigest.isEqual`). No primitive, tag comparison, RNG or encoder is hand-rolled, and the library has zero third-party or remotely fetched dependencies.
- **No injection or unsafe sink surface:** the component builds no SQL, no OS command, no file path, no URL, no XML/HTML, and no reflective or dynamic class lookup. Key IDs are used solely as `Map` keys, never as paths or query fragments, so the `.` and `/` characters permitted by the allowlist cannot reach a traversal or injection sink.
- **Access control scope:** the component deliberately makes no authentication or authorization decision and never treats `context` as an authorization grant; `README.md` states that the caller must perform the tenant/record access check before invoking it. This is a correct and clearly documented boundary rather than a missing control, and the accompanying argument that per-source rate limiting does not belong in a cryptographic primitive (where it would become a lockout vector) was reviewed and accepted.
- **Test harness:** reviewed as non-production code. It contains no hardcoded key material, writes nothing to disk, opens no network or file handles, and is never referenced from `src/main`. It was read statically and not compiled or executed.
