# Security Review: AesGcmDataProtector (com.example.security.crypto) — AES-256-GCM authenticated data protection library

## 1. Executive Summary

The component is a dependency-free Java 17 library that provides authenticated encryption for application data at rest. It holds a small ring of caller-supplied 256-bit AES keys, encrypts under a server-configured "active" key ID, serialises the result into a versioned envelope (`DP E1` magic, version, algorithm byte, key-ID length, key ID, 96-bit nonce), and authenticates a caller-supplied `context` plus a fixed `purpose` as GCM additional authenticated data. Decryption parses a hostile envelope, selects a trusted key by the envelope's key ID, and fails with one uniform, cause-less exception.

The cryptographic core is sound and was reviewed in depth: `AES/GCM/NoPadding` with a full 128-bit tag, exactly-256-bit keys, CSPRNG nonces that a caller can never supply, a length-delimited AAD construction that is not vulnerable to field-boundary ambiguity, bounds checking before any allocation, a dummy-decryption path for unknown key IDs to equalise failure timing/cost, and deliberate suppression of error detail. **No Critical or High severity vulnerability was found.** Four issues remain, all Medium or Low:

1. **SEC-01 (Medium)** — the per-key encryption budget that bounds random-nonce collision risk is counted *per component instance*, not per key across processes/replicas, so the `2^32` ceiling presented in code and README as the safety limit does not actually hold in any multi-instance deployment; nonce reuse in GCM is catastrophic (authenticity loss plus plaintext recovery), and exhaustion is signalled by the same generic failure as a bad ciphertext, so operators cannot observe or act on the limit.
2. **SEC-02 (Medium)** — the tenant/record binding that the README presents as the control preventing a valid ciphertext being moved to another location is an optional parameter: a zero-length `context` is accepted, and the shipped test suite itself uses the unbound form.
3. **SEC-03 (Low)** — the operation-scoped key class blocks *serialisation* but not *deserialisation*, so a crafted stream can materialise a `SecretKey` outside the constructor's invariants and outside the component's erase-on-destroy lifecycle.
4. **SEC-04 (Low)** — `DestroyableAesKey.hashCode()` returns a value derived from raw key bytes, contradicting the class's own redaction hardening and providing an offline verification oracle if the operator ever supplies lower-entropy key material.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/security/crypto/AesGcmDataProtector.java` | AES-256-GCM encrypt/decrypt component with a key ring, key rotation, envelope format and lifecycle control | Key acceptance and copying, nonce generation, AAD construction, hostile-envelope parsing, size limits, per-key usage budget, thread-safety vs `close()`, in-memory key erasure, serialisability of the internal key class |
| `src/main/java/com/example/security/crypto/DataProtectionException.java` | Single runtime failure type for all crypto failures | Suppresses cause and stack trace; one fixed message so failures do not disclose which check failed |
| `src/test/java/com/example/security/crypto/AesGcmDataProtectorTest.java` | Dependency-free `main()` verification harness | Exercises tampering, context mismatch, unknown key, rotation, size bounds, post-close use; uses zero-length `context` in places |
| `README.md` | Documented trust boundaries, input-validation table and security claims | Claims about key sourcing, nonce limits across processes, context as anti-substitution control, and deliberate no-rate-limiting posture — checked against the code |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to the whole of `AesGcmDataProtector.java` — algorithm/mode deprecation check, cipher-mode check, key-size check, hardcoded-secret search, KDF check, RNG/entropy check, and key storage/rotation review.
- `implementing-aes-encryption-for-data-at-rest`: applied to the AES-GCM specifics — 96-bit nonce handling and the "nonce must never be reused with the same key" invariant, tag presence, key size for long-term data, and key erasure.
- `exploiting-insecure-deserialization`: applied to `DestroyableAesKey` (`AesGcmDataProtector.java:380-455`) using the skill's Java knowledge (serialisable classes, `readObject` hooks, JEP 290 filtering, class allowlisting). Its scripts are Python/offensive tooling and were not run against this Java code.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched: cryptographic failure-oracle and timing analysis (unknown-key path, uniform exceptions — CWE-203/CWE-204), concurrency and TOCTOU between `close()` and in-flight operations (CWE-367), resource-exhaustion/DoS bounds on attacker-controlled envelopes (CWE-400/CWE-770), and injection/logging sinks (CWE-89, CWE-78, CWE-778 — the component has no SQL, command, filesystem, network or logging sink at all).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Per-key nonce-reuse budget enforced per instance, not per key across the deployment | Medium | CWE-323 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:336` |
| SEC-02 | Security-boundary binding (`context`) may be empty, permitting cross-record ciphertext substitution | Medium | CWE-1287 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:321` |
| SEC-03 | Serialisable secret-key class guards write but not read | Low | CWE-502 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:452` |
| SEC-04 | Key-derived `hashCode()` on the secret-key class | Low | CWE-200 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:444` |

## 5. Detailed Findings

### SEC-01: Per-key nonce-reuse budget enforced per instance, not per key across the deployment

- **Severity:** Medium
- **CWE:** CWE-323: Reusing a Nonce, IV with the Same Key
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:45-46`, `:158-163`, `:334-351`

**Vulnerable code:**
```java
// AesGcmDataProtector.java:45-46
    // NIST's limit for independently generated random GCM IVs under one key.
    private static final long MAX_ENCRYPTIONS_PER_KEY = 0xffff_ffffL;
```
```java
// AesGcmDataProtector.java:334-351
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
```java
// AesGcmDataProtector.java:157-163
            KeyEntry entry = keys.get(activeKeyId);
            if (!entry.reserveEncryption()) {
                throw new DataProtectionException();
            }

            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
```

**Why it is a problem:** `encryptionCount` is a field of `KeyEntry`, which is created inside the `AesGcmDataProtector` constructor. The counter therefore bounds nonces drawn by *one object in one JVM*, while the nonce it is protecting is a 96-bit *random* value drawn independently by every process that holds the same key bytes. A normal deployment — several replicas, a background migration job, a CLI re-encryption tool, or simply two `create()` calls in one process — each gets a fresh `AtomicLong` starting at zero, so the aggregate number of random nonces drawn under a single key is the sum over instances, and nothing in the code bounds that sum. The library's own README states the real requirement ("Track total encryptions across all processes and deployments and rotate before 2^32 invocations under one key; the component also enforces that limit atomically within each instance"), which concedes that the in-code enforcement does not cover the boundary that matters. Consequence: the birthday bound on 96-bit random nonces is `≈ n²/2^97`; at `n = 2^32` for a single key, collision probability is already about `2^-33`, and it grows with the square of the number of instances (roughly `2^-21` with 64 replicas at the cap). A GCM nonce collision under one key is not a soft failure: it exposes the GHASH subkey `H`, which allows an attacker who knows one colliding pair to forge authenticated envelopes for arbitrary plaintext under that key, and it leaks the XOR of the two colliding plaintexts. The `SAFE_IDENTIFIER`/tag/length controls do not mitigate this — they all depend on the same key. Two secondary weaknesses make the control unoperable: hitting the cap throws the identical `DataProtectionException` used for a malformed ciphertext, and no accessor exposes remaining budget, so an operator gets a permanent, undiagnosable encryption outage at exactly the point where re-keying was required. Finally, the comment at line 45 attributes `2^32` to NIST; SP 800-38D's stated `2^48` bound is on PRF invocations per key for the *deterministic* construction, and there is no NIST-stated per-key cap of `2^32` for random IVs — `2^32` is a birthday-bound rule of thumb, which is precisely why it must be applied per key, not per process.

**Fix:** Do not make nonce uniqueness depend on a budget shared across processes. Build the nonce so uniqueness holds by construction — a slot identifier that is unique among all live processes holding the key (leased from the KMS/secret manager, coordinator, or database), concatenated with a monotonic per-(key, slot) counter that survives restarts and can never be rewound. SP 800-38D's deterministic construction then permits far more messages per key, and the random-draw collision analysis no longer applies.

```java
// Corrected: 96-bit nonce = 4-byte live-process slot id || 8-byte monotonic per-(key,slot) counter.
// The slot must be leased from shared state (KMS/DB/coordinator) and never reissued
// while the key is still active; the counter must be persisted (or advanced past any
// value used before a restart) so it cannot rewind to a previously used value.
private static final long MAX_NONCES_PER_SLOT = 1L << 40;

private byte[] nextNonce(KeyEntry entry) throws DataProtectionException {
    long count = entry.nextCounter();            // atomic, persisted, never rewound
    if (count >= MAX_NONCES_PER_SLOT) {
        throw new DataProtectionException();     // caller must rotate the key / re-lease the slot
    }
    return ByteBuffer.allocate(NONCE_BYTES).putInt(entry.slotId()).putLong(count).array();
}
```

If a coordinator or KMS counter is genuinely unavailable, the honest stop-gap is to divide the random-nonce budget by the number of live instances sharing each key (configured per key, because the library cannot infer it) and to expose the remaining budget so re-keying is driven by a metric instead of discovered by an outage:

```java
// Corrected stop-gap: budget is per key per deployment, divided by live instances by the operator,
// and exhaustion is observable rather than indistinguishable from a ciphertext error.
KeyEntry(byte[] bytes, long encryptionBudgetPerInstance) {
    this.bytes = bytes;
    this.budget = encryptionBudgetPerInstance;
}

private boolean reserveEncryption() {
    return encryptionCount.incrementAndGet() <= budget;
}

long remainingEncryptionBudget() {
    return Math.max(0L, budget - encryptionCount.get());   // wire to a re-key alarm, e.g. at 10 % left
}
```

Correct the comment on line 45 so it no longer claims a per-process interpretation of a per-key limit.

### SEC-02: Security-boundary binding (`context`) may be empty, permitting cross-record ciphertext substitution

- **Severity:** Medium
- **CWE:** CWE-1287: Improper Validation of Security Boundaries
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:321-325`

**Vulnerable code:**
```java
// AesGcmDataProtector.java:321-325
    private static void validateContext(byte[] context) throws DataProtectionException {
        if (context == null || context.length > MAX_CONTEXT_BYTES) {
            throw new DataProtectionException();
        }
    }
```
```java
// AesGcmDataProtectorTest.java:64
        byte[] context = new byte[0];
```

**Why it is a problem:** The only mechanism that ties an envelope to the record it belongs to is the `context` value, fed into `updateAAD` at `AesGcmDataProtector.java:304-305`; the README states the property explicitly: "`context` should identify the intended tenant, record, and field so a valid ciphertext cannot be moved to another location." `validateContext` checks only null and the upper bound, so a zero-length context is accepted on both encrypt and decrypt. With an empty (or constant) context, the authenticated data for every record encrypted under the same key ring and `purpose` is byte-for-byte identical, so the AEAD tag no longer discriminates between records: an attacker who can write to the ciphertext store — a compromised database, a backup or cache-poisoning path, a SQL-injection sink in the calling application, or a malicious insider — can copy user B's entire envelope over user A's stored envelope, and `decrypt` will return B's plaintext for A's record while reporting complete success. No authentication error fires, so there is no log, metric, or exception to react to, and because `purpose` is a coarse per-data-type constant, this applies across every tenant in a shared key ring at once. The security invariant is therefore optional and silent-by-default, which is a fail-open boundary check rather than an enforced one, and the library's own test harness demonstrates the unsafe call shape (`context = new byte[0]`), so callers copying it inherit the gap. Note that the component correctly does not itself authorise anything — but it should refuse to run in a mode where its advertised anti-substitution control is absent, rather than accept it as the default.

**Fix:** Make binding the default by refusing degenerate contexts, and require an explicit, greppable opt-in for any caller that genuinely has no per-record identity to bind.

```java
// Corrected: reject contexts too short to carry an identity; force an auditable opt-out.
private static final int MIN_CONTEXT_BYTES = 8;

/** Callers that truly have no per-record identity must pass this exact value. */
public static final byte[] CONTEXT_BINDING_DISABLED =
        "com.example.crypto.NO-BINDING".getBytes(StandardCharsets.US_ASCII);

private static void validateContext(byte[] context) throws DataProtectionException {
    if (context == null
            || (context.length < MIN_CONTEXT_BYTES
                    && !MessageDigest.isEqual(CONTEXT_BINDING_DISABLED, context))
            || context.length > MAX_CONTEXT_BYTES) {
        throw new DataProtectionException();
    }
}
```

Document the required content as a stable identity triple (tenant, record, field, plus a version/epoch for future re-keying), update `AesGcmDataProtectorTest.java:64` to a non-empty context and add a test asserting that an envelope produced for one context fails to decrypt under a different context, and have the calling application authorise access to that identity before invoking the component.

### SEC-03: Serialisable secret-key class guards write but not read

- **Severity:** Low
- **CWE:** CWE-502: Deserialization of Untrusted Data
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:380-385`, `:452-454`

**Vulnerable code:**
```java
// AesGcmDataProtector.java:380-385
    private static final class DestroyableAesKey implements SecretKey {
        private static final long serialVersionUID = 1L;
        private byte[] bytes;

        private DestroyableAesKey(byte[] ownedBytes) {
            this.bytes = Objects.requireNonNull(ownedBytes);
        }
```
```java
// AesGcmDataProtector.java:452-454
        private void writeObject(ObjectOutputStream stream) throws IOException {
            throw new NotSerializableException("Secret keys cannot be serialized");
        }
```

**Why it is a problem:** The class is documented as "A non-serializable operation-scoped key", but `javax.crypto.SecretKey` extends `java.security.Key`, which extends `Serializable`, so `DestroyableAesKey` is in fact a serialisable class with a non-final `byte[]` field. `writeObject` closes only the *outbound* direction. There is no `readObject`, `readResolve`, or `readObjectNoData` defence, and Java deserialisation does not invoke constructors — a `byte[]` supplied by the stream is written straight into `bytes`. Any deserialisation sink in the host application (or in a library it embeds) can therefore materialise an `AesGcmDataProtector$DestroyableAesKey` carrying attacker-chosen bytes: the `Objects.requireNonNull` invariant at line 385 is bypassed, the "destroyed ⇒ `bytes == null`" invariant is bypassed, and the resulting object is a live `SecretKey` that the component's `close()`/`operationKey.destroy()` lifecycle never sees, so its bytes persist in the heap indefinitely. This is a one-sided hardening control rather than a complete one. Severity is Low rather than higher because the library itself contains no deserialisation sink, the class is `private static final` with no `readObject` gadget behaviour, and it is not a usable standalone RCE chain — the exposure is confined to host applications that deserialise untrusted data, and per the deserialisation skill's guidance the class itself should still be made non-deserialisable rather than relying on that assumption.

**Fix:** Make the class genuinely non-serialisable in both directions.

```java
// Corrected: block the inbound path as well as the outbound path.
private void writeObject(ObjectOutputStream stream) throws IOException {
    throw new NotSerializableException("Secret keys cannot be serialized");
}

private void readObject(ObjectInputStream stream) throws IOException {
    stream.defaultReadObject();                       // drain the stream
    throw new NotSerializableException("Secret keys cannot be deserialized");
}

private Object readResolve() throws IOException {
    throw new NotSerializableException("Secret keys cannot be deserialized");
}
```

Add `import java.io.ObjectInputStream;`, and — since this is defence in depth for the host process — keep the application-level mitigations recommended by the deserialisation skill: an allowlist `ObjectInputFilter` (JEP 290) on any `ObjectInputStream`, and a preference for non-Java serialisation formats for data crossing a trust boundary.

### SEC-04: Key-derived `hashCode()` on the secret-key class

- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:439-445`, `:427-428`

**Vulnerable code:**
```java
// AesGcmDataProtector.java:439-445
        @Override
        public synchronized int hashCode() {
            if (bytes == null) {
                return 0;
            }
            return Arrays.hashCode(bytes);
        }
```
```java
// AesGcmDataProtector.java:427-428
            byte[] mine = getEncoded();
            byte[] theirs = ((SecretKey) other).getEncoded();
```

**Why it is a problem:** Every other accessor on this class is deliberately hardened against leaking key material — `toString()` returns `"DestroyableAesKey[redacted]"` (line 449) and `writeObject` refuses to emit it — but `hashCode()` returns `Arrays.hashCode(bytes)`, a 32-bit value computed directly from the raw AES key. That value is an offline verification oracle: anyone who observes it (the key placed in a `HashMap`/`HashSet` that is later serialised, cached, or logged; a debugger; a heap dump plus a logged hash) can test candidate 32-byte keys at negligible cost. For a key generated by `generateKey()` this is only a 32-bit fingerprint of a 256-bit value and not directly invertible, but `create()` performs no entropy check on supplied key material — it verifies only that the array is exactly 32 bytes (`AesGcmDataProtector.java:88`) — so any operator that sources weaker material (a truncated passphrase, a padded ASCII string, a derived-but-weak secret) is reduced to brute-forcing a space the hash verifies outright. The `return 0` branch additionally discloses destroy state through a public method. The same method pair has a secondary contract defect: `equals()` calls `getEncoded()`, which throws `IllegalStateException` once the key is destroyed, so a concurrent `destroy()` between the null check and the call makes `Object.equals` throw — a documented `Object` contract violation, and this code calls `operationKey.destroy()` on another path. These objects are created fresh per operation and are never used as collection keys today, hence Low severity, but the API invites that use.

**Fix:** Give an operation-scoped key identity semantics, so no value derived from key bytes is ever exposed and `equals` cannot throw.

```java
// Corrected: identity semantics — no key-derived value, no getEncoded() call.
@Override
public int hashCode() {
    return System.identityHashCode(this);
}

@Override
public boolean equals(Object other) {
    return this == other;
}
```

If value equality must be preserved for compatibility, keep the constant-time comparison but never let `equals` throw (catch `IllegalStateException` and return `false`) and still replace `hashCode()` with `System.identityHashCode(this)`. Independently of this finding, consider adding a minimum-entropy requirement or a KMS/HSM key-handle API to `create()`, since the current API accepts any 32 bytes it is handed.

## 6. Verified Controls and Checks With No Finding

- **Algorithm and mode selection (crypto-audit checklist):** `CIPHER = "AES/GCM/NoPadding"` with `TAG_BITS = 128` (`AesGcmDataProtector.java:37`) and `AES_KEY_BYTES = 32`; no ECB/CBC, no DES/3DES/RC4/Blowfish, no MD5/SHA-1 used for integrity or signatures. `MessageDigest.isEqual` is used only as a constant-time comparison (`:95`, `:253`, `:430`), never as a hash of secrets.
- **Tag length / decryption-query bound:** the full 128-bit tag is required at `:199` and never truncated. This is what makes the README's deliberate "no rate limiting on failures" posture cryptographically acceptable — GCM forgery advantage for `q` failed verification attempts grows as roughly `q²/2^128`, so unbounded attempts are not exploitable at the crypto layer (the calling application must still rate-limit its own endpoint and cap per-source work; the per-operation 16 MiB ceiling at `:199-201` bounds cost per call).
- **Nonce source and caller control:** nonces come only from `SecureRandom` (`:163`, seeded at `:107`), never from caller input; no `java.util.Random`, no time-based seeding, no `System.nanoTime`/`currentTimeMillis` entropy anywhere in the file. The unused `keyIdBytes`/`nonce`/`sealed`/`plaintext` scratch arrays are zeroised (`:179`, `:185`, `:222`, `:230`).
- **No hardcoded secrets (crypto-audit checklist):** the only literals are the `DP E1` magic, version, algorithm tag, and regex; the decoy key is generated at runtime (`:108-109`). No credentials, endpoints, or key material appear in source.
- **Key acceptance and rotation hygiene:** keys must be non-null and exactly 256 bits (`:88`), at most 32 keys (`:96-99` range checks), each ID validated against `SAFE_IDENTIFIER`, the active ID must exist in the ring, and duplicate key material under different IDs is rejected with a constant-time compare (`:94-98`) — closing the "same bytes, two IDs" rotation mistake. Key material is defensively cloned into the ring and cloned again per operation, then erased (`:353-358`, `:404-411`).
- **AAD construction is unambiguous:** `purpose_len || purpose || header || context_len || context` (`:301-305`). I checked the field-boundary ambiguity attack algebraically — extending the header by the 4 context-length bytes to re-absorb them requires the attacker's chosen context to start with the original length prefix and equal the original context, so no distinct `(purpose, header, context)` triple yields the same AAD. Cross-purpose and cross-record substitution fails authentication whenever a real context is supplied (see SEC-02 for the empty-context caveat).
- **Hostile-envelope parsing:** `MAGIC`, `VERSION`, and the algorithm byte are checked before use, so there is no version or algorithm downgrade (`:247-252`); `keyIdLength` is bounds-checked against both the ring maximum and the remaining buffer *before* `input.get` (`:254-257`); total envelope length is bounded before any allocation (`:197-202`); `plaintext.length > maxPlaintextBytes` is re-checked after decryption (`:221`). No integer overflow is reachable in the length arithmetic (all ceilings ≤ 16 MiB + 83 bytes).
- **Key-ID canonicalisation:** `SAFE_IDENTIFIER` (`:47-48`) admits only `[A-Za-z0-9._/-]`, so `US_ASCII` decoding is injective over accepted values and no non-ASCII byte sequence can alias onto a legitimate key ID (the `?` substitution result is rejected by the regex). Key IDs are used only as in-memory map keys; despite allowing `.` and `/` they reach no filesystem, shell, SQL, or log sink, so no traversal or injection issue arises.
- **Failure oracle and timing:** unknown key IDs take a dummy authenticated-decryption path against a per-instance random key (`:210-212`) so cost and timing match the known-key path; every runtime failure surfaces as `DataProtectionException` with one fixed message, no cause, and no stack trace (`DataProtectionException.java:12-15`, `super(GENERIC_MESSAGE, null, false, false)`), and the test harness asserts exactly that at `AesGcmDataProtectorTest.java:104-112`. No logging exists anywhere, so plaintext, context, and envelopes cannot be leaked incidentally.
- **Concurrency / close-vs-use (CWE-367):** `ReentrantReadWriteLock` makes `close()` wait for in-flight operations and makes new operations fail closed under the same lock (`:154-156`, `:186-188`, `:240-249`); `closed`, `purpose`, and key bytes are only touched under that lock, so the zeroisation in `close()` cannot race an active `Cipher.doFinal`. Per-key budget reservation is a correct CAS loop (`:342-350`).
- **Constructor failure cleanup:** if provider initialisation fails, already-copied ring keys and the decoy key are erased before the exception propagates (`:111-117`), so a partially constructed protector never leaves live key material behind.
- **Caller authorisation boundary:** correctly declared out of scope in the README trust table — the component authenticates and binds data but does not decide access, and the README states the caller must authorise the tenant/record first. No authentication, session, cookie, or token handling exists in scope, so those OWASP categories are not applicable here.
- **Test coverage reviewed:** tampering at header, nonce, and tag positions, context mismatch, null envelope, rotation across two key IDs, same-length unknown key ID, oversize plaintext, post-close use, and invalid configuration are all exercised (`AesGcmDataProtectorTest.java:38-88`); `AES/GCM/NoPadding` resolves to a valid JCE transformation and no non-existent API is referenced. Gaps worth closing (not vulnerabilities): no test for equal-context substitution across records, no test for AAD length-prefix boundaries, no concurrency or budget-exhaustion test.
