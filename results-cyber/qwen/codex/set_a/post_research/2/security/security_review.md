# Security Review: AesGcmDataProtector (Java AES-256-GCM data-protection component)

## 1. Executive Summary

The component under review is a small, self-contained envelope-encryption helper: it seals byte
payloads with AES-256-GCM using a per-call random 96-bit IV, prefixes a versioned header (`MAGIC`
+ version + algorithm + key-ID length + key ID + nonce), binds a caller-supplied `purpose` string
and per-call `context` as additional authenticated data, and supports a small named key ring with
an active key for encryption and any known key for decryption.

The cryptographic core is sound and, in most respects, better than typical generated code:
authenticated encryption with a 128-bit tag, a fresh `SecureRandom` nonce per call, length-prefixed
AAD framing that prevents purpose/context splicing, strict envelope length and format validation
*before* parsing, uniform generic failure for every rejection path (no padding-style or key-ID
enumeration oracle), dummy decryption under a random key for unknown key IDs, defensive key copying
with erasure, rejection of duplicate key material, blocked serialization of key objects, and
fail-closed lifecycle locking after `close()`.

Three issues remain. The one that matters is the nonce-reuse safety valve: the code caps
encryptions per key at NIST's full `2^32 - 1` random-IV budget and enforces it with a counter that
lives inside a single JVM instance and starts at zero on every construction. Any deployment with
more than one replica, or with ephemeral/restarting processes, sharing a key ID can therefore
collectively draw far more random 96-bit nonces under that key than the bound allows, and nothing
in the process notices. A GCM nonce repeat under one key is not a graceful failure — it loses
confidentiality for the colliding messages and enables forgery. The project's own `README.md`
states the limit is enforced "within each instance" and asks operators to track usage across all
processes, which is the correct caveat but means the in-code control is a no-op in exactly the
deployments where it is needed; setting the ceiling at the absolute maximum leaves no margin to
absorb that gap. The other two findings are latent defects in the private `DestroyableAesKey`
helper (`equals()` destroys key material it does not own and throws instead of returning `false`;
`hashCode()` derives a fingerprint from live key bytes, defeating the class's own redaction).
Neither is reachable from today's call sites — the class is private and its instances only ever
reach `Cipher.init` — so they are reported as low-severity hardening items rather than exploitable
defects. No hardcoded secrets, weak algorithms, unsafe deserialization sinks, injection sinks,
logging of sensitive material, or non-cryptographic RNG use were found anywhere in the source.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/example/security/crypto/AesGcmDataProtector.java` | Envelope encryptor/decryptor: versioned header, named key ring, active-key selection, AES-256-GCM sealing with `purpose` + `context` as AAD | Random 96-bit IV per call from `SecureRandom`; 128-bit tag; per-key encryption budget gate (`reserveEncryption()`); pre-parse envelope length bounds and format validation; constant-time magic compare and duplicate-key compare; dummy decryption under random `unknownKey` for unknown key IDs; generic failure for all rejections; key copies with erasure (`DestroyableAesKey.destroy()`); read/write-lock lifecycle with `closed` flag; plaintext/context/key-ring size caps; `writeObject` blocked on the key class |
| `src/main/java/com/example/security/crypto/DataProtectionException.java` | Single uniform checked exception for every crypto failure | `super(GENERIC_MESSAGE, null, false, false)` — no cause, no suppression, no stack trace, so failures cannot leak which check tripped; fixed `serialVersionUID`, no `readObject` |
| `src/test/java/com/example/security/crypto/AesGcmDataProtectorTest.java` | `main()`-driven self-test harness | Asserts nonce freshness across calls, tamper/context-mismatch rejection, rotation + unknown-key rejection, fail-closed bounds/lifecycle, invalid-config rejection, and that the thrown message is the generic one with `getCause() == null` |
| `README.md` | Usage and trust-boundary documentation | Documents 96-bit `SecureRandom` nonce, 128-bit tag, keys sourced from a secret manager/KMS, and explicitly states the 2^32 encryption ceiling is enforced "within each instance" only |

Reviewed in place from the read-only mount. Nothing in that folder was modified; nothing was
executed, built, installed, or imported — analysis is static only.

## 3. Skills Applied

Library skills whose instructions were loaded and used to drive the audit:

- `performing-cryptographic-audit-of-application` — provided the weakness-category checklist
  (primitive/mode choice, IV/nonce handling, key management and lifecycle, storage of key material,
  side-channel and oracle exposure, serialization of crypto objects) used to structure the pass
  over `AesGcmDataProtector.java`.
- `implementing-aes-encryption-for-data-at-rest` — supplied the GCM rules the findings are judged
  against: never reuse a (key, nonce) pair, 96-bit random IVs, 128-bit tags, the bounded number of
  encryptions permitted per key under random IVs, and authentication of associated data. This is
  the skill that identifies SEC-01.
- `testing-for-sensitive-data-exposure` — guided the sweep for key/secret material reaching
  `toString()`, exception text, logs, hashes, or serialization streams, and for information leaked
  through error differentiation (SEC-03 and the section 6 checks on the generic exception and the
  redacted `toString()`).
- `exploiting-insecure-deserialization` — used to test the Java-serialization markers that are
  present (`serialVersionUID` on both the exception and `DestroyableAesKey`, a
  `private void writeObject`) against the absence of any deserialization sink.

Consulted by description only, then not applied (the code manages keys through a caller-supplied
ring and does not itself integrate a vault or a KMS): `implementing-secrets-management-with-vault`,
`implementing-envelope-encryption-with-aws-kms`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Per-key random-nonce budget set to the full NIST maximum and counted per instance | Medium | CWE-323 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:45-46` |
| SEC-02 | `DestroyableAesKey.equals()` zeroes key material it does not own and throws on destroyed keys | Low | CWE-664 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:420-437` |
| SEC-03 | `hashCode()` derives a 32-bit fingerprint from live AES key bytes | Low | CWE-200 | `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:440-445` |

## 5. Detailed Findings

### SEC-01: Per-key random-nonce budget set to the full NIST maximum and counted per instance

- **Severity:** Medium
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:45-46`

**Vulnerable code:**

```java
    // NIST's limit for independently generated random GCM IVs under one key.
    private static final long MAX_ENCRYPTIONS_PER_KEY = 0xffff_ffffL;
```

The gate that consumes this budget is per-instance state
(`src/main/java/com/example/security/crypto/AesGcmDataProtector.java:334-336` and `:342-351`):

```java
    private static final class KeyEntry {
        private final byte[] bytes;
        private final AtomicLong encryptionCount = new AtomicLong();
```

```java
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

and is reached from `encrypt()` on every sealing call
(`src/main/java/com/example/security/crypto/AesGcmDataProtector.java:157-162`):

```java
            KeyEntry entry = keys.get(activeKeyId);
            if (!entry.reserveEncryption()) {
                throw new DataProtectionException();
            }

            byte[] nonce = new byte[NONCE_BYTES];
```

**Why it is a problem:**

`encrypt()` draws each nonce at random (`random.nextBytes(nonce)`, line 163), so the safety of the
whole scheme rests on never repeating a (key, nonce) pair. NIST SP 800-38D caps independent random
IVs at `2^32` invocations per key precisely because the collision probability for random 96-bit
nonces becomes uncomfortable beyond that point. This code adopts the ceiling verbatim *and*
enforces it with a counter that is reset to zero every time the object is constructed. The
consequence is that the ceiling measures per-instance, per-lifetime usage, while the real budget is
per-key across every process that holds that key:

- N replicas that share the active key ID each get their own fresh `2^32 - 1` allowance, so the
  fleet's true allowance is N × 2^32 — the bound is exceeded before any single instance trips its
  limit, and no instance can observe the others.
- Autoscaled or containerised services that restart constantly never approach the counter limit at
  all: the counter resets on each boot while the *key* keeps accumulating nonces across boots. In
  that very common topology the check effectively never fires, no matter how much the key is used.
- Setting the ceiling at the absolute maximum leaves zero margin for exactly this undercounting.
  There is no "rotate soon" band below the hard stop; the counter can only ever fire at the last
  permitted nonce, by which time the accumulated birthday probability from a fleet-wide undercount
  is already the risk being accepted.

The failure mode when a nonce does repeat under one key is not graceful: two envelopes sharing a
nonce under the same key leak the XOR of their plaintexts and, because the GHASH subkeys are
identical, expose the authentication key, which allows existential forgery of new ciphertexts that
decrypt successfully. That is a confidentiality *and* integrity break in a component whose entire
job is to provide both, which is why this is rated Medium despite requiring very heavy key use to
trigger. The project's own `README.md` acknowledges the gap — "the component also enforces that
limit atomically **within each instance**" and asks the operator to "track total encryptions across
all processes and deployments" — which is honest documentation, but a documented caveat is not an
enforced control. A safety valve that cannot fire in the deployments where the bound is actually
approached should be set low enough that the limit is hit *because* of the undercount, not despite
it.

**Fix:**

Treat the per-instance counter as a lower bound on true key usage and size the ceiling so the
undercount from restarts and replicas is absorbed — rotate long before the mathematical limit, and
make the exhaustion path explicit so callers can rotate instead of silently hitting a wall:

```java
    // Random 96-bit nonces must never repeat under one key. This counter is per
    // instance, so the ceiling has to absorb every restart and every replica
    // that shares the key id: use a conservative fraction of NIST's 2^32 bound
    // and rotate well before the mathematical limit.
    private static final long MAX_ENCRYPTIONS_PER_KEY = 1L << 28;
```

```java
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

and surface the exhaustion as a rotation signal rather than an opaque crypto failure, so that
reaching the (now conservative) ceiling drives a key-ring change instead of an outage that tempts
an operator to work around it by raising the constant:

```java
            KeyEntry entry = keys.get(activeKeyId);
            if (!entry.reserveEncryption()) {
                throw new DataProtectionException(
                        "Active key has reached its encryption budget and must be rotated");
            }

            byte[] nonce = new byte[NONCE_BYTES];
```

Two complementary hardening measures are worth taking with this change: (a) back the budget with
usage that survives restarts (an external counter, or key-usage telemetry from the KMS/secret
manager) so the fleet-wide truth is visible and rotation can be triggered by real consumption
rather than by the local lower bound; (b) if the deployment cannot guarantee per-key usage bounds,
switch from random 96-bit IVs to the deterministic per-key invocation-counter construction of
SP 800-38D §8.2.2, which turns nonce uniqueness into a monotonic-counter obligation instead of a
birthday-bound one — in which case that counter must be persisted, not held in memory.

### SEC-02: `DestroyableAesKey.equals()` zeroes key material it does not own and throws on destroyed keys

- **Severity:** Low
- **CWE:** CWE-664: Improper Control of a Resource Through its Lifetime
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:420-437`

**Vulnerable code:**

```java
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

**Why it is a problem:**

`equals()` is expected to be a side-effect-free predicate. This implementation mutates two buffers
that are not its own, and both mutations rest on unsafe assumptions about someone else's contract:

- `theirs` is whatever the *other* `SecretKey` implementation's `getEncoded()` chose to hand back.
  For `DestroyableAesKey` (which returns `bytes.clone()`, line 403) and for `SecretKeySpec` that
  happens to be a clone, so the fill is harmless. But `SecretKey` does not require a copy: an
  implementation may return its internal array (custom providers, HSM/PKCS#11 stubs, and most
  non-JDK key wrappers do whatever is convenient for them). For such a key, `a.equals(b)` silently
  overwrites `b`'s live secret with zeros. `b`'s owner never asked for that and cannot detect it —
  `isDestroyed()` on that object still reports false while `getEncoded()` now returns 32 zero
  bytes, so the next cipher initialised with `b` runs under an all-zero AES key and produces
  ciphertext that looks perfectly valid. Destroying a resource outside your own lifetime control is
  the defect here; the erasure discipline that is correct for `mine` does not transfer to a buffer
  you do not own.
- `getEncoded()` on `this` is `synchronized` and throws
  `IllegalStateException("Key is unavailable")` once the key has been destroyed (lines 399-403). A
  destroyed key therefore makes `equals()` *throw* rather than return `false`, violating the
  `Object.equals` contract (it must not throw and must be consistent) and turning an ordinary
  comparison into an unexpected failure — inside a `HashSet.contains` or `List.indexOf`, say.

Both are latent rather than reachable today. `DestroyableAesKey` is a `private static final` nested
class; its only instances are created inside `encrypt()` (line 166) and `decrypt()` (line 212) and
passed straight to `Cipher.init`, and nothing in this source tree calls `.equals()` on it or uses
it as a hash-collection key (the duplicate-material check at
`src/main/java/com/example/security/crypto/AesGcmDataProtector.java:94-99` deliberately compares
raw `byte[]` with `MessageDigest.isEqual` instead). The finding is that this code is a loaded gun:
the class is `Serializable`, is a `SecretKey`, and behaves in a way that will destroy or blow up the
first key anyone outside these two methods compares.

**Fix:**

Make the comparison non-destructive for foreign material and total for destroyed keys. Zero only
buffers this object owns, and treat a missing key as "not equal" rather than an exception:

```java
        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof SecretKey)) {
                return false;
            }
            byte[] mine = null;
            try {
                mine = getEncoded();
                byte[] theirs = ((SecretKey) other).getEncoded();
                return theirs != null
                        && theirs.length == AES_KEY_BYTES
                        && MessageDigest.isEqual(mine, theirs);
            } catch (RuntimeException unavailable) {
                // A key that cannot expose its bytes is simply not equal to this one.
                return false;
            } finally {
                if (mine != null) {
                    Arrays.fill(mine, (byte) 0);
                }
            }
        }
```

The `finally` block erases only `mine`, which this object cloned for itself; `theirs` is left
untouched, because its owner decides when that key dies. If the intent was to scrub every transient
copy of a secret, note that this method cannot honour that goal for another class's array, and the
comparison itself leaves copies it cannot erase inside `MessageDigest.isEqual`'s parameters —
another reason not to offer value equality on a key class at all.

### SEC-03: `hashCode()` derives a 32-bit fingerprint from live AES key bytes

- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/example/security/crypto/AesGcmDataProtector.java:440-445`

**Vulnerable code:**

```java
        @Override
        public synchronized int hashCode() {
            if (bytes == null) {
                return 0;
            }
            return Arrays.hashCode(bytes);
        }
```

**Why it is a problem:**

The class goes out of its way not to disclose key material: `toString()` returns
`"DestroyableAesKey[redacted]"` (line 449) and serialization is refused outright (lines 452-454).
`hashCode()` reopens that hole. `Arrays.hashCode(bytes)` is a cheap, deterministic function of the
secret key, so the 32-bit value is a key fingerprint available to anything that reads it — and
`hashCode()` is read implicitly and constantly: `HashMap`/`HashSet`/`Hashtable` bucketing,
`String.format`, assertion and error text built from a collection, debuggers, profilers, and heap
dumps. Once that value reaches a log line or a crash report, an attacker holding a candidate key
set (default or derived keys, a leaked provisioning template, a key whose entropy was lost during
provisioning) can confirm a candidate with a single comparison, with no crypto involved. That is a
practical offline verification oracle for exactly the class of weak or shared key material a KMS is
supposed to rule out.

The method also breaks the contract of the erasure design it sits inside. `hashCode()` is
value-based while `destroy()` nulls the bytes (lines 407-413), so an instance inserted into a hash
collection before `close()` reports a different hash afterwards and can never be found or removed
again — a collection entry that keeps a reference to the key object alive past the erasure the whole
class exists to guarantee. JDK key classes do not offer value-based hashing, which is the signal
here: a secret key object has no legitimate reason to need either `equals` or `hashCode` by value.

As with SEC-02 the exposure is latent — `DestroyableAesKey` is private and never enters a collection
in this tree — so this is hardening against a future caller rather than a live leak.

**Fix:**

Do not derive a value from key bytes. Fall back to identity semantics, so a value derived from the
secret can never exist:

```java
        @Override
        public int hashCode() {
            // Never derive a value from key bytes: the 32-bit digest of a secret key is a
            // verifiable fingerprint, and it reaches logs, assertions, collection
            // internals and heap dumps. Identity semantics only.
            return System.identityHashCode(this);
        }
```

If value equality from SEC-02 is kept, identity hashing makes the `equals`/`hashCode` pair
inconsistent — which is the right outcome for a secret-bearing class. In that case the cleanest
resolution is to remove both overrides and document that `DestroyableAesKey` must never be used as
a map key or compared by value.

## 6. Verified Controls and Checks With No Finding

The following were examined and are working as intended. Each is stated with the behaviour that
shows it, so the absence of a finding is auditable rather than assumed.

- **AEAD primitive and tag strength.** `AES/GCM/NoPadding` with
  `new GCMParameterSpec(TAG_BITS, nonce)` and `TAG_BITS = 128` (lines 34, 36-38, 168-170). No
  unauthenticated mode anywhere: no ECB, CBC-without-HMAC, raw CTR, DES/3DES, RC4, or
  MD5/SHA-1-based MAC. Searches for weak-algorithm identifiers returned nothing.
- **Nonce generation.** A fresh 12-byte nonce is generated per `encrypt()` call from a
  `SecureRandom` created in the constructor (lines 107, 162-163) and carried in the header for
  decryption. No static, derived, or reused nonce; no `Math.random()`, `java.util.Random`,
  `ThreadLocalRandom`, or time-based seeding exists in the source. The *budget* around this is
  SEC-01; the generation itself is correct. The nonce is zeroed after use (line 185).
- **AAD framing and domain separation.** `addAuthenticatedData` binds
  `int32be(len(purpose)) ‖ purpose ‖ header ‖ int32be(len(context)) ‖ context` (lines 300-305,
  using `ByteBuffer.allocate(Integer.BYTES).putInt(...)`). The 4-byte length prefixes make the
  framing injective, so a `purpose`/`context` pair cannot be re-split into a different pair that
  reproduces the same AAD byte string, and the header (magic, version, algorithm, key-ID length,
  key ID, nonce) is covered — binding the envelope's own routing data to the tag. `purpose` is
  fixed per instance and capped at 64 bytes; `context` is validated per call and capped at 64 KiB
  (lines 321-325).
- **No decryption oracle.** Every rejection path — bad length, bad magic, wrong version, wrong
  algorithm byte, bad key-ID length, unsafe key-ID characters, unknown key ID, tag mismatch,
  over-long plaintext, closed instance, exhausted budget — throws the same
  `DataProtectionException` with a single fixed message (lines 197-203, 209-224, 262-280, 308-312).
  Unknown key IDs additionally run a real decryption against a random per-instance `unknownKey`
  (lines 108-109, 211-224), so a missing key is not answerable faster or differently than a wrong
  key, removing the key-ID enumeration signal.
- **Exception design without information leakage.** `DataProtectionException` passes
  `(GENERIC_MESSAGE, null, false, false)` — no cause chain, no suppression, no stack trace — so
  neither message nor trace can reveal which check failed or any internal state. The tests assert
  the generic message and `getCause() == null`.
- **Input validation at the trust boundary.**
  `SAFE_IDENTIFIER = [A-Za-z0-9][A-Za-z0-9._/-]{0,63}` plus a US-ASCII byte-length re-check (lines
  47, 327-332) is applied to every key ID both at construction (line 86) and again on every parse
  (line 278), so a hostile envelope cannot smuggle control characters, over-long IDs, or non-ASCII
  encodings into the key-ring lookup or into anything an integrator might log.
  `Byte.toUnsignedInt` is used for the length field (line 269), and
  `input.remaining() < keyIdLength + NONCE_BYTES + TAG_BYTES` is checked before any read
  (lines 270-273), with a whole-envelope length ceiling applied *before* parsing (lines 197-201) —
  so `parseEnvelope` has no path to an unchecked `BufferUnderflowException` or to an allocation
  driven by attacker-controlled sizes. Every `RuntimeException` escaping the parse is folded into
  the generic exception (lines 288-290).
- **Resource-exhaustion bounds.** Plaintext capped at 16 MiB (`MAX_ALLOWED_PLAINTEXT_BYTES`,
  validated before encryption at line 151 and re-checked against the decrypted length at line 221),
  context at 64 KiB (lines 321-325), key ring at 32 entries (lines 70-71, 79-81), key ID and
  purpose at 64 bytes each. The decrypt upper bound is derived from `maxPlaintextBytes`, so a short
  header claiming a huge plaintext cannot force a large allocation.
- **Key material handling and lifetime.** The constructor clones every supplied key
  (`new KeyEntry(key.clone())`, line 100) so caller-side mutation cannot alter the ring, rejects
  non-256-bit material and duplicate IDs, and rejects duplicate *material* across IDs via a
  constant-time `MessageDigest.isEqual` compare (lines 94-99). Copies are destroyed if the
  constructor fails partway (lines 110-116). Per-operation keys are `DestroyableAesKey` instances
  destroyed in a `finally` after each cipher operation (lines 183-186, 233-235); `sealed` is zeroed
  in a `finally` (lines 178-180), and `ParsedEnvelope.destroy()` zeroes nonce and header (lines
  234-235, 362-377); `magic` and `keyIdBytes` scratch buffers are zeroed inside `parseEnvelope`
  (lines 264, 277). `close()` destroys every ring key, zeroes `unknownKey` and `purpose`, and sets
  `closed` under the write lock (lines 244-256).
- **Fail-closed lifecycle.** `encrypt`, `decrypt`, and `close` take the read/write halves of one
  `ReentrantReadWriteLock` and call `ensureOpen()` before touching key state (lines 154-156,
  205-207, 244-251, 308-312), so a closed instance can neither seal nor open data and `close()`
  cannot interleave with an in-flight operation. The ring map is `Collections.unmodifiableMap`
  (line 118).
- **Serialization posture.** `DestroyableAesKey.writeObject` throws
  `NotSerializableException("Secret keys cannot be serialized")` (lines 452-454), so a key cannot be
  written out even if an enclosing object is made serializable. Reviewed against
  `exploiting-insecure-deserialization`: the codebase contains no `ObjectInputStream`, no
  `readObject`/`readResolve`, no Jackson/Gson/Fastjson/XStream deserialization, no YAML loading, no
  JNDI lookup, and no reflection on attacker-controlled class names. The fixed `serialVersionUID` on
  `DataProtectionException` is not a risk here because nothing deserializes it and the class carries
  no fields. The serialization markers that do exist are the defensive `writeObject` block, not a
  gadget surface.
- **No injection, command, or filesystem sinks.** No `Runtime.exec`, `ProcessBuilder`, shell
  invocation, file/socket/HTTP I/O, SQL/LDAP/XPath/XML parsing, template or expression evaluation,
  or `File`/`Path` construction from input exists in the reviewed sources; `purpose` and key IDs are
  confined to AAD bytes and map lookups.
- **No secret material in code, and no sensitive telemetry.** No key literals, base64 blobs,
  passwords, or API tokens appear anywhere; keys arrive only from the caller-supplied ring, which
  `README.md` correctly attributes to a secret manager/KMS. There is no `Logger`, `System.out`,
  `System.err`, `printStackTrace`, or environment-variable read in the source, so nothing can log
  plaintext, key bytes, or AAD — the `toString()` redaction (line 449) is consistent with that. The
  gap is SEC-03's `hashCode`.
- **Platform-only cryptography.** The implementation uses only JCA/JCE (`Cipher`,
  `GCMParameterSpec`, `SecretKey`, `MessageDigest.isEqual`, `SecureRandom`). No hand-rolled
  primitives, no hand-rolled MAC or padding, no hand-rolled tag comparison — and the two places
  where secrecy-sensitive bytes *are* compared (`magic` at line 263, duplicate key material at line
  95) both use `MessageDigest.isEqual`, the constant-time comparison the situation calls for. The
  checks that are not secret-dependent (version byte, algorithm byte, line 265-266) use ordinary
  comparisons, which is appropriate.
- **Behaviour reviewed against general OWASP/CWE knowledge, where no library skill applied.** Two
  areas had no matching specialised skill in the library and were therefore checked against general
  practice rather than a loaded skill: (1) crypto-object lifecycle and zeroisation discipline
  (`DestroyableAesKey`, `ParsedEnvelope.destroy()`, `sealed`/`nonce`/`magic` zeroing, the
  constructor's failure-path cleanup) — reviewed as CWE-664 resource-lifetime reasoning; this
  produced SEC-02 and informed SEC-03, and the copy/erase coverage in `encrypt()`, `decrypt()`,
  `parseEnvelope()`, and `close()` is otherwise complete. (2) Key-rotation ergonomics for a
  versioned envelope format with in-band key selection — no library skill covers envelope-format
  crypto versioning with in-band key IDs; against general practice the design is correct, since
  `activeKeyId` and the ring are fixed at construction from trusted server-side configuration and
  the key ID taken from an attacker-supplied envelope is used only as a lookup into that
  already-trusted map: an unknown ID can never select attacker-chosen key material, it selects the
  random `unknownKey` and then fails authentication and the `!knownKey` check (lines 209-224).
  `close()` provides a hard stop, and rotation is expressed by rebuilding the instance with a new
  ring rather than mutating it in place.
