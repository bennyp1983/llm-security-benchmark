# Security Review: data-crypto

## 1. Executive Summary

`data-crypto` is a dependency-free Java 17 library that encrypts byte[] / text payloads with AES-256-GCM in a versioned envelope (`EDC1` | version | keyIdLen | keyId | nonce | ciphertext | tag), resolves keys by externally supplied key id, and loads key material from environment variables, a PKCS#12 keystore, or a passphrase-derived key.

The core cryptographic design is sound and, unusually for generated code, deliberately hardened: AEAD-only API, 96-bit CSPRNG nonces with a per-key nonce budget, envelope header bound as additional authenticated data, constant-time magic comparison, a decoy key that removes the key-id oracle, fail-closed configuration, aggressive key wiping, a single generic exception with no cause or stack trace, and a logging funnel that masks secret-bearing values. No weak cipher, mode of operation, insecure RNG, hardcoded key, or untrusted deserialization sink exists anywhere in the source.

Three findings are reported, all **Low** severity, none of which break the confidentiality of the ciphertext under default configuration:

- **SEC-01** — the PBKDF2-HMAC-SHA256 work-factor *floor* (210,000) sits below current OWASP guidance (600,000), so a configured value can weaken derived keys ~2.9×.
- **SEC-02** — the key-file guards are not atomic with the read that follows them (`Files.readAllBytes` follows symlinks after a `NOFOLLOW_LINKS` check), and only the *immediate* parent directory is checked for world-writability.
- **SEC-03** — the key-file ownership check decides trust from `System.getProperty("user.name")`, a mutable JVM property rather than the process's effective uid.

SEC-02 and SEC-03 are defense-in-depth weaknesses in a gate whose preconditions (local write access adjacent to the key file, or control of JVM launch arguments) already imply substantial host control; they are reported because that gate is an explicitly advertised control in the code comments and `README.md`, and both make it weaker than documented. Remediating all three is a small, low-risk change.

**Findings: 0 Critical, 0 High, 0 Medium, 3 Low.**

Review was performed statically by reading every source file; nothing was executed, built, or imported.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/example/crypto/AesGcmDataCipher.java` | Core cipher; envelope encode/parse and GCM operations | AES-256-GCM only, 128-bit tag, random 96-bit nonce, header + AAD bound via `updateAAD`, size bounds before allocation, decoy-key decryption for unknown key ids, per-key nonce budget, plaintext/nonce wiping |
| `src/main/java/com/example/crypto/DataCipher.java` | Public encryption interface | AEAD-only contract; documents that unauthenticated modes are not offered and that failures are generic |
| `src/main/java/com/example/crypto/SecretKeyProvider.java` | Key-lookup interface by key id | Fail-closed contract: unknown/invalid id returns `null`, never a substituted default key |
| `src/main/java/com/example/crypto/KeySetSecretKeyProvider.java` | Immutable in-memory key set | Defensive copy + validation at construction, `MAX_KEYS = 64`, active key must exist, `close()` destroys all key material |
| `src/main/java/com/example/crypto/ZeroizableSecretKey.java` | Erasable AES-256 `SecretKey` implementation | Owns its only key copy, `destroy()` actually zeroes it, `getEncoded()` returns `null` after destruction, `toString`/`hashCode` leak nothing, Java (de)serialization refused |
| `src/main/java/com/example/crypto/KeyId.java` | Validation of externally supplied key ids | Allowlist `[A-Za-z0-9._-]{1,64}`; rejects path traversal, whitespace, control bytes, non-ASCII |
| `src/main/java/com/example/crypto/KeyMaterial.java` | CSPRNG key/byte generation, configured-key import | Single shared `SecureRandom`, strict Base64 decoder, exactly 32 bytes required, all-zero key rejected |
| `src/main/java/com/example/crypto/PassphraseKeyDerivation.java` | PBKDF2 key derivation from a passphrase | Platform `PBKDF2WithHmacSHA256`, iteration/salt/passphrase bounds, wipes `PBEKeySpec`, derived bytes and caller passphrase. **SEC-01** |
| `src/main/java/com/example/crypto/EnvironmentKeySource.java` | Loads key set from `APP_DATA_KEY_*` env vars | Rejects hostile id/variable names, refuses incomplete config, destroys half-loaded keys on any failure |
| `src/main/java/com/example/crypto/KeyStoreKeySource.java` | Loads key set from a PKCS#12 keystore | Reads store through `SecureFiles`, password also verifies store MAC, wipes password buffer on every path, generic message on wrong password |
| `src/main/java/com/example/crypto/SecureFiles.java` | Permission gate for files holding key material | Refuses symlinks/non-regular files, oversized files, group/other access bits, non-owner files, world-writable parent; fails closed without POSIX attributes. **SEC-02, SEC-03** |
| `src/main/java/com/example/crypto/Bytes.java` | Byte/char helpers | `wipe` helpers, `constantTimeEquals` via `MessageDigest.isEqual`, UTF-8 decode in strict `REPORT` mode |
| `src/main/java/com/example/crypto/CryptoLog.java` | Single logging funnel | Only non-secret metadata logged; `masked()` renders secret-bearing values as `[redacted N bytes]` |
| `src/main/java/com/example/crypto/CryptoException.java` | Single public exception type | Generic message, `suppressed = false`, `writableStackTrace = false` — no cause chain, no stack trace leakage |
| `src/test/java/com/example/crypto/AesGcmDataCipherTest.java` | Cipher behaviour tests | Asserts tamper/truncation/bit-flip rejection, AAD binding, nonce uniqueness, size limits, passphrase wiping, key rotation, buffer wiping |
| `src/test/java/com/example/crypto/KeyHandlingTest.java` | Key handling/config tests | Asserts key-length/all-zero rejection, serialization refusal, hostile key-id and env-value rejection, symlink and permission refusal, weak KDF-parameter rejection. Contains one literal NUL byte (line 137), which makes `grep`/`ripgrep` classify it as binary (see §6) |
| `pom.xml` | Maven build definition | Java 17, zero runtime dependencies, test-scoped JUnit 5.10.2, pinned plugin/dependency versions |

Out of scope: `target/` (compiled build output) and harness metadata (`prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`).

## 3. Skills Applied

- **`review-code-for-security-vulnerabilities`** — the router skill that structured this review: determine what the code actually does first, then select specialised skills by name/description match, then apply them and report with CWE ids and `file:line` evidence. Applied to the whole component.
- **`performing-cryptographic-audit-of-application`** (including `references/standards.md`) — applied to `AesGcmDataCipher.java`, `KeyMaterial.java`, `Bytes.java`, `ZeroizableSecretKey.java`, `KeyStoreKeySource.java`: primitive and mode selection, IV/nonce generation and reuse limits, key length and storage, key destruction, tag verification order, and constant-time comparison of authentication-relevant bytes.
- **`implementing-aes-encryption-for-data-at-rest`** — applied to `AesGcmDataCipher.java` (envelope layout, AAD binding, tag handling, nonce budget) and directly to `PassphraseKeyDerivation.java` (key-derivation work factor, salt length/uniqueness, passphrase handling). This skill's own guidance — "PBKDF2: minimum 600,000 iterations as of 2024" — is the yardstick for **SEC-01**.
- **`exploiting-insecure-deserialization`** — matched on `javax.crypto.SecretKey` extending `java.io.Serializable`, and on `KeyStoreKeySource.java` parsing an externally supplied file. No finding: the only `ObjectInputStream`/`ObjectOutputStream` members in the source are the deliberate refusals at `ZeroizableSecretKey.java:126` and `ZeroizableSecretKey.java:130`, and no `ObjectInputStream.readObject()` sink exists in `src/` (verified by search and full read). Keystore bytes are parsed by the JDK PKCS#12 implementation, not by Java serialization, and only after `SecureFiles` gating and MAC verification with the supplied password.
- **General OWASP / CWE fallback review** — no skill in the library covers secret-file filesystem guards, key-material lifecycle hygiene, error/log information leakage, or supply-chain review of the build file, so these were audited against general knowledge: OWASP A01/A02/A05 (broken access control, cryptographic failures, security misconfiguration) and CWE-367, CWE-807, CWE-916, CWE-209/CWE-532. This fallback produced **SEC-02** and **SEC-03** and the verified-control list in §6.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | PBKDF2 work-factor floor below current guidance for HMAC-SHA256 | Low | CWE-916 | `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:36` |
| SEC-02 | Key-file checks are not atomic with the read; only the immediate parent is checked | Low | CWE-367 | `src/main/java/com/example/crypto/SecureFiles.java:62` |
| SEC-03 | Key-file ownership decided from the mutable `user.name` system property | Low | CWE-807 | `src/main/java/com/example/crypto/SecureFiles.java:92` |

## 5. Detailed Findings

### SEC-01: PBKDF2 work-factor floor below current guidance for HMAC-SHA256

- **Severity:** Low
- **CWE:** CWE-916: Password Hash Computations with Insufficient Cost
- **Location:** `src/main/java/com/example/crypto/PassphraseKeyDerivation.java:36`

**Vulnerable code:**

```java
// PassphraseKeyDerivation.java:35-39
    /** OWASP-recommended floor for PBKDF2-HMAC-SHA-256. */
    public static final int MIN_ITERATIONS = 210_000;

    /** Default work factor; raise it as hardware improves. */
    public static final int DEFAULT_ITERATIONS = 600_000;
```

The floor is the only thing standing between a configuration value and the work factor actually used, enforced here:

```java
// PassphraseKeyDerivation.java:94-97
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be "
                        + MIN_ITERATIONS + "-" + MAX_ITERATIONS);
            }
```

**Why it is a problem:** the derived key is the sole secret protecting data at rest on this path — the envelope format carries no salt or iteration count, and the ciphertext is GCM-authenticated, so the primary attack on a stolen ciphertext store is offline passphrase guessing whose rate is exactly `1 / iterations`. OWASP's Password Storage Cheat Sheet sets 600,000 iterations as the minimum for PBKDF2-**HMAC-SHA256**; 210,000 is the figure for PBKDF2-HMAC-SHA-**512** (higher per-iteration cost, so a lower count buys equivalent work). The code applies the SHA-512 number to a SHA-256 instantiation — the class javadoc at `PassphraseKeyDerivation.java:20-21` repeats this misattribution ("OWASP's 2023 floor for PBKDF2-HMAC-SHA-256") — so the enforced floor admits a work factor ~2.9× weaker than guidance. Severity is Low rather than higher because the out-of-the-box `DEFAULT_ITERATIONS` (600,000) is compliant: real exposure requires a caller or operator to pass a lower value from configuration, which the public `deriveKey(char[], byte[], int)` overload and `MIN_ITERATIONS` constant actively invite. The DoS guard at line 94 also means a fix is fail-closed rather than silently downgrading anything.

**Fix:** raise the floor to the SHA-256 guidance value and leave headroom in the default:

```java
    /**
     * OWASP floor for PBKDF2-HMAC-SHA-256. 210 000 is the floor for
     * PBKDF2-HMAC-SHA-512, whose iterations are ~3x more expensive; for
     * SHA-256 the 2024 guidance is 600 000.
     */
    public static final int MIN_ITERATIONS = 600_000;

    /** Default work factor; raise it as hardware improves. */
    public static final int DEFAULT_ITERATIONS = 1_000_000;
```

Operationally: because the check rejects rather than clamps, any deployment configured between 210,000 and 599,999 will now fail closed at startup with `IllegalArgumentException` — ship that with a configuration-migration note rather than silently accepting values the code itself documents as weak. The iteration tests in `KeyHandlingTest.java` reference `MIN_ITERATIONS` symbolically, so they keep passing (they will simply run ~3× slower); the comment at `KeyHandlingTest.java:379` ("below the OWASP floor"), the field comment at `PassphraseKeyDerivation.java:35` and the javadoc claim at `PassphraseKeyDerivation.java:20-21` should be corrected at the same time.

### SEC-02: Key-file checks are not atomic with the read; only the immediate parent is checked

- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/crypto/SecureFiles.java:62`

**Vulnerable code:**

```java
// SecureFiles.java:51-62
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

and:

```java
// SecureFiles.java:104-109
        PosixFileAttributeView view = Files.getFileAttributeView(parent, PosixFileAttributeView.class);
        if (view == null) {
            return; // non-POSIX filesystem; the file check above already failed closed
        }
        Set<PosixFilePermission> permissions = view.readAttributes().permissions();
        if (permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
```

**Why it is a problem:** four separate path-based lookups (`isRegularFile`, `size`, the attribute view in `requireOwnerOnlyAccess`, the parent check) are followed by a fifth lookup, `Files.readAllBytes(file)`, which resolves the path *again* and, unlike the earlier probes, follows symlinks. The comment at lines 51-52 names exactly this hazard ("or be swapped between check and read") but nothing in the implementation prevents it: every check validates whatever the path named at that instant, and the bytes read are those of whatever the path names at line 62. A local principal holding write permission on the containing directory can replace `data.key` inside that window, and all four gates are then meaningless — the file the process actually loads is the attacker's, not the file that was vetted. The same gap in `requireSafeParent` widens the reach: only `file.getParent()` is inspected for `OTHERS_WRITE`, so a world-writable *ancestor* (`/var/app/` at 0777 holding a properly mode-0755 `keys/`) lets an attacker rename the whole key directory aside and substitute a directory of their own, defeating the control that exists precisely to stop replacement. `requireSafeParent` also returns silently when the attribute view is unavailable, so on non-POSIX mounts the directory half of the gate is simply absent while the file half fails closed.

The realistic consequence is key substitution rather than key disclosure: the application encrypts new records under, and can decrypt attacker-supplied envelopes with, key material the attacker chose, i.e. a plaintext oracle over the stored ciphertext set. The preconditions keep this at Low: exploiting it needs local write access in or above the key directory, and the strongest version of the attack (an unprivileged user namespace plus a FUSE/overlay mount, where the attacker also dictates reported ownership and mode) bypasses the ownership and permission gates outright. It is reported because this function is the library's advertised key-file control — `README.md` and the class doc claim a key file cannot be "reached through a symlink" or "sitting in a world-writable directory" — and the guarantee is weaker than documented.

**Fix:** open the file once without following the final symlink, then perform the size check and the read through that same descriptor, so the vetted object and the read object are necessarily identical; and validate every directory on the path rather than just the parent:

```java
    static byte[] readPrivateFile(Path path) {
        Path file = path.toAbsolutePath().normalize();
        requireSafeAncestors(file);
        try (FileChannel channel = FileChannel.open(file,
                StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            // Every check below and the read itself act on this already-open
            // O_NOFOLLOW descriptor: the file cannot be swapped for another
            // object (or a symlink) between check and read.
            requireOwnerOnlyAccess(file);
            long size = channel.size();
            if (size == 0 || size > MAX_KEY_FILE_BYTES) {
                throw new IllegalStateException("key file size is out of range: " + file);
            }
            ByteBuffer buffer = ByteBuffer.allocate((int) size);
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw new IllegalStateException("key file shrank during read: " + file);
                }
            }
            return buffer.array();
        } catch (IOException e) {
            CryptoLog.configProblem("unable to read key file: " + file);
            throw new UncheckedIOException("unable to read key file", e);
        }
    }

    /** No directory on the path may be writable by anyone other than the owner. */
    private static void requireSafeAncestors(Path file) throws IOException {
        for (Path dir = file.getParent(); dir != null; dir = dir.getParent()) {
            requireSafeParent(dir);
        }
    }
```

`requireSafeParent` should also stop returning silently when `view == null` if the platform is expected to support POSIX attributes — an unverifiable directory should fail closed, as `requireOwnerOnlyAccess` already does for the file itself. Where the key path is not operator-controlled (shared hosts, containers with writable image layers), pair this with an integrity check on the loaded key (expected key id plus a published SHA-256 of the material) — no in-process permission check can compensate for an attacker who can already write the key directory before startup.

### SEC-03: Key-file ownership decided from the mutable `user.name` system property

- **Severity:** Low
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/example/crypto/SecureFiles.java:92`

**Vulnerable code:**

```java
// SecureFiles.java:90-96
        UserPrincipal me = file.getFileSystem()
                .getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name", ""));
        if (!attrs.owner().equals(me)) {
            CryptoLog.configProblem("key file is not owned by the current user: " + file);
            throw new IllegalStateException("key file must be owned by the current user: " + file);
        }
```

**Why it is a problem:** `user.name` is an ordinary, mutable JVM system property that the JDK seeds from the operating system at startup — it is not the process's effective uid. It is overridden by `-Duser.name=<whoever>` on the command line, by any `System.setProperty` call in-process (including inside a library), and by whatever the launcher script or application-server configuration supplies. The security-critical question "does this key file belong to *me*?" is therefore answered using a value controllable from the very trust boundary the check is meant to police, and passing it makes the library accept key material owned by a different principal. That matters most on the mounts where the ownership gate is actually load-bearing: NFS, CIFS/SMB, FUSE and container bind mounts, where mode bits are advisory or server-supplied and ownership is nominal, so the mode-bit loop above cannot be trusted either and "owner == me" is the remaining signal — a signal defeated by setting one property before launch. Passing `""` (the default when the property is unset) to `lookupPrincipalByName` additionally throws `UserPrincipalNotFoundException`, so a stripped environment turns this into a startup failure whose message is a filesystem lookup error rather than a clear ownership-control failure. This is not independently exploitable — an attacker able to set JVM launch properties or inject code into the process already has broad control, and on a normal POSIX filesystem a `0600` file owned by someone else is unreadable regardless — so severity is Low. It is still a CWE-807 defect: a security decision resting on attacker-influenceable input, which silently converts an advertised control into an advisory one.

**Fix:** compare numeric identities derived from the operating system instead of a property — the file's owner uid against this process's effective uid — and keep the existing fail-closed behaviour when neither is available:

```java
        // The effective uid is not attacker-settable, unlike the user.name
        // property, which -Duser.name=... and System.setProperty can change.
        long ownerUid = (long) Files.getAttribute(file, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        long ourUid = new com.sun.security.auth.module.UnixSystem().getUid();
        if (ownerUid != ourUid) {
            CryptoLog.configProblem("key file is not owned by the current user: " + file);
            throw new IllegalStateException("key file must be owned by the current user: " + file);
        }
```

`unix:uid` is supported by the default `UnixFileSystemProvider` (read it with `NOFOLLOW_LINKS`, unlike `Files.getOwner`, which follows links); if either lookup is unavailable, let the resulting `IOException`/`UnsupportedOperationException` propagate to the existing fail-closed handler rather than falling back to the property. If a portable expected-owner value is genuinely required, take it from operator-supplied trusted configuration (explicitly documented as such) rather than from a JVM property that startup tooling and any in-process code can rewrite.

## 6. Verified Controls and Checks With No Finding

Confirmed by reading every source file in full, plus targeted searches; the code was never executed or built.

- **Algorithm and mode selection** — the only cipher requested is `AES/GCM/NoPadding` with a 128-bit tag (`AesGcmDataCipher.java:166`, `AesGcmDataCipher.java:243`); no ECB, unauthenticated CBC, stream cipher, MAC-then-encrypt construction, or hand-rolled mode exists (`DataCipher.java` restricts the public API to AEAD).
- **GCM nonce handling** — a fresh 12-byte nonce per encryption from the shared `SecureRandom` (`AesGcmDataCipher.java:162`, `KeyMaterial.java:22`), never derived from a counter or clock; a per-key nonce budget is enforced by a check-and-increment `AtomicLong.incrementAndGet` (`AesGcmDataCipher.java:427`), so no two threads claim the same draw; the nonce is wiped after use.
- **Header/domain separation via AAD** — both the envelope header and the caller's AAD are fed to `updateAAD` on encrypt (`AesGcmDataCipher.java:167-168`) and decrypt (`AesGcmDataCipher.java:244-245`), so version and key id cannot be rewritten to re-route a ciphertext without tag failure.
- **No key-id oracle** — decryption with an unknown key id still performs a full GCM attempt against an internally generated decoy key (`AesGcmDataCipher.java:238`, `AesGcmDataCipher.java:110`), removing the timing/error discriminator between "unknown id" and "wrong key".
- **Authentication before trust, constant-time where it matters** — length, magic and version are validated before any key lookup or decryption, magic bytes compared with `MessageDigest.isEqual` (`Bytes.java:37-38`), and plaintext is used only after the tag verifies.
- **Denial-of-service and allocation bounds** — `maxPlaintextBytes` (1 MiB default, 64 MiB hard ceiling) enforced on both encrypt (`AesGcmDataCipher.java:150`) and decrypt (`AesGcmDataCipher.java:254`) before allocation, envelope minimum-length check (`AesGcmDataCipher.java:218`), ≤64 keys, ≤256 KiB key files, `MAX_ITERATIONS` cap on the KDF, and PBKDF2 passphrase/salt length bounds.
- **Untrusted-input validation** — externally supplied key ids restricted to the allowlist `[A-Za-z0-9._-]{1,64}` (`KeyId.java:30`), rejecting path traversal, whitespace, control characters and non-ASCII; strict (non-MIME, non-padding-tolerant) Base64 requiring exactly 32 non-zero bytes for imported keys; UTF-8 decoded with `CodingErrorAction.REPORT` (`AesGcmDataCipher.java:321`) so malformed input fails rather than being silently replaced.
- **No insecure deserialization** — the library never calls `ObjectInputStream.readObject()`; `ZeroizableSecretKey` explicitly refuses both directions (`writeObject` at `:126`, `readObject` at `:130` throw `NotSerializableException`) precisely because `SecretKey` extends `Serializable`, and `KeyHandlingTest.keyMaterialCannotBeSerialized` asserts no key bytes reach the stream.
- **Key-material hygiene** — `ZeroizableSecretKey` owns its single copy and genuinely zeroes it on `destroy()`, returns `null` from `getEncoded()` afterwards, keeps `destroy`/`isDestroyed`/reads synchronized, and renders only `ZeroizableSecretKey[AES-256, destroyed=…]`; wiping is complete on the paths traced: `PBEKeySpec.clearPassword()`, derived bytes and caller passphrase (`PassphraseKeyDerivation.java:111`, `:114`), keystore password (`KeyStoreKeySource.java:107`), half-loaded keys on any failure (`EnvironmentKeySource.java:99`, `KeyStoreKeySource.java:104`), and nonce/plaintext buffers in the cipher.
- **Randomness** — one `SecureRandom` instance for all key, salt and nonce generation; no `java.util.Random`, `Math.random()`, `setSeed`, or timing-derived randomness anywhere in `src/`.
- **No hardcoded credentials or weak primitives** — searching `src/` for `MD5`, `SHA-1`, `DES`, `RC4`, `Blowfish`, `ECB`, `new Random`, `setSeed`, `Math.random`, `currentTimeMillis`/`nanoTime` and private-key blocks returned only documentation comments and the test-suite's dummy passphrase/keystore values; no production key, password, token or API literal exists.
- **Error and log information leakage** — one public exception type constructed with no cause and no stack trace (`CryptoException.java`), a single generic decrypt message, key material and configured secrets routed only through `CryptoLog.masked()` which emits `[redacted N bytes]`, and negative tests asserting that malformed-key and wrong-password messages do not echo the offending value.
- **Fail-closed configuration** — missing active id, missing/extra key material, invalid key ids, oversized key sets, destroyed keys, absent POSIX attributes, group/other-readable key files and non-owner-owned key files all abort startup rather than degrading to a default.
- **Filesystem gates that do hold** — the `NOFOLLOW_LINKS` regular-file refusal, the 1–262 144-byte size bound, the group/other `rwx` refusal, the non-POSIX fail-closed branch, and the immediate-parent `OTHERS_WRITE` refusal were each verified present and reached in the correct order (see SEC-02 for the residual TOCTOU/ancestor-chain gap).
- **Test suite asserts the security properties** (read, not executed) — ciphertext/tag bit-flips, truncations, reordered and re-keyed envelopes, AAD mismatch, nonce non-reuse, symlink and permission refusals, serialization refusal, hostile env-var names and values, sub-floor iteration counts, and buffer-wiping postconditions.
- **Build/supply-chain hygiene** — `pom.xml` declares zero runtime dependencies (everything used is JDK), test-scoped JUnit 5.10.2, Java 17, and pinned versions, so the library adds no transitive CVE surface; no plugins execute remote code beyond compile/test.
- **Residual risks that the `README.md` already discloses honestly** (deliberately *not* counted as findings, since they are documented design boundaries, not defects): environment variables as a key source are readable via `/proc/<pid>/environ` and inherited by children, and the JVM's `String` copies cannot be wiped (`EnvironmentKeySource` wipes only its own copies); keys necessarily reside in heap while in use, so a heap dump or swap image taken before `destroy()` may contain material; an externally supplied key id lets a caller choose which configured key a ciphertext is tried against, mitigated as described above; and the nonce budget is enforced per process rather than globally, so two processes must not share a key. Prefer `KeyStoreKeySource`, a KMS/HSM, disabled core dumps and encrypted swap where those boundaries matter.
- **One review-process note, not a vulnerability** — `src/test/java/com/example/crypto/KeyHandlingTest.java` contains a single raw NUL byte inside the string literal at line 137 (`KeyId.isValid("v1\0")`, an intentional hostile-input case). Because of that byte, `grep` and `ripgrep` classify the file as binary and **silently skip it** during default pattern scans, so secret/weak-primitive sweeps that look clean may never have inspected this file; it was reviewed by full read instead. If the repo relies on grep-based scanning, prefer `"\u0000"` in that literal (with `grep -a` as a belt-and-braces measure) so the file stays text to tooling.
