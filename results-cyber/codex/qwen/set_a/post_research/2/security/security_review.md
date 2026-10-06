# Security Review: secure-data-crypto

## 1. Executive Summary
`secure-data-crypto` is a JDK 17 library for AES-256-GCM encryption, versioned key rotation, password-wrapped keys, PKCS#12 and file/environment key sources, and restrictive parsing and filesystem handling. The review was static only: no source code was executed, built, installed, or imported.

Five vulnerabilities were identified. The most directly exploitable is a test-time OS command injection caused by concatenating a filesystem path into `sh -c`. The production cryptography also accepts a PBKDF2-HMAC-SHA256 work factor below current OWASP guidance and does not enforce a per-key AES-GCM nonce/invocation budget. Lower-severity issues are a public UTF-8 decoder with no input bound and predictable, destructively reused test temporary paths. The implementation otherwise has strong controls around authenticated encryption, key sizes, AAD binding, canonical encodings, secret redaction, and owner-only file creation.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `README.md` | Documents the component, threat model, controls, and residual risks. | Defines intended nonce, KDF, file-security, error-redaction, and key-lifecycle guarantees. |
| `pom.xml` | Maven build configuration for Java 17 and JUnit. | Pins compiler, test plugin, and test-only dependency versions. |
| `src/main/java/com/example/crypto/CryptoException.java` | Provides fixed-vocabulary public errors and separate technical details. | Redacts causes and stack traces and prevents secrets or failure distinctions from reaching callers. |
| `src/main/java/com/example/crypto/EncryptedBlob.java` | Parses and serializes authenticated encrypted records. | Bounds input, enforces canonical base64url, validates headers, and exposes unauthenticated key-version peeking. |
| `src/main/java/com/example/crypto/EnvKeySource.java` | Loads AES keys from environment variables. | Validates variable names and values and avoids echoing secret contents. |
| `src/main/java/com/example/crypto/KeyEncoding.java` | Parses raw or canonical base64url AES keys. | Enforces exact key length and strict, canonical encoding. |
| `src/main/java/com/example/crypto/KeyFileKeySource.java` | Loads AES keys from files. | Delegates owner, mode, symlink, ancestry, size, and encoding checks. |
| `src/main/java/com/example/crypto/KeyMaterial.java` | Owns, uses, exports, and erases AES key bytes. | Restricts keys to 256 bits, clones input, wipes owned copies, and controls exports. |
| `src/main/java/com/example/crypto/KeySource.java` | Defines the key-source contract. | Requires fresh key material and fail-closed source behavior. |
| `src/main/java/com/example/crypto/KeyVault.java` | Routes versioned keys, rotates keys, and provides encryption/decryption operations. | Enforces version binding, disables retired keys, bounds cached versions, uses decoy keys, and destroys loaded material. |
| `src/main/java/com/example/crypto/KeystoreKeySource.java` | Creates and reads PKCS#12 stores. | Handles passwords, file privacy, store size, aliases, entry type, and key extraction. |
| `src/main/java/com/example/crypto/Limits.java` | Centralizes input and KDF limits. | Defines payload, context, tag, IV, encoded-record, and PBKDF2 bounds. |
| `src/main/java/com/example/crypto/PasswordKeySource.java` | Wraps a random data key with a PBKDF2-derived AES-GCM key. | Generates salt/nonce/key material, authenticates container metadata, bounds KDF cost, and erases password-derived data. |
| `src/main/java/com/example/crypto/PrivateFiles.java` | Creates and reads secret files with POSIX security checks. | Uses atomic owner-only creation and checks type, symlinks, ownership, permissions, ancestors, inode identity, and size. |
| `src/main/java/com/example/crypto/RandomPasswords.java` | Generates machine passwords. | Uses `SecureRandom`, a large printable alphabet, and mutable output. |
| `src/main/java/com/example/crypto/SymmetricCrypto.java` | Implements AES-256-GCM encryption and decryption. | Generates random nonces, binds headers/context as AAD, verifies tags, bounds plaintext, and handles provider failures. |
| `src/test/java/com/example/crypto/CipherBehaviourTest.java` | Tests cipher, record, parsing, timing, bounds, and concurrency behavior. | Exercises tampering, nonce uniqueness samples, canonical encodings, input limits, and error uniformity. |
| `src/test/java/com/example/crypto/EnvKeySourceChild.java` | Child-process helper for environment-key tests. | Reads an environment key and prints only a non-secret fingerprint or status. |
| `src/test/java/com/example/crypto/Fixtures.java` | Creates test files/directories and reads production source for structural assertions. | Manages temporary paths and recursive cleanup; accepts source-path overrides. |
| `src/test/java/com/example/crypto/KeyFilePermissionTest.java` | Tests file modes, symlinks, ancestry, races, and atomic creation. | Starts OS processes, including one shell command built with a path. |
| `src/test/java/com/example/crypto/KeySourceTest.java` | Tests key parsing and all key-source types. | Starts a child JVM, manipulates secret containers, serializes exceptions, and checks KDF bounds. |
| `src/test/java/com/example/crypto/KeyVaultTest.java` | Tests version routing, rotation, cache bounds, and concurrency. | Exercises unknown versions, decoy keys, source lifetimes, and concurrent rotations. |
| `src/test/java/com/example/crypto/NoSecretLeakTest.java` | Tests error and logging surfaces for secret leakage. | Renders exception surfaces and checks them against plaintext, context, password, and key representations. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: used to inventory every Java source/configuration file, identify security-relevant behavior, route to matching specialized skills, and require CWE-tagged evidence.
- `performing-cryptographic-audit-of-application`: applied to algorithms, modes, key sizes, entropy, password derivation, key storage, secret handling, and rotation.
- `implementing-aes-encryption-for-data-at-rest`: applied to AES-256-GCM, authentication tags, IV/nonce management, AAD, PBKDF2 parameters, and key erasure.
- `testing-for-sensitive-data-exposure`: applied to hardcoded secrets, error/cause rendering, technical details, paths, plaintext, passwords, and key representations.
- General OWASP Top 10 / CWE knowledge: applied to OS command construction, temporary-file safety, filesystem races, public input bounds, denial of service, Java serialization, and dependency/build configuration because no specialized sibling skill matched those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Shell command injection through a test path | Medium | CWE-78 | `src/test/java/com/example/crypto/KeyFilePermissionTest.java:381` |
| SEC-02 | AES-GCM nonce uniqueness and per-key use limits are not enforced | Medium | CWE-323 | `src/main/java/com/example/crypto/SymmetricCrypto.java:121` |
| SEC-03 | PBKDF2-HMAC-SHA256 accepts an insufficient work factor | Medium | CWE-916 | `src/main/java/com/example/crypto/Limits.java:34` |
| SEC-04 | Predictable test directories are recursively reused | Low | CWE-377 | `src/test/java/com/example/crypto/Fixtures.java:27` |
| SEC-05 | Public UTF-8 decoding accepts unbounded input | Low | CWE-400 | `src/main/java/com/example/crypto/SymmetricCrypto.java:254` |

## 5. Detailed Findings

### SEC-01: Shell command injection through a test path
- **Severity:** Medium
- **CWE:** CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Location:** `src/test/java/com/example/crypto/KeyFilePermissionTest.java:381-385`

**Vulnerable code:**
```java
// src/test/java/com/example/crypto/KeyFilePermissionTest.java:381-385
        Process racer = new ProcessBuilder("sh", "-c",
                "umask 000; set -C; : > '" + hisFile + "'")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
```

**Why it is a problem:** `hisFile` is derived from `java.io.tmpdir` through `Fixtures.dir`. A quote or shell metacharacter in that configurable path breaks out of the hand-written single quotes and is interpreted by `sh`. Running the tests can therefore execute arbitrary commands with the build agent's privileges. This is especially relevant in CI, where tests execute automatically and temporary-directory configuration may come from runner or job configuration. MITRE recommends separating command arguments from shell directives rather than composing a shell string ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)).

**Fix:** Pass the path as a positional shell argument, or preferably replace the shell operation with Java NIO. If the shell semantics are required for this test, positional parameters keep data out of the command language.
```java
        Process racer = new ProcessBuilder(
                "sh", "-c", "umask 000; set -C; : > \"$1\"", "sh", hisFile.toString())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
```

### SEC-02: AES-GCM nonce uniqueness and per-key use limits are not enforced
- **Severity:** Medium
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/com/example/crypto/SymmetricCrypto.java:121-132`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SymmetricCrypto.java:121-132
        byte[] nonce = new byte[Limits.IV_BYTES];
        random.nextBytes(nonce);
        int keyVersion = key.version();
        /*
         * Built before the lambda: a Function cannot throw a checked exception, and the context has
         * already been validated. At write time the record's header fields and the caller's/key's
         * fields agree by construction - the point of writing both is that a reader cannot make them
         * disagree without breaking the tag.
         */
        byte[] aadBytes = aad(EncryptedBlob.FORMAT_VERSION, hasContext ? 1 : 0, keyVersion, hasContext,
                keyVersion, context);
        byte[] body = key.use(k -> cipherOp(Cipher.ENCRYPT_MODE, k, nonce, aadBytes, pt));
```

**Why it is a problem:** GCM requires that a key/nonce pair never repeat. This implementation draws a random 96-bit nonce but neither detects collisions nor enforces a total invocation budget for each key across threads, restarts, or processes. The public constructor also accepts any `SecureRandom` instance, including a faulty subclass that repeats output. A single nonce reuse under one GCM key compromises confidentiality and enables forgeries. NIST requires the probability of ever repeating a key/IV pair to remain at most 2^-32 and places invocation requirements on GCM implementations ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), [FIPS 140-3 implementation guidance](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf)). Documentation advising callers to rotate does not enforce that invariant.

**Fix:** Obtain nonces from an atomic, durable per-key sequence that reserves unique 96-bit values across all writers and refuses before exhaustion. The prefix and counter state must survive restarts and be coordinated across processes; a JVM-local counter alone is insufficient.
```java
public interface NonceSequence {
    /** Returns a never-before-used 12-byte nonce for this key version, or fails closed. */
    byte[] nextNonce(int keyVersion) throws CryptoException;
}

private final NonceSequence nonces;

private EncryptedBlob doEncrypt(KeyMaterial key, byte[] plaintext, String context)
        throws CryptoException {
    // Validate key, plaintext, and context as before.
    int keyVersion = key.version();
    byte[] nonce = nonces.nextNonce(keyVersion); // durable and atomic across all writers
    if (nonce == null || nonce.length != Limits.IV_BYTES) {
        throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                "nonce allocation failed");
    }
    byte[] aadBytes = aad(EncryptedBlob.FORMAT_VERSION, context != null ? 1 : 0,
            keyVersion, context != null, keyVersion, context);
    byte[] body = null;
    try {
        body = key.use(k -> cipherOp(Cipher.ENCRYPT_MODE, k, nonce, aadBytes, plaintext));
        byte[] packed = new byte[EncryptedBlob.HEADER_BYTES + body.length];
        packed[0] = EncryptedBlob.FORMAT_VERSION;
        packed[1] = (byte) (context != null ? 1 : 0);
        packed[2] = (byte) keyVersion;
        System.arraycopy(nonce, 0, packed, 3, Limits.IV_BYTES);
        System.arraycopy(body, 0, packed, EncryptedBlob.HEADER_BYTES, body.length);
        return EncryptedBlob.wrap(packed, context != null, context);
    } finally {
        Arrays.fill(nonce, (byte) 0);
        if (body != null) {
            Arrays.fill(body, (byte) 0);
        }
    }
}
```

### SEC-03: PBKDF2-HMAC-SHA256 accepts an insufficient work factor
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/crypto/Limits.java:34-38`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/Limits.java:34-38
    /** Lower bound for PBKDF2. Values below this are rejected rather than honoured. */
    public static final int MIN_KDF_ITERATIONS = 310_000;

    /** Upper bound for PBKDF2: above this a wrong-password attempt becomes a cheap DoS. */
    public static final int MAX_KDF_ITERATIONS = 2_000_000;
```

**Why it is a problem:** `PasswordKeySource.create` accepts the minimum, stores it in the container, and `load` honors it. An attacker who obtains the container can therefore perform offline guesses at roughly half the current recommended PBKDF2-HMAC-SHA256 work factor. The default is 600,000, but the enforced security boundary is 310,000 and the tests deliberately use that value. Current OWASP guidance recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256 ([OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)). Recovering the passphrase exposes the wrapped data key and all records protected by it.

**Fix:** Raise the accepted floor to at least the current baseline and calibrate it periodically for deployment hardware. Prefer a versioned Argon2id container when a reviewed implementation is available; retain PBKDF2 where FIPS requirements apply.
```java
    /** Minimum accepted PBKDF2-HMAC-SHA256 work factor. */
    public static final int MIN_KDF_ITERATIONS = 600_000;

    /** Upper bound prevents attacker-controlled key files from imposing unbounded CPU work. */
    public static final int MAX_KDF_ITERATIONS = 2_000_000;
```

### SEC-04: Predictable test directories are recursively reused
- **Severity:** Low
- **CWE:** CWE-377: Insecure Temporary File
- **Location:** `src/test/java/com/example/crypto/Fixtures.java:27-35`

**Vulnerable code:**
```java
// src/test/java/com/example/crypto/Fixtures.java:27-35
    static synchronized Path dir(String name) throws IOException {
        Path base = Path.of(System.getProperty("java.io.tmpdir"),
                "secure-data-crypto-" + ProcessHandle.current().pid(), name);
        if (Files.exists(base)) {
            deleteRecursively(base);
        }
        Files.createDirectories(base);
        Files.setPosixFilePermissions(base, EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
```

**Why it is a problem:** The directory name is predictable from the process ID and pre-existing content at that location is recursively processed and deleted. On a shared build host, a local attacker can pre-create or race this path, causing denial of service, inducing operations on attacker-selected entries, or exploiting the cleanup's follow-on permission changes. Permissions are also tightened only after `createDirectories`, rather than atomically at creation. Test code runs with the build agent's privileges and must treat shared temporary storage as hostile.

**Fix:** Create one unpredictable owner-only root atomically, create only fresh child directories beneath it, and never recursively delete a path that the current process did not create.
```java
    private static final Set<PosixFilePermission> OWNER_RWX = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE);

    private static final Path TEST_ROOT = createTestRoot();

    private static Path createTestRoot() {
        try {
            return Files.createTempDirectory("secure-data-crypto-",
                    java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_RWX));
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    static synchronized Path dir(String name) throws IOException {
        if (!name.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("invalid fixture name");
        }
        return Files.createDirectory(TEST_ROOT.resolve(name),
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_RWX));
    }
```

### SEC-05: Public UTF-8 decoding accepts unbounded input
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/crypto/SymmetricCrypto.java:254-260`

**Vulnerable code:**
```java
// src/main/java/com/example/crypto/SymmetricCrypto.java:254-260
    public static String decodeUtf8(byte[] raw) throws CryptoException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(raw))
                    .toString();
```

**Why it is a problem:** Although internal decrypt paths produce at most `MAX_PLAINTEXT_BYTES`, this helper is public and accepts any caller-provided array. A large attacker-controlled array causes proportional decoding and string allocation, bypassing the component's stated rule that externally supplied values are bounded before work or allocation. A null input also escapes as an unchecked exception rather than the component's fail-closed `CryptoException`.

**Fix:** Apply the same plaintext limit at the public boundary before constructing the decoder or output string.
```java
    public static String decodeUtf8(byte[] raw) throws CryptoException {
        byte[] bounded = Limits.requirePayload(raw, Limits.MAX_PLAINTEXT_BYTES, "plaintext");
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bounded))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "record does not contain well-formed UTF-8", e);
        }
    }
```

## 6. Verified Controls and Checks With No Finding
- Algorithm and mode: production encryption uses fixed `AES/GCM/NoPadding`, 256-bit keys, 96-bit nonces, and 128-bit tags in `SymmetricCrypto.java` and `Limits.java`; no ECB, CBC, DES, RC4, MD5, or SHA-1 security use was found.
- Authenticated metadata: format version, context presence, record key version, actual key version, and context are bound into GCM AAD in `SymmetricCrypto.java`; ciphertext/tag tampering does not return plaintext.
- Key generation: data keys, wrapping salts/nonces, decoy keys, and generated passwords use `SecureRandom`; no production hardcoded key, password, default key, or time-seeded PRNG was found.
- Key length and encoding: `KeyMaterial.java` accepts only 32-byte AES keys; `KeyEncoding.java` accepts only exact raw keys or canonical unpadded base64url and rejects padding, whitespace, malformed encodings, and wrong lengths.
- Password container validation: `PasswordKeySource.java` authenticates KDF metadata, bounds iteration counts before derivation, validates fixed field lengths, uses a random data key, and wipes owned password, key, and KEK arrays.
- Record parsing and resource bounds: `EncryptedBlob.java` bounds encoded and raw records before copying/decoding, validates structure, enforces canonical base64url, and limits key-version peeking to four encoded characters.
- File creation: `PrivateFiles.java` uses `CREATE_NEW` with owner-only creation attributes, refuses overwrite, validates parent directories, and forces writes before returning.
- File reads: `PrivateFiles.java` rejects symlinks, non-regular files, group/other permissions, execute/set-id bits, unexpected ownership, and insecure ancestors; it performs additional inode/mode/owner checks for shared parents.
- Error and logging surfaces: `CryptoException.java` exposes fixed public messages, suppresses stack traces, sanitizes rendered causes, and keeps technical details transient; no production logging of keys, passwords, plaintext, or ciphertext was found.
- Key lifecycle: `KeyMaterial.java`, `PasswordKeySource.java`, `KeystoreKeySource.java`, and `KeyVault.java` clone caller inputs where appropriate, wipe owned mutable secret arrays, destroy per-operation keys, and fail closed after destruction/closure.
- Version routing and rotation: `KeyVault.java` verifies source key versions, never tries multiple keys until one decrypts, bounds tracked versions, disables superseded versions, and uses fresh random decoy keys for impossible versions.
- Context and text validation: contexts and identifiers are restricted to bounded printable ASCII, and decrypted text is decoded with malformed/unmappable UTF-8 rejection.
- Process invocation other than SEC-01: the child JVM, `mkfifo`, and `chmod` test invocations use argument-separated `ProcessBuilder` forms and do not interpolate values into shell command text.
- Serialization: the only deserialization located is a test round-trip of a locally created `CryptoException`; no production deserialization of untrusted objects was found.
- Dependencies: the shipped library has no third-party runtime dependency; JUnit is test-scoped and versions are pinned rather than ranged.
