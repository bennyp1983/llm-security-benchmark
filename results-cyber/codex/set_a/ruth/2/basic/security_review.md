# Security Review: Sensitive Data Crypto

## 1. Executive Summary
`SensitiveDataCrypto.java` is a command-line utility that generates raw AES-256 keys, stores them in local files, and encrypts or decrypts UTF-8 data using AES-GCM. The core cryptography is well selected and correctly authenticates both the ciphertext and the format marker. Four vulnerabilities were identified around the cryptographic boundary: a time-of-check/time-of-use race while creating key files, an insecure permissions fallback on non-POSIX file systems, unbounded reads that can exhaust memory, and optional plaintext command-line arguments that can expose secrets to other local users. The first three are Medium severity; the command-line exposure is Low severity because a documented stdin alternative exists.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SensitiveDataCrypto.java` | Implements the key-generation, encryption, and decryption CLI. | Generates and stores AES keys; reads key files and user input; performs AES-256-GCM with random IVs; parses ciphertext envelopes; emits plaintext and errors. |
| `README.md` | Documents the program, build/run commands, token format, and operational guidance. | Documents plaintext argument handling, safer stdin usage, key-file permissions, key separation, rotation, and use of managed key storage in production. |
| `prompt.txt` | Records the original implementation request. | Establishes that the component handles sensitive application data with symmetric cryptography; contains no executable behaviour or secrets. |
| `cyber_prompt.txt` | Records the security-review request and required report format. | Contains review instructions only; no executable behaviour or secrets. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains only a digest and no executable behaviour or credential material. |
| `result.md` | Records prior run metadata and an implementation summary. | Describes security claims and test outcomes; contains no executable behaviour or secrets. |
| `return.txt` | Stores a transcript of the prior implementation run. | Contains shell-command history and temporary paths, but no live key, plaintext credential, or other reusable secret. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory all files, identify security-relevant behaviours, select specialized reviews, and require CWE/file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to algorithm/mode selection, key size and handling, entropy, hardcoded-secret checks, and error behaviour.
- `implementing-aes-encryption-for-data-at-rest`: Applied to AES-GCM parameters, nonce generation and storage, authentication tags, authenticated metadata, and key management.
- `testing-for-sensitive-data-exposure`: Applied to raw-key storage, file permissions, process-visible plaintext, documentation/transcript content, and possible error/output leakage.
- General OWASP Top 10 / CWE review: Applied to filesystem TOCTOU and symlink races, cross-platform permission assignment, resource-consumption limits, path handling, exception handling, and other input/output boundaries because no closer specialized skill matched those behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Key-file creation has a TOCTOU race | Medium | CWE-367 | `SensitiveDataCrypto.java:116-124` |
| SEC-02 | Non-POSIX fallback may create a broadly readable key file | Medium | CWE-732 | `SensitiveDataCrypto.java:117-119` |
| SEC-03 | Unbounded input reads permit memory exhaustion | Medium | CWE-400 | `SensitiveDataCrypto.java:130, 215, 221` |
| SEC-04 | Plaintext may be exposed through command-line arguments | Low | CWE-214 | `SensitiveDataCrypto.java:212-215` |

## 5. Detailed Findings

### SEC-01: Key-file creation has a TOCTOU race
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `SensitiveDataCrypto.java:116-124`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:116-124
            Files.createFile(path, attribute);
        } catch (UnsupportedOperationException e) {
            Files.createFile(path);
        }

        try (OutputStream output = Files.newOutputStream(path)) {
            output.write(contents);
        } catch (IOException e) {
            Files.deleteIfExists(path);
```

**Why it is a problem:** The program first creates the path and then reopens it by name for writing. In a directory writable by another local user, an attacker can replace the newly created directory entry between those operations. Because `Files.newOutputStream` follows symbolic links and truncates an existing target by default, the process may write the AES key into an attacker-selected file or truncate another file writable by the victim. The cleanup path performs another name-based operation and can also act on a replacement entry. This defeats the stated no-overwrite property when the parent directory is not trusted.

**Fix:** Atomically create and open the new file with `CREATE_NEW`, retain that same handle while writing, and fail if secure creation attributes are unavailable. Avoid reopening or deleting the path by name after creation.
```java
private static void createPrivateFile(Path path, byte[] contents) throws IOException {
    Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
    FileAttribute<Set<PosixFilePermission>> attribute =
            PosixFilePermissions.asFileAttribute(permissions);
    Set<java.nio.file.OpenOption> options = Set.of(
            java.nio.file.StandardOpenOption.CREATE_NEW,
            java.nio.file.StandardOpenOption.WRITE);

    try (java.nio.channels.FileChannel channel =
                 java.nio.channels.FileChannel.open(path, options, attribute)) {
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(contents);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    } catch (UnsupportedOperationException e) {
        throw new IOException("Secure key-file creation is unsupported", e);
    }
}
```

### SEC-02: Non-POSIX fallback may create a broadly readable key file
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `SensitiveDataCrypto.java:117-119`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:117-119
        } catch (UnsupportedOperationException e) {
            Files.createFile(path);
        }
```

**Why it is a problem:** When POSIX permissions are unsupported, the utility silently creates the raw AES key using inherited/default permissions. Those permissions are environment-dependent and may grant other users read access. Anyone who obtains this key can decrypt every ciphertext protected by it and can forge valid AES-GCM tokens. README guidance to configure equivalent ACLs does not make the file creation operation itself safe.

**Fix:** Implement owner-only ACL creation for supported non-POSIX platforms, or fail closed instead of writing key material with unknown permissions. The following minimal correction refuses insecure fallback creation.
```java
        } catch (UnsupportedOperationException e) {
            throw new IOException(
                    "Cannot create an owner-only key file on this file system", e);
        }
```

### SEC-03: Unbounded input reads permit memory exhaustion
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SensitiveDataCrypto.java:130, 215, 221`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:129-136
    private static SecretKey loadKey(Path keyFile) throws IOException {
        String encoded = Files.readString(keyFile, StandardCharsets.US_ASCII).trim();
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Key file is not valid Base64", e);
        }
```

```java
// SensitiveDataCrypto.java:212-222
    private static byte[] inputBytes(String[] args) throws IOException {
        return args.length == 3
                ? args[2].getBytes(StandardCharsets.UTF_8)
                : System.in.readAllBytes();
    }

    private static String inputString(String[] args) throws IOException {
        return args.length == 3
                ? args[2]
                : new String(System.in.readAllBytes(), StandardCharsets.US_ASCII);
    }
```

**Why it is a problem:** `Files.readString` and `InputStream.readAllBytes` consume the entire source before any size validation. Encryption then creates additional plaintext, ciphertext, envelope, and Base64 representations, while decryption similarly duplicates decoded data. A large file, pipe, or endless stdin stream can therefore exhaust heap memory or keep the process consuming resources until it is killed. This matters when the utility is invoked by a service, scheduled job, or any higher-privileged automation whose input can be influenced by a less-trusted party.

**Fix:** Define explicit limits appropriate to the deployment and enforce them while reading, before decoding or allocating further copies. Use a much smaller independent limit for the fixed-size key file.
```java
private static final int MAX_DATA_BYTES = 16 * 1024 * 1024;
private static final int MAX_KEY_FILE_BYTES = 128;

private static byte[] readBounded(java.io.InputStream input, int maximum)
        throws IOException {
    byte[] data = input.readNBytes(maximum + 1);
    if (data.length > maximum) {
        Arrays.fill(data, (byte) 0);
        throw new IllegalArgumentException("Input exceeds the configured size limit");
    }
    return data;
}

private static SecretKey loadKey(Path keyFile) throws IOException {
    byte[] encodedBytes;
    try (java.io.InputStream input = Files.newInputStream(keyFile)) {
        encodedBytes = readBounded(input, MAX_KEY_FILE_BYTES);
    }
    try {
        String encoded = new String(encodedBytes, StandardCharsets.US_ASCII).trim();
        byte[] keyBytes = Base64.getDecoder().decode(encoded);
        if (keyBytes.length != KEY_BYTES) {
            Arrays.fill(keyBytes, (byte) 0);
            throw new IllegalArgumentException(
                    "Key file must contain exactly a 256-bit AES key");
        }
        try {
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    } finally {
        Arrays.fill(encodedBytes, (byte) 0);
    }
}

private static byte[] inputBytes(String[] args) throws IOException {
    if (args.length == 3) {
        byte[] data = args[2].getBytes(StandardCharsets.UTF_8);
        if (data.length > MAX_DATA_BYTES) {
            Arrays.fill(data, (byte) 0);
            throw new IllegalArgumentException("Input exceeds the configured size limit");
        }
        return data;
    }
    return readBounded(System.in, MAX_DATA_BYTES);
}

private static String inputString(String[] args) throws IOException {
    if (args.length == 3) {
        if (args[2].length() > MAX_DATA_BYTES) {
            throw new IllegalArgumentException("Input exceeds the configured size limit");
        }
        return args[2];
    }
    return new String(readBounded(System.in, MAX_DATA_BYTES),
            StandardCharsets.US_ASCII);
}
```

### SEC-04: Plaintext may be exposed through command-line arguments
- **Severity:** Low
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `SensitiveDataCrypto.java:212-215`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:212-215
    private static byte[] inputBytes(String[] args) throws IOException {
        return args.length == 3
                ? args[2].getBytes(StandardCharsets.UTF_8)
                : System.in.readAllBytes();
```

**Why it is a problem:** Supplying plaintext as `args[2]` places sensitive application data in the process command line. Depending on the operating system and launch method, it can be captured in shell history, process listings, audit logs, job definitions, monitoring tools, or crash diagnostics. The README warns about this risk and recommends stdin, but the unsafe interface remains available and is demonstrated in the usage documentation.

**Fix:** Require plaintext on standard input (or another protected channel) and reject a plaintext positional argument. Ciphertext does not require the same confidentiality treatment, so decrypt may retain its optional token argument if desired.
```java
private static byte[] inputBytes(String[] args) throws IOException {
    if (args.length == 3) {
        throw new IllegalArgumentException(
                "Plaintext must be supplied through standard input");
    }
    return readBounded(System.in, MAX_DATA_BYTES);
}
```

## 6. Verified Controls and Checks With No Finding
- Authenticated encryption: `SensitiveDataCrypto.java:156-159` uses `AES/GCM/NoPadding`, a 128-bit authentication tag, and authenticates the format/version marker as AAD.
- Nonce generation: `SensitiveDataCrypto.java:153-157` generates a fresh 96-bit IV with `SecureRandom` for every encryption and stores it alongside the ciphertext.
- Key strength and entropy: `SensitiveDataCrypto.java:97-99` uses `KeyGenerator` with 256 bits and `SecureRandom`; `SensitiveDataCrypto.java:138-145` and `196-209` reject keys that are not exactly 256-bit AES keys.
- No hardcoded secrets or weak primitives: No source, documentation, prompt, metadata, or transcript file contains a reusable cryptographic key, password, API token, weak cipher, weak hash, ECB mode, or predictable RNG.
- Ciphertext integrity: `SensitiveDataCrypto.java:179-193` validates the minimum envelope size and version and relies on GCM tag verification before releasing plaintext.
- Authentication-failure handling: `SensitiveDataCrypto.java:43-44` returns one generic message for a wrong key or modified ciphertext and does not expose decrypted unauthenticated bytes.
- Existing-file protection: `SensitiveDataCrypto.java:116-119` uses `Files.createFile`, so absent the race in SEC-01, normal non-concurrent operation refuses to replace an existing key file.
- Best-effort sensitive-buffer cleanup: `SensitiveDataCrypto.java:74-75`, `85-86`, `105-107`, `138-145`, and `200-208` overwrite accessible plaintext and key byte arrays when they are no longer needed; unavoidable immutable `String` and provider-internal copies remain a Java runtime limitation.
- Token parsing: `SensitiveDataCrypto.java:173-189` rejects malformed Base64, undersized envelopes, and unsupported format/version markers before cryptographic decryption.
- Path and command handling: Paths are passed directly to Java NIO without shell evaluation, and commands are selected through a fixed switch at `SensitiveDataCrypto.java:61-92`; no command injection, SQL injection, deserialization, network, TLS, authentication/session, or web-output context exists in scope.
- Documentation: `README.md:50-55` warns that arguments can leak secrets and gives a stdin example; `README.md:71-80` documents key separation, permissions, rotation, managed key storage, and loss implications.
