# Security Code Review Report: SymmetricEncryption.java

## 1. Executive Summary

A comprehensive security code review was performed on the codebase located in this directory, specifically `SymmetricEncryption.java`, following the workflow defined in the `review-code-for-security-vulnerabilities` skill.

The application implements symmetric encryption and key lifecycle management using standard Java Cryptography Architecture (JCA) APIs (`javax.crypto.*` and `java.security.*`), featuring AES-GCM (AES-256 in Galois/Counter Mode), PKCS#12 KeyStore management, PBKDF2 key derivation, and custom envelope serialization.

While the core cryptographic primitive selection is strong (AES-256-GCM with 128-bit authentication tags and 96-bit random IVs), the review identified several significant vulnerabilities and design weaknesses in key storage, file I/O permissions, process argument handling, wire format deserialization, and memory hygiene.

---

## 2. Scope & File Overview (Step 1)

### File Under Review: `SymmetricEncryption.java`
- **Purpose**: Provides a standalone utility and CLI tool for encrypting/decrypting sensitive data with AES-256-GCM, storing and rotating keys in a PKCS#12 KeyStore, deriving keys via PBKDF2-HMAC-SHA256, packaging ciphertexts into self-describing wire envelopes, and wiping memory buffers.
- **Security-Relevant Behaviors Flagged**:
  1. **Cryptography**: AES-GCM authenticated encryption/decryption, 256-bit key generation, 96-bit IV generation using `SecureRandom`, PBKDF2 key derivation (`PBKDF2WithHmacSHA256`).
  2. **Secret & Key Storage**: Master password handling, PKCS#12 KeyStore file creation, POSIX file permission modification (`0600`), in-memory secret zeroization.
  3. **Input Handling & CLI Execution**: Command-line arguments in `main()` accepting paths, master passwords, aliases, and plaintext data.
  4. **Serialization & Deserialization**: Custom binary format parsing in `EncryptedEnvelope.fromByteArray()`, Base64 encoding/decoding.
  5. **File System Operations**: Temporary file creation (`Files.createTempFile`), deletion, and non-atomic stream truncation (`Files.newOutputStream`).
  6. **Error Handling & Diagnostics**: Exception catching, permission fallback handling, and standard error stack traces (`e.printStackTrace()`).

---

## 3. Skills Applied (Step 2 & Step 3)

In accordance with the `review-code-for-security-vulnerabilities` workflow, the skill repository was queried for specialized domain skills matching the security-relevant behaviors:

1. **`review-code-for-security-vulnerabilities`**: Router skill defining the overall assessment workflow.
2. **`performing-cryptographic-audit-of-application`**: Applied to audit cryptographic primitives, key derivation parameters, cipher modes, entropy sources, and secret management.
3. **`implementing-aes-encryption-for-data-at-rest`**: Applied to evaluate AES-256-GCM implementation specifics, nonce uniqueness, tag validation, iteration counts, and authenticated data binding.
4. **`testing-for-sensitive-data-exposure`**: Applied to evaluate credential exposure, process visibility, and memory hygiene.

### General OWASP Top 10 & CWE Knowledge
For behaviors not covered by dedicated skills in the library (specifically command-line process parameter exposure, race conditions during file creation, non-atomic file replacement, and custom binary deserialization validation), the code was reviewed against general **OWASP Top 10 (2021)** and **CWE (Common Weakness Enumeration)** guidelines.

---

## 4. Summary of Findings

| ID | Finding Title | Severity | CWE ID | Primary Location |
|---|---|---|---|---|
| **SEC-01** | Sensitive Passwords and Plaintext Exposed via Command-Line Arguments | **High** | [CWE-214](https://cwe.mitre.org/data/definitions/214.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | `SymmetricEncryption.java:1045-1165` |
| **SEC-02** | Insecure Temporary File Handling & Permission Race Condition (TOCTOU) | **High** | [CWE-377](https://cwe.mitre.org/data/definitions/377.html), [CWE-378](https://cwe.mitre.org/data/definitions/378.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | `SymmetricEncryption.java:474-479`, `867-868` |
| **SEC-03** | Non-Atomic KeyStore Overwrite Leading to Potential Data Loss | **Medium** | [CWE-404](https://cwe.mitre.org/data/definitions/404.html), [CWE-703](https://cwe.mitre.org/data/definitions/703.html) | `SymmetricEncryption.java:474`, `650` |
| **SEC-04** | Silent Exception Swallowing During File Permission Enforcement | **Medium** | [CWE-391](https://cwe.mitre.org/data/definitions/391.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | `SymmetricEncryption.java:671-673` |
| **SEC-05** | Unauthenticated Envelope Header Metadata in Wire Format | **Medium** | [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-353](https://cwe.mitre.org/data/definitions/353.html) | `SymmetricEncryption.java:380-388`, `718-722` |
| **SEC-06** | Incomplete Field and Bounds Validation in Custom Envelope Deserialization | **Medium** | [CWE-125](https://cwe.mitre.org/data/definitions/125.html), [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | `SymmetricEncryption.java:392-419` |
| **SEC-07** | Hardcoded Demonstration Passwords and Immutable Heap Retention | **Low** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | `SymmetricEncryption.java:852`, `996` |
| **SEC-08** | Sensitive Plaintext Handled in Immutable Strings and Un-Zeroized Buffers | **Low** | [CWE-316](https://cwe.mitre.org/data/definitions/316.html), [CWE-244](https://cwe.mitre.org/data/definitions/244.html) | `SymmetricEncryption.java:221-224`, `736` |
| **SEC-09** | PBKDF2 Iteration Count Threshold Below Current OWASP/NIST Recommendations | **Low** | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | `SymmetricEncryption.java:63`, `118-120` |
| **SEC-10** | Information Disclosure via Detailed Stack Traces in CLI Entry Point | **Low** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | `SymmetricEncryption.java:1174` |

---

## 5. Detailed Vulnerability Findings

---

### SEC-01: Sensitive Passwords and Plaintext Exposed via Command-Line Arguments

- **Severity**: **High**
- **CWE ID**: [CWE-214: Invocation of Process Initializer with Untrusted Host Values](https://cwe.mitre.org/data/definitions/214.html) / [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- **File & Lines**:
  - `SymmetricEncryption.java:1045-1050`: Command-line interface usage definitions
  - `SymmetricEncryption.java:1081`: `char[] pass = args[2].toCharArray();` (`--init-keystore`)
  - `SymmetricEncryption.java:1097`: `char[] pass = args[2].toCharArray();` (`--gen-key`)
  - `SymmetricEncryption.java:1115`: `char[] pass = args[2].toCharArray();` (`--list-keys`)
  - `SymmetricEncryption.java:1135-1137`: `char[] pass = args[2].toCharArray();` and `String plaintext = args[4];` (`--encrypt`)
  - `SymmetricEncryption.java:1155`: `char[] pass = args[2].toCharArray();` (`--decrypt`)
- **Problem Description**:
  The command-line interface expects master passwords and sensitive application plaintext as positional command-line arguments:
  ```
  java SymmetricEncryption --encrypt <keystore-path> <password> <alias> <text>
  ```
  On multi-user operating systems (Linux, macOS, Windows), command-line arguments are stored in system process tables and are globally visible to unprivileged users via `ps aux`, `ps -ef`, `/proc/<pid>/cmdline`, or Task Manager. Furthermore, standard user shells (bash, zsh) persistently record executed commands in history files (`~/.bash_history`, `~/.zsh_history`).
  Additionally, passing passwords via `String[] args` creates immutable `String` instances on the JVM heap before `main()` executes. Converting `args[2]` to `char[]` and wiping `pass` in `finally` blocks (e.g. line 1143) is ineffective because `args[2]` and `args[4]` remain un-zeroized on the heap indefinitely.
- **Remediation**:
  1. Never accept passwords as command-line arguments. Prompt interactively using `System.console().readPassword("KeyStore password: ")`, or accept credentials via a secure environment variable or standard input pipe (`System.in`).
  2. Read plaintext input from `System.in` or a permission-restricted file instead of CLI arguments.

---

### SEC-02: Insecure Temporary File Handling & Permission Race Condition (TOCTOU)

- **Severity**: **High**
- **CWE ID**: [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html) / [CWE-378: Creation of Temporary File With Insecure Permissions](https://cwe.mitre.org/data/definitions/378.html) / [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- **File & Lines**:
  - `SymmetricEncryption.java:867-868`:
    ```java
    tempKeystorePath = Files.createTempFile("app_vault_", ".p12");
    Files.deleteIfExists(tempKeystorePath); // createKeyStore will write fresh
    ```
  - `SymmetricEncryption.java:474-479`:
    ```java
    try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
        ks.store(fos, masterPassword);
    }
    setStrictFilePermissions(keyStorePath);
    ```
- **Problem Description**:
  Two interacting issues create a file permission race condition:
  1. In `runDemonstration()`, `Files.createTempFile()` generates a secure temporary file in `/tmp`, but line 868 immediately deletes it (`Files.deleteIfExists(tempKeystorePath)`). In a shared temporary directory, this introduces a classic Time-of-Check to Time-of-Use (TOCTOU) symlink attack window where a local attacker can create a symlink pointing to another file before `createKeyStore` runs.
  2. In `KeyManager.createKeyStore()`, `Files.newOutputStream(keyStorePath)` creates the file using the process's default umask (typically `0644` or `0664`, readable by all users). Sensitive cryptographic keys are written to disk at line 475 *before* `setStrictFilePermissions()` is called at line 479. Any local process monitoring the filesystem can read the newly generated KeyStore before permissions are restricted to `0600`.
- **Remediation**:
  Atomically create the file with `0600` permissions upon inode creation using `Files.newByteChannel` or `Files.createFile` with POSIX file attributes:
  ```java
  Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
  FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
  Files.createFile(keyStorePath, attr);
  ```
  Never delete a generated temporary file path prior to recreation.

---

### SEC-03: Non-Atomic KeyStore Overwrite Leading to Potential Data Loss

- **Severity**: **Medium**
- **CWE ID**: [CWE-404: Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html) / [CWE-703: Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
- **File & Lines**:
  - `SymmetricEncryption.java:474-476`: File output stream creation in `createKeyStore()`
  - `SymmetricEncryption.java:650-652`:
    ```java
    private synchronized void saveKeyStore() throws GeneralSecurityException, IOException {
        try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
            keyStore.store(fos, masterPassword);
        }
        setStrictFilePermissions(keyStorePath);
    }
    ```
- **Problem Description**:
  `Files.newOutputStream(keyStorePath)` defaults to `StandardOpenOption.TRUNCATE_EXISTING`. When `saveKeyStore()` is executed during key generation, key storage, or key rotation, the target KeyStore file is truncated to zero bytes before the new KeyStore content is written.
  If the JVM crashes, power is lost, or an `IOException` / `GeneralSecurityException` occurs mid-write, the existing KeyStore file is permanently corrupted or emptied. All cryptographic keys in the store are lost, rendering all historical ciphertexts permanently unrecoverable.
- **Remediation**:
  Implement safe atomic replacement:
  1. Write the new KeyStore to a temporary file in the same directory (`keyStorePath.resolveSibling("...tmp")`) with `0600` permissions.
  2. Flush and close the stream.
  3. Atomically replace the destination file using:
     ```java
     Files.move(tempPath, keyStorePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
     ```

---

### SEC-04: Silent Exception Swallowing During File Permission Enforcement

- **Severity**: **Medium**
- **CWE ID**: [CWE-391: Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html) / [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- **File & Lines**:
  - `SymmetricEncryption.java:659-674`:
    ```java
    private static void setStrictFilePermissions(Path path) {
        try {
            Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException e) {
            ...
        } catch (IOException ignored) {
            // Best effort if underlying filesystem attributes restrict modifications
        }
    }
    ```
- **Problem Description**:
  When `Files.setPosixFilePermissions()` throws an `IOException` (e.g. filesystem permission denial, network filesystem limitations, read-only attributes), the exception is swallowed silently without logging or re-throwing. The application continues running, giving a false assurance of security while leaving the KeyStore file exposed with overly permissive default permissions.
- **Remediation**:
  Adopt a fail-closed approach. Propagate the `IOException` or throw a `SecurityException` if file hardening fails:
  ```java
  private static void setStrictFilePermissions(Path path) throws IOException {
      try {
          Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
          Files.setPosixFilePermissions(path, permissions);
      } catch (UnsupportedOperationException e) {
          File file = path.toFile();
          if (!file.setReadable(false, false) || !file.setReadable(true, true) ||
              !file.setWritable(false, false) || !file.setWritable(true, true)) {
              throw new IOException("Failed to enforce restrictive file permissions on " + path);
          }
      }
  }
  ```

---

### SEC-05: Unauthenticated Envelope Header Metadata in Wire Format

- **Severity**: **Medium**
- **CWE ID**: [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) / [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- **File & Lines**:
  - `SymmetricEncryption.java:380-387`: Serialization of version, alias length, alias, IV, and ciphertext
  - `SymmetricEncryption.java:718-720`: Encryption AAD update only includes external associated data
  - `SymmetricEncryption.java:773-775`: Decryption AAD update only includes external associated data
- **Problem Description**:
  The `EncryptedEnvelope` wire format prepends plaintext metadata (`version`, `keyAlias`, and `iv`) to the ciphertext. However, `encryptWithKeyManager()` and `decryptWithKeyManager()` do not feed the envelope metadata into the AEAD Associated Authenticated Data (AAD) stream.
  Because the header is unauthenticated, an attacker can modify the `keyAlias` or `version` byte without triggering an AEAD authentication tag failure on the header itself:
  - Altering `keyAlias` causes the decryptor to look up an unintended key. If the modified alias does not exist, `KeyStoreException` is thrown instead of `AEADBadTagException`, creating an error oracle.
  - If multiple valid keys exist, swapping aliases causes tag failure under the wrong key rather than detecting metadata tampering explicitly.
- **Remediation**:
  Cryptographically bind all envelope header metadata (`version`, `keyAlias`, `iv`) into AES-GCM Associated Authenticated Data (AAD):
  ```java
  byte[] headerAad = ByteBuffer.allocate(1 + 1 + aliasBytes.length + 1 + iv.length)
      .put(version).put((byte) aliasBytes.length).put(aliasBytes).put((byte) iv.length).put(iv).array();
  cipher.updateAAD(headerAad);
  if (associatedData != null && associatedData.length > 0) {
      cipher.updateAAD(associatedData);
  }
  ```

---

### SEC-06: Incomplete Field and Bounds Validation in Custom Envelope Deserialization

- **Severity**: **Medium**
- **CWE ID**: [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html) / [CWE-248: Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
- **File & Lines**:
  - `SymmetricEncryption.java:392-419`:
    ```java
    int minSize = 1 + 1 + 1 + 1 + GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / Byte.SIZE);
    if (bytes.length < minSize) { ... }
    ...
    int ivLen = Byte.toUnsignedInt(buffer.get());
    if (buffer.remaining() < ivLen) { ... }
    byte[] iv = new byte[ivLen];
    buffer.get(iv);
    byte[] cipherBytes = new byte[buffer.remaining()];
    ```
  - `SymmetricEncryption.java:770`: `GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, envelope.getIv());`
- **Problem Description**:
  The deserialization logic in `EncryptedEnvelope.fromByteArray()` does not sufficiently validate input bounds:
  1. The `minSize` check (line 392) verifies total byte length but does not guard against variable fields consuming the buffer. If `aliasLen` consumes the remaining bytes, calling `buffer.get()` at line 411 throws an uncaught `java.nio.BufferUnderflowException`.
  2. `ivLen` is accepted as any value between 0 and 255. The code does not verify that `ivLen == GCM_IV_LENGTH_BYTES` (12 bytes). If an envelope specifies an invalid IV length, it passes deserialization and later crashes `GCMParameterSpec` with `InvalidAlgorithmParameterException`.
  3. The remaining `cipherBytes.length` is not validated to be at least the GCM authentication tag size (16 bytes).
- **Remediation**:
  1. Verify `buffer.remaining() >= 1` before reading each length byte.
  2. Enforce `if (ivLen != GCM_IV_LENGTH_BYTES) throw new IllegalArgumentException("Invalid IV length: " + ivLen);`.
  3. Validate that `buffer.remaining() >= (GCM_TAG_LENGTH_BITS / Byte.SIZE)`.

---

### SEC-07: Hardcoded Demonstration Passwords and Immutable Heap Retention

- **Severity**: **Low**
- **CWE ID**: [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) / [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
- **File & Lines**:
  - `SymmetricEncryption.java:852`: `char[] masterPassword = "MasterApplicationVaultKey!2026".toCharArray();`
  - `SymmetricEncryption.java:896`: `String sensitivePayload = "{\"customerId\": 98765, \"ssn\": \"000-12-3456\", ...}";`
  - `SymmetricEncryption.java:996`: `char[] userPassphrase = "UserSuperStrongMasterPassphrase!2026#".toCharArray();`
- **Problem Description**:
  In `runDemonstration()`, passwords and secret passphrases are initialized from `String` literals. In the JVM, string literals are interned in the String constant pool and cannot be modified or cleared. Calling `.toCharArray()` copies the characters to a mutable array, but the original literal remains resident in heap memory. Even after `wipe()` is called (lines 1014-1016), the cleartext password persists in memory dumps or swap space.
- **Remediation**:
  Generate test credentials dynamically using `SecureRandom` in demonstration/test code, or populate char arrays directly without instantiating intermediate `String` literals.

---

### SEC-08: Sensitive Plaintext Handled in Immutable Strings and Un-Zeroized Buffers

- **Severity**: **Low**
- **CWE ID**: [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html) / [CWE-244: Improper Clearing of Heap Memory Containing Sensitive Information](https://cwe.mitre.org/data/definitions/244.html)
- **File & Lines**:
  - `SymmetricEncryption.java:221-224`: `encrypt(String plaintext, ...)`
  - `SymmetricEncryption.java:318`: `return new String(plaintextBytes, StandardCharsets.UTF_8);`
  - `SymmetricEncryption.java:736`: `byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);`
- **Problem Description**:
  The convenience methods `encrypt(String ...)` and `decrypt(String ...)` process plaintext as `java.lang.String`. In Java, strings are immutable and cannot be zeroized after use. Furthermore, `plaintext.getBytes(StandardCharsets.UTF_8)` at line 736 allocates an intermediate byte array that is abandoned to the garbage collector without zeroization, leaving cleartext sensitive data in heap memory.
- **Remediation**:
  Provide `char[]` or `byte[]` APIs for handling sensitive plaintext data. In wrapper methods that create intermediate byte arrays, zeroize them in `finally` blocks:
  ```java
  byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
  try {
      return encryptWithKeyManager(plaintextBytes, keyManager, keyAlias, associatedData).toBase64();
  } finally {
      wipe(plaintextBytes);
  }
  ```

---

### SEC-09: PBKDF2 Iteration Count Threshold Below Current OWASP/NIST Recommendations

- **Severity**: **Low**
- **CWE ID**: [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- **File & Lines**:
  - `SymmetricEncryption.java:63`: `public static final int PBKDF2_ITERATIONS = 310_000;`
  - `SymmetricEncryption.java:118-120`:
    ```java
    if (iterations < 100_000) {
        throw new IllegalArgumentException("PBKDF2 iteration count must be at least 100,000 for security.");
    }
    ```
- **Problem Description**:
  The default iteration count `PBKDF2_ITERATIONS = 310_000` is based on older 2021 guidelines. Current OWASP recommendations (OWASP Password Storage Cheat Sheet 2023/2024) and NIST SP 800-132 specify a minimum of 600,000 iterations for `PBKDF2WithHmacSHA256` to sufficiently resist GPU/ASIC hardware brute-forcing. Additionally, line 118 permits callers to configure down to 100,000 iterations, which is considered weak for current threat models.
- **Remediation**:
  Increase `PBKDF2_ITERATIONS` to at least 600,000 and update the minimum enforcement check at line 118 from 100,000 to 600,000.

---

### SEC-10: Information Disclosure via Detailed Stack Traces in CLI Entry Point

- **Severity**: **Low**
- **CWE ID**: [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- **File & Lines**:
  - `SymmetricEncryption.java:1174`: `e.printStackTrace();`
- **Problem Description**:
  In `main()`, unexpected exceptions cause a complete stack trace to be printed to `System.err`. In production or shared command-line environments, stack traces reveal internal package structures, class names, file system paths, and runtime environments to unauthorized observers.
- **Remediation**:
  Replace `e.printStackTrace()` with a sanitized user error message:
  ```java
  System.err.println("Error: " + e.getMessage());
  ```
  Route detailed diagnostic stack traces to an access-controlled debug log if required.

---

## 6. Positive Security Controls Identified

The code demonstrates several strong security engineering practices:
- **Cipher Selection**: Uses AES-256 in Galois/Counter Mode (`AES/GCM/NoPadding`) with a full 128-bit authentication tag, avoiding CBC padding oracle attacks and guaranteeing ciphertext integrity.
- **Nonce Generation**: Generates fresh 96-bit random IVs for every encryption operation using `java.security.SecureRandom`.
- **Authenticated Data Support**: Provides native support for Associated Authenticated Data (AAD) to bind ciphertexts to organizational contexts.
- **Standard KeyStore Usage**: Utilizes standard PKCS#12 password-protected key stores rather than unencrypted flat files.
- **Key Rotation Architecture**: Envelope wire format supports versioned aliases, facilitating zero-downtime key rotation.
- **Memory Zeroization**: Provides explicit utility methods (`wipe(char[])`, `wipe(byte[])`) for clearing sensitive byte and character arrays from heap memory.
