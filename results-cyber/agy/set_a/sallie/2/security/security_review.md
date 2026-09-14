# Security Review: PIIEncryption (Java AES-256-GCM Encryption System)

## 1. Executive Summary
A comprehensive security review was conducted on the `PIIEncryption` Java application, designed to encrypt and decrypt Personally Identifiable Information (PII) such as full names and email addresses using AES-256 in Galois/Counter Mode (GCM). The cryptographic core correctly adheres to industry standards: it uses authenticated encryption (AES-256-GCM), draws fresh 12-byte random nonces from a cryptographically secure pseudo-random number generator (`SecureRandom`) for each operation, avoids hardcoded secret keys in the codebase, and properly verifies 128-bit authentication tags.

However, several significant security vulnerabilities were identified in the key management, logging, process invocation, and memory handling layers:
1. **Active Secret Key Logging to Standard Output (High)**: On every execution, the application prints the full active AES-256 secret key in Base64 directly to standard output, exposing the secret key to terminal scrollback, CI/CD pipelines, container logging systems, and process monitors.
2. **Key Ingestion via Command-Line Arguments (High)**: The application accepts raw cryptographic keys via `--key` / `-k` CLI arguments and Java system properties (`-Dpii.encryption.key`), exposing secrets to local users via the process table (`ps`, `/proc/<pid>/cmdline`), shell history files, and system audit logs.
3. **Plaintext PII Output Logging (Medium)**: Full names and email addresses are printed in cleartext to console output both before encryption and after decryption, undermining the privacy objectives of PII protection.
4. **Missing Key File Permission Controls & Unbounded Read (Medium)**: When loading keys from an external file, the application neither verifies strict file permissions (e.g., `0600`) nor limits the maximum file read size, exposing keys stored in world-readable files and risking memory exhaustion.
5. **In-Memory Key Material Retention (Medium)**: Raw decoded key bytes are not zeroized after use, and keys and PII are managed as immutable `String` objects, leaving sensitive data in JVM heap memory.
6. **Information Leakage via Exception Stack Traces (Low)**: Raw exception stack traces are printed to `System.err` using `printStackTrace()`, disclosing internal implementation details and class structures.

Remediations for each finding are detailed in this report, along with verification of the cryptographic controls that functioned securely.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `PIIEncryption.java` | Main application source file implementing AES-256-GCM encryption, decryption, dynamic key resolution, and CLI/interactive execution. | Key generation, key parsing, file reading, command-line argument processing, GCM encryption/decryption, authentication tag verification, standard output logging, and exception handling. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit algorithm selection (AES-256), cipher mode (`AES/GCM/NoPadding`), random number generator (`SecureRandom`), IV management, authentication tag validation, and hardcoded secret scanning.
- `implementing-aes-encryption-for-data-at-rest`: Applied to review AES-GCM AEAD construction, 12-byte nonce generation and uniqueness, authentication tag enforcement, payload packaging `[IV || Ciphertext + Tag]`, and key handling.
- `testing-for-sensitive-data-exposure`: Applied to assess data leakage in standard output / console logs, command-line argument exposure via process tables, and memory handling of sensitive PII.
- Reviewed against general OWASP Top 10 / CWE knowledge:
  - Command-line argument handling and process table exposure (CWE-214, CWE-200)
  - In-memory secret zeroization and immutable string handling (CWE-316, CWE-226)
  - File permission verification for external key storage (CWE-732)
  - Exception handling and stack trace information leakage (CWE-209)

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Plaintext Cryptographic Key Exposure via Standard Output Logging | High | CWE-532 | `PIIEncryption.java:376-383` |
| SEC-02 | Cryptographic Key Exposure via Command-Line Arguments and System Properties | High | CWE-214 | `PIIEncryption.java:108-113` |
| SEC-03 | Exposure of Plaintext Personally Identifiable Information via Console Output | Medium | CWE-532 | `PIIEncryption.java:424-426` |
| SEC-04 | Missing File Permission Verification and Unbounded Read on External Key File | Medium | CWE-732 | `PIIEncryption.java:209-212` |
| SEC-05 | Sensitive Data Retention in Memory via Immutable Strings and Missing Buffer Zeroization | Medium | CWE-316 | `PIIEncryption.java:189-200` |
| SEC-06 | Information Disclosure Through Detailed Exception Stack Traces | Low | CWE-209 | `PIIEncryption.java:498-506` |

## 5. Detailed Findings

### SEC-01: Plaintext Cryptographic Key Exposure via Standard Output Logging
- **Severity:** High
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `PIIEncryption.java:376-383`

**Vulnerable code:**
```java
// PIIEncryption.java:376-383
            System.out.println("  Active Secret Key  : " + base64Key);

            if (keyContext.isNewlyGenerated()) {
                System.out.println();
                System.out.println("  [NOTICE] To persist and reuse this key for subsequent runs, set:");
                System.out.println("           export " + ENV_PII_KEY + "=\"" + base64Key + "\"");
                System.out.println("           or supply via --key / --key-file");
            }
```

**Why it is a problem:** 
On every execution, regardless of whether the cryptographic key was loaded from an environment variable, an external file, or dynamically generated, the program emits the active 256-bit AES key in Base64 plaintext directly to standard output (`System.out`). Standard output is routinely collected by terminal logs, CI/CD pipeline consoles, Docker/Kubernetes container logging daemons, and system audit logs. An unauthorized party who gains access to execution logs can obtain the key and decrypt all historical and future PII encrypted with it, completely compromising confidentiality.

**Fix:** 
Redact or eliminate output of active cryptographic keys from standard output. If a newly generated key must be provided to the user, write it to a user-specified file with restricted permissions (e.g., `0600`), or mask the key when displaying status information.
```java
            System.out.println("  Active Secret Key  : [REDACTED]");

            if (keyContext.isNewlyGenerated()) {
                System.out.println();
                System.out.println("  [NOTICE] A new key was generated. To persist and reuse this key, save");
                System.out.println("           it securely to a protected key file (e.g., permissions 0600)");
                System.out.println("           and supply via --key-file or " + ENV_KEY_FILE + ".");
            }
```

---

### SEC-02: Cryptographic Key Exposure via Command-Line Arguments and System Properties
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Initializer with Untrusted / Sensitive Argument
- **Location:** `PIIEncryption.java:108-113`

**Vulnerable code:**
```java
// PIIEncryption.java:108-113
        for (int i = 0; i < args.length; i++) {
            if (("--key".equalsIgnoreCase(args[i]) || "-k".equalsIgnoreCase(args[i])) && i + 1 < args.length) {
                String keyStr = args[i + 1].trim();
                SecretKey key = keyFromBase64(keyStr);
                return new KeyContext(key, "Command-Line Argument (--key / -k)", false);
            }
```

**Why it is a problem:** 
The application allows users to supply raw Base64-encoded secret keys via command-line arguments (`--key <base64Key>` or `-k <base64Key>`) and Java system properties (`-Dpii.encryption.key`). On multi-user operating systems (such as Linux), process command-line arguments are stored in the system process table and are readable by any local unprivileged user via `ps`, `top`, or `/proc/<pid>/cmdline`. Furthermore, arguments are recorded in shell history files (e.g., `~/.bash_history`) and system process auditing logs (e.g., `auditd`), allowing unprivileged users to capture secret keys without direct filesystem or memory access.

**Fix:** 
Remove support for passing raw cryptographic keys through command-line arguments or system properties. Restrict key acquisition to secure external key files with verified filesystem permissions, environment variables, or secure key management systems.
```java
        for (int i = 0; i < args.length; i++) {
            if ("--key".equalsIgnoreCase(args[i]) || "-k".equalsIgnoreCase(args[i])) {
                throw new IllegalArgumentException(
                    "Passing raw keys via command-line arguments is prohibited due to process listing and shell history exposure. " +
                    "Please use an external key file (--key-file) or the " + ENV_PII_KEY + " environment variable."
                );
            }
            if (("--key-file".equalsIgnoreCase(args[i]) || "-kf".equalsIgnoreCase(args[i])) && i + 1 < args.length) {
                String filePath = args[i + 1].trim();
                SecretKey key = loadKeyFromFile(filePath);
                return new KeyContext(key, "Key File via CLI (--key-file: " + filePath + ")", false);
            }
        }
```

---

### SEC-03: Exposure of Plaintext Personally Identifiable Information via Console Output
- **Severity:** Medium
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `PIIEncryption.java:424-426`

**Vulnerable code:**
```java
// PIIEncryption.java:424-426
            System.out.println("  Full Name     : " + name);
            System.out.println("  Email Address : " + email);
```

**Why it is a problem:** 
The primary objective of PII encryption is to prevent unauthorized disclosure of personal data and maintain compliance with privacy regulations such as GDPR, HIPAA, and CCPA. Printing cleartext full names and email addresses to standard output (both in Section 2 during input echo and Section 4 during decryption recovery) causes PII to be persisted in terminal buffers, process logs, and redirection files, directly undermining the confidentiality controls intended for the sensitive data.

**Fix:** 
Mask or redact sensitive PII when displaying status in console logs, showing only non-identifying characters (or omitting the cleartext values entirely).
```java
            System.out.println("  Full Name     : " + (name.length() > 2 ? name.charAt(0) + "***" : "***"));
            System.out.println("  Email Address : " + (email.contains("@") ? email.charAt(0) + "***@" + email.substring(email.indexOf('@') + 1) : "***"));
```

---

### SEC-04: Missing File Permission Verification and Unbounded Read on External Key File
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `PIIEncryption.java:209-212`

**Vulnerable code:**
```java
// PIIEncryption.java:209-212
    public static SecretKey loadKeyFromFile(String filePath) throws Exception {
        String content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8).trim();
        return keyFromBase64(content);
    }
```

**Why it is a problem:** 
When loading a cryptographic key from an external file path, the method reads the entire file into memory using `Files.readAllBytes` without verifying filesystem permissions. If an administrator or user leaves the key file world-readable (e.g., `0644` or `0666`), any unprivileged user on the local host can read the key. Furthermore, calling `Files.readAllBytes` without bounding the file size exposes the application to resource exhaustion (Denial of Service) if the path points to an extraordinarily large file or a special device file (e.g., `/dev/urandom`).

**Fix:** 
Validate that the path is a regular file, restrict the maximum allowable file size (e.g., 4 KB), and verify that POSIX file permissions do not permit group or other read access (enforcing `0600` or `0400`).
```java
    public static SecretKey loadKeyFromFile(String filePath) throws Exception {
        java.nio.file.Path path = Paths.get(filePath);
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Key file does not exist or is not a regular file: " + filePath);
        }
        if (Files.size(path) > 4096) {
            throw new IllegalArgumentException("Key file exceeds maximum permitted size (4KB).");
        }
        try {
            java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            if (perms.contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ) ||
                perms.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ)) {
                throw new SecurityException("Insecure key file permissions: readable by group or others. Enforce chmod 600 or 400.");
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystem (e.g. Windows); fall back to OS-specific ACL enforcement if needed
        }
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8).trim();
        return keyFromBase64(content);
    }
```

---

### SEC-05: Sensitive Data Retention in Memory via Immutable Strings and Missing Buffer Zeroization
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `PIIEncryption.java:189-200`

**Vulnerable code:**
```java
// PIIEncryption.java:189-200
    public static SecretKey keyFromBase64(String base64Key) {
        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Key string cannot be null or empty.");
        }
        byte[] decodedKey = Base64.getDecoder().decode(base64Key.trim());
        int keyLengthBits = decodedKey.length * 8;
        if (keyLengthBits != 128 && keyLengthBits != 192 && keyLengthBits != 256) {
            throw new IllegalArgumentException(
                    "Invalid AES key length: " + keyLengthBits + " bits. AES keys must be 128, 192, or 256 bits.");
        }
        return new SecretKeySpec(decodedKey, "AES");
    }
```

**Why it is a problem:** 
Key representations and PII strings are handled as immutable `java.lang.String` instances, and the intermediate `decodedKey` byte array created during key reconstruction is abandoned without zeroization. Because `String` objects are immutable in Java, their underlying character/byte contents cannot be overwritten after use and remain on the JVM heap until garbage collected and overwritten. Attackers with access to core dumps, JVM heap dumps, or process memory can extract cleartext keys and PII.

**Fix:** 
Zeroize intermediate byte buffers containing key material immediately after constructing cryptographic key objects using `java.util.Arrays.fill(...)`. Where feasible, handle sensitive user input as `char[]` or `byte[]` arrays that can be explicitly cleared.
```java
    public static SecretKey keyFromBase64(String base64Key) {
        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Key string cannot be null or empty.");
        }
        byte[] decodedKey = Base64.getDecoder().decode(base64Key.trim());
        try {
            int keyLengthBits = decodedKey.length * 8;
            if (keyLengthBits != 128 && keyLengthBits != 192 && keyLengthBits != 256) {
                throw new IllegalArgumentException(
                        "Invalid AES key length: " + keyLengthBits + " bits. AES keys must be 128, 192, or 256 bits.");
            }
            return new SecretKeySpec(decodedKey, "AES");
        } finally {
            java.util.Arrays.fill(decodedKey, (byte) 0);
        }
    }
```

---

### SEC-06: Information Disclosure Through Detailed Exception Stack Traces
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `PIIEncryption.java:498-506`

**Vulnerable code:**
```java
// PIIEncryption.java:498-506
        } catch (GeneralSecurityException e) {
            System.err.println("[SECURITY ERROR] Cryptographic operation failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("[ERROR] Application error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
```

**Why it is a problem:** 
Invoking `e.printStackTrace()` prints the full exception call stack to standard error. In production deployments, detailed stack traces expose internal file system paths, class and method structures, JVM runtime versions, and potentially sensitive contextual parameters to console listeners or centralized error monitoring tools.

**Fix:** 
Replace `e.printStackTrace()` with sanitized, user-friendly error messages that do not expose internal execution details.
```java
        } catch (GeneralSecurityException e) {
            System.err.println("[SECURITY ERROR] Cryptographic operation failed. Verify key validity and ciphertext integrity.");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("[ERROR] An application error occurred. Please check configuration settings.");
            System.exit(1);
        }
```

## 6. Verified Controls and Checks With No Finding
- **Cryptographic Algorithm Strength**: Verified that the application uses AES-256 (NIST FIPS 197) and does not utilize deprecated or broken algorithms such as DES, 3DES, RC4, or MD5 (`PIIEncryption.java:44-47`).
- **Authenticated Encryption Mode (AEAD)**: Verified that Galois/Counter Mode (`AES/GCM/NoPadding`) is enforced, providing both confidentiality and cryptographic integrity while eliminating padding oracle vulnerabilities inherent to CBC mode (`PIIEncryption.java:44, 244, 307`).
- **Absence of Hardcoded Secrets**: Verified that no cryptographic keys, static passphrases, or static salts are embedded in the source code (`PIIEncryption.java:21-40, 106-157`).
- **Cryptographically Secure Pseudo-Random Number Generation**: Verified that IVs and runtime keys are generated using `java.security.SecureRandom` rather than predictable generators such as `java.util.Random` (`PIIEncryption.java:61, 167, 241`).
- **Initialization Vector (IV) Management**: Verified that a fresh 12-byte (96-bit) IV is generated per encryption operation according to NIST SP 800-38D recommendations, preventing nonce reuse vulnerabilities (`PIIEncryption.java:49-50, 240-245`).
- **Authentication Tag Length & Tamper Detection**: Verified that a full 128-bit (16-byte) authentication tag is specified (`GCM_TAG_LENGTH_BITS = 128`) and verified by `cipher.doFinal()`, rejecting tampered ciphertexts with `AEADBadTagException` (`PIIEncryption.java:53, 245, 308, 312, 484-491`).
- **Ciphertext Payload Length Validation**: Verified that `decrypt()` checks the minimum payload length (12-byte IV + 16-byte authentication tag = 28 bytes) before slicing buffers, preventing `IndexOutOfBoundsException` or buffer underflow on truncated inputs (`PIIEncryption.java:290-295`).
