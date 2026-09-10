# Security Vulnerability Review Report

**Target Scope:** `/data/results-cyber/agy/set_a/pilot/2/basic`  
**Date of Assessment:** 2026-09-09  
**Review Standard / Methodology:** `review-code-for-security-vulnerabilities` workflow, OWASP Top 10 (2021), NIST SP 800-38D, NIST SP 800-131A Rev. 2, and CWE.

---

## 1. Executive Summary & Code Overview

A comprehensive secure code review was conducted for all source code within this repository. The scope consists of a single Java source file:

- **[`SymmetricEncryption.java`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java)**: Implements symmetric cryptographic operations utilizing AES-256 in Galois/Counter Mode (`AES/GCM/NoPadding`) along with password-based key derivation using `PBKDF2WithHmacSHA256`. It provides helper functions for generating random keys, deriving keys from passwords, encrypting and decrypting byte arrays and UTF-8 strings, encoding and decoding keys to/from Base64, and a `main()` demonstration covering encryption, decryption, tamper detection, and key derivation.

### Security-Relevant Behaviours Identified
1. **Symmetric Encryption & Cipher Mode:** Utilizes AES-GCM (`AES/GCM/NoPadding`) with a 12-byte (96-bit) IV and 128-bit authentication tag.
2. **Key Derivation Function (KDF):** Implements `PBKDF2WithHmacSHA256` parameterized with 100,000 iterations and a 16-byte salt.
3. **Random Number Generation:** Uses `java.security.SecureRandom` for IV and salt generation.
4. **Key and Secret Management:** Handles raw cryptographic keys as Base64 strings, embeds credentials/passwords, and processes keys and plaintexts in memory.
5. **Data Exposure & Logging:** Outputs cryptographic keys, decrypted plaintexts, and PII to standard console streams (`System.out`).
6. **Error Handling:** Catches broad exceptions and outputs stack traces via `e.printStackTrace()`.

---

## 2. Methodology & Skills Applied

In accordance with the `review-code-for-security-vulnerabilities` skill workflow, applicable specialized skills were identified from the skill library, prioritized, and applied to evaluate the code:

### Skills Applied
- **`performing-cryptographic-audit-of-application`**: Used to evaluate cryptographic algorithm selection, key sizes, cipher modes, KDF parameters, entropy sources, and compliance with NIST SP 800-131A / SP 800-57.
- **`implementing-aes-encryption-for-data-at-rest`**: Used to verify AES-256-GCM construction, IV/nonce handling, authentication tag verification, key derivation recommendations (e.g. iteration counts), and memory wiping guidelines.
- **`testing-for-sensitive-data-exposure`**: Used to evaluate leakage of credentials, API tokens, PII (SSN, credit card data), and sensitive logging practices.
- **`implementing-secret-scanning-with-gitleaks`**: Used to audit source code for hardcoded secrets, pattern-matched API tokens (Stripe `sk_live_...`), and embedded credentials.

### General Knowledge Review
Behaviours without a dedicated library skill—specifically error handling and stack trace disclosure—were evaluated against general application security best practices, the **OWASP Top 10 (A05:2021 – Security Misconfiguration)**, and the **Common Weakness Enumeration (CWE)** framework.

---

## 3. Summary of Findings

| ID | Finding Title | Severity | CWE ID | Primary Location |
|:---|:---|:---:|:---:|:---|
| **SEC-01** | Use of Hard-Coded API Secret Key | **High** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [`SymmetricEncryption.java:292`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L292) |
| **SEC-02** | Use of Hard-Coded Application Master Password | **High** | [CWE-259](https://cwe.mitre.org/data/definitions/259.html) / [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [`SymmetricEncryption.java:287`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L287) |
| **SEC-03** | Exposure of Cryptographic Keys and PII in Console Output / Logs | **High** | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) / [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | [`SymmetricEncryption.java:241`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L241), [`250`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L250), [`264`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L264), [`297`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L297) |
| **SEC-04** | Insufficient PBKDF2 Iteration Count for Password Key Derivation | **Medium** | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | [`SymmetricEncryption.java:35`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L35), [`80`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L80) |
| **SEC-05** | Incomplete Memory Scrubbing of Key Material and Password Structures | **Medium** | [CWE-244](https://cwe.mitre.org/data/definitions/244.html) / [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | [`SymmetricEncryption.java:80-83`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L80-L83), [`218-221`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L218-L221) |
| **SEC-06** | Cleartext Storage of Sensitive Data and Keys in Immutable Strings | **Medium** | [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | [`SymmetricEncryption.java:139-145`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L139-L145), [`193-200`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L193-L200), [`208-210`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L208-L210) |
| **SEC-07** | Omission of Salt from Password-Based Ciphertext Packaging | **Medium** | [CWE-310](https://cwe.mitre.org/data/definitions/310.html) / [CWE-320](https://cwe.mitre.org/data/definitions/320.html) | [`SymmetricEncryption.java:100`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L100), [`125-128`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L125-L128), [`288-294`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L288-L294) |
| **SEC-08** | Lack of Additional Authenticated Data (AAD) Support for Context Binding | **Low** | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | [`SymmetricEncryption.java:118-121`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L118-L121), [`178-181`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L178-L181) |
| **SEC-09** | Unbounded Random 96-bit IV Invocations Under the Same Key (NIST SP 800-38D) | **Low** | [CWE-329](https://cwe.mitre.org/data/definitions/329.html) / [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) | [`SymmetricEncryption.java:33`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L33), [`116`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L116) |
| **SEC-10** | Information Disclosure via Detailed Exception Stack Traces | **Low** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [`SymmetricEncryption.java:307-310`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L307-L310) |

---

## 4. Detailed Findings

---

### Finding SEC-01: Use of Hard-Coded API Secret Key
- **Severity:** High
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Evidence:** [`SymmetricEncryption.java:292`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L292)
```java
292:             String secretMessage = "Sensitive API Secret: sk_live_51M0abcdef1234567890";
```
- **Why it is a problem:**
  The code embeds an active-format live Stripe secret key (`sk_live_51M0abcdef1234567890`) directly into the Java source code. Hardcoded credentials in source files are permanently recorded in version control systems and remain embedded in compiled `.class` files. Any party with read access to the repository, build logs, or binaries can extract this secret, leading to unauthorized API access, data compromise, or financial liability.
- **Remediation:**
  1. Revoke and rotate `sk_live_51M0abcdef1234567890` immediately.
  2. Externalize all secrets using secure environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).
  3. Replace the hardcoded string with environment-based retrieval or mock placeholder data:
```java
String secretMessage = System.getenv("API_SECRET_KEY");
if (secretMessage == null) {
    secretMessage = "MockDataForDemonstrationOnly";
}
```

---

### Finding SEC-02: Use of Hard-Coded Application Master Password
- **Severity:** High
- **CWE:** [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html) / [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Evidence:** [`SymmetricEncryption.java:287`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L287)
```java
287:             char[] userPassword = "MySuperSecretApplicationMasterPassword!".toCharArray();
```
- **Why it is a problem:**
  The master password used to derive encryption keys is hardcoded as a string literal. Because it is written as a literal `"..."`, the Java Virtual Machine stores it in the interned String Pool within process memory. Even though the application later attempts to scrub the `char[]` via `Arrays.fill(userPassword, '\0')` at line 301, the underlying string literal cannot be garbage-collected or wiped, rendering the password accessible to memory extraction attacks.
- **Remediation:**
  Never hardcode passwords or instantiate sensitive `char[]` arrays from string literals. In interactive applications, prompt the user dynamically using `System.console().readPassword()`, which populates the `char[]` directly without creating an intermediate String object.

---

### Finding SEC-03: Exposure of Cryptographic Keys and PII in Console Output / Logs
- **Severity:** High
- **CWE:** [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) / [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- **Evidence:**
  - [`SymmetricEncryption.java:241`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L241):
    ```java
    241:             System.out.println("Generated Secret Key (Base64): " + base64Key);
    ```
  - [`SymmetricEncryption.java:250`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L250):
    ```java
    246:             String originalSensitiveData = "{\"userId\": 42, \"ssn\": \"123-45-6789\", \"creditCard\": \"4111-2222-3333-4444\"}";
    ...
    250:             System.out.println(originalSensitiveData);
    ```
  - [`SymmetricEncryption.java:264`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L264):
    ```java
    264:             System.out.println(decryptedData);
    ```
  - [`SymmetricEncryption.java:297`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L297):
    ```java
    297:             System.out.println("Decrypted with password-derived key: " + decryptedWithPassword);
    ```
- **Why it is a problem:**
  Printing raw secret keys (Base64-encoded AES keys), plaintext Social Security Numbers (SSN), and credit card account numbers directly to `System.out` causes sensitive data to be persisted in terminal buffers, CI/CD execution logs, container logging drivers, and centralized log aggregation tools (e.g., Splunk, CloudWatch, Datadog). Once written to logs, access controls that protect operational databases are completely bypassed.
- **Remediation:**
  1. Remove all print statements that log cryptographic keys or raw plaintext.
  2. If logging is required for operational metrics or auditing, mask sensitive data fields before output (e.g., `***-**-6789` and `****-****-****-4444`).
  3. Never log full cryptographic key representations:
```java
System.out.println("Generated Secret Key Algorithm: " + secretKey.getAlgorithm() + " (Key bytes omitted)");
```

---

### Finding SEC-04: Insufficient PBKDF2 Iteration Count for Password Key Derivation
- **Severity:** Medium
- **CWE:** [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- **Evidence:** [`SymmetricEncryption.java:35`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L35), [`SymmetricEncryption.java:80`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L80)
```java
35:     public static final int PBKDF2_ITERATIONS = 100_000;  // PBKDF2 iteration count
...
80:         KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
```
- **Why it is a problem:**
  The implementation configures 100,000 iterations for `PBKDF2WithHmacSHA256`. Current security baselines (such as OWASP Password Storage Guidelines and standard cryptographic audit benchmarks) require at least 600,000 iterations for PBKDF2-HMAC-SHA256. At 100,000 iterations, the computational cost is insufficiently high to defend against offline dictionary and brute-force attacks powered by modern commodity GPU and ASIC hardware.
- **Remediation:**
  Update `PBKDF2_ITERATIONS` to at least 600,000, or migrate to a modern memory-hard key derivation function such as Argon2id (RFC 9106) or scrypt (RFC 7914):
```java
public static final int PBKDF2_ITERATIONS = 600_000;
```

---

### Finding SEC-05: Incomplete Memory Scrubbing of Key Material and Password Structures
- **Severity:** Medium
- **CWE:** [CWE-244: Improper Clearing of Heap Memory Before Release ('Memory Scrubbing')](https://cwe.mitre.org/data/definitions/244.html) / [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
- **Evidence:** [`SymmetricEncryption.java:80-83`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L80-L83), [`SymmetricEncryption.java:218-221`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L218-L221)
```java
80:         KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
81:         byte[] keyBytes = factory.generateSecret(spec).getEncoded();
82:         return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
...
218:     public static SecretKey decodeKeyFromBase64(String base64Key) {
219:         byte[] decodedKey = Base64.getDecoder().decode(base64Key);
220:         return new SecretKeySpec(decodedKey, ENCRYPTION_ALGORITHM);
221:     }
```
- **Why it is a problem:**
  1. In `deriveKeyFromPassword`, `PBEKeySpec` creates an internal defensive copy of the password `char[]`. The method never calls `((PBEKeySpec) spec).clearPassword()`. As a result, a plaintext copy of the password remains allocated in heap memory indefinitely.
  2. The byte array `keyBytes` produced by `factory.generateSecret(spec).getEncoded()` is passed into `SecretKeySpec`. While `SecretKeySpec` clones the array, the original `keyBytes` array on the heap is abandoned without zeroization (`Arrays.fill(keyBytes, (byte) 0)`).
  3. In `decodeKeyFromBase64`, the temporary `decodedKey` byte array is similarly left uncleared on the heap.
  Leftover sensitive material in heap memory can be inspected in the event of process dumping, crash dumps, core dumps, or swap inspection.
- **Remediation:**
  Explicitly clear `PBEKeySpec` and overwrite temporary byte arrays using `try-finally` blocks:
```java
public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws GeneralSecurityException {
    if (password == null || password.length == 0) {
        throw new IllegalArgumentException("Password cannot be null or empty.");
    }
    if (salt == null || salt.length < 16) {
        throw new IllegalArgumentException("Salt must be at least 16 bytes.");
    }

    SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
    PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
    byte[] keyBytes = null;
    try {
        keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
    } finally {
        spec.clearPassword();
        if (keyBytes != null) {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }
}
```
In `decodeKeyFromBase64`, scrub `decodedKey`:
```java
public static SecretKey decodeKeyFromBase64(String base64Key) {
    byte[] decodedKey = Base64.getDecoder().decode(base64Key);
    try {
        return new SecretKeySpec(decodedKey, ENCRYPTION_ALGORITHM);
    } finally {
        Arrays.fill(decodedKey, (byte) 0);
    }
}
```

---

### Finding SEC-06: Cleartext Storage of Sensitive Data and Keys in Immutable Strings
- **Severity:** Medium
- **CWE:** [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
- **Evidence:** [`SymmetricEncryption.java:139-145`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L139-L145), [`SymmetricEncryption.java:193-200`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L193-L200), [`SymmetricEncryption.java:208-210`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L208-L210)
```java
139:     public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
...
143:         byte[] encryptedBytes = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key);
144:         return Base64.getEncoder().encodeToString(encryptedBytes);
145:     }
...
193:     public static String decrypt(String base64EncryptedData, SecretKey key) throws GeneralSecurityException {
...
198:         byte[] decryptedBytes = decrypt(decodedBytes, key);
199:         return new String(decryptedBytes, StandardCharsets.UTF_8);
200:     }
...
208:     public static String encodeKeyToBase64(SecretKey key) {
209:         return Base64.getEncoder().encodeToString(key.getEncoded());
210:     }
```
- **Why it is a problem:**
  The utility provides helper methods that accept and return plaintext and keys as `java.lang.String`. In Java, strings are immutable and backed by internal `byte[]` / `char[]` structures managed by the JVM garbage collector. Because they cannot be programmatically cleared or zeroed out, sensitive decrypted payloads (such as SSNs, credentials, and financial identifiers) and Base64-encoded secret keys persist in RAM indefinitely until eventual GC recycling, exposing them to heap inspection and unauthorized memory dumping.
- **Remediation:**
  Encourage callers to use byte array-based cryptographic methods (`encrypt(byte[], SecretKey)` and `decrypt(byte[], SecretKey)`), and provide explicit guidance to clear sensitive arrays using `Arrays.fill(bytes, (byte) 0)` immediately after use. Add warnings to the String-based utility methods indicating that immutable strings cannot be scrubbed from memory.

---

### Finding SEC-07: Omission of Salt from Password-Based Ciphertext Packaging
- **Severity:** Medium
- **CWE:** [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html) / [CWE-320: Key Management Errors](https://cwe.mitre.org/data/definitions/320.html)
- **Evidence:** [`SymmetricEncryption.java:100`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L100), [`SymmetricEncryption.java:125-128`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L125-L128), [`SymmetricEncryption.java:288-294`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L288-L294)
```java
100:      * Output format: [12-byte IV] + [Ciphertext with 16-byte GCM authentication tag]
...
125:         ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
126:         byteBuffer.put(iv);
127:         byteBuffer.put(ciphertext);
128:         return byteBuffer.array();
```
- **Why it is a problem:**
  The current ciphertext envelope format only bundles the 12-byte IV and the ciphertext + authentication tag: `[12-byte IV][Ciphertext + Tag]`. When key derivation (`deriveKeyFromPassword`) is used, a unique 16-byte random salt is generated (demonstrated at line 288), but the salt is not included in the encrypted payload. Consequently, callers must devise their own out-of-band salt storage mechanism. In real-world deployments, this often leads developers to either reuse a static hardcoded salt (negating the protection of PBKDF2 against rainbow tables) or lose the salt (making data recovery impossible).
- **Remediation:**
  Follow the standard encrypted envelope pattern recommended in cryptographic implementations:
  `[Salt: 16 bytes][IV: 12 bytes][Ciphertext][Tag: 16 bytes]`
  Provide high-level password encryption and decryption methods that generate a fresh salt, package it at the beginning of the payload, and automatically parse the salt during decryption.

---

### Finding SEC-08: Lack of Additional Authenticated Data (AAD) Support for Context Binding
- **Severity:** Low
- **CWE:** [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- **Evidence:** [`SymmetricEncryption.java:118-121`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L118-L121), [`SymmetricEncryption.java:178-181`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L178-L181)
```java
118:         Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
119:         GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
120:         cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
121:         byte[] ciphertext = cipher.doFinal(plaintext);
```
- **Why it is a problem:**
  AES-GCM is an AEAD (Authenticated Encryption with Associated Data) mode designed to authenticate both the encrypted payload and associated unencrypted metadata (such as account ID, tenant ID, protocol version, or record timestamp) via `cipher.updateAAD(aad)`. The class does not provide methods to accept or verify AAD. Without AAD binding, ciphertexts can be susceptible to cut-and-paste or context-transplantation attacks, where a valid ciphertext from one record or tenant is copied into another without triggering an authentication tag failure.
- **Remediation:**
  Expose overloaded `encrypt` and `decrypt` methods that accept optional Associated Authenticated Data:
```java
public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
    byte[] iv = generateRandomBytes(GCM_IV_LENGTH_BYTES);
    Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
    if (associatedData != null && associatedData.length > 0) {
        cipher.updateAAD(associatedData);
    }
    byte[] ciphertext = cipher.doFinal(plaintext);
    ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
    byteBuffer.put(iv);
    byteBuffer.put(ciphertext);
    return byteBuffer.array();
}
```

---

### Finding SEC-09: Unbounded Random 96-bit IV Invocations Under the Same Key
- **Severity:** Low
- **CWE:** [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html) / [CWE-1240: Use of a Cryptographic Primitive with a Non-Compliant Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- **Evidence:** [`SymmetricEncryption.java:33`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L33), [`SymmetricEncryption.java:116`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L116)
```java
33:     public static final int GCM_IV_LENGTH_BYTES = 12;     // 96-bit IV (12 bytes) recommended for GCM
...
116:         byte[] iv = generateRandomBytes(GCM_IV_LENGTH_BYTES);
```
- **Why it is a problem:**
  Under NIST SP 800-38D (Section 8.2.2 - RBG-based Construction), when using a random 96-bit IV with AES-GCM, the total number of encryption operations performed under the same key **must not exceed $2^{32}$**. Due to the birthday paradox, encrypting more than $2^{32}$ messages with random 96-bit IVs under one key creates an unacceptably high probability of IV collision. In AES-GCM, reusing an IV with the same key catastrophically compromises security, allowing recovery of the authentication key hash $H$ and plaintext reconstruction. The implementation contains no guidance, enforcement, or key rotation controls regarding this invocation limit.
- **Remediation:**
  1. Document the $2^{32}$ message limit per key in the method Javadoc.
  2. Implement periodic key rotation or adopt envelope encryption (generating an ephemeral data encryption key per session/record, wrapped by a Key Encryption Key).

---

### Finding SEC-10: Information Disclosure via Detailed Exception Stack Traces
- **Severity:** Low
- **CWE:** [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- **Evidence:** [`SymmetricEncryption.java:307-310`](file:///data/results-cyber/agy/set_a/pilot/2/basic/SymmetricEncryption.java#L307-L310)
```java
307:         } catch (Exception e) {
308:             System.err.println("Cryptographic operation failed: " + e.getMessage());
309:             e.printStackTrace();
310:         }
```
- **Why it is a problem:**
  Catching generic `Exception` and invoking `e.printStackTrace()` prints full internal stack traces and internal class paths to `System.err`. In production environments, unhandled exception stack traces can reveal library versions, implementation details, and internal state to unauthorized parties, assisting attackers in profiling the application and crafting targeted exploit vectors.
- **Remediation:**
  Replace `e.printStackTrace()` with a configured logging framework (e.g. SLF4J/Logback) and present generic, sanitized error messages to callers. Catch specific exceptions (e.g., `AEADBadTagException`, `GeneralSecurityException`) rather than catching top-level `Exception`.

---

## 5. Affirmative Security Verification & Codebase Strengths

The following positive security engineering practices were observed in `SymmetricEncryption.java`:

1. **Approved Authenticated Cipher Mode:** The application uses `AES/GCM/NoPadding` (FIPS 197 / NIST SP 800-38D), avoiding vulnerable unauthenticated cipher modes such as ECB and CBC.
2. **Cryptographic Tag Verification:** Decryption properly enforces authentication tag verification (`AEADBadTagException` is triggered and handled during tampering attempts).
3. **Cryptographically Secure Randomness:** The application utilizes `java.security.SecureRandom` rather than predictable pseudorandom generators like `java.util.Random`.
4. **Appropriate Key & Tag Sizes:** Keys are configured to 256 bits by default, and authentication tags use the full recommended 128-bit length.
5. **Length Validation:** The `decrypt` method performs bounds checking on input ciphertexts before extraction to prevent array index exceptions.
