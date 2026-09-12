# Symmetric Encryption & Decryption in Java

A complete, production-ready Java application that demonstrates how to securely encrypt and decrypt sensitive application data using symmetric encryption and the standard Java Cryptography Architecture (`javax.crypto`, `java.security`).

---

## Features

- **Standard Java Cryptography APIs**: Built strictly using the Java Standard Library (`javax.crypto`, `java.security`, `java.nio`, `java.util`). No external dependencies or third-party libraries required.
- **Modern AEAD Cipher**: Uses **AES-256-GCM** (`AES/GCM/NoPadding`), providing **Authenticated Encryption with Associated Data**. This guarantees both data **confidentiality** and **integrity/authenticity** against tampering or chosen-ciphertext attacks.
- **Cryptographically Secure IVs**: Generates a fresh, unpredictable 96-bit (12-byte) Initialization Vector (IV) via `java.security.SecureRandom` for every encryption operation.
- **Combined Wire Format**: Employs the industry-standard packed payload format `[IV (12 bytes)] + [Ciphertext + Auth Tag (16 bytes)]`, encoded as standard Base64 for easy database storage, JSON serialization, and API transmission.
- **Tamper Detection**: Cryptographically verifies the 128-bit GCM authentication tag upon decryption, immediately raising `AEADBadTagException` if ciphertext or IV has been altered.
- **Password-Based Encryption (PBE)**: Supports password/passphrase-based encryption using **PBKDF2WithHmacSHA256** with a random 128-bit salt and 310,000 iterations (OWASP recommendation).
- **Flexible Execution Modes**:
  - Automated demonstration mode showcasing end-to-end encryption, decryption, and tamper detection.
  - Interactive console menu for testing custom data on the fly.
  - Direct Command-Line Interface (CLI) for scripting and pipeline automation.

---

## Cryptographic Design & Parameters

| Component | Specification | Description |
| :--- | :--- | :--- |
| **Cipher Algorithm** | AES (`AES/GCM/NoPadding`) | Advanced Encryption Standard in Galois/Counter Mode |
| **Key Size** | 256 bits (32 bytes) | High security symmetric key generated via `KeyGenerator` |
| **IV / Nonce** | 96 bits (12 bytes) | Generated uniquely per encryption using `SecureRandom` |
| **Auth Tag Length** | 128 bits (16 bytes) | Protects ciphertext from tampering and bit-flipping |
| **PBE Algorithm** | `PBKDF2WithHmacSHA256` | Password-based key derivation function |
| **PBE Salt Length** | 128 bits (16 bytes) | Unique salt per password encryption |
| **PBE Iterations** | 310,000 | Conforms to OWASP Password Storage & Derivation Guidelines |
| **Encoding** | Base64 (`java.util.Base64`) | URL-safe and standard string representation |

---

## Prerequisites

- **Java Development Kit (JDK)**: JDK 8 or higher (tested on OpenJDK 17).
- Verify your Java installation:
  ```bash
  java -version
  javac -version
  ```

---

## Compilation

Compile the Java source file using the standard Java compiler (`javac`):

```bash
javac SymmetricEncryptionApp.java
```

This generates `SymmetricEncryptionApp.class`.

---

## Running the Application

### 1. Automated Demonstration Mode

To run an end-to-end demonstration that generates a key, encrypts sensitive JSON data, decrypts it, verifies integrity, demonstrates tamper rejection, and runs password-based encryption:

```bash
java SymmetricEncryptionApp --demo
```

*(Note: Running `java SymmetricEncryptionApp` with no arguments will run the demo and then enter interactive mode if an interactive terminal is present.)*

### 2. Interactive Menu Mode

Launch an interactive console where you can generate keys and encrypt/decrypt arbitrary strings:

```bash
java SymmetricEncryptionApp --interactive
```

### 3. Command-Line Interface (CLI) Commands

#### A. Generate an AES-256 Key
Generates a new, cryptographically strong 256-bit AES key formatted as Base64:
```bash
java SymmetricEncryptionApp keygen
```
*Example Output:*
```text
oVTN/NvKB+HaBL+fnO5rW9UIuAhvuWkR8BpvkCKPZPQ=
```

#### B. Encrypt Plaintext Using an AES Key
```bash
java SymmetricEncryptionApp encrypt "Sensitive credit card data: 4111-2222-3333-4444" "<BASE64_KEY>"
```
*Example Output:*
```text
At40h6YkdlmzaNwF0gdMsPQ8ksvq4dUS9ZMwGf016tajYhGOWTcTMKIIBHM7ucDE...
```

#### C. Decrypt Ciphertext Using an AES Key
```bash
java SymmetricEncryptionApp decrypt "<BASE64_CIPHERTEXT>" "<BASE64_KEY>"
```
*Example Output:*
```text
Sensitive credit card data: 4111-2222-3333-4444
```

#### D. Encrypt Plaintext Using a Password (PBKDF2)
```bash
java SymmetricEncryptionApp encrypt-pw "Secret API Token: sk_live_987654321" "MySecretPassword!2026"
```

#### E. Decrypt Ciphertext Using a Password (PBKDF2)
```bash
java SymmetricEncryptionApp decrypt-pw "<BASE64_CIPHERTEXT>" "MySecretPassword!2026"
```

---

## Programmatic API Usage

You can also use `SymmetricEncryptionApp` directly as a utility class within your own Java application.

### Symmetric Key Encryption Example

```java
import javax.crypto.SecretKey;

// 1. Generate or load a 256-bit AES key
SecretKey key = SymmetricEncryptionApp.generateKey();
String base64Key = SymmetricEncryptionApp.encodeKeyToBase64(key);

// Or load an existing key:
// SecretKey key = SymmetricEncryptionApp.decodeKeyFromBase64("your-base64-key");

// 2. Encrypt sensitive plaintext
String plaintext = "{\"accountNumber\": 123456789, \"balance\": 9500.50}";
String ciphertext = SymmetricEncryptionApp.encryptString(plaintext, key);

// 3. Decrypt ciphertext back to original plaintext
String decrypted = SymmetricEncryptionApp.decryptString(ciphertext, key);
System.out.println("Decrypted: " + decrypted);
```

### Password-Based Encryption Example

```java
char[] password = "UserProvidedPassphrase!".toCharArray();

// Encrypt
String ciphertext = SymmetricEncryptionApp.encryptWithPassword("Top secret payload", password);

// Decrypt
String decrypted = SymmetricEncryptionApp.decryptWithPassword(ciphertext, password);

// Clear password from memory when done
java.util.Arrays.fill(password, '0');
```

---

## Security Best Practices Implemented

1. **Why AES-GCM over AES-CBC or AES-ECB?**
   - **ECB mode** is insecure because identical plaintext blocks produce identical ciphertext blocks, revealing patterns.
   - **CBC mode** provides confidentiality only and is vulnerable to padding oracle attacks (e.g., POODLE) unless combined with a separate MAC using an Encrypt-then-MAC scheme.
   - **GCM mode** (Galois/Counter Mode) provides **AEAD** (Authenticated Encryption with Associated Data). It prevents padding oracle vulnerabilities and guarantees that if any part of the ciphertext or IV is altered, decryption will fail immediately with `AEADBadTagException`.

2. **Initialization Vector (IV) Uniqueness:**
   - In GCM mode, an IV must **never** be reused with the same key. A fresh 12-byte IV is generated via `SecureRandom` for every single encryption call.
   - The 12-byte IV is prepended to the ciphertext payload so the decryptor can cleanly unpack it without needing separate storage for the IV.

3. **Memory Hygiene:**
   - Sensitive password characters are accepted as `char[]` arrays and can be cleared with zeros (`Arrays.fill(pwd, '0')`) immediately after derivation, preventing plaintexts from lingering in heap dumps.
