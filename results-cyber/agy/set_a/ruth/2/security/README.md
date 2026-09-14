# Symmetric Cryptography for Sensitive Application Data in Java

A complete, production-grade Java application and service implementing symmetric encryption and decryption for sensitive application data using Java standard cryptography APIs (Java Cryptography Architecture / JCA).

---

## Table of Contents
1. [Overview & Security Architecture](#overview--security-architecture)
2. [Key Management Architecture](#key-management-architecture)
3. [Cryptographic Design Decisions](#cryptographic-design-decisions)
4. [Payload Container Specification](#payload-container-specification)
5. [Prerequisites](#prerequisites)
6. [Compilation](#compilation)
7. [Running the Application](#running-the-application)
   - [Automated Verification & Demonstration (`demo`)](#1-automated-verification--demonstration-demo)
   - [Managing Keys in a PKCS#12 KeyStore](#2-managing-keys-in-a-pkcs12-keystore)
   - [Encrypting & Decrypting Data with KeyStore Keys](#3-encrypting--decrypting-data-with-keystore-keys)
   - [Encrypting & Decrypting Data with Password Derivation (PBKDF2)](#4-encrypting--decrypting-data-with-password-derivation-pbkdf2)
   - [Context-Bound Encryption with Additional Authenticated Data (AAD)](#5-context-bound-encryption-with-additional-authenticated-data-aad)
   - [File and Stream / Pipe Operations](#6-file-and-stream--pipe-operations)
8. [Programmatic API Usage (Embedding in Java Projects)](#programmatic-api-usage-embedding-in-java-projects)
9. [Summary of Security Best Practices](#summary-of-security-best-practices)

---

## Overview & Security Architecture

This application provides robust symmetric encryption and decryption designed for sensitive data such as:
- Personally Identifiable Information (PII: Social Security Numbers, phone numbers, birth dates)
- Payment card data (PAN, CVV, bank account details)
- Protected Health Information (PHI)
- Application secrets, database credentials, and session tokens

### Core Cryptographic Specifications
| Parameter | Choice / Standard | Rationale |
| :--- | :--- | :--- |
| **Symmetric Cipher** | `AES` (Advanced Encryption Standard) | FIPS 197 standard; hardware-accelerated via AES-NI on modern CPUs |
| **Cipher Mode** | `GCM` (Galois/Counter Mode) | AEAD (Authenticated Encryption with Associated Data); provides both confidentiality and data integrity |
| **Padding** | `NoPadding` | GCM operates as a stream cipher internally, eliminating padding oracle vulnerabilities |
| **Key Size** | 256 bits (32 bytes) | Maximum AES strength; quantum-resistant against Grover's algorithm brute force |
| **Initialization Vector (IV / Nonce)** | 12 bytes (96 bits) | NIST SP 800-38D standard length; generated uniquely via `SecureRandom` per encryption |
| **Authentication Tag** | 128 bits (16 bytes) | NIST recommendation; detects any tampering, bit-flipping, or data corruption |
| **Key Storage** | PKCS#12 KeyStore (`.p12`) | Standardized, portable, password-encrypted key repository; POSIX `0600` file permissions |
| **Key Derivation (KDF)** | `PBKDF2WithHmacSHA256` | OWASP recommended password hashing algorithm; 310,000 iterations with 128-bit random salt |

---

## Key Management Architecture

A cryptographic algorithm is only as secure as the management of its keys. This application follows rigorous key lifecycle principles:

### 1. Key Generation
- Generated using `KeyGenerator.getInstance("AES")` initialized to 256 bits.
- Seeded with `SecureRandom.getInstanceStrong()`, which draws entropy from the operating system's cryptographic random source (`/dev/urandom` or CSPRNG).

### 2. Key Storage (`KeyStoreManager`)
- **PKCS#12 Format**: Uses Java's default and industry-standard `PKCS12` keystore type.
- **Dual-Layer Protection**:
  1. *KeyStore Master Password*: Protects the entire keystore file against unauthorized extraction or offline tampering.
  2. *Key Entry Password*: Protects individual `SecretKeyEntry` instances inside the keystore.
- **Strict File System Permissions**: On POSIX-compliant systems (Linux/macOS), keystore files are automatically created with `0600` (read/write only by the file owner) to prevent unauthorized local access.
- **Key Aliasing & Rotation**: Keys are referenced by human-readable aliases (e.g., `dek-2026-v1`, `payment-dek-v2`). This enables zero-downtime key rotation: new records are encrypted with the new alias while old records can still be decrypted with the previous alias.

### 3. Password-Based Key Derivation (PBKDF2)
- For scenarios where data must be encrypted with a user-provided passphrase rather than a pre-shared KeyStore key.
- Uses `PBKDF2WithHmacSHA256` with:
  - **Salt**: 16 bytes (128 bits) of cryptographic randomness generated uniquely for every encryption.
  - **Work Factor**: 310,000 iterations (OWASP recommendation), significantly raising the computational cost of brute-force and dictionary attacks.

### 4. In-Memory Cryptographic Hygiene
- Passwords are collected and handled as `char[]` rather than immutable `java.lang.String`. Strings reside in the JVM heap and string intern pool indefinitely until garbage collected, creating risks in heap dump analysis.
- The `wipe(char[])` and `wipe(byte[])` utility methods explicitly overwrite sensitive arrays with null bytes (`\0` or `0x00`) as soon as cryptographic operations conclude.

---

## Cryptographic Design Decisions

### Why AES-GCM (AEAD) instead of AES-CBC?
- **CBC Mode Vulnerabilities**: Unauthenticated modes like `AES/CBC/PKCS5Padding` are vulnerable to padding oracle attacks and bit-flipping attacks (where an attacker modifies ciphertext bits to alter decrypted plaintext in predictable ways).
- **Authenticated Encryption**: GCM produces a 128-bit cryptographic authentication tag over both the ciphertext and the IV. If an attacker tampers with even a single bit of the ciphertext or IV, Java's `Cipher.doFinal()` throws `AEADBadTagException`, preventing corrupted or malicious data from reaching application logic.

### Why 12-byte IVs?
NIST SP 800-38D recommends a 96-bit (12-byte) IV for AES-GCM. Non-12-byte IVs require an additional GHASH computation before initialization, introducing computational overhead and subtle edge-case risks.

### Why Unique IVs per Encryption?
Reusing an IV with the same AES key under GCM is catastrophic—it leaks the XOR of plaintexts and allows an adversary to forge authentication tags. The implementation guarantees a freshly generated random IV for every encryption call using `SecureRandom`.

### Additional Authenticated Data (AAD)
GCM supports "associated data"—metadata that is authenticated but not encrypted. This binds ciphertext to its application context (e.g., `tenant-id`, `record-id`, `table-name`). If an attacker copies valid ciphertext from one tenant's database record to another, decryption fails because the associated metadata will not match.

---

## Payload Container Specification

Encrypted payloads are packaged into self-describing binary containers and Base64-encoded for safe storage and transmission in JSON, REST APIs, or databases:

### Format 0x01: KeyStore / Pre-Shared Key Payload
```
+----------------+---------------------+---------------------------------------+
| Version (1 B)  | IV / Nonce (12 B)   | Ciphertext + GCM Auth Tag (Variable)  |
| 0x01           | SecureRandom        | Encrypted bytes + 16-byte Tag         |
+----------------+---------------------+---------------------------------------+
```

### Format 0x02: Password-Derived (PBKDF2) Payload
```
+---------------+---------------+--------------------+---------------+----------------------------+
| Version (1 B) | Salt (16 B)   | Iterations (4 B)   | IV (12 B)     | Ciphertext + Tag (Var)     |
| 0x02          | SecureRandom  | Big-Endian Int     | SecureRandom  | Encrypted bytes + 16B Tag  |
+---------------+---------------+--------------------+---------------+----------------------------+
```

This self-describing structure ensures that decryption routines can automatically extract the necessary parameters (salt, iteration count, and IV) without requiring external metadata tables.

---

## Prerequisites

- **Java Development Kit (JDK)**: Java 11 or higher (JDK 17+ recommended).
- **Operating System**: Linux, macOS, or Windows.
- **Dependencies**: None. The program uses only standard Java runtime libraries (`javax.crypto`, `java.security`, `java.nio`).

---

## Compilation

Compile the single source file using the standard Java compiler:

```bash
javac SymmetricCryptoApp.java
```

To compile with all compiler lint checks enabled:
```bash
javac -Xlint:all SymmetricCryptoApp.java
```

---

## Running the Application

The application includes a comprehensive CLI that supports both interactive and scripted execution.

### 1. Automated Verification & Demonstration (`demo`)
Run the built-in test suite to verify cryptographic correctness, key management, tamper detection, AAD, and PBKDF2 derivation:

```bash
java SymmetricCryptoApp demo
```

**What the demo exercises:**
1. Generates a secure 256-bit AES key and saves it to a PKCS#12 keystore file.
2. Retrieves the key from the keystore using dual passwords.
3. Encrypts a sensitive JSON payload (PII and financial record) using AES-256-GCM.
4. Decrypts the ciphertext container and verifies exact plaintext recovery.
5. Injects a 1-bit corruption into the ciphertext to prove that `AEADBadTagException` blocks tampering.
6. Encrypts with AAD context (`tenant-id`) and demonstrates that context-swapping is detected and rejected.
7. Performs password-based encryption and decryption using PBKDF2 key derivation.
8. Demonstrates secure in-memory array wiping.

---

### 2. Managing Keys in a PKCS#12 KeyStore

#### Initialize an empty KeyStore:
```bash
java SymmetricCryptoApp init-keystore -k app-keystore.p12 -p MasterPass123!
```

#### Generate a 256-bit AES key inside the KeyStore:
```bash
java SymmetricCryptoApp generate-key \
  -k app-keystore.p12 \
  -a customer-dek \
  -kp MasterPass123! \
  -p KeySecret456!
```
*(Parameters: `-k` keystore path, `-a` alias, `-kp` keystore master password, `-p` key entry password)*

#### List stored key aliases:
```bash
java SymmetricCryptoApp list-keys -k app-keystore.p12 -p MasterPass123!
```

---

### 3. Encrypting & Decrypting Data with KeyStore Keys

#### Encrypt plaintext string:
```bash
java SymmetricCryptoApp encrypt \
  -k app-keystore.p12 \
  -a customer-dek \
  -kp MasterPass123! \
  -p KeySecret456! \
  -t "Sensitive Patient Record: SSN 000-12-3456"
```
*Output: A Base64-encoded ciphertext string.*

#### Decrypt ciphertext string:
```bash
java SymmetricCryptoApp decrypt \
  -k app-keystore.p12 \
  -a customer-dek \
  -kp MasterPass123! \
  -p KeySecret456! \
  -t "<paste-base64-string-here>"
```
*Output: Original sensitive plaintext.*

---

### 4. Encrypting & Decrypting Data with Password Derivation (PBKDF2)

When a pre-shared KeyStore is not applicable, data can be encrypted directly using a passphrase:

#### Encrypt with password:
```bash
java SymmetricCryptoApp encrypt \
  -p "MySecretPassphrase#2026" \
  -t "Confidential Financial Report Q3"
```

#### Decrypt with password:
```bash
java SymmetricCryptoApp decrypt \
  -p "MySecretPassphrase#2026" \
  -t "<paste-base64-string-here>"
```

---

### 5. Context-Bound Encryption with Additional Authenticated Data (AAD)

Bind encrypted data to an application context (e.g., user ID or database primary key):

#### Encrypt with AAD:
```bash
java SymmetricCryptoApp encrypt \
  -p "MasterPassphrase!2026" \
  -t "Credit Card 4111-2222-3333-4444" \
  --aad "user_id=10492;table=users;col=cc_token"
```

#### Decrypt with matching AAD (succeeds):
```bash
java SymmetricCryptoApp decrypt \
  -p "MasterPassphrase!2026" \
  -t "<ciphertext>" \
  --aad "user_id=10492;table=users;col=cc_token"
```

#### Decrypt with mismatched AAD (fails authentication):
```bash
java SymmetricCryptoApp decrypt \
  -p "MasterPassphrase!2026" \
  -t "<ciphertext>" \
  --aad "user_id=99999;table=users;col=cc_token"
```

---

### 6. File and Stream / Pipe Operations

#### Encrypt a file to disk:
```bash
echo "Highly confidential source code" > sensitive.txt

java SymmetricCryptoApp encrypt \
  -p "VaultPassword123" \
  -i sensitive.txt \
  -o sensitive.enc
```

#### Decrypt an encrypted file:
```bash
java SymmetricCryptoApp decrypt \
  -p "VaultPassword123" \
  -i sensitive.enc \
  -o restored.txt

diff sensitive.txt restored.txt # Identical
```

#### Unix Pipe / Streaming:
```bash
echo "Streaming data through pipes" | \
  java SymmetricCryptoApp encrypt -p "PipeSecret" | \
  java SymmetricCryptoApp decrypt -p "PipeSecret"
```

---

## Programmatic API Usage (Embedding in Java Projects)

The application is structured modularly so classes can be directly imported or reused in Java services:

```java
import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

// 1. Initialize KeyStore and Load / Generate Key
Path keystorePath = Paths.get("data/keys/app_keystore.p12");
char[] keystorePassword = "KeystorePassword123!".toCharArray();
char[] keyPassword = "KeyEntryPassword456!".toCharArray();
String keyAlias = "user-pii-key";

// Create or load key
SecretKey key = SymmetricCryptoApp.KeyStoreManager.loadKey(
        keystorePath, keystorePassword, keyAlias, keyPassword);

// 2. Encrypt Application Data
SymmetricCryptoApp.SymmetricEncryptionService crypto = 
        new SymmetricCryptoApp.SymmetricEncryptionService();

String sensitiveData = "Patient Blood Test: Result Negative";
byte[] aadContext = "patient-id:PT-9042".getBytes(StandardCharsets.UTF_8);

// Encrypt to Base64 container
String ciphertext = crypto.encryptString(sensitiveData, key, aadContext);
System.out.println("Stored Ciphertext: " + ciphertext);

// 3. Decrypt Back to Original Data
String decryptedPlaintext = crypto.decryptString(ciphertext, key, aadContext);
System.out.println("Recovered Plaintext: " + decryptedPlaintext);

// 4. Clean Memory
SymmetricCryptoApp.wipe(keystorePassword);
SymmetricCryptoApp.wipe(keyPassword);
```

---

## Summary of Security Best Practices

1. **Never use AES in ECB mode**: ECB does not use an IV and encrypts identical plaintext blocks to identical ciphertext blocks, leaking structural patterns.
2. **Always use Authenticated Encryption (AEAD)**: GCM protects confidentiality and verifies integrity in a single pass.
3. **Never reuse an IV with the same key in GCM mode**: A fresh 12-byte random IV must be generated for every encryption operation.
4. **Never hardcode keys or store them in plaintext files**: Store keys in a password-protected PKCS#12 keystore or a Hardware Security Module (HSM) / Cloud Key Management Service (KMS).
5. **Enforce restrictive OS permissions**: Protect keystore files with owner-only access (`chmod 0600`).
6. **Wipe sensitive data from memory**: Passwords and raw key bytes should be zeroed out when no longer needed to limit exposure in memory dumps.
7. **Use high iteration counts for KDFs**: When deriving keys from passwords, use PBKDF2 with at least 310,000 iterations and a cryptographically random salt.
