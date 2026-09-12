# Personally Identifiable Information (PII) Encryption with AES-256-GCM

This project provides a complete, production-ready Java program that encrypts and decrypts Personally Identifiable Information (PII)—specifically names and email addresses—using the **Advanced Encryption Standard (AES)** in **Galois/Counter Mode (GCM)**.

---

## Table of Contents

1. [Overview](#overview)
2. [Why Encrypt PII?](#why-encrypt-pii)
3. [Cryptographic Architecture](#cryptographic-architecture)
   - [Why AES-256?](#why-aes-256)
   - [Why Galois/Counter Mode (GCM)?](#why-galoiscounter-mode-gcm)
   - [Initialization Vector (IV / Nonce)](#initialization-vector-iv--nonce)
   - [Combined Payload Format](#combined-payload-format)
4. [File Structure](#file-structure)
5. [Prerequisites](#prerequisites)
6. [How to Compile and Run](#how-to-compile-and-run)
   - [Option A: Interactive Input](#option-a-interactive-input)
   - [Option B: Command-Line Arguments](#option-b-command-line-arguments)
   - [Option C: Non-Interactive / Piped Input](#option-c-non-interactive--piped-input)
7. [Step-by-Step Program Walkthrough](#step-by-step-program-walkthrough)
8. [Security Demonstration: Tamper Detection](#security-demonstration-tamper-detection)
9. [Production Security Recommendations](#production-security-recommendations)

---

## Overview

Personally Identifiable Information (PII) is any data that can be used to distinguish or trace an individual's identity, such as a full name, home address, Social Security Number, or email address. When stored or processed, PII must be protected against unauthorized access, leaks, and data manipulation.

This application accepts a person's name and email address, generates a 256-bit AES secret key, encrypts both data points into secure Base64 strings, and subsequently decrypts them to verify that the original data is recovered without loss or corruption.

---

## Why Encrypt PII?

- **Privacy Compliance**: Laws and standards such as the EU General Data Protection Regulation (GDPR), California Consumer Privacy Act (CCPA), and Health Insurance Portability and Accountability Act (HIPAA) mandate rigorous safeguards for personal data.
- **Breach Mitigation**: Even if an unauthorized party gains access to a database or storage disk, strongly encrypted information remains completely unreadable and unusable without the secret decryption key.
- **Data Integrity**: Authenticated encryption ensures that any unauthorized modification of sensitive data in storage or transit is immediately detected and rejected.

---

## Cryptographic Architecture

Modern cryptography requires careful selection of algorithms, cipher modes, and key management practices.

### Why AES-256?
- **AES (Advanced Encryption Standard)** is the international standard adopted by the U.S. National Institute of Standards and Technology (NIST) and used worldwide.
- **256-bit Key Length**: A 256-bit key offers $2^{256}$ possible combinations, rendering brute-force attacks computationally infeasible even with modern supercomputers or quantum search algorithms.

### Why Galois/Counter Mode (GCM)?
Cryptographic modes determine how block ciphers process data longer than a single block (16 bytes for AES):
- **ECB (Electronic Codebook)**: **Insecure**. Encrypts identical plaintext blocks into identical ciphertext blocks, leaking structural patterns.
- **CBC (Cipher Block Chaining)**: Provides confidentiality but **no integrity verification**. CBC requires manual padding (vulnerable to padding oracle attacks such as POODLE) and must be combined with a separate MAC (e.g., HMAC-SHA256) using an "Encrypt-then-MAC" construction to prevent tampering.
- **GCM (Galois/Counter Mode)**: **The recommended modern standard**. GCM is an **AEAD (Authenticated Encryption with Associated Data)** mode. It provides both:
  1. **Confidentiality**: The plaintext is encrypted using counter mode.
  2. **Authenticity & Integrity**: An integrated 128-bit authentication tag (GHASH) is calculated. If even a single bit of the ciphertext or IV is altered, decryption fails immediately with an authentication tag error before any plaintext is released.
  3. **No Padding Required**: Operates as a stream cipher, avoiding all padding oracle vulnerabilities.

### Initialization Vector (IV / Nonce)
- An IV is a non-secret random value used to ensure that encrypting the same text multiple times produces completely different ciphertexts.
- In accordance with NIST SP 800-38D, a **12-byte (96-bit)** IV is generated for every encryption operation using `java.security.SecureRandom`.
- **Critical Rule**: An IV must never be repeated with the same key. Generating a fresh 12-byte random IV per operation prevents nonce reuse.

### Combined Payload Format
Because the decryption process requires the original IV to initialize the cipher, the program packages the output into a single, self-contained binary structure:

```
+--------------------------+-------------------------------------------------------+
|  IV (12 bytes / 96 bits) |  Ciphertext + GCM Authentication Tag (16 bytes / 128)  |
+--------------------------+-------------------------------------------------------+
```

This byte array is then encoded into a **Base64** string, making it easy to store in relational databases, JSON payloads, or log files safely.

---

## File Structure

```
.
├── PIIEncryption.java   # Main Java source code with encryption, decryption, and demo logic
├── README.md            # Comprehensive documentation in plain English
└── README               # Plain English documentation mirror
```

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 8, 11, 17, 21, or higher.
- **No external libraries or build tools required**: Uses only standard Java Cryptography Architecture (`javax.crypto.*`, `java.security.*`).

Verify your Java installation:
```bash
javac -version
java -version
```

---

## How to Compile and Run

### 1. Compile the Program
Compile the Java source file using `javac`:
```bash
javac PIIEncryption.java
```

### 2. Run the Program

#### Option A: Interactive Input
Run the program with no arguments. You will be prompted to type in the name and email address:
```bash
java PIIEncryption
```
Example terminal prompt:
```
Please enter the Personally Identifiable Information (PII):
  -> Enter Person's Full Name: Jane Doe
  -> Enter Email Address: jane.doe@example.com
```

#### Option B: Command-Line Arguments
Pass the full name and email address as two command-line arguments (use quotes if the name contains spaces):
```bash
java PIIEncryption "Alice Smith" "alice.smith@example.org"
```

#### Option C: Non-Interactive / Piped Input
Feed values directly through standard input:
```bash
printf "Bob Dylan\nbob@example.com\n" | java PIIEncryption
```
If standard input is empty, the application automatically uses sensible fallback values so automated pipelines run without interruption.

---

## Step-by-Step Program Walkthrough

When executed, the program performs the following steps in sequence:

1. **Captures Input**: Retrieves the person's name and email address.
2. **Generates Secret Key**: Creates a fresh 256-bit AES symmetric key using a cryptographically secure random number generator (`SecureRandom`).
3. **Encrypts Data**:
   - Generates a fresh 12-byte IV for the name.
   - Encrypts the name with `AES/GCM/NoPadding` and generates a 128-bit authentication tag.
   - Prepends the IV to the ciphertext and encodes the result in Base64.
   - Repeats the process independently for the email address with its own unique IV.
4. **Decrypts Data**:
   - Decodes each Base64 payload back into raw bytes.
   - Extracts the first 12 bytes as the IV.
   - Decrypts the remaining bytes and validates the GCM authentication tag.
5. **Verifies Integrity**:
   - Performs an exact string equality check comparing the decrypted text against the original input.
   - Reports verification status (`PASSED`).
6. **Demonstrates Tamper Detection**:
   - Flips a bit in the encrypted payload to simulate an attacker modifying the ciphertext.
   - Attempts decryption and catches `AEADBadTagException`, demonstrating the cipher's built-in defense against data tampering.

---

## Example Output

```text
==================================================================
         PII Encryption & Decryption System (AES-256-GCM)         
==================================================================
[INFO] Input received from command line arguments.

------------------------------------------------------------------
1. ORIGINAL PII INPUT
------------------------------------------------------------------
  Full Name     : Alice Smith
  Email Address : alice.smith@example.org

------------------------------------------------------------------
2. KEY GENERATION
------------------------------------------------------------------
  Algorithm     : AES
  Key Length    : 256 bits (AES-256)
  Generated Key : XTXCV2vlZnHEaXsYflaemPeWBVEhiFJZK/OYqDjT+xM=

------------------------------------------------------------------
3. ENCRYPTION PROCESS (AES/GCM/NoPadding)
------------------------------------------------------------------
  Mode          : GCM (Galois/Counter Mode with AEAD)
  IV Length     : 12 bytes (96 bits, unique per encryption)
  Tag Length    : 128 bits (16 bytes integrity tag)

  Encrypted Name (Base64 [IV + Ciphertext + Tag]):
    z6YCRp2Fq1zoNA7AKHNkO2IdsScxdSUCBHiLg6NjF3bYBxMp/Etf

  Encrypted Email (Base64 [IV + Ciphertext + Tag]):
    qj5j/ux2bPgOEVZDLf1C87CWvhxXpjDtuoJkXiCRgtNYOdrD/F1TIeqi2MIuLDitgOYA

------------------------------------------------------------------
4. DECRYPTION & INTEGRITY VERIFICATION
------------------------------------------------------------------
  Decrypted Name     : Alice Smith
  Decrypted Email    : alice.smith@example.org

------------------------------------------------------------------
5. INTEGRITY CHECK RESULTS
------------------------------------------------------------------
  Name Match Check   : PASSED (100% exact match)
  Email Match Check  : PASSED (100% exact match)

------------------------------------------------------------------
6. SECURITY DEMONSTRATION: TAMPER DETECTION
------------------------------------------------------------------
  Simulating unauthorized modification of the encrypted email payload...
  [SECURITY CONFIRMED] AEADBadTagException caught successfully!
  The GCM authentication tag detected tampering and rejected the ciphertext.
  Error details: Tag mismatch!

==================================================================
      PII Encryption and Decryption Completed Successfully!       
==================================================================
```

---

## Security Demonstration: Tamper Detection

In traditional cipher modes like CBC without HMAC, modifying ciphertext bytes often results in corrupted plaintext or padding errors, but might not prevent deliberate bit-flipping attacks.

In this program's step 6:
1. The program deliberately changes one bit of the encrypted email payload.
2. The decryption routine runs using the same key.
3. Java's AES-GCM engine computes the GHASH authentication tag and discovers that the calculated tag does not match the tag embedded in the payload.
4. Java immediately aborts decryption and throws an `AEADBadTagException`, preventing modified or forged data from ever being processed.

---

## Production Security Recommendations

When deploying AES encryption for PII in enterprise environments, observe the following best practices:

1. **Key Management Services (KMS)**:
   - Never hardcode cryptographic keys in source code or configuration files.
   - Use managed key services such as AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault.
   - Use **Envelope Encryption**: Data keys are generated per-record or per-customer, used to encrypt the PII, and then encrypted under a root Key Encryption Key (KEK) stored in a Hardware Security Module (HSM).

2. **Key Rotation**:
   - Establish a policy for scheduled key rotation (e.g., annually) to minimize exposure in the event of a compromised key.

3. **Memory Hygiene**:
   - Sensitive data should be cleared from memory as soon as it is no longer needed. Use mutable structures (`char[]` or `byte[]`) instead of immutable `String` objects where possible, and overwrite them with zeroes (`Arrays.fill(bytes, (byte) 0)`) when finished.

4. **Defense in Depth**:
   - Combine encryption at rest (AES-256-GCM) with encryption in transit (TLS 1.3).
   - Implement role-based access controls (RBAC) and comprehensive audit logging so only authorized personnel can trigger decryption operations.
