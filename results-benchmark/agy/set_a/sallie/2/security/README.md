# Secure PII Encryption and Decryption with AES-256-GCM

This project provides a robust, production-grade Java application that encrypts and decrypts Personally Identifiable Information (PII)—specifically individuals' names and email addresses—using the **Advanced Encryption Standard (AES)** in **Galois/Counter Mode (GCM)**.

In accordance with strict security standards, **no cryptographic keys are hardcoded or embedded in the source code**. Keys are managed through external configuration (environment variables, key files, or command-line parameters) or dynamically generated at runtime.

---

## Table of Contents

1. [What is PII and Why Encrypt It?](#what-is-pii-and-why-encrypt-it)
2. [Why Hardcoding Cryptographic Keys is Dangerous](#why-hardcoding-cryptographic-keys-is-dangerous)
3. [Cryptographic Architecture](#cryptographic-architecture)
   - [AES-256 Symmetric Cipher](#aes-256-symmetric-cipher)
   - [Galois/Counter Mode (GCM) and AEAD](#galoiscounter-mode-gcm-and-aead)
   - [Initialization Vector (IV / Nonce)](#initialization-vector-iv--nonce)
   - [Combined Payload Structure](#combined-payload-structure)
4. [External Key Management Architecture](#external-key-management-architecture)
   - [Supported Key Sources](#supported-key-sources)
   - [Dynamic Key Generation (Fallback)](#dynamic-key-generation-fallback)
5. [File Structure](#file-structure)
6. [Prerequisites](#prerequisites)
7. [How to Compile and Run](#how-to-compile-and-run)
   - [1. Compile the Code](#1-compile-the-code)
   - [2. Run with Command-Line Arguments](#2-run-with-command-line-arguments)
   - [3. Run Using an Environment Variable](#3-run-using-an-environment-variable)
   - [4. Run Using an External Key File](#4-run-using-an-external-key-file)
   - [5. Run Interactively](#5-run-interactively)
   - [6. Run Non-Interactively via Piped Input](#6-run-non-interactively-via-piped-input)
8. [Sample Program Output](#sample-program-output)
9. [Tamper Detection Demonstration](#tamper-detection-demonstration)
10. [Production Security Recommendations](#production-security-recommendations)

---

## What is PII and Why Encrypt It?

**Personally Identifiable Information (PII)** is any data that can be used to identify, contact, or locate a specific individual. Common examples include full names, email addresses, phone numbers, government ID numbers, and home addresses.

### Why PII Must Be Encrypted:
- **Regulatory Compliance**: Global data privacy regulations such as the General Data Protection Regulation (**GDPR**), California Consumer Privacy Act (**CCPA**), and Health Insurance Portability and Accountability Act (**HIPAA**) mandate data protection at rest and in transit.
- **Data Breach Defense**: If an attacker breaches a database, storage volume, or backup archive, encrypted PII remains mathematically undecipherable without the cryptographic key.
- **Data Integrity & Trust**: Authenticated encryption ensures sensitive personal data cannot be silently modified or corrupted in transit or storage.

---

## Why Hardcoding Cryptographic Keys is Dangerous

Hardcoding secrets in source code is classified as **CWE-798: Use of Hard-coded Credentials** and is one of the most critical vulnerabilities in software engineering:
1. **Source Code Exposure**: Source code is stored in version control systems (e.g., Git), replicated across developer workstations, and published in build artifacts. Anyone with repository access can extract hardcoded keys.
2. **Key Rotation Impossibility**: Rotating a compromised key requires rewriting code, rebuilding artifacts, and redeploying the entire software package.
3. **Environment Collisions**: Different environments (development, staging, production) inadvertently share the same cryptographic keys, compromising production secrets.

### How This Program Solves It
In this program, **zero cryptographic keys are embedded in the source code**. The application dynamically retrieves the key from:
- Environment variables (`PII_ENCRYPTION_KEY` or `AES_SECRET_KEY`)
- External key files (`--key-file <path>` or `PII_KEY_FILE`)
- Command-line arguments (`--key <base64>`)
- Runtime CSPRNG generation if no external key is configured, displaying instructions for persisting the key.

---

## Cryptographic Architecture

### AES-256 Symmetric Cipher
- **AES (Advanced Encryption Standard)** is the international standard established by NIST (FIPS 197).
- A **256-bit key length** offers $2^{256}$ possible combinations, rendering brute-force attacks impossible with current and anticipated future computing power.

### Galois/Counter Mode (GCM) and AEAD
This application uses `AES/GCM/NoPadding`. GCM is an **Authenticated Encryption with Associated Data (AEAD)** mode:
1. **Confidentiality**: Plaintext is encrypted using counter mode, converting the block cipher into a stream cipher.
2. **Authenticity & Integrity**: An integrated 128-bit authentication tag is calculated over the ciphertext and IV using GHASH arithmetic in a Galois field.
3. **Tamper Evident**: If even a single bit in the ciphertext is altered, the authentication tag verification fails immediately (`AEADBadTagException`), preventing tampered data from being processed.
4. **Padding Oracle Immunity**: Because GCM operates in counter mode, no PKCS padding is required, eliminating padding oracle vulnerabilities (such as POODLE or Lucky Thirteen).

### Initialization Vector (IV / Nonce)
- The Initialization Vector (IV) ensures that encrypting identical data multiple times produces completely different ciphertexts.
- In compliance with **NIST SP 800-38D**, each encryption operation generates a **12-byte (96-bit)** unique IV using Java's cryptographically secure pseudo-random number generator (`java.security.SecureRandom`).
- **Never Reuse IVs**: A fresh random IV is generated for every single encryption call.

### Combined Payload Structure
Decryption requires both the ciphertext and the IV used during encryption. To make the payload self-contained and portable, the application packages them into a binary format:

```
+------------------------------------+-------------------------------------------------------+
|   Initialization Vector (IV)       |        Ciphertext + GCM Authentication Tag            |
|       (12 bytes / 96 bits)         |             (N bytes plaintext + 16 bytes tag)        |
+------------------------------------+-------------------------------------------------------+
```

The combined payload is then encoded into standard **Base64**, making it safe for transport in JSON APIs, relational databases, environment files, or text logs.

---

## External Key Management Architecture

### Supported Key Sources
The program checks for the AES-256 key in the following order of precedence:

| Priority | Source | Description | Example |
| :--- | :--- | :--- | :--- |
| 1 | CLI Argument `--key` / `-k` | Base64-encoded 256-bit AES key | `java PIIEncryption --key "<base64>" "Alice" "alice@example.org"` |
| 2 | CLI Argument `--key-file` / `-kf` | Path to file containing Base64 key | `java PIIEncryption --key-file /path/to/key.txt "Alice" "alice@example.org"` |
| 3 | Environment Variable `PII_ENCRYPTION_KEY` | Primary environment variable | `export PII_ENCRYPTION_KEY="<base64>"` |
| 4 | Environment Variable `AES_SECRET_KEY` | Secondary standard environment variable | `export AES_SECRET_KEY="<base64>"` |
| 5 | Environment Variable `PII_KEY_FILE` | Path to external key file | `export PII_KEY_FILE="/secrets/pii.key"` |
| 6 | System Property `pii.encryption.key` | Java `-D` property | `java -Dpii.encryption.key="<base64>" PIIEncryption ...` |
| 7 | System Property `pii.key.file` | Java `-D` file property | `java -Dpii.key.file="/path/key" PIIEncryption ...` |
| 8 | Dynamic Generation | Secure runtime generation if none set | Generates a 256-bit key on the fly and outputs export command |

### Dynamic Key Generation (Fallback)
If no external key is provided, the application generates a cryptographically secure 256-bit AES key using `KeyGenerator` initialized with `SecureRandom`. It prints the generated key and displays the shell command needed to save and reuse it for future operations.

---

## File Structure

```
.
├── PIIEncryption.java    # Complete Java source code (encryption, decryption, external key management)
├── PIIEncryption.class   # Compiled Java bytecode
├── README.md             # Comprehensive technical documentation in plain English
└── README                # Plain English documentation mirror
```

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 8, 11, 17, 21, or higher.
- **Dependencies**: None. Uses solely standard Java Cryptography Architecture (`javax.crypto.*`, `java.security.*`).

Check your Java installation:
```bash
javac -version
java -version
```

---

## How to Compile and Run

### 1. Compile the Code

Compile the Java source file using the standard Java compiler:
```bash
javac PIIEncryption.java
```

### 2. Run with Command-Line Arguments

Provide the person's name and email directly as positional arguments:
```bash
java PIIEncryption "Alice Smith" "alice.smith@example.org"
```

You can also use named flags:
```bash
java PIIEncryption --name "Alice Smith" --email "alice.smith@example.org"
```

### 3. Run Using an Environment Variable

Provide a 256-bit AES key via the `PII_ENCRYPTION_KEY` environment variable:
```bash
# Generate or supply a 32-byte (256-bit) Base64 string
export PII_ENCRYPTION_KEY="RIO+6P218oPtpfInP2ejwwMXxYEI4BzBoFkEVht3bJ4="

# Execute the application
java PIIEncryption "Alice Smith" "alice.smith@example.org"
```

### 4. Run Using an External Key File

Store your secret key in an external file with restricted file permissions:
```bash
# Create key file with restricted permissions (read/write only for owner)
echo "RIO+6P218oPtpfInP2ejwwMXxYEI4BzBoFkEVht3bJ4=" > /path/to/secret.key
chmod 600 /path/to/secret.key

# Run the program referencing the key file
java PIIEncryption --key-file /path/to/secret.key "Alice Smith" "alice.smith@example.org"
```

### 5. Run Interactively

If no arguments are provided, the program prompts interactively for input:
```bash
java PIIEncryption
```

Example prompt:
```text
Please enter the Personally Identifiable Information (PII):
  -> Enter Person's Full Name: Jane Doe
  -> Enter Email Address: jane.doe@example.com
```

### 6. Run Non-Interactively via Piped Input

Feed input directly using shell pipes or redirects:
```bash
printf "Robert Johnson\nrobert.johnson@example.com\n" | java PIIEncryption
```

---

## Sample Program Output

Below is an authentic run execution demonstrating key resolution, encryption, decryption, integrity validation, and tamper resistance:

```text
==================================================================
     PII Encryption & Decryption System (AES-256-GCM AEAD)        
==================================================================

------------------------------------------------------------------
1. CRYPTOGRAPHIC KEY MANAGEMENT (NO HARDCODED KEYS)
------------------------------------------------------------------
  Key Source         : Environment Variable (PII_ENCRYPTION_KEY)
  Algorithm          : AES
  Key Length         : 256 bits (AES-256)
  Active Secret Key  : RIO+6P218oPtpfInP2ejwwMXxYEI4BzBoFkEVht3bJ4=

[INFO] Input received from command-line arguments.

------------------------------------------------------------------
2. ORIGINAL PII INPUT
------------------------------------------------------------------
  Full Name     : Alice Smith
  Email Address : alice.smith@example.org

------------------------------------------------------------------
3. ENCRYPTION PROCESS (AES/GCM/NoPadding)
------------------------------------------------------------------
  Cipher Mode   : GCM (Galois/Counter Mode with AEAD)
  IV Length     : 12 bytes (96 bits, unique per encryption)
  Tag Length    : 128 bits (16 bytes integrity tag)

  Encrypted Name (Base64 [12-byte IV || Ciphertext + Tag]):
    x+t2YfT0c6W5J6rhjzIl9xL/fN037RINVj2lOBtG3/c+MHbqtt9a

  Encrypted Email (Base64 [12-byte IV || Ciphertext + Tag]):
    kEGZmDjuLtmZn5p2Qj51cVwDRjvZ5xkEbtfF0TrrjL+LTXnOe/K4BowmvmA=

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
  Simulating unauthorized modification of encrypted payload...
  [SECURITY CONFIRMED] AEADBadTagException successfully triggered!
  The GCM authentication tag detected tampering and rejected the ciphertext.
  Details: Tag mismatch!

==================================================================
      PII Encryption and Decryption Completed Successfully!       
==================================================================
```

---

## Tamper Detection Demonstration

Traditional cipher modes like CBC or CTR only guarantee confidentiality—they do **not** protect against tampering. In CBC mode, an adversary who modifies bits in the ciphertext may corrupt plaintext without the application knowing, potentially causing application-level exploits.

In contrast, **AES-GCM includes an authentication tag** calculated using Galois field multiplication. 

In Step 6 of the program execution:
1. The program intentionally flips a single bit in the Base64 ciphertext payload.
2. It attempts to decrypt the altered payload.
3. The underlying cryptographic provider detects that the calculated authentication tag does not match the tag included in the payload.
4. Java immediately aborts decryption and throws `javax.crypto.AEADBadTagException`.
5. No corrupted data is ever released to the application.

---

## Production Security Recommendations

For deploying PII encryption in production environments:

1. **Hardware Security Modules (HSM) & Cloud KMS**:
   Use managed key management services such as AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault to store master keys. Never store raw secret keys in code repositories.

2. **Envelope Encryption**:
   Generate unique Data Encryption Keys (DEKs) per user or record, and encrypt DEKs under a Key Encryption Key (KEK) managed in KMS.

3. **Key Rotation**:
   Establish automatic key rotation policies (e.g., annual rotation) to limit the amount of data protected under a single key.

4. **Zeroize Sensitive Memory**:
   In Java, Strings are immutable and remain in memory until garbage collected. For ultra-high security requirements, store plaintext in `char[]` or `byte[]` arrays and explicitly overwrite them (`Arrays.fill(bytes, (byte) 0)`) immediately after encryption/decryption.

5. **Strict Access Controls**:
   Limit access to decryption keys using the principle of least privilege, and maintain detailed audit logs of all decryption operations.
