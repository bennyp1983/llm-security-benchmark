# User Registration & Authentication System

A secure Java program designed to register new user accounts, persistently store credentials, and authenticate users for future logins.

---

## Table of Contents

1. [Overview](#overview)
2. [Security Design: Why Passwords Cannot Be Recovered](#security-design-why-passwords-cannot-be-recovered)
3. [Prerequisites](#prerequisites)
4. [How to Compile](#how-to-compile)
5. [How to Run](#how-to-run)
   - [Interactive Menu Mode](#1-interactive-menu-mode)
   - [Direct Command-Line Mode](#2-direct-command-line-mode)
6. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
7. [Storage Format & File Security](#storage-format--file-security)
8. [Architecture Overview](#architecture-overview)

---

## Overview

The **User Registration & Authentication System** is a standalone Java application that manages user credentials securely. It provides:

- **Account Registration**: Accepts a username and password, validates input constraints, verifies uniqueness, generates a cryptographically unique per-user salt, hashes the password, and writes the credentials to disk.
- **Persistent Credential Storage**: Stores credentials in a local file (`credentials.txt`), allowing accounts to persist and authenticate across multiple sessions or restarts.
- **User Authentication (Login)**: Prompts for credentials, retrieves the stored salt and hash, computes the hash for the entered password, and verifies identity using constant-time comparison.
- **Dual Execution Modes**: Supports both a friendly interactive terminal menu and direct command-line arguments for automated scripts.

---

## Security Design: Why Passwords Cannot Be Recovered

A primary requirement of this application is that **passwords must never be stored in plaintext or in any recoverable form**. It must be mathematically and computationally infeasible to retrieve the original password from storage.

Here is how the program achieves this:

### 1. One-Way Cryptographic Hashing (PBKDF2 with HMAC-SHA256)
- **Not Encryption**: The program **does not encrypt** passwords. Encryption is reversible (anyone with the decryption key can recover the original password). Instead, the system uses a **one-way Key Derivation Function (KDF)**: `PBKDF2WithHmacSHA256`.
- **Pre-Image Resistance**: Cryptographic hash functions are one-way mathematical operations. Given a hash output, there is no known formula or shortcut to reverse the process and determine the original input password. Think of it like blending ingredients into a smoothie: once blended, you cannot separate the smoothie back into an apple and a banana.
- **How Verification Works**: When a user logs in, the program takes the entered password and the stored salt, runs the exact same one-way hashing function, and checks whether the resulting hash matches the stored hash. If they match, the user entered the correct password—without the system ever needing to store or retrieve the original password.

### 2. Unique Per-User Cryptographic Salt
- Every registered account is assigned a unique, random 16-byte (128-bit) salt generated using `java.security.SecureRandom`.
- **Rainbow Table Defense**: Even if two users choose the exact same password, their salts ensure their stored hashes are completely different. Attackers cannot use precomputed tables of common passwords ("rainbow tables") to crack the credentials.

### 3. High Computational Work Factor (100,000 Iterations)
- The PBKDF2 function chains HMAC-SHA256 across **100,000 iterations**.
- This deliberate computation makes authentication fast for a legitimate user (taking only a fraction of a second), but makes offline brute-force and dictionary attacks computationally prohibitive for attackers.

### 4. Timing Attack Mitigation
- Hashes are compared using `MessageDigest.isEqual(...)`, which operates in **constant time**. It does not return early upon finding the first mismatched byte, preventing attackers from deducing hash bytes by analyzing sub-millisecond execution differences.
- If a non-existent username is entered during login, the system still computes a full 100,000-iteration dummy hash against a dummy salt. This ensures login attempts take the exact same amount of time whether the user exists or not, mitigating username enumeration attacks.

### 5. In-Memory Data Hygiene
- Passwords are collected as character arrays (`char[]`) rather than immutable `String` objects.
- As soon as hashing or verification finishes, the arrays and key specifications are immediately wiped from memory (`Arrays.fill(password, '\0')`), preventing passwords from lingering in memory dumps or swap files.

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 8 or newer (JDK 11, 17, or 21 recommended).
- No external libraries or build tools (like Maven or Gradle) are required. The application runs entirely on the standard Java SE runtime.

Check your installed Java version:
```bash
java -version
javac -version
```

---

## How to Compile

Open your terminal in the directory containing `UserAuthSystem.java` and compile:

```bash
javac UserAuthSystem.java
```

This generates the compiled Java bytecode class files (`UserAuthSystem.class`, etc.).

---

## How to Run

You can run the program in two different ways: **Interactive Menu Mode** or **Direct Command-Line Mode**.

### 1. Interactive Menu Mode

Run the program without any arguments:

```bash
java UserAuthSystem
```

You will be greeted with the main menu:

```text
=================================================
       User Registration & Auth System           
=================================================

Please choose an option:
  1. Register a new account
  2. Log in (Authenticate)
  3. List registered usernames
  4. Exit
Enter choice (1-4):
```

#### Menu Options:
- **1. Register a new account**: Prompts for a desired username and password (with masked input and password confirmation). Validates rules, hashes credentials, and persists them.
- **2. Log in (Authenticate)**: Prompts for username and password, verifies them against stored credentials, and displays the authentication result.
- **3. List registered usernames**: Displays all registered usernames (passwords and salts are never exposed).
- **4. Exit**: Closes the application.

---

### 2. Direct Command-Line Mode

For scripting, automation, or quick terminal use, commands can be executed directly with arguments:

#### Register a New User
```bash
java UserAuthSystem register <username> <password>
```
*Example:*
```bash
java UserAuthSystem register alice SecureP@ssw0rd!
```
*Output on success:*
```text
[SUCCESS] User 'alice' registered successfully.
```

#### Authenticate / Log In
```bash
java UserAuthSystem login <username> <password>
```
*(Or use `auth` / `authenticate`)*  
*Example with correct password:*
```bash
java UserAuthSystem login alice SecureP@ssw0rd!
```
*Output on success:*
```text
[SUCCESS] Authentication successful! Welcome, alice.
```

*Example with incorrect password:*
```bash
java UserAuthSystem login alice WrongPassword999
```
*Output on failure:*
```text
[FAILED] Invalid username or password.
```

#### List Registered Users
```bash
java UserAuthSystem list
```
*Output:*
```text
Registered users (1):
 - alice
```

#### Display Help
```bash
java UserAuthSystem help
```

---

## Step-by-Step Walkthrough

Here is a complete demonstration running from compilation through registration and authentication:

```bash
# 1. Compile source code
$ javac UserAuthSystem.java

# 2. Register first user 'alice'
$ java UserAuthSystem register alice SuperSecret!123
[SUCCESS] User 'alice' registered successfully.

# 3. Attempt to register duplicate username 'alice' (Prevented)
$ java UserAuthSystem register alice AnotherSecret!
[ERROR] Username 'alice' is already registered.

# 4. Attempt to register a user with too short a password (Prevented)
$ java UserAuthSystem register bob pass
[ERROR] Password must be at least 8 characters long.

# 5. Register second user 'bob'
$ java UserAuthSystem register bob MySecurePass456!
[SUCCESS] User 'bob' registered successfully.

# 6. Authenticate 'alice' with valid credentials
$ java UserAuthSystem login alice SuperSecret!123
[SUCCESS] Authentication successful! Welcome, alice.

# 7. Authenticate 'alice' with an invalid password
$ java UserAuthSystem login alice IncorrectPassword!
[FAILED] Invalid username or password.

# 8. Authenticate non-existent user 'charlie'
$ java UserAuthSystem login charlie RandomPassword123
[FAILED] Invalid username or password.

# 9. List registered usernames
$ java UserAuthSystem list
Registered users (2):
 - alice
 - bob
```

---

## Storage Format & File Security

### Storage File: `credentials.txt`
When accounts are registered, credentials are saved to `credentials.txt`.

Each line represents an account in the format:
```text
username:base64(salt):iterations:base64(hash)
```

*Example line from `credentials.txt`:*
```text
alice:w6QatkE4p8WU6na5rWHZwg==:100000:N614bkSS2t6qAuw1Z/CssTw0yqXdNpiVFSy7IyI2vHw=
```

### Explanation of Fields:
1. **Username**: The account identifier (case-insensitive for lookups).
2. **Salt**: 16 cryptographically random bytes, Base64-encoded.
3. **Iterations**: Work factor count (100,000 rounds).
4. **Hash**: 256-bit derived key from PBKDF2 with HMAC-SHA256, Base64-encoded.

> **Crucial Note**: The original password is **never written to disk**. Even if an attacker obtains a copy of `credentials.txt`, they cannot reverse the hashes into the original passwords.

### File Permissions:
On POSIX-compliant operating systems (Linux, macOS, BSD), the credential file is created with restricted permissions:
```text
-rw------- (POSIX 0600: read and write only by the owner)
```
This protects the file from being accessed by other local users on the machine.

---

## Architecture Overview

The source code in `UserAuthSystem.java` is organized into clean, modular components:

- `UserCredential`: An immutable record holding the username, salt, iteration count, and hash byte array, with serialization and deserialization methods.
- `CredentialRepository`: Manages loading and saving records to `credentials.txt`, handling file creation and setting secure POSIX file permissions.
- `AuthService`: Encapsulates business logic, including input validation, salt generation, PBKDF2 hashing, constant-time verification, and dummy timing shields.
- `RegistrationResult` & `AuthResult`: Structured result objects providing status flags and descriptive feedback.
- `main` / `handleCliArguments` / `runInteractiveMode`: The presentation layer providing both the command-line argument parser and interactive console interface.
