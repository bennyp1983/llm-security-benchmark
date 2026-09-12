# User Registration & Authentication System

A Java application that registers new user accounts, securely stores credentials, and authenticates users for future logins.

---

## Table of Contents

1. [Overview](#overview)
2. [Security Design](#security-design)
3. [Prerequisites](#prerequisites)
4. [How to Compile](#how-to-compile)
5. [How to Run](#how-to-run)
   - [Interactive Menu Mode](#1-interactive-menu-mode)
   - [Direct Command-Line Mode](#2-direct-command-line-mode)
6. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
7. [Storage Format](#storage-format)
8. [File Structure](#file-structure)

---

## Overview

This program provides a user authentication workflow:
- **Registration**: Allows a user to create an account by providing a username and a password. It verifies that the username is not already taken, enforces password rules, and creates a secure record.
- **Credential Storage**: Saves credentials into a local file (`credentials.txt`). Passwords are **never** stored in plain text; only cryptographically salted hashes are saved.
- **Authentication (Login)**: Allows a registered user to log in by verifying their entered password against the stored credentials.
- **Persistence**: Because credentials are saved to a file, accounts remain stored and can be authenticated across separate runs of the program.

---

## Security Design

The application follows industry security best practices:

- **PBKDF2 Password Hashing**: Passwords are protected using `PBKDF2WithHmacSHA256` with 65,536 iterations and a 256-bit derived key length (recommended by OWASP).
- **Per-User Cryptographic Salt**: A unique 16-byte random salt is generated for each account using `SecureRandom`. This prevents rainbow table attacks and ensures that identical passwords produce completely different stored hashes.
- **Timing Attack Mitigation**: Credential comparison uses `MessageDigest.isEqual`, which runs in constant time. A dummy hash computation is performed even if a username does not exist, preventing attackers from detecting valid usernames by measuring response times.
- **Memory Hygiene**: Password character arrays are wiped from memory immediately after use.
- **Restricted File Permissions**: On compatible operating systems (Linux/macOS), the credential file permissions are set to `rw-------` (read and write only by the file owner) to protect the file from other users on the system.

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 8 or newer (JDK 17 or higher recommended).
- Check your installed Java version:
  ```bash
  java -version
  javac -version
  ```

---

## How to Compile

In your terminal, navigate to the directory containing `UserAuthSystem.java` and run:

```bash
javac UserAuthSystem.java
```

This compiles the source code and produces the bytecode `.class` files.

---

## How to Run

You can run the program in two ways: **Interactive Menu Mode** or **Direct Command-Line Mode**.

### 1. Interactive Menu Mode

Run the program without any arguments:

```bash
java UserAuthSystem
```

You will see an interactive menu:

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

Type a number (1-4) and press **Enter** to select an action:
- **Option 1**: Prompts for a desired username and password (with confirmation), validates them, and registers the account.
- **Option 2**: Prompts for username and password, then checks if the credentials are valid.
- **Option 3**: Displays all registered usernames (without exposing salts or passwords).
- **Option 4**: Exits the program.

---

### 2. Direct Command-Line Mode

You can also run commands directly from the terminal without using the interactive menu:

#### Register a user:
```bash
java UserAuthSystem register <username> <password>
```
*Example:*
```bash
java UserAuthSystem register alice MySecretPass123!
```

#### Log in / Authenticate:
```bash
java UserAuthSystem login <username> <password>
```
*Example:*
```bash
java UserAuthSystem login alice MySecretPass123!
```

#### List registered users:
```bash
java UserAuthSystem list
```

#### View help instructions:
```bash
java UserAuthSystem help
```

---

## Step-by-Step Walkthrough

### Example 1: Registering a New User
```text
Enter choice (1-4): 1

--- New User Registration ---
Enter desired username (3-30 chars, letters/numbers/._-): alice
Enter password (min 8 chars): 
Confirm password: 
[Success] User 'alice' registered successfully.
```

### Example 2: Successful Login
```text
Enter choice (1-4): 2

--- User Login / Authentication ---
Enter username: alice
Enter password: 

>>> [LOGIN SUCCESSFUL] Authentication successful! Welcome, alice. <<<
```

### Example 3: Failed Login (Wrong Password or Unknown User)
```text
Enter choice (1-4): 2

--- User Login / Authentication ---
Enter username: alice
Enter password: 

>>> [LOGIN FAILED] Invalid username or password. <<<
```
*(Notice that the error message is identical whether the username does not exist or the password is incorrect, preventing username guessing.)*

---

## Storage Format

Credentials are saved in `credentials.txt` in the following colon-separated format:

```text
username:base64(salt):base64(hash)
```

Example file entry:
```text
alice:rQy/q+18pD3A6iF6XzM9eA==:dGVzdGhhc2h2YWx1ZXNhbXBsZWJhc2U2NA==
```

- `username`: The unique user identifier.
- `salt`: 16-byte random salt encoded in Base64.
- `hash`: 256-bit PBKDF2-HMAC-SHA256 hash encoded in Base64.

---

## File Structure

```text
.
├── README.md               # Plain English documentation and user guide
├── UserAuthSystem.java     # Complete Java source code
└── credentials.txt         # Secure credential storage (created on first registration)
```
