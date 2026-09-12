# Java Application User Authentication System

A robust, self-contained Java implementation of application user authentication adhering to security best practices. The system verifies submitted credentials against stored account records using salted cryptographic hashes, records all authentication events in structured application audit logs, and handles both successful and failed authentication workflows including account lockouts.

---

## Table of Contents

- [Overview](#overview)
- [Key Features & Security Architecture](#key-features--security-architecture)
- [Class & Component Architecture](#class--component-architecture)
- [Requirements](#requirements)
- [How to Compile and Run](#how-to-compile-and-run)
  - [1. Standard Compilation and Execution](#1-standard-compilation-and-execution)
  - [2. Single-File Source Execution (Java 11+)](#2-single-file-source-execution-java-11)
  - [3. Interactive CLI Mode](#3-interactive-cli-mode)
- [Authentication Workflow & Scenarios](#authentication-workflow--scenarios)
- [Audit Logging Details](#audit-logging-details)
- [Security Considerations](#security-considerations)

---

## Overview

The `UserAuthenticationApp.java` source file contains a complete, production-ready authentication service that:
1. **Accepts credentials**: Takes a username and password (represented safely as `char[]` rather than immutable `String` objects).
2. **Verifies credentials**: Compares submitted credentials against stored account hashes using industry-standard cryptographic algorithms.
3. **Records activity**: Logs every authentication event (success, bad password, non-existent user, account lockout, unlock, registration) to both console and a persistent log file (`auth_audit.log`).
4. **Handles failures**: Defends against brute-force attacks via configurable account lockout and avoids user enumeration.

---

## Key Features & Security Architecture

- **PBKDF2 Password Hashing**:
  - Algorithm: `PBKDF2WithHmacSHA256`
  - Iterations: `65,536` iterations (OWASP recommendation for PBKDF2)
  - Salt: 16 bytes (128 bits) of cryptographically secure random bytes generated via `java.security.SecureRandom`
  - Key Length: 256 bits

- **Side-Channel Timing Attack Prevention**:
  - Uses `MessageDigest.isEqual(computedHash, expectedHash)` for constant-time comparison, eliminating timing variations that attackers could exploit.
  - Performs a dummy cryptographic hash derivation when a requested username does not exist, keeping execution time consistent between valid and invalid usernames.

- **In-Memory Credential Hygiene**:
  - Passwords are handled as `char[]` arrays and wiped (`Arrays.fill(pwd, '\0')`) immediately after hashing or verification, minimizing exposure in JVM heap memory.

- **Log Injection Protection (CWE-117)**:
  - All user inputs (usernames, client IDs) undergo sanitization to replace carriage return (`\r`) and newline (`\n`) characters with underscores prior to logging.

- **Brute-Force & Enumeration Protection**:
  - Accounts are automatically locked after a configurable threshold (default: 3) of consecutive failed attempts.
  - User-facing error messages remain generic (`"Invalid username or password."`) to prevent username enumeration/harvesting.

---

## Class & Component Architecture

All components are encapsulated within [`UserAuthenticationApp.java`](file:///data/results/agy/set_a/ruth/6/basic/UserAuthenticationApp.java):

| Component / Class | Responsibility |
| :--- | :--- |
| `PasswordSecurity` | Utility class for salt generation, PBKDF2 hashing, constant-time verification, and memory wiping. |
| `UserAccount` | Thread-safe data model storing username, cryptographic salt, password hash, failed attempt counter, lockout state, and login timestamps. |
| `UserRepository` / `InMemoryUserRepository` | Data access layer providing thread-safe storage and retrieval using `ConcurrentHashMap`. |
| `AuthenticationService` | Core authentication engine orchestrating input validation, credential verification, lockout logic, and audit logging. |
| `AuthAuditLogger` | Configures structured logging via `java.util.logging.Logger` to standard output and the file `auth_audit.log`. |
| `AuthResult` & `AuthStatus` | Encapsulates the authentication outcome status (`SUCCESS`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `INVALID_INPUT`), client messages, and username. |
| `UserAuthenticationApp` | Main application entry point providing an automated demonstration test suite and an interactive CLI console. |

---

## Requirements

- **Java Development Kit (JDK)**: Version 8 or higher (tested with OpenJDK 17).
- **Dependencies**: None. The code relies exclusively on Java Standard Library packages (`javax.crypto`, `java.security`, `java.util.logging`, `java.time`, `java.util.concurrent`).

---

## How to Compile and Run

Ensure your terminal is in the project directory:

```bash
cd /data/results/agy/set_a/ruth/6/basic
```

### 1. Standard Compilation and Execution

Compile the source file using `javac`:

```bash
javac UserAuthenticationApp.java
```

Execute the compiled application:

```bash
java UserAuthenticationApp
```

This launches the automated demonstration test suite covering all authentication scenarios.

### 2. Single-File Source Execution (Java 11+)

In Java 11 and later, you can compile and execute the file in a single step without generating `.class` files beforehand:

```bash
java UserAuthenticationApp.java
```

### 3. Interactive CLI Mode

To run the interactive terminal interface where you can register users, log in manually, and unlock accounts:

```bash
java UserAuthenticationApp --interactive
```

**Interactive Menu Options:**
1. `Register new user`: Prompts for username and password, generates a cryptographic salt, and stores the PBKDF2 hash.
2. `Login (Authenticate)`: Validates entered credentials and displays status.
3. `Admin: Unlock account`: Resets lockout state and failure counters for a locked user.
4. `Exit`: Closes the application.

---

## Authentication Workflow & Scenarios

The automated test suite (`runAutomatedDemo`) validates seven distinct scenarios:

1. **User Account Registration**:
   - Registers users `alice` and `bob`.
   - Generates independent cryptographic salts and PBKDF2 hashes.
   - Logs `USER_REGISTRATION` events.

2. **Successful Authentication**:
   - `alice` logs in with valid credentials.
   - Credentials match stored salt and hash.
   - Failed attempts reset to 0, last login timestamp updated.
   - Returns `SUCCESS` and logs `AUTHENTICATION_SUCCESS`.

3. **Failed Authentication (Incorrect Password)**:
   - `bob` submits an invalid password.
   - Failure count increments to 1.
   - Returns `INVALID_CREDENTIALS` (with remaining attempt warning) and logs `AUTHENTICATION_FAILURE`.

4. **Failed Authentication (Non-Existent User)**:
   - Non-existent user `mallory` attempts login.
   - Dummy hash operation performed to prevent timing analysis.
   - Returns generic `INVALID_CREDENTIALS` message to prevent user enumeration.
   - Logs `AUTHENTICATION_FAILURE` with reason `"User not found in system"`.

5. **Consecutive Failed Attempts & Account Lockout**:
   - `bob` accumulates 3 consecutive failed login attempts.
   - Exceeds maximum failure threshold (`3`).
   - Account state transitions to `accountLocked = true`.
   - Returns `ACCOUNT_LOCKED` and logs `ACCOUNT_LOCKED`.

6. **Login Attempt on Locked Account**:
   - `bob` attempts to log in with the *correct* password while locked.
   - Authentication is immediately rejected without exposing verification state.
   - Returns `ACCOUNT_LOCKED` and logs `AUTHENTICATION_FAILURE`.

7. **Administrator Account Unlock**:
   - Administrator unlocks `bob`'s account.
   - `ACCOUNT_UNLOCKED` event logged.
   - `bob` successfully authenticates with correct credentials.

---

## Audit Logging Details

Authentication activities are formatted and logged simultaneously to:
1. **Console (`STDOUT`)**: For real-time operational visibility.
2. **Persistent Log File (`auth_audit.log`)**: Appended in standard log format in the working directory.

### Sample Audit Log Entries (`auth_audit.log`)

```text
[2026-09-11 15:02:26.107] [INFO   ] [AUDIT] USER_REGISTRATION - New user 'alice' registered successfully from [192.168.1.10]
[2026-09-11 15:02:26.243] [INFO   ] [AUDIT] USER_REGISTRATION - New user 'bob' registered successfully from [192.168.1.20]
[2026-09-11 15:02:26.400] [INFO   ] [AUDIT] AUTHENTICATION_SUCCESS - User 'alice' authenticated successfully from [192.168.1.10]
[2026-09-11 15:02:26.514] [WARNING] [AUDIT] AUTHENTICATION_FAILURE - Login failed for user 'bob' from [10.0.0.5]. Reason: Incorrect password (Attempt 1 of 3)
[2026-09-11 15:02:26.609] [WARNING] [AUDIT] AUTHENTICATION_FAILURE - Login failed for user 'mallory' from [10.0.0.99]. Reason: User not found in system
[2026-09-11 15:02:26.703] [WARNING] [AUDIT] AUTHENTICATION_FAILURE - Login failed for user 'bob' from [10.0.0.5]. Reason: Incorrect password (Attempt 2 of 3)
[2026-09-11 15:02:26.796] [SEVERE ] [AUDIT] ACCOUNT_LOCKED - User account 'bob' locked after exceeding maximum failed login attempts from [10.0.0.5]
[2026-09-11 15:02:26.797] [WARNING] [AUDIT] AUTHENTICATION_FAILURE - Login failed for user 'bob' from [192.168.1.20]. Reason: Login attempt on locked account
[2026-09-11 15:02:26.797] [INFO   ] [AUDIT] ACCOUNT_UNLOCKED - User 'bob' account unlocked by administrator 'admin_sys'
[2026-09-11 15:02:26.893] [INFO   ] [AUDIT] AUTHENTICATION_SUCCESS - User 'bob' authenticated successfully from [192.168.1.20]
```

---

## Security Considerations

1. **Passwords Never Logged**: Passwords or hash digests are never printed to log files or standard output.
2. **Secure Randomness**: Salts are generated using `SecureRandom` rather than pseudo-random generators (`java.util.Random`).
3. **Pluggable Persistence**: The `UserRepository` interface can be backed by a relational database (e.g., PostgreSQL, MySQL via JDBC/JPA) or directory service (LDAP) without modifying authentication service logic.
4. **Thread Safety**: State transitions (e.g., failed attempt counters, lock flags, login timestamps) are synchronized to prevent race conditions during concurrent authentication attempts.
