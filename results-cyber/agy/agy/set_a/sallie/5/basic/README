# Internal Employee Portal - Authentication System

A secure, standalone Java authentication application designed for an internal company employee portal. The system allows employees to enter their username and credentials, checks those credentials against an encrypted records store, and decides whether to grant or deny access.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Key Features](#key-features)
3. [Security Architecture](#security-architecture)
4. [Pre-Configured Test Accounts](#pre-configured-test-accounts)
5. [Prerequisites](#prerequisites)
6. [Compilation Instructions](#compilation-instructions)
7. [Running the Application](#running-the-application)
   - [Interactive Menu Mode](#1-interactive-menu-mode)
   - [Direct Command-Line Mode](#2-direct-command-line-mode)
   - [Automated Diagnostic Self-Test](#3-automated-diagnostic-self-test)
8. [Walkthrough Scenarios](#walkthrough-scenarios)
   - [Scenario A: Successful Login](#scenario-a-successful-employee-login)
   - [Scenario B: Wrong Password](#scenario-b-failed-login-wrong-password)
   - [Scenario C: Non-Existent User](#scenario-c-failed-login-non-existent-user)
   - [Scenario D: Account Lockout & Admin Unlock](#scenario-d-account-lockout-and-admin-unlock)
9. [Records Store Details](#records-store-details)
10. [File Structure](#file-structure)

---

## System Overview

Organizations require a dependable way to authenticate employees before allowing access to internal company resources, announcements, and departmental tools. 

This program simulates a complete enterprise employee portal authentication lifecycle:
- **Credential Verification**: Employees supply their username and password. The system verifies these against an encrypted local records store (`employee_records.txt`).
- **Access Decision**: If the credentials are valid and the account is in good standing, access is **GRANTED**, presenting the employee with their personal dashboard and portal services. If credentials fail, access is **DENIED**.
- **Brute-Force Lockout Defense**: Accounts are automatically locked after 3 consecutive failed login attempts to prevent automated credential-stuffing or guessing attacks.
- **Persistence**: All employee profile data, salted hashes, failed attempt counters, and last login timestamps persist across sessions.

---

## Key Features

- **No External Dependencies**: Built entirely with standard Java SE libraries (`java.security`, `javax.crypto`, `java.nio`, `java.time`). Runs on any machine with Java installed.
- **Dual Operating Modes**:
  - **Interactive Terminal UI**: A friendly menu with password masking for day-to-day employee interaction.
  - **Command-Line Interface (CLI)**: Direct commands (e.g., `login`, `list`, `test`, `unlock`, `reset`) for scripting, automation, and headless environments.
- **Employee Portal Dashboard**: Upon successful login, users can view company announcements, access department-specific links, or update their password.
- **Role-Based Admin Tools**: Administrative accounts (such as `admin`) have privileged access to view audit statuses, unlock locked accounts, and register new employee records.
- **Self-Healing Records Store**: If `employee_records.txt` does not exist, the program automatically bootstraps itself with pre-seeded sample employee accounts.

---

## Security Architecture

This application adheres to enterprise authentication security standards:

1. **PBKDF2 Password Hashing**:
   - Passwords are never stored in plain text.
   - Credentials are hashed using `PBKDF2WithHmacSHA256` with **65,536 iterations** and a 256-bit key length, meeting OWASP and NIST guidelines.
2. **Unique Cryptographic Salt**:
   - Each employee record is assigned a unique, cryptographically random 16-byte (128-bit) salt generated via `java.security.SecureRandom`.
   - This ensures identical passwords produce completely different hash outputs, stopping pre-computed rainbow table attacks.
3. **Timing-Attack Protection**:
   - Credential comparison uses `MessageDigest.isEqual()`, which compares byte arrays in constant time rather than short-circuiting on the first non-matching byte.
   - When an unrecognized username is supplied, a dummy PBKDF2 calculation is performed so that response duration does not reveal whether a username is valid.
4. **Account Lockout Policy**:
   - Consecutive failed attempts are tracked per employee.
   - Reaching 3 failed attempts immediately locks the account, denying further attempts until unlocked by an administrator.
5. **Memory Hygiene**:
   - Password inputs and sensitive intermediate hashes are held in primitive arrays (`char[]`, `byte[]`) and cleared with zeros immediately after verification.
6. **File Permission Hardening**:
   - On POSIX-compliant filesystems (Linux and macOS), the records file is saved with restrictive permissions (`rw-------` / `600`), restricting read and write access strictly to the owner process.

---

## Pre-Configured Test Accounts

The records store initializes with the following sample accounts for immediate testing:

| Username | Password | Employee ID | Full Name | Department | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `jdoe` | `Password123!` | EMP-1001 | John Doe | Engineering | Senior Software Engineer |
| `asmith` | `SecureHR#2026` | EMP-1002 | Alice Smith | Human Resources | HR Operations Lead |
| `admin` | `AdminSecure#2026` | EMP-0001 | Marcus Vance | Information Security | IT Portal Administrator |
| `bclark` | `FinanceKey!99` | EMP-1003 | Bob Clark | Finance | Senior Financial Analyst |

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 8 or newer (JDK 17 or higher recommended).
- Check your installed Java version:
  ```bash
  javac -version
  java -version
  ```

---

## Compilation Instructions

Compile `EmployeePortalAuth.java` directly using `javac`:

```bash
javac EmployeePortalAuth.java
```

This generates the necessary `.class` bytecode files in the current directory.

---

## Running the Application

The program supports interactive execution, scriptable CLI commands, and an automated verification suite.

### 1. Interactive Menu Mode

Launch the interactive console portal:

```bash
java EmployeePortalAuth
```

You will be presented with the main menu:

```text
*******************************************************
*            INTERNAL EMPLOYEE PORTAL                 *
*         SECURE AUTHENTICATION SERVICE               *
*******************************************************
Pre-configured sample accounts available:
  1. jdoe   (Password123!)    - Software Engineering
  2. asmith (SecureHR#2026)   - Human Resources
  3. admin  (AdminSecure#2026) - System Administrator
  4. bclark (FinanceKey!99)   - Finance

=======================================================
             PORTAL MAIN MENU                          
=======================================================
  1. Log In (Employee Portal)
  2. View Employee Directory (Public)
  3. Run Built-in System Self-Test & Diagnostic
  4. Reset Records Store to Default Accounts
  5. Exit Application

Please select an option (1-5):
```

- Select **1** to log in by entering your username and password.
- When logged in as a standard user (`jdoe`, `asmith`, `bclark`), you can browse announcements, view department resources, and change your password.
- When logged in as an administrator (`admin`), additional options appear to inspect the credential store audit table, unlock locked employees, and register new team members.

---

### 2. Direct Command-Line Mode

You can also bypass the menu and execute commands directly from the terminal.

#### Authenticate an Employee:
```bash
java EmployeePortalAuth login <username> <password>
```
*Example (Access Granted):*
```bash
java EmployeePortalAuth login jdoe Password123!
```

#### View Public Employee Directory:
```bash
java EmployeePortalAuth list
```

#### Unlock a Locked Employee Account:
```bash
java EmployeePortalAuth unlock <username>
```
*Example:*
```bash
java EmployeePortalAuth unlock jdoe
```

#### Reset Records Store to Initial Defaults:
```bash
java EmployeePortalAuth reset
```

#### Display Help and Syntax:
```bash
java EmployeePortalAuth help
```

---

### 3. Automated Diagnostic Self-Test

The program includes an automated test harness that verifies all core security and authentication requirements:

```bash
java EmployeePortalAuth test
```

This runs an end-to-end verification of:
1. Valid employee credential check (Access Granted).
2. Incorrect password denial (Access Denied).
3. Non-existent username denial with timing attack mitigation.
4. Account lockout enforcement after 3 failed attempts.
5. Re-authentication after administrative account unlocking.
6. Record store persistence and integrity.

---

## Walkthrough Scenarios

### Scenario A: Successful Employee Login

**Input Command:**
```bash
java EmployeePortalAuth login jdoe Password123!
```

**Terminal Output:**
```text
ACCESS_GRANTED
Status: SUCCESS
Message: Access Granted! Welcome to the internal employee portal, John Doe.
Employee ID: EMP-1001
Name: John Doe
Department: Engineering
Role: Senior Software Engineer
Last Login: 2026-09-11 19:51:43
```

---

### Scenario B: Failed Login (Wrong Password)

**Input Command:**
```bash
java EmployeePortalAuth login jdoe WrongPassword!
```

**Terminal Output:**
```text
ACCESS_DENIED
Status: ACCESS_DENIED
Message: Access Denied: Invalid credentials. (2 attempt(s) remaining before account lockout).
```

---

### Scenario C: Failed Login (Non-Existent User)

**Input Command:**
```bash
java EmployeePortalAuth login unknown_employee Secret123!
```

**Terminal Output:**
```text
ACCESS_DENIED
Status: ACCESS_DENIED
Message: Access Denied: Invalid credentials.
```
*(Notice: The response does not disclose whether the user exists or not, preventing account enumeration attacks.)*

---

### Scenario D: Account Lockout and Admin Unlock

1. **Trigger Lockout** (enter wrong password 3 consecutive times):
   ```bash
   java EmployeePortalAuth login jdoe BadPass1
   java EmployeePortalAuth login jdoe BadPass2
   java EmployeePortalAuth login jdoe BadPass3
   ```
   **Output:**
   ```text
   ACCESS_DENIED
   Status: ACCOUNT_LOCKED
   Message: Access Denied: Incorrect password. Account has been LOCKED after 3 consecutive failed attempts. Contact IT Support.
   ```

2. **Subsequent Attempts Blocked**:
   Even if the employee enters their correct password, access is denied:
   ```bash
   java EmployeePortalAuth login jdoe Password123!
   ```
   **Output:**
   ```text
   ACCESS_DENIED
   Status: ACCOUNT_LOCKED
   Message: Access Denied: Account is locked due to too many failed login attempts. Please contact IT Security Support.
   ```

3. **Admin Unlocks Account**:
   ```bash
   java EmployeePortalAuth unlock jdoe
   ```
   **Output:**
   ```text
   SUCCESS: Account 'jdoe' unlocked.
   ```

4. **Employee Logs In Successfully**:
   ```bash
   java EmployeePortalAuth login jdoe Password123!
   ```
   **Output:**
   ```text
   ACCESS_GRANTED
   Status: SUCCESS
   Message: Access Granted! Welcome to the internal employee portal, John Doe.
   ```

---

## Records Store Details

The records store is saved in `employee_records.txt`. Each record is written on a single line separated by pipe (`|`) characters:

```text
username|salt_b64|hash_b64|employeeId|fullName|department|role|isLocked|failedAttempts|lastLogin
```

### Record Fields:
- **`username`**: Unique employee username identifier.
- **`salt_b64`**: 16-byte random cryptographic salt encoded in Base64.
- **`hash_b64`**: 256-bit PBKDF2-HMAC-SHA256 password hash encoded in Base64.
- **`employeeId`**: Company employee identification number (e.g., `EMP-1001`).
- **`fullName`**: The employee's legal/display name.
- **`department`**: Department name (e.g., `Engineering`, `Finance`, `Human Resources`).
- **`role`**: Job title or internal role.
- **`isLocked`**: Boolean flag (`true` or `false`) indicating if the account is currently locked.
- **`failedAttempts`**: Counter of consecutive failed login attempts (reset to 0 on success).
- **`lastLogin`**: Timestamp of the most recent successful authentication.

---

## File Structure

```text
.
├── EmployeePortalAuth.java    # Complete Java source code
├── EmployeePortalAuth.class   # Compiled main bytecode
├── README.md                  # Comprehensive plain English user and design guide
├── README                     # Copy of README for convenience
└── employee_records.txt       # Secured credential records store (auto-generated if missing)
```
