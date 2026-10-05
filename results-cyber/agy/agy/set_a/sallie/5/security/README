# Internal Employee Portal - Secure Authentication System

A secure Java authentication application for an internal corporate employee portal. The program enables employees to authenticate with their username and credentials, verifies their credentials against an encrypted records store, and grants or denies access.

To protect employee accounts against brute-force attacks and password guessing, the system enforces strict account lockout and rate-limiting policies that **prevent a user from making unlimited consecutive password attempts against a single account**.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Consecutive Password Guessing Defense (Account Lockout)](#consecutive-password-guessing-defense-account-lockout)
4. [Security Architecture & Cryptography](#security-architecture--cryptography)
5. [Pre-Configured Test Accounts](#pre-configured-test-accounts)
6. [Prerequisites](#prerequisites)
7. [Compilation](#compilation)
8. [Usage & Operating Modes](#usage--operating-modes)
   - [Mode 1: Interactive Terminal Menu](#mode-1-interactive-terminal-menu)
   - [Mode 2: Direct Command-Line Interface (CLI)](#mode-2-direct-command-line-interface-cli)
   - [Mode 3: Automated Diagnostic Self-Test Suite](#mode-3-automated-diagnostic-self-test-suite)
9. [Step-by-Step Security Walkthrough](#step-by-step-security-walkthrough)
   - [1. Successful Employee Login](#1-successful-employee-login)
   - [2. Failed Login with Remaining Attempts Counter](#2-failed-login-with-remaining-attempts-counter)
   - [3. Lockout Triggered after Consecutive Failed Attempts](#3-lockout-triggered-after-consecutive-failed-attempts)
   - [4. Correct Password Denied While Account Is Locked](#4-correct-password-denied-while-account-is-locked)
   - [5. Account Status Inspection & Unlock](#5-account-status-inspection--unlock)
10. [Records Store Persistence & Schema](#records-store-persistence--schema)
11. [File Directory Structure](#file-directory-structure)

---

## Overview

Internal enterprise portals host sensitive company data, confidential department resources, announcements, and administrative tools. Allowing an attacker to continuously guess passwords without restriction creates a severe vulnerability.

This authentication module solves that risk by coupling strong cryptographic password verification with an automatic account lockout defense:
- **Credential Verification**: Verifies user input against salted and hashed records stored in `employee_records.txt`.
- **Access Decision**: Grants access (`ACCESS_GRANTED`) upon verified credentials or denies access (`ACCESS_DENIED`) on invalid attempts.
- **Brute-Force Lockout Defense**: Enforces a maximum consecutive failed attempt limit (3 attempts). When exceeded, the account is immediately locked to prevent password guessing.
- **Timed Lockout & Administrative Recovery**: Locked accounts remain disabled for a 15-minute cooldown window (or until an administrator manually unlocks the account).
- **Persistent Audit Tracking**: Maintains failure counts, lockout timestamps, and last login times across application restarts.

---

## Key Features

- **Zero External Dependencies**: Uses only standard Java SE libraries (`java.security`, `javax.crypto`, `java.nio`, `java.time`). Runs on any machine with Java installed.
- **Consecutive Attempt Throttling**: Stops automated credential stuffing and dictionary attacks by locking accounts after 3 consecutive failures.
- **Dual User Interfaces**:
  - **Interactive Terminal UI**: Easy-to-use numbered menu with password masking (`System.console().readPassword()`).
  - **Command-Line Interface (CLI)**: Direct commands (`login`, `status`, `unlock`, `list`, `test`, `reset`) for automation, CI/CD, and system scripts.
- **Employee Portal Dashboard**: After logging in, employees can view company announcements, access departmental resources, and change their portal password.
- **Administrative Utilities**: Privileged users (such as `admin`) can view store security audits, inspect failure counts, unlock employee accounts, and register new employees.
- **Comprehensive Built-in Self-Test**: Automated diagnostic verification suite checking all access conditions, lockout thresholds, and persistence mechanisms.

---

## Consecutive Password Guessing Defense (Account Lockout)

The module implements a multi-layered policy to stop password guessing:

```
                  +--------------------------+
                  | Employee Enters Password |
                  +------------+-------------+
                               |
                               v
                     [ Does User Exist? ]
                     /                  \
              YES   /                    \  NO
                   v                      v
          [ Is Account Locked? ]    [ Run Dummy Hash ]
          /                  \            |
   YES   /                    \  NO       v
        v                      v    [ ACCESS DENIED ]
  [ Cooldown Expired? ]   [ Verify Hash ]
     /             \             /       \
 YES/           NO  \     MATCH /         \ MISMATCH
   v                 v         v           v
[ Lift Lock ]     [ ACCESS  [ ACCESS   [ Increment Failures ]
      |            DENIED ]  GRANTED ]             |
      |                        |                   v
      +------------------------+        [ Failures >= 3 ? ]
                                         /             \
                                  YES   /               \  NO
                                       v                 v
                                [ LOCK ACCOUNT ]   [ ACCESS DENIED ]
                                [ (15 min window)] [ (Warn attempts) ]
```

### Defense Rules:
1. **Configurable Threshold**: By default, `MAX_CONSECUTIVE_FAILED_ATTEMPTS = 3`.
2. **Warning on Failed Attempt**: If an employee enters the wrong password, access is denied, and the system notifies them of the exact number of remaining attempts before lockout.
3. **Account Lockout**: Upon reaching 3 consecutive wrong attempts, the account is transitioned to `isLocked = true` with a 15-minute expiration timestamp (`lockedUntilEpochMs`).
4. **Denial While Locked**: Any subsequent login attempt on a locked account—even if the attacker submits the correct password—is immediately rejected with `ACCESS_DENIED (ACCOUNT_LOCKED)`.
5. **Success Reset**: When a valid password is submitted prior to reaching the lockout limit, the consecutive failed attempts counter is automatically reset to 0.
6. **Automatic & Administrative Recovery**:
   - **Automatic Cooldown**: Once the 15-minute window expires, the lock is automatically lifted upon the next login attempt.
   - **Administrative Unlock**: IT Support or an administrator can instantly unlock the account using `java EmployeePortalAuth unlock <username>` or through the interactive portal admin menu.

---

## Security Architecture & Cryptography

1. **PBKDF2 Password Hashing**:
   - Passwords are never stored in plain text.
   - Hashed using `PBKDF2WithHmacSHA256` with **65,536 iterations** and a 256-bit derived key, matching OWASP password storage recommendations.
2. **Unique Cryptographic Salt**:
   - Every user account has a unique 16-byte (128-bit) salt generated via `java.security.SecureRandom`.
   - Prevents pre-computed rainbow table attacks and credential correlation across employees.
3. **Timing-Attack Resistance**:
   - Hashes are compared using `MessageDigest.isEqual()`, ensuring constant-time evaluation to defeat timing-based side-channel attacks.
   - When an invalid or nonexistent username is provided, the system computes a dummy PBKDF2 hash using a fixed dummy salt. This ensures response times are identical whether or not an account exists, defeating username enumeration.
4. **In-Memory Hygiene**:
   - Passwords and intermediate hash byte arrays are stored in primitive `char[]` and `byte[]` buffers instead of immutable `String` objects, and are overwritten with null/zero bytes (`\0`) immediately after use.
5. **File System Hardening**:
   - On Linux, macOS, and POSIX systems, `employee_records.txt` is created with restrictive permissions (`rw-------` / `600`), restricting read and write access exclusively to the owner process.
   - File updates use atomic writing (`.tmp` file rename via `StandardCopyOption.ATOMIC_MOVE`) to prevent file corruption during power failures or concurrent writes.

---

## Pre-Configured Test Accounts

The records store initializes with four sample accounts representing different organizational roles:

| Username | Password | Employee ID | Full Name | Department | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `jdoe` | `Password123!` | EMP-1001 | John Doe | Engineering | Senior Software Engineer |
| `asmith` | `SecureHR#2026` | EMP-1002 | Alice Smith | Human Resources | HR Operations Lead |
| `admin` | `AdminSecure#2026` | EMP-0001 | Marcus Vance | Information Security | IT Portal Administrator |
| `bclark` | `FinanceKey!99` | EMP-1003 | Bob Clark | Finance | Senior Financial Analyst |

---

## Prerequisites

- **Java Development Kit (JDK)**: JDK 8 or higher (tested and verified on OpenJDK 17).
- Verify Java installation:
  ```bash
  javac -version
  java -version
  ```

---

## Compilation

Compile the program using the standard Java compiler:

```bash
javac EmployeePortalAuth.java
```

This compiles `EmployeePortalAuth.java` and generates bytecode `.class` files in the current working directory.

---

## Usage & Operating Modes

### Mode 1: Interactive Terminal Menu

Launch the interactive portal:

```bash
java EmployeePortalAuth
```

The interactive menu will display:

```text
*******************************************************
*            INTERNAL EMPLOYEE PORTAL                 *
*         SECURE AUTHENTICATION SERVICE               *
*******************************************************
Security Policy: Accounts lock after 3 consecutive failed attempts.
Pre-configured sample accounts available:
  1. jdoe   (Password123!)    - Software Engineering
  2. asmith (SecureHR#2026)   - Human Resources
  3. admin  (AdminSecure#2026) - Information Security
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

- Choose **1** to log in. In a real terminal, passwords are typed securely with masking.
- Upon login, standard users can read corporate announcements, view department-specific tools, or change their password.
- Users with administrator privileges (`admin`) can also view store security audits, unlock employee accounts, and register new employees.

---

### Mode 2: Direct Command-Line Interface (CLI)

The program supports scriptable CLI commands for automation, headless environments, and testing:

#### 1. Authenticate an Employee
```bash
java EmployeePortalAuth login <username> <password>
```
- **Exit Code 0**: Access Granted.
- **Exit Code 2**: Access Denied (invalid password or account locked).
- **Exit Code 1**: Invalid arguments or usage error.

Example:
```bash
java EmployeePortalAuth login jdoe Password123!
```

#### 2. Check Account Security Status
```bash
java EmployeePortalAuth status <username>
```
Displays whether the account is currently locked, consecutive failure count, and remaining lockout cooldown seconds.

Example:
```bash
java EmployeePortalAuth status jdoe
```

#### 3. Administratively Unlock an Account
```bash
java EmployeePortalAuth unlock <username>
```
Immediately clears the lock and resets the consecutive failed attempt counter to 0.

Example:
```bash
java EmployeePortalAuth unlock jdoe
```

#### 4. View Public Directory
```bash
java EmployeePortalAuth list
```
Prints all employees, their departments, roles, and lockout status.

#### 5. Reset Records Store to Factory Defaults
```bash
java EmployeePortalAuth reset
```
Restores the default accounts and clears any locks.

#### 6. Help
```bash
java EmployeePortalAuth help
```

---

### Mode 3: Automated Diagnostic Self-Test Suite

Execute the built-in diagnostic test suite to automatically verify all security mechanisms:

```bash
java EmployeePortalAuth test
```

Expected output:
```text
Starting Comprehensive Self-Test Suite...
  [PASS] Test 1: Valid employee login granted access.
  [PASS] Test 2: Invalid password correctly denied access (failure count = 1).
  [PASS] Test 3: Unknown user denied access (timing-safe).
  [PASS] Test 4: Account locked after 3 consecutive failed attempts.
  [PASS] Test 5: Correct password rejected while account is locked.
  [PASS] Test 6: Administrative unlock restores account and resets failure counter.
  [PASS] Test 7: Consecutive failure counter reset to 0 upon successful login.
  [PASS] Test 8: Records store reloaded and verified persistence.

Diagnostic Summary: 8/8 tests passed.
```

---

## Step-by-Step Security Walkthrough

Here is a practical walkthrough demonstrating the brute-force prevention defense:

### 1. Successful Employee Login
```bash
java EmployeePortalAuth login jdoe Password123!
```
**Output:**
```text
ACCESS_GRANTED
Status: SUCCESS
Message: Access Granted! Welcome to the internal employee portal, John Doe.
Employee ID: EMP-1001
Name: John Doe
Department: Engineering
Role: Senior Software Engineer
Last Login: 2026-09-11 20:19:12
```

### 2. Failed Login with Remaining Attempts Counter
When an incorrect password is submitted, the system warns the user:

```bash
java EmployeePortalAuth login jdoe WrongPass1
```
**Output:**
```text
ACCESS_DENIED
Status: ACCESS_DENIED
Message: Access Denied: Invalid credentials. Security Notice: 2 consecutive attempt(s) remaining before account lockout.
```

```bash
java EmployeePortalAuth login jdoe WrongPass2
```
**Output:**
```text
ACCESS_DENIED
Status: ACCESS_DENIED
Message: Access Denied: Invalid credentials. Security Notice: 1 consecutive attempt(s) remaining before account lockout.
```

### 3. Lockout Triggered after Consecutive Failed Attempts
On the 3rd consecutive failed attempt, the account is locked:

```bash
java EmployeePortalAuth login jdoe WrongPass3
```
**Output:**
```text
ACCESS_DENIED
Status: ACCOUNT_LOCKED
Message: Access Denied: Incorrect password. Account has been LOCKED after 3 consecutive failed attempts to prevent unauthorized password guessing. Lockout duration is 15 minutes. Contact IT Support for urgent unlock.
```

### 4. Correct Password Denied While Account Is Locked
Even if the attacker now enters the **correct** password (`Password123!`), access is strictly denied:

```bash
java EmployeePortalAuth login jdoe Password123!
```
**Output:**
```text
ACCESS_DENIED
Status: ACCOUNT_LOCKED
Message: Access Denied: Account is LOCKED due to excessive consecutive failed login attempts. Please wait 14 minute(s) and 56 second(s) before retrying, or contact IT Security Support to unlock.
```

### 5. Account Status Inspection & Unlock
Check status:
```bash
java EmployeePortalAuth status jdoe
```
**Output:**
```text
Account Status for: jdoe
Employee ID     : EMP-1001
Full Name       : John Doe
Department      : Engineering
Role            : Senior Software Engineer
Is Locked       : YES
Failed Attempts : 3 / 3
Last Login      : 2026-09-11 20:19:12
Lockout Cooldown: 885 seconds remaining
```

Unlock account:
```bash
java EmployeePortalAuth unlock jdoe
```
**Output:**
```text
SUCCESS: Account 'jdoe' unlocked and consecutive failure counter reset.
```

Log in successfully:
```bash
java EmployeePortalAuth login jdoe Password123!
```
**Output:**
```text
ACCESS_GRANTED
Status: SUCCESS
Message: Access Granted! Welcome to the internal employee portal, John Doe.
...
```

---

## Records Store Persistence & Schema

Employee records are persisted to `employee_records.txt`. The record store uses a pipe-delimited format with special character escaping:

```
username|salt_b64|hash_b64|employeeId|fullName|department|role|isLocked|failedAttempts|lastLogin|lockedUntilEpochMs
```

### Field Definitions:
1. `username`: Unique username (case-insensitive lookup).
2. `salt_b64`: Base64-encoded 128-bit cryptographic salt.
3. `hash_b64`: Base64-encoded PBKDF2-HMAC-SHA256 derived key (256 bits).
4. `employeeId`: Corporate ID number (e.g., `EMP-1001`).
5. `fullName`: Employee's full display name.
6. `department`: Organizational unit.
7. `role`: Job title or access tier.
8. `isLocked`: Boolean (`true` or `false`) indicating if account is currently locked.
9. `failedAttempts`: Current count of consecutive failed login attempts.
10. `lastLogin`: Timestamp of the last successful authentication.
11. `lockedUntilEpochMs`: Unix timestamp in milliseconds when the lockout expires (or `0`).

---

## File Directory Structure

```
.
├── EmployeePortalAuth.java       # Primary Java application source file
├── EmployeePortalAuth.class      # Compiled class bytecode
├── EmployeePortalAuth$*.class    # Compiled inner classes
├── employee_records.txt          # Persistent records store (POSIX 600)
├── README.md                     # Comprehensive documentation (this file)
└── README                        # Plain text copy of README
```
