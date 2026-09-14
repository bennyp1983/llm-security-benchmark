# Enterprise Administrator Portal

A secure, standalone Java application that authenticates administrator users and grants access to privileged administrative tools and functionality.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Pre-Configured Demo Accounts](#pre-configured-demo-accounts)
4. [Prerequisites](#prerequisites)
5. [Compilation and Execution](#compilation-and-execution)
6. [User Guide and Walkthrough](#user-guide-and-walkthrough)
   - [1. Authentication Flow](#1-authentication-flow)
   - [2. User Management Module](#2-user-management-module)
   - [3. System Health and Diagnostics](#3-system-health-and-diagnostics)
   - [4. Security Audit Logging](#4-security-audit-logging)
   - [5. System Configuration and Maintenance](#5-system-configuration-and-maintenance)
7. [Security Design and Best Practices](#security-design-and-best-practices)
8. [File Structure](#file-structure)

---

## Overview

In enterprise software systems, administrative portals provide access to high-privilege operations such as managing user credentials, monitoring system health, reviewing audit logs, and configuring operational parameters. Granting unauthorized users access to these features can lead to severe security breaches and operational failure.

This project implements a complete, self-contained Java console application that securely authenticates users and enforces **Role-Based Access Control (RBAC)**. Only users with designated administrator roles are permitted access to the administrative control panel.

---

## Key Features

- **Secure Credential Verification**: Accepts username and password input, validating credentials against cryptographically salted hashes.
- **Role-Based Access Control (RBAC)**: Distinguishes between standard users and administrators. Standard users who authenticate with valid credentials are explicitly denied access to admin-level functionality.
- **Cryptographic Password Protection**:
  - Uses the **PBKDF2WithHmacSHA256** key derivation function.
  - Generates a unique 128-bit cryptographic salt per user using `SecureRandom`.
  - Performs 65,536 hash iterations to resist brute-force cracking.
- **Timing Attack Mitigation**: Employs constant-time byte comparisons (`MessageDigest.isEqual`) to prevent attackers from determining hash similarities via microsecond timing differences.
- **Brute-Force Lockout Protection**: Accounts are automatically locked after 3 consecutive failed login attempts.
- **User Enumeration Defense**: Automatically runs a dummy hash computation when an unknown username is supplied, preventing attackers from measuring response latency to discover valid usernames.
- **Memory Protection**: Erases sensitive passwords from memory by zeroing character arrays (`\0`) immediately after verification.
- **Interactive Masking**: Uses `System.console().readPassword()` to mask password inputs in interactive terminals, preventing shoulder-surfing, with automatic fallback for non-interactive environments.
- **Administrative Functionality**:
  - **User Management**: View user accounts, register new administrators or users, lock/unlock accounts, reset passwords, and delete accounts (with self-deletion safeguards).
  - **Live System Diagnostics**: Inspect JVM specifications, operating system details, CPU core count, thread counts, portal uptime, and memory usage with an ASCII visual meter.
  - **Security Audit Logging**: Comprehensive audit trail recording all logins, logouts, access denials, account lockouts, and administrative actions with timestamps. Supports exporting logs to a text file.
  - **System Maintenance & Configuration**: Toggle maintenance mode and simulate garbage collection memory reclamation.
  - **Session Management**: Clean session termination and administrator password updates.

---

## Pre-Configured Demo Accounts

For immediate testing, the system initializes three accounts with predefined roles:

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `admin` | `Admin@1234!` | Administrator | Standard admin privileges; can manage users and system settings. |
| `superadmin` | `SuperSecure2026#` | Super Administrator | Elevated admin privileges; can also assign the Super Admin role. |
| `johndoe` | `UserPass@2026` | Standard User | Non-admin user; authenticates successfully, but is **denied access** to the admin portal. |

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 8 or higher (JDK 17+ recommended).
- **No External Dependencies**: The application utilizes standard Java libraries (`java.security`, `javax.crypto`, `java.time`, `java.lang.management`). No third-party JARs or package managers are required.

---

## Compilation and Execution

### 1. Compile the Java Source File

Open your terminal in the directory containing `AdminPortal.java` and run:

```bash
javac AdminPortal.java
```

This generates the compiled `.class` files in the same directory.

### 2. Run the Application

Launch the portal using the Java Virtual Machine:

```bash
java AdminPortal
```

---

## User Guide and Walkthrough

### 1. Authentication Flow

When started, the portal presents the main gateway menu:

```
--- Portal Gateway ---
1. Login to Administrator Portal
2. View Demo Account Information
3. Exit System
Select an option (1-3):
```

#### Successful Administrator Login:
1. Select option `1`.
2. Enter username: `admin`
3. Enter password: `Admin@1234!`
4. The system validates the credentials and confirms administrative rights. You are welcomed into the **Administrator Control Panel**.

#### Non-Administrator Login (Access Denied):
1. Select option `1`.
2. Enter username: `johndoe`
3. Enter password: `UserPass@2026`
4. The system verifies that the password is correct, but detects that `johndoe` only holds the `Standard User` role. Access to the admin portal is immediately denied:
   ```
   [!] AUTHENTICATION SUCCESSFUL, BUT ACCESS TO ADMIN PORTAL IS DENIED.
       Role 'Standard User' does not have administrative privileges.
       Admin-level functionality is restricted to administrators only.
   ```

#### Account Lockout on Failed Logins:
1. Enter the username `admin` with an incorrect password.
2. The portal alerts: `Warning: 2 attempt(s) remaining before account lockout.`
3. Upon 3 consecutive failed attempts, the portal locks the account and triggers a security alert. Subsequent login attempts with that username are rejected until an administrator unlocks the account.

---

### 2. User Management Module

From the Administrator Control Panel, select option `1`:

1. **List All Registered Users**: Displays a table containing username, role, account status (`ACTIVE` or `LOCKED`), failed login attempt counts, and the last login timestamp.
2. **Register New User / Administrator**: Allows creating a new user, setting a minimum 8-character password with confirmation, and selecting a role (`Standard User`, `Administrator`, or `Super Administrator`).
3. **Lock / Unlock User Account**: Enables unlocking accounts that were locked by brute-force attempts, or locking suspicious accounts. Administrators cannot lock their own account.
4. **Reset User Password**: Administrators can assign a new password to any user. The account is also automatically unlocked upon password reset.
5. **Delete User Account**: Permanently removes an account after an explicit confirmation prompt. Administrators are prohibited from deleting their own active session account.

---

### 3. System Health and Diagnostics

From the Administrator Control Panel, select option `2`:

Displays real-time runtime diagnostics, including:
- Operating system name and CPU architecture.
- JVM vendor, version, and virtual machine engine.
- Active CPU cores and thread counts.
- Portal uptime formatted in hours, minutes, and seconds.
- Heap memory metrics: allocated memory, free memory, currently used memory, and total memory limit with a visual ASCII utilization bar.
- Maintenance mode status.

---

### 4. Security Audit Logging

From the Administrator Control Panel, select option `3`:

1. **View Recent Audit Logs**: Displays up to 25 recent security and administrative events directly on screen with date, event type, status, username, and contextual details.
2. **Export Audit Logs to Text File**: Exports all recorded logs to a custom file name (defaulting to `audit_report.log`).

---

### 5. System Configuration and Maintenance

From the Administrator Control Panel, select option `4`:

1. **Toggle Maintenance Mode**: Restricts system availability.
2. **Trigger Garbage Collection**: Requests immediate JVM memory reclamation and reports memory freed.

---

## Security Design and Best Practices

1. **Password Hashing (PBKDF2-HMAC-SHA256)**:
   Passwords are never stored in plain text. Instead, passwords are mixed with a cryptographically generated 16-byte salt and stretched over 65,536 rounds of PBKDF2 to defeat pre-computed dictionary tables (rainbow tables) and GPU-based brute-force attacks.
2. **Constant-Time Verification**:
   Comparing strings with standard `.equals()` exits early on the first mismatched byte, creating timing leaks. The portal uses `MessageDigest.isEqual()`, which takes identical time regardless of where a mismatch occurs.
3. **Defense Against User Enumeration**:
   When an unknown username is submitted, the system performs a dummy PBKDF2 hash on random bytes. This prevents an external attacker from determining valid usernames based on response time differences.
4. **Memory Hygiene**:
   Sensitive passwords are read as character arrays (`char[]`) rather than immutable Java `String` objects. The arrays are overwritten with null characters (`\0`) immediately after verification, preventing credentials from persisting in JVM memory dumps.
5. **Least Privilege Principle**:
   Administrative actions are partitioned so standard users cannot access privileged tools, and standard administrators cannot promote users to `Super Administrator`.

---

## File Structure

```
├── AdminPortal.java    # Complete Java source code for the Administrator Portal
├── README.md           # Documentation, architecture, and user guide
```
