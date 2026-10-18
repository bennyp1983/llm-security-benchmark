# Enterprise Administrator Portal

A production-grade, secure Java console application providing an administrative authentication gateway, Role-Based Access Control (RBAC), admin-level management capabilities, and comprehensive audit logging for all authentication and security events.

---

## Table of Contents

1. [Overview](#overview)
2. [Core Requirements Addressed](#core-requirements-addressed)
3. [Security Architecture & Defense-in-Depth](#security-architecture--defense-in-depth)
4. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
5. [Pre-Configured Demonstration Accounts](#pre-configured-demonstration-accounts)
6. [Prerequisites](#prerequisites)
7. [Compilation & Execution](#compilation--execution)
8. [Administrator Portal Functionalities](#administrator-portal-functionalities)
9. [Audit Logging Subsystem](#audit-logging-subsystem)
   - [Log File Location & Format](#log-file-location--format)
   - [Recorded Event Types](#recorded-event-types)
   - [Reviewing Audit Logs](#reviewing-audit-logs)
10. [Account Lockout & Brute-Force Defense](#account-lockout--brute-force-defense)
11. [Step-by-Step Usage Walkthrough](#step-by-step-usage-walkthrough)

---

## Overview

The **Enterprise Administrator Portal** is designed to restrict access to sensitive administrative operations by requiring secure credential verification. It accepts a username and password, authenticates users against cryptographically salted and stretched hashes, verifies administrative role privileges, and grants or denies access accordingly.

Every authentication attempt—whether successful, failed due to bad credentials, locked out due to repeated failures, or denied due to lack of administrative privileges—is permanently recorded to an append-only audit trail (`audit.log`) with ISO-8601 UTC timestamps. In addition, an interactive in-portal audit viewer allows authorized administrators to inspect, filter, and export past security events directly within the application.

---

## Core Requirements Addressed

1. **Authentication Gateway**: Accepts username and password input, securely verifies credentials against stored cryptographic hashes, and clears sensitive in-memory buffers.
2. **Access Control (RBAC)**: Grants access to admin-level functionalities only to verified administrators. Standard non-admin users who authenticate with valid credentials are explicitly denied access to the admin portal.
3. **Audit Trail for Later Review**: Every authentication attempt (successful, failed, locked out, or non-admin denial) and subsequent administrative operation is recorded to `audit.log` and can be reviewed inside the portal or via standard command-line tools.
4. **Self-Contained & Documented**: Implemented in standard Java with zero external third-party dependencies, fully documented in plain English.

---

## Security Architecture & Defense-in-Depth

The application implements defense-in-depth security principles mitigating common vulnerabilities:

| Security Measure | Implementation Details | Vulnerability / CWE Mitigated |
| :--- | :--- | :--- |
| **Password Hashing** | Uses `PBKDF2WithHmacSHA256` with **120,000 iterations** and **16-byte random salts** generated via `java.security.SecureRandom`. Plaintext passwords are never stored. | **CWE-916**: Use of Password Hash With Insufficient Computational Effort |
| **Timing Attack Resistance** | Uses `MessageDigest.isEqual()` for constant-time hash comparison, preventing byte-by-byte timing discrepancy attacks. | **CWE-208**: Observable Timing Discrepancy |
| **User Enumeration Prevention** | When an unknown username is entered, the system computes a PBKDF2 hash against a dummy salt. This ensures response latency is identical regardless of whether a username exists. Error messages are generic (`"Invalid username or password."`). | **CWE-200**: Exposure of Sensitive Information |
| **In-Memory Credential Scrubbing** | Passwords are read into `char[]` arrays rather than immutable `String` objects, and memory is overwritten with zeros (`\0`) immediately after verification. | **CWE-244**: Improper Clearing of Heap Memory Containing Sensitive Data |
| **Log Injection Defense** | All user-supplied inputs (usernames, sources) are strictly sanitized before writing to the log file. Newlines (`\r`, `\n`) and control characters are stripped/replaced to prevent CRLF log forging. | **CWE-117**: Improper Output Handling for Logs |
| **Zero Secret Leakage** | Passwords (plaintext or hashes) are never written to log files or displayed on console screens. | **CWE-532**: Insertion of Sensitive Information into Log File |
| **Brute-Force & Lockout Defense** | Accounts are automatically locked after 5 consecutive failed attempts. Locked accounts remain disabled for a 15-minute cooldown or until an administrator unlocks them. | **CWE-307**: Improper Restriction of Excessive Authentication Attempts |

---

## Role-Based Access Control (RBAC)

The portal defines four roles:

| Role | Admin Privileges? | Description |
| :--- | :---: | :--- |
| `SUPER_ADMIN` | **Yes** | Full administrative rights: user management, system config, diagnostics, log review. |
| `ADMIN` | **Yes** | Standard administrator: system telemetry, user management, audit review. |
| `SECURITY_AUDITOR` | **Yes** | Read-only security auditor: audit log review, telemetry, and security diagnostics. |
| `STANDARD_USER` | **No** | Regular user. Authenticates successfully, but **access to admin portal is denied**. |

---

## Pre-Configured Demonstration Accounts

The following accounts are pre-seeded for testing and demonstration:

| Username | Role | Password | Expected Authentication Result |
| :--- | :--- | :--- | :--- |
| `admin` | `SUPER_ADMIN` | `Admin@Secure2026!` | **Access Granted**: Full Administrator Control Panel |
| `secops` | `ADMIN` | `SecOps#Secure2026!` | **Access Granted**: Administrator Control Panel |
| `auditor` | `SECURITY_AUDITOR` | `Audit#Secure2026!` | **Access Granted**: Security & Audit Control Panel |
| `johndoe` | `STANDARD_USER` | `UserPass@2026!` | **Access Denied**: Valid credentials, but lacks admin role |

---

## Prerequisites

- **Java Development Kit (JDK)**: Version 11 or higher (tested on OpenJDK 17).
- **Operating System**: Linux, macOS, or Windows.
- **Terminal/Console**: Supports interactive terminals (masked password input via `System.console()`) and standard input redirection/pipes for automated scripts.

---

## Compilation & Execution

### 1. Compile

```bash
javac AdminPortal.java
```

### 2. Run

```bash
java AdminPortal
```

To display help and usage options:

```bash
java AdminPortal --help
```

---

## Administrator Portal Functionalities

Once successfully authenticated as an administrator, the following features are available in the **Administrator Control Panel**:

1. **System Health & Resource Telemetry**:
   - Host Operating System, Version, and Architecture.
   - Java Virtual Machine version and vendor.
   - Portal uptime clock and UTC system timestamp.
   - Available CPU cores and active thread counts.
   - JVM allocated, free, and maximum heap memory with an ASCII utilization gauge.

2. **Review Security Audit Logs**:
   - View all recorded audit entries.
   - Filter exclusively for authentication failures, lockouts, and access denials (security incident inspection).
   - Filter for successful logins.
   - Search/filter events by specific username.

3. **User Account Management**:
   - **List All Registered Accounts**: Displays usernames, assigned roles, lockout status, failed attempt counts, and last login timestamps.
   - **Create New User or Administrator**: Provision new accounts with mandatory password complexity validation (min 10 characters, uppercase, lowercase, numbers, and special symbols).
   - **Lock or Unlock an Account**: Manually lock compromised accounts or unlock locked accounts (with safeguards against self-lockout).
   - **Reset User Password**: Change another user's password with complexity validation.
   - **Delete User Account**: Permanently remove accounts (with safeguards against deleting your own active session).

4. **Security Diagnostics & Cryptographic Engine Benchmark**:
   - Verifies `audit.log` file existence, read/write permissions, byte size, and line count.
   - Runs a benchmark of the PBKDF2 cryptographic engine and reports hashing duration in milliseconds.

5. **System Maintenance & Configuration**:
   - Toggle maintenance mode.
   - Trigger JVM garbage collection and report reclaimed heap memory.

6. **Change Administrator Password**:
   - Allows the logged-in administrator to change their own password (requires entering current password, new password, and confirmation).

7. **Export Audit Summary Report**:
   - Exports the entire audit log trail into a standalone, formatted text report file (`audit_report_<timestamp>.txt`) for distribution or regulatory archiving.

8. **Logout / Terminate Admin Session**:
   - Logs an official `LOGOUT` event in `audit.log` and securely terminates the administrative session.

---

## Audit Logging Subsystem

### Log File Location & Format

All events are appended to `audit.log` located in the application directory. Each entry is written as a structured, single-line record:

```text
[TIMESTAMP_UTC] [EVENT_TYPE] User: <USERNAME> | Source: <SOURCE> | Status: <STATUS> | Details: <DETAILS>
```

#### Example Log Records:

```text
[2026-09-11T21:17:00.005Z] [AUTH_DENIED_NON_ADMIN] User: johndoe | Source: CLI-Local | Status: DENIED | Details: Credentials verified, but user role 'Standard User' lacks admin privileges
[2026-09-11T21:17:00.186Z] [AUTH_FAILURE] User: ghost_user | Source: CLI-Local | Status: FAILED | Details: Authentication rejected: invalid credentials (unknown user)
[2026-09-11T21:17:00.357Z] [AUTH_SUCCESS] User: admin | Source: CLI-Local | Status: SUCCESS | Details: Authentication successful with role: SUPER_ADMIN
[2026-09-11T21:17:00.360Z] [ADMIN_ACTION] User: admin | Source: CLI-Local | Status: SUCCESS | Details: Entered Administrator Portal session
[2026-09-11T21:17:01.799Z] [AUTH_LOCKOUT] User: secops | Source: CLI-Local | Status: LOCKED | Details: Account locked after reaching 5 consecutive failed attempts
[2026-09-11T21:17:01.975Z] [ADMIN_ACTION] User: admin | Source: CLI-Local | Status: SUCCESS | Details: Unlocked account for user: secops
[2026-09-11T21:17:02.147Z] [LOGOUT] User: secops | Source: CLI-Local | Status: SUCCESS | Details: Administrator session ended normally
```

### Recorded Event Types

| Event Type | Trigger Condition |
| :--- | :--- |
| `AUTH_SUCCESS` | Successful authentication for an account with administrative privileges. |
| `AUTH_FAILURE` | Failed authentication due to incorrect password or non-existent username. |
| `AUTH_LOCKOUT` | Account locked due to 5 consecutive failed attempts, or a login attempt on a locked account. |
| `AUTH_DENIED_NON_ADMIN` | Valid credentials supplied, but account lacks administrative privileges (`STANDARD_USER`). |
| `ADMIN_ACTION` | Administrative operation performed (account created, unlocked, password reset, telemetry viewed, diagnostics run). |
| `LOGOUT` | Administrator explicitly logs out and ends their session. |

### Reviewing Audit Logs

Audit logs can be reviewed in multiple ways:
1. **Interactive In-Portal Reviewer**: Log in as an administrator, select Option `2` ("Review Security Audit Logs"), and choose to view all events, filter only security failures, filter successes, or search by specific username.
2. **Exported Text Report**: In the admin menu, select Option `7` ("Export Audit Summary Report to File").
3. **Command Line / External Tools**: Inspect `audit.log` directly using standard tools:
   ```bash
   # View all events
   cat audit.log

   # Inspect failed attempts and lockouts
   grep -E "AUTH_FAILURE|AUTH_LOCKOUT|AUTH_DENIED" audit.log

   # Follow logs in real time
   tail -f audit.log
   ```

---

## Account Lockout & Brute-Force Defense

- **Lockout Threshold**: 5 consecutive failed login attempts.
- **Lockout Duration**: 15-minute automatic cooldown window.
- **Manual Administrative Unlock**: An administrator can log in and immediately unlock the account via **User Account Management -> Lock or Unlock an Account**.
- **Counter Reset**: Successful login resets the failed attempts counter to 0.

---

## Step-by-Step Usage Walkthrough

### 1. Launch the Application

```bash
$ java AdminPortal
************************************************************
*            SECURE ENTERPRISE ADMIN PORTAL                *
*        Role-Based Access Control & Audit Logging         *
************************************************************
System initialized at  : 2026-09-11T21:17:00.000Z
Audit trail destination: /data/results/agy/set_a/sallie/6/security/audit.log

Default Pre-seeded Accounts for Demonstration:
  - admin     (SUPER_ADMIN)      : Admin@Secure2026!
  - secops    (ADMIN)            : SecOps#Secure2026!
  - auditor   (SECURITY_AUDITOR) : Audit#Secure2026!
  - johndoe   (STANDARD_USER)    : UserPass@2026! (Non-admin)

==================================================
            PORTAL MAIN GATEWAY
==================================================
  1. Authenticate & Enter Administrator Portal
  2. System Quick-Check / Public Status
  3. Exit Gateway

Select an option (1-3): 1
```

### 2. Attempt Authentication as a Non-Admin User

```text
--------------------------------------------------
           ADMINISTRATOR AUTHENTICATION
--------------------------------------------------
Username: johndoe
Password: [Hidden Input]

[!] AUTHENTICATION SUCCESSFUL, BUT ACCESS TO ADMIN PORTAL IS DENIED.
    User 'johndoe' holds role: Standard User
    Access to administrator-level functionality requires an administrative role.
    This access denial event has been recorded in the security audit log.
```

### 3. Authenticate as an Administrator

```text
Select an option (1-3): 1
--------------------------------------------------
           ADMINISTRATOR AUTHENTICATION
--------------------------------------------------
Username: admin
Password: [Hidden Input]

================================================================================
 [+] AUTHENTICATION SUCCESSFUL: ACCESS GRANTED
 Welcome, admin (Super Administrator)!
 Last Login: 2026-09-11T21:16:30.055Z
================================================================================
```

### 4. Inspecting Audit Logs Inside the Portal

```text
==================================================
           ADMINISTRATOR CONTROL PANEL
  Logged in as: admin | Role: Super Administrator
==================================================
  1. System Health & Resource Telemetry
  2. Review Security Audit Logs (Successful & Failed Logins)
  3. User Account Management (View, Add, Lock/Unlock, Delete)
  4. Security Diagnostics & Cryptographic Engine Benchmark
  5. System Maintenance & Configuration (Maintenance Mode, GC)
  6. Change My Administrator Password
  7. Export Audit Summary Report to File
  8. Logout / Terminate Admin Session

Select admin action (1-8): 2

==================================================
             SECURITY AUDIT LOG VIEWER
==================================================
  1. View All Recorded Audit Events
  2. View Only Authentication Failures & Denials (Security Events)
  3. View Only Successful Logins
  4. Filter Audit Events by Specific Username
  5. Return to Administrator Control Panel

Select review option (1-5): 2

--- Audit Log: Authentication Failures, Lockouts & Access Denials (Total Matching: 2) ---
TIMESTAMP (UTC)            | EVENT TYPE             | USERNAME       | STATUS     | DETAILS
--------------------------------------------------------------------------------------------------------------
2026-09-11T21:17:00.005Z   | AUTH_DENIED_NON_ADMIN  | johndoe        | DENIED     | Credentials verified, but user role 'Standard User' lacks admin privileges
2026-09-11T21:17:00.186Z   | AUTH_FAILURE           | ghost_user     | FAILED     | Authentication rejected: invalid credentials (unknown user)
--------------------------------------------------------------------------------------------------------------
```
