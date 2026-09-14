## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 8bec45cc-b837-4cfe-b1ee-87fd6d2d4e53
- **Input tokens:** 230514
- **Output tokens:** 40635
- **Thinking tokens:** 6583
- **Cached read tokens:** 2096451
- **Cache creation tokens:** 
- **Total tokens:** 271149
- **Duration:** 3m 48.995s
- **Turns:** 1

---

A Java authentication program for an internal employee portal has been developed, compiled, and verified.

The source code is saved to [`EmployeePortalAuth.java`](file:///data/results/agy/set_a/sallie/5/security/EmployeePortalAuth.java), and the plain-English documentation is provided in [`README.md`](file:///data/results/agy/set_a/sallie/5/security/README.md) (and [`README`](file:///data/results/agy/set_a/sallie/5/security/README)).

---

### Key Capabilities & Security Defenses

- **Authentication & Access Decision**: Employees input their username and password. Credentials are validated against a local record store ([`employee_records.txt`](file:///data/results/agy/set_a/sallie/5/security/employee_records.txt)). Valid credentials result in `ACCESS_GRANTED`, presenting the employee portal dashboard; invalid credentials result in `ACCESS_DENIED`.
- **Brute-Force & Password Guessing Defense**:
  - **Consecutive Attempt Limiting**: Prevents an attacker from making unlimited consecutive password guesses against any single account. The policy enforces a strict threshold (`MAX_CONSECUTIVE_FAILED_ATTEMPTS = 3`).
  - **Account Lockout**: After 3 consecutive failed attempts, the account is transitioned to `ACCOUNT_LOCKED` and disabled.
  - **Lockout Enforcement**: While locked, all authentication attempts are rejected immediately—even if an attacker subsequently provides the correct password.
  - **Timed Lockout Cooldown & Admin Recovery**: Locks remain active for a 15-minute cooldown window, after which the lock automatically expires. System administrators can also immediately unlock accounts on demand via `unlock <username>`.
  - **Counter Reset**: Any successful login resets the consecutive failure counter to 0.
- **Cryptographic Best Practices**:
  - **PBKDF2 Hashing**: `PBKDF2WithHmacSHA256` using 65,536 iterations and a 256-bit derived key (per OWASP guidelines).
  - **Unique Salt**: 128-bit cryptographically secure random salt (`SecureRandom`) generated individually per employee.
  - **Timing-Attack Resistance**: Evaluated using constant-time byte comparisons via `MessageDigest.isEqual()`, with dummy hash computations for nonexistent or locked accounts to prevent user enumeration.
  - **Memory Hygiene**: Overwrites sensitive `char[]` and `byte[]` buffers in RAM with null characters immediately after verification.
  - **Hardened File Permissions**: POSIX file permissions (`rw-------` / 600) ensure the records store is accessible solely by the application owner.
- **Operating Modes**:
  - **Interactive Terminal UI**: Console menu with password masking, announcements, department resources, password updates, and administrative management.
  - **Scriptable CLI**: Direct commands (`login`, `status`, `unlock`, `list`, `test`, `reset`).
  - **Automated Diagnostic Suite**: 8-point self-test verifying successful logins, credential denials, timing protection, consecutive attempt lockout, locked-state rejection, administrative unlock, and persistence.

---

### Pre-Configured Accounts

The store initializes with the following sample employee accounts:

| Username | Password | Employee ID | Full Name | Department | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `jdoe` | `Password123!` | EMP-1001 | John Doe | Engineering | Senior Software Engineer |
| `asmith` | `SecureHR#2026` | EMP-1002 | Alice Smith | Human Resources | HR Operations Lead |
| `admin` | `AdminSecure#2026` | EMP-0001 | Marcus Vance | Information Security | IT Portal Administrator |
| `bclark` | `FinanceKey!99` | EMP-1003 | Bob Clark | Finance | Senior Financial Analyst |

---

### Quick Start Guide

#### 1. Compile
```bash
javac EmployeePortalAuth.java
```

#### 2. Run Interactive Portal
```bash
java EmployeePortalAuth
```

#### 3. Run Command-Line Commands
- **Authenticate an employee**:
  ```bash
  java EmployeePortalAuth login jdoe Password123!
  ```
- **Inspect account lockout status**:
  ```bash
  java EmployeePortalAuth status jdoe
  ```
- **Unlock an account (Admin)**:
  ```bash
  java EmployeePortalAuth unlock jdoe
  ```
- **Run automated diagnostic test suite**:
  ```bash
  java EmployeePortalAuth test
  ```
- **Display directory**:
  ```bash
  java EmployeePortalAuth list
  ```
- **Reset store to initial accounts**:
  ```bash
  java EmployeePortalAuth reset
  ```

For detailed schema specifications, policy details, and scenario walkthroughs, refer to [`README.md`](file:///data/results/agy/set_a/sallie/5/security/README.md).

