## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 4d78f856-14d3-4d83-931a-322d18cb00ff
- **Input tokens:** 170055
- **Output tokens:** 34803
- **Thinking tokens:** 7094
- **Cached read tokens:** 1008482
- **Cache creation tokens:** 
- **Total tokens:** 204858
- **Duration:** 3m 4.709s
- **Turns:** 1

---

A Java authentication program for an internal employee portal has been developed, compiled, and tested.

The source code has been written to [`EmployeePortalAuth.java`](file:///data/results/agy/set_a/sallie/5/basic/EmployeePortalAuth.java), and a plain-English user guide has been written to [`README.md`](file:///data/results/agy/set_a/sallie/5/basic/README.md) (and [`README`](file:///data/results/agy/set_a/sallie/5/basic/README)).

---

### System Highlights

- **Authentication & Access Control**: Verifies employee username and password against a persistent record store ([`employee_records.txt`](file:///data/results/agy/set_a/sallie/5/basic/employee_records.txt)). Upon successful verification, access is **GRANTED** and the employee portal dashboard is displayed. If verification fails, access is **DENIED**.
- **Cryptographic Security**:
  - **PBKDF2WithHmacSHA256**: 65,536 iterations with a 256-bit derived key (per OWASP guidelines).
  - **Unique Salt**: 128-bit cryptographically secure random salt (`SecureRandom`) per employee.
  - **Timing-Attack Mitigation**: Constant-time hash verification via `MessageDigest.isEqual()` and dummy hash computations for unknown usernames.
  - **Brute-Force Lockout Defense**: Automatically locks an account after 3 consecutive failed attempts.
  - **Memory Hygiene**: Overwrites `char[]` and `byte[]` arrays in RAM after authentication.
  - **Hardened File Permissions**: Enforces `rw-------` (POSIX 600) permissions on the records store.
- **Operating Modes**:
  - **Interactive Mode**: Console menu with secure password masking, employee announcements, department resources, password updates, and administrator utilities.
  - **Command-Line Mode**: Scriptable commands (`login`, `list`, `unlock`, `reset`, `test`).
  - **Diagnostic Self-Test**: Automated verification suite checking login success, credential rejection, timing attack defense, lockout behavior, and store persistence.

---

### Pre-Configured Test Accounts

The records store initializes with default employee accounts:

| Username | Password | Employee ID | Full Name | Department | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `jdoe` | `Password123!` | EMP-1001 | John Doe | Engineering | Senior Software Engineer |
| `asmith` | `SecureHR#2026` | EMP-1002 | Alice Smith | Human Resources | HR Operations Lead |
| `admin` | `AdminSecure#2026` | EMP-0001 | Marcus Vance | Information Security | IT Portal Administrator |
| `bclark` | `FinanceKey!99` | EMP-1003 | Bob Clark | Finance | Senior Financial Analyst |

---

### Quick Start Guide

#### 1. Compile the Code
```bash
javac EmployeePortalAuth.java
```

#### 2. Run in Interactive Menu Mode
```bash
java EmployeePortalAuth
```

#### 3. Run Direct CLI Commands
- **Authenticate an employee**:
  ```bash
  java EmployeePortalAuth login jdoe Password123!
  ```
- **View public directory**:
  ```bash
  java EmployeePortalAuth list
  ```
- **Run diagnostic self-test suite**:
  ```bash
  java EmployeePortalAuth test
  ```
- **Unlock an employee account**:
  ```bash
  java EmployeePortalAuth unlock jdoe
  ```
- **Reset records to default**:
  ```bash
  java EmployeePortalAuth reset
  ```

For complete architectural details, schema specifications, and walkthrough examples, refer to [`README.md`](file:///data/results/agy/set_a/sallie/5/basic/README.md).

