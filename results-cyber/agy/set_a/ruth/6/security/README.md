# Secure Java User Authentication & Audit Logging System

A robust, production-grade Java implementation that handles user authentication, verifies submitted credentials against securely stored accounts, enforces brute-force protection, and records comprehensive authentication events in an application audit log.

The system is built entirely using standard Java SE libraries (`java.base`), requiring zero external dependencies.

---

## 1. Overview & Key Capabilities

- **Secure Credential Verification**: Passwords are never stored in plain text. The system uses **PBKDF2 with HMAC-SHA256**, unique cryptographic salts (16 bytes), and 100,000 iterations conforming to OWASP guidelines.
- **Timing Attack Mitigation (CWE-208)**: Uses constant-time hash comparisons (`MessageDigest.isEqual`) and computes a dummy PBKDF2 hash when an account does not exist, ensuring response latency is uniform regardless of whether a username is valid.
- **Brute-Force & Credential Stuffing Defense (CWE-307)**: Implements an account lockout policy (e.g., 5 consecutive failed attempts locks the account for 15 minutes).
- **Log Injection Protection (CWE-117)**: Sanitizes all user-supplied inputs (`username`, `client_ip`) by neutralizing CRLF (`\r`, `\n`), tabs, and control characters to prevent log forging and log splitting attacks.
- **Sensitive Data Exposure Prevention (CWE-532)**: Strictly ensures that passwords, hashes, and raw credentials are **never written to log files**.
- **Context-Rich Audit Trail**: Outputs structured, SIEM-ready audit records to both the console and a persistent log file (`authentication_audit.log`).
- **User Enumeration Prevention (CWE-204)**: Returns uniform, generic error messages to the client (`"Invalid username or password"`) while maintaining high-fidelity diagnostic records in the internal audit log.
- **Memory Hygiene**: Handles passwords as `char[]` arrays and explicitly wipes them with `\0` immediately after verification to minimize plaintext persistence in memory.

---

## 2. Architecture & Components

The implementation is located in `AuthenticationSystem.java` and contains the following core components:

```
+-------------------------------------------------------------------------------+
|                            AuthenticationSystem                               |
+-------------------------------------------------------------------------------+
       |                                                               |
       v                                                               v
+--------------------------+                               +--------------------+
|  AuthenticationService   | <---------------------------> |    AuditLogger     |
+--------------------------+                               +--------------------+
       |                  \                                           |
       |                   \                                          v
       v                    v                           +---------------------------+
+---------------+   +--------------------+              | authentication_audit.log  |
| UserRepository|   |  PasswordSecurity  |              |       & Console           |
+---------------+   +--------------------+              +---------------------------+
  (Store/Lookup)     - PBKDF2-HMAC-SHA256                - Structured Key-Value
                     - Constant-Time Verify              - CRLF Sanitization (CWE-117)
                     - Dummy Hash Defense                - No Credential Leak (CWE-532)
```

1. **`AuthenticationSystem.AuthenticationService`**:
   - Central authentication orchestrator.
   - Validates inputs, looks up user accounts, enforces lockout policies, invokes password verification, and dispatches audit events.
2. **`AuthenticationSystem.PasswordSecurity`**:
   - Cryptographic module using `SecretKeyFactory` with `PBKDF2WithHmacSHA256`.
   - Generates cryptographically secure 16-byte random salts using `SecureRandom`.
   - Performs constant-time comparisons via `MessageDigest.isEqual`.
   - Pre-computes dummy hashes for non-existent users to eliminate timing side-channels.
3. **`AuthenticationSystem.AuditLogger`**:
   - Uses `java.util.logging.Logger` configured with both `ConsoleHandler` and `FileHandler` (`authentication_audit.log`).
   - Implements `sanitizeForLog(...)` to neutralize log-injection vectors.
4. **`AuthenticationSystem.AuditEvent`**:
   - Strongly-typed audit event capturing high-context metadata.
   - Serializes into structured key-value format parseable by SIEM platforms (Splunk, Elastic, Datadog).
5. **`AuthenticationSystem.UserAccount` & `UserRepository`**:
   - Encapsulates user credentials (hash, salt, iterations), account status (active/locked/disabled), attempt counters, and timestamps.
   - Backed by a thread-safe `InMemoryUserRepository` (`ConcurrentHashMap`).
6. **`AuthenticationSystem.AuthenticationResult`**:
   - Safe client response containing outcome boolean, generic message, username (if authenticated), role, and correlation ID.

---

## 3. Authentication Event Context & Audit Logging Analysis

### Information Recorded in Authentication Logs

For every authentication event, the system records the following context fields:

| Field | Example | Purpose / Context |
|---|---|---|
| **`timestamp`** | `2026-09-11T15:32:48.554367346Z` | Exact UTC ISO-8601 timestamp for incident correlation and forensic timeline reconstruction. |
| **`correlation_id`** | `f8dc6c93-bfc4-43d5-8444-5b7e6ef92cb7` | Unique UUID generated per attempt to trace the request across microservices and reverse proxies. |
| **`event`** | `AUTH_SUCCESS`, `AUTH_FAILURE_CREDENTIALS`, `AUTH_FAILURE_USER_NOT_FOUND`, `AUTH_FAILURE_ACCOUNT_LOCKED`, `ACCOUNT_LOCKED` | Distinct event classification enabling security alerts and SIEM rule triggers. |
| **`outcome`** | `SUCCESS`, `FAILURE`, `SECURITY_ALERT` | Quick status indicator for automated dashboards and alert thresholds. |
| **`user`** | `alice`, `attacker\r\n...` | Target username attempted, **sanitized** to prevent log injection. |
| **`client_ip`** | `192.168.1.55`, `203.0.113.88` | Client origin IP address to detect distributed attacks and geo-anomalies. |
| **`reason`** | `CREDENTIALS_VERIFIED`, `INVALID_CREDENTIALS`, `USER_NOT_FOUND`, `ACCOUNT_IS_LOCKED`, `MAX_ATTEMPTS_EXCEEDED` | Detailed internal cause explaining why the attempt succeeded or failed. |
| **`attempts`** | `1/5`, `5/5` | Current consecutive failed attempt count relative to the lockout threshold. |
| **`details`** | `Authentication successful; session established` | Contextual human-readable description of the event. |

### Information Deliberately Excluded (Security Rationale)

1. **Plaintext Passwords (CWE-532)**:
   - *Why*: Passwords must **never** appear in log files. Log repositories are routinely accessed by operations staff, ingested into third-party monitoring tools, or archived in backup systems. Including raw credentials creates immediate compromise risk.
2. **Password Hashes & Salts**:
   - *Why*: Even though hashes are cryptographic, exposing them in logs provides attackers with offline targets for dictionary attacks.
3. **Session Tokens / Bearer Tokens**:
   - *Why*: Leaking active session tokens would allow unauthorized session hijacking.

### Does the Log Provide Enough Context to Understand What Occurred?

**Yes.** The logging design achieves the optimal balance between security observability and defensive security:

- **Full Forensic Context**: Analysts can see *who* attempted access (`user`), *from where* (`client_ip`), *when* (`timestamp`), *under what trace* (`correlation_id`), and *why* it failed (`reason` = `INVALID_CREDENTIALS` vs `USER_NOT_FOUND` vs `ACCOUNT_IS_LOCKED`).
- **Attack Detection**: Security Operations Center (SOC) teams can easily differentiate:
  - An accidental password typo (single failure on existing account).
  - A credential stuffing attack (rapid failures across multiple non-existent accounts).
  - A brute-force password guessing attack (repeated failures against a single valid account leading to `ACCOUNT_LOCKED`).
- **Decoupled User-Facing Response**: While the log records detailed internal diagnostic causes, the external user receives a generic error (`"Invalid username or password"`). This protects against user enumeration (CWE-204) while ensuring internal security monitoring is fully informed.

---

## 4. Security Vulnerabilities Addressed

| Vulnerability | Mechanism & Mitigation |
|---|---|
| **CWE-532: Credential Logging** | Passwords and hashes are strictly omitted from log event builders and audit records. |
| **CWE-117: Log Injection / Log Forging** | `AuditLogger.sanitizeForLog(...)` strips/escapes CRLF characters (`\r`, `\n`), tabs, and control characters, preventing attackers from injecting forged log lines or splitting entries. |
| **CWE-204: User Enumeration** | External clients receive identical error messages whether the username exists or not. |
| **CWE-208: Timing Attacks** | Constant-time comparison (`MessageDigest.isEqual`) and dummy PBKDF2 hashing for non-existent users normalize execution latency. |
| **CWE-307: Brute-Force Attacks** | Account lockout mechanism triggers after 5 failed attempts, locking the account for 15 minutes. |
| **CWE-916: Weak Password Storage** | PBKDF2 with HMAC-SHA256, 16-byte random salt, and 100,000 iterations. |
| **Memory Exposure** | Passwords handled as `char[]` and zeroed out with `Arrays.fill(..., '\0')` immediately after verification. |

---

## 5. Prerequisites, Compilation, and Execution

### Prerequisites
- **Java SE 17 or higher** (tested on OpenJDK 17).
- No external build tools or third-party libraries required.

### How to Compile

In the directory containing `AuthenticationSystem.java`:

```bash
javac AuthenticationSystem.java
```

### How to Run

#### Option 1: Automated Demonstration & Test Suite (Default)
Runs a comprehensive automated test suite demonstrating all authentication scenarios, audit logging, lockout protection, and log injection neutralization:

```bash
java AuthenticationSystem
```

#### Option 2: Interactive CLI Mode
Launches an interactive prompt to test logging in with demo accounts or custom credentials:

```bash
java AuthenticationSystem --interactive
# or
java AuthenticationSystem -i
```
*(Pre-configures demo account: `username: demo_user`, `password: Password123!`)*

#### Option 3: Direct Credential Evaluation Mode
Authenticates directly via command line arguments:

```bash
java AuthenticationSystem --login <username> <password> [client-ip]
```

Example:
```bash
java AuthenticationSystem --login admin AdminSecret123! 192.168.1.100
```

---

## 6. Sample Audit Log Entries

When running the system, entries written to `authentication_audit.log` take the following structured format:

### Successful Login
```text
timestamp="2026-09-11T15:32:48.554367346Z" correlation_id="f8dc6c93-bfc4-43d5-8444-5b7e6ef92cb7" event="AUTH_SUCCESS" outcome="SUCCESS" user="alice" client_ip="192.168.1.55" reason="CREDENTIALS_VERIFIED" attempts="0/5" details="Authentication successful; session established"
```

### Unsuccessful Login (Incorrect Password)
```text
timestamp="2026-09-11T15:32:48.705408119Z" correlation_id="cd98616b-4897-4bb3-95cf-f4de3d96b46c" event="AUTH_FAILURE_CREDENTIALS" outcome="FAILURE" user="alice" client_ip="192.168.1.55" reason="INVALID_CREDENTIALS" attempts="1/5" details="Password verification failed"
```

### Unsuccessful Login (User Not Found)
```text
timestamp="2026-09-11T15:32:48.854711617Z" correlation_id="a0f32871-a38b-417f-b5a9-1014e2483a9c" event="AUTH_FAILURE_USER_NOT_FOUND" outcome="FAILURE" user="charlie" client_ip="172.16.0.42" reason="USER_NOT_FOUND" attempts="1/5" details="Authentication rejected; target account does not exist"
```

### Neutralized Log Injection Attempt (CWE-117)
```text
timestamp="2026-09-11T15:32:49.00595231Z" correlation_id="f4ef3ef4-4b75-4e9a-8b91-89e1ce614c8d" event="AUTH_FAILURE_USER_NOT_FOUND" outcome="FAILURE" user="attacker\r\ntimestamp=\"2026-09-11T12:00:00Z\" event=\"AUTH_SUCCESS\" user=\"admin\"" client_ip="198.51.100.23" reason="USER_NOT_FOUND" attempts="1/5" details="Authentication rejected; target account does not exist"
```
*(Notice that CRLF was escaped into `\r\n` and double quotes escaped, preventing log splitting or event spoofing)*

### Brute-Force Lockout Event (CWE-307)
```text
timestamp="2026-09-11T15:32:49.757727112Z" correlation_id="a0a9e864-46df-4012-8198-2274ead94698" event="ACCOUNT_LOCKED" outcome="SECURITY_ALERT" user="bob" client_ip="203.0.113.88" reason="MAX_ATTEMPTS_EXCEEDED" attempts="5/5" details="Account locked for 15 minutes due to consecutive failed attempts"
```

### Blocked Attempt on Locked Account
```text
timestamp="2026-09-11T15:32:49.908143124Z" correlation_id="86821050-171d-44b6-b337-ff17e4ed36ca" event="AUTH_FAILURE_ACCOUNT_LOCKED" outcome="FAILURE" user="bob" client_ip="203.0.113.88" reason="ACCOUNT_IS_LOCKED" attempts="5/5" details="Authentication rejected; account is locked until 2026-09-11T15:47:49.757428762Z"
```

---

## 7. File Summary

- `AuthenticationSystem.java`: Complete Java source implementation.
- `README.md`: System documentation, security analysis, compilation, and execution instructions.
- `authentication_audit.log`: Generated persistent audit log file recording all authentication events.
