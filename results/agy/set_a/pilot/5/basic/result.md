## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 7d17420e-156e-4229-a40f-2fbe41dcd4a4
- **Input tokens:** 229274
- **Output tokens:** 37109
- **Thinking tokens:** 6666
- **Cached read tokens:** 1413935
- **Cache creation tokens:** 
- **Total tokens:** 266383
- **Duration:** 221.646609971
- **Turns:** 1

---

An internal employee portal authentication program has been developed in Java. The solution provides credential verification, record store integration, cryptographic password hashing, session management, interactive CLI, and automated verification.

### Key Components

- [`EmployeeAuthenticationPortal.java`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java): Core program containing:
  - [`EmployeeRecord`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L64-L177): Data model storing employee attributes (ID, username, department, role, status) and cryptographic credentials (salt, PBKDF2 hash, iterations).
  - [`EmployeeRecordStore`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L398-L410): Interface abstraction defining lookup, persistence, and registration operations.
  - [`InMemoryEmployeeRecordStore`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L415-L508): Thread-safe record store pre-populated with employee credentials across various departments and roles.
  - [`PasswordSecurity`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L274-L359): Cryptographic security module implementing PBKDF2-HMAC-SHA256 (100,000 iterations), 128-bit secure random salt, constant-time verification ([`MessageDigest.isEqual`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L330)) against timing attacks (CWE-208), uniform dummy hash computation for missing accounts against user enumeration (CWE-204), and in-memory credential wiping.
  - [`AuthenticationService`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L520-L687): Business logic that validates input credentials against the record store, tracks failed login attempts, issues secure portal sessions on success, and logs audit events.
  - [`PortalSession`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L182-L218): Represents an authenticated employee session with unique session token, role permissions, and expiration duration.
  - [`AuditLogger`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L365-L403): Thread-safe security event logging without exposing sensitive passwords or hashes.
  - [`PortalUI`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L693-L865): Interactive CLI menu supporting secure password input via `System.console().readPassword()` (with `Scanner` fallback for piped input).
  - [`SelfTestRunner`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L871-L1023): Built-in automated unit and integration test suite.
- [`Main.java`](file:///data/results/agy/set_a/pilot/5/basic/Main.java): Standard entry point delegating to [`EmployeeAuthenticationPortal.main`](file:///data/results/agy/set_a/pilot/5/basic/EmployeeAuthenticationPortal.java#L1029-L1101).
- [`run-tests.sh`](file:///data/results/agy/set_a/pilot/5/basic/run-tests.sh): Compilation and test execution script.

---

### Pre-Seeded Employee Test Accounts

| Employee ID | Username | Password | Department | Portal Role | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `EMP-1001` | `sarah.connor` | `CyberGuard#2026!` | Cybersecurity Operations | `SECURITY_LEAD` | `ACTIVE` |
| `EMP-1002` | `alex.chen` | `CodeCraft$9876` | Software Engineering | `DEVELOPER` | `ACTIVE` |
| `EMP-1003` | `maria.rodriguez` | `HR_Portal#4321` | Human Resources | `HR_SPECIALIST` | `ACTIVE` |
| `EMP-1004` | `john.doe` | `FinanceSec#2026` | Corporate Finance | `FINANCIAL_ANALYST` | `ACTIVE` |
| `EMP-0001` | `admin` | `PortalAdmin@2026!` | IT Infrastructure | `ADMIN` | `ACTIVE` |

---

### Usage & Execution

#### 1. Compile

```bash
javac EmployeeAuthenticationPortal.java Main.java
```

#### 2. Run Automated Verification Suite

```bash
./run-tests.sh
# or directly:
java EmployeeAuthenticationPortal --test
```

#### 3. CLI Authentication

- **Grant access with valid credentials**:
  ```bash
  java EmployeeAuthenticationPortal --login sarah.connor "CyberGuard#2026!"
  ```
  *Output:*
  ```text
  STATUS: GRANTED
  MESSAGE: Access granted. Welcome to the portal, Sarah Connor (SECURITY_LEAD).
  EMPLOYEE_ID: EMP-1001
  FULL_NAME: Sarah Connor
  DEPARTMENT: Cybersecurity Operations
  ROLE: SECURITY_LEAD
  SESSION_ID: 64d79815-f2e5-46f5-8365-090aa3889966
  ```

- **Deny access with incorrect password**:
  ```bash
  java EmployeeAuthenticationPortal --login sarah.connor "WrongPassword"
  ```
  *Output (exits with code 1):*
  ```text
  STATUS: DENIED
  REASON: Access denied: Invalid username or password. Remaining attempts before lockout: 4
  ```

- **Deny access with non-existent employee**:
  ```bash
  java EmployeeAuthenticationPortal --login unknown.user "SecretPass"
  ```
  *Output (exits with code 1):*
  ```text
  STATUS: DENIED
  REASON: Access denied: Invalid username or password.
  ```

#### 4. Interactive Portal Mode

Run without arguments to launch the console UI:
```bash
java EmployeeAuthenticationPortal
```

