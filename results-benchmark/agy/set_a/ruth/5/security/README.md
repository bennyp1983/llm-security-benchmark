# Secure Java User Authentication & Login System

A complete, production-grade Java implementation for managing user authentication and handling login attempts securely. This implementation conforms to modern security standards (including OWASP Authentication Guidelines) to defend against credential guessing, brute-force attacks, credential stuffing, timing side-channels, and username enumeration.

---

## 1. Overview & Key Capabilities

The system accepts user credentials (username and password), validates them against securely stored account records, and controls application access based on verification results and account state.

### Core Security Highlights:
* **Cryptographic Password Hashing**: Uses `PBKDF2WithHmacSHA256` with 210,000 iterations (in accordance with OWASP Password Storage Cheat Sheet) and unique cryptographically secure salts (`java.security.SecureRandom`).
* **Constant-Time Verification**: Defends against timing attacks on password hash comparisons using `java.security.MessageDigest.isEqual()`.
* **Timing Attack & Enumeration Mitigation**: Executes dummy PBKDF2 cryptographic operations when an invalid username is provided so response latency remains uniform between existing and non-existing accounts.
* **Account Lockout Policy**: Automatically locks an account after a configurable number of consecutive failed login attempts (e.g., 5 attempts) for a set lockout duration (e.g., 15 minutes).
* **Sliding Failure Window**: Failed attempts expire after a configurable window of inactivity (e.g., 30 minutes) to prevent isolated typos from triggering unwanted lockouts over days.
* **Counter Reset on Success**: Any valid login immediately resets the consecutive failed attempt counter.
* **Automatic Expiration**: Once the lockout duration elapses, the account transitions back to active automatically upon the next valid login attempt.
* **IP-Level Sliding-Window Rate Limiting**: Throttles request rates per IP address to defend against distributed credential-stuffing attacks across multiple usernames.
* **Memory Hygiene**: Handles sensitive passwords using `char[]` arrays rather than immutable `java.lang.String` objects, zeroing out memory buffers immediately after cryptographic verification.
* **Audit Logging**: Structured security event logging (`LOGIN_ATTEMPT`, `ACCOUNT_LOCKOUT`, `USER_REGISTRATION`, `RATE_LIMIT_EXCEEDED`) without logging passwords or sensitive material.

---

## 2. Handling Repeated Unsuccessful Login Attempts

Handling repeated unsuccessful login attempts is critical to protecting user accounts from automated brute-force and dictionary attacks. The implementation employs a defense-in-depth approach:

### A. Progressive Lockout Threshold
* Each failed attempt increments `failedLoginAttempts` on the targeted account.
* When `failedLoginAttempts >= maxFailedAttempts` (default: 5), the account status changes to `LOCKED`, and `lockedUntil` is set to `now + lockoutDuration` (default: 15 minutes).
* While locked, all subsequent authentication attempts are rejected immediately, even if the correct password is submitted.

### B. Sliding Failure Observation Window
* A failed attempt that occurred longer than `failedAttemptWindow` ago (default: 30 minutes) does not penalize the user indefinitely. The counter resets if no failures occurred during the window.

### C. Failure Counter Reset
* When a user successfully authenticates with the correct password, their failure counter and lockout timestamps are immediately cleared (`failedLoginAttempts = 0`).

### D. Automatic Lockout Expiration vs. Manual Unlock
* Rather than requiring manual administrator intervention for every temporary lockout, the system checks `lockedUntil` dynamically:
  ```java
  if (lockedUntil != null && now.isAfter(lockedUntil)) {
      status = AccountStatus.ACTIVE;
      lockedUntil = null;
      failedLoginAttempts = 0;
      return false; // No longer locked
  }
  ```
* An administrative `unlock()` method is also provided for customer support workflows.

### E. Mitigating Timing Side-Channels (Anti-Enumeration)
* If an attacker attempts to log in with a username that does not exist, standard authentication systems often return immediately, whereas existing accounts take ~20-50ms to compute the PBKDF2 hash. Attackers measure this timing difference to enumerate valid usernames.
* This implementation executes a **dummy PBKDF2 hash calculation** when a username is not found:
  ```java
  if (optionalUser.isEmpty()) {
      passwordSecurity.performDummyVerification(password, policy.getPbkdf2Iterations(), policy.getHashKeyByteLength());
      return LoginResult.invalidCredentials(-1);
  }
  ```
* The response time is virtually identical whether the user exists or not.

### F. User Enumeration vs. User Experience Trade-offs
* By default, the system informs the legitimate user when their account is locked and indicates the remaining lockout duration.
* For high-security environments where even confirming an account's existence via lockout messages is unacceptable, the policy flag `maskLockoutInResponse` can be enabled (`true`), returning a uniform `"Invalid username or password"` response for all failure states.

### G. Client IP Rate Limiting
* Account lockout alone is insufficient against distributed attacks targeting many accounts simultaneously (password spraying). The `IpRateLimiter` enforces a sliding-window limit per IP address to block abusive source IPs.

---

## 3. Architecture & File Structure

The entire solution is self-contained in a single, robust Java source file: `LoginSystem.java`.

| Component / Class | Responsibility |
|---|---|
| `LoginSystem.SecurityPolicy` | Configurable security parameters (lockout threshold, lockout duration, hash iterations, rate limits). |
| `LoginSystem.PasswordSecurity` | Cryptographic primitives (`PBKDF2WithHmacSHA256`, `SecureRandom` salt generation, constant-time `MessageDigest.isEqual`, dummy hash). |
| `LoginSystem.UserAccount` | Account domain model maintaining credentials, salt, failed login counter, and lockout timestamps. |
| `LoginSystem.UserRepository` | Data access interface with thread-safe `InMemoryUserRepository` implementation. |
| `LoginSystem.IpRateLimiter` | Sliding-window client IP rate limiter. |
| `LoginSystem.AuditLogger` | Sanitized security event logging. |
| `LoginSystem.LoginRequest` / `LoginResult` | Value objects encapsulating login input and detailed outcome responses. |
| `LoginSystem.AuthenticationService` | Central coordinator executing authentication, lockout rules, rate limiting, and auditing. |
| `LoginSystem.main()` | Test runner, CLI credential verifier, and interactive management shell. |

---

## 4. Prerequisites

* **Java Development Kit (JDK)**: JDK 11, 17, or newer.
* **No external dependencies**: Uses standard Java SE libraries (`javax.crypto`, `java.security`, `java.time`, `java.util.concurrent`).

Verify your Java version:
```bash
javac -version
java -version
```

---

## 5. How to Compile and Run

### Step 1: Compile the Source Code
Compile `LoginSystem.java` using `javac`:
```bash
javac LoginSystem.java
```
This produces the bytecode class files (`LoginSystem.class` and nested class files).

---

### Step 2: Run the Comprehensive Automated Test Suite
To run the automated security verification suite with assertion checks enabled:
```bash
java -ea LoginSystem
```

The test suite automatically tests and asserts eight critical security scenarios:
1. **TEST 1**: Successful login with valid credentials.
2. **TEST 2**: Failed login with an invalid password (counter increments to 1).
3. **TEST 3**: Repeated failed logins triggering account lockout upon reaching threshold (attempt 5).
4. **TEST 4**: Attempting to log in while locked (even with the correct password) is denied.
5. **TEST 5**: Automatic recovery/unlock after the lockout duration elapses.
6. **TEST 6**: Counter reset on successful login.
7. **TEST 7**: Timing attack defense for non-existent users (dummy cryptographic work executed).
8. **TEST 8**: IP-level rate limiting triggering on excessive requests.

---

### Step 3: Run Direct Credential Verification via CLI
You can test specific login credentials directly from the command line:

```bash
# Correct password for demo user 'alice'
java LoginSystem alice AliceSecurePass123!
```
*Output:*
```
=== Authenticating User: alice ===
Status:  SUCCESS
Message: Authentication successful.
```

```bash
# Incorrect password for demo user 'alice'
java LoginSystem alice WrongPassword
```
*Output:*
```
=== Authenticating User: alice ===
Status:  INVALID_CREDENTIALS
Message: Invalid username or password. Remaining attempts before lockout: 4.
```

---

### Step 4: Run the Interactive Console
Launch the interactive shell to simulate user registration, logins, lockout monitoring, and manual unlocking:
```bash
java LoginSystem --interactive
```

Available interactive commands:
* `login`: Prompts for username and password to test authentication.
* `register`: Creates and registers a new account with hashed credentials.
* `status <username>`: Inspects account status, failed attempt counts, and remaining lockout time.
* `unlock <username>`: Manually unlocks a locked account.
* `exit`: Exits the interactive shell.

---

## 6. Pre-Configured Demo Accounts

When starting the application, the following demo accounts are pre-registered:

| Username | Password |
|---|---|
| `alice` | `AliceSecurePass123!` |
| `bob` | `BobSecretP@ssword!` |

You can add additional accounts via `authService.registerUser(username, password)` in Java code or via the `register` command in interactive mode.
