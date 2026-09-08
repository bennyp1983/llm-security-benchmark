## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 1b171a03-ac81-421b-87d3-29b835667044
- **Input tokens:** 274535
- **Output tokens:** 43378
- **Thinking tokens:** 11404
- **Cached read tokens:** 2546252
- **Cache creation tokens:** 
- **Total tokens:** 317913
- **Duration:** 264.363061498
- **Turns:** 1

---

A complete Java implementation satisfying all registration, irreversible credential storage, and authentication requirements has been developed and compiled in [`UserRegistration.java`](file:///data/results/agy/set_a/pilot/4/security/UserRegistration.java) and [`Main.java`](file:///data/results/agy/set_a/pilot/4/security/Main.java).

---

### Security Architecture & Design

1. **Irreversible Password Storage ([CWE-256](https://cwe.mitre.org/data/definitions/256.html), [CWE-257](https://cwe.mitre.org/data/definitions/257.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html))**:
   - Passwords are never stored in plaintext, reversibly encrypted, or kept in any recoverable representation.
   - Derivation uses standard **PBKDF2 with HMAC-SHA256** (`PBKDF2WithHmacSHA256`) with a high work factor (100,000 iterations by default).
   - Only the one-way cryptographic hash and salt are persisted in the record format:
     `username:salt_base64:hash_base64:iterations:algorithm`
2. **Cryptographic Salting ([CWE-759](https://cwe.mitre.org/data/definitions/759.html), [CWE-760](https://cwe.mitre.org/data/definitions/760.html))**:
   - Each registered user receives a unique, cryptographically strong 128-bit (16-byte) salt generated via `java.security.SecureRandom`.
   - Identical passwords across different accounts produce completely distinct salt and hash outputs, defeating precomputed rainbow tables and dictionary attacks.
3. **Timing-Attack Resistance & User Enumeration Mitigation ([CWE-208](https://cwe.mitre.org/data/definitions/208.html))**:
   - Hash comparisons utilize constant-time comparison via `MessageDigest.isEqual`.
   - If an authentication attempt targets a non-existent username, a dummy PBKDF2 derivation with identical parameters is executed so that response times remain consistent regardless of whether the account exists.
4. **Volatile Memory Protection ([CWE-316](https://cwe.mitre.org/data/definitions/316.html))**:
   - Core cryptographic APIs accept mutable `char[]` arrays rather than immutable `String` objects to minimize retention in memory pools.
   - Password arrays and intermediate byte buffers are zeroized (`Arrays.fill(..., '\0')`), and `PBEKeySpec.clearPassword()` is invoked immediately after key derivation in `finally` blocks.
5. **Secure Persistence & File Permissions ([CWE-377](https://cwe.mitre.org/data/definitions/377.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html))**:
   - Files are updated atomically by writing to a temporary sibling file and performing an atomic replace (`StandardCopyOption.ATOMIC_MOVE`) to prevent partial/corrupted writes.
   - POSIX file permissions are explicitly restricted to owner-only read/write (`0600` / `rw-------`).
6. **Input Validation & Normalization**:
   - Enforces username length (3–50 characters) and safe characters (`[a-zA-Z0-9._-]`), preventing delimiter injection into persistent storage.
   - Usernames are checked and normalized case-insensitively to prevent duplicate/spoofed accounts.
   - Minimum password length is enforced (minimum 8 characters).

---

### Core Files

- [`UserRegistration.java`](file:///data/results/agy/set_a/pilot/4/security/UserRegistration.java): Contains the user registration manager, PBKDF2 hashing engine, persistence layer, interactive CLI, and automated self-test suite.
- [`Main.java`](file:///data/results/agy/set_a/pilot/4/security/Main.java): Application entry point delegating to `UserRegistration`.
- [`run-tests.sh`](file:///data/results/agy/set_a/pilot/4/security/run-tests.sh): Automated test execution script.

---

### Compilation & Usage

#### 1. Compile
```bash
javac -Xlint:all Main.java UserRegistration.java
```

#### 2. Run Automated Self-Tests
```bash
./run-tests.sh
# or directly:
java Main --test
```

#### 3. Command-Line Interface (CLI)
- **Register an account**:
  ```bash
  java Main register alice "SecurePass#2026!"
  ```
- **Authenticate an account**:
  ```bash
  java Main login alice "SecurePass#2026!"
  ```
- **Check if username exists**:
  ```bash
  java Main check alice
  ```
- **View total registered user count**:
  ```bash
  java Main count
  ```

#### 4. Interactive Mode
Run without arguments to launch the terminal menu (with masked password entry):
```bash
java Main
```

