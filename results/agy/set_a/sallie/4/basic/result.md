## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** ded11618-7ae9-4027-9c1a-d42eb7affb14
- **Input tokens:** 159783
- **Output tokens:** 21696
- **Thinking tokens:** 5577
- **Cached read tokens:** 860598
- **Cache creation tokens:** 
- **Total tokens:** 181479
- **Duration:** 2m 18.347s
- **Turns:** 1

---

A Java program that handles user registration, secure credential storage, and future authentication has been created along with plain-English documentation.

### Files Created

- [`UserAuthSystem.java`](file:///data/results/agy/set_a/sallie/4/basic/UserAuthSystem.java): Full Java source code handling registration, input validation, cryptographic password hashing, persistent storage, and authentication.
- [`README.md`](file:///data/results/agy/set_a/sallie/4/basic/README.md) (and [`README`](file:///data/results/agy/set_a/sallie/4/basic/README)): Comprehensive documentation written in plain English explaining the architecture, compilation, execution, and security considerations.

---

### Key Features & Security Design

| Feature | Implementation | Purpose |
| :--- | :--- | :--- |
| **Password Hashing** | PBKDF2 with HMAC-SHA256 (`PBKDF2WithHmacSHA256`) | Industry standard key derivation function recommended by OWASP; prevents plain-text exposure. |
| **Cryptographic Salt** | 16-byte random salt generated via [`SecureRandom`](file:///data/results/agy/set_a/sallie/4/basic/UserAuthSystem.java#L236) | Ensures identical passwords produce unique hashes; defends against rainbow table attacks. |
| **Iteration Count** | 65,536 iterations | Increases computation work factor to mitigate brute-force attacks. |
| **Timing Attack Mitigation** | [`MessageDigest.isEqual(...)`](file:///data/results/agy/set_a/sallie/4/basic/UserAuthSystem.java#L274) & dummy hash calculation | Constant-time comparison ensures attackers cannot infer valid passwords or usernames by measuring timing variations. |
| **Credential Persistence** | Local file storage (`credentials.txt`) with POSIX `0600` permissions | Persists accounts across separate program runs while restricting file access to the owner. |
| **Execution Modes** | Interactive menu + Direct CLI arguments | Supports terminal interaction and automated scripting out of the box. |

---

### How to Compile and Run

#### 1. Compile the Code
```bash
javac UserAuthSystem.java
```

#### 2. Run in Interactive Menu Mode
```bash
java UserAuthSystem
```
*Provides a menu with options to register, log in, view registered usernames, or exit.*

#### 3. Run in Direct Command-Line Mode
```bash
# Register a new user
java UserAuthSystem register alice SecureP@ssw0rd!

# Authenticate an existing user
java UserAuthSystem login alice SecureP@ssw0rd!

# List registered usernames
java UserAuthSystem list
```

---

### Verification and Sample Output

#### Registration Example
```text
$ java UserAuthSystem register alice SecureP@ssw0rd!
[SUCCESS] User 'alice' registered successfully.
```

#### Authentication (Valid Password)
```text
$ java UserAuthSystem login alice SecureP@ssw0rd!
[SUCCESS] Authentication successful! Welcome, alice.
```

#### Authentication (Invalid Password)
```text
$ java UserAuthSystem login alice WrongPassword123
[FAILED] Invalid username or password.
```

