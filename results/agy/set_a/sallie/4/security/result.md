## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 8a21e73c-9868-4f31-a76b-05217292d638
- **Input tokens:** 200737
- **Output tokens:** 26534
- **Thinking tokens:** 6158
- **Cached read tokens:** 1360894
- **Cache creation tokens:** 
- **Total tokens:** 227271
- **Duration:** 3m 4.547s
- **Turns:** 1

---

A complete Java user registration and authentication application has been developed and verified.

### Files Created

- [`UserAuthSystem.java`](file:///data/results/agy/set_a/sallie/4/security/UserAuthSystem.java): Full Java source code handling account registration, persistent credential storage, non-recoverable password hashing, and user authentication.
- [`README.md`](file:///data/results/agy/set_a/sallie/4/security/README.md) (and plain text [`README`](file:///data/results/agy/set_a/sallie/4/security/README)): Comprehensive documentation written in plain English explaining the security architecture, how one-way hashing works, compilation, and usage walkthroughs.

---

### Security Architecture: Non-Recoverable Passwords

The system guarantees that the original password **cannot be retrieved or reconstructed from storage**:

| Security Mechanism | Technical Implementation | Purpose & Security Guarantee |
| :--- | :--- | :--- |
| **Non-Recoverable Hashing** | PBKDF2 with HMAC-SHA256 (`PBKDF2WithHmacSHA256`) | Passwords are never encrypted (which is reversible); they are processed using a one-way mathematical function with pre-image resistance. Reversing the hash back to the original password is computationally infeasible. |
| **Per-User Cryptographic Salt** | 16-byte (128-bit) random salt generated via [`SecureRandom`](file:///data/results/agy/set_a/sallie/4/security/UserAuthSystem.java#L282) | Prevents rainbow table attacks; two accounts with identical passwords have completely distinct hashes. |
| **High Work Factor** | 100,000 HMAC-SHA256 iterations | Exponentially increases the computational cost for offline brute-force and dictionary attacks. |
| **Timing Attack Mitigation** | Constant-time comparison (`MessageDigest.isEqual`) & dummy hash calculation | Prevents attackers from measuring response time variations to deduce password characters or harvest valid usernames. |
| **In-Memory Hygiene** | Sensitive passwords handled via `char[]` and zeroed out | Password character arrays and key specifications are immediately wiped (`Arrays.fill(..., '\0')`) to prevent retention in RAM. |
| **Persistent Storage & File Security** | Local storage (`credentials.txt`) with POSIX `0600` permissions | Persists accounts across program runs while restricting file access solely to the file owner. |

---

### How to Compile and Run

#### 1. Compile
```bash
javac UserAuthSystem.java
```

#### 2. Interactive Menu Mode
Run without arguments to launch the interactive terminal interface:
```bash
java UserAuthSystem
```
*Provides a menu to register new accounts (with masked input and password confirmation), authenticate, or list registered usernames.*

#### 3. Direct Command-Line Mode
For scripting and terminal automation:
```bash
# Register a new account
java UserAuthSystem register alice "SecurePass123!"

# Authenticate an existing account
java UserAuthSystem login alice "SecurePass123!"

# List registered usernames
java UserAuthSystem list
```

---

### Example Verification

```bash
# Register user 'alice'
$ java UserAuthSystem register alice "SecurePass123!"
[SUCCESS] User 'alice' registered successfully.

# Authenticate with valid password
$ java UserAuthSystem login alice "SecurePass123!"
[SUCCESS] Authentication successful! Welcome, alice.

# Authenticate with incorrect password
$ java UserAuthSystem login alice "WrongPassword"
[FAILED] Invalid username or password.

# Stored credential record (credentials.txt) - only salt and hash stored:
alice:w6QatkE4p8WU6na5rWHZwg==:100000:N614bkSS2t6qAuw1Z/CssTw0yqXdNpiVFSy7IyI2vHw=
```

