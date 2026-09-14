# Secure User Account Registration and Authentication in Java (JDBC)

A robust, enterprise-grade Java implementation for securely registering new user accounts and authenticating credentials against an SQL database using an active JDBC `Connection`.

---

## Table of Contents

- [Overview](#overview)
- [Password Handling & Security Architecture](#password-handling--security-architecture)
  - [1. Before Storage (In-Memory Security & Hygiene)](#1-before-storage-in-memory-security--hygiene)
  - [2. During Storage (Hashing, Salting & Storage Design)](#2-during-storage-hashing-salting--storage-design)
  - [3. During Authentication (Side-Channel & Timing Protections)](#3-during-authentication-side-channel--timing-protections)
  - [4. Database Security & Injection Prevention](#4-database-security--injection-prevention)
- [Database Schema](#database-schema)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [How to Compile and Run](#how-to-compile-and-run)
  - [Option 1: Using Standard `javac` and `java` (Recommended)](#option-1-using-standard-javac-and-java-recommended)
  - [Option 2: Using Maven](#option-2-using-maven)
  - [Option 3: Using the Provided Shell Script](#option-3-using-the-provided-shell-script)
- [Integrating with External Databases (PostgreSQL, MySQL, etc.)](#integrating-with-external-databases-postgresql-mysql-etc)
- [API Reference & Code Examples](#api-reference--code-examples)

---

## Overview

The `UserAccountService` class handles user account registration and authentication over any standard SQL database. It assumes that an active JDBC `java.sql.Connection` is already established and passed into its service methods.

Key responsibilities:
- Creating the necessary database schema (`users` table).
- Validating incoming user credentials (username and password).
- Salting and hashing passwords using modern cryptographic standards.
- Persisting account credentials using parameterized SQL queries.
- Authenticating users while shielding against timing side-channel attacks and user enumeration.
- Managing memory lifecycle to eliminate plaintext password traces from JVM heap memory.

---

## Password Handling & Security Architecture

Handling user passwords securely requires defense-in-depth across the entire lifecycle of the credential.

### 1. Before Storage (In-Memory Security & Hygiene)

- **`char[]` over `java.lang.String`:**
  - Java `String` objects are immutable. Once created, string contents reside in the JVM heap and the String intern pool until garbage collected. Even after GC, the plaintext characters remain in memory until the heap blocks are overwritten.
  - In the event of a memory dump, core dump, debugger inspection, or OS swap to disk, plaintext passwords in `String` form can be extracted by an adversary.
  - The service accepts passwords as mutable `char[]` arrays (`registerUser(conn, username, char[] password)`). This allows the application to explicitly zero out the memory immediately after the hash is derived:
    ```java
    Arrays.fill(password, '\0');
    ```
- **Clearing Cryptographic Key Spec Buffers:**
  - Java's `javax.crypto.spec.PBEKeySpec` creates an internal clone of the password `char[]`.
  - The service executes `spec.clearPassword()` inside a `finally` block to guarantee that the key spec's internal memory buffer is wiped, even if an unexpected exception occurs during key derivation.
- **Strict Input Validation & DoS Mitigation:**
  - **Username:** Checked against `^[a-zA-Z0-9_.@-]{3,64}$` to prevent control-character injection and malformed identifiers.
  - **Password Length Bounds:** Minimum length of 8 characters (complying with NIST SP 800-63B guidelines) and maximum length of 128 characters. The upper bound protects against Algorithmic Complexity / Denial of Service (DoS) attacks where an attacker submits arbitrarily large payloads (e.g., 10MB strings) to exhaust server CPU during PBKDF2 key stretching.

### 2. During Storage (Hashing, Salting & Storage Design)

- **Key Derivation Function (PBKDF2-HMAC-SHA512):**
  - Plaintext passwords and fast cryptographic hash functions (such as MD5, SHA-1, or unsalted SHA-256) are never used. Fast hash algorithms allow GPUs and ASICs to compute billions of guesses per second.
  - The implementation uses standard Java Cryptography Architecture (JCA) `PBKDF2WithHmacSHA512` (Password-Based Key Derivation Function 2 with HMAC-SHA-512, RFC 8018 / PKCS #5 v2.1).
  - SHA-512 employs 64-bit integer arithmetic, significantly increasing the cost of hardware-accelerated (GPU/ASIC) cracking attacks compared to 32-bit algorithms.
- **Work Factor (Iteration Count):**
  - Configured to **210,000 iterations**, adhering to OWASP Password Storage recommendations for PBKDF2-HMAC-SHA512.
  - Provides substantial defense against brute-force and dictionary attacks.
- **Cryptographic Salt Generation:**
  - Each registered user receives a cryptographically strong, unique 128-bit (16-byte) random salt generated via `java.security.SecureRandom`.
  - Salts defeat rainbow tables and pre-computed lookup dictionaries, and prevent attackers from determining whether two users share the same password.
- **Cryptographic Agility & Parameter Storage:**
  - The database table stores `password_hash`, `salt`, `iterations`, and `algorithm` as separate attributes.
  - If hardware speeds increase or security standards require raising iterations (e.g., to 300,000) or adopting a newer algorithm, existing user credentials remain valid, and the service can detect outdated credentials via `needsRehash(conn, username)` and upgrade them seamlessly on next login via `updatePassword(...)`.

### 3. During Authentication (Side-Channel & Timing Protections)

- **Constant-Time Hash Comparison:**
  - Comparing derived hash bytes using standard `Arrays.equals` or `String.equals` is vulnerable to timing attacks because standard comparison short-circuits on the first non-matching byte.
  - The service utilizes `java.security.MessageDigest.isEqual(expectedHash, computedHash)`, which executes in constant time relative to byte content, mitigating side-channel timing analysis.
- **Mitigation of User Enumeration via Timing Discrepancies:**
  - If an authentication attempt is made for a non-existent username, a naive implementation immediately returns `false` (< 1 ms). If the user exists, computing PBKDF2 takes ~300-500 ms. An attacker can exploit this difference to enumerate valid usernames.
  - To prevent this, when a queried username is not found in the database, `authenticateUser` executes a dummy PBKDF2 derivation with the exact same iteration count against a static `DUMMY_SALT` before returning `false`. Both paths take approximately the same duration.
- **Immediate Cleanup:**
  - All intermediate byte buffers (salt, decoded stored hash, computed hash, dummy hash) are immediately overwritten with `(byte) 0` in `finally` blocks.

### 4. Database Security & Injection Prevention

- **Parameterized Queries:**
  - All SQL statements use `java.sql.PreparedStatement` with bind parameters (`?`). User inputs are never concatenated into SQL strings, preventing SQL Injection (SQLi).
- **Unique Constraint Enforcement:**
  - The `username` column is declared as the `PRIMARY KEY`.
  - Duplicate registration attempts are caught gracefully via ANSI SQL integrity constraint violations (SQLState class `23`) and converted into checked `UserAlreadyExistsException`.

---

## Database Schema

The database table is defined using standard ANSI SQL, ensuring broad compatibility across SQLite, H2, PostgreSQL, MySQL, SQL Server, and Oracle:

```sql
CREATE TABLE IF NOT EXISTS users (
    username      VARCHAR(64)  PRIMARY KEY,
    password_hash VARCHAR(128) NOT NULL,
    salt          VARCHAR(64)  NOT NULL,
    iterations    INT          NOT NULL,
    algorithm     VARCHAR(64)  NOT NULL,
    created_at    TIMESTAMP    NOT NULL
);
```

### Column Descriptions

| Column | Type | Description |
|---|---|---|
| `username` | `VARCHAR(64) PRIMARY KEY` | Unique account identifier (3-64 chars: alphanumeric, dot, underscore, hyphen, @) |
| `password_hash` | `VARCHAR(128) NOT NULL` | Base64-encoded 512-bit PBKDF2 derived key |
| `salt` | `VARCHAR(64) NOT NULL` | Base64-encoded 128-bit cryptographically secure random salt |
| `iterations` | `INT NOT NULL` | Number of PBKDF2 hashing iterations used (default: 210,000) |
| `algorithm` | `VARCHAR(64) NOT NULL` | Key derivation algorithm name (default: `PBKDF2WithHmacSHA512`) |
| `created_at` | `TIMESTAMP NOT NULL` | Timestamp when the account was registered |

---

## Project Structure

```
.
├── UserAccountService.java   # Complete Java implementation with embedded verification suite
├── README.md                 # Complete documentation and user guide
├── pom.xml                   # Maven build and dependency configuration
├── run_demo.sh               # Executable compilation and verification runner
└── lib/
    └── h2.jar                # H2 in-memory JDBC driver for standalone offline execution
```

---

## Prerequisites

- **Java Development Kit (JDK):** Version 17 or higher (`javac` and `java` on `PATH`).
- *(Optional)* **Apache Maven:** Version 3.8+ if building via Maven.

---

## How to Compile and Run

### Option 1: Using Standard `javac` and `java` (Recommended)

1. **Compile the source file:**
   ```bash
   javac -Xlint:all UserAccountService.java
   ```

2. **Execute the demonstration suite:**
   ```bash
   java -cp .:lib/h2.jar UserAccountService
   ```

   The built-in verification suite runs against an in-memory database and verifies:
   - Schema creation and table initialization
   - New user registration with salted PBKDF2-HMAC-SHA512
   - Successful authentication with valid credentials
   - Rejection of invalid passwords
   - Rejection and exception handling for duplicate usernames
   - Validation failure on weak/short passwords
   - Timing attack defense for non-existent usernames
   - In-memory zeroization of password character arrays
   - User account metadata retrieval

### Option 2: Using Maven

If you prefer building with Maven:

```bash
# Compile and run the main demonstration
mvn clean compile exec:java
```

### Option 3: Using the Provided Shell Script

A helper script is provided to compile and execute the suite in one step:

```bash
./run_demo.sh
```

---

## Integrating with External Databases (PostgreSQL, MySQL, etc.)

The `UserAccountService` expects an active `java.sql.Connection`. You can pass any active JDBC connection to the methods:

```java
import java.sql.Connection;
import java.sql.DriverManager;

// Connect to PostgreSQL, MySQL, SQLite, etc.
Connection conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password");

UserAccountService authService = new UserAccountService();
authService.initializeDatabase(conn);

// Register user
char[] password = "MySecurePassword2026!".toCharArray();
authService.registerUser(conn, "john_doe", password);

// Authenticate user
char[] loginAttempt = "MySecurePassword2026!".toCharArray();
boolean isAuthenticated = authService.authenticateUser(conn, "john_doe", loginAttempt);
```

You can also run the demonstration program against a specific database URL by supplying the JDBC URL as a command-line argument:

```bash
# Run with custom JDBC URL:
java -cp .:lib/h2.jar:/path/to/driver.jar UserAccountService "jdbc:your-database-url"
```

---

## API Reference & Code Examples

### 1. Registering a New User

```java
UserAccountService service = new UserAccountService();

// Pass password as char[] to permit memory zeroization
char[] password = "UserSecretPassword#123".toCharArray();

try {
    // Automatically wipes the 'password' char array with '\0' upon completion
    service.registerUser(conn, "alice_smith", password);
    System.out.println("User registered successfully!");
} catch (UserAccountService.UserAlreadyExistsException e) {
    System.err.println("Username is already taken: " + e.getMessage());
} catch (UserAccountService.ValidationException e) {
    System.err.println("Input validation error: " + e.getMessage());
}
```

### 2. Authenticating Credentials

```java
char[] attempt = "UserSecretPassword#123".toCharArray();

boolean ok = service.authenticateUser(conn, "alice_smith", attempt);
if (ok) {
    System.out.println("Authentication succeeded.");
} else {
    System.out.println("Invalid username or password.");
}
```

### 3. Upgrading Security Parameters (Needs Rehash)

```java
// Check if user's stored parameters (iterations/algorithm) are outdated
if (service.needsRehash(conn, "alice_smith")) {
    char[] currentPassword = ...; // Obtained during successful authentication
    service.updatePassword(conn, "alice_smith", currentPassword);
}
```

### 4. Retrieving Public Account Metadata

```java
Optional<UserAccountService.UserAccount> user = service.getUserAccount(conn, "alice_smith");
user.ifPresent(u -> {
    System.out.println("Username: " + u.username());
    System.out.println("Created At: " + u.createdAt());
    System.out.println("Iterations: " + u.iterations());
    System.out.println("Algorithm: " + u.algorithm());
});
```
