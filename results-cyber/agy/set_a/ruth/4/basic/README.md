# User Account Registration and Authentication Service

A secure, production-grade Java implementation for registering new user accounts and authenticating users against an SQL database using an active JDBC `Connection`.

The implementation is self-contained in [UserAccountService.java](file:///data/results/agy/set_a/ruth/4/basic/UserAccountService.java) and requires only the standard Java Development Kit (JDK 11+ / Java 17) to compile.

---

## Features

- **Active JDBC Connection Compatibility**: Accepts an existing `java.sql.Connection`, leaving connection pooling and transaction lifecycle control in the hands of the calling application.
- **Cryptographic Security (OWASP Standard)**:
  - **PBKDF2 with HMAC-SHA-512**: Strong key-stretching function (`PBKDF2WithHmacSHA512`) with **210,000 iterations**.
  - **Unique Per-User Salt**: 128-bit (16-byte) cryptographically secure salt generated via `java.security.SecureRandom`.
  - **Constant-Time Verification**: Uses `java.security.MessageDigest.isEqual(...)` to prevent timing side-channel attacks during password verification.
  - **Username Enumeration Mitigation**: Executes a dummy PBKDF2 hash computation even when a queried username is not found, mitigating timing differences between existing and non-existing accounts.
  - **Secure In-Memory Handling**: Supports `char[]` passwords with automatic memory clearing (`clearPassword()`) alongside standard `String` methods.
- **SQL Injection Prevention**: All database interactions strictly utilize parameterized queries via `java.sql.PreparedStatement`.
- **Concurrency & Duplicate Handling**: Gracefully handles duplicate registration attempts via pre-checks and database unique constraint violations.
- **Zero Third-Party Compile Dependencies**: Implemented purely with Java SE standard libraries (`java.sql.*`, `javax.crypto.*`, `java.security.*`, `java.util.*`).

---

## Database Schema

The service manages user records in a table named `users`. The schema is ANSI SQL compliant and compatible across SQLite, PostgreSQL, MySQL, H2, Oracle, MariaDB, and SQL Server:

```sql
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(255) NOT NULL PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

You can initialize this table programmatically using `UserAccountService.createUsersTable(connection)`.

---

## API Overview

### Constructors
- `UserAccountService(Connection connection)`: Binds the service to an active JDBC connection.

### Registration Methods
- `boolean registerUser(String username, String password)`: Registers a new user. Returns `true` on success, or `false` if the username is already registered.
- `boolean registerUser(String username, char[] password)`: Overload accepting a character array password for secure memory hygiene.
- `void registerNewUser(String username, String password)`: Registers a user; throws `UserAlreadyExistsException` if the username exists.
- `static boolean registerUser(Connection conn, String username, String password)`: Static helper for one-off invocations.

### Authentication Methods
- `boolean authenticateUser(String username, String password)`: Authenticates user credentials. Returns `true` if username and password match, `false` otherwise.
- `boolean authenticateUser(String username, char[] password)`: Overload accepting a character array password.
- `static boolean authenticateUser(Connection conn, String username, String password)`: Static helper for one-off invocations.

### Utility Methods
- `boolean userExists(String username)`: Checks if a username is already registered.
- `static void createUsersTable(Connection conn)`: Executes DDL to create the `users` table if absent.

---

## Integration Example

```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Example {
    public static void main(String[] args) throws SQLException {
        // Assume an active JDBC connection is available
        try (Connection conn = DriverManager.getConnection("jdbc:your-database-url", "user", "password")) {
            
            // 1. Create table schema if not already initialized
            UserAccountService.createUsersTable(conn);

            // 2. Initialize service instance with the connection
            UserAccountService authService = new UserAccountService(conn);

            // 3. Register a new user account
            boolean registered = authService.registerUser("alice", "SuperSecretP@ss123");
            if (registered) {
                System.out.println("User registered successfully!");
            }

            // 4. Authenticate later
            boolean isAuthenticated = authService.authenticateUser("alice", "SuperSecretP@ss123");
            if (isAuthenticated) {
                System.out.println("Authentication successful!");
            } else {
                System.out.println("Invalid credentials.");
            }
        }
    }
}
```

---

## How to Compile and Run

### Prerequisites
- **JDK 11+** or **JDK 17+** (`javac` and `java` on `PATH`)
- Optional: **Apache Maven** (`mvn`)

---

### Method 1: Using `javac` and `java` (Command Line)

#### 1. Compile the Source Code
Because `UserAccountService.java` relies only on standard Java libraries, it compiles directly with `javac`:

```bash
javac UserAccountService.java
```

Or compile with the bundled JDBC driver on the classpath:

```bash
javac -cp ".:lib/*" UserAccountService.java
```

#### 2. Run the Demonstration
Run the built-in demonstration with the included H2 in-memory JDBC driver:

```bash
java -cp ".:lib/*" UserAccountService
```

#### 3. Run with an External Database (e.g. PostgreSQL, MySQL)
To run against your existing database, include your driver JAR and provide JDBC parameters:

```bash
java -cp ".:path/to/driver.jar" UserAccountService "jdbc:postgresql://localhost:5432/mydb" "dbuser" "dbpass"
```

---

### Method 2: Using Apache Maven

A `pom.xml` is provided for automated dependency management and testing.

#### 1. Compile the Project
```bash
mvn compile
```

#### 2. Run the Unit Test Suite
Executes 10 automated test cases verifying registration, authentication, salt uniqueness, password hashing verification, duplicate prevention, and SQL injection safety:

```bash
mvn test
```

#### 3. Run the Interactive Demonstration
```bash
mvn exec:java
```

---

## Test Coverage Summary

The included JUnit 5 test suite ([UserAccountServiceTest.java](file:///data/results/agy/set_a/ruth/4/basic/src/test/java/UserAccountServiceTest.java)) covers:
1. `testRegisterUserSuccess`: Verifies successful account creation in the database.
2. `testPasswordIsHashedAndSalted`: Asserts that plain text passwords are never stored in the database.
3. `testUniqueSaltsForIdenticalPasswords`: Verifies that two users with the same password receive distinct random salts and generate distinct hashes.
4. `testDuplicateUsernameRegistration`: Ensures duplicate usernames are rejected.
5. `testAuthenticationSuccess`: Verifies valid credentials authenticate successfully.
6. `testAuthenticationFailureWrongPassword`: Ensures incorrect passwords are denied.
7. `testAuthenticationFailureNonExistentUser`: Ensures non-existent users are rejected.
8. `testInputValidation`: Enforces constraints against null/blank usernames and passwords.
9. `testSqlInjectionSafety`: Verifies parameterized queries prevent SQL injection payloads in usernames.
10. `testCharArrayPasswordSupport`: Confirms secure `char[]` password API functions identically.
