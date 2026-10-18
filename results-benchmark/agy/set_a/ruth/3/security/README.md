# Secure User Account Retrieval via JDBC

A production-ready Java implementation that securely queries and retrieves user account records from an SQL database using an active JDBC `Connection`.

The code strictly adheres to modern security standards, primarily addressing **SQL Injection (CWE-89)** through parameterized queries, deterministic **Resource Management (CWE-404 / CWE-772)**, **Least Privilege / Credential Protection (CWE-200)**, and defensive **Input Validation (CWE-20)**.

---

## Table of Contents

1. [Overview & Requirements Fulfillment](#overview--requirements-fulfillment)
2. [Security Architecture & Threat Mitigation](#security-architecture--threat-mitigation)
   - [SQL Injection Defense (CWE-89)](#1-sql-injection-defense-cwe-89)
   - [Caller Connection Ownership & Transaction Boundaries](#2-caller-connection-ownership--transaction-boundaries)
   - [Deterministic Resource Management (CWE-404 / CWE-772)](#3-deterministic-resource-management-cwe-404--cwe-772)
   - [Principle of Least Privilege & Sensitive Data Protection (CWE-200)](#4-principle-of-least-privilege--sensitive-data-protection-cwe-200)
   - [Defensive Input Validation (CWE-20)](#5-defensive-input-validation-cwe-20)
   - [Execution Limits & Query Timeout](#6-execution-limits--query-timeout)
3. [Domain Model: `UserAccount`](#domain-model-useraccount)
4. [API Reference](#api-reference)
   - [Static API (Caller-Supplied Connection)](#static-api)
   - [Instance-Based Repository API](#instance-based-repository-api)
   - [Exception Handling](#exception-handling)
5. [Prerequisites](#prerequisites)
6. [Compilation](#compilation)
7. [Running the Code](#running-the-code)
   - [Automated Security & Functional Test Suite](#1-automated-security--functional-test-suite)
   - [Ad-Hoc Username Lookup Mode](#2-ad-hoc-username-lookup-mode)
   - [Running with Real In-Memory Database (H2)](#3-running-with-real-in-memory-database-h2)
   - [Running with Zero External Dependencies (Pure JDK Fallback)](#4-running-with-zero-external-dependencies-pure-jdk-fallback)
8. [Integration Guide](#integration-guide)

---

## Overview & Requirements Fulfillment

This component fulfills the following requirements:
- **Active JDBC Connection:** Assumes an existing, open `java.sql.Connection` passed by the caller.
- **User-Supplied Input Handling:** Accepts a `username` string and safely queries the database without introducing SQL injection vulnerabilities.
- **Account Retrieval & Mapping:** Queries the matching record and encapsulates the data into a strongly typed, immutable `UserAccount` domain object.
- **Self-Contained Source File:** All repository logic, domain records, exceptions, and verification test suites are contained within `UserAccountRepository.java`.

---

## Security Architecture & Threat Mitigation

### 1. SQL Injection Defense (CWE-89)

#### The Vulnerability
SQL Injection occurs when untrusted user input is directly concatenated or formatted into dynamic SQL strings:
```java
// INSECURE VULNERABLE PATTERN - DO NOT USE
Statement stmt = connection.createStatement();
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
ResultSet rs = stmt.executeQuery(query);
```
If an adversary supplies a malicious payload such as `' OR '1'='1` or `admin' --`, the query syntax is altered, bypassing authentication, extracting unauthorized data, or executing stacked commands (`DROP TABLE`).

#### The Solution: Parameterized Queries via `PreparedStatement`
In `UserAccountRepository`, all SQL queries use parameterized statements with positional bind markers (`?`):
```java
public static final String DEFAULT_SELECT_QUERY =
    "SELECT id, username, email, full_name, role, is_active, created_at, last_login_at " +
    "FROM users " +
    "WHERE username = ?";

try (PreparedStatement pstmt = connection.prepareStatement(sqlQuery)) {
    pstmt.setString(1, trimmedUsername);
    try (ResultSet rs = pstmt.executeQuery()) {
        // ...
    }
}
```

**Why this guarantees security:**
1. **Compilation Phase Isolation:** The database parser compiles the query structure into an Abstract Syntax Tree (AST) *before* parameter values are bound.
2. **Literal Value Binding:** The database engine treats the contents of `pstmt.setString(1, ...)` strictly as literal data. Characters such as `'`, `"`, `;`, `--`, or `/*` cannot alter the query grammar or execution plan.

---

### 2. Caller Connection Ownership & Transaction Boundaries

The repository respects the lifecycle of the caller's connection:
- **No Connection Closing:** The repository never invokes `connection.close()`.
- **No Transaction Tampering:** The repository never calls `connection.commit()` or `connection.rollback()`.
- **Connection Pool Compatibility:** This design allows seamless use within managed connection pools (e.g., HikariCP, Apache Commons DBCP) and enterprise frameworks (Spring `@Transactional`, Jakarta EE JTA).

---

### 3. Deterministic Resource Management (CWE-404 / CWE-772)

Both `PreparedStatement` and `ResultSet` are allocated inside nested Java **try-with-resources** blocks:
```java
try (PreparedStatement pstmt = connection.prepareStatement(sqlQuery)) {
    pstmt.setString(1, trimmed);
    try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
            return Optional.of(mapRowToUserAccount(rs));
        }
        return Optional.empty();
    }
}
```
Regardless of whether execution completes successfully or throws a runtime `SQLException`, all statement handles and database cursors are immediately closed in reverse order of creation. This prevents database cursor exhaustion and memory leaks.

---

### 4. Principle of Least Privilege & Sensitive Data Protection (CWE-200)

1. **Explicit Projections:** Queries avoid `SELECT *`. Explicitly enumerating columns (`id, username, email, full_name, ...`) ensures only authorized fields are requested.
2. **Exclusion of Secrets:** Passwords, password hashes (e.g., bcrypt/argon2), salts, MFA secret seeds, and reset tokens are excluded from both the SQL query and the `UserAccount` domain record.

---

### 5. Defensive Input Validation (CWE-20)

Before executing any database statement:
- **Null Safety:** If `username == null`, the method safely returns `Optional.empty()` without issuing unnecessary database queries.
- **Whitespace Normalization:** Leading and trailing whitespace is stripped via `username.trim()`.
- **Length Bounds:** Input length is enforced against `MAX_USERNAME_LENGTH` (255 characters) to defend against memory exhaustion and buffer overflow payloads.
- **Log Injection Sanitization:** Exception messages strip newline and carriage return characters (`\r`, `\n`) to prevent log forging (CWE-117).

---

### 6. Execution Limits & Query Timeout

- `pstmt.setQueryTimeout(10)`: Limits statement execution to 10 seconds, preventing long-running queries or denial-of-service locks.
- `pstmt.setMaxRows(1)`: Instructs the JDBC driver to buffer at most 1 matching row, minimizing memory consumption.

---

## Domain Model: `UserAccount`

The retrieved account information is represented as a Java `record`:

```java
public record UserAccount(
    Long id,              // Unique database identifier
    String username,      // Account username
    String email,         // Registered email address
    String fullName,      // User's full display name
    String role,          // Authorization role (e.g., "ADMIN", "USER")
    boolean isActive,     // Account enabled / active flag
    Instant createdAt,    // Creation timestamp (UTC)
    Instant lastLoginAt   // Timestamp of last login (nullable)
)
```

The record provides standard accessor methods (`account.username()`, `account.email()`) as well as JavaBean-style getters (`account.getUsername()`, `account.getEmail()`, `account.isActive()`) for framework interoperability.

---

## API Reference

### Static API

Ideal for functional callers who manage connections directly:

```java
// Modern Optional-based retrieval
Optional<UserAccount> user = UserAccountRepository.findByUsername(connection, "alice");

// Alias matching requirement wording
Optional<UserAccount> user = UserAccountRepository.getUserByUsername(connection, "alice");

// Null-returning retrieval (legacy style)
UserAccount user = UserAccountRepository.getAccountByUsername(connection, "alice");

// Strict retrieval (throws UserAccountNotFoundException if absent)
UserAccount user = UserAccountRepository.requireByUsername(connection, "alice");

// Custom parameterized query retrieval
String customQuery = "SELECT id, username, email, full_name, role, is_active, created_at, last_login_at FROM accounts WHERE login = ?";
Optional<UserAccount> user = UserAccountRepository.findByUsername(connection, "alice", customQuery);
```

### Instance-Based Repository API

Ideal for dependency injection (e.g., Spring or Guice):

```java
UserAccountRepository repository = new UserAccountRepository(connection);

Optional<UserAccount> user = repository.findByUsername("alice");
UserAccount requiredUser = repository.requireByUsername("alice");
```

### Exception Handling

- `java.sql.SQLException`: Thrown when a database access or communication failure occurs.
- `IllegalArgumentException`: Thrown by `requireByUsername` if the username is null or blank.
- `UserAccountNotFoundException`: Thrown by `requireByUsername` when no user matches the supplied username.

---

## Prerequisites

- **Java Development Kit (JDK):** Version 17 or higher (tested on OpenJDK 17).
- **JDBC Driver:** (Optional) An H2 driver is included in `lib/h2.jar`. If absent, the application automatically uses an internal dynamic mock JDBC driver for standalone testing.

---

## Compilation

Compile the Java source file using `javac`:

```bash
# Compile using the included H2 driver library
javac -cp .:lib/h2.jar UserAccountRepository.java

# Or compile using pure standard JDK (no external libraries needed)
javac UserAccountRepository.java
```

---

## Running the Code

### 1. Automated Security & Functional Test Suite

Running the program without arguments launches the built-in test suite:

```bash
java -cp .:lib/h2.jar UserAccountRepository
```

The automated suite runs and verifies 10 rigorous test cases:
1. **Existing User Lookup:** Queries an existing account (`alice`) and validates all retrieved fields.
2. **Whitespace Normalization:** Queries `  bob  ` with padding whitespace; verifies proper trimming.
3. **Data Containing Quotes:** Queries a user with legitimate apostrophes (`o'brien`).
4. **Non-Existent User:** Queries `charlie`; verifies clean return of `Optional.empty()`.
5. **SQL Injection Attack Suite:** Executes 10 distinct attack vectors against the repository:
   - Tautologies (`' OR '1'='1`)
   - Comment bypasses (`' OR 1=1 --`, `admin' --`, `alice' /*`)
   - Stacked query injection (`alice'; DROP TABLE users; --`)
   - UNION-based data exfiltration (`' UNION SELECT 999, 'hacker', ... --`)
   - Empty quote manipulation (`admin' OR ''='`)
   - Special wildcards and escapes (`\`, `%`, `_`)
6. **Database Integrity Verification:** Asserts that user count remains exactly 3 and no tables were altered or dropped during attack simulation.
7. **Input Boundary Validation:** Verifies safe handling of `null`, empty string, whitespace-only, and oversized strings (>255 chars).
8. **Strict Retrieval Validation:** Verifies that `requireByUsername()` correctly throws `IllegalArgumentException` on blank inputs and `UserAccountNotFoundException` on unknown users.
9. **Caller Connection Preservation:** Confirms that the caller's connection remains open and transaction state (auto-commit) is unmolested.
10. **Principle of Least Privilege:** Inspects reflection metadata on `UserAccount` to ensure no password hashes or secret tokens are exposed.

### 2. Ad-Hoc Username Lookup Mode

You can query individual usernames directly from the command line:

```bash
# Query an existing user
java -cp .:lib/h2.jar UserAccountRepository alice

# Query a non-existent user
java -cp .:lib/h2.jar UserAccountRepository nonexistent_user

# Test an injection payload safely from CLI
java -cp .:lib/h2.jar UserAccountRepository "' OR '1'='1"
```

### 3. Running with Real In-Memory Database (H2)

When `lib/h2.jar` is available on the classpath, the test suite initializes an in-memory H2 database (`jdbc:h2:mem:useraccount_demo`), creates the `users` table, and seeds initial records.

### 4. Running with Zero External Dependencies (Pure JDK Fallback)

If running in an environment without external JARs or internet access:
```bash
javac UserAccountRepository.java
java -cp . UserAccountRepository
```
The repository contains an internal dynamic proxy-based mock JDBC driver that implements `Connection`, `PreparedStatement`, `Statement`, and `ResultSet`. All 10 tests execute and validate successfully using pure JDK 17 standard libraries.

---

## Integration Guide

To integrate this repository into your existing application:

```java
import java.sql.Connection;
import java.util.Optional;

public class UserService {

    private final DataSource dataSource;

    public UserService(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void displayUserProfile(String inputUsername) {
        try (Connection conn = dataSource.getConnection()) {
            // Retrieve user using the secure repository
            Optional<UserAccountRepository.UserAccount> accountOpt = 
                UserAccountRepository.getUserByUsername(conn, inputUsername);

            accountOpt.ifPresentOrElse(
                account -> System.out.println("Welcome, " + account.fullName() + " (" + account.email() + ")"),
                () -> System.out.println("User not found.")
            );
        } catch (SQLException e) {
            // Handle or log database connection errors
            logger.error("Failed to query user database", e);
        }
    }
}
```
