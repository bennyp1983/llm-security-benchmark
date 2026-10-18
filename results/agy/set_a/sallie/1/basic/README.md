# Java Authentication and Session Cookie Web Application

A lightweight, secure, and standalone Java web application demonstrating user authentication and HTTP session cookie management. This application accepts user credentials (username and password), validates them against salted cryptographic hashes, and issues a secure HTTP session cookie that browsers use to maintain authenticated state across requests.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Security Features](#security-features)
- [Preconfigured Test Accounts](#preconfigured-test-accounts)
- [Project Files](#project-files)
- [Prerequisites](#prerequisites)
- [How to Build and Run](#how-to-build-and-run)
  - [Method 1: Direct Execution (Zero Compilation)](#method-1-direct-execution-zero-compilation)
  - [Method 2: Standard Compilation with javac](#method-2-standard-compilation-with-javac)
  - [Method 3: Using Apache Maven](#method-3-using-apache-maven)
- [Testing the Application](#testing-the-application)
  - [1. Testing in a Web Browser](#1-testing-in-a-web-browser)
  - [2. Testing with Command-Line curl](#2-testing-with-command-line-curl)
  - [3. Running the Automated Test Suite](#3-running-the-automated-test-suite)
- [Application Endpoints](#application-endpoints)
- [Detailed Architecture and Implementation](#detailed-architecture-and-implementation)

---

## Overview

In web applications, HTTP is a stateless protocol. This means each request sent to the server is independent, and the server does not inherently remember who the user is between page visits.

To create an authenticated session:
1. The user submits their username and password through an HTML login form.
2. The server verifies the credentials.
3. Upon successful verification, the server generates a cryptographically unique session token and sends it back to the client in an HTTP header named `Set-Cookie`.
4. The client's browser stores this cookie and automatically attaches it (`Cookie: SESSIONID=...`) to all subsequent requests to the server.
5. The server checks incoming cookies against its active session store to identify and authorize the user without requiring them to re-enter their credentials on every page.

This project implements that entire workflow natively in Java with **zero third-party dependencies**.

---

## How It Works

```
  +--------------+                                       +--------------+
  |  Web Browser |                                       |  Java Server |
  +-------+------+                                       +-------+------+
          |                                                      |
          | 1. GET /login                                        |
          |----------------------------------------------------->|
          | 2. 200 OK (Render HTML Login Form)                   |
          |<-----------------------------------------------------|
          |                                                      |
          | 3. POST /login (username=admin, password=...)        |
          |----------------------------------------------------->|
          |                                                      | Verify Credentials
          |                                                      | Create Session
          | 4. 302 Redirect to /dashboard                        |
          |    Set-Cookie: SESSIONID=<token>; HttpOnly; SameSite |
          |<-----------------------------------------------------|
[Cookie Stored in Browser]                                       |
          |                                                      |
          | 5. GET /dashboard                                    |
          |    Cookie: SESSIONID=<token>                         |
          |----------------------------------------------------->|
          |                                                      | Validate Session ID
          |                                                      | Refresh Idle Expiry
          | 6. 200 OK (Render Protected Dashboard)              |
          |<-----------------------------------------------------|
          |                                                      |
          | 7. POST /logout                                      |
          |    Cookie: SESSIONID=<token>                         |
          |----------------------------------------------------->|
          |                                                      | Invalidate Session
          | 8. 302 Redirect to /login?logout=true                |
          |    Set-Cookie: SESSIONID=; Max-Age=0 (Delete Cookie) |
          |<-----------------------------------------------------|
[Cookie Deleted]                                                 |
```

---

## Security Features

1. **Robust Password Hashing (PBKDF2)**:
   - Uses `PBKDF2WithHmacSHA256` with 65,536 iterations and unique 128-bit cryptographic salts per user.
   - Passwords are never stored in plain text.
   - Uses `MessageDigest.isEqual` to compare hashes in constant time, preventing side-channel timing attacks.
   - Includes dummy hash computation for non-existent users to eliminate user-enumeration timing discrepancies.

2. **Cryptographically Secure Session Tokens**:
   - Session identifiers are generated using `java.security.SecureRandom` with 256 bits of entropy (64 hexadecimal characters), preventing session prediction or brute-force guessing.

3. **Protective Session Cookie Directives**:
   - `HttpOnly`: Disallows access to the session cookie via JavaScript (`document.cookie`), mitigating Cross-Site Scripting (XSS) session hijacking.
   - `SameSite=Strict`: Tells the browser not to send the cookie along with cross-site requests, mitigating Cross-Site Request Forgery (CSRF).
   - `Path=/`: Ensures the cookie is sent to all endpoints within the application.
   - `Max-Age=1800`: Sets a 30-minute expiration period.

4. **Server-Side Session State & Expiration**:
   - Sessions are maintained in a thread-safe `ConcurrentHashMap`.
   - Supports sliding window idle expiration (30 minutes) and absolute session lifetime (12 hours).
   - A background thread automatically purges expired sessions every minute.

5. **Safe Invalidation on Logout**:
   - Invalidation removes the session from the server-side memory.
   - Sends an expired cookie header (`Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`) prompting the browser to discard the cookie immediately.

6. **Input Sanitization**:
   - User inputs and query parameters are escaped before rendering in HTML templates to prevent Cross-Site Scripting (XSS).

---

## Preconfigured Test Accounts

The application initializes three demo accounts for testing:

| Username | Password | Full Name | Role |
| :--- | :--- | :--- | :--- |
| `admin` | `AdminPassword123!` | System Administrator | Administrator |
| `alice` | `AlicePass#2026` | Alice Johnson | Software Engineer |
| `bob` | `BobSecret99!` | Bob Smith | Security Analyst |

---

## Project Files

- **`AuthApplication.java`**: The complete, self-contained Java source code containing the HTTP server, routing handlers, password hashing service, user database, session manager, and HTML view templates.
- **`pom.xml`**: Apache Maven configuration file for compiling, packaging, and running the project as an executable JAR.
- **`test_app.sh`**: Automated integration test script that launches the application and verifies all login, cookie issuance, dashboard protection, and logout workflows via `curl`.
- **`README.md`**: Project documentation and user guide.

---

## Prerequisites

- **Java Development Kit (JDK)**: Java 11 or higher (Java 17 LTS recommended).
- **Maven** (Optional): Version 3.6+ if you prefer using Maven build commands.
- **cURL** (Optional): For command-line testing.

Verify your Java version:
```bash
java -version
```

---

## How to Build and Run

You can run this application using any of the three methods below.

### Method 1: Direct Execution (Zero Compilation)
Java 11+ supports executing single-file source code directly without creating `.class` files:

```bash
# Run on default port (8080)
java AuthApplication.java

# Or specify a custom port as an argument:
java AuthApplication.java 9000
```

### Method 2: Standard Compilation with javac
Compile using the standard Java compiler:

```bash
# Compile
javac AuthApplication.java

# Run
java AuthApplication
```

### Method 3: Using Apache Maven
You can compile and run directly using Maven:

```bash
# Run with Maven exec plugin
mvn compile exec:java

# Or package into an executable JAR
mvn clean package

# Run the packaged JAR
java -jar target/auth-session-app-1.0.0.jar
```

---

## Testing the Application

### 1. Testing in a Web Browser

1. Start the application:
   ```bash
   java AuthApplication
   ```
2. Open your browser and navigate to:
   [http://localhost:8080](http://localhost:8080)
3. You will be automatically redirected to the `/login` page.
4. Enter test credentials:
   - **Username**: `admin`
   - **Password**: `AdminPassword123!`
5. Click **Sign In**:
   - Upon successful authentication, the server sets the `SESSIONID` cookie and redirects you to the `/dashboard`.
   - The dashboard displays your profile details, session creation time, active cookie token, and security flags.
6. Inspect the cookie in your browser:
   - Open Developer Tools (`F12` or `Ctrl+Shift+I` / `Cmd+Option+I`).
   - Go to the **Application** tab (Chrome/Edge) or **Storage** tab (Firefox).
   - Under **Cookies**, select `http://localhost:8080`.
   - Notice the cookie named `SESSIONID` with the `HttpOnly` and `SameSite` flags enabled.
7. Click **Sign Out**:
   - The session is invalidated on the server, the cookie is deleted in the browser, and you are redirected to the login page.
   - If you try navigating back to `/dashboard`, access is denied, redirecting you to `/login?error=unauthorized`.

---

### 2. Testing with Command-Line curl

You can verify the HTTP exchange, headers, and cookies step-by-step in your terminal:

#### Step 1: Attempt to access protected dashboard without authentication
```bash
curl -i http://localhost:8080/dashboard
```
**Expected Response**: `302 Found` with header `Location: /login?error=unauthorized`.

---

#### Step 2: Attempt login with invalid credentials
```bash
curl -i -X POST http://localhost:8080/login \
     -d "username=admin&password=WrongPassword"
```
**Expected Response**: `302 Found` with header `Location: /login?error=invalid_credentials`. No cookie is issued.

---

#### Step 3: Login with valid credentials and store the session cookie
The `-c cookies.txt` flag instructs `curl` to write received cookies to a file:
```bash
curl -i -X POST http://localhost:8080/login \
     -c cookies.txt \
     -d "username=admin&password=AdminPassword123!"
```
**Expected Response**:
```http
HTTP/1.1 302 Found
Set-Cookie: SESSIONID=...; Path=/; Max-Age=1800; HttpOnly; SameSite=Strict
Location: /dashboard
```

Inspect the saved cookie file:
```bash
cat cookies.txt
```

---

#### Step 4: Access protected dashboard using the session cookie
The `-b cookies.txt` flag sends stored cookies back to the server:
```bash
curl -s -b cookies.txt http://localhost:8080/dashboard | grep "Welcome"
```
**Expected Output**:
```html
    <h1>Welcome, System Administrator!</h1>
```

---

#### Step 5: Test the JSON API endpoint
The application also exposes a programmatic API:
```bash
curl -s -b cookies.txt http://localhost:8080/api/session
```
**Expected JSON Response**:
```json
{
  "authenticated": true,
  "username": "admin",
  "fullName": "System Administrator",
  "role": "Administrator",
  "sessionId": "...",
  "createdAt": "2026-10-09T05:15:37.000Z",
  "lastAccessedAt": "2026-10-09T05:15:37.000Z"
}
```

---

#### Step 6: Log out and invalidate the session
```bash
curl -i -X POST http://localhost:8080/logout \
     -b cookies.txt \
     -c cookies.txt
```
**Expected Response**:
```http
HTTP/1.1 302 Found
Set-Cookie: SESSIONID=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT
Location: /login?logout=true
```

---

#### Step 7: Verify session is invalidated
Attempting to access the dashboard with the previous session cookie now fails:
```bash
curl -i -b cookies.txt http://localhost:8080/dashboard
```
**Expected Response**: `302 Found` with `Location: /login?error=unauthorized`.

---

### 3. Running the Automated Test Suite

An automated integration script is included. It automatically compiles the code, spins up an isolated server instance on port 8085, executes 10 end-to-end integration tests, and cleanly shuts down:

```bash
chmod +x test_app.sh
./test_app.sh
```

**Expected output:**
```
==========================================================
Starting AuthApplication on port 8085...
==========================================================
Running Integration Tests...

Test 1: GET /login returns 200 OK and contains login form... PASS
Test 2: GET /dashboard without session cookie redirects to /login?error=unauthorized... PASS
Test 3: POST /login with invalid credentials redirects to /login?error=invalid_credentials... PASS
Test 4: POST /login with valid credentials returns Set-Cookie and redirects to /dashboard... PASS
Test 5: GET /dashboard with valid session cookie displays protected dashboard... PASS
Test 6: POST /logout invalidates session and clears cookie... PASS
Test 7: Accessing /dashboard after logout is rejected (unauthorized)... PASS
Test 8: API POST /api/login authenticates and returns JSON + cookie... PASS
Test 9: API GET /api/session returns authenticated session details... PASS
Test 10: API POST /api/logout terminates session... PASS

==========================================================
ALL 10 TESTS PASSED SUCCESSFULLY!
==========================================================
```

---

## Application Endpoints

| Method | Path | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Root router: redirects to `/dashboard` if authenticated, else `/login` | Public |
| `GET` | `/login` | Displays the login form with test accounts | Public |
| `POST` | `/login` | Authenticates username/password; sets session cookie | Public |
| `GET` | `/dashboard` | Protected user dashboard displaying profile & session status | Authenticated |
| `POST` / `GET` | `/logout` | Invalidates session and clears browser cookie | Authenticated |
| `POST` | `/api/login` | JSON authentication endpoint | Public |
| `GET` | `/api/session` | JSON endpoint returning active session metadata | Authenticated |
| `POST` | `/api/logout` | JSON logout endpoint | Authenticated |

---

## Detailed Architecture and Implementation

### 1. `AuthApplication` Class
Serves as the main orchestrator and entry point. It creates an instance of `com.sun.net.httpserver.HttpServer`, maps endpoint URIs to handler implementations, and manages graceful shutdowns using a JVM shutdown hook.

### 2. `UserManager` and `User`
Maintains user records in memory. When a user is registered or preloaded:
- A unique 16-byte cryptographically secure random salt is generated via `SecureRandom`.
- The password and salt are hashed using `PBKDF2WithHmacSHA256` through 65,536 iterations.
- When authenticating, the input password is submitted to the same hashing derivation, and `MessageDigest.isEqual()` performs a constant-time byte comparison to defend against timing attacks.

### 3. `SessionManager` and `Session`
Stores active authenticated sessions in a `ConcurrentHashMap`:
- **Session Token Generation**: Produces a 256-bit random token formatted as a 64-character hexadecimal string.
- **Sliding Inactivity Expiration**: Each access updates `lastAccessedAt`. If inactivity exceeds 30 minutes, `getValidSession()` rejects the token and removes it.
- **Purge Worker**: A scheduled single-threaded executor regularly sweeps expired sessions to prevent memory bloat.

### 4. `Views` Class
Generates clean, responsive HTML and embedded CSS for both the `/login` and `/dashboard` screens, ensuring self-contained operation without external web fonts or CDN dependencies.
