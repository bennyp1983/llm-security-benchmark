# Security Review: User Registration & Authentication System (UserAuthSystem)

## 1. Executive Summary
The target system is a standalone Java application (`UserAuthSystem.java`) implementing user account registration, persistent credential storage, and password-based authentication. It supports both an interactive console menu and non-interactive command-line interface (CLI) execution modes. The cryptographic foundation is well-constructed, using `PBKDF2WithHmacSHA256` with 65,536 iterations, per-user 16-byte cryptographically secure salts via `SecureRandom`, constant-time digest comparison (`MessageDigest.isEqual`), and dummy hash computations for unknown usernames.

However, several significant security vulnerabilities were identified:
1. **Plaintext Password Exposure via Command-Line Arguments (High)**: Passwords accepted directly on the command line in CLI mode are visible in the operating system process table (`ps`, `/proc`) to unprivileged users, preserved in shell history, and retained immutably in JVM heap memory.
2. **Insecure File Creation and TOCTOU Permissions Window (High)**: `credentials.txt` is created non-atomically with default umask permissions before attempting to restrict POSIX permissions, exposing a window where unauthorized local users can access salted hashes, while existing files and non-POSIX filesystems are left unrestricted.
3. **Unauthenticated User Account Enumeration (Medium)**: Despite deliberate timing-attack mitigations in login, the system exposes an unauthenticated `list` command and menu option that dumps all registered usernames.
4. **Missing Authentication Rate Limiting and Account Lockout (Medium)**: There is no throttling or lockout on repeated failed login attempts, enabling rapid local password guessing attacks.
5. **Sensitive Memory Retention on Scanner Fallback (Low)**: Fallback terminal input uses `Scanner.nextLine()`, creating immutable `String` objects that cannot be zeroed from heap memory.
6. **Missing Maximum Password Length Limit (Low)**: Lack of an upper bound on password length allows resource exhaustion (DoS) through oversized payloads in PBKDF2 hashing.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAuthSystem.java` | Core application source code implementing data models, storage repository, crypto service, CLI, and interactive console menu | PBKDF2 password hashing, salt generation, constant-time verification, credential serialization/deserialization, POSIX file permission management, CLI argument parsing, console password input, user listing |
| `README.md` / `README` | Documentation and operational user guide | Documents command-line execution examples passing plaintext passwords, credential storage file format, and security design claims |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to password hashing algorithm selection (`PBKDF2WithHmacSHA256`), iteration count (65,536), derived key size (256 bits), cryptographic salt generation via `SecureRandom`, constant-time comparison via `MessageDigest.isEqual`, and dummy hash calculation for timing side-channel mitigation.
- `testing-for-sensitive-data-exposure`: Applied to plaintext password handling in CLI arguments, process table exposure, shell history persistence, heap memory management of character arrays and strings, and unauthenticated exposure of registered usernames.
- General OWASP Top 10 / CWE Knowledge:
  - Reviewed filesystem storage permissions, file creation atomicity, time-of-check to time-of-use (TOCTOU) race conditions, and link following against CWE-732, CWE-378, CWE-362, and CWE-59.
  - Reviewed access control and unauthenticated user listing against CWE-306 / CWE-200 (OWASP A01: Broken Access Control).
  - Reviewed brute-force susceptibility and lack of rate limiting against CWE-307 (OWASP A07: Identification and Authentication Failures).
  - Reviewed unbounded input password length and resource allocation against CWE-770 / CWE-400 (OWASP A04: Insecure Design).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Plaintext Password Exposure via Command-Line Arguments and Process Table | High | CWE-214 | `UserAuthSystem.java:444-465` |
| SEC-02 | Insecure File Creation and TOCTOU Permissions Window on Credential Store | High | CWE-732 | `UserAuthSystem.java:175-185` |
| SEC-03 | Unauthenticated User Account Enumeration via User List Function | Medium | CWE-306 | `UserAuthSystem.java:474-480` |
| SEC-04 | Missing Authentication Rate Limiting and Account Lockout | Medium | CWE-307 | `UserAuthSystem.java:282-320` |
| SEC-05 | Sensitive Password Retained in Immutable String Memory on Scanner Fallback | Low | CWE-316 | `UserAuthSystem.java:646-657` |
| SEC-06 | Missing Maximum Password Length Limit Permitting Resource Exhaustion DoS | Low | CWE-770 | `UserAuthSystem.java:222-230` |

## 5. Detailed Findings

### SEC-01: Plaintext Password Exposure via Command-Line Arguments and Process Table
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- Location: `UserAuthSystem.java:444-465`

**Vulnerable code:**
```java
// UserAuthSystem.java:444-465
                    char[] regPass = args[2].toCharArray();
                    RegistrationResult regRes = authService.register(args[1], regPass);
                    Arrays.fill(regPass, ' ');
                    if (regRes.isSuccess()) {
                        System.out.println("[SUCCESS] " + regRes.getMessage());
                        System.exit(0);
                    } else {
                        System.err.println("[ERROR] " + regRes.getMessage());
                        System.exit(1);
                    }
                    break;

                case "login":
                case "authenticate":
                    if (args.length < 3) {
                        System.err.println("Usage: java UserAuthSystem login <username> <password>");
                        System.exit(1);
                    }
                    char[] loginPass = args[2].toCharArray();
                    AuthResult authRes = authService.authenticate(args[1], loginPass);
                    Arrays.fill(loginPass, ' ');
```

**Why it is a problem:**
In CLI execution mode, the application requires the user to pass their password as a command-line argument (`args[2]`). On multi-user systems (UNIX, Linux, macOS, and Windows):
1. Command-line arguments are globally visible to all local users via process enumeration tools (e.g. `ps aux`, `ps -ef`, `/proc/<pid>/cmdline`, Process Explorer).
2. The invocation string containing the plaintext password is saved to user shell history files (such as `~/.bash_history` or `~/.zsh_history`) and environment audit logs (e.g. Linux auditd or Windows Event ID 4688).
3. The argument arrives as an immutable `java.lang.String` in `args[2]`. Although `regPass` and `loginPass` are cleared via `Arrays.fill()`, the underlying string object in the `args` array cannot be modified or cleared, persisting indefinitely in JVM heap memory until garbage collected.

**Fix:**
Never accept passwords as command-line arguments. In CLI mode, accept the username as an argument and prompt the user interactively using `System.console().readPassword()` or standard input, or read the password from a secure redirected stream without echoing to the process table.

```java
                case "register":
                    if (args.length < 2) {
                        System.err.println("Usage: java UserAuthSystem register <username>");
                        System.exit(1);
                    }
                    Console regConsole = System.console();
                    char[] regPass;
                    if (regConsole != null) {
                        regPass = regConsole.readPassword("Enter password for '%s': ", args[1]);
                    } else {
                        regPass = readPassword(null, new Scanner(System.in), "Enter password: ");
                    }
                    if (regPass == null || regPass.length == 0) {
                        System.err.println("[ERROR] Password cannot be empty.");
                        System.exit(1);
                    }
                    try {
                        RegistrationResult regRes = authService.register(args[1], regPass);
                        if (regRes.isSuccess()) {
                            System.out.println("[SUCCESS] " + regRes.getMessage());
                            System.exit(0);
                        } else {
                            System.err.println("[ERROR] " + regRes.getMessage());
                            System.exit(1);
                        }
                    } finally {
                        Arrays.fill(regPass, ' ');
                    }
                    break;

                case "login":
                case "authenticate":
                    if (args.length < 2) {
                        System.err.println("Usage: java UserAuthSystem login <username>");
                        System.exit(1);
                    }
                    Console loginConsole = System.console();
                    char[] loginPass;
                    if (loginConsole != null) {
                        loginPass = loginConsole.readPassword("Enter password for '%s': ", args[1]);
                    } else {
                        loginPass = readPassword(null, new Scanner(System.in), "Enter password: ");
                    }
                    if (loginPass == null || loginPass.length == 0) {
                        System.err.println("[ERROR] Password cannot be empty.");
                        System.exit(1);
                    }
                    try {
                        AuthResult authRes = authService.authenticate(args[1], loginPass);
                        if (authRes.isAuthenticated()) {
                            System.out.println("[SUCCESS] " + authRes.getMessage());
                            System.exit(0);
                        } else {
                            System.err.println("[FAILED] " + authRes.getMessage());
                            System.exit(1);
                        }
                    } finally {
                        Arrays.fill(loginPass, ' ');
                    }
                    break;
```

---

### SEC-02: Insecure File Creation and TOCTOU Permissions Window on Credential Store
- **Severity:** High
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- Location: `UserAuthSystem.java:175-185`

**Vulnerable code:**
```java
// UserAuthSystem.java:175-185
        private void ensureFileExistsWithSecurePermissions() throws IOException {
            if (!Files.exists(filePath)) {
                Files.createFile(filePath);
                try {
                    Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(filePath, permissions);
                } catch (UnsupportedOperationException ignored) {
                    // Windows or filesystems that do not support POSIX permissions
                }
            }
        }
```

**Why it is a problem:**
1. **Non-Atomic Permission Assignment (Race Condition / TOCTOU)**: `Files.createFile(filePath)` creates the credential file using default operating system umask permissions (typically `0644` / `rw-r--r--`, world-readable). `Files.setPosixFilePermissions` is called in a separate subsequent operation. This leaves a time-of-check to time-of-use window during which other local users can open read file descriptors to `credentials.txt` before permissions are restricted.
2. **Pre-Existing Files Ignored**: If `credentials.txt` already exists prior to running the program (e.g. pre-created by a malicious local user with permissive `0666` permissions in a shared folder, or created during a previous run with non-restrictive permissions), `!Files.exists(filePath)` evaluates to `false`, and no permissions are ever checked or enforced.
3. **No Windows / Non-POSIX Access Restriction**: Catching `UnsupportedOperationException` and ignoring it leaves credential files on Windows systems with default inherited ACL permissions, without any attempt to restrict access via `java.io.File` (`setReadable`/`setWritable`) or ACL file attributes.

**Fix:**
Atomically create the file with initial POSIX file permissions (`rw-------` / `0600`) using `PosixFilePermissions.asFileAttribute()`. If the file already exists, enforce and verify the permissions on every invocation. Add fallback permission hardening for non-POSIX environments.

```java
        private void ensureFileExistsWithSecurePermissions() throws IOException {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
            if (!Files.exists(filePath)) {
                try {
                    Files.createFile(filePath, PosixFilePermissions.asFileAttribute(perms));
                    return;
                } catch (UnsupportedOperationException e) {
                    Files.createFile(filePath);
                }
            }
            // Enforce restrictive permissions on both existing and newly created files
            try {
                Files.setPosixFilePermissions(filePath, perms);
            } catch (UnsupportedOperationException e) {
                // Fallback for non-POSIX platforms (e.g., Windows)
                File file = filePath.toFile();
                file.setReadable(false, false);
                file.setWritable(false, false);
                file.setReadable(true, true);
                file.setWritable(true, true);
            }
        }
```

---

### SEC-03: Unauthenticated User Account Enumeration via User List Function
- **Severity:** Medium
- **CWE:** CWE-306: Missing Authentication for Critical Function
- Location: `UserAuthSystem.java:474-480`

**Vulnerable code:**
```java
// UserAuthSystem.java:474-480
                case "list":
                    List<String> users = authService.listRegisteredUsers();
                    System.out.println("Registered users count: " + users.size());
                    for (String user : users) {
                        System.out.println(" - " + user);
                    }
                    break;
```

**Why it is a problem:**
The system incorporates deliberate anti-enumeration mechanisms in the authentication workflow, including constant-time digest comparison (`MessageDigest.isEqual`), dummy PBKDF2 hash computation for non-existent users, and generic failure messages (`"Invalid username or password."`). However, both the CLI `list` command (lines 474-480) and the interactive menu Option 3 (`handleInteractiveList`, lines 625-640) expose an unauthenticated function that directly dumps all registered usernames to anyone who executes the command. This completely defeats the anti-enumeration protections and provides attackers with valid usernames for targeted password spraying and brute-force attacks.

**Fix:**
Remove unauthenticated user listing functionality or restrict access so that only successfully authenticated administrative accounts can inspect user lists.

```java
                case "list":
                    System.err.println("[ERROR] Listing registered accounts requires administrative authentication.");
                    System.exit(1);
                    break;
```

---

### SEC-04: Missing Authentication Rate Limiting and Account Lockout
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- Location: `UserAuthSystem.java:282-320`

**Vulnerable code:**
```java
// UserAuthSystem.java:282-320
        public AuthResult authenticate(String username, char[] password) throws IOException {
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                return AuthResult.failure("Username and password must not be empty.");
            }

            Map<String, UserCredential> users = repository.loadAll();
            UserCredential credential = users.get(username.toLowerCase(Locale.ROOT));

            byte[] saltToUse;
            byte[] expectedHash;

            if (credential != null) {
                saltToUse = credential.getSalt();
                expectedHash = credential.getPasswordHash();
            } else {
                // User not found: compute dummy hash to prevent timing-based user enumeration
                saltToUse = DUMMY_SALT;
                expectedHash = DUMMY_HASH;
            }

            byte[] computedHash;
            try {
                computedHash = hashPassword(password, saltToUse);
            } catch (Exception e) {
                return AuthResult.failure("Authentication error: " + e.getMessage());
            }

            // MessageDigest.isEqual performs constant-time comparison
            boolean matches = MessageDigest.isEqual(computedHash, expectedHash);

            // Clean up temporary computed hash
            Arrays.fill(computedHash, (byte) 0);

            if (credential != null && matches) {
                return AuthResult.success(credential.getUsername());
            } else {
                return AuthResult.failure("Invalid username or password.");
            }
        }
```

**Why it is a problem:**
The `authenticate` method lacks any rate-limiting, failure-counting, or account-lockout controls. An attacker can repeatedly invoke authentication in a rapid automated loop. While PBKDF2 with 65,536 iterations imposes computational overhead, modern hardware can still evaluate hundreds of guesses per second, enabling feasible brute-force attacks against weak or standard user passwords without detection or throttling.

**Fix:**
Track failed login attempts per account. Introduce progressive delays (exponential backoff) and temporarily lock out authentication attempts after a configured threshold of consecutive failures (e.g., 5 attempts).

```java
        private static final int MAX_FAILED_ATTEMPTS = 5;
        private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
        private final Map<String, Integer> failedAttempts = new HashMap<>();
        private final Map<String, Long> lockoutTimestamps = new HashMap<>();

        public synchronized AuthResult authenticate(String username, char[] password) throws IOException {
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                return AuthResult.failure("Username and password must not be empty.");
            }

            String normalizedUser = username.toLowerCase(Locale.ROOT);
            long now = System.currentTimeMillis();
            Long lockoutTime = lockoutTimestamps.get(normalizedUser);
            if (lockoutTime != null) {
                if (now - lockoutTime < LOCKOUT_DURATION_MS) {
                    return AuthResult.failure("Account is temporarily locked due to excessive failed attempts. Please try again later.");
                } else {
                    lockoutTimestamps.remove(normalizedUser);
                    failedAttempts.remove(normalizedUser);
                }
            }

            Map<String, UserCredential> users = repository.loadAll();
            UserCredential credential = users.get(normalizedUser);

            byte[] saltToUse = (credential != null) ? credential.getSalt() : DUMMY_SALT;
            byte[] expectedHash = (credential != null) ? credential.getPasswordHash() : DUMMY_HASH;

            byte[] computedHash;
            try {
                computedHash = hashPassword(password, saltToUse);
            } catch (Exception e) {
                return AuthResult.failure("Authentication error: " + e.getMessage());
            }

            boolean matches = MessageDigest.isEqual(computedHash, expectedHash);
            Arrays.fill(computedHash, (byte) 0);

            if (credential != null && matches) {
                failedAttempts.remove(normalizedUser);
                return AuthResult.success(credential.getUsername());
            } else {
                int attempts = failedAttempts.getOrDefault(normalizedUser, 0) + 1;
                failedAttempts.put(normalizedUser, attempts);
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    lockoutTimestamps.put(normalizedUser, now);
                }
                return AuthResult.failure("Invalid username or password.");
            }
        }
```

---

### SEC-05: Sensitive Password Retained in Immutable String Memory on Scanner Fallback
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- Location: `UserAuthSystem.java:646-657`

**Vulnerable code:**
```java
// UserAuthSystem.java:646-657
    private static char[] readPassword(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            if (scanner.hasNextLine()) {
                return scanner.nextLine().toCharArray();
            } else {
                return null;
            }
        }
    }
```

**Why it is a problem:**
When `System.console()` is unavailable (e.g. within IDE consoles, piped input, or continuous integration environments), `readPassword` falls back to `scanner.nextLine().toCharArray()`. `scanner.nextLine()` creates an immutable `java.lang.String` in the JVM heap. Unlike mutable character arrays (`char[]`), `String` objects cannot be wiped or zeroed after use. The cleartext password remains in memory until collected and overwritten during garbage collection, exposing credentials to memory scraping, swap inspection, or crash dump analysis. Furthermore, `Scanner` does not mask password keystrokes on standard output.

**Fix:**
Read characters directly from `System.in` into a pre-allocated `char[]` buffer without creating intermediate `String` objects, and enforce `System.console()` where terminal masking is required.

```java
    private static char[] readPassword(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                char[] buffer = new char[128];
                int len = 0;
                int ch;
                while ((ch = reader.read()) != -1 && ch != '\n' && ch != '\r') {
                    if (len < buffer.length) {
                        buffer[len++] = (char) ch;
                    }
                }
                char[] result = Arrays.copyOf(buffer, len);
                Arrays.fill(buffer, ' ');
                return result;
            } catch (IOException e) {
                return null;
            }
        }
    }
```

---

### SEC-06: Missing Maximum Password Length Limit Permitting Resource Exhaustion DoS
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- Location: `UserAuthSystem.java:222-230`

**Vulnerable code:**
```java
// UserAuthSystem.java:222-230
        public String validatePassword(char[] password) {
            if (password == null || password.length == 0) {
                return "Password cannot be empty.";
            }
            if (password.length < MIN_PASSWORD_LENGTH) {
                return "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.";
            }
            return null;
        }
```

**Why it is a problem:**
The application enforces a minimum password length of 8 characters, but specifies no upper bound (`MAX_PASSWORD_LENGTH`). PBKDF2 executes 65,536 rounds of HMAC-SHA256 over the input password. If an attacker submits an excessively large password (e.g. megabytes of text via automated scripts or input redirection), `PBEKeySpec` and the underlying hashing routine consume extensive CPU time and memory allocations, creating a potential denial of service (DoS) vector. NIST SP 800-63B recommends establishing an upper limit (e.g., 64 to 128 characters) to prevent algorithmic complexity and resource exhaustion attacks.

**Fix:**
Define a maximum password length (e.g. 128 characters) and reject any password exceeding this limit during input validation.

```java
        private static final int MAX_PASSWORD_LENGTH = 128;

        public String validatePassword(char[] password) {
            if (password == null || password.length == 0) {
                return "Password cannot be empty.";
            }
            if (password.length < MIN_PASSWORD_LENGTH) {
                return "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.";
            }
            if (password.length > MAX_PASSWORD_LENGTH) {
                return "Password must not exceed " + MAX_PASSWORD_LENGTH + " characters.";
            }
            return null;
        }
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing Algorithm**: Verified that passwords are encrypted using `PBKDF2WithHmacSHA256` with 65,536 iterations and 256 derived key bits, avoiding obsolete hash algorithms such as MD5, SHA-1, or unsalted digests (`UserAuthSystem.java:36-39, 338-345`).
- **Cryptographic Salt Quality and Entropy**: Verified that per-user 16-byte random salts are generated using `SecureRandom`, preventing rainbow table attacks and cross-user hash correlation (`UserAuthSystem.java:37, 258-260`).
- **Constant-Time Hash Comparison**: Verified that password verification uses `MessageDigest.isEqual()`, mitigating side-channel timing attacks during hash comparison (`UserAuthSystem.java:310`).
- **Timing Discrepancy Mitigation for Non-Existent Users**: Verified that authentication attempts for unknown usernames still compute a PBKDF2 hash using `DUMMY_SALT` and compare against `DUMMY_HASH`, equalizing execution time across valid and invalid usernames (`UserAuthSystem.java:41-54, 297-307`).
- **Generic Authentication Failure Messages**: Verified that authentication failure responses return a uniform error message (`"Invalid username or password."`) regardless of whether the username exists or the password was incorrect (`UserAuthSystem.java:318`).
- **Sensitive Memory Scrubbing in Key Derivation**: Verified that `PBEKeySpec.clearPassword()` is invoked immediately following key derivation to zero out sensitive password characters from the key specification (`UserAuthSystem.java:343`).
- **Username Delimiter and Injection Prevention**: Verified that `validateUsername` enforces a strict whitelist regex (`^[a-zA-Z0-9._-]{3,30}$`), preventing record injection, newline injection, or colon delimiter corruption in the flat-file database (`UserAuthSystem.java:31-32, 208-216`).
- **Locale-Independent Username Normalization**: Verified that username lookups consistently use `username.toLowerCase(Locale.ROOT)`, preventing internationalization normalization vulnerabilities such as the Turkish dotless 'I' flaw (`UserAuthSystem.java:145, 252, 288`).
- **Defensive Copying of Cryptographic Arrays**: Verified that `UserCredential` performs defensive `.clone()` copies on both `salt` and `passwordHash` arrays in its constructor and getter methods, preventing caller mutation (`UserAuthSystem.java:68-84`).
