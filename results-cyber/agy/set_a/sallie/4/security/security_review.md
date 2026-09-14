# Security Review: User Registration & Authentication System

## 1. Executive Summary
The target component is a standalone Java application (`UserAuthSystem`) providing user account registration, persistent credential storage in a local file (`credentials.txt`), and user authentication. Passwords are treated as non-recoverable by deriving keys with PBKDF2-HMAC-SHA256 over 100,000 iterations with a 16-byte cryptographically secure random salt, and hash comparison uses constant-time byte checking with dummy hash calculations to mitigate timing attacks.

Despite these robust cryptographic foundations, several significant security issues were identified during this review. The most critical vulnerabilities include exposing plaintext passwords as command-line arguments (visible in process lists, `/proc` filesystem entries, and shell history files), a non-atomic file creation and permission assignment race condition (TOCTOU) allowing temporary world-readability of the credential database, and an unauthenticated user enumeration command (`list`) that bypasses the timing attack protections built into the authentication flow. Additional findings address concurrent registration race conditions, potential heap memory retention via fallback scanners, and unbounded input lengths.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAuthSystem.java` | Core application source code providing user registration, credential persistence, password hashing, authentication verification, and CLI/interactive console interfaces. | PBKDF2 password hashing, `SecureRandom` salt generation, constant-time comparison, POSIX file permissions handling, in-memory credential clearing, command-line argument processing, and user listing. |
| `README.md` | Plain English documentation detailing application architecture, compilation, usage walkthroughs, and security design justifications. | Documents non-recoverable hashing architecture, permission requirements, and provides CLI usage examples that instruct users to pass passwords as command-line arguments. |
| `README` | Plain text copy of `README.md`. | Same as `README.md`. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives in `UserAuthSystem.java`, evaluating PBKDF2WithHmacSHA256, work factor (100,000 iterations), salt generation via `SecureRandom`, constant-time comparison via `MessageDigest.isEqual`, and dummy hash calculations.
- `testing-api-authentication-weaknesses`: Applied to audit registration and authentication workflows, credential verification logic, password policy validation, and user enumeration defenses.
- `testing-for-sensitive-data-exposure`: Applied to audit credential storage on disk, in-memory credential hygiene (`char[]` zeroing vs immutable `String` retention), and sensitive parameter exposure via command-line arguments.
- `testing-for-broken-access-control`: Applied to audit application commands and menu options, specifically identifying unauthenticated access to the user listing functionality.
- `exploiting-race-condition-vulnerabilities`: Applied to evaluate concurrency controls during registration checks and file creation routines for Time-of-Check to Time-of-Use (TOCTOU) flaws.
- Insecure default permissions, non-atomic file creation, and POSIX permission race conditions reviewed against general OWASP Top 10 / CWE knowledge (CWE-732 / CWE-378 / CWE-276) because no skill specifically covered local file permission race conditions.
- Command-line argument credential exposure in process tables and shell history reviewed against general OWASP Top 10 / CWE knowledge (CWE-214 / CWE-532) because no skill specifically covered CLI process argument sniffing.
- Algorithmic complexity and uncontrolled resource consumption via unbounded inputs reviewed against general OWASP Top 10 / CWE knowledge (CWE-400 / CWE-770).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Exposure of Plaintext Passwords in Process Arguments and Shell History | High | CWE-214 | `UserAuthSystem.java:548-574` |
| SEC-02 | Insecure File Creation and Non-Atomic Permission Assignment Leading to TOCTOU Race Condition | High | CWE-732 | `UserAuthSystem.java:266-280` |
| SEC-03 | Missing Authentication on User Enumeration Functionality | Medium | CWE-306 | `UserAuthSystem.java:429-436` |
| SEC-04 | Concurrency Race Condition (TOCTOU) in User Registration Allowing Duplicate Account Overwrites | Medium | CWE-362 | `UserAuthSystem.java:347-368` |
| SEC-05 | Sensitive Data Exposure in JVM Heap Memory via Fallback Scanner | Low | CWE-316 | `UserAuthSystem.java:757-768` |
| SEC-06 | Unbounded Password Length Enabling Algorithmic Complexity Denial of Service | Low | CWE-400 | `UserAuthSystem.java:317-325` |
| SEC-07 | Unbounded Iteration Count in Credential Deserialization Leading to Resource Exhaustion | Low | CWE-400 | `UserAuthSystem.java:160-176` |

## 5. Detailed Findings

### SEC-01: Exposure of Plaintext Passwords in Process Arguments and Shell History
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `UserAuthSystem.java:548-574`

**Vulnerable code:**
```java
// UserAuthSystem.java:548-574
                    if (args.length < 3) {
                        System.err.println("Usage: java UserAuthSystem register <username> <password>");
                        System.exit(1);
                    }
                    char[] regPass = args[2].toCharArray();
                    RegistrationResult regRes = authService.register(args[1], regPass);
                    Arrays.fill(regPass, '\0'); // Wipe password
                    if (regRes.isSuccess()) {
                        System.out.println("[SUCCESS] " + regRes.getMessage());
                        System.exit(0);
                    } else {
                        System.err.println("[ERROR] " + regRes.getMessage());
                        System.exit(1);
                    }
                    break;

                case "login":
                case "auth":
                case "authenticate":
                    if (args.length < 3) {
                        System.err.println("Usage: java UserAuthSystem login <username> <password>");
                        System.exit(1);
                    }
                    char[] loginPass = args[2].toCharArray();
                    AuthResult authRes = authService.authenticate(args[1], loginPass);
                    Arrays.fill(loginPass, '\0'); // Wipe password
```

**Why it is a problem:**
When `register` or `login` is invoked via direct command-line arguments with `<password>` as `args[2]`, the plaintext password is exposed across multiple surfaces on multi-user systems:
1. Process listing commands (such as `ps aux`, `ps -ef`) and the `/proc/<pid>/cmdline` pseudo-filesystem allow any unprivileged local user to view running command line arguments of other users.
2. Shell history mechanisms (`~/.bash_history`, `~/.zsh_history`) persist executed commands to disk in plaintext, permanently recording the password.
3. System logging frameworks, audit daemons (`auditd`), and process accounting logs record command arguments to persistent system logs.
4. Java passes CLI arguments as immutable `java.lang.String` objects in `args`. Even though the code converts `args[2]` to a `char[]` and wipes it with `Arrays.fill(..., '\0')`, the underlying `String` remains pinned in the JVM heap and cannot be cleared, defeating the in-memory wiping safeguard.

**Fix:**
Remove acceptance of passwords as command-line arguments. Instead, accept only the username on the command line and prompt for the password interactively via `System.console().readPassword()`, or read it securely from standard input without echoing.

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
                        System.err.println("[ERROR] Interactive console required for secure password entry.");
                        System.exit(1);
                        return;
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
                        if (regPass != null) {
                            Arrays.fill(regPass, '\0');
                        }
                    }
                    break;

                case "login":
                case "auth":
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
                        System.err.println("[ERROR] Interactive console required for secure password entry.");
                        System.exit(1);
                        return;
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
                        if (loginPass != null) {
                            Arrays.fill(loginPass, '\0');
                        }
                    }
                    break;
```

### SEC-02: Insecure File Creation and Non-Atomic Permission Assignment Leading to TOCTOU Race Condition
- **Severity:** High
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `UserAuthSystem.java:266-280`

**Vulnerable code:**
```java
// UserAuthSystem.java:266-280
        private void ensureFileExistsWithRestrictedPermissions() throws IOException {
            if (!Files.exists(filePath)) {
                Path parent = filePath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }
                Files.createFile(filePath);
                try {
                    Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(filePath, permissions);
                } catch (UnsupportedOperationException ignored) {
                    // Windows or filesystem without POSIX support
                }
            }
        }
```

**Why it is a problem:**
1. `Files.createFile(filePath)` creates the file using the default system umask (typically `0644` or `0664`, granting world/group read permissions). The restrictive POSIX permissions (`rw-------`) are only applied in a subsequent call on line 275 (`Files.setPosixFilePermissions(filePath, permissions)`). This creates a non-atomic Time-of-Check to Time-of-Use (TOCTOU) race condition where `credentials.txt` exists momentarily with world-readable permissions. Any local attacker or concurrent process can open a file descriptor to `credentials.txt` during this interval.
2. If `credentials.txt` already exists prior to invocation (e.g., pre-created by a local attacker with `0666` permissions, or as a symlink pointing to an unauthorized location), `Files.exists(filePath)` evaluates to `true`. Consequently, permission restriction is skipped entirely, leaving sensitive hashes and salts accessible to unauthorized users.

**Fix:**
Atomically apply restricted permissions (`rw-------`) at file creation time using `PosixFilePermissions.asFileAttribute(permissions)` passed directly to `Files.createFile()`. In addition, if the file already exists, verify that its permissions are strictly restricted to the file owner.

```java
        private void ensureFileExistsWithRestrictedPermissions() throws IOException {
            Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
            if (!Files.exists(filePath)) {
                Path parent = filePath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }
                try {
                    Files.createFile(filePath, PosixFilePermissions.asFileAttribute(permissions));
                } catch (UnsupportedOperationException e) {
                    Files.createFile(filePath);
                }
            } else {
                try {
                    Files.setPosixFilePermissions(filePath, permissions);
                } catch (UnsupportedOperationException ignored) {
                    // Windows or filesystem without POSIX support
                }
            }
        }
```

### SEC-03: Missing Authentication on User Enumeration Functionality
- **Severity:** Medium
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `UserAuthSystem.java:429-436`

**Vulnerable code:**
```java
// UserAuthSystem.java:429-436
        public List<String> listRegisteredUsers() throws IOException {
            Map<String, UserCredential> users = repository.loadAll();
            List<String> list = new ArrayList<>();
            for (UserCredential cred : users.values()) {
                list.add(cred.getUsername());
            }
            return Collections.unmodifiableList(list);
        }
```

**Why it is a problem:**
The system implements sophisticated side-channel defenses during authentication (computing dummy PBKDF2 hashes against a pre-generated salt for nonexistent users and returning uniform error messages to prevent username enumeration). However, `listRegisteredUsers()` completely bypasses these protections by exposing a public, unauthenticated listing mechanism. Any unauthenticated caller can execute `java UserAuthSystem list` or select Option 3 in the interactive menu to obtain the complete directory of registered usernames. Exposing valid usernames facilitates targeted brute-force, dictionary, and password-spraying attacks against existing accounts.

**Fix:**
Remove unauthenticated access to the user listing functionality, or require administrator authentication before releasing user account names.

```java
        public List<String> listRegisteredUsers(String adminUsername, char[] adminPassword) throws IOException {
            AuthResult auth = authenticate(adminUsername, adminPassword);
            if (!auth.isAuthenticated() || !"admin".equalsIgnoreCase(adminUsername)) {
                throw new SecurityException("Unauthorized: administrator authentication required to list users.");
            }
            Map<String, UserCredential> users = repository.loadAll();
            List<String> list = new ArrayList<>();
            for (UserCredential cred : users.values()) {
                list.add(cred.getUsername());
            }
            return Collections.unmodifiableList(list);
        }
```

### SEC-04: Concurrency Race Condition (TOCTOU) in User Registration Allowing Duplicate Account Overwrites
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `UserAuthSystem.java:347-368`

**Vulnerable code:**
```java
// UserAuthSystem.java:347-368
            Map<String, UserCredential> users = repository.loadAll();
            String lookupKey = username.toLowerCase(Locale.ROOT);
            if (users.containsKey(lookupKey)) {
                return RegistrationResult.failure("Username '" + username + "' is already registered.");
            }

            // Generate cryptographically secure random salt
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(salt);

            // Compute irreversible one-way PBKDF2 hash
            byte[] hash;
            try {
                hash = hashPassword(password, salt, ITERATIONS);
            } catch (Exception e) {
                return RegistrationResult.failure("Cryptographic error while hashing password: " + e.getMessage());
            }

            // Store credentials (salt + hash, NEVER plaintext password)
            UserCredential credential = new UserCredential(username, salt, ITERATIONS, hash);
            repository.save(credential);
```

**Why it is a problem:**
The `register` method performs an existence check (`users.containsKey(lookupKey)`), followed by an expensive cryptographic computation (100,000 PBKDF2 iterations), followed by appending the new record (`repository.save(credential)`). The `register` method is not synchronized, nor is there file locking across processes.
If two registration requests for the same username occur concurrently:
1. Both requests read the file via `loadAll()` and observe that the username does not exist.
2. Both derive salts and hashes over several hundred milliseconds.
3. Both call `repository.save()`, appending two separate lines with identical usernames to `credentials.txt`.
4. On subsequent loads, `repository.loadAll()` loops through lines in file order, causing the second line to overwrite the first in the in-memory map. This leads to account hijacking, credential collision, and storage inconsistency.

**Fix:**
Synchronize the registration routine and synchronize access across threads and processes to ensure the uniqueness check and file write form an atomic transaction.

```java
        public synchronized RegistrationResult register(String username, char[] password) throws IOException {
            String userError = validateUsername(username);
            if (userError != null) {
                return RegistrationResult.failure(userError);
            }

            String passError = validatePassword(password);
            if (passError != null) {
                return RegistrationResult.failure(passError);
            }

            synchronized (repository) {
                Map<String, UserCredential> users = repository.loadAll();
                String lookupKey = username.toLowerCase(Locale.ROOT);
                if (users.containsKey(lookupKey)) {
                    return RegistrationResult.failure("Username '" + username + "' is already registered.");
                }

                byte[] salt = new byte[SALT_LENGTH_BYTES];
                secureRandom.nextBytes(salt);

                byte[] hash;
                try {
                    hash = hashPassword(password, salt, ITERATIONS);
                } catch (Exception e) {
                    return RegistrationResult.failure("Cryptographic error while hashing password: " + e.getMessage());
                }

                UserCredential credential = new UserCredential(username, salt, ITERATIONS, hash);
                repository.save(credential);
            }

            return RegistrationResult.success("User '" + username + "' registered successfully.");
        }
```

### SEC-05: Sensitive Data Exposure in JVM Heap Memory via Fallback Scanner
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserAuthSystem.java:757-768`

**Vulnerable code:**
```java
// UserAuthSystem.java:757-768
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
When `System.console()` is null (such as in headless environments, IDE consoles, or redirected input streams), `readPassword` falls back to `scanner.nextLine().toCharArray()`.
`Scanner.nextLine()` creates an immutable `java.lang.String` on the JVM heap. Because `String` objects cannot be modified or zeroed out, the cleartext password remains resident in heap memory until garbage collected. This leaves passwords exposed to memory inspection, process core dumps, and heap dumping attacks.

**Fix:**
Read characters directly from `System.in` into a reusable character buffer without constructing intermediate `String` objects, and clear the buffer immediately after reading.

```java
    private static char[] readPassword(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
            try {
                char[] buffer = new char[256];
                int len = 0;
                int c;
                while ((c = reader.read()) != -1 && c != '\n' && c != '\r') {
                    if (len < buffer.length) {
                        buffer[len++] = (char) c;
                    }
                }
                char[] password = Arrays.copyOf(buffer, len);
                Arrays.fill(buffer, '\0');
                return password;
            } catch (IOException e) {
                return null;
            }
        }
    }
```

### SEC-06: Unbounded Password Length Enabling Algorithmic Complexity Denial of Service
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `UserAuthSystem.java:317-325`

**Vulnerable code:**
```java
// UserAuthSystem.java:317-325
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
The password validation enforces a minimum length of 8 characters, but does not enforce any maximum length limit. Because PBKDF2 executes 100,000 HMAC-SHA256 iterations over the input password, submitting an excessively large password (e.g., several megabytes) causes disproportionate CPU and memory consumption. An attacker could exploit this to trigger algorithmic complexity Denial of Service (DoS) and exhaust server compute resources.

**Fix:**
Enforce an upper bound on password length (e.g., 128 characters, as recommended by NIST SP 800-63B and OWASP) in `validatePassword`.

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

### SEC-07: Unbounded Iteration Count in Credential Deserialization Leading to Resource Exhaustion
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `UserAuthSystem.java:160-176`

**Vulnerable code:**
```java
// UserAuthSystem.java:160-176
            // Expected format: username:saltBase64:iterations:hashBase64
            String[] parts = trimmed.split(":", 4);
            if (parts.length == 4) {
                try {
                    String username = parts[0].trim();
                    Base64.Decoder decoder = Base64.getDecoder();
                    byte[] salt = decoder.decode(parts[1].trim());
                    int iterations = Integer.parseInt(parts[2].trim());
                    byte[] hash = decoder.decode(parts[3].trim());
                    if (username.isEmpty() || salt.length == 0 || hash.length == 0 || iterations <= 0) {
                        return null;
                    }
                    return new UserCredential(username, salt, iterations, hash);
                } catch (Exception e) {
                    return null;
                }
            }
```

**Why it is a problem:**
When parsing credentials from storage, `deserialize` accepts any positive integer for `iterations`. If the storage file is tampered with or contains an entry with an arbitrarily large iteration count (e.g. `Integer.MAX_VALUE`), attempting to authenticate as that user will cause `hashPassword` to execute billions of iterations, freezing the execution thread and exhausting CPU resources.

**Fix:**
Enforce upper and lower bounds on `iterations` during deserialization (e.g., between 10,000 and 1,000,000 iterations).

```java
            // Expected format: username:saltBase64:iterations:hashBase64
            String[] parts = trimmed.split(":", 4);
            if (parts.length == 4) {
                try {
                    String username = parts[0].trim();
                    Base64.Decoder decoder = Base64.getDecoder();
                    byte[] salt = decoder.decode(parts[1].trim());
                    int iterations = Integer.parseInt(parts[2].trim());
                    byte[] hash = decoder.decode(parts[3].trim());
                    if (username.isEmpty() || salt.length == 0 || hash.length == 0 
                            || iterations < 10000 || iterations > 1000000) {
                        return null;
                    }
                    return new UserCredential(username, salt, iterations, hash);
                } catch (Exception e) {
                    return null;
                }
            }
```

## 6. Verified Controls and Checks With No Finding
- Password Hashing Primitive: Verified that PBKDF2 with HMAC-SHA256 (`PBKDF2WithHmacSHA256`) is used with 100,000 iterations and a 256-bit derived key (`UserAuthSystem.java:77-81, 443-452`). Passwords are never stored in plaintext or reversible encryption, complying with NIST SP 800-63B guidelines.
- Cryptographic Salt Generation: Verified that a unique 16-byte (128-bit) salt is generated using `java.security.SecureRandom` for each registered account (`UserAuthSystem.java:78, 354-355`), preventing rainbow table attacks.
- Constant-Time Hash Comparison: Verified that hash verification uses `MessageDigest.isEqual(...)` (`UserAuthSystem.java:412`), which compares byte arrays in constant time and prevents side-channel timing analysis on hash byte contents.
- User Enumeration Mitigation in Authentication: Verified that `AuthService.authenticate` computes a full 100,000-iteration dummy hash using `DUMMY_SALT` and `DUMMY_HASH` when an unknown username is provided (`UserAuthSystem.java:398-409`), equalizing execution time between valid and invalid usernames.
- Uniform Authentication Error Responses: Verified that `AuthService.authenticate` returns `"Invalid username or password."` (`UserAuthSystem.java:422`) for both non-existent users and invalid passwords, preventing discrepancy-based enumeration during login.
- Key Specification Memory Hygiene: Verified that `PBEKeySpec.clearPassword()` is invoked in a `finally` block in `hashPassword` (`UserAuthSystem.java:450`), and `computedHash` byte arrays are zeroed with `Arrays.fill(computedHash, (byte) 0)` (`UserAuthSystem.java:415`).
- SQL / NoSQL Injection Immunity: Verified that no SQL or NoSQL database queries exist in the codebase. Persistence is file-based, and usernames are strictly validated against `^[a-zA-Z0-9._-]{3,30}$` (`UserAuthSystem.java:71`), preventing record delimiter or newline injection into `credentials.txt`.
- Data Model Encapsulation: Verified that `UserCredential` defends against mutable state leakage by defensively cloning salt and password hash byte arrays in its constructor and getter methods (`UserAuthSystem.java:114, 116, 124, 132`).
