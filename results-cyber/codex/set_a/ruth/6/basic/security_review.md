# Security Review: Java Authentication Example

## 1. Executive Summary
`AuthenticationApp.java` is a dependency-free command-line authenticator that creates a local properties-based account store, verifies passwords with salted PBKDF2-HMAC-SHA256, and appends authentication outcomes to a local audit log. The most serious issue is an active, publicly documented demonstration account whose password is hard-coded into the application. The review also found that the account database is created without guaranteed restrictive permissions, authentication attempts are not limited, the non-console fallback visibly captures the password in an immutable `String`, password-hash parameters loaded from disk are not bounded, and the audit log is opened without guaranteed restrictive permissions. These issues could enable unauthorized access, offline password attacks, brute force, credential exposure, or local denial of service depending on how and where the program is deployed.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthenticationApp.java` | Implements credential input, account creation/loading, password verification, and audit logging. | Handles plaintext passwords; derives and compares password hashes; creates and reads the account database; creates and appends to a log; processes attacker-controlled usernames and stored hash parameters. |
| `README.md` | Documents the application, its default account, generated files, and execution procedure. | Publicly discloses the bundled default credential and warns that file permissions, rate limiting, and production enrollment are external concerns. |
| `cyber_prompt.txt` | Records the requested security-review task and report format. | Contains no executable behavior or secret; defines the audit requirements. |
| `prompt.txt` | Records the original implementation request. | Contains no executable behavior or credential material. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains no executable behavior; the digest is not used as a credential or security control. |
| `result.md` | Summarizes the prior code-generation run. | Contains no executable behavior; describes security claims that were verified against the source. |
| `return.txt` | Stores the prior tool transcript and test output. | Contains no executable behavior; repeats the public demonstration credential and authentication-log examples. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the required routing workflow to inventory every file, identify security-relevant behavior, select specialized skills, and require CWE/file:line evidence.
- `implementing-secret-scanning-with-gitleaks`: Applied to source and documentation for embedded passwords, tokens, keys, and other credential material.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm selection, iteration count, salt generation, derived-key length, constant-time comparison, secret lifetime, and parameters loaded from storage.
- `implementing-api-rate-limiting-and-throttling`: Applied to the login path's resistance to brute force and resource-exhaustion attempts; its authentication-attempt principles were adapted to this CLI application.
- General OWASP Top 10 / CWE knowledge: Applied to terminal credential input, local file permissions, audit-log protection, log injection, error handling, account enumeration, and resource-consumption boundaries because no closer Java-specific sibling skill matched those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Application ships an active hard-coded default credential | High | CWE-798 | `AuthenticationApp.java:129` |
| SEC-02 | Account database is created without restrictive permissions | Medium | CWE-732 | `AuthenticationApp.java:149` |
| SEC-03 | Authentication attempts are not rate-limited | Medium | CWE-307 | `AuthenticationApp.java:45` |
| SEC-04 | Fallback input visibly reads the password into an immutable string | Medium | CWE-522 | `AuthenticationApp.java:77` |
| SEC-05 | Stored password-hash work factors and sizes are not bounded | Low | CWE-400 | `AuthenticationApp.java:169` |
| SEC-06 | Authentication log is opened without restrictive permissions | Low | CWE-732 | `AuthenticationApp.java:88` |

## 5. Detailed Findings

### SEC-01: Application ships an active hard-coded default credential
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AuthenticationApp.java:129-130`

**Vulnerable code:**
```java
// AuthenticationApp.java:129-130
        private static final String DEMO_USERNAME = "demo";
        private static final char[] DEMO_PASSWORD = "changeMe123!".toCharArray();
```

**Why it is a problem:** On first run, the application automatically provisions this account and accepts its fixed password. The same credential is published in `README.md:17-20` and repeated in `return.txt`, so anyone who can reach an unchanged deployment can authenticate as `demo`. Printing a warning does not make the credential safe or force replacement, and clearing the array after account creation cannot undo its presence in source, bytecode, repository history, and documentation.

**Fix:** Do not create an account from a bundled password. Require an explicit administrative enrollment step that receives the initial secret from a protected console or identity provider, and fail closed when no account store has been provisioned. Remove the credential from source and documentation; if it was ever used outside an isolated demonstration, rotate it.
```java
        private static final String DEMO_USERNAME = "demo";

        static AccountStore open(Path path) throws IOException, GeneralSecurityException {
            if (Files.notExists(path)) {
                throw new IOException(
                        "Account store is not provisioned; run the administrative enrollment tool");
            }
            Properties accounts = new Properties();
            try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                accounts.load(reader);
            }
            return new AccountStore(accounts);
        }
```

### SEC-02: Account database is created without restrictive permissions
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AuthenticationApp.java:149-150`

**Vulnerable code:**
```java
// AuthenticationApp.java:149-150
                try (var writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
```

**Why it is a problem:** The account store contains salts and password hashes and determines which accounts can authenticate, but it is created with permissions inherited from the platform and process umask. A commonly produced world-readable file exposes hashes to offline cracking; a permissive deployment could also allow another local user to replace account records and gain access. README advice to restrict access does not enforce the control.

**Fix:** Place the store in a trusted application-data directory and create it atomically with owner-only permissions. On platforms without POSIX permissions, apply an equivalent owner-only ACL and fail provisioning if that cannot be guaranteed.
```java
                Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
                Files.createFile(path, PosixFilePermissions.asFileAttribute(ownerOnly));
                try (var writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                        StandardOpenOption.WRITE)) {
                    accounts.store(writer,
                            "username=PBKDF2 iterations:Base64 salt:Base64 hash");
                }
```

### SEC-03: Authentication attempts are not rate-limited
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AuthenticationApp.java:45-58`

**Vulnerable code:**
```java
// AuthenticationApp.java:45-58
            try {
                boolean authenticated = accounts.verify(
                        submitted.username(), submitted.password());
                String safeUsername = sanitizeForLog(submitted.username());

                if (authenticated) {
                    AUDIT_LOG.log(Level.INFO,
                            "Authentication succeeded for user \"{0}\"", safeUsername);
                    System.out.println("Login successful. Welcome, " + submitted.username() + ".");
                } else {
                    AUDIT_LOG.log(Level.WARNING,
                            "Authentication failed for user \"{0}\"", safeUsername);
                    System.out.println("Login failed: invalid username or password.");
                }
```

**Why it is a problem:** Every process invocation is allowed to perform a password check, with no delay, lockout, quota, or durable failure counter. An attacker able to invoke the authentication interface repeatedly can automate password guessing and consume CPU through the intentionally expensive PBKDF2 operation. Because this is a one-shot CLI, a purely in-memory counter would reset on every launch and would not be sufficient.

**Fix:** Enforce a durable, tamper-resistant attempt policy before hashing, keyed by both the claimed account and an appropriate caller identity. Record failures atomically across processes, introduce bounded backoff or temporary lockout, clear the account counter on success, and keep the response generic. The limiter's own storage must not reveal whether an account exists.
```java
            try {
                AttemptDecision decision = ATTEMPT_LIMITER.check(
                        submitted.username(), callerIdentity());
                if (!decision.allowed()) {
                    AUDIT_LOG.log(Level.WARNING, "Authentication throttled");
                    System.out.println("Login failed: invalid username or password.");
                    return;
                }

                boolean authenticated = accounts.verify(
                        submitted.username(), submitted.password());
                ATTEMPT_LIMITER.recordResult(
                        submitted.username(), callerIdentity(), authenticated);
                if (authenticated) {
                    System.out.println("Login successful.");
                } else {
                    System.out.println("Login failed: invalid username or password.");
                }
```

### SEC-04: Fallback input visibly reads the password into an immutable string
- **Severity:** Medium
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `AuthenticationApp.java:77-85`

**Vulnerable code:**
```java
// AuthenticationApp.java:77-85
        // IDEs and redirected processes often do not expose a Console.
        BufferedReader input = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        System.out.print("Username: ");
        String username = input.readLine();
        System.out.print("Password (input will be visible): ");
        String password = input.readLine();
        return new Credentials(username == null ? "" : username,
                password == null ? new char[0] : password.toCharArray());
```

**Why it is a problem:** When `System.console()` is unavailable, the password is echoed on interactive terminals and can be observed or captured by terminal recording. It is also first stored in an immutable `String` that cannot be wiped; clearing the later `char[]` leaves the original password in heap memory until garbage collection. Warning the user that input is visible acknowledges but does not prevent the exposure.

**Fix:** Fail closed when a protected console is unavailable, or integrate a terminal library that disables echo and returns mutable character data. For non-interactive automation, use a protected credential channel rather than standard input or command-line arguments.
```java
        Console console = System.console();
        if (console == null) {
            throw new IOException("A protected interactive console is required");
        }
        String username = console.readLine("Username: ");
        char[] password = console.readPassword("Password: ");
        return new Credentials(username == null ? "" : username,
                password == null ? new char[0] : password);
```

### SEC-05: Stored password-hash work factors and sizes are not bounded
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `AuthenticationApp.java:169-178`

**Vulnerable code:**
```java
// AuthenticationApp.java:169-178
                String[] fields = stored.split(":", -1);
                if (fields.length != 3) {
                    throw new GeneralSecurityException("Invalid account record format");
                }

                int iterations = Integer.parseInt(fields[0]);
                byte[] salt = Base64.getDecoder().decode(fields[1]);
                byte[] expectedHash = Base64.getDecoder().decode(fields[2]);
                byte[] submittedHash = hash(password, salt, iterations,
                        expectedHash.length * Byte.SIZE);
```

**Why it is a problem:** The account file controls the PBKDF2 iteration count and derived-key size. The validation in `hash` rejects only values that are too small or misaligned; it imposes no upper bound. A corrupted or locally supplied record can therefore request an extreme amount of CPU or memory and make authentication unavailable. Oversized Base64 fields also allocate before their decoded lengths are validated.

**Fix:** Bound the account-file size before loading it, restrict encoded-field lengths before decoding, and accept only an approved iteration range plus the expected salt and hash sizes. Treat out-of-policy records as configuration errors without attempting their KDF.
```java
                String[] fields = stored.split(":", -1);
                if (fields.length != 3 || fields[1].length() != 24
                        || fields[2].length() != 44) {
                    throw new GeneralSecurityException("Invalid account record format");
                }

                int iterations = Integer.parseInt(fields[0]);
                if (iterations < 210_000 || iterations > 2_000_000) {
                    throw new GeneralSecurityException("Password hash work factor is out of policy");
                }
                byte[] salt = Base64.getDecoder().decode(fields[1]);
                byte[] expectedHash = Base64.getDecoder().decode(fields[2]);
                if (salt.length != SALT_BYTES || expectedHash.length != HASH_BITS / Byte.SIZE) {
                    throw new GeneralSecurityException("Invalid password hash dimensions");
                }
                byte[] submittedHash = hash(password, salt, iterations, HASH_BITS);
```

### SEC-06: Authentication log is opened without restrictive permissions
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AuthenticationApp.java:88-90`

**Vulnerable code:**
```java
// AuthenticationApp.java:88-90
    private static void configureAuditLog() throws IOException {
        Files.createDirectories(LOG_FILE.toAbsolutePath().getParent());
        FileHandler handler = new FileHandler(LOG_FILE.toString(), true);
```

**Why it is a problem:** `FileHandler` creates or opens the audit log using platform defaults, so the program does not guarantee that authentication usernames, outcomes, and timestamps are confidential or protected from modification. In a permissive working directory or under a permissive umask, another local user may read sensitive activity or alter audit evidence.

**Fix:** Keep logs in a trusted directory, create the log with owner-only permissions before passing it to `FileHandler`, reject symbolic links and non-regular files, and use an equivalent restrictive ACL on non-POSIX systems. A production service should additionally forward records to access-controlled centralized storage.
```java
    private static void configureAuditLog() throws IOException {
        Path log = LOG_FILE.toAbsolutePath();
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        if (Files.notExists(log, LinkOption.NOFOLLOW_LINKS)) {
            Files.createFile(log, PosixFilePermissions.asFileAttribute(ownerOnly));
        } else if (Files.isSymbolicLink(log) || !Files.isRegularFile(log, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Audit log must be a regular, non-symbolic-link file");
        }
        Files.setPosixFilePermissions(log, ownerOnly);
        FileHandler handler = new FileHandler(log.toString(), true);
```

## 6. Verified Controls and Checks With No Finding
- Password hashing: `AuthenticationApp.java:125-128` and `188-212` use a 16-byte `SecureRandom` salt, PBKDF2-HMAC-SHA256, 210,000 iterations, and a 256-bit derived value; no deprecated hash, predictable RNG, static salt, or reversible password storage was found.
- Constant-time verification: `AuthenticationApp.java:179` uses `MessageDigest.isEqual` rather than ordinary array or string equality.
- Username-enumeration resistance: `AuthenticationApp.java:133-139` and `163-185` use a syntactically equivalent dummy credential for unknown users and return a generic failure response at line 57. No direct “unknown user” disclosure was found.
- Log injection: `AuthenticationApp.java:48`, `55-56`, and `106-115` replace ISO control characters and truncate logged usernames to 100 characters before parameterized logging.
- Password logging: The audit messages at `AuthenticationApp.java:51-56` contain only the outcome and sanitized username; submitted passwords and hashes are not logged.
- Secret cleanup: `AuthenticationApp.java:59-61`, `118-121`, `153-155`, `196-198`, and `206-212` clear mutable password or derived-hash buffers where practical. The immutable fallback `String` is separately reported as SEC-04.
- Account-record parsing: `AuthenticationApp.java:169-183` rejects an incorrect field count, invalid integers, and malformed Base64 rather than accepting a malformed credential. Missing upper bounds are separately reported as SEC-05.
- Account-file creation race: `AuthenticationApp.java:149-150` uses `CREATE_NEW`, preventing silent overwrite of an already existing pathname during first-run creation.
- Authentication result disclosure: `AuthenticationApp.java:54-57` returns the same user-facing message for an invalid username and an invalid password.
- Exception scope: `AuthenticationApp.java:62-65` terminates on account-store, logging, or cryptographic initialization errors rather than continuing in an insecure partially initialized state; no stack trace or credential data is emitted.
- SQL injection, command injection, path traversal, deserialization, SSRF, XSS, TLS, JWT, and session management: No database, operating-system command, attacker-selected path, object deserialization, network, HTML, token, or session functionality exists in the reviewed code.
