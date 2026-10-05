# Security Review: Administrator Portal

## 1. Executive Summary
The component is a Java 17 command-line administrator login that reads one configured username and a salted PBKDF2 password hash from environment variables, verifies credentials, records the result as JSON Lines, and exposes placeholder administrator functions only after successful authentication. Four medium-severity vulnerabilities were identified: login attempts are not throttled, generated and accepted PBKDF2 hashes use an insufficient work factor, credential input and audit records are not safely bounded, and the audit file is opened through attacker-replaceable filesystem paths before its safety and permissions are established. The implementation otherwise uses a cryptographically secure salt, constant-time comparisons, password-array clearing, JSON escaping, file locking, forced writes, and fail-closed audit handling.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AdminPortal.java` | Implements the administrator CLI, credential verification, hash generation, audit logging, and the protected menu. | Reads credentials and configuration; derives PBKDF2-HMAC-SHA256 hashes; compares credentials; clears password buffers; constructs JSON; creates, locks, appends, flushes, and changes permissions on an environment-selected audit file. |
| `README.md` | Documents compilation, credential setup, execution, and audit-log review. | Directs operators to use environment variables or a production secret manager, warns that redirected passwords are visible, and recommends protecting/centralizing audit logs. |
| `prompt.txt` | Records the original implementation request. | Specifies username/password authentication and logging of every successful and unsuccessful attempt; it is not executable. |
| `cyber_prompt.txt` | Records the security-review request and required report format. | Contains review instructions only; it is not executable or consumed by the application. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains no credential, executable code, or runtime configuration. |
| `result.md` | Records metadata and the prior implementation summary. | Describes claimed security controls and test outcomes; it is not executable or consumed by the application. |
| `return.txt` | Stores the prior tool/agent transcript. | Contains historical commands and a sample password hash, but no plaintext production secret; it is not executable or consumed by the application. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every file, identify security-relevant behaviours, select matching specialist skills, and require CWE and file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm and work-factor selection, salt generation, random-number generation, secret handling, comparison behavior, and password-buffer clearing.
- General OWASP Top 10 / CWE knowledge: Applied to brute-force resistance, input/resource limits, authentication flow, JSON audit-log injection, filesystem link handling, audit-file permissions, fail-closed behavior, and authorization placement because no CLI-focused specialist skill matched those behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Authentication attempts are not throttled | Medium | CWE-307 | `AdminPortal.java:65-79` |
| SEC-02 | PBKDF2 work factor is below current guidance | Medium | CWE-916 | `AdminPortal.java:28` |
| SEC-03 | Unbounded credential input can exhaust memory and audit storage | Medium | CWE-400 | `AdminPortal.java:107-124` |
| SEC-04 | Audit logging follows replaceable filesystem paths | Medium | CWE-59 | `AdminPortal.java:197-221` |

## 5. Detailed Findings

### SEC-01: Authentication attempts are not throttled
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AdminPortal.java:65-79`

**Vulnerable code:**
```java
// AdminPortal.java:65-79
        boolean authenticated = false;
        String reason = "invalid_credentials";
        try {
            if (supplied.username().length() > MAX_USERNAME_LENGTH) {
                reason = "invalid_username";
            } else {
                // Verify the password even when the username is wrong. This reduces
                // useful timing differences between unknown users and bad passwords.
                boolean passwordMatches = verifyPassword(
                        supplied.password(), configuredPasswordHash);
                boolean usernameMatches = MessageDigest.isEqual(
                        supplied.username().getBytes(StandardCharsets.UTF_8),
                        configuredUsername.getBytes(StandardCharsets.UTF_8));
                authenticated = usernameMatches & passwordMatches;
            }
```

**Why it is a problem:** Every process invocation performs a password check, and no process-independent attempt counter, cooldown, lockout, or upstream rate limit is consulted. An attacker who can repeatedly invoke the portal can make unlimited online guesses against the single privileged account. Starting concurrent processes also lets the attacker consume CPU through repeated PBKDF2 operations. Because each invocation is a new JVM, an in-memory counter alone would not address the weakness.

**Fix:** Enforce a process-independent limiter in the trusted launcher, authentication service, PAM module, or an OS-protected persistent store. Key it to the account and, when applicable, the source identity; use progressive delays or a bounded temporary lock rather than a permanent denial-of-service-prone lockout. Audit rejected rate-limited attempts without performing PBKDF2. For example, with a shared limiter supplied by the deployment:
```java
// Corrected authentication gate (rateLimiter must use state shared by all JVMs)
        if (!rateLimiter.tryAcquire(configuredUsername)) {
            appendAuditEvent(auditPath, "[rate-limited]", false, "rate_limited");
            System.err.println("Access denied.");
            System.exit(1);
        }

        boolean authenticated = false;
        String reason = "invalid_credentials";
        try {
            boolean passwordMatches = verifyPassword(
                    supplied.password(), configuredPasswordHash);
            boolean usernameMatches = MessageDigest.isEqual(
                    supplied.username().getBytes(StandardCharsets.UTF_8),
                    configuredUsername.getBytes(StandardCharsets.UTF_8));
            authenticated = usernameMatches & passwordMatches;
            rateLimiter.recordResult(configuredUsername, authenticated);
        } finally {
            Arrays.fill(supplied.password(), '\0');
        }
```

### SEC-02: PBKDF2 work factor is below current guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `AdminPortal.java:28,165-167`

**Vulnerable code:**
```java
// AdminPortal.java:28
    private static final int PBKDF2_ITERATIONS = 210_000;
```

```java
// AdminPortal.java:165-167
        int iterations = Integer.parseInt(fields[0]);
        if (iterations < 100_000 || iterations > 10_000_000) {
            throw new IllegalArgumentException("Unsafe iteration count");
```

**Why it is a problem:** The generator uses 210,000 PBKDF2-HMAC-SHA256 iterations, and the verifier accepts hashes with as few as 100,000. Current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) guidance recommends PBKDF2-HMAC-SHA256 with at least 600,000 iterations when PBKDF2 is required. If `ADMIN_PASSWORD_HASH` is disclosed, these lower costs make offline guessing materially cheaper. PBKDF2 remains an acceptable choice when appropriately tuned, and the actual work factor should also be benchmarked so verification remains below roughly one second on the deployment hardware.

**Fix:** Generate new hashes at no less than 600,000 iterations, raise the accepted floor, and rotate the currently configured hash. Prefer Argon2id for a new non-FIPS design when a maintained implementation is available.
```java
// Corrected PBKDF2 parameters and validation
    private static final int PBKDF2_ITERATIONS = 600_000;

        int iterations = Integer.parseInt(fields[0]);
        if (iterations < PBKDF2_ITERATIONS || iterations > 10_000_000) {
            throw new IllegalArgumentException("Unsafe iteration count");
        }
```

### SEC-03: Unbounded credential input can exhaust memory and audit storage
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `AdminPortal.java:107-124,68-69,88`

**Vulnerable code:**
```java
// AdminPortal.java:107-124
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return username == null || password == null ? null : new Credentials(username, password);
        }

        // Useful for redirected input and automated execution. A real terminal uses
        // Console.readPassword above so the password is not displayed.
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        System.out.print("Username: ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        String username = scanner.nextLine();
        System.out.print("Password: ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        return new Credentials(username, scanner.nextLine().toCharArray());
```

```java
// AdminPortal.java:68-69
            if (supplied.username().length() > MAX_USERNAME_LENGTH) {
                reason = "invalid_username";
```

```java
// AdminPortal.java:88
            appendAuditEvent(auditPath, supplied.username(), authenticated, reason);
```

**Why it is a problem:** Both console and redirected-input paths materialize complete, arbitrarily long lines before checking a limit, and there is no password-length limit. Worse, a username rejected for exceeding 128 characters is still copied into the audit event. Repeated oversized attempts can exhaust heap memory or rapidly fill the audit filesystem; once logging fails, all subsequent logins fail closed, creating a persistent availability impact. The username length check therefore does not bound the resources consumed.

**Fix:** Read redirected input with a streaming bounded reader, impose a generous password limit before PBKDF2, clear rejected password arrays, and never log the full value of an overlong identifier. Console input should be checked immediately after the API returns because `Console` does not expose a bounded password-read method.
```java
// Corrected post-read validation and bounded audit value
    private static final int MAX_USERNAME_LENGTH = 128;
    private static final int MAX_PASSWORD_LENGTH = 1_024;

        Credentials supplied = readCredentialsWithBoundedRedirectedInput(
                MAX_USERNAME_LENGTH, MAX_PASSWORD_LENGTH);
        if (supplied == null) {
            System.exit(2);
        }

        boolean usernameTooLong = supplied.username().length() > MAX_USERNAME_LENGTH;
        boolean passwordTooLong = supplied.password().length > MAX_PASSWORD_LENGTH;
        String auditUsername = usernameTooLong ? "[overlong-username]" : supplied.username();
        if (usernameTooLong || passwordTooLong) {
            Arrays.fill(supplied.password(), '\0');
            appendAuditEvent(auditPath, auditUsername, false, "invalid_credentials");
            System.out.println("Access denied.");
            System.exit(1);
        }
```

### SEC-04: Audit logging follows replaceable filesystem paths
- **Severity:** Medium
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following')
- **Location:** `AdminPortal.java:197-221`

**Vulnerable code:**
```java
// AdminPortal.java:197-221
        Path absolutePath = path.toAbsolutePath();
        Path parent = absolutePath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        String event = "{\"timestamp\":\"" + Instant.now()
                + "\",\"username\":\"" + jsonEscape(username)
                + "\",\"result\":\"" + (success ? "SUCCESS" : "FAILURE") + "\""
                + (success ? "" : ",\"reason\":\"" + failureReason + "\"")
                + "}" + System.lineSeparator();

        try (FileChannel channel = FileChannel.open(absolutePath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
             FileLock lock = channel.lock()) {
            if (!lock.isValid()) {
                throw new IOException("Could not lock the audit log");
            }
            ByteBuffer buffer = StandardCharsets.UTF_8.encode(event);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        restrictToOwner(absolutePath);
```

**Why it is a problem:** `toAbsolutePath()` does not canonicalize or reject symbolic links. `FileChannel.open` follows a pre-existing final-component link, and parent components may also be links. If an untrusted user can write the selected audit directory or working directory, that user can redirect the privileged process to append JSON to another file it can access. There is also a race because the channel is closed before `restrictToOwner` resolves the pathname again: the directory entry can be replaced so the permission change targets a different file. Finally, a newly created file receives default permissions until after sensitive event data has been written and closed, and unsupported POSIX permissions are silently ignored at lines 224-231.

**Fix:** Place the log in a pre-created, trusted directory that untrusted users cannot modify; create a new file atomically with owner-only permissions; reject links with `NOFOLLOW_LINKS`; set/verify permissions before writing; and use an appropriate ACL implementation or fail closed on non-POSIX systems. A central append-only logging service is preferable for production integrity.
```java
// Corrected POSIX example; trustedDirectory is provisioned and not writable by untrusted users
        Path trustedDirectory = Path.of("/var/log/my-portal").toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path absolutePath = trustedDirectory.resolve("authentication.jsonl");
        Set<PosixFilePermission> permissions = EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.createFile(absolutePath,
                    PosixFilePermissions.asFileAttribute(permissions));
        } catch (FileAlreadyExistsException expected) {
            if (!Files.isRegularFile(absolutePath, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Audit path is not a regular file");
            }
            Files.getFileAttributeView(absolutePath, PosixFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS).setPermissions(permissions);
        }

        try (FileChannel channel = FileChannel.open(absolutePath,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND,
                LinkOption.NOFOLLOW_LINKS);
             FileLock lock = channel.lock()) {
            ByteBuffer buffer = StandardCharsets.UTF_8.encode(event);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
```

## 6. Verified Controls and Checks With No Finding
- Credential storage: `AdminPortal.java:47-48` loads the username and password hash from deployment configuration rather than hardcoding a plaintext password; `README.md:43-45` recommends a production secret manager.
- Password hashing primitive: `AdminPortal.java:143-149,184-192` uses a unique 16-byte `SecureRandom` salt, PBKDF2-HMAC-SHA256, and a 256-bit derived value; no MD5, SHA-1, DES, RC4, ECB, static salt, or predictable RNG is used.
- Hash parsing bounds: `AdminPortal.java:161-174` requires exactly three fields, bounds the configured iteration count above, and rejects salts shorter than 16 bytes and hashes shorter than 32 bytes.
- Comparison behavior: `AdminPortal.java:71-78,176-180` derives a password result even for an ordinary unknown username, uses `MessageDigest.isEqual` for both comparisons, and uses non-short-circuit `&` so both results are evaluated.
- Password exposure and cleanup: `AdminPortal.java:105-109,150,154-155,180,186-191` hides password input on a real console and clears password and derived-key buffers where the Java APIs permit; neither success nor failure logs contain the password.
- Configuration errors: `AdminPortal.java:52-57,80-82,95-97` rejects missing/malformed credential configuration and does not expose exception details to the user.
- Audit injection: `AdminPortal.java:203-207,234-255` escapes quotes, backslashes, control characters, and newlines before embedding the supplied username in JSON, preventing forged JSONL records.
- Audit durability and concurrency: `AdminPortal.java:209-220` takes an exclusive file lock, completes partial writes in a loop, forces data to storage, and propagates write failures.
- Fail-closed auditing: `AdminPortal.java:87-93` denies access when the authentication event cannot be recorded.
- Authorization placement: `AdminPortal.java:95-101,258-265` reaches administrator functions only after successful authentication and successful audit recording.
- Dangerous sinks and dependencies: No SQL/database access, OS-command execution, object deserialization, dynamic code loading, outbound network/TLS use, third-party dependency, or session/token implementation exists in the reviewed runtime code.
