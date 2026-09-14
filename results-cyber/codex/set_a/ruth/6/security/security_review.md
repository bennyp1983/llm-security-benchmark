# Security Review: Java Authentication Example

## 1. Executive Summary
`AuthenticationApp.java` is a self-contained console login demonstration. It reads a username and password, normalizes the username, verifies a PBKDF2-HMAC-SHA-256 password hash from an in-memory account store, and writes sanitized authentication events to a local audit log. The review found six vulnerabilities. The most important is that the executable contains fixed demo accounts whose working passwords are published with the application. The password KDF also uses too little work for PBKDF2-HMAC-SHA-256, and authentication attempts are not persistently limited. Lower-severity issues affect audit-log permissions, plaintext password lifetime in the non-console fallback, and disclosure of internal exception details.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthenticationApp.java` | Implements the console application, credential input, in-memory account store, password verification, and audit logging. | Accepts untrusted username/password input; hashes passwords with PBKDF2; compares hashes in constant time; embeds account records; normalizes usernames; sanitizes usernames for logs; creates and appends to a log file; prints error details. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory and understand all source code, identify security-relevant behavior, route the review to specialized skills, and require CWE/file-and-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to the PBKDF2 algorithm, work factor, hash length, salts, fixed credential material, secret handling, and constant-time comparison.
- `testing-for-sensitive-data-exposure`: Applied to embedded credentials, password handling in memory and at the terminal, audit-log contents, filesystem storage, and user-visible error output.
- General OWASP Top 10 / CWE review: Applied to authentication attempt throttling, input normalization, account-enumeration resistance, log injection, audit-file permissions, denial-of-service exposure, and exception handling because no closer specialized non-API skill matched those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Fixed demonstration credentials are usable at runtime | High | CWE-798 | `AuthenticationApp.java:192-203` |
| SEC-02 | PBKDF2-HMAC-SHA-256 uses an insufficient work factor | Medium | CWE-916 | `AuthenticationApp.java:220-234` |
| SEC-03 | Authentication attempts have no persistent throttling or lockout | Medium | CWE-307 | `AuthenticationApp.java:46-47` |
| SEC-04 | Audit log is created without explicit restrictive permissions | Low | CWE-732 | `AuthenticationApp.java:98-109` |
| SEC-05 | Fallback input stores and may expose the plaintext password | Low | CWE-316 | `AuthenticationApp.java:85-95` |
| SEC-06 | Internal exception details are disclosed to the user | Low | CWE-209 | `AuthenticationApp.java:61-68` |

## 5. Detailed Findings

### SEC-01: Fixed demonstration credentials are usable at runtime
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AuthenticationApp.java:192-203`

**Vulnerable code:**
```java
// AuthenticationApp.java:192-203
        static AccountStore demo() {
            Map<String, Account> records = new HashMap<>();
            records.put("alice", new Account(
                    hex("54c0f1dc0c8a5542d7f970f53dc4c572"),
                    hex("0e9032fbd50e0af19849146d2f85561c"
                            + "98b843684fc121ad4b665a93eb31891b")));
            records.put("bob", new Account(
                    hex("976d286129ec9402c572575f5d31591a"),
                    hex("b9b36fbdc9d9739141d0fec76b4d811c"
                            + "5e94fa38d6b749ad3a95a36639f29457")));
            return new AccountStore(records);
        }
```

**Why it is a problem:** The application always instantiates these two accounts, and the repository documentation publishes their plaintext passwords. Recomputing PBKDF2-HMAC-SHA-256 with the configured 210,000 iterations confirms that the published passwords match these embedded records. Anyone with the distributed application or documentation therefore has valid credentials. The credentials cannot be revoked or rotated without changing and redistributing the program. Calling the store a demonstration does not protect a build that is accidentally deployed or reused.

**Fix:** Remove all usable demo accounts from runtime code. Require an externally provisioned identity store in every non-test execution, inject it into the application, and keep test fixtures in test-only sources that cannot be packaged into the production artifact.
```java
AccountStore accounts = AccountStore.fromIdentityStore(
        Objects.requireNonNull(System.getenv("AUTH_IDENTITY_STORE"),
                "AUTH_IDENTITY_STORE must be configured"));
Authenticator authenticator = new Authenticator(accounts);
```

### SEC-02: PBKDF2-HMAC-SHA-256 uses an insufficient work factor
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `AuthenticationApp.java:220-234`

**Vulnerable code:**
```java
// AuthenticationApp.java:220-234
    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 210_000;
        private static final int KEY_LENGTH_BITS = 256;

        private PasswordHasher() {
        }

        static byte[] hash(char[] password, byte[] salt)
                throws GeneralSecurityException {
            PBEKeySpec spec = new PBEKeySpec(
                    password, salt, ITERATIONS, KEY_LENGTH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM)
                        .generateSecret(spec).getEncoded();
```

**Why it is a problem:** The value 210,000 corresponds to the lower work factor commonly used with PBKDF2-HMAC-SHA-512, while current OWASP password-storage guidance recommends 600,000 or more iterations for PBKDF2-HMAC-SHA-256. If the hashes are obtained from the binary, source, logs, backups, or a future identity store, the lower cost makes offline guessing materially cheaper. The 16-byte per-account salts and 256-bit output are otherwise appropriate.

**Fix:** Benchmark on production hardware and use at least the current guidance for the selected PRF. Store the algorithm and work factor with every record so the value can be increased over time, and rehash successfully authenticated passwords whose stored parameters are obsolete. Existing demo hashes must be regenerated after changing the work factor.
```java
private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
private static final int ITERATIONS = 600_000;
private static final int KEY_LENGTH_BITS = 256;
```

### SEC-03: Authentication attempts have no persistent throttling or lockout
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AuthenticationApp.java:46-47`

**Vulnerable code:**
```java
// AuthenticationApp.java:46-47
            Authenticator authenticator = new Authenticator(AccountStore.demo());
            boolean authenticated = authenticator.authenticate(credentials.username, password);
```

**Why it is a problem:** Every process invocation performs an authentication attempt immediately. There is no delay, attempt counter, lockout, or persistent rate limit, so an attacker able to invoke the application can automate guesses indefinitely. An in-memory limiter would be insufficient because restarting this short-lived process would reset it. PBKDF2 raises the cost of each guess but does not replace online attempt controls.

**Fix:** Enforce a persistent limiter before verification, keyed using an appropriate combination of account and trusted client/device identity. Use bounded exponential backoff or a temporary lock, avoid permanent attacker-triggered account denial of service, record the result atomically, and retain the same generic response for unknown and known accounts.
```java
String principal = normalizeUsername(credentials.username);
if (!attemptLimiter.tryAcquire(principal)) {
    auditLogger.warning("event=authentication outcome=failure reason=rate_limited");
    System.out.println("Authentication failed: invalid username or password.");
    return;
}
boolean authenticated = authenticator.authenticate(principal, password);
attemptLimiter.recordResult(principal, authenticated); // persistent, atomic storage
```

### SEC-04: Audit log is created without explicit restrictive permissions
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AuthenticationApp.java:98-109`

**Vulnerable code:**
```java
// AuthenticationApp.java:98-109
    private static Logger createAuditLogger(Path logPath) throws IOException {
        Logger logger = Logger.getLogger("authentication.audit");
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.INFO);

        // Avoid adding duplicate handlers if main is invoked more than once in a JVM.
        Arrays.stream(logger.getHandlers()).forEach(logger::removeHandler);
        FileHandler handler = new FileHandler(logPath.toString(), true);
        handler.setEncoding(StandardCharsets.UTF_8.name());
        handler.setFormatter(new SimpleFormatter());
        logger.addHandler(handler);
        return logger;
```

**Why it is a problem:** `FileHandler` opens a relative pathname and the application never establishes or verifies owner-only permissions. The resulting access depends on the launch directory, platform defaults, and process umask. Other local users may be able to read usernames and authentication outcomes or alter/replace the audit trail. A predictable relative path also makes secure operational ownership harder to guarantee.

**Fix:** Put the log in an administrator-controlled directory, reject symbolic links, create it with owner-only permissions, and verify permissions before opening it. On non-POSIX systems, apply the equivalent ACL. Prefer a protected system logging service when available.
```java
Path secureLog = Path.of("/var/log/authentication-app/authentication.log");
if (Files.isSymbolicLink(secureLog)) {
    throw new IOException("Refusing symbolic-link audit log");
}
Set<PosixFilePermission> ownerOnly = EnumSet.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
if (Files.notExists(secureLog, LinkOption.NOFOLLOW_LINKS)) {
    Files.createFile(secureLog, PosixFilePermissions.asFileAttribute(ownerOnly));
}
Files.setPosixFilePermissions(secureLog, ownerOnly);
FileHandler handler = new FileHandler(secureLog.toString(), true);
```

### SEC-05: Fallback input stores and may expose the plaintext password
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `AuthenticationApp.java:85-95`

**Vulnerable code:**
```java
// AuthenticationApp.java:85-95
        // Useful for redirected input and IDEs. A terminal should use Console so
        // that the password is not echoed.
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        System.err.println("Warning: no system console; password input may be visible.");
        System.out.print("Username: ");
        String username = reader.readLine();
        System.out.print("Password: ");
        String passwordLine = reader.readLine();
        return new Credentials(username,
                passwordLine == null ? null : passwordLine.toCharArray());
```

**Why it is a problem:** When no `Console` is available, the password may be echoed by the terminal or IDE and is first stored in an immutable `String`. Converting it to `char[]` creates a second copy; wiping the array in `finally` cannot erase the `String`, which remains in heap memory until garbage collection and may be recovered from a memory dump. Printing a warning does not prevent the exposure.

**Fix:** Fail closed when masked console input is unavailable. If non-interactive operation is required, use a deliberately configured secret-input mechanism that supplies mutable bytes/characters without terminal echo, define its trust boundary, and wipe its buffers promptly.
```java
private static Credentials readCredentials() throws IOException {
    Console console = System.console();
    if (console == null) {
        throw new IOException("Secure console input is required");
    }
    String username = console.readLine("Username: ");
    char[] password = console.readPassword("Password: ");
    return new Credentials(username, password);
}
```

### SEC-06: Internal exception details are disclosed to the user
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `AuthenticationApp.java:61-68`

**Vulnerable code:**
```java
// AuthenticationApp.java:61-68
        } catch (IOException | GeneralSecurityException | IllegalArgumentException ex) {
            if (auditLogger != null) {
                auditLogger.log(Level.SEVERE,
                        "event=authentication outcome=error source=" + SOURCE
                                + " error_type=" + ex.getClass().getSimpleName());
            }
            System.err.println("Unable to complete authentication: " + ex.getMessage());
            System.exit(1);
```

**Why it is a problem:** Exception messages from log-file creation, character encoding, cryptographic providers, or malformed configuration may contain filesystem paths, provider details, or other operational information. Sending those details to an untrusted caller helps reconnaissance and creates inconsistent information-disclosure behavior. The audit record already records a safe exception type without the sensitive message.

**Fix:** Return a generic message to the caller. Send diagnostic details only to a protected operational channel, with deliberate redaction and an internal correlation identifier.
```java
auditLogger.log(Level.SEVERE,
        "event=authentication outcome=error source=" + SOURCE
                + " error_type=" + ex.getClass().getSimpleName());
System.err.println("Unable to complete authentication.");
System.exit(1);
```

## 6. Verified Controls and Checks With No Finding
- Password hashing primitives: Verified `PBKDF2WithHmacSHA256`, a 256-bit derived value, and distinct 128-bit salts for the two records at `AuthenticationApp.java:194-201` and `AuthenticationApp.java:220-234`; only the work factor produced a finding.
- Constant-time verification: Verified `MessageDigest.isEqual` compares derived and expected hashes at `AuthenticationApp.java:175-179`, and the temporary derived hash is wiped in a `finally` block.
- Username-enumeration resistance: Verified missing users still incur the PBKDF2 operation using a dummy salt/hash at `AuthenticationApp.java:153-180`, and success/failure output does not distinguish an unknown user from a wrong password at `AuthenticationApp.java:50-60`.
- Password cleanup: Verified the mutable password array is wiped in `main` at `AuthenticationApp.java:69-72` and the `PBEKeySpec` internal password is cleared at `AuthenticationApp.java:230-237`; the immutable fallback `String` is reported separately in SEC-05.
- Log injection: Verified usernames are capped at 128 code points and carriage returns, line feeds, tabs, quotes, backslashes, and ISO control characters are replaced at `AuthenticationApp.java:123-139`.
- Secret logging: Verified audit events do not include the supplied password, salts, hashes, exception message, or stack trace at `AuthenticationApp.java:49-65`.
- Username canonicalization: Verified trimming and locale-independent lowercasing at `AuthenticationApp.java:241-243`, preventing locale-dependent account lookup behavior.
- Mutable record isolation: Verified salts and password hashes are cloned when account records are constructed at `AuthenticationApp.java:210-217`, and the account map is defensively copied and made unmodifiable at `AuthenticationApp.java:185-190`.
- Injection and unsafe execution sinks: Verified there is no SQL construction, shell/process execution, dynamic code loading, object deserialization, template/HTML output, or attacker-controlled file path in the source.
- Network and session security: Verified the component has no network listener/client, TLS configuration, cookies, JWTs, or session tokens, so those control classes are not applicable.
