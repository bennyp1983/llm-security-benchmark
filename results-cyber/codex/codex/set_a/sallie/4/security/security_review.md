# Security Review: Java User Account Program

## 1. Executive Summary
The component is a Java 11 command-line account-registration and authentication program backed by a local `accounts.db` text file. It uses per-account random salts, PBKDF2-HMAC-SHA-256, and constant-time hash comparison, so it does not store recoverable passwords. Six vulnerabilities were identified. The most consequential are unsafe handling of the credential-file path, which can follow a pre-existing symbolic link and append data as the application's OS identity, and credential-file creation that falls back to platform-default permissions. The PBKDF2 work factor is also below current OWASP guidance. Lower-severity issues allow username enumeration through timing, unbounded memory use while reading the credential store, and visible password entry when no Java console is available.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountApp.java` | Implements registration, persistent credential storage, and authentication. | Reads usernames and passwords; validates input; derives salted PBKDF2 hashes; creates, locks, parses, and appends to `accounts.db`; compares hashes; clears selected secret buffers. |
| `README.md` | Documents compilation, operation, storage format, and security limitations. | Warns that the credential file remains sensitive and states that rate limiting, MFA, authorization, and transport security are outside the example's scope. |
| `cyber_prompt.txt` | Contains the instructions for this security review. | No executable behaviour; defines report requirements only. |
| `prompt.txt` | Contains the original implementation request. | Establishes the requirement that stored passwords be one-way protected. |
| `prompt_hash.txt` | Records a hash identifying the original prompt. | No executable behaviour or credential material. |
| `result.md` | Summarizes the earlier implementation and test run. | Describes the selected password-hashing scheme and file-permission test; contains no production credential. |
| `return.txt` | Stores the earlier tool transcript. | Contains non-production test passwords in command text, illustrating why real secrets must not be supplied through logged command lines; it does not affect application execution. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every file, identify security-relevant behaviours, select specialized guidance, verify each behaviour, and report concrete CWE-mapped evidence.
- `performing-cryptographic-audit-of-application`: Applied to algorithm selection, PBKDF2 work factor, salt entropy and length, hardcoded-secret checks, password handling, and hash comparison.
- General OWASP Top 10 / CWE knowledge: Applied to local filesystem link resolution and permissions, authentication timing, input masking, concurrency, parsing, and resource-consumption behaviour because no matching specialized skill covered this local Java CLI design.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Credential store follows attacker-controlled symbolic links | High | CWE-59 | `UserAccountApp.java:113-116` |
| SEC-02 | Credential file can be created with unsafe default permissions | Medium | CWE-732 | `UserAccountApp.java:199-200` |
| SEC-03 | PBKDF2 work factor is below current guidance | Medium | CWE-916 | `UserAccountApp.java:27` |
| SEC-04 | Authentication timing discloses whether a username exists | Low | CWE-208 | `UserAccountApp.java:142-148` |
| SEC-05 | Credential file is loaded into memory without a size bound | Low | CWE-400 | `UserAccountApp.java:157-160` |
| SEC-06 | Password fallback can echo secrets on screen | Low | CWE-549 | `UserAccountApp.java:83-87` |

## 5. Detailed Findings

### SEC-01: Credential store follows attacker-controlled symbolic links
- **Severity:** High
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following')
- **Location:** `UserAccountApp.java:113-116`

**Vulnerable code:**
```java
// UserAccountApp.java:113-116
        createCredentialFileIfMissing();
        try (FileChannel channel = FileChannel.open(ACCOUNT_FILE,
                StandardOpenOption.READ, StandardOpenOption.WRITE);
             var ignored = channel.lock()) {
```

**Why it is a problem:** `ACCOUNT_FILE` is a relative path in the process working directory, and both the existence check and `FileChannel.open` follow symbolic links. An attacker who controls that directory can place an `accounts.db` symlink to another file writable by the application identity. Registration then reads and appends an account record to the target. Depending on the target format and the privileges used to launch the program, this can corrupt sensitive data or turn an arbitrary-file append into privilege escalation. The file lock does not prevent link traversal. There is also a race between checking/creating the path and reopening it.

**Fix:** Place the store in an owner-controlled directory, atomically create it with owner-only permissions, reject non-regular existing paths, and use `NOFOLLOW_LINKS` whenever it is opened. Pass the resulting locked channel to record-reading code instead of reopening the pathname.
```java
private static FileChannel openCredentialFileSecurely() throws IOException {
    Set<OpenOption> options = Set.of(
            StandardOpenOption.READ,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS);
    try {
        return FileChannel.open(ACCOUNT_FILE, Set.of(
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rw-------")));
    } catch (FileAlreadyExistsException e) {
        if (!Files.isRegularFile(ACCOUNT_FILE, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("credential path is not a regular file");
        }
        return FileChannel.open(ACCOUNT_FILE, options);
    }
}

try (FileChannel channel = openCredentialFileSecurely();
     var ignored = channel.lock()) {
    AccountRecord existing = findRecord(channel, username);
    // Append only through this verified, locked channel.
}
```

### SEC-02: Credential file can be created with unsafe default permissions
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `UserAccountApp.java:199-200`

**Vulnerable code:**
```java
// UserAccountApp.java:199-200
            } catch (UnsupportedOperationException e) {
                Files.createFile(ACCOUNT_FILE);
```

**Why it is a problem:** When POSIX file attributes are unavailable, creation silently falls back to the platform's default ACL or umask. That default may permit other local users to read the salts and password hashes, enabling offline password guessing. The program also accepts an already-existing credential file without verifying its owner or permissions, so even POSIX deployments can continue using an overly broad file mode.

**Fix:** Fail closed if restrictive permissions cannot be established, or implement the platform's ACL mechanism. Validate permissions every time an existing store is opened; do not assume that successful creation once guarantees continued protection.
```java
Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
try {
    if (Files.notExists(ACCOUNT_FILE, LinkOption.NOFOLLOW_LINKS)) {
        Files.createFile(ACCOUNT_FILE,
                PosixFilePermissions.asFileAttribute(ownerOnly));
    }
    Set<PosixFilePermission> actual = Files.getPosixFilePermissions(
            ACCOUNT_FILE, LinkOption.NOFOLLOW_LINKS);
    if (!actual.equals(ownerOnly)) {
        throw new IOException("credential file permissions must be rw-------");
    }
} catch (UnsupportedOperationException e) {
    throw new IOException("cannot enforce owner-only credential-file permissions", e);
}
```

### SEC-03: PBKDF2 work factor is below current guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `UserAccountApp.java:27`

**Vulnerable code:**
```java
// UserAccountApp.java:27
    private static final int ITERATIONS = 310_000;
```

**Why it is a problem:** The program uses PBKDF2-HMAC-SHA-256 with 310,000 iterations. The current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommends 600,000 iterations for PBKDF2-HMAC-SHA-256, with the final cost calibrated on deployment hardware. A stolen `accounts.db` therefore costs an attacker roughly half the work imposed by that baseline for each password guess. The persisted work factor is useful for migration, but authentication never upgrades older records.

**Fix:** Prefer Argon2id through a reviewed library when compatibility permits. If PBKDF2 is required, benchmark the deployment, use at least the current recommended HMAC-SHA-256 work factor, and rehash successfully authenticated records whose stored work factor is obsolete.
```java
private static final int ITERATIONS = 600_000;

private static boolean needsRehash(AccountRecord record) {
    return record.iterations < ITERATIONS;
}
```

### SEC-04: Authentication timing discloses whether a username exists
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `UserAccountApp.java:142-148`

**Vulnerable code:**
```java
// UserAccountApp.java:142-148
            AccountRecord record = findRecord(username);
            if (record == null) {
                return false;
            }
            byte[] candidate = derive(password, record.salt, record.iterations);
            try {
                return MessageDigest.isEqual(candidate, record.hash);
```

**Why it is a problem:** An unknown username returns immediately, whereas a registered username triggers hundreds of thousands of PBKDF2 iterations. Although both cases print `Authentication failed.`, repeated timing measurements can distinguish them and enumerate registered usernames. In a local CLI this requires an attacker to be able to invoke or wrap the program, so the impact is lower than it would be for a network service.

**Fix:** Perform a comparable KDF and constant-time comparison even when no record exists. Use a fixed, non-secret dummy salt of the normal length and keep failure messages identical.
```java
private static final byte[] DUMMY_SALT = new byte[SALT_BYTES];

AccountRecord record = findRecord(username);
byte[] salt = record == null ? DUMMY_SALT : record.salt;
int iterations = record == null ? ITERATIONS : record.iterations;
byte[] candidate = derive(password, salt, iterations);
byte[] expected = record == null ? candidate.clone() : record.hash;
try {
    boolean matches = MessageDigest.isEqual(candidate, expected);
    return record != null && matches;
} finally {
    Arrays.fill(candidate, (byte) 0);
    Arrays.fill(expected, (byte) 0);
}
```

### SEC-05: Credential file is loaded into memory without a size bound
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `UserAccountApp.java:157-160`

**Vulnerable code:**
```java
// UserAccountApp.java:157-160
    private static AccountRecord findRecord(String username) throws IOException {
        List<String> lines = Files.readAllLines(ACCOUNT_FILE, StandardCharsets.UTF_8);
        for (String line : lines) {
            String[] fields = line.split(":", -1);
```

**Why it is a problem:** Every registration and authentication loads the entire credential database and all its lines into memory. Registration has no account-count or file-size quota, so repeated registrations can grow the file until normal authentication causes excessive memory use or process termination. A malformed oversized store has the same effect. The linear scan also makes CPU time grow with every account.

**Fix:** Use a database with indexed unique usernames and deployment-appropriate quotas. For this flat-file example, enforce a maximum file size before parsing and stream one bounded record at a time instead of materializing the entire file.
```java
private static final long MAX_CREDENTIAL_FILE_BYTES = 16L * 1024 * 1024;

private static AccountRecord findRecord(String username) throws IOException {
    long size = Files.size(ACCOUNT_FILE);
    if (size > MAX_CREDENTIAL_FILE_BYTES) {
        throw new IOException("credential file exceeds the configured size limit");
    }
    try (BufferedReader reader = Files.newBufferedReader(
            ACCOUNT_FILE, StandardCharsets.UTF_8)) {
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.length() > 1024) {
                throw new IOException("credential record exceeds the size limit");
            }
            AccountRecord match = parseMatchingRecord(line, username);
            if (match != null) {
                return match;
            }
        }
    }
    return null;
}
```

### SEC-06: Password fallback can echo secrets on screen
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `UserAccountApp.java:83-87`

**Vulnerable code:**
```java
// UserAccountApp.java:83-87
        } else {
            // This fallback supports redirected input; terminals should use Console so input is hidden.
            System.out.print("Password: ");
            String line = FALLBACK_INPUT.readLine();
            password = line == null ? null : line.toCharArray();
```

**Why it is a problem:** `System.console()` is commonly null under IDEs, subprocesses, and some terminal launchers—not only when standard input is intentionally redirected. In those cases `BufferedReader.readLine()` does not disable terminal echo, so a real password may be displayed and captured in terminal scrollback, screen recordings, or logs. It is also first stored in an immutable `String` that cannot be explicitly erased.

**Fix:** Require a console for interactive password entry. If automation is required, expose a separately documented secret-input mechanism whose source and invocation are designed not to echo or log the password.
```java
private static char[] readPassword() throws IOException {
    Console console = System.console();
    if (console == null) {
        throw new IOException("secure console unavailable; refusing visible password input");
    }
    char[] password = console.readPassword("Password: ");
    if (password == null || password.length < 12) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
        throw new IllegalArgumentException(
                "password must contain at least 12 characters");
    }
    return password;
}
```

## 6. Verified Controls and Checks With No Finding
- One-way password storage: `UserAccountApp.java:182-190` uses PBKDF2-HMAC-SHA-256 rather than plaintext storage or reversible encryption; no password, encryption key, API token, or production secret is hardcoded.
- Salt generation: `UserAccountApp.java:30,109-111` uses `SecureRandom` and a fresh 16-byte salt for every registration.
- Derived-key length: `UserAccountApp.java:29,184-187` requests a 256-bit derived value, avoiding truncated password hashes.
- Hash comparison: `UserAccountApp.java:146-150` uses `MessageDigest.isEqual` rather than an ordinary early-exit array or string comparison.
- Secret-buffer cleanup: `UserAccountApp.java:56-58,129-131,149-152,188-190` explicitly clears the caller's password array, derived candidates, salts/hashes loaded for authentication, and the `PBEKeySpec` password copy; the immutable fallback `String` exception is reported as SEC-06.
- Username record safety: `UserAccountApp.java:98-105,120-122,207-214` bounds username length, rejects control characters, and Base64URL-encodes usernames before placing them in a colon-delimited record, preventing record injection.
- Stored work-factor validation: `UserAccountApp.java:166-169` rejects non-positive or extreme persisted iteration counts before invoking PBKDF2.
- Malformed-record handling: `UserAccountApp.java:160-177` checks field count and converts malformed numeric/Base64 data into a controlled `IOException` rather than accepting corrupt credentials.
- Duplicate registration concurrency: `UserAccountApp.java:114-128` takes an exclusive file lock around duplicate checking and append; `UserAccountApp.java:140-154` takes a shared lock for authentication. The separate path reopen is addressed by SEC-01, but cooperating application processes do not race duplicate registration.
- Authentication result text: `UserAccountApp.java:50-54` uses the same visible failure message for an unknown username and an incorrect password. The remaining timing side channel is reported as SEC-04.
- SQL injection, command injection, deserialization, XSS, SSRF, TLS, and authorization bypass: No database API, shell execution, object deserialization, web rendering, outbound network call, transport listener, or privileged operation is present in any executable source file.
