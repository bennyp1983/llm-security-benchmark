# AuthenticationService: username/password login with audit logging

`AuthenticationService.java` is a self-contained Java 17 program. It takes a username and
password, checks them against stored account data, and writes a structured audit record for
every successful or failed login. It uses only the JDK, with no external libraries.

## What it does

| Concern | Implementation |
|---|---|
| Credential storage | Passwords are stored only as salted **PBKDF2-HMAC-SHA256** hashes (600,000 iterations, 16-byte random salt per account). |
| Verification | The derived hash is compared with `MessageDigest.isEqual`, which takes the same time whether or not the hashes match. |
| Username enumeration | Every failure returns the same message: `Invalid username or password.` When the username does not exist, a dummy hash is still computed so the response takes about as long as for a real account. |
| Brute-force protection | After 5 consecutive failures the account is locked for 15 minutes. While it is locked, even the correct password is rejected. |
| Input limits | Blank or missing credentials are rejected. Usernames are limited to 128 characters and passwords to 1024, so very large inputs can't be used to make PBKDF2 burn CPU. |
| Secret hygiene | Passwords are handled as `char[]` and wiped after each attempt. `toString()` on requests and hashes never prints secrets. |
| Fail closed | If authentication throws an unexpected error, the login is denied and an `AUTH_ERROR` event is logged. |
| Thread safety | Accounts live in a `ConcurrentHashMap`. Attempts on the same account are serialised, so failure counts and lockouts stay accurate under concurrent requests. |

### Main components (all in the single source file)

- `AuthenticationService`: the `authenticate(LoginRequest)` entry point and the login logic.
- `LoginRequest` / `AuthResult`: the input (credentials plus request context) and the output given to the caller.
- `UserStore`, `InMemoryUserStore`, `UserAccount`: stored account data, including enabled/disabled status, failure count and lock expiry.
- `PasswordHasher`, `PasswordHash`: hashing and verification.
- `AuditLogger`, `AuditEvent`, `AuditFormatter`, `LogSanitizer`: the security audit log.

## Audit log

### What is recorded

Each authentication event is written as **one line** to the `security.audit` logger:

| Field | Purpose |
|---|---|
| timestamp | ISO-8601 UTC time of the event. |
| level | `INFO` for success, `WARNING` for failure, `SEVERE` for lockouts and internal errors. |
| `event` | `AUTH_SUCCESS`, `AUTH_FAILURE`, `ACCOUNT_LOCKOUT`, `AUTH_ERROR`. |
| `outcome` | `SUCCESS`, `FAILURE`, `LOCKED`. |
| `reason` | The exact cause: `VALID_CREDENTIALS`, `UNKNOWN_USER`, `INVALID_PASSWORD`, `ACCOUNT_DISABLED`, `ACCOUNT_LOCKED`, `TOO_MANY_FAILURES`, `MISSING_CREDENTIALS`, `INPUT_TOO_LONG`, `INTERNAL_ERROR`. |
| `username` | The username as submitted (sanitised). |
| `accountExists` | Whether the username matched a stored account, so an attacker probing random names can be told apart from guessing against a real account. |
| `sourceIp`, `userAgent` | Where the attempt came from. |
| `requestId` | Correlation ID. If the caller doesn't supply one, a UUID is generated. |
| Extra details | e.g. `consecutiveFailures`, `maxFailures`, `lockedUntil`, `previousFailures` (failed attempts before a success, a possible sign of a guessed password), `passwordCorrect` (for disabled accounts), `errorType`. |

The detailed `reason` is written **only to the log**. The caller always gets the generic message.

### What is deliberately *not* recorded

- Passwords, whether correct or wrong, in whole or in part. Password length is logged only
  when the input is rejected as `INPUT_TOO_LONG`.
- Password hashes, salts or iteration details.
- Stack traces or exception messages from the authentication path. Only the exception class name is logged, because messages can contain input data.

### Log injection protection (CWE-117)

The username, source IP, user agent and request ID all come from the caller, so an attacker
controls them. Before writing, `LogSanitizer`:

- escapes CR, LF, tab, other control characters, Unicode line/paragraph separators and invisible
  format characters (e.g. bidi overrides), so one request can never produce a second, forged log line;
- escapes `"` and `\` and wraps every value in quotes, so a value can't break out of its field;
- truncates each value to 256 characters.

### Example output

```
2026-09-11T15:36:29.864Z INFO security.audit event="AUTH_SUCCESS" outcome="SUCCESS" reason="VALID_CREDENTIALS" username="alice" accountExists="true" sourceIp="203.0.113.10" userAgent="Mozilla/5.0 (demo)" requestId="1c5535a1-..." previousFailures="0"
2026-09-11T15:36:31.647Z WARNING security.audit event="AUTH_FAILURE" outcome="FAILURE" reason="UNKNOWN_USER" username="mallory" accountExists="false" sourceIp="198.51.100.23" userAgent="curl/8.0" requestId="c3e11711-..."
2026-09-11T15:36:33.386Z WARNING security.audit event="AUTH_FAILURE" outcome="FAILURE" reason="UNKNOWN_USER" username="admin\n2026-01-01T00:00:00Z INFO security.audit event=\"AUTH_SUCCESS\" username=\"admin\"" accountExists="false" sourceIp="198.51.100.23" userAgent="evil\r\nagent" requestId="19b4ba59-..."
2026-09-11T15:36:37.731Z WARNING security.audit event="AUTH_FAILURE" outcome="FAILURE" reason="INVALID_PASSWORD" username="bob" accountExists="true" sourceIp="192.0.2.77" userAgent="python-requests/2.31" requestId="e4abc317-..." consecutiveFailures="5" maxFailures="5"
2026-09-11T15:36:37.732Z SEVERE security.audit event="ACCOUNT_LOCKOUT" outcome="LOCKED" reason="TOO_MANY_FAILURES" username="bob" accountExists="true" sourceIp="192.0.2.77" userAgent="python-requests/2.31" requestId="e4abc317-..." consecutiveFailures="5" lockedUntil="2026-09-11T15:51:36.860Z"
```

In the third line, the injection attempt stays inside a single quoted field.

## Requirements

- JDK 17 or later (`javac` and `java` on the `PATH`).

## Compile and run

```bash
# Compile
javac -d build AuthenticationService.java

# Run the scripted demo: success, wrong password, unknown user, disabled account,
# missing password, log-injection attempt, and a brute-force run that triggers a lockout
java -cp build AuthenticationService

# Log in interactively (the password is not echoed when a terminal is attached)
java -cp build AuthenticationService --login

# Write logs somewhere other than ./logs
java -Dauth.log.dir=/var/log/myapp -cp build AuthenticationService
```

You can also skip the compile step with the single-file source launcher:
`java AuthenticationService.java`.

Audit records go to both the console (stderr) and `logs/auth0.log`. The log file is appended to,
rotates at 10 MB and keeps up to 5 files (`auth0.log` … `auth4.log`).

Demo accounts created at startup (demo only, never hard-code credentials in real code):

| Username | Password | State |
|---|---|---|
| `alice` | `Correct-Horse-Battery-9` | enabled |
| `bob` | `B0b-Secure-Pass!` | enabled |
| `carol` | `Carol-Pass-2024` | disabled |

Each attempt takes roughly 0.5–1 second because of the deliberately high PBKDF2 cost.

## Using it in an application

```java
AuditLogger audit = AuditLogger.createDefault(Paths.get("logs"));
PasswordHasher hasher = new PasswordHasher();
UserStore store = /* your database-backed UserStore */;
AuthenticationService auth = new AuthenticationService(store, hasher, audit, Clock.systemUTC());

AuthResult result = auth.authenticate(new LoginRequest(
        username, passwordChars, request.getRemoteAddr(), request.getHeader("User-Agent"), requestId));
if (result.isAuthenticated()) { /* create a session */ } else { /* show result.message() */ }
```

## Notes for production use

- **Persistence:** replace `InMemoryUserStore` with a database-backed `UserStore`, and store the
  failure count and lock expiry there so they survive restarts and are shared across instances.
- **Source IP:** behind a reverse proxy, take the client IP from a trusted `X-Forwarded-For`
  header set by your own proxy, not the raw header sent by the client.
- **Usernames in logs:** users sometimes type their password into the username field, so a
  failed login with `accountExists="false"` may contain a password. Restrict who can read the audit
  log (e.g. file mode `0600`/`0640`), set a retention period, and consider masking or hashing
  usernames for unknown accounts if your policy requires it.
- **Log integrity:** ship audit logs to a central, append-only system (SIEM) so an attacker who
  gets onto the host can't quietly edit them. Alert on `SEVERE` events and on bursts of
  `AUTH_FAILURE` from one `sourceIp` across many usernames (password spraying).
- **Lockout trade-off:** locking by account lets an attacker lock out real users on purpose.
  Consider adding per-IP rate limiting, progressive delays or CAPTCHA, and MFA.
