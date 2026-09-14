# Security Review: AuthenticationService (Java username/password login with audit logging)

## 1. Executive Summary
`AuthenticationService.java` is a self-contained Java 17 component. It checks a username and password against accounts held in memory, stores passwords as salted PBKDF2-HMAC-SHA256 hashes and locks an account for 15 minutes after 5 consecutive failures. It writes a structured, sanitised audit record for every attempt to a rotating log file and to the console. A `main` method provides a scripted demo and an interactive login.

The main controls are sound: a strong KDF with a random salt, constant-time comparison, a generic failure message, dummy-hash timing equalisation, failing closed on errors, wiping passwords from memory, and log-injection neutralisation (CWE-117). No injection, deserialization or authentication-bypass flaws were found. The most important weaknesses are about **abuse resistance**:

- **SEC-01 (Medium):** Attempts are limited only per account, never per source or globally. Password spraying across accounts and against unknown usernames is unlimited, and every attempt forces a 600,000-iteration PBKDF2 computation, so CPU can be exhausted.
- **SEC-02 (Medium):** Any anonymous client can lock a chosen victim out of their account indefinitely, because the lockout is keyed only on the account.
- **SEC-03 (Medium):** The per-account lock is held for the whole PBKDF2 computation. Concurrent requests for a real account are serialised while those for unknown usernames run in parallel. That timing difference defeats the anti-enumeration design, and it also lets an attacker tie up request threads.
- Five Low-severity findings: possible passwords and password lengths in the audit log, audit log files created with default permissions, no bounds on the PBKDF2 iteration count, hard-coded demo credentials, and password echo in the CLI fallback.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthenticationService.java` | Complete authentication component: `authenticate()` flow, `LoginRequest`/`AuthResult`, `InMemoryUserStore`/`UserAccount` (failure counter, lockout), `PasswordHasher` (PBKDF2), `AuditEvent`/`LogSanitizer`/`AuditLogger`/`AuditFormatter` (audit log), demo `main` | Password hashing and verification (KDF parameters, salt, RNG, constant-time compare); authentication and account lockout; username enumeration and timing; concurrency around the failure counter; logging of attacker-controlled data (log injection, sensitive data in logs); log file creation and permissions; hard-coded credentials; interactive password input |
| `README.md` | Documentation of design, log format, build/run steps and production notes | Documents demo credentials and known trade-offs (lockout DoS, passwords typed into username field); no executable code |
| `prompt.txt` | Original generation prompt (plain text) | None (not code) |
| `cyber_prompt.txt` | This review task's instructions (plain text) | None (not code) |
| `result.md`, `return.txt` | Metadata and summary of the run that generated the code | None (not code) |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. Read every file, extracted the security-relevant behaviour, searched skill names in the library, and selected and applied the matching skills below.
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher`/`PasswordHash` (lines 329-394): algorithm choice, KDF iteration count and bounds, salt size and RNG, key length, constant-time comparison, hard-coded passwords in source (lines 628-630). Produced SEC-06 and SEC-07.
- `testing-api-authentication-weaknesses`: Applied to `authenticate`/`doAuthenticate` (lines 81-174): brute-force and credential-stuffing susceptibility, lockout design, account enumeration through response content and timing, failure messages. Produced SEC-01, SEC-02 and SEC-03.
- `exploiting-race-condition-vulnerabilities`: Applied to failure counting and lockout (lines 124-173, 292-321): TOCTOU and limit-overrun on the attempt counter, synchronisation scope. Informed SEC-03; no limit-overrun was found with the in-memory store.
- `testing-for-sensitive-data-exposure`: Applied to what the audit log records (lines 101-171, 443-512) and how log files are created (lines 578-598), `toString()` redaction, and password input in the CLI. Produced SEC-04, SEC-05 and SEC-08.
- General OWASP Top 10 / CWE knowledge was used where no specialised skill matched: log injection and the output neutralisation logic in `LogSanitizer` (CWE-117), `java.util.logging` formatter behaviour, fail-closed exception handling (CWE-636), and handling of secrets in memory (CWE-226/CWE-316).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No per-source or global throttling: unlimited password spraying and PBKDF2 CPU exhaustion | Medium | CWE-307 | `AuthenticationService.java:113` |
| SEC-02 | Account-keyed lockout lets any anonymous client lock out a chosen user | Medium | CWE-645 | `AuthenticationService.java:154` |
| SEC-03 | Per-account monitor held during PBKDF2 leaks account existence through timing and serialises requests | Medium | CWE-208 | `AuthenticationService.java:124` |
| SEC-04 | Audit log records raw unmatched usernames (possibly passwords) and password length | Low | CWE-532 | `AuthenticationService.java:492` |
| SEC-05 | Audit log directory and files created with default (typically world-readable) permissions | Low | CWE-732 | `AuthenticationService.java:579` |
| SEC-06 | PasswordHasher accepts any positive iteration count and verifies with unbounded stored parameters | Low | CWE-916 | `AuthenticationService.java:362` |
| SEC-07 | Hard-coded demo account passwords in source | Low | CWE-798 | `AuthenticationService.java:628` |
| SEC-08 | Password echoed and held in an immutable String when no console is available | Low | CWE-549 | `AuthenticationService.java:650` |

## 5. Detailed Findings

### SEC-01: No per-source or global throttling: unlimited password spraying and PBKDF2 CPU exhaustion
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AuthenticationService.java:113-120` (also `:127-134`, `:351`)

**Vulnerable code:**
```java
// AuthenticationService.java:113-120
        Optional<UserAccount> maybeAccount = userStore.findByUsername(username);
        if (maybeAccount.isEmpty()) {
            hasher.verify(password, dummyHash); // equalise timing; result intentionally ignored
            audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.UNKNOWN_USER, request, clock)
                    .accountExists(false)
                    .build());
            return AuthResult.failure();
        }
```

**Why it is a problem:** The only limit on attempts is the per-account counter (`MAX_FAILED_ATTEMPTS`). Nothing limits attempts per source IP, per time window or globally:
- **Password spraying and credential stuffing are unrestricted.** An attacker who tries 4 common passwords against every account every 15 minutes never triggers a lockout. Attempts against unknown usernames are never counted at all.
- **CPU exhaustion (CWE-770).** Every request that passes the length checks runs a full 600,000-iteration PBKDF2 derivation (about 0.5-1 s of CPU, per the README). That includes unknown usernames (line 115) and already-locked accounts (line 128). A handful of concurrent anonymous clients can saturate every core and deny logins to everyone, and the work per request is not bounded.

**Fix:** Before any hashing, check a per-source rate limit and a global cap on concurrent PBKDF2 computations. Reject cheaply, with the same generic message, when either limit is hit. In production, keep the limiter state in a shared, bounded store (for example Redis with TTLs) and add MFA or CAPTCHA for distributed guessing.
```java
/** Fixed-window limiter checked before any PBKDF2 work. */
static final class AttemptLimiter {
    private record Window(Instant start, int count) {}
    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final int maxPerWindow;
    private final Duration window;
    private final Clock clock;

    AttemptLimiter(int maxPerWindow, Duration window, Clock clock) {
        this.maxPerWindow = maxPerWindow;
        this.window = window;
        this.clock = clock;
    }

    boolean tryAcquire(String key) {
        Instant now = clock.instant();
        Window w = windows.compute(key, (k, cur) ->
                (cur == null || !now.isBefore(cur.start().plus(window)))
                        ? new Window(now, 1)
                        : new Window(cur.start(), cur.count() + 1));
        return w.count() <= maxPerWindow;
    }
}

// Fields
private final AttemptLimiter sourceLimiter = new AttemptLimiter(20, Duration.ofMinutes(1), Clock.systemUTC());
private final java.util.concurrent.Semaphore hashingPermits =
        new java.util.concurrent.Semaphore(Runtime.getRuntime().availableProcessors());

// In doAuthenticate, after the length checks and before userStore.findByUsername(...)
String source = Objects.requireNonNullElse(request.sourceIp(), "unknown");
if (!sourceLimiter.tryAcquire(source) || !hashingPermits.tryAcquire()) {
    audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.RATE_LIMITED, request, clock)
            .build());
    return AuthResult.failure();
}
try {
    // ... existing lookup, verification and lockout logic ...
} finally {
    hashingPermits.release();
}
```

### SEC-02: Account-keyed lockout lets any anonymous client lock out a chosen user
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `AuthenticationService.java:127-134` and `:154-162`

**Vulnerable code:**
```java
// AuthenticationService.java:127-134
            if (account.isLockedAt(now)) {
                hasher.verify(password, dummyHash);
                audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.ACCOUNT_LOCKED, request, clock)
                        .accountExists(true)
                        .detail("lockedUntil", account.lockedUntil())
                        .build());
                return AuthResult.failure();
            }
// AuthenticationService.java:154-162
                if (failures >= MAX_FAILED_ATTEMPTS) {
                    Instant lockedUntil = now.plus(LOCKOUT_DURATION);
                    account.lockUntil(lockedUntil);
                    audit.record(AuditEvent.builder(EventType.ACCOUNT_LOCKOUT, Outcome.LOCKED, Reason.TOO_MANY_FAILURES, request, clock)
                            .accountExists(true)
                            .detail("consecutiveFailures", failures)
                            .detail("lockedUntil", lockedUntil)
                            .build());
                }
```

**Why it is a problem:** The failure counter and lock live only on the account, regardless of who is failing. The lock rejects even the correct password from the legitimate owner. With no authentication, an attacker who knows or guesses a username (for example `admin` or an email address) can send 5 wrong passwords every 15 minutes from anywhere and keep that user locked out forever. Scripting this across a list of usernames locks out a whole user base. The README acknowledges the trade-off, but the code ships with no mitigation.

**Fix:** Apply the hard lockout to the (account, source) pair that is actually failing, so an attacker locks out only their own source. Pair this with SEC-01's per-source limiter. Where an account-wide reaction to distributed guessing is needed, use step-up verification (CAPTCHA or MFA) rather than refusing the real owner.
```java
/** Failure state keyed by (account, source IP): guessing from one source never locks out other sources. */
static final class SourceLockouts {
    private static final class State { int failures; Instant lockedUntil; }
    private final Map<String, State> states = new ConcurrentHashMap<>();

    private State state(String username, String sourceIp) {
        return states.computeIfAbsent(username + '\n' + sourceIp, k -> new State());
    }

    boolean isLocked(String username, String sourceIp, Instant now) {
        State s = state(username, sourceIp);
        synchronized (s) {
            if (s.lockedUntil != null && now.isBefore(s.lockedUntil)) {
                return true;
            }
            if (s.lockedUntil != null) {
                s.lockedUntil = null;
                s.failures = 0;
            }
            return false;
        }
    }

    int registerFailure(String username, String sourceIp, Instant now) {
        State s = state(username, sourceIp);
        synchronized (s) {
            if (++s.failures >= MAX_FAILED_ATTEMPTS) {
                s.lockedUntil = now.plus(LOCKOUT_DURATION);
            }
            return s.failures;
        }
    }

    void clear(String username, String sourceIp) {
        states.remove(username + '\n' + sourceIp);
    }
}

// In doAuthenticate:
if (sourceLockouts.isLocked(account.username(), request.sourceIp(), now)) { /* dummy verify, audit ACCOUNT_LOCKED, fail */ }
// on wrong password:
int failures = sourceLockouts.registerFailure(account.username(), request.sourceIp(), now);
// on success:
sourceLockouts.clear(account.username(), request.sourceIp());
```

### SEC-03: Per-account monitor held during PBKDF2 leaks account existence through timing and serialises requests
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `AuthenticationService.java:122-136`

**Vulnerable code:**
```java
// AuthenticationService.java:122-136
        UserAccount account = maybeAccount.get();
        // Serialise attempts per account so failure counting and lockout are race-free.
        synchronized (account) {
            Instant now = clock.instant();

            if (account.isLockedAt(now)) {
                hasher.verify(password, dummyHash);
                audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.ACCOUNT_LOCKED, request, clock)
                        .accountExists(true)
                        .detail("lockedUntil", account.lockedUntil())
                        .build());
                return AuthResult.failure();
            }

            boolean passwordMatches = hasher.verify(password, account.passwordHash());
```

**Why it is a problem:** The dummy hash equalises the time of a *single* request, but the expensive PBKDF2 call runs while holding the account's monitor. Requests for unknown usernames (lines 114-120) take no lock and run in parallel.
- **Username enumeration.** An attacker sends, say, 4 simultaneous requests for a username. If the account does not exist, all 4 return after about T. If it exists (enabled, disabled or locked), the requests queue behind each other and the last returns after about 4T. This reliably reveals which usernames are real, undoing the generic-message and dummy-hash protections (lines 44-45, 67-68, 115).
- **Thread starvation.** N concurrent requests against one account hold N server threads for up to N x T in total. A small burst aimed at one account ties up the request thread pool far longer than the same burst against unknown names, and delays the real user's login.

**Fix:** Do only the counter bookkeeping inside short critical sections and run PBKDF2 without holding the lock. To stay race-free (no limit overrun), reserve an attempt slot before verifying and settle it afterwards. In a database-backed `UserStore`, move these atomic operations into the store (for example `SELECT ... FOR UPDATE` or conditional updates), because `synchronized` on per-lookup objects gives no mutual exclusion.
```java
// UserAccount
private int inFlight;

/** Reserves an attempt; false if locked or all remaining attempts are already in flight. */
synchronized boolean tryBeginAttempt(Instant now) {
    if (isLockedAt(now) || failedAttempts + inFlight >= MAX_FAILED_ATTEMPTS) {
        return false;
    }
    inFlight++;
    return true;
}

synchronized void abortAttempt() {
    inFlight--;
}

synchronized int completeFailedAttempt(Instant now) {
    inFlight--;
    if (++failedAttempts >= MAX_FAILED_ATTEMPTS) {
        lockedUntil = now.plus(LOCKOUT_DURATION);
    }
    return failedAttempts;
}

synchronized int completeSuccessfulAttempt(Instant now) {
    inFlight--;
    int previous = failedAttempts;
    failedAttempts = 0;
    lockedUntil = null;
    lastSuccessfulLogin = now;
    return previous;
}

// doAuthenticate: no monitor is held while PBKDF2 runs
UserAccount account = maybeAccount.get();
Instant now = clock.instant();
if (!account.tryBeginAttempt(now)) {
    hasher.verify(password, dummyHash);
    // audit ACCOUNT_LOCKED as before
    return AuthResult.failure();
}
boolean settled = false;
try {
    boolean passwordMatches = hasher.verify(password, account.passwordHash());
    if (!account.isEnabled()) {
        account.abortAttempt();
        settled = true;
        // audit ACCOUNT_DISABLED as before
        return AuthResult.failure();
    }
    if (!passwordMatches) {
        int failures = account.completeFailedAttempt(now);
        settled = true;
        // audit INVALID_PASSWORD and, if failures >= MAX_FAILED_ATTEMPTS, ACCOUNT_LOCKOUT
        return AuthResult.failure();
    }
    int previousFailures = account.completeSuccessfulAttempt(now);
    settled = true;
    // audit AUTH_SUCCESS with previousFailures
    return AuthResult.success(account.username());
} finally {
    if (!settled) {
        account.abortAttempt();
    }
}
```

### SEC-04: Audit log records raw unmatched usernames (possibly passwords) and password length
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `AuthenticationService.java:492` (used by all events), `:105-110`

**Vulnerable code:**
```java
// AuthenticationService.java:105-110
        if (username.length() > MAX_USERNAME_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.INPUT_TOO_LONG, request, clock)
                    .detail("usernameLength", username.length())
                    .detail("passwordLength", password.length)
                    .build());
            return AuthResult.failure();
// AuthenticationService.java:492
                this.username = request.username();
```

**Why it is a problem:**
- Every event logs the submitted username verbatim, including `UNKNOWN_USER`, `MISSING_CREDENTIALS` and `INPUT_TOO_LONG` events where it matches no account. Users often type their password into the username field (or paste `user<TAB>password`), so the log ends up holding cleartext passwords. The file and console handlers then expose them to anyone who can read logs or the SIEM they are shipped to.
- The `INPUT_TOO_LONG` event logs `passwordLength` whenever *either* field is too long. With an over-long username and a normal real password, the exact length of that password is recorded, which narrows brute-force search. The README states password length is logged "only when the input is rejected", but the rejection may have nothing to do with the password.

**Fix:** Log a keyed fingerprint of the username until it has been matched to a real account (it can still be correlated across events but reveals nothing). Record only which field was too long, not the password length.
```java
// Builder constructor: until matched to an account, the name may be a mistyped password.
this.username = UsernameFingerprint.of(request.username());

// Builder: call with the matched account instead of accountExists(true)
Builder account(UserAccount account) {
    this.accountExists = true;
    this.username = account.username();
    return this;
}

static final class UsernameFingerprint {
    /** Loaded from a secret store or environment at startup; never hard-coded. */
    private static final byte[] KEY = Base64.getDecoder().decode(System.getenv("AUDIT_FINGERPRINT_KEY"));

    static String of(String value) {
        if (value == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
            byte[] tag = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return "hmac:" + HexFormat.of().formatHex(tag, 0, 8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Fingerprinting unavailable", e);
        }
    }
}

// INPUT_TOO_LONG event
audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.INPUT_TOO_LONG, request, clock)
        .detail("usernameTooLong", username.length() > MAX_USERNAME_LENGTH)
        .detail("passwordTooLong", password.length > MAX_PASSWORD_LENGTH)
        .build());
```

### SEC-05: Audit log directory and files created with default (typically world-readable) permissions
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AuthenticationService.java:579-591`

**Vulnerable code:**
```java
// AuthenticationService.java:579-591
            Files.createDirectories(logDir);
            Logger logger = Logger.getLogger("security.audit");
            logger.setUseParentHandlers(false);
            logger.setLevel(Level.INFO);
            for (Handler h : logger.getHandlers()) {
                logger.removeHandler(h);
            }

            Formatter formatter = new AuditFormatter();
            FileHandler file = new FileHandler(logDir.resolve("auth%g.log").toString(), 10 * 1024 * 1024, 5, true);
            file.setEncoding(StandardCharsets.UTF_8.name());
            file.setFormatter(formatter);
            logger.addHandler(file);
```

**Why it is a problem:** `Files.createDirectories` and `FileHandler` use the process umask, which on most Linux systems gives `0755` directories and `0644` files. The audit log holds usernames, source IPs, user agents, account-existence and lockout status, and possibly mistyped passwords (SEC-04). Any local user or co-hosted service can read it. A pre-existing directory that other users can write to would also let them tamper with or pre-create the `auth*.log` and `.lck` files. The README recommends `0600`/`0640`, but the code does not enforce it.

**Fix:** Create the directory owner-only, or tighten it if it already exists, so every file inside, including files rotated later, is unreachable by other users. On non-POSIX filesystems, apply an equivalent ACL.
```java
Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rwx------");
Files.createDirectories(logDir, PosixFilePermissions.asFileAttribute(ownerOnly));
Files.setPosixFilePermissions(logDir, ownerOnly); // createDirectories does not change an existing directory
if (!Files.getOwner(logDir).equals(Files.getOwner(Paths.get(System.getProperty("user.home"))))) {
    throw new IOException("Audit log directory is not owned by the service account: " + logDir);
}
Logger logger = Logger.getLogger("security.audit");
// ... handlers configured as before ...
FileHandler file = new FileHandler(logDir.resolve("auth%g.log").toString(), 10 * 1024 * 1024, 5, true);
```

### SEC-06: PasswordHasher accepts any positive iteration count and verifies with unbounded stored parameters
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `AuthenticationService.java:362-367` and `:375-376`

**Vulnerable code:**
```java
// AuthenticationService.java:362-367
        public PasswordHasher(int iterations) {
            if (iterations < 1) {
                throw new IllegalArgumentException("iterations must be positive");
            }
            this.iterations = iterations;
        }
// AuthenticationService.java:375-376
        public boolean verify(char[] password, PasswordHash stored) {
            byte[] candidate = derive(password, stored.salt, stored.iterations, stored.hash.length * 8);
```

**Why it is a problem:** The public constructor accepts `new PasswordHasher(1)`. A misconfiguration, or a "fast" setting left over from tests, silently produces hashes that can be cracked offline at billions of guesses per second, and nothing flags them. In the other direction, `verify` trusts `iterations`, salt length and hash length read from storage. A corrupted or tampered record (for example `iterations = Integer.MAX_VALUE`) makes each login for that account burn CPU for hours. That turns a write to the user store into a denial of service, and gives SEC-01 another way to exhaust CPU.

**Fix:** Enforce a minimum work factor when hashing, and check stored parameters against sane bounds before deriving. Rehash on successful login when a stored hash is below the current policy.
```java
static final int MIN_ITERATIONS = 600_000;
static final int MAX_ITERATIONS = 10_000_000;

public PasswordHasher(int iterations) {
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
        throw new IllegalArgumentException("iterations must be between " + MIN_ITERATIONS + " and " + MAX_ITERATIONS);
    }
    this.iterations = iterations;
}

public boolean verify(char[] password, PasswordHash stored) {
    if (stored.iterations < 1 || stored.iterations > MAX_ITERATIONS
            || stored.salt.length < SALT_BYTES || stored.hash.length != KEY_BITS / 8) {
        throw new IllegalStateException("Stored password hash has unsupported parameters"); // fails closed in authenticate()
    }
    byte[] candidate = derive(password, stored.salt, stored.iterations, stored.hash.length * 8);
    try {
        return MessageDigest.isEqual(candidate, stored.hash);
    } finally {
        Arrays.fill(candidate, (byte) 0);
    }
}

boolean needsRehash(PasswordHash stored) {
    return stored.iterations < iterations;
}
```

### SEC-07: Hard-coded demo account passwords in source
- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AuthenticationService.java:627-630` (reused at `:665`, `:668`, `:678`)

**Vulnerable code:**
```java
// AuthenticationService.java:627-630
        InMemoryUserStore store = new InMemoryUserStore();
        store.save(new UserAccount("alice", hasher.hash("Correct-Horse-Battery-9".toCharArray()), true));
        store.save(new UserAccount("bob", hasher.hash("B0b-Secure-Pass!".toCharArray()), true));
        store.save(new UserAccount("carol", hasher.hash("Carol-Pass-2024".toCharArray()), false));
```

**Why it is a problem:** The public `main` of the production class creates enabled accounts whose passwords are published in the source and the README. If the class is launched as-is (for example `java AuthenticationService --login` on a server), or this bootstrap code is copied into a real application, anyone can log in as `alice` or `bob`. These values also end up in version control and binaries. The impact is limited because the store is in-memory and the code is demo-only, hence Low.

**Fix:** Generate random demo passwords at startup (or read them from the environment) and pass them to the demo, so no credential is in the source. Better still, move the demo into a separate, non-shipped class.
```java
Map<String, String> demoPasswords = Map.of(
        "alice", randomPassword(), "bob", randomPassword(), "carol", randomPassword());
InMemoryUserStore store = new InMemoryUserStore();
store.save(new UserAccount("alice", hasher.hash(demoPasswords.get("alice").toCharArray()), true));
store.save(new UserAccount("bob", hasher.hash(demoPasswords.get("bob").toCharArray()), true));
store.save(new UserAccount("carol", hasher.hash(demoPasswords.get("carol").toCharArray()), false));
// runDemo(service, demoPasswords) uses demoPasswords.get("alice") etc. instead of literals

private static String randomPassword() {
    byte[] bytes = new byte[18];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}
```

### SEC-08: Password echoed and held in an immutable String when no console is available
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `AuthenticationService.java:649-656`

**Vulnerable code:**
```java
// AuthenticationService.java:649-656
        } else {
            System.err.println("(No console available: password input will be echoed.)");
            Scanner in = new Scanner(System.in, StandardCharsets.UTF_8);
            System.out.print("Username: ");
            username = in.hasNextLine() ? in.nextLine() : null;
            System.out.print("Password: ");
            password = in.hasNextLine() ? in.nextLine().toCharArray() : null;
        }
```

**Why it is a problem:** When `System.console()` is null (IDE consoles, some `ssh`/`sudo`/container or piped sessions), the program continues and reads the password in cleartext. It is visible on screen, in terminal scrollback and in session recordings. It is also first stored as an immutable `String` from `nextLine()`, which cannot be wiped, so the `char[]` wiping promised in the design (lines 79, 213-217) does not apply (CWE-316).

**Fix:** Refuse interactive password entry without a real console, so passwords are only read with echo disabled into a wipeable `char[]`.
```java
private static void interactiveLogin(AuthenticationService service) {
    Console console = System.console();
    if (console == null) {
        System.err.println("An interactive terminal is required so the password is not echoed.");
        return;
    }
    String username = console.readLine("Username: ");
    char[] password = console.readPassword("Password: ");
    AuthResult result = service.authenticate(new LoginRequest(username, password, "127.0.0.1", "cli", null));
    System.out.println(result.message());
}
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm and parameters:** `PBKDF2WithHmacSHA256`, 600,000 iterations by default (matches the OWASP Password Storage Cheat Sheet), 256-bit derived key (`AuthenticationService.java:349-353`). No MD5, SHA-1, unsalted or reversible storage anywhere.
- **Salt and RNG:** A 16-byte salt per hash comes from `java.security.SecureRandom` (`:355`, `:370-371`). No `java.util.Random`, time-based seeds or static salts.
- **Constant-time comparison:** `MessageDigest.isEqual` compares the derived and stored hash (`:378`). The derived candidate is zeroed afterwards (`:380`) and `PBEKeySpec.clearPassword()` runs in `finally` (`:391`).
- **No hash or secret leakage through objects:** `PasswordHash.toString()` redacts salt and hash (`:343-345`). `LoginRequest.toString()` leaves out the password (`:220-223`). The salt and hash arrays are defensively copied (`:338-339`). `passwordHash()` is package-private (`:289`).
- **Generic caller response:** Every failure path returns `AuthResult.failure()` with `GENERIC_FAILURE_MESSAGE` and no reason (`:61`, `:242-244`). The unknown, locked, disabled, wrong-password and error cases cannot be told apart from the response content.
- **Single-request timing equalisation:** Unknown usernames (`:115`) and locked accounts (`:128`) run a dummy PBKDF2 verification with the same parameters as real hashes (`:75`). Disabled accounts verify against the real hash (`:136`). The concurrency-based leak is reported separately as SEC-03.
- **Input bounds before hashing:** Null or blank usernames and empty passwords are rejected, and usernames over 128 or passwords over 1024 characters are refused before any PBKDF2 work (`:100-111`).
- **Fail closed:** `authenticate` catches `RuntimeException`, logs only the exception class name (no message or stack trace), and returns failure. The password is wiped in `finally` (`:83-93`). Exceptions thrown while logging still propagate as non-success, and a success result is only returned after `registerSuccess` and the audit write both complete (`:166-172`).
- **Disabled and locked accounts:** A disabled account is rejected even with the correct password, and its failure counter is not changed (`:138-144`). A locked account is rejected before password verification (`:127-134`). An expired lock resets the counter (`:296-307`). Logging `passwordCorrect` for disabled accounts records only a boolean, never the password.
- **Lockout counter race conditions (in-memory store):** `InMemoryUserStore` returns the same `UserAccount` instance for a username (`:261-270`), and the lock check, verification, increment and lock all happen in one `synchronized (account)` block (`:124-173`). Concurrent requests cannot go past `MAX_FAILED_ATTEMPTS`, so there is no limit-overrun with the shipped store. Caveat: a database-backed `UserStore` that returns new objects per lookup would lose this guarantee (see the SEC-03 fix).
- **Username normalisation consistency:** The same `normalizeUsername` (strip, then `toLowerCase(Locale.ROOT)`) is applied when saving accounts (`:283`) and when looking them up (`:97`). Locale-independent lowercasing avoids the Turkish-i mismatch, and case or whitespace variants cannot create a second identity for the same account.
- **Log injection / log forging (CWE-117):** `LogSanitizer.quote` escapes `"`, `\`, CR, LF, TAB, all ISO control characters (including U+0085 NEL), U+2028/U+2029 and Unicode FORMAT characters such as bidi overrides. It wraps every value in quotes and truncates at 256 characters (`:525-556`). All attacker-controlled fields (username, sourceIp, userAgent, requestId) go through it (`:457-467`). Detail keys are compile-time constants, and detail values are numbers, booleans, `Instant`s or JDK class names.
- **Formatter safety:** `AuditFormatter` uses `record.getMessage()` rather than `formatMessage()` (`:605-606`), so `{0}`-style `MessageFormat` placeholders in attacker input are not interpreted. Each record is exactly one line.
- **Audit completeness:** Every outcome (success, each failure reason, lockout, internal error) produces a record with a UTC timestamp, a severity level, source IP, user agent and request ID (`:101-171`, `:447-453`). A missing request ID is replaced with a random UUID (`:204`).
- **Injection, deserialization, SSRF and path traversal:** The file contains no SQL, OS command execution, deserialization, reflection, XML parsing or outbound network calls. The only file path (`auth.log.dir`, `:623`) is an operator-supplied JVM system property, not request input.
- **Non-code files:** `README.md`, `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` and `prompt_hash.txt` contain no executable code. The README's demo credentials are covered by SEC-07.
