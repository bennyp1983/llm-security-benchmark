# Security Review: LoginService (Java login handling with brute-force throttling)

## 1. Executive Summary
`LoginService.java` is a self-contained Java 11+ login component. It checks a username and a `char[]` password against a pluggable `UserStore`. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes (600,000 iterations). Failed attempts are throttled per username and per client source, with lockouts that double in length up to a cap. The folder also holds a README and some metadata/prompt text files from the run that produced the code. None of those files contain executable code.

The cryptography is sound: strong KDF parameters, `SecureRandom` salts, constant-time comparison, and a dummy hash for unknown users. The account-enumeration defences also hold up. The weaknesses are in the **repeated-failed-login handling**, which is the part the component was meant to get right:

- **SEC-01 (High):** The lock check, the password verification and the failure recording are three separate steps, and nothing makes them atomic. An attacker who sends many attempts in parallel gets every one of them verified before the first failure is recorded. The 5-attempt limit becomes "as many as the server will run at once" per lockout window.
- **SEC-02 (Medium):** The per-username lock applies to every client. Anyone who knows a username can keep that account locked out indefinitely, and the exact retry time is disclosed to help them time it.
- **SEC-03 (Medium):** When the tracking table is full, entries are evicted even if they hold failure history or an active lock. An attacker can wipe a victim's counter or lock by flooding the table.
- **SEC-04 (Medium):** Usernames and client sources are stored as map keys without any length limit. The tables cap the number of entries but not their size, so memory can still be exhausted.
- **SEC-05 (Medium):** Per-source throttling is off when `clientSource` is `null`, and it keys on the raw string. Rotating IPv6 addresses or using different spellings of the same address gets around it. This leaves password spraying and PBKDF2 CPU exhaustion unthrottled.
- **SEC-06 (Low):** Accounts can be created with trivially weak passwords.
- **SEC-07 (Low):** Demo credentials are hardcoded in the production class.

This was a static review. No Java runtime was available in the environment, so none of the findings were confirmed by running the code.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginService.java` | The whole login component: public API types, `InMemoryUserStore`, `AttemptTracker` (failure counting and lockout), `PasswordHasher` (PBKDF2), and a scripted/interactive demo `main` | Password hashing and verification; constant-time comparison; defences against account enumeration and timing leaks; per-user and per-source brute-force throttling with exponential lockout; bounded in-memory tracking tables; synchronized shared state; wiping of `char[]` secrets; input length caps; hardcoded demo credentials; console password input |
| `README.md` | Explains the design, how to compile and run it, and how to integrate it | Deployment guidance: `clientSource` / `X-Forwarded-For` trust, TLS, MFA, counters kept only in memory. Reviewed to check that the documented claims match the code |
| `prompt.txt` | The original task prompt used to generate the code | None (text only) |
| `cyber_prompt.txt` | This review task's prompt | None (text only) |
| `result.md` | Metadata and summary of the generation run | None (text only) |
| `return.txt` | Raw JSON result of the generation run | None (text only; no secrets found) |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. It covered understanding each file, grepping skill names for the keywords (authentication, password, brute force, rate limit, race condition, crypto, credential, secret), and selecting and applying the skills listed below.
- `exploiting-race-condition-vulnerabilities`: Applied to the attempt-limiting logic in `LoginService.login()` (TOCTOU between the lock check, the PBKDF2 verification and the failure recording; the skill's "rate-limited operations (login attempts)" target). Result: SEC-01.
- `testing-api-authentication-weaknesses`: Applied to credential verification, account enumeration (response and message differences, timing), handling of disabled accounts, susceptibility to credential stuffing and spraying, and password policy at account creation. Results: SEC-02, SEC-05, SEC-06. Enumeration controls were verified in section 6.
- `implementing-api-rate-limiting-and-throttling`: Applied to how `AttemptTracker` is designed: per-user and per-IP keys, window and lockout semantics, `Retry-After` disclosure, and in-memory versus shared counters. Results: SEC-02, SEC-03.
- `performing-api-rate-limiting-bypass`: Applied to the choice of throttle keys: null or spoofable sources, IP rotation, rotating identifiers to dodge per-account limits, and resetting counters. Results: SEC-03, SEC-05.
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher`: KDF algorithm and iteration count, salt size and RNG, output length, constant-time comparison, weak algorithms, and hardcoded keys or passwords. The crypto itself had no finding (see section 6). Result: SEC-07 (hardcoded passwords).
- General OWASP Top 10 / CWE knowledge, used because no library skill matched: memory exhaustion through unbounded tracker keys (CWE-770, SEC-04), lockout as a denial-of-service lever (CWE-645, SEC-02), and handling of the demo console input (A04/A07). Injection, deserialization, file, command and network sinks were also checked, and none are present.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Concurrent login attempts bypass the failure threshold (check-then-act race) | High | CWE-367 | `LoginService.java:257-297` |
| SEC-02 | Per-username lockout lets any client keep a victim locked out indefinitely | Medium | CWE-645 | `LoginService.java:257-264` |
| SEC-03 | Evicting entries from a full tracker resets failure counters and active lockouts | Medium | CWE-307 | `LoginService.java:383-402` |
| SEC-04 | Unbounded username/source key length makes the "size-bounded" tables a memory-exhaustion vector | Medium | CWE-770 | `LoginService.java:293-294` |
| SEC-05 | Per-source throttling is disabled by a null source and bypassed by address rotation or formatting | Medium | CWE-307 | `LoginService.java:253-260` |
| SEC-06 | No password strength policy at account creation | Low | CWE-521 | `LoginService.java:189-192` |
| SEC-07 | Hardcoded demo credentials in the production class | Low | CWE-798 | `LoginService.java:468-469` |

## 5. Detailed Findings

### SEC-01: Concurrent login attempts bypass the failure threshold (check-then-act race)
- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `LoginService.java:257-297`

**Vulnerable code:**
```java
// LoginService.java:257-293
            // 1. Reject throttled attempts BEFORE touching the password, so a locked-out
            //    attacker learns nothing from further guesses.
            Duration userWait = userAttempts.remainingLock(userKey, now);
            Duration sourceWait = sourceKey == null ? Duration.ZERO : sourceAttempts.remainingLock(sourceKey, now);
            Duration wait = userWait.compareTo(sourceWait) >= 0 ? userWait : sourceWait;
            if (!wait.isZero()) {
                return new LoginResult(Status.LOCKED_OUT, null, wait);
            }

            // 2. Basic input validation (still counts as a failure, still takes hashing time).
            boolean inputValid = !userKey.isEmpty()
                    && userKey.length() <= MAX_USERNAME_LENGTH
                    && password != null
                    && password.length > 0
                    && password.length <= MAX_PASSWORD_LENGTH;

            // 3. Verify. Always perform one hash computation, whether or not the user exists.
            boolean authenticated;
            Optional<UserAccount> account = inputValid ? userStore.findByUsername(userKey) : Optional.empty();
            if (account.isPresent()) {
                boolean passwordOk = PasswordHasher.verify(password, account.get().passwordHash());
                authenticated = passwordOk && account.get().enabled();
            } else {
                PasswordHasher.verify(inputValid ? password : new char[] {'x'}, dummyHash);
                authenticated = false;
            }

            // 4. Record the outcome.
            if (authenticated) {
                userAttempts.reset(userKey);
                // The source counter is intentionally NOT reset on success: otherwise an attacker
                // could log into their own account periodically to clear the per-source counter
                // while guessing other users' passwords.
                return new LoginResult(Status.SUCCESS, account.get().username(), Duration.ZERO);
            }

            Duration userLock = userKey.isEmpty() ? Duration.ZERO : userAttempts.recordFailure(userKey, now);
```

**Why it is a problem:** `remainingLock()` and `recordFailure()` are each `synchronized`, but `login()` calls them as separate steps. Between them sits a PBKDF2 computation with 600,000 iterations, which takes hundreds of milliseconds. Nothing reserves an attempt slot when the check passes. Suppose an attacker sends N simultaneous guesses for `alice`, for example through HTTP/2 single-packet requests or a large thread pool. All N read "not locked" at step 1 before any failure is recorded, and all N get a full password verification. The lock only takes effect once the in-flight requests finish. Each request that arrives after the fifth failure keeps incrementing the counter, but none of them are stopped. In effect the limit of 5 failures per window (3 in the demo) becomes N guesses per lockout period, where N is bounded only by server concurrency. The per-source counter is bypassed the same way. This undermines the component's main anti-guessing guarantee ("further attempts are rejected without checking the password").

**Fix:** Reserve the attempt atomically, in the same critical section as the lock check. Track in-flight verifications, and reject a new attempt when `failures + inFlight` would reach the threshold. Release the reservation when the attempt is recorded or when it succeeds. Entries with in-flight attempts must not be evicted.
```java
private static final class Entry {
    int failures;
    int inFlight;              // attempts currently being verified
    int lockCount;
    Instant lastFailure = Instant.EPOCH;
    Instant lockedUntil = Instant.EPOCH;
}

/** Atomically checks the lock and reserves an attempt. Non-zero return = rejected. */
synchronized Duration tryAcquire(String key, Instant now) {
    Entry e = entries.get(key);
    if (e == null) {
        makeRoom(now);
        e = new Entry();
        entries.put(key, e);
    }
    if (now.isBefore(e.lockedUntil)) {
        return Duration.between(now, e.lockedUntil);
    }
    if (e.failures + e.inFlight >= threshold) {
        return policy.baseLockout;   // pending verifications already use up the budget
    }
    e.inFlight++;
    return Duration.ZERO;
}

synchronized void release(String key) {
    Entry e = entries.get(key);
    if (e != null && e.inFlight > 0) {
        e.inFlight--;
    }
}

// recordFailure(): add `if (e.inFlight > 0) e.inFlight--;` before `e.failures++;`
// makeRoom(): never evict entries with `e.inFlight > 0`

// In login():
String reservedUser = null;
String reservedSource = null;
try {
    Duration userWait = userAttempts.tryAcquire(userKey, now);
    if (!userWait.isZero()) {
        return new LoginResult(Status.LOCKED_OUT, null, userWait);
    }
    reservedUser = userKey;
    if (sourceKey != null) {
        Duration sourceWait = sourceAttempts.tryAcquire(sourceKey, now);
        if (!sourceWait.isZero()) {
            return new LoginResult(Status.LOCKED_OUT, null, sourceWait);
        }
        reservedSource = sourceKey;
    }
    // ... verify exactly as before ...
    if (authenticated) {
        userAttempts.reset(userKey);          // consumes the user reservation
        reservedUser = null;
        return new LoginResult(Status.SUCCESS, account.get().username(), Duration.ZERO);
    }
    Duration userLock = userAttempts.recordFailure(userKey, now);   // consumes reservation
    reservedUser = null;
    Duration sourceLock = sourceKey == null ? Duration.ZERO : sourceAttempts.recordFailure(sourceKey, now);
    reservedSource = null;
    // ... build result as before ...
} finally {
    if (reservedUser != null) userAttempts.release(reservedUser);       // e.g. store threw
    if (reservedSource != null) sourceAttempts.release(reservedSource);
    if (password != null) Arrays.fill(password, '\0');
}
```

### SEC-02: Per-username lockout lets any client keep a victim locked out indefinitely
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `LoginService.java:257-264` (also `LoginService.java:92-94`, `LoginService.java:141-145`, `LoginService.java:293`)

**Vulnerable code:**
```java
// LoginService.java:257-264
            // 1. Reject throttled attempts BEFORE touching the password, so a locked-out
            //    attacker learns nothing from further guesses.
            Duration userWait = userAttempts.remainingLock(userKey, now);
            Duration sourceWait = sourceKey == null ? Duration.ZERO : sourceAttempts.remainingLock(sourceKey, now);
            Duration wait = userWait.compareTo(sourceWait) >= 0 ? userWait : sourceWait;
            if (!wait.isZero()) {
                return new LoginResult(Status.LOCKED_OUT, null, wait);
            }
// LoginService.java:92-94
                case LOCKED_OUT:
                    return "Too many failed login attempts. Please try again in "
                            + Math.max(1, (retryAfter.toMillis() + 999) / 1000) + " second(s).";
```

**Why it is a problem:** The username lock is global. Once it is set, every client is refused, including the real owner with the correct password. It takes 5 bad attempts from anywhere to set it, and the per-source limit of 20 is well above that. The class Javadoc and README say an attacker "can't disable the account for good", but that is only true of a single lock. An attacker can send 5 wrong passwords right when each lock expires, and `userMessage()` / `retryAfter()` tell them exactly when that is. `lockCount` keeps growing because the history is never quiet for a full `failureWindow`, so the account stays locked around the clock for about 5 requests per hour. Four victims per source IP can be held this way, and many more with several IPs. Usernames are often public (emails, handles), so this is a cheap, targeted denial of service against specific users such as administrators.

**Fix:** Apply the hard lock only to the (username, source) pair that is misbehaving. Across all sources, give a username a much higher threshold, and when it is reached, respond with step-up friction (CAPTCHA, MFA or an emailed login link) instead of refusing the correct password. Don't give unauthenticated callers precise lock-expiry timing.
```java
// New tracker keyed on the pair; the global per-user tracker uses a much higher threshold
// (e.g. 100) and triggers step-up authentication rather than a hard refusal.
String pairKey = userKey + ' ' + (sourceKey == null ? "" : sourceKey);
Duration pairWait = userSourceAttempts.remainingLock(pairKey, now);
Duration sourceWait = sourceKey == null ? Duration.ZERO : sourceAttempts.remainingLock(sourceKey, now);
Duration wait = pairWait.compareTo(sourceWait) >= 0 ? pairWait : sourceWait;
if (!wait.isZero()) {
    return new LoginResult(Status.LOCKED_OUT, null, wait);
}
boolean stepUpRequired = userAttempts.failuresInWindow(userKey, now) >= policy.globalUserStepUpThreshold;
// ... if stepUpRequired, verify CAPTCHA/MFA before (not instead of) the password ...

// userMessage(): do not disclose the exact expiry
case LOCKED_OUT:
    return "Too many failed login attempts. Please try again later.";
```

### SEC-03: Evicting entries from a full tracker resets failure counters and active lockouts
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginService.java:383-402`

**Vulnerable code:**
```java
// LoginService.java:383-402
        private void makeRoom(Instant now) {
            if (entries.size() < policy.maxTrackedKeys) {
                return;
            }
            entries.values().removeIf(e -> !now.isBefore(e.lockedUntil) && isStale(e, now));
            // Still full: evict least-recently-used entries that are not currently locked.
            var it = entries.values().iterator();
            while (entries.size() >= policy.maxTrackedKeys && it.hasNext()) {
                Entry e = it.next();
                if (!now.isBefore(e.lockedUntil)) {
                    it.remove();
                }
            }
            // Everything is locked: evict the least-recently-used entry regardless.
            it = entries.values().iterator();
            while (entries.size() >= policy.maxTrackedKeys && it.hasNext()) {
                it.next();
                it.remove();
            }
        }
```

**Why it is a problem:** Once the table reaches `maxTrackedKeys` (100,000 by default), each new key evicts an entry. The second loop removes the least-recently-used entry that is not locked, even if it has `failures = threshold - 1` or a high `lockCount` from recent attacks. The third loop removes entries that are locked right now. Every attempt is recorded under a username, and unknown usernames are tracked too, so an attacker can churn the table with random names. Doing that from many sources, or with a null source (see SEC-05), avoids the per-source limit. The attack goes: make 4 guesses against `alice`, flood new junk usernames until alice's entry is evicted, and repeat with a fresh counter. If the attacker instead fills the table with locked junk entries, even an active lock on the victim is dropped. Exponential back-off is also lost, because `lockCount` goes with the evicted entry.

**Fix:** Never evict entries that still carry live failure history or an active lock. Remove only stale entries. If the table is still full, fail closed for keys that aren't tracked yet by applying a short throttle to them. Alert on saturation and size the store (or use a shared Redis/DB store) so this doesn't happen under normal load.
```java
/** Returns false if there is no room without discarding live throttling state. */
private boolean makeRoom(Instant now) {
    if (entries.size() < policy.maxTrackedKeys) {
        return true;
    }
    entries.values().removeIf(e -> e.inFlight == 0 && !now.isBefore(e.lockedUntil) && isStale(e, now));
    return entries.size() < policy.maxTrackedKeys;
}

synchronized Duration recordFailure(String key, Instant now) {
    Entry e = entries.get(key);
    if (e == null) {
        if (!makeRoom(now)) {
            // Table saturated (likely an attack): throttle untracked keys instead of
            // forgetting the history of tracked ones. Emit a security alert here.
            return policy.baseLockout;
        }
        e = new Entry();
        entries.put(key, e);
    } else if (isStale(e, now)) {
        e.failures = 0;
        e.lockCount = 0;
    }
    // ... unchanged ...
}
```

### SEC-04: Unbounded username/source key length makes the "size-bounded" tables a memory-exhaustion vector
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `LoginService.java:293-294` (keys derived at `LoginService.java:254-255` and `LoginService.java:307-309`)

**Vulnerable code:**
```java
// LoginService.java:254-255
            String userKey = normalizeUsername(username);
            String sourceKey = clientSource == null ? null : clientSource.trim();
// LoginService.java:293-294
            Duration userLock = userKey.isEmpty() ? Duration.ZERO : userAttempts.recordFailure(userKey, now);
            Duration sourceLock = sourceKey == null ? Duration.ZERO : sourceAttempts.recordFailure(sourceKey, now);
```

**Why it is a problem:** `MAX_USERNAME_LENGTH` only feeds the `inputValid` flag. A username longer than 256 characters still goes through `trim().toLowerCase()`, which copies the whole string, and it is still stored as a map key by `recordFailure(userKey, now)`. `clientSource` has no length limit at all, and it is attacker-controlled when an integrator derives it from `X-Forwarded-For`. The tables cap the **number** of keys (100,000) but not their **size**. For example, 100,000 usernames of 1 MB each come to about 100 GB of retained heap, which is an `OutOfMemoryError` for the whole application. Each distinct key needs at most one request, so the per-source limit doesn't slow this down meaningfully once sources rotate (SEC-05). This contradicts the documented guarantee that the tables "cannot be used to exhaust memory".

**Fix:** Check raw lengths before normalizing, and map oversize values to a single shared bucket so they are still throttled but can't grow memory. Optionally store a fixed-size digest of the key instead of the raw string.
```java
private static final int MAX_SOURCE_LENGTH = 64;
private static final String OVERSIZE_USER_KEY = " oversize-user";
private static final String OVERSIZE_SOURCE_KEY = " oversize-source";

boolean usernameTooLong = username != null && username.length() > MAX_USERNAME_LENGTH;
String userKey = usernameTooLong ? OVERSIZE_USER_KEY : normalizeUsername(username);
String sourceKey = clientSource == null ? null
        : clientSource.length() > MAX_SOURCE_LENGTH ? OVERSIZE_SOURCE_KEY
        : clientSource.trim();

boolean inputValid = !usernameTooLong
        && !userKey.isEmpty()
        && password != null
        && password.length > 0
        && password.length <= MAX_PASSWORD_LENGTH;
```

### SEC-05: Per-source throttling is disabled by a null source and bypassed by address rotation or formatting
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginService.java:253-260` (also `LoginService.java:294`)

**Vulnerable code:**
```java
// LoginService.java:253-260
            Instant now = clock.instant();
            String userKey = normalizeUsername(username);
            String sourceKey = clientSource == null ? null : clientSource.trim();

            // 1. Reject throttled attempts BEFORE touching the password, so a locked-out
            //    attacker learns nothing from further guesses.
            Duration userWait = userAttempts.remainingLock(userKey, now);
            Duration sourceWait = sourceKey == null ? Duration.ZERO : sourceAttempts.remainingLock(sourceKey, now);
```

**Why it is a problem:** The per-source counter is the only defence against password spraying, where one common password is tried across many usernames and each account stays below its own limit of 5. It fails in three ways:
1. **Null source.** The API documents `clientSource` as "may be null", and in that case source throttling is skipped entirely. An integrator who passes `null` (for instance because the address isn't available in that layer) gets unlimited spraying across all accounts.
2. **Rotation.** The key is the raw address string. A single IPv6 host usually controls a /64, which is 2^64 addresses, so each attempt can use a fresh key and never reach 20 failures.
3. **Formatting variants.** `::1`, `0:0:0:0:0:0:0:1`, `::ffff:127.0.0.1` and `[::1]` all count as different sources.

Every unthrottled attempt also costs a 600,000-iteration PBKDF2 run, including for unknown or invalid usernames. The same bypass therefore lets an attacker exhaust server CPU (CWE-400).

**Fix:** Require a source. Canonicalize it by parsing IP literals only, without DNS lookups, and group IPv6 addresses by /64. Add a global limit on concurrent hashing so CPU use stays bounded however the throttling is sidestepped.
```java
private final java.util.concurrent.Semaphore hashPermits = new java.util.concurrent.Semaphore(16);

static String canonicalSource(String clientSource) {
    Objects.requireNonNull(clientSource, "clientSource is required for brute-force protection");
    String s = clientSource.trim();
    boolean ipv4 = s.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    boolean ipv6 = s.length() <= 45 && s.matches("[0-9A-Fa-f:.]+") && s.indexOf(':') >= 0;
    if (!ipv4 && !ipv6) {
        return "invalid-source";                       // shared bucket, never resolved via DNS
    }
    try {
        byte[] addr = java.net.InetAddress.getByName(s).getAddress();  // literal parsing only
        if (addr.length == 16) {
            addr = Arrays.copyOf(addr, 8);             // throttle IPv6 per /64
        }
        return Base64.getEncoder().encodeToString(addr);
    } catch (java.net.UnknownHostException e) {
        return "invalid-source";
    }
}

// In login():
String sourceKey = canonicalSource(clientSource);
// ... and wrap the PBKDF2 verification:
if (!hashPermits.tryAcquire()) {
    return new LoginResult(Status.LOCKED_OUT, null, Duration.ofSeconds(1));
}
try {
    // verify as before
} finally {
    hashPermits.release();
}
```

### SEC-06: No password strength policy at account creation
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `LoginService.java:189-192`

**Vulnerable code:**
```java
// LoginService.java:189-192
                if (password == null || password.length == 0) {
                    throw new IllegalArgumentException("password must not be empty");
                }
                UserAccount account = new UserAccount(normalized, PasswordHasher.hash(password), true);
```

**Why it is a problem:** `createAccount` accepts any non-empty password, such as `"a"`, `"123456"` or `"password"`. The README shows this method being used in an application. Throttling limits guesses per account, but spraying the most common passwords across many accounts (SEC-05) still succeeds against weak ones. There is also no upper bound here, so a password longer than 1,024 characters can be created but can never be used to log in (`MAX_PASSWORD_LENGTH` is checked at line 271). That is a functional inconsistency that locks the user out of their own account.

**Fix:** Enforce NIST SP 800-63B-style rules: a minimum length (15 when the password is the only factor), the same maximum as login, and a check against a list of breached or common passwords.
```java
private static final int MIN_PASSWORD_LENGTH = 15;

if (password == null
        || password.length < MIN_PASSWORD_LENGTH
        || password.length > MAX_PASSWORD_LENGTH) {
    throw new IllegalArgumentException(
            "password must be between " + MIN_PASSWORD_LENGTH + " and " + MAX_PASSWORD_LENGTH + " characters");
}
if (compromisedPasswords.contains(password)) {   // e.g. HIBP k-anonymity or a local blocklist
    throw new IllegalArgumentException("password is too common or has appeared in a breach");
}
UserAccount account = new UserAccount(normalized, PasswordHasher.hash(password), true);
```

### SEC-07: Hardcoded demo credentials in the production class
- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginService.java:468-469` (printed at `LoginService.java:485` and `LoginService.java:514`)

**Vulnerable code:**
```java
// LoginService.java:466-469
    public static void main(String[] args) {
        InMemoryUserStore store = new InMemoryUserStore();
        store.createAccount("alice", "CorrectHorseBatteryStaple".toCharArray());
        store.createAccount("bob", "s3cure-Passw0rd!".toCharArray());
// LoginService.java:485
        System.out.println("Demo accounts: alice / CorrectHorseBatteryStaple, bob / s3cure-Passw0rd!");
```

**Why it is a problem:** The demo `main`, its fixed passwords, and the code that prints them all ship inside the production `LoginService` class, and the README documents them. If the class goes out as-is, anyone who runs the entry point (or copies the setup into a real app) gets accounts whose passwords are public in source, docs and logs. Credentials in source also end up in version control and in build artifacts. The interactive demo also reads the password into an immutable `String` and echoes it when no console is present (lines 534-535). It warns before doing so, but the password stays in memory and on screen.

**Fix:** Move the demo into a separate class that is left out of production builds. Generate a random one-time password per run, or read it from the environment, instead of embedding literals.
```java
// LoginServiceDemo.java (excluded from production artifacts)
public static void main(String[] args) {
    LoginService.InMemoryUserStore store = new LoginService.InMemoryUserStore();
    char[] alicePassword = System.getenv("DEMO_ALICE_PASSWORD") != null
            ? System.getenv("DEMO_ALICE_PASSWORD").toCharArray()
            : randomPassword(24);
    System.out.println("Demo account 'alice' created with a one-time random password (shown once):");
    System.out.println(new String(alicePassword));
    store.createAccount("alice", alicePassword);   // wipes alicePassword
}

private static char[] randomPassword(int length) {
    java.security.SecureRandom rng = new java.security.SecureRandom();
    char[] out = new char[length];
    for (int i = 0; i < length; i++) {
        out[i] = (char) ('!' + rng.nextInt(94));
    }
    return out;
}
```

## 6. Verified Controls and Checks With No Finding
- **Password hashing algorithm and parameters:** PBKDF2WithHmacSHA256 with 600,000 iterations (the OWASP recommendation), a 16-byte per-password salt from `SecureRandom`, and 256-bit output. No MD5, SHA-1, DES, ECB or unsalted hashing anywhere (`LoginService.java:406-424`, `LoginService.java:446-455`).
- **Constant-time comparison:** Hashes are compared with `MessageDigest.isEqual` (`LoginService.java:440`).
- **Randomness:** Salts and the dummy password both come from `SecureRandom`. `java.util.Random` and time-based seeds are not used (`LoginService.java:234-239`, `LoginService.java:412`, `LoginService.java:420`).
- **Enumeration via messages or status:** Unknown user, wrong password and disabled account all return `INVALID_CREDENTIALS` with the same message. `LoginResult.toString()` leaves out the username (`LoginService.java:87-103`, `LoginService.java:276-282`).
- **Enumeration via timing:** Unknown or invalid usernames are verified against a dummy hash with the same algorithm, iteration count and output length, so every path costs one PBKDF2 run (`LoginService.java:221-241`, `LoginService.java:273-282`). Disabled accounts still go through a full verification (`LoginService.java:277-278`).
- **Enumeration via lockout:** Non-existent usernames are tracked and locked the same way as real ones (`LoginService.java:293`).
- **Locked-out attempts skip the password check:** Attempts are rejected before the password is verified when a lock is already recorded (`LoginService.java:257-264`). The concurrency gap is covered in SEC-01.
- **Resetting the source counter via your own account:** A successful login resets only the username counter, not the source counter (`LoginService.java:285-290`).
- **Lockout duration arithmetic:** The exponential back-off caps the shift and checks for overflow before multiplying, then caps the result at `maxLockout` (`LoginService.java:368-376`). `LockoutPolicy` rejects non-positive thresholds and durations (`LoginService.java:125-132`).
- **Robust parsing of stored hashes:** A malformed prefix, part count, Base64, iteration count or empty hash returns `false` instead of throwing (`LoginService.java:427-444`). The iteration count read from the store has no upper or lower bound. That is acceptable only because the `UserStore` is treated as trusted, and write access to it would already allow account takeover.
- **Secret hygiene in memory:** Passwords arrive as `char[]` and are wiped in `finally` blocks, and `PBEKeySpec.clearPassword()` is called (`LoginService.java:196-200`, `LoginService.java:300-304`, `LoginService.java:453`). The password length is capped at 1,024 on login, which limits HMAC and PBKDF2 input cost (`LoginService.java:266-271`).
- **Normalization consistency:** Account creation, lookup and throttling all use the same `normalizeUsername` (trim plus `toLowerCase(Locale.ROOT)`), so case variants can't create a separate account or a separate throttle bucket for the same login (`LoginService.java:185`, `LoginService.java:254`, `LoginService.java:307-309`).
- **Thread safety of individual operations:** Tracker methods are `synchronized`, and the in-memory store uses `ConcurrentHashMap.putIfAbsent` to prevent duplicate-account races (`LoginService.java:193`, `LoginService.java:332-366`). The race across multiple operations is covered in SEC-01.
- **Injection, deserialization, file, command and network sinks:** None present. No SQL, no reflection, no `ObjectInputStream`, no file or path access, no `Runtime.exec`, no outbound network calls, and no XML parsing in `LoginService.java`.
- **Secrets in the non-code files:** `README.md`, `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` and `prompt_hash.txt` were checked. They contain no keys, tokens or real credentials, only the documented demo passwords already reported in SEC-07. The README's guidance to trust `X-Forwarded-For` only from your own proxy, to use TLS and to add MFA is correct.
