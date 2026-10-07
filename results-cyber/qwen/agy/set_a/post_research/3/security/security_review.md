# Security Review: Secure Java Authentication System (`secure-auth-system:1.0.0`)

## 1. Executive Summary

This is a Java 17 / Maven command-line authentication component (`com.example.auth`, artifact `secure-auth-system:1.0.0`) that registers users and authenticates an email/password pair against an embedded H2 database over JDBC, issuing an in-memory bearer session on success. Read on its own terms, the core credential handling is competently written: a modern key derivation function (`PBKDF2WithHmacSHA256`, 210,000 iterations, 16-byte random salt, 256-bit key), `SecureRandom` for all security-relevant randomness, `MessageDigest.isEqual` for digest comparison, exclusively parameterised SQL, `char[]` password handling with deliberate zeroization in `finally` blocks, revalidation of hostile database-supplied hash parameters before use, CRLF neutralisation and email masking on the audit path. Those controls are individually verified and are recorded in section 6 rather than reported as findings.

Where the design fails is at the boundaries the author did not treat as hostile: process configuration, the caller-supplied client identity, and the operating-system and resource layer around the crypto. Several findings are additionally instances of a rule the README asserts but the code does not implement, which matters because integrators read the README as a contract and will build on controls that are not there.

**19 findings: 6 High, 9 Medium, 4 Low.**

Two clusters account for most of the severity. The first is configuration trust: `AUTH_DB_URL` is passed to `DriverManager.getConnection` with no validation (SEC-01), and in H2 a URL may carry an `INIT=RUNSCRIPT FROM 'http://…'` or `CREATE ALIAS` directive, so whoever controls that variable obtains arbitrary Java execution at connect time — while the same unvalidated string also selects a directory that the code then `chmod`s to `0700` (SEC-02), letting it rewrite permissions on arbitrary world-readable paths. The second is abuse control, which is the component's stated specialty and is the weakest part of it: the limiter counts *attempts* rather than failures and refunds only on success, so an attacker driving wrong passwords locks the legitimate owner out (SEC-03); its notion of "who" is the `AUTH_SOURCE_ID` environment variable, which the caller invents (SEC-04); its composite key is joined with a `:` that the source-id pattern itself permits (SEC-09); and the only cross-source mechanism is an advisory `Thread.sleep` aimed at whoever knocks next on a targeted mailbox — precisely the lockout-denial-of-service the README lists as defeated (SEC-07). Between the clusters sit a raw bearer token printed to stdout (SEC-05), a `validateSession()` that no production path ever calls (SEC-16), and three public getters that hand out the limiter, the session factory and the hasher, two of them bypass-shaped and all three with zero internal call sites (SEC-06).

The remaining findings are residual oracles and resource ceilings. Enumeration is mitigated but not "completely defeated": the equalising dummy path always pays a hard-wired 210,000 iterations while the real path honours whatever the database row says, between 100,000 and 10,000,000 (SEC-10), and the SQL-error and rate-limit strings differ from the credentials-failure string (SEC-10); that same 10,000,000 ceiling converts a single login into minutes of CPU for anyone able to plant or register a row (SEC-11).

Remediate in this order: SEC-01 and SEC-02 (remote code execution and permission tampering from one unvalidated variable), then SEC-05 and SEC-06 (token disclosure and exposed bypass primitives), then the abuse-control cluster SEC-03, SEC-04 and SEC-07, then the rest.

## 2. Scope

Review was **static only**. The source tree is mounted read-only and was not modified; nothing in it was built, installed, executed or imported — no `mvn`, no `java`, no test run — and no helper script belonging to the skill library was executed. Findings rest on reading the files; runtime claims are framed as code properties, not observations.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/Main.java` | CLI entry point: argument parsing, register and login flows, credential prompts | Reads `AUTH_DB_URL`, `AUTH_SOURCE_ID`; prints session token and cookie to stdout; hand-rolled password reader with length cap and byte→char cast; auto-registration when the user table is empty |
| `src/main/java/com/example/auth/DatabaseManager.java` | Owns the JDBC URL, credentials, schema DDL and connections | Resolves URL/user/password from environment with `sa`/empty defaults; passes URL verbatim to `DriverManager`; derives a filesystem path from the URL and applies POSIX modes |
| `src/main/java/com/example/auth/AuthenticationService.java` | Login and registration orchestration | Orders limiter before validation and lookup; dummy-KDF paths for timing equalisation; session issuance; public getters for security components |
| `src/main/java/com/example/auth/RateLimiter.java` | Per-source, per-(source,account) and per-account throttling with progressive delay | Attempt vs failure accounting; composite `source:email` key; three unbounded-at-10k maps; blocking delay consumed by caller; `resetAll()` |
| `src/main/java/com/example/auth/SessionManager.java` | Issues and stores bearer sessions | 256-bit `SecureRandom` token; cookie string; `ConcurrentHashMap` lookup; expiry-only eviction; validation/revocation API unused in production |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2 hashing and verification | Iteration/salt/key policy; dummy verification path with hardcoded filler; honours database-supplied iteration count |
| `src/main/java/com/example/auth/InputValidator.java` | Email, password, source-id and database-row validation | Email regex and bounds; password length-only policy; `sourceId` pattern permitting `:`; PBKDF2 iteration window 100,000–10,000,000 |
| `src/main/java/com/example/auth/UserRepository.java` | Data access for `users` | Parameterised SELECT/INSERT/COUNT; fail-closed validation of stored hash parameters |
| `src/main/java/com/example/auth/SecurityLogger.java` | Audit and error logging | Email/token masking, CRLF sanitisation, console handler, throwable attachment |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Outcome value object | Four fixed user-facing messages; session exposure on success |
| `src/main/java/com/example/auth/UserRecord.java` | Persisted user row | `isActive()` requires exact status `ACTIVE` |
| `src/main/java/com/example/auth/HashResult.java` | Derived hash bundle | Compact constructor validating material lengths |
| `pom.xml` | Build | Java 17, `-Xlint:all -Werror`, H2 2.2.224 in compile scope, shade plugin, no dependency-analysis plugin |
| `README.md` | Documents eight security rules and an adversarial-findings matrix | Used as the control contract: claims are checked against code and contradicted where necessary |
| `src/test/java/com/example/auth/*` | Six test classes | Census of test annotations only, to size the README's test claim; not used as evidence of behaviour |

Out of scope: `target/` (build output, including shaded jars), `dependency-reduced-pom.xml` (shade by-product), and the harness files `prompt.txt`, `prompt_hash.txt`, `return.txt`, `result.md`. The source folder is **not a git repository**, so there is no baseline or merge-base to compare against; every finding below is therefore new-surface rather than a regression.

## 3. Skills Applied

Skill selection followed the library's routing method: the sibling skill **names** were grepped, then only the `description` frontmatter of plausible candidates was skimmed, and the shortlist was ordered by the severity class each checklist could actually bear on. The library was never loaded wholesale, and no skill script was executed.

| Skill | Why selected | What it drove |
|---|---|---|
| `performing-cryptographic-audit-of-application` | KDF choice, work factor, salt handling, comparison and key-management review are its subject | SEC-10, SEC-11, SEC-19, and the section 6 checks on KDF parameters, constant-time comparison, randomness and zeroization |
| `testing-api-authentication-weaknesses` | Token validation, session management, credential lifetime and enumeration are its checklist | SEC-10, SEC-16, SEC-17, and the section 6 checks on token entropy and cookie attributes |
| `implementing-api-abuse-detection-with-rate-limiting` | The component's own specialty: what a limiter must count, keyed on what, bounded how | SEC-03, SEC-04, SEC-07, SEC-08, SEC-09, SEC-15 |
| `testing-for-sensitive-data-exposure` | Secrets reaching logs, stdout and heap | SEC-05, SEC-13, SEC-19 |
| `exploiting-sql-injection-vulnerabilities` | Ran as a **negative** checklist to confirm the data-access layer rather than assume it | No finding; section 6 check 1 |
| `testing-for-broken-access-control` | Considered for privilege and object-level checks | Description-level only; **no finding** — the component has no roles, tenants or object references; the closest analogue is reported as SEC-06 |
| `implementing-secret-scanning-with-gitleaks` | Only the hardcoded-credential angle | Contributes the secret-hygiene half of SEC-19 |
| `detecting-anomalous-authentication-patterns` | Detection-side view of what the limiter should be emitting | Context for SEC-03 and SEC-04; no finding of its own |

**Findings reached with general OWASP/CWE knowledge, where no specialised skill in this library matched.** SEC-01 (trusting a JDBC URL as configuration, CWE-20 / CWE-94 / CWE-15), SEC-02 (path derived from untrusted configuration and a permission side effect on it, CWE-22 / CWE-281), SEC-06 (exposed dangerous methods, CWE-749 escalating to CWE-284 / CWE-639), SEC-12 (embedded-database bootstrap defaults, CWE-1392 / CWE-306 / CWE-312), the resource-ceiling reasoning in SEC-08, SEC-11 and SEC-15 (CWE-400 / CWE-770), SEC-14 (silent truncation and lossy decoding at a credential boundary, CWE-20 / CWE-244), and the registration time-of-check/time-of-use race examined in section 6 (CWE-367 considered, not filed because it fails closed).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unvalidated `AUTH_DB_URL` reaches `DriverManager`, enabling H2 `INIT=RUNSCRIPT` remote code execution and a hostile credential store | High | CWE-20, CWE-94, CWE-15 | `DatabaseManager.java:132-138`, `:39-49`, `:55-57` |
| SEC-02 | `chmod 0700` applied to any existing directory named by the unvalidated URL, with no traversal check | High | CWE-22, CWE-281 | `DatabaseManager.java:91-126` (esp. `:100-112`) |
| SEC-03 | Rate limiter consumes a permit on every attempt and refunds only on success, locking out legitimate users | High | CWE-307, CWE-362 | `RateLimiter.java:116-130`, `:147-159`; `AuthenticationService.java:64-69` |
| SEC-04 | Rate-limit identity is a caller-supplied environment variable; invalid values collapse unrelated users into shared buckets | High | CWE-290, CWE-770 | `Main.java:76-79`; `InputValidator.java:118-131` |
| SEC-05 | Raw bearer token printed to stdout in the `Cookie:` line | High | CWE-532, CWE-200 | `Main.java:85-88`; `SessionManager.java:80-83` |
| SEC-06 | Public getters expose the limiter, session factory and hasher; `resetAll()` disarms throttling, `createSession()` mints sessions with no credential check | High | CWE-749, CWE-284, CWE-639 | `AuthenticationService.java:189-199`; `RateLimiter.java:216-224`; `SessionManager.java:64-88` |
| SEC-07 | Global email-keyed progressive `Thread.sleep` lets an attacker throttle the legitimate owner of a mailbox | Medium | CWE-307, CWE-400 | `RateLimiter.java:132-142`, `:150-159`; `AuthenticationService.java:71-80` |
| SEC-08 | Cache bound is not enforced: purge removes only already-expired entries, and there is no LRU despite the documentation | Medium | CWE-400, CWE-770 | `RateLimiter.java:186-192`, `:194-214` |
| SEC-09 | Delimiter collision in the `source:email` composite rate-limit key | Medium | CWE-20, CWE-74 | `RateLimiter.java:114`, `:168`; `InputValidator.java:31-34` |
| SEC-10 | Timing and message oracles still distinguish an existing account | Medium | CWE-208, CWE-211 | `PasswordHasher.java:127`, `:157`; `AuthenticationService.java:94-101`; `AuthenticationResult.java:22-24` |
| SEC-11 | Database-supplied iteration count up to 10,000,000 turns one login into minutes of CPU | Medium | CWE-400, CWE-770 | `InputValidator.java:36-38`, `:148-150`; `PasswordHasher.java:117-127` |
| SEC-12 | Default DB credentials (`sa`/empty), unencrypted file store, and first-actor-wins auto-registration | Medium | CWE-1392, CWE-306, CWE-312 | `DatabaseManager.java:27-29`, `:140-148`; `Main.java:51-57` |
| SEC-13 | Throwables attached to `SEVERE` records are rendered to stderr by the console handler, leaking internals | Medium | CWE-209, CWE-532 | `SecurityLogger.java:21-35`, `:109-111` |
| SEC-14 | Password silently truncated at 128 characters and decoded byte→char, so the verified secret is not the typed one | Medium | CWE-20, CWE-244 | `Main.java:178-195`, `:150-162` |
| SEC-15 | Registration is completely unthrottled and pays full KDF cost per call | Medium | CWE-770, CWE-400 | `AuthenticationService.java:147-187` |
| SEC-16 | Sessions are never validated or revoked in production code; no idle timeout and no binding | Low | CWE-613 | `SessionManager.java:42`, `:90-113`, `:115-125` |
| SEC-17 | Session-token lookup is not constant-time (mitigated by 256-bit entropy) | Low | CWE-208 | `SessionManager.java:98` |
| SEC-18 | Password policy is length-only, with no breached-password or account-derived rejection | Low | CWE-521 | `InputValidator.java:98-110` |
| SEC-19 | Token mask reveals 8 of 43 characters, and the dummy password is a hardcoded, never-zeroized literal | Low | CWE-200, CWE-798 | `SecurityLogger.java:74-82`; `PasswordHasher.java:26-42` |

## 5. Detailed Findings

### SEC-01: Unvalidated `AUTH_DB_URL` reaches `DriverManager`, enabling H2 `INIT=RUNSCRIPT` remote code execution and a hostile credential store

**Severity:** High

**CWE:** CWE-20 (Improper Input Validation), CWE-94 (Improper Control of Generation of Code), CWE-15 (External Control of System or Configuration Setting)

**Location:** `src/main/java/com/example/auth/DatabaseManager.java:132-138`, `:39-49`, `:55-57`

**Vulnerable code:** `DatabaseManager.java:132-138`

```java
    private static String resolveDatabaseUrl() {
        String envUrl = System.getenv("AUTH_DB_URL");
        if (envUrl != null && !envUrl.isBlank()) {
            return envUrl.trim();
        }
        return DEFAULT_IN_MEMORY_URL;
    }
```

**Vulnerable code:** `DatabaseManager.java:39-49`

```java
    public DatabaseManager(String dbUrl, String dbUser, String dbPassword) {
        if (dbUrl == null || dbUrl.isBlank()) {
            throw new IllegalArgumentException("Database URL cannot be null or blank");
        }
        this.dbUrl = dbUrl;
        this.dbUser = (dbUser != null) ? dbUser : "";
        this.dbPassword = (dbPassword != null) ? dbPassword : "";

        ensureSecureFilePermissionsIfLocal(this.dbUrl);
        initializeSchema();
    }
```

**Vulnerable code:** `DatabaseManager.java:55-57`

```java
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(this.dbUrl, this.dbUser, this.dbPassword);
    }
```

**Why it is a problem:** The only check applied to the environment-supplied URL anywhere on its path is "not null and not blank", plus `trim()`. An H2 JDBC URL is not an opaque address — it is a small configuration language, and the only consumer of this string is `DriverManager.getConnection`. Two of its features turn attacker-controlled URL text into code execution at connect time: the `INIT=` property, which executes SQL against the new connection before it is returned, and `RUNSCRIPT FROM 'http://host/file.sql'`, which fetches and executes an arbitrary remote script. A single statement in that script — `CREATE ALIAS PWN FOR 'pkg.Class.run'` — causes H2 to compile and invoke arbitrary Java in the application's own process, with the application's own file and network privileges, before `initializeSchema()` returns. No credential or file write is needed to reach it; the trigger is the first `getConnection()` call, which the CLI performs unconditionally at start-up. The same variable additionally allows `jdbc:h2:tcp://attacker/...`, which silently redirects the entire credential store — every email, salt and PBKDF2 hash — to a server the attacker runs, and which then also controls the `iterations` and `algorithm` values the code later trusts for work-factor decisions (see SEC-11). `AUTH_DB_USER` and `AUTH_DB_PASSWORD` are read from the same trust domain (SEC-12), so one environment-setting primitive on either side of the deployment — a CI variable, a container manifest, a `.env` committed to a repo, a compromised deploy step — yields code execution, exfiltration, and permission tampering (SEC-02) at once. The README treats `AUTH_DB_URL` purely as convenience configuration and lists env-based configuration as a control (Rule "credentials never hardcoded"), so an integrator has no signal that this variable is a code-execution surface.

**Fix:** Treat the URL as untrusted input and constrain it to the two shapes the component actually needs, rejecting anything that can carry instructions. Prefer constructing the URL from validated parts over parsing a caller's string at all.

```java
    private static final Pattern APPROVED_H2_URL = Pattern.compile(
            "jdbc:h2:(?:mem:[A-Za-z0-9_\\-/]{1,64}"
          + "|\\./(?:[A-Za-z0-9_\\-]+/){0,4}[A-Za-z0-9_\\-]{1,64})"
          + "(?:;(?:DB_CLOSE_DELAY=-1|DB_CLOSE_ON_EXIT=FALSE|CIPHER=AES)){0,3}"
    );

    /** Directive- and transport-denied, so the string can never select behaviour. */
    static String validateDatabaseUrl(String candidate) {
        String url = (candidate == null || candidate.isBlank())
                ? DEFAULT_IN_MEMORY_URL : candidate.trim();
        String upper = url.toUpperCase(Locale.ROOT);
        for (String banned : List.of("INIT", "RUNSCRIPT", "CREATE ALIAS", "SHUTDOWN",
                                     "TCP:", "SSL:", "AUTO_SERVER")) {
            if (upper.contains(banned)) {
                throw new IllegalArgumentException("Database URL rejected: forbidden directive");
            }
        }
        if (!APPROVED_H2_URL.matcher(url).matches()) {
            throw new IllegalArgumentException("Database URL rejected: not an approved local H2 URL");
        }
        return url;
    }
```

Call it before the field is assigned so no other code path can observe an unvalidated value, and keep the check in the constructor so library callers who pass `dbUrl` directly are covered too:

```java
    public DatabaseManager(String dbUrl, String dbUser, String dbPassword) {
        this.dbUrl = validateDatabaseUrl(dbUrl);   // replaces the null/blank check
        this.dbUser = (dbUser != null) ? dbUser : "";
        this.dbPassword = (dbPassword != null) ? dbPassword : "";

        ensureSecureFilePermissionsIfLocal(this.dbUrl);
        initializeSchema();
    }
```

---

### SEC-02: `chmod 0700` applied to any existing directory named by the unvalidated URL, with no traversal check

**Severity:** High

**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-281 (Improper Preservation of Permissions)

**Location:** `src/main/java/com/example/auth/DatabaseManager.java:91-126` (in particular `:100-112`)

**Vulnerable code:** `DatabaseManager.java:91-99`

```java
    private static void ensureSecureFilePermissionsIfLocal(String jdbcUrl) {
        if (jdbcUrl.startsWith("jdbc:h2:./") || jdbcUrl.startsWith("jdbc:h2:/")) {
            try {
                // Extract file path from H2 JDBC URL
                String rawPath = jdbcUrl.substring("jdbc:h2:".length());
                int semicolonIdx = rawPath.indexOf(';');
                if (semicolonIdx >= 0) {
                    rawPath = rawPath.substring(0, semicolonIdx);
                }
```

**Vulnerable code:** `DatabaseManager.java:100-112`

```java
                Path path = Paths.get(rawPath);
                Path parent = path.getParent();
                if (parent != null) {
                    if (!Files.exists(parent)) {
                        if (supportsPosix()) {
                            Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                            Files.createDirectories(parent, PosixFilePermissions.asFileAttribute(dirPerms));
                        } else {
                            Files.createDirectories(parent);
                        }
                    } else if (supportsPosix()) {
                        Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"));
                    }
```

**Why it is a problem:** The path is taken by substring from the same unvalidated URL as SEC-01, and the result is used to *mutate filesystem permissions* before any connection is opened. The `startsWith` test selects on prefix only; nothing normalises the path or confines it to a data root. `Paths.get` does not collapse `..`, so `jdbc:h2:./../../../../var/lib/app/db` passes the `./` prefix test and yields a `parent` outside any intended directory, which the code then unconditionally rewrites to `0700`. An absolute form needs no traversal at all: `jdbc:h2:/etc/app/x` targets `/etc/app`. The primitive has two distinct harms. Where the process owns or may modify the target, it *strips group and other access from a directory that was deliberately shared* — a deploy directory, a shared mount, a home directory containing `~/.ssh` or a group-readable data volume — breaking availability and, for the `!Files.exists` branch, *creating* an owner-only directory at an attacker-chosen location where the administrator expected something else. Where it does not own the target, the `IOException` is caught and merely logged (L122-124), so the attempt is non-fatal and effectively silent to the operator, who sees a permission-hardening "control" reported in the README as if it had applied. The hardening intent is sound and the code even bothers to detect POSIX support; the defect is that the target of the hardening is chosen by untrusted input, which converts a protective `chmod` into an unvalidated write primitive on the mode bits of arbitrary paths — and it fires twice per start-up, from the constructor (L47) and again from `initializeSchema()` (L85).

**Fix:** Never derive a filesystem target from a URL string. Pass the data directory as its own validated setting, resolve it to a canonical absolute path, and refuse anything that escapes the configured root before touching permissions.

```java
    private static void ensureSecureFilePermissionsIfLocal(String jdbcUrl, Path allowedRoot) {
        String pathPart = extractFilePortion(jdbcUrl);           // no-op for mem: URLs
        if (pathPart == null) {
            return;                                             // in-memory store: nothing to chmod
        }
        Path root = allowedRoot.toAbsolutePath().normalize();
        Path parent = Paths.get(pathPart).toAbsolutePath().normalize().getParent();
        if (parent == null || !parent.startsWith(root)) {
            throw new IllegalArgumentException("Database path escapes the configured data root");
        }
        applyOwnerOnlyPermissions(parent);                       // create/0700 or set/0700 as before
        applyOwnerOnlyFile(parent.resolve(fileBasename(pathPart)));// 0600 for <name>.mv.db
    }
```

with the root supplied by configuration (`resolveDatabaseUrl()` returning only `mem:` or `./`-relative paths per SEC-01's allow-list), and with the `IOException` branch escalated to a fatal start-up error rather than a logged warning, so a failed hardening attempt is never mistaken for a successful one.

---

### SEC-03: Rate limiter consumes a permit on every attempt and refunds only on success, locking out legitimate users

**Severity:** High

**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)

**Location:** `src/main/java/com/example/auth/RateLimiter.java:116-130`, `:147-159`; `src/main/java/com/example/auth/AuthenticationService.java:64-69`

**Vulnerable code:** `RateLimiter.java:116-130`

```java
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
```

**Vulnerable code:** `RateLimiter.java:147-159`

```java
    /**
     * Records a failed authentication attempt across source, (source, account), and global account trackers.
     */
    public void recordAuthenticationFailure(String sourceId, String email) {
        long now = System.currentTimeMillis();
        String safeEmail = InputValidator.canonicalizeEmail(email);

        if (!safeEmail.isEmpty()) {
            AttemptTracker globalTracker = getOrCreateTracker(globalAccountTrackers, safeEmail,
                    GLOBAL_ACCOUNT_WINDOW_MS, Integer.MAX_VALUE, now);
            globalTracker.tryAcquire(now);
        }
    }
```

**Vulnerable code:** `AuthenticationService.java:64-69`

```java
            // 1. Concurrency & Rate Limiting Check (Rules 3 & 7)
            RateLimiter.RateLimitResult rateCheck = rateLimiter.checkAndAcquire(safeSource, safeEmail);
            if (!rateCheck.isAllowed()) {
                SecurityLogger.logRateLimitExceeded(safeEmail, safeSource, rateCheck.status().name());
                return AuthenticationResult.rateLimited();
            }
```

**Why it is a problem:** The two enforcing counters are incremented inside `checkAndAcquire`, i.e. once per *attempt*, before the credential is examined — the state names (`MAX_SOURCE_ATTEMPTS`, `SOURCE_BLOCKED`, "Attempt permitted") are honest about this, while the failure path is not. `recordAuthenticationFailure` is the only place that would express "this attempt was bad", and as shown above it touches *only* `globalAccountTrackers` and ignores its `sourceId` parameter entirely, contradicting its own Javadoc, which promises increments "across source, (source, account), and global account trackers". Consequently the per-source and per-(source,account) budgets are spent by attempts whether they fail or not, and the only code that ever gives them back is `recordAuthenticationSuccess`. The result is a limiter whose effective semantics are "five attempts per source per five minutes, three per account", with forgiveness available only to someone who already knows the correct password. A mistyped first attempt is charged against the user's own budget; three mistypes lock that source out of that account for five minutes.

The lockout becomes a genuine denial of service once the identity is shared, which it is (SEC-04): `Main` defaults `sourceId` to the constant `cli-local`, so every client launched without the environment variable lands in one bucket of 5 attempts per 5 minutes and 3 per account — an attacker needs five cheap calls to refuse service to all of them, and the legitimate users cannot work their way out because success is the only refund. Conversely an attacker who *does* set a distinct `AUTH_SOURCE_ID` per attempt is never limited at all, so the control both denies service to honest users and fails to stop the adversary it names in its reason strings. Two concurrency notes, stated precisely: each `AttemptTracker` method is `synchronized`, so a counter cannot be read torn, and the README's "Atomic Check-and-Act" claim holds *within* a tracker; what is not atomic is the two-stage acquire (a request can consume a source permit and then be rejected by the account stage, leaving the first permit spent with no failure recorded), and `getCount` followed by the caller's sleep (SEC-07) is a read-then-act pair with no lock spanning it, so concurrent requests all observe the same count and all sleep.

**Fix:** Make the counters mean failures, keep the atomic acquire (it is the right primitive), and refund the permit on every outcome that is not a credential failure. Give the failure recorder the same keys it documents.

```java
    // AttemptTracker: return a permit that was consumed by a non-failure outcome.
        synchronized void refund() {
            if (count > 0) {
                count--;
            }
        }

    // RateLimiter: refunds the source and (source,account) permits.
    public void refundAttempt(String sourceId, String email) {
        long now = System.currentTimeMillis();
        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        AttemptTracker source = sourceTrackers.get(safeSource);
        if (source != null) {
            source.refund();
        }
        if (!safeEmail.isEmpty()) {
            AttemptTracker pair = sourceAccountTrackers.get(safeSource + ":" + safeEmail);
            if (pair != null) {
                pair.refund();
            }
        }
    }

    // RateLimiter: failures now charge the enforcing buckets, as documented.
    public void recordAuthenticationFailure(String sourceId, String email) {
        long now = System.currentTimeMillis();
        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        getOrCreateTracker(sourceTrackers, safeSource, SOURCE_WINDOW_MS, MAX_SOURCE_ATTEMPTS, now)
                .tryAcquire(now);
        if (!safeEmail.isEmpty()) {
            getOrCreateTracker(sourceAccountTrackers, safeSource + ":" + safeEmail,
                    SOURCE_ACCOUNT_WINDOW_MS, MAX_SOURCE_ACCOUNT_ATTEMPTS, now).tryAcquire(now);
            getOrCreateTracker(globalAccountTrackers, safeEmail,
                    GLOBAL_ACCOUNT_WINDOW_MS, Integer.MAX_VALUE, now).tryAcquire(now);
        }
    }
```

and in `authenticate`, refund rather than silently leak the permit for the outcomes that are not a wrong credential — malformed input, database error, and the rate-limited return itself, which currently spends a source permit in order to say "too many attempts":

```java
            if (!emailValid || !passwordValid) {
                passwordHasher.verifyDummyPassword(passwordChars);
                rateLimiter.refundAttempt(safeSource, safeEmail);   // malformed input is not a credential failure
                SecurityLogger.logAuthFailure(safeEmail, safeSource, "MALFORMED_INPUT");
                return AuthenticationResult.invalidCredentials();
            }
```

---

### SEC-04: Rate-limit identity is a caller-supplied environment variable; invalid values collapse unrelated users into shared buckets

**Severity:** High

**CWE:** CWE-290 (Authentication Bypass by Spoofing), CWE-770 (Allocation of Resources Without Limits or Throttling)

**Location:** `src/main/java/com/example/auth/Main.java:76-79`; `src/main/java/com/example/auth/InputValidator.java:118-131`

**Vulnerable code:** `Main.java:76-79`

```java
            String sourceId = System.getenv("AUTH_SOURCE_ID");
            if (sourceId == null || sourceId.isBlank()) {
                sourceId = "cli-local";
            }
```

**Vulnerable code:** `InputValidator.java:118-131`

```java
    public static String sanitizeSourceId(String sourceId) {
        if (sourceId == null || sourceId.isBlank()) {
            return "unknown-source";
        }
        String trimmed = sourceId.trim();
        if (trimmed.length() > MAX_SOURCE_ID_LENGTH) {
            trimmed = trimmed.substring(0, MAX_SOURCE_ID_LENGTH);
        }
        if (SOURCE_ID_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        // Fall back to a safe placeholder if invalid characters are present
        return "invalid-source-format";
    }
```

**Why it is a problem:** Every abuse control in this component is keyed on `sourceId`, and `sourceId` is a string the caller invents in its own environment. It is not attested by anything — no peer address, no certificate, no signed token — so it carries none of the assumptions a rate limit needs in order to bound an adversary. The attacker chooses their identity per attempt (`AUTH_SOURCE_ID=try-000001`, `try-000002`, …), which defeats both enforcing buckets outright and, because each fresh identity allocates three new tracker entries, simultaneously drives the memory growth in SEC-08. There is no ceiling on the number of distinct source keys, so the "per source" qualifier has no referent.

The default and the two fallbacks push the same design the other way, into a shared-fate hazard. With the variable unset — the ordinary way to run this CLI — all clients share `cli-local`, so the 5-per-5-minutes budget in SEC-03 becomes an organisation-wide budget and five attacker calls lock out everyone. `sanitizeSourceId` then collapses every blank value onto the single key `unknown-source` and every syntactically invalid value onto the single key `invalid-source-format`, so an attacker can deliberately land in either shared bucket by sending a value with one disallowed character, and can merge their traffic with that of misconfigured clients in the same key. Truncation at 64 characters merges identifiers that agree on their first 64 characters, which is the opposite of what a distinct-key guarantee requires. Finally, collapsing distinct clients into two fixed keys destroys the very signal `detecting-anomalous-authentication-patterns` style detection needs: the audit trail records `Source=invalid-source-format` for a crowd of unrelated clients, so per-principal baselines cannot be built at all.

**Fix:** Do not let the caller name itself. Bind the identity to something the transport already attests, and make "unknown" mean *this connection*, never a shared sentinel.

```java
    // Main: identity comes from the platform, not from the environment.
    // In a servlet container: req.getRemoteAddr(), or the verified mTLS subject.
    // In a CLI there is no trustworthy source, so use one per process invocation.
    private static String resolveSourceId() {
        String fromEnv = System.getenv("AUTH_SOURCE_ID");
        if (fromEnv != null && !fromEnv.isBlank()) {
            String cleaned = InputValidator.sanitizeSourceId(fromEnv);
            if (!InputValidator.isUsableSourceId(cleaned)) {
                throw new IllegalArgumentException("AUTH_SOURCE_ID is not a valid client identifier");
            }
            return cleaned;
        }
        return "cli-" + UUID.randomUUID();   // distinct, never shared, never a fixed key
    }
```

```java
    // InputValidator: reject instead of collapsing, so callers cannot opt into a shared bucket.
    public static boolean isUsableSourceId(String candidate) {
        return candidate != null
                && candidate.length() >= 1
                && candidate.length() <= MAX_SOURCE_ID_LENGTH
                && SOURCE_ID_PATTERN.matcher(candidate).matches();
    }
```

Keep `checkAndAcquire`'s internal call to `sanitizeSourceId` as a defensive re-check, but have it fail closed by returning a `Status` that refuses service for a malformed identity rather than a bucket everyone shares.

---

### SEC-05: Raw bearer token printed to stdout in the `Cookie:` line

**Severity:** High

**CWE:** CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Location:** `src/main/java/com/example/auth/Main.java:85-88`; `src/main/java/com/example/auth/SessionManager.java:80-83`

**Vulnerable code:** `Main.java:85-88`

```java
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    System.out.println("Cookie: " + session.cookieHeader());
                });
```

**Vulnerable code:** `SessionManager.java:80-83`

```java
        String cookieHeader = String.format(
                "__Host-AuthSession=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=%d",
                token, sessionDurationSeconds
        );
```

**Why it is a problem:** The adjacent line shows the author knew this value is a secret — it goes through `SecurityLogger.maskToken` — and the very next line prints the unmasked original. `cookieHeader` is built by embedding the full 43-character URL-safe Base64 token in a string that `Main` then writes to `System.out` verbatim, so the masking on the line above discloses nothing that the line below has not already given away. A CLI's stdout is the least private channel in most environments: it lands in interactive terminal scrollback and shell history wrappers, in `tee`/`script`/`script -f` recordings, in CI job logs and their retained artifacts, in systemd unit journals, in support screenshots and pasted "here's what it printed" snippets, and in any wrapper script that captures output for parsing. Whoever holds that string holds a complete bearer credential for `DEFAULT_SESSION_DURATION_SECONDS` (3600s) with no second factor, no binding, and no revocation path that production code ever invokes (SEC-16). This directly contradicts the component's own Rule 2, which the `SecurityLogger` class header states as "Passwords and secrets are never printed or logged", and it is the highest-impact of the exposure findings because the printed artifact is the credential itself rather than a hint about it.

**Fix:** Print the masked correlation form by default, and require an explicit opt-in to emit the raw value — the same discipline as a cloud CLI printing an access key once.

```java
                result.getSession().ifPresent(session -> {
                    System.out.println("Session: " + SecurityLogger.maskToken(session.sessionId()));
                    if (showRawToken) {                       // --show-token, default false
                        System.err.println("WARNING: writing a live bearer token to stdout.");
                        System.out.println("Cookie: " + session.cookieHeader());
                    } else {
                        System.out.println("Cookie: __Host-AuthSession=<redacted>; Path=/; Secure; HttpOnly; SameSite=Strict");
                    }
                });
```

If the raw cookie must be machine-readable for a scripted caller, write it to a descriptor or file the caller controls (`--cookie-file`, created `0600`) instead of the channel a human and every log shipper read.

---

### SEC-06: Public getters expose the limiter, session factory and hasher; `resetAll()` disarms throttling, `createSession()` mints sessions with no credential check

**Severity:** High

**CWE:** CWE-749 (Exposed Dangerous Method or Function), CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key)

**Location:** `src/main/java/com/example/auth/AuthenticationService.java:189-199`; `src/main/java/com/example/auth/RateLimiter.java:216-224`; `src/main/java/com/example/auth/SessionManager.java:64-68`

**Vulnerable code:** `AuthenticationService.java:189-199`

```java
    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public PasswordHasher getPasswordHasher() {
        return passwordHasher;
    }
```

**Vulnerable code:** `RateLimiter.java:216-224`

```java
    /**
     * Clears all trackers (useful for test isolation).
     */
    public void resetAll() {
        sourceTrackers.clear();
        sourceAccountTrackers.clear();
        globalAccountTrackers.clear();
        entryCount.set(0);
    }
```

**Vulnerable code:** `SessionManager.java:64-68`

```java
    public Session createSession(long userId, String email) {
        evictIfNecessary();

        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(randomBytes);
```

**Why it is a problem:** `AuthenticationService` is the class that holds the security machinery, and it hands all three of its collaborators to any code that can reach it, including two methods that are pure authentication and abuse-control bypasses once exposed. `getRateLimiter().resetAll()` erases every tracker in the process, so a caller can clear an in-progress lockout at will — including its own — which makes the entire limiter advisory for anyone with a reference. `getSessionManager().createSession(userId, email)` takes a numeric user id and an email address and returns a live, registered bearer session; it performs no credential check, no authorization check and no caller check, because inside `authenticate` the caller has already done that work — but the getter moves it out of that context, where nothing has. Given a user id, that is a complete authentication bypass (CWE-639: the authorisation decision is now driven by a caller-supplied key). `getPasswordHasher()` additionally lets a holder construct a `PasswordHasher` at the 100,000-iteration floor or re-tune policy, undermining the work factor `authenticate` relies on.

What makes this reportable rather than merely untidy is that none of the three getters is used: grepping `src/` finds no call site for `getRateLimiter`, `getSessionManager` or `getPasswordHasher`, and none for `resetAll` anywhere, including the test sources. The Javadoc on `resetAll` even says "useful for test isolation", but the tests do not call it. This is therefore attack surface with no function — the exposure exists purely because the fields were made reachable for convenience. In the deployment this component actually invites (a library inside a web application), the reference-holding set is large: dependency-injection containers, health endpoints, admin modules, plugins and test-support beans can all see `AuthenticationService`, and each of them then holds a bypass path around Rules 3, 4 and 7.

**Fix:** Delete the getters — nothing calls them — and make the collaborators constructor-injected so they remain testable seams without being exposed from the security-critical object.

```java
    public final class AuthenticationService {

        private final DatabaseManager databaseManager;
        private final UserRepository userRepository;
        private final PasswordHasher passwordHasher;
        private final RateLimiter rateLimiter;
        private final SessionManager sessionManager;

        // Tests inject their own instances; production code never receives them back out.
        public AuthenticationService(DatabaseManager databaseManager,
                                     UserRepository userRepository,
                                     PasswordHasher passwordHasher,
                                     RateLimiter rateLimiter,
                                     SessionManager sessionManager) {
            this.databaseManager = Objects.requireNonNull(databaseManager);
            this.userRepository = Objects.requireNonNull(userRepository);
            this.passwordHasher = Objects.requireNonNull(passwordHasher);
            this.rateLimiter = Objects.requireNonNull(rateLimiter);
            this.sessionManager = Objects.requireNonNull(sessionManager);
        }

        // getRateLimiter(), getSessionManager(), getPasswordHasher(): removed.
    }
```

and confine the destructive factory so possession of a `SessionManager` is not equivalent to holding a session:

```java
    // Package-private: only the authenticated flow inside com.example.auth can mint a session.
    Session createSession(long userId, String email) { ... }

    // RateLimiter: no bulk disarm. Tests reset a single principal, not the process.
    void resetForPrincipal(String sourceId, String email) {
        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        sourceAccountTrackers.remove(safeSource + ":" + safeEmail);
        if (!safeEmail.isEmpty()) {
            globalAccountTrackers.remove(safeEmail);
        }
    }
```

---

### SEC-07: Global email-keyed progressive `Thread.sleep` lets an attacker throttle the legitimate owner of a mailbox

**Severity:** Medium

**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-400 (Uncontrolled Resource Consumption)

**Location:** `src/main/java/com/example/auth/RateLimiter.java:132-142`, `:150-159`; `src/main/java/com/example/auth/AuthenticationService.java:71-80`

**Vulnerable code:** `RateLimiter.java:132-142`

```java
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
```

**Vulnerable code:** `AuthenticationService.java:71-80`

```java
            // Apply progressive delay if account is under distributed brute force pressure
            if (rateCheck.progressiveDelayMs() > 0) {
                try {
                    Thread.sleep(rateCheck.progressiveDelayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    SecurityLogger.logSystemError("Authentication thread interrupted during throttle delay", e);
                    return AuthenticationResult.internalError();
                }
            }
```

**Why it is a problem:** This is the component's only control that spans sources, and it is aimed at the wrong party. The delay is keyed solely on the target's email address, with no reference to who produced the recorded failures, and it is applied to *whatever request arrives next for that address*. The attacker therefore does not pay the cost — they set the alarm and walk away, and the 3-second ceiling is charged to the legitimate owner's next login. Reaching the threshold costs five recorded failures (`GLOBAL_ACCOUNT_THROTTLE_THRESHOLD = 5`), after which every genuine login to that mailbox sleeps 3 seconds inside the authentication call for the remainder of the 10-minute window, renewable indefinitely with five more calls per window. The README's adversarial matrix lists exactly this scenario — "Attacker locks out legitimate admin by repeatedly failing logins for admin email" — and marks it defeated on the grounds that source-scoped blocking leaves the real user free; but source scoping is precisely what an adversary escapes with per-attempt identities (SEC-04), leaving this global delay as the only remaining control, and it fires on the victim rather than the attacker.

It also fails in the other direction: it never refuses anything. `Status` has exactly three constants (`ALLOWED`, `SOURCE_BLOCKED`, `SOURCE_ACCOUNT_BLOCKED`), so a `RateLimitResult` carrying a delay is `ALLOWED` — the global tracker is created with `Integer.MAX_VALUE` attempts and can only ever produce a sleep. An attacker behind a few thousand identities is slowed by at most 3 seconds per attempt while the target's users are slowed on every attempt, so the ratio favours the attacker. Finally, `Thread.sleep` inside the authentication path is itself the resource problem: the request thread is held, along with its connection, its request context and its position in the container's worker pool, so N concurrent targeted logins convert a 3-second "polite" delay into sustained thread exhaustion (CWE-400), and because the sleep is bounded while the failure count is not, the control cannot escalate past 3 seconds no matter how large the abuse becomes.

**Fix:** Charge the cost to the source that produced the failures, escalate to refusal rather than a capped sleep, and never block a worker thread for policy reasons.

```java
    // RateLimiter: the global tracker becomes an enforcing check, not an advisory pause.
    public enum Status {
        ALLOWED,
        SOURCE_BLOCKED,
        SOURCE_ACCOUNT_BLOCKED,
        ACCOUNT_THROTTLED          // new: refusal, not a pause
    }

        if (!safeEmail.isEmpty()) {
            AttemptTracker globalAccountTracker = getOrCreateTracker(globalAccountTrackers, safeEmail,
                    GLOBAL_ACCOUNT_WINDOW_MS, MAX_GLOBAL_ACCOUNT_ATTEMPTS, now);
            if (!globalAccountTracker.tryAcquire(now)) {
                return new RateLimitResult(Status.ACCOUNT_THROTTLED, 0,
                        "Account temporarily throttled; retry after backoff");
            }
        }
```

```java
            // AuthenticationService: no sleeping in the request path; tell the client to back off.
            if (!rateCheck.isAllowed()) {
                SecurityLogger.logRateLimitExceeded(safeEmail, safeSource, rateCheck.status().name());
                return AuthenticationResult.rateLimited();   // maps to HTTP 429 + Retry-After at the edge
            }
```

Distribute the throttle by attested source and require an identity that is expensive to mint before allowing repeated failures for one mailbox (proof of work, captcha step-up), so the marginal cost of the 50th failure falls on the attacker instead of on the account owner.

---

### SEC-08: Cache bound is not enforced: purge removes only already-expired entries, and there is no LRU despite the documentation

**Severity:** Medium

**CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits or Throttling)

**Location:** `src/main/java/com/example/auth/RateLimiter.java:186-192`, `:194-214`

**Vulnerable code:** `RateLimiter.java:186-192`

```java
    private AttemptTracker getOrCreateTracker(ConcurrentHashMap<String, AttemptTracker> map,
                                              String key, long windowMs, int maxAttempts, long now) {
        return map.computeIfAbsent(key, k -> {
            entryCount.incrementAndGet();
            return new AttemptTracker(windowMs, maxAttempts, now);
        });
    }
```

**Vulnerable code:** `RateLimiter.java:194-214`

```java
    /**
     * Enforces bounded memory (Rule 5). Purges expired trackers when capacity limit is reached.
     */
    private void evictIfNecessary(long now) {
        if (entryCount.get() > MAX_CACHE_ENTRIES) {
            purgeExpired(sourceTrackers, now);
            purgeExpired(sourceAccountTrackers, now);
            purgeExpired(globalAccountTrackers, now);
            entryCount.set(sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size());
        }
    }

    private void purgeExpired(ConcurrentHashMap<String, AttemptTracker> map, long now) {
        Iterator<Map.Entry<String, AttemptTracker>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, AttemptTracker> entry = it.next();
            if (entry.getValue().isExpired(now)) {
                it.remove();
            }
        }
    }
```

**Why it is a problem:** The Javadoc calls this "Enforces bounded memory (Rule 5)" and the README describes "automated LRU and expiration eviction", but neither half of that sentence is implemented. There is no LRU anywhere — no access-order tracking, no recency field, nothing that could rank entries for eviction. What exists is a threshold test (`entryCount.get() > MAX_CACHE_ENTRIES`) that triggers a sweep removing *only trackers whose window has already fully elapsed*. Those are exactly the entries an adversary does not generate: by minting a fresh identity per attempt (SEC-04), every key the attacker creates is young, so the sweep frees nothing while insertion continues. Because the tracker window is 5 or 10 minutes, the live working set is roughly the attempt rate multiplied by the window, with no ceiling the code can apply to it — an attacker issuing, say, 2,000 uniquely-identified attempts per second holds tens of thousands of live trackers per window, each a map entry plus an object plus two strings, and the 10,000 threshold becomes a trigger for a full three-map iteration that reclaims nothing rather than a bound on memory. The threshold is also evaluated once per `checkAndAcquire`, so a burst between two calls allocates freely, and `entryCount` is only recomputed after a purge — it never decreases as a result of ordinary operation, meaning once the sweep stops freeing space, every subsequent call pays three full map iterations and still grows. The identical shape appears in `SessionManager.evictIfNecessary()` (`SessionManager.java:115-125`), where sessions past `MAX_ACTIVE_SESSIONS` are kept unless already expired, so 10,000 live sessions is a floor, not a cap. The practical consequence of unbounded tracker growth is heap exhaustion and full-GC stalls in a service whose stated job is to survive abuse; a limiter that can be switched off by filling memory is not a limiter.

**Fix:** Bound the structure by capacity with LRU eviction, and make the counter decrement when entries are actually removed. A cache library is the correct dependency here; if one is not available, an access-ordered map under a lock is honest about its cost.

```java
    private static final int MAX_TRACKERS_PER_MAP = 10_000;

    // Bounded, access-ordered, and single-lock — correct beats fast for a limiter.
    private static final class LruTrackers {
        private final LinkedHashMap<String, AttemptTracker> map =
                new LinkedHashMap<>(256, 0.75f, true);

        synchronized AttemptTracker getOrCreate(String key, long windowMs, int maxAttempts, long now) {
            AttemptTracker tracker = map.get(key);
            if (tracker == null) {
                tracker = new AttemptTracker(windowMs, maxAttempts, now);
                map.put(key, tracker);
                if (map.size() > MAX_TRACKERS_PER_MAP) {
                    map.remove(map.keySet().iterator().next());   // evict least recently used
                }
            }
            return tracker;
        }

        synchronized void purgeExpired(long now) {
            map.entrySet().removeIf(e -> e.getValue().isExpired(now));
        }

        synchronized void remove(String key) {
            map.remove(key);
        }
    }
```

Then replace `evictIfNecessary`'s threshold sweep with a scheduled or on-insert purge, drop `entryCount` (the map's own size is the bound and cannot drift), and give `SessionManager` the same treatment — cap by count with least-recently-validated eviction rather than expiry-only removal.

---

### SEC-09: Delimiter collision in the `source:email` composite rate-limit key

**Severity:** Medium

**CWE:** CWE-20 (Improper Input Validation), CWE-74 (Improper Neutralization of Special Elements in Output Used by a Downstream Component)

**Location:** `src/main/java/com/example/auth/RateLimiter.java:114`, `:168`; `src/main/java/com/example/auth/InputValidator.java:31-34`

**Vulnerable code:** `InputValidator.java:31-34`

```java
    // Source identifier pattern: alphanumeric, IPv4, IPv6, colons, dots, dashes, underscores.
    private static final Pattern SOURCE_ID_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9.:_\\-]{1,64}$"
    );
```

**Vulnerable code:** `RateLimiter.java:112-114`

```java
        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        String sourceAccountKey = safeSource + ":" + safeEmail;
```

**Why it is a problem:** The composite key is built by string concatenation around `:`, and `SOURCE_ID_PATTERN` explicitly admits `:` — the comment says colons are allowed for IPv6 — so a source identifier can contain the join character. The join is also applied to `safeEmail`, which is produced by `canonicalizeEmail`: that method trims and lowercases but performs no validation at all, and it runs *before* `isValidEmail`, which `authenticate` does not reach until later (`AuthenticationService.java:83`). The mapping from `(source, email)` to key is therefore not injective: `source="1:2"`, `email="a@b.com"` and `source="1"`, `email="2:a@b.com"` both yield `1:2:a@b.com` and land in the same `(source, account)` bucket. The consequence is quota interference in both directions — an attacker can spend another principal's per-account budget by choosing an email string that collides with their key (the malformed email is rejected for authentication purposes but has already consumed the shared tracker), and can hide their own failure count inside a victim's bucket, so the victim is throttled for traffic they never generated. The same concatenation is repeated independently in `recordAuthenticationSuccess` (`RateLimiter.java:168`), which means the key format is an implicit contract duplicated across methods rather than a type; any future change to one site silently stops resets matching increments. README Rule 1 claims `sourceId` is validated "to prevent header injection or delimiter collision in rate limit keys", so the very property that is missing is the one the documentation asserts, and the pattern that permits `:` is the mechanism by which it fails.

**Fix:** Do not encode two fields into one string. Use a structured key, forbid the delimiter in the source component, and validate the email before it is ever used as an identity.

```java
    // RateLimiter: a real product type — collision-free by construction.
    private record SourceAccountKey(String source, String email) { }

    private final ConcurrentHashMap<SourceAccountKey, AttemptTracker> sourceAccountTrackers =
            new ConcurrentHashMap<>();

        SourceAccountKey sourceAccountKey = new SourceAccountKey(safeSource, safeEmail);
```

and close the input side so a source id can never contain the delimiter, encoding IPv6 in brackets instead of relying on bare colons:

```java
    // InputValidator: colon is not a legal source character.
    private static final Pattern SOURCE_ID_PATTERN = Pattern.compile(
            "^(?:[a-zA-Z0-9._\\-]{1,64}|\\[[0-9a-fA-F:]{1,45}\\])$"
    );

    // canonicalizeEmail must not be usable as an identity producer:
    public static String canonicalizeEmail(String email) {
        if (email == null || !isValidEmail(email)) {
            return "";                       // empty already means "no account key" throughout
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }
```

Keep the bracketed form's translation to a canonical address in one place, and derive both the increment and the reset paths from the same record so the two can never drift apart again.

---

### SEC-10: Timing and message oracles still distinguish an existing account

**Severity:** Medium

**CWE:** CWE-208 (Observable Timing Discrepancy), CWE-211 (Internally-Sensitive Information Externally Observable by Timing or Message Discrepancy)

**Location:** `src/main/java/com/example/auth/PasswordHasher.java:127`, `:157`; `src/main/java/com/example/auth/AuthenticationService.java:94-101`; `src/main/java/com/example/auth/AuthenticationResult.java:22-24`

**Vulnerable code:** `PasswordHasher.java:127-128`

```java
            derivedKeyBytes = deriveKey(candidatePassword, saltBytes, storedIterations, KEY_BIT_LENGTH);
            return MessageDigest.isEqual(derivedKeyBytes, expectedHashBytes);
```

**Vulnerable code:** `PasswordHasher.java:157-160`

```java
            derived = deriveKey(passwordToUse, DUMMY_SALT, DEFAULT_ITERATIONS, KEY_BIT_LENGTH);
            // Constant-time comparison against dummy hash to match branch execution flow
            MessageDigest.isEqual(derived, DUMMY_HASH);
            return false;
```

**Vulnerable code:** `AuthenticationService.java:94-101`

```java
            // 3. Database State Verification (Rules 1 & 3)
            Optional<UserRecord> userOpt;
            try (Connection conn = databaseManager.getConnection()) {
                userOpt = userRepository.findByEmail(conn, safeEmail);
            } catch (SQLException e) {
                SecurityLogger.logSystemError("Database query failed during authentication", e);
                return AuthenticationResult.internalError();
            }
```

**Vulnerable code:** `AuthenticationResult.java:22-24`

```java
    public static final String MSG_INVALID_CREDENTIALS = "Authentication failed. Invalid email or password.";
    public static final String MSG_RATE_LIMITED = "Authentication failed. Too many attempts, please try again later.";
    public static final String MSG_INTERNAL_ERROR = "Authentication failed. An internal error occurred.";
```

**Why it is a problem:** The timing-equalisation design is real and, for the branches it covers, effective: unknown account, inactive account, malformed input and malformed stored hash all run `verifyDummyPassword` so a rejection costs roughly one key derivation. Two gaps remain, and both are account-enumeration channels.

The first is cost asymmetry. The dummy path is pinned to the hard-coded `DEFAULT_ITERATIONS` (210,000, at `PasswordHasher.java:157`), while the real path derives with `storedIterations` taken from the database row (`PasswordHasher.java:127`) — legitimately, since rows may predate a policy change. But the accepted window is 100,000 to 10,000,000, so the two paths are *not* the same length: a row at the floor costs about 48 % of a dummy derivation, and a row at the ceiling roughly 48 times as much. An unauthenticated caller who measures login latency can therefore separate "no such account" from "account exists, and here is how many iterations it uses", and the difference is large relative to measurement noise: taking the median of a few dozen requests per address, with the same password, same connection and alternating address, distinguishes 100,000 from 210,000 comfortably, and a single row configured high above 210,000 is detectable in one sample. This is what makes the README's claim that user enumeration is "completely defeated" overstated — the equaliser neutralises the *presence* oracle for rows at the default cost and for the fail-closed branches, not for arbitrary stored costs.

The second gap is the database-error branch, which needs no measurement at all. On `SQLException`, `authenticate` does no dummy work, records no failure, and returns `AuthenticationResult.internalError()`, whose user-facing string — "Authentication failed. An internal error occurred." — is a different string from the credentials-failure message, so the response is distinguishable by content, and its timing is a fast path with no derivation behind it. Any condition that makes queries fail intermittently (lock contention, a full connection pool, an H2 page-store error) leaks "this address was looked up, and the lookup itself broke" rather than the uniform answer the four-message design was built to give. A rate-limited response is also a distinct string; that one is defensible for usability, but it means the response vocabulary alone already conveys three different states about an address.

**Fix:** Make the dummy path match the cost of the row it is imitating, and give the error branch the same shape as every other rejection.

```java
    // PasswordHasher: equalise against the row's own work factor when the row is known.
    public boolean verifyDummyPassword(char[] candidatePassword, int mimicIterations) {
        char[] passwordToUse = (candidatePassword != null
                && InputValidator.isValidPasswordForAuth(candidatePassword))
                ? candidatePassword
                : DUMMY_INPUT_PASSWORD;
        byte[] derived = null;
        try {
            int iterations = Math.min(Math.max(mimicIterations, InputValidator.MIN_PBKDF2_ITERATIONS),
                                      InputValidator.MAX_PBKDF2_ITERATIONS);
            derived = deriveKey(passwordToUse, DUMMY_SALT, iterations, KEY_BIT_LENGTH);
            MessageDigest.isEqual(derived, expectedDummyFor(iterations));
            return false;
        } finally {
            if (derived != null) {
                Arrays.fill(derived, (byte) 0);
            }
        }
    }
```

```java
            // AuthenticationService: the SQL-error branch pays the same cost and says the same thing.
            } catch (SQLException e) {
                SecurityLogger.logSystemError("Database query failed during authentication", e);
                passwordHasher.verifyDummyPassword(passwordChars, PasswordHasher.DEFAULT_ITERATIONS);
                return AuthenticationResult.invalidCredentials();   // uniform string; cause is in the log, not the client
            }
```

where the not-found branch passes `PasswordHasher.DEFAULT_ITERATIONS` and the corrupted/inactive branches pass the row's own `iterations`. If operational monitoring must keep the error signal, expose it only through the server-side log and a metric, never through the response string or the response time.

---

### SEC-11: Database-supplied iteration count up to 10,000,000 turns one login into minutes of CPU

**Severity:** Medium

**CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits or Throttling)

**Location:** `src/main/java/com/example/auth/InputValidator.java:36-38`, `:148-150`; `src/main/java/com/example/auth/PasswordHasher.java:117-127`

**Vulnerable code:** `InputValidator.java:36-38`

```java
    // Safe iteration limits for PBKDF2.
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;
```

**Vulnerable code:** `InputValidator.java:148-150`

```java
        if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
            return false;
        }
```

**Vulnerable code:** `PasswordHasher.java:127-128`

```java
            derivedKeyBytes = deriveKey(candidatePassword, saltBytes, storedIterations, KEY_BIT_LENGTH);
            return MessageDigest.isEqual(derivedKeyBytes, expectedHashBytes);
```

**Why it is a problem:** The revalidation of database-supplied hash parameters is a genuinely good control — it rejects unknown algorithms, short salts and wrong-length digests, and it fails closed — but on the one field that determines CPU cost per request, the ceiling it enforces is 10,000,000 iterations, 48 times the component's own default. `verifyPassword` then honours whatever the row says, so the work factor of every login is chosen by whoever wrote that row, and the request thread pays it synchronously. Anyone able to plant or alter a row can convert a single unauthenticated login attempt into seconds-to-minutes of single-core CPU, repeated at will; that is a favourable exchange rate for a denial-of-service attacker, and it is not bounded by the limiter's own interaction (five attempts per source is still five minutes of CPU per source, and identities are free per SEC-04). The write paths are not hypothetical: the store's default credentials are `sa` with an empty password (SEC-12), an attacker-influenced `AUTH_DB_URL` can point the application at a database the attacker serves — and thereby feeds it rows (SEC-01) — and registration is open and unthrottled (SEC-15). Even with all of that closed, the ceiling is a latent self-inflicted outage: a future "security improvement" that raises the configured iteration count toward the documented maximum silently multiplies authentication CPU by the same factor, and this component has no queue, budget or admission control that would notice. `PasswordHasher`'s constructor does range-check its own default against the same constants, which shows the author treated the window as the safety boundary — the window is simply set 48x above the intended cost, with no relationship to any latency or CPU budget.

**Fix:** Separate "what a stored row may claim" from "what this service is willing to spend", cap the latter, and repair over-costed rows on the next successful login rather than paying them indefinitely.

```java
    // InputValidator: what the service will actually pay for one verification.
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;   // allowed in stored data (migration headroom)
    public static final int MAX_ACCEPTED_ITERATIONS   =  600_000; // CPU budget for a single login

    public static boolean isVerifiableWithinBudget(int iterations) {
        return iterations >= MIN_PBKDF2_ITERATIONS && iterations <= MAX_ACCEPTED_ITERATIONS;
    }
```

```java
    // PasswordHasher.verifyPassword: refuse the cost, do not absorb it, and signal rehash.
            if (!InputValidator.isVerifiableWithinBudget(storedIterations)) {
                SecurityLogger.logSystemError(
                        "Stored hash exceeds verification cost budget; rehash required", null);
                return verifyDummyPassword(candidatePassword);   // uniform latency, no CPU spike
            }
            derivedKeyBytes = deriveKey(candidatePassword, saltBytes, storedIterations, KEY_BIT_LENGTH);
            boolean matches = MessageDigest.isEqual(derivedKeyBytes, expectedHashBytes);
            if (matches && storedIterations > PasswordHasher.DEFAULT_ITERATIONS) {
                // caller re-derives at DEFAULT_ITERATIONS and updates the row (see SEC-10's fix for the dummy path)
                throw new RehashRequiredException(storedIterations);
            }
            return matches;
```

Additionally cap concurrent derivations with a small `Semaphore` sized to the core count so that even in-budget attempts cannot be multiplied into saturation, and bound wall-clock time per verification.

---

### SEC-12: Default DB credentials (`sa`/empty), unencrypted file store, and first-actor-wins auto-registration

**Severity:** Medium

**CWE:** CWE-1392 (Use of Default Credentials), CWE-306 (Missing Authentication for Critical Function), CWE-312 (Cleartext Storage of Sensitive Information)

**Location:** `src/main/java/com/example/auth/DatabaseManager.java:27-29`, `:140-148`; `src/main/java/com/example/auth/Main.java:51-57`

**Vulnerable code:** `DatabaseManager.java:27-29`

```java
    public static final String DEFAULT_IN_MEMORY_URL = "jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1";
    public static final String DEFAULT_FILE_DIR = "./data";
    public static final String DEFAULT_FILE_URL = "jdbc:h2:./data/authdb";
```

**Vulnerable code:** `DatabaseManager.java:140-148`

```java
    private static String resolveUser() {
        String envUser = System.getenv("AUTH_DB_USER");
        return (envUser != null) ? envUser.trim() : "sa";
    }

    private static String resolvePassword() {
        String envPass = System.getenv("AUTH_DB_PASSWORD");
        return (envPass != null) ? envPass : "";
    }
```

**Vulnerable code:** `Main.java:51-57`

```java
                try (Connection conn = dbManager.getConnection()) {
                    UserRepository userRepo = new UserRepository();
                    if (userRepo.countUsers(conn) == 0) {
                        System.out.println("[INFO] No user accounts found in database.");
                        System.out.println("[INFO] Please create an account first.");
                        return handleRegistration(authService, console);
                    }
```

**Why it is a problem:** Three defaults combine into one exposure. `resolveUser`/`resolvePassword` substitute the well-known H2 pair `sa` / empty password whenever `AUTH_DB_USER` / `AUTH_DB_PASSWORD` are unset, so the store is opened with the first credentials any attacker would try; there is no startup check that refuses to run with them, and no way to distinguish "the operator intentionally chose an empty password" from "the operator forgot to configure one". The README states credentials are "never hardcoded", but these are hardcoded fallbacks, and the code path that uses them is the default path. Second, whatever store the operator selects is used unencrypted: `DatabaseManager` offers `jdbc:h2:./data/authdb` as its file option and applies no `CIPHER=` parameter anywhere, so on the file-backed configuration the password hash, the 16-byte salt and the iteration count of every account sit in cleartext in `./data/authdb.mv.db`. That combination is the exploitable one — PBKDF2-HMAC-SHA256 at 210,000 iterations is a sound choice *in isolation* (see SEC-10's and SEC-11's notes on the parameters themselves), but an offline copy of the file removes the rate limiter from the picture entirely, and the row also carries an `iterations` field the attacker is now free to exploit in the other direction: they can copy the row and drop `iterations` to the 100,000 floor before cracking it, since SEC-11 shows the application will honour any value in the accepted window. Third, the file's mode is tightened to `0600` only on the path where the operator configured a URL (`applySecurePermissions` is reached for configured URLs; SEC-02 covers what else that method touches), so the fallback location is not the one the permission logic was written for, and in a container image or a shared CI runner the directory may already be world-readable before the first write.

The empty-database bootstrap then hands the account to whoever arrives first. `Main` opens the database, calls `countUsers`, and if the count is zero immediately drops into interactive registration with no authentication, no confirmation prompt and no operator token — the same shape as the cloud instance metadata "first caller wins" problem. Any principal that can start the application, or reach a database the application will open (SEC-01 makes the target database itself selectable by whoever controls the environment), becomes the sole and first account before any legitimate user exists; because `email` is `UNIQUE` and registration is the only way to create an account (there is no admin function), that actor now permanently owns the mailbox the login flow will later direct its throttle and lockout consequences to (SEC-07).

**Fix:** Fail closed on missing credentials, encrypt the file store by default, and gate the bootstrap on an explicit operator action.

```java
    private static String resolveUser() {
        String envUser = System.getenv("AUTH_DB_USER");
        if (envUser == null || envUser.isBlank()) {
            throw new IllegalStateException("AUTH_DB_USER must be set; refusing to use default 'sa'");
        }
        return envUser.trim();
    }

    private static String resolvePassword() {
        String envPass = System.getenv("AUTH_DB_PASSWORD");
        if (envPass == null || envPass.isEmpty()) {
            throw new IllegalStateException("AUTH_DB_PASSWORD must be set; refusing to connect without a password");
        }
        return envPass;
    }

    // Default file store must be encrypted at rest.
    public static final String DEFAULT_FILE_URL =
            "jdbc:h2:./data/authdb;CIPHER=AES;PAGE_SIZE=4096";
    // ... and getConnection() must pass the cipher password as the second argument
    //     for an encrypted database, not merely the role password.
```

```java
                try (Connection conn = dbManager.getConnection()) {
                    UserRepository userRepo = new UserRepository();
                    if (userRepo.countUsers(conn) == 0) {
                        if (!"true".equalsIgnoreCase(System.getenv("AUTH_ALLOW_BOOTSTRAP"))) {
                            System.err.println("[FATAL] No accounts exist. Set AUTH_ALLOW_BOOTSTRAP=true "
                                    + "on an operator console to create the first one.");
                            return 2;
                        }
                        return handleRegistration(authService, console);
                    }
                }
```

Apply the `0700`/`0600` tightening to the fallback location as well as to configured ones, and record in the audit log the moment a bootstrap registration succeeds, so a first-account takeover is at least an observable event.

---

### SEC-13: Throwables attached to `SEVERE` records are rendered to stderr by the console handler, leaking internals

**Severity:** Medium

**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File)

**Location:** `src/main/java/com/example/auth/SecurityLogger.java:21-35`, `:109-111`

**Vulnerable code:** `SecurityLogger.java:21-35`

```java
    static {
        LOGGER.setUseParentHandlers(false);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                return String.format("[%1$tF %1$tT.%1$tL] [%2$s] %3$s%n",
                        record.getMillis(),
                        record.getLevel().getName(),
                        record.getMessage());
            }
        });
        LOGGER.addHandler(handler);
    }
```

**Vulnerable code:** `SecurityLogger.java:109-111`

```java
    public static void logSystemError(String operation, Throwable throwable) {
        LOGGER.log(Level.SEVERE, "SECURITY [SYSTEM_ERROR] Operation=" + sanitizeCrlf(operation), throwable);
    }
```

**Why it is a problem:** The formatter looks like the control that keeps internals out of the output — it prints only a timestamp, a level and the message, deliberately omitting `record.getThrown()`. It does not, because `java.util.logging.Formatter.format(LogRecord)` is the method that appends the attached throwable's stack trace to whatever `formatMessage` returned, and `StreamHandler.publish` writes that whole string. So every `logSystemError` call emits a full stack trace, and `sanitizeCrlf` is applied only to the message, never to the throwable. There are six call sites that attach live exceptions: `AuthenticationService.java:99` (the `SQLException` from a login lookup), `AuthenticationService.java:175` and `:179` (registration failures and connection failures), `DatabaseManager.java:82` (schema initialisation), `DatabaseManager.java:123` (the permission-setting path), and `AuthenticationService.java:77` (interrupted throttle delay). An H2 `SQLException` is not a short, opaque error: its message embeds the generated SQL or the affected file path, its `getSQLState`/`getErrorCode` identify the engine and version, and the trace exposes H2's internal class names, the JDBC driver's connection-setup frames and the absolute path of the database file. Combined with SEC-01 — where the URL is attacker-influenced — the stderr stream becomes a free oracle for confirming whether a supplied URL parsed, which directive was rejected, and where on disk the process believes its data lives, all of which materially shortens the loop for the `INIT=RUNSCRIPT` attack. Because the handler writes to the console, in the normal deployment of a CLI container that stream is captured by the container runtime's log collection and forwarded to whatever aggregation the platform configures, so this is log-file exposure (CWE-532) as much as error-message exposure (CWE-209): the trace will be retained, indexed and readable by anyone with log-view access, while nothing in the code indicates that was intended. The design already gets the confidentiality half right — every audit path masks the email and neutralises CRLF — which makes the throwable the only unfiltered channel from exception state to persistent output.

**Fix:** Decide explicitly whether traces belong in the operator stream; if they do, put them on a separate level or stream that is never shipped to the shared log pipeline, and strip messages that can contain SQL or paths from what is retained.

```java
    static {
        LOGGER.setUseParentHandlers(false);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                String line = String.format("[%1$tF %1$tT.%1$tL] [%2$s] %3$s%n",
                        record.getMillis(), record.getLevel().getName(), record.getMessage());
                if (record.getThrown() != null) {
                    // Type and code only: no message text, no frames, no paths.
                    Throwable t = record.getThrown();
                    line += String.format("    cause=%s sqlCode=%d%n",
                            t.getClass().getSimpleName(), sqlCodeOf(t));
                }
                return line;
            }
        });
        LOGGER.addHandler(handler);
    }

    public static void logSystemError(String operation, Throwable throwable) {
        // Full trace goes to the developer channel only, never to the shipped stream.
        DEV_LOGGER.log(Level.SEVERE, "SECURITY [SYSTEM_ERROR] Operation=" + sanitizeCrlf(operation), throwable);
        LOGGER.log(Level.SEVERE, "SECURITY [SYSTEM_ERROR] Operation=" + sanitizeCrlf(operation)
                + " type=" + (throwable == null ? "none" : throwable.getClass().getSimpleName()));
    }
```

Keep the client-visible string exactly as `AuthenticationResult.MSG_INTERNAL_ERROR` already has it — the current code is right that the caller must not see internals; the leak is on the operator side of the same call.

---

### SEC-14: Password silently truncated at 128 characters and decoded byte→char, so the verified secret is not the typed one

**Severity:** Medium

**CWE:** CWE-20 (Improper Input Validation), CWE-244 (Improper Clearing of Memory Before Release)

**Location:** `src/main/java/com/example/auth/Main.java:178-195`, `:150-162`

**Vulnerable code:** `Main.java:178-195`

```java
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

**Vulnerable code:** `Main.java:150-162`

```java
    private static char[] readPassword(Console console, String prompt) {
        if (console != null) {
            char[] chars = console.readPassword(prompt);
            return chars != null ? chars : new char[0];
        } else {
            System.out.print(prompt);
            try {
                return readPasswordDirect(System.in);
            } catch (IOException e) {
                return new char[0];
            }
        }
    }
```

**Why it is a problem:** `readPasswordDirect` is the fallback used whenever `System.console()` is null, which is the normal case inside a container, under a test harness, or when stdin is a pipe — so this is not the exotic path, it is the default one. It reads raw bytes from `System.in` and casts each one to `char` with no charset decoding, which is correct only for US-ASCII. Any password containing a non-ASCII character is therefore misinterpreted: a UTF-8 encoded passphrase such as `pässwörd` arrives as 11 bytes and is turned into an 11-character `char[]` of mojibake, so the value registered differs from the value typed by the number of continuation bytes. Two consequences follow. If registration and login both go through this path on the same machine with the same locale, the wrong value is hashed consistently and the user is locked out as soon as they log in from a real terminal, where `console.readPassword` decodes properly — an account that cannot be logged into, with no diagnostic. If only one side used this path, the effective secret is a *deterministic function* of the typed one, known to anyone who can read this 12-line method. The truncation is worse: bytes past `MAX_PASSWORD_LENGTH` (128) are dropped inside the `if (len < InputValidator.MAX_PASSWORD_LENGTH)` guard with no error, no warning and no shortening indicator, so a 130-character passphrase is silently registered as its own 128-character prefix. The password that grants access is thus not the password the user was shown to have chosen, and for passphrases longer than 128 characters the accepted secret space collapses to a prefix the user cannot perceive — the same class of defect that makes truncated-hash systems break on FIPS-compliant passphrases. `isValidPasswordForCreation` bounds the length at 128 *after* the truncation has already happened, so validation can never see the over-long input and cannot reject it. `readLineFromStream` (`Main.java:164-176`) repeats the byte→char cast for the email prompt — a smaller problem, since emails are validated, but the same silent misdecoding. The zeroization discipline is otherwise good here (`Arrays.fill(buffer, '\0')` before return); the defect is the decode and the silent cap, not the clearing.

**Fix:** Decode with the platform charset and reject over-long input explicitly instead of cutting it, in the one place that both branches share.

```java
    private static char[] readPasswordDirect(InputStream in) throws IOException {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1 && b != '\n') {
            if (b != '\r') {
                raw.write(b);                       // never discard silently
            }
        }
        String line = raw.toString(StandardCharsets.UTF_8);
        Arrays.fill(raw.toByteArray(), (byte) 0);
        if (line.codePointCount(0, line.length()) > InputValidator.MAX_PASSWORD_LENGTH) {
            System.out.println("[ERROR] Password exceeds the maximum of "
                    + InputValidator.MAX_PASSWORD_LENGTH + " characters.");
            return new char[0];                     // caller fails validation; no silent truncation
        }
        return line.toCharArray();
    }
```

For the email prompt, use the same decode (`new String(raw.toByteArray(), StandardCharsets.UTF_8)`) so that the value reaching `canonicalizeEmail` is the value the operator typed, and log the rejected length rather than the secret itself.

---

### SEC-15: Registration is completely unthrottled and pays full KDF cost per call

**Severity:** Medium

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption)

**Location:** `src/main/java/com/example/auth/AuthenticationService.java:147-187`

**Vulnerable code:** `AuthenticationService.java:147-156`

```java
    public boolean registerUser(String email, char[] passwordChars) {
        try {
            if (!InputValidator.isValidEmail(email) || !InputValidator.isValidPasswordForCreation(passwordChars)) {
                return false;
            }

            String canonicalEmail = InputValidator.canonicalizeEmail(email);
            HashResult hashResult = passwordHasher.hashPassword(passwordChars);

            try (Connection conn = databaseManager.getConnection()) {
```

**Why it is a problem:** `authenticate` opens by consulting the limiter and paying a `Status` check before any crypto (SEC-03's complaint is that it consumes a permit too eagerly); `registerUser` never touches `rateLimiter` at all. The only gates in front of the expensive work are `isValidEmail` and `isValidPasswordForCreation` — two format checks — and the very next statement is `hashPassword`, which runs the full 210,000-iteration PBKDF2 before the code has opened a connection or asked whether the address already exists. The design therefore sells a fixed, expensive unit of CPU to any caller for nothing, and the exchange rate is fixed by `DEFAULT_ITERATIONS`: each unauthenticated call buys the attacker roughly the same CPU the login path buys, with no per-source accounting, no per-account accounting, no global cap and no captcha or confirmation mail to absorb it. That makes account creation a pure amplification primitive for a denial-of-service attempt against the authentication tier, which is precisely the tier a limiter exists to protect; it also makes the cost an *oracle*, because latency per address is now a free, unthrottled measurement channel (a call that reaches the `findByEmail` duplicate branch costs measurably more than one that returns at validation, and the difference is visible on top of the derivation). The second consequence is state growth: with no throttle, registration is also the cheapest way to fill the store — nothing in this path limits accounts per source, per domain, or in total, so a script can mint thousands of rows, each of which permanently adds a lookup to every subsequent query, and each of which becomes a future KDF-cost target that SEC-11's unbounded `iterations` ceiling turns back into CPU. The `Main` bootstrap path (SEC-12) shows the authors did think about who is allowed to create an account; that reasoning simply stops at the boundary of this method, even though this method is the one that stays reachable after bootstrap.

**Fix:** Put the limiter in front of registration with its own, tighter policy, and check for the existing account before paying for the derivation.

```java
    public boolean registerUser(String email, char[] passwordChars) {
        try {
            if (!InputValidator.isValidEmail(email) || !InputValidator.isValidPasswordForCreation(passwordChars)) {
                return false;
            }
            String canonicalEmail = InputValidator.canonicalizeEmail(email);

            // New: registration has its own policy (e.g. 3/hour per source), keyed like authenticate().
            RateLimiter.Status st = rateLimiter.checkAndAcquireRegistration(sourceId, canonicalEmail);
            if (st != RateLimiter.Status.ALLOWED) {
                SecurityLogger.logRateLimitExceeded(canonicalEmail, sourceId, "REGISTRATION");
                return false;
            }

            try (Connection conn = databaseManager.getConnection()) {
                // New: cheap uniqueness probe before the expensive KDF, not after.
                if (userRepository.findByEmail(conn, canonicalEmail).isPresent()) {
                    return false;
                }
            }

            HashResult hashResult = passwordHasher.hashPassword(passwordChars);
            // ... existing transaction ...
```

Also add a global ceiling on registrations per unit time (a `Semaphore` or token bucket independent of the per-source limiter, so SEC-04's spoofable identity cannot mint past it), and emit an audit record for each accepted registration so account flooding is at least visible.

---

### SEC-16: Sessions are never validated or revoked in production code; no idle timeout and no binding

**Severity:** Low

**CWE:** CWE-613 (Insufficient Session Expiration)

**Location:** `src/main/java/com/example/auth/SessionManager.java:42`, `:90-113`, `:115-125`

**Vulnerable code:** `SessionManager.java:94-103`

```java
    public Optional<Session> validateSession(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        Session session = activeSessions.get(token);
        if (session == null) {
            return Optional.empty();
        }
        if (session.isExpired()) {
            activeSessions.remove(token);
```

**Vulnerable code:** `SessionManager.java:115-125`

```java
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

**Why it is a problem:** The session machinery is well built and completely disconnected. A grep over `src/main` finds `validateSession` and `invalidateSession` only at their own declarations — the sole other references anywhere in the tree are in `SessionManagerTest.java` (lines 38, 41, 46, 47). `Main` mints a session, prints its cookie header (SEC-05) and exits; nothing in the shipped program ever accepts a token and asks whether it is still good. So every guarantee in this class is theoretical in the artifact as delivered: expiry is enforced only when someone calls `validateSession`, and revocation exists only as a method no caller uses. If a caller is added later, what it gets is still weaker than the surrounding code suggests. Expiration is absolute — `Session` carries `createdAt` and `expiresAt` and `isExpired()` compares only `expiresAt` against `Instant.now()` — so there is no idle timeout: a token captured on day one of an eight-hour session stays valid for the remaining seven hours no matter how many times it goes unused. There is no binding either: the record holds `sessionId`, `userId`, `email`, `createdAt`, `expiresAt` and `cookieHeader`, and nothing ties a token to a client IP, user agent, or a per-user session generation counter, which means a replayed token is indistinguishable from the original holder's, and "log out everywhere" cannot be implemented because there is no notion of a user's session epoch to bump. Logout in the interactive flow simply drops the local variable; the entry stays in `activeSessions` until some later `createSession` happens to sweep it. That sweep is itself weak, in the same shape SEC-08 documents for `RateLimiter`: `evictIfNecessary` runs only when `activeSessions.size() > MAX_ACTIVE_SESSIONS` and removes only entries where `isExpired()` is already true, so past the threshold a process holds every live session it has ever issued — a stolen-but-unexpired token cannot be aged out by capacity pressure, and the map grows to the number of logins rather than to the cap. Since sessions die with the JVM there is no cluster-wide state to revoke either, but the reverse is also true: this design cannot be carried to a multi-instance deployment without inventing the validation call and the revocation list from scratch. Severity is Low because nothing consumes the token today, so there is no live bypass — the risk is that the class reads as a finished session layer and will be wired up as one.

**Fix:** Wire the validation and revocation paths in, and make the lifetime policy explicit rather than purely absolute.

```java
    // Session: add idle tracking and a binding fingerprint.
    public record Session(String sessionId, long userId, String email,
                          Instant createdAt, Instant expiresAt, Instant lastAccessAt,
                          String clientFingerprint, String cookieHeader) {

        boolean isExpired(long idleSeconds) {
            Instant now = Instant.now();
            return Instant.now().isAfter(expiresAt)
                    || now.isAfter(lastAccessAt.plusSeconds(idleSeconds));
        }
    }

    // SessionManager: reject a bound mismatch, slide the idle window, and hard-cap by age.
    public Optional<Session> validateSession(String token, String clientFingerprint) {
        Session s = (token == null || token.isBlank()) ? null : activeSessions.get(token);
        if (s == null || s.isExpired(idleSeconds) || !s.clientFingerprint().equals(clientFingerprint)) {
            if (s != null) activeSessions.remove(token);
            return Optional.empty();
        }
        activeSessions.put(withSlidingAccess(s), token);   // slide idle window
        return Optional.of(s);
    }

    private void evictIfNecessary() {
        if (activeSessions.size() > MAX_ACTIVE_SESSIONS) {
            // Age-based hard bound: oldest createdAt first, remove regardless of expiry.
            activeSessions.entrySet().stream()
                    .sorted(Comparator.comparing(e -> e.getValue().createdAt()))
                    .limit(activeSessions.size() - MAX_ACTIVE_SESSIONS)
                    .forEach(e -> activeSessions.remove(e.getKey()));
        }
    }
```

Then have the production entry point call `validateSession` on every authenticated operation and `invalidateSession` on logout, on password change, and on any security-relevant role change, so revocation stops being dead code.

---

### SEC-17: Session-token lookup is not constant-time (mitigated by 256-bit entropy)

**Severity:** Low

**CWE:** CWE-208 (Observable Timing Discrepancy)

**Location:** `src/main/java/com/example/auth/SessionManager.java:98`

**Vulnerable code:** `SessionManager.java:98-100`

```java
        Session session = activeSessions.get(token);
        if (session == null) {
            return Optional.empty();
```

**Why it is a problem:** Everywhere a secret is compared, this codebase reaches for `MessageDigest.isEqual` — hash verification in `PasswordHasher` does exactly that, and the comments show the author understood why. Session lookup is the one place a secret is matched by a general-purpose hash map instead: `ConcurrentHashMap.get(token)` hashes the candidate, walks to one bucket, and compares keys with `String.equals`, which is a length check followed by a character-by-character loop that returns on the first mismatch. That gives an attacker two observable effects they do not have against `MessageDigest.isEqual`: the response differs in timing between "no entry in this bucket" and "an entry here matched at least a prefix", and the early-exit comparison is a variable-time operation on secret material. In isolation that is a textbook secret-branch timing channel. It is rated Low rather than Medium because the practical prerequisites are not met here. The token is 32 bytes from `SecureRandom` rendered as URL-safe Base64 without padding — 43 characters, 256 bits of entropy, with no structure, no signature segment and no server-chosen prefix an attacker can hold constant while varying the rest, which rules out the compress-and-match style of attack that makes byte-at-a-time timing attacks against session identifiers feasible. The map is also populated only by successful logins, so an attacker who has not authenticated is measuring an almost-empty map where bucket occupancy is dominated by the defender's own sessions, and the noise floor for a single `get` on a modern JVM (JIT, hash computation, and the network and terminal I/O around it) is far larger than the prefix-comparison difference being sought. Finally, as SEC-16 records, nothing in the shipped program calls `validateSession` at all, so today there is no request surface on which to measure. The finding stands as a consistency defect and a forward-looking one: the moment this class is wired into a server loop with a populated session table, the weakest comparison in the codebase will be the one guarding the bearer credential, and the mitigation that makes it acceptable is an entropy argument, not a code property — nothing stops a future edit from shortening `TOKEN_BYTE_LENGTH` or switching to a structured token format.

**Fix:** Compare tokens through a constant-time primitive over a keyed digest, so the guarantee comes from the code rather than from the token's entropy.

```java
    // Key the lookup: attacker cannot influence which bucket is probed, and the
    // comparison is over a fixed-length digest via MessageDigest.isEqual.
    private byte[] lookupKey(String token) throws NoSuchAlgorithmException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(lookupKeyBytes, "HmacSHA256"));   // random per process
        return mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
    }

    public Optional<Session> validateSession(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            byte[] key = lookupKey(token);
            for (Map.Entry<byte[], Session> e : sessionsByKey.entrySet()) {
                // One fixed-time compare per entry; no early exit on a matching prefix.
                if (MessageDigest.isEqual(key, e.getKey())) {
                    return touchIfValid(e);
                }
            }
            return Optional.empty();
        } catch (GeneralSecurityException e) {
            SecurityLogger.logSystemError("Session lookup keying failed", e);
            return Optional.empty();
        }
    }
```

If a hash map is retained for scalability, keep the keyed digest as the key (which removes the attacker's control over bucket placement) and document `TOKEN_BYTE_LENGTH` as a security-relevant constant with a minimum of 32 bytes.

---

### SEC-18: Password policy is length-only, with no breached-password or account-derived rejection

**Severity:** Low

**CWE:** CWE-521 (Weak Password Requirements)

**Location:** `src/main/java/com/example/auth/InputValidator.java:98-110`

**Vulnerable code:** `InputValidator.java:98-110`

```java
    /**
     * Validates password strength for registration / account creation.
     * Requires minimum length and bounds maximum length.
     *
     * @param password Password character array.
     * @return true if valid for creation; false otherwise.
     */
    public static boolean isValidPasswordForCreation(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= MIN_PASSWORD_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
    }
```

**Why it is a problem:** The whole creation policy is the final `return`: one lower-bound comparison and one upper-bound comparison. No composition rule, no dictionary or breach-list check, and no comparison against anything derived from the account being created. The length floor itself is 8 characters — the Javadoc is candid that this is what it does — and the README documents the range as "1 and 128 characters" for authentication, so the policy permits `Password1` and, more importantly, permits the exact string the user just typed into the *other* field in the same prompt sequence. At registration, `AuthenticationService.registerUser` has `canonicalEmail` in scope at the point it calls the validator, so rejecting a password equal to the local part, the full address, or the reversed local part would be a few lines and would remove the most common weak-account shape in any deployment. The larger gap is the missing breach check. The storage design is deliberately future-proof — per-account random salt, algorithm and iteration count stored per row, revalidated on read, with a rehash path implied (SEC-10's fix) — but a modern KDF only protects a hash against *offline* cracking, and it does nothing for a password that already appears in a public corpus: such an account falls to an online or replayed credential-stuffing attempt in which PBKDF2's cost is irrelevant, and SEC-15 shows registration is unthrottled while SEC-03 shows a wrong-password attempt is cheap until the counter is exhausted. There is also no rejection of the empty or whitespace-only values that pass an 8-character length test (`"        "` — eight spaces — satisfies `>= MIN_PASSWORD_LENGTH`), which matters because `readPasswordDirect` (SEC-14) can produce exactly such a value from a stray input line and return it as a "valid" secret. Severity is Low because this is a strength policy rather than an authentication bypass, and because the compensating cost hardening is real; it is a finding because the code *claims* a password policy and delivers only a length gate, and because two of the three missing checks (email-derived and blank-password) are cheap to add at the exact call site that already has the data.

**Fix:** Keep the length bounds, and add the two checks that cost nothing plus a breach-list gate at the layer that already enforces policy.

```java
    public static boolean isValidPasswordForCreation(char[] password, String canonicalEmail) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH
                || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        String value = new String(password);
        if (value.isBlank() || value.trim().length() < MIN_PASSWORD_LENGTH) {
            return false;                                     // whitespace-only is not a secret
        }
        if (canonicalEmail != null && !canonicalEmail.isBlank()) {
            String local = canonicalEmail.substring(0, canonicalEmail.indexOf('@'));
            if (value.equalsIgnoreCase(local)
                    || value.equalsIgnoreCase(canonicalEmail)
                    || value.equalsIgnoreCase(new StringBuilder(local).reverse().toString())) {
                return false;                                 // account-derived password rejected
            }
        }
        return true;
    }
```

```java
    // Registration call site: also screen against a corpus before the KDF runs.
    if (!InputValidator.isValidPasswordForCreation(passwordChars, canonicalEmail)
            || BREACHED_PASSWORDS.containsNormalized(new String(passwordChars))) {
        return false;
    }
```

For the breach corpus, either embed a k-anonymity range client (send the first 5 bytes of `SHA-1(password)`, fetch the suffix range, never transmit the password) or load a local top-N list; normalize case and Unicode the same way `canonicalizeEmail` does, so a screened password cannot be re-typed in a different casing at login.

---

### SEC-19: Token mask reveals 8 of 43 characters, and the dummy password is a hardcoded, never-zeroized literal

**Severity:** Low

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-798 (Use of Hard-coded Credentials)

**Location:** `src/main/java/com/example/auth/SecurityLogger.java:74-82`; `src/main/java/com/example/auth/PasswordHasher.java:26-42`

**Vulnerable code:** `SecurityLogger.java:74-82`

```java
    public static String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "[EMPTY_TOKEN]";
        }
        if (token.length() <= 8) {
            return "***";
        }
        return sanitizeCrlf(token.substring(0, 4) + "..." + token.substring(token.length() - 4));
    }
```

**Vulnerable code:** `PasswordHasher.java:26-29`

```java
    // Pre-computed static dummy values used for timing attack defense
    private static final byte[] DUMMY_SALT = new byte[SALT_BYTE_LENGTH];
    private static final byte[] DUMMY_HASH;
    private static final char[] DUMMY_INPUT_PASSWORD = "DummyFallbackPassword#2026".toCharArray();
```

**Why it is a problem:** `maskToken` is the masking function that `Main.java:86` uses on the session token when it writes the audit line, and it leaves 8 of the token's 43 characters in the clear: the first four and the last four, separated by a literal `"..."` that also discloses the exact format. Four URL-safe Base64 characters are 24 bits, and the last four are 24 more, so a log reader is handed roughly 48 of the token's 256 bits — and, more usefully, an unambiguous template telling them the secret is a 43-character unpadded URL-safe Base64 string with 24 bits known at the front and 24 at the back. The mask is applied consistently, so a token *is* logged in this form on every login, and once SEC-05's raw-token stdout line has been fixed (as it should be) this becomes the residual token exposure. The stated purpose of masking is to make log content safe to retain and share, and 48 disclosed bits plus a format description does not achieve that purpose: it is a fingerprint, not a redaction, which is enough to correlate one token's use across log sources and to make an offline search for a captured token dramatically cheaper. The right output is a keyed, truncated digest — enough to correlate, impossible to extend. The second half of this finding is a consistency defect against the file's own stated rule. `DUMMY_INPUT_PASSWORD` is a literal password in source, contradicting the README's claim of "zero static, default, or backdoor passwords", and it is never cleared: the static block calls `spec.clearPassword()`, which wipes the `PBEKeySpec`'s internal copy, but the `char[]` field itself keeps `"DummyFallbackPassword#2026"` for the life of the process, where `verifyDummyPassword` re-reads it on every unknown-account login as the fallback input. In isolation the value is harmless — it is not a credential for anything, and an attacker who can read process memory already owns the host. It matters because it is the one place where the zeroization discipline that the rest of `PasswordHasher` follows carefully (salt and derived-key buffers are wiped, `clearPassword()` is in a `finally`) is quietly not applied, and because it is indistinguishable at a glance from a real hardcoded secret, which trains reviewers to skip over exactly the kind of line they should stop at.

**Fix:** Log a keyed digest prefix instead of live token characters, and derive the dummy input per process rather than storing a literal.

```java
    public static String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "[EMPTY_TOKEN]";
        }
        try {                                     // correlation handle, not a partial secret
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(MASK_KEY, "HmacSHA256"));   // random per process, never logged
            byte[] d = mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(Arrays.copyOf(d, 6));         // 9 chars, no format disclosure
        } catch (GeneralSecurityException e) {
            return "[MASK_UNAVAILABLE]";
        }
    }
```

```java
    // PasswordHasher: process-random dummy input, cleared once the dummy hash is built.
    private static final char[] DUMMY_INPUT_PASSWORD =
            String.format("Dp-%d-%d#x", SECURE_RANDOM.nextInt(), SECURE_RANDOM.nextInt()).toCharArray();

    static {
        SECURE_RANDOM.nextBytes(DUMMY_SALT);
        // ... build DUMMY_HASH from DUMMY_INPUT_PASSWORD at DEFAULT_ITERATIONS ...
        Arrays.fill(DUMMY_INPUT_PASSWORD, '\0');   // nothing reusable left in memory afterwards
    }
```

Because `DUMMY_HASH` is computed once at class-initialisation time, the dummy password only has to exist until then; randomising and then clearing it removes both the source literal and the long-lived plaintext copy, and makes the dummy path's cost independent of anything an attacker can read out of the class file.

---

## 6. Verified Controls and Checks With No Finding

The following were examined and found correctly implemented, or were searched for and not present. They are recorded so the report's absences are as reviewable as its findings.

**SQL injection — none found.** Every statement in `UserRepository` is a compile-time constant executed through `prepareStatement`, and every user-influenced value is bound as a parameter: `UserRepository.java:44` (`findByEmail`), `:99` (`createUser`), `:115` (`countUsers`), with the email bound at `:45` as `pstmt.setString(1, canonical);`. There is no `createStatement` anywhere in `src/main`, and no string concatenation reaches a SQL string — including the registration and authentication paths, which pass the canonicalised email as a value rather than interpolating it. The `exploiting-sql-injection-vulnerabilities` checklist was run as a negative test and matched nothing; general OWASP/CWE knowledge was not needed to reach that conclusion.

**Untrusted data read back from the database is revalidated.** `findByEmail` carries the comment `// Treat values from database as untrusted until verified (Rule 1)` and then refuses to construct a `UserRecord` unless the stored algorithm, iteration count, salt length and hash length all pass `InputValidator.isValidDatabaseHashParameters`, returning `Optional.empty()` on any failure rather than substituting defaults (`UserRepository.java:57-74`, validator at `InputValidator.java:143-158`). Null/blank required fields are likewise rejected before the record is built. This is the right posture for a field the application itself wrote, and it is what makes SEC-11 about the *value* of the ceiling rather than about missing validation.

**Credential and secret handling.** Passwords are carried in `char[]` rather than `String` from the prompt onward; buffers are wiped with `Arrays.fill` after use; `PBEKeySpec` is released through `clearPassword()` in a `finally`; generated salts and derived-key buffers are zeroized after encoding. `MessageDigest.isEqual` is used for password-hash comparison, `SecureRandom` is the only randomness source, and `PasswordHasher`'s constructor range-checks its iteration default against the published bounds.

**Log injection and identity masking.** `sanitizeCrlf` neutralises CR/LF before any value reaches a log message, `maskEmail`/`maskSegment` partially redact the account identity on every audit path, and `sourceId` is sanitised on each of the audit calls, so a crafted address or source identifier cannot forge additional audit lines. The remaining log findings are specific and separate: the raw token written by `Main` (SEC-05), the throwable traces (SEC-13), and the mask's own residual disclosure (SEC-19).

**Regular expressions.** The email pattern is applied to a length-bounded input and contains no nested quantifier or unbounded alternation, so the linear-time behaviour holds; no catastrophic-backtracking (ReDoS) candidate exists in `InputValidator`.

**Registration race (CWE-367) considered and not filed.** `registerUser` checks existence with `findByEmail` and then inserts, which is a check-then-act pair, but the schema declares the column `email VARCHAR(254) NOT NULL UNIQUE` (`DatabaseManager.java:66`) inside a transaction with `conn.setAutoCommit(false)` and explicit commit/rollback, so a concurrent duplicate loses on the unique constraint and the transaction rolls back to a `false` return. The race fails closed and cannot create two rows or let one account claim another's address, so it is not reported.

**Session token construction and cookie attributes.** Tokens are 32 `SecureRandom` bytes as unpadded URL-safe Base64, with the raw byte array zeroized after encoding, and the emitted cookie uses `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict` and `Path=/`. The lookup mechanism around that token is SEC-17; the construction itself is sound.

**Rate limiter internals.** `AttemptTracker`'s methods are `synchronized`, so the counter itself cannot tear and `entryCount` cannot be corrupted by concurrent increments. The defects filed against this class are about policy and lifecycle, not thread safety of the counter: the two-stage acquire is not atomic as a unit and the `getCount`-then-delay decision is racy (SEC-03, SEC-07), and the purge reclaims only already-expired entries (SEC-08).

**Build configuration.** Compilation runs with `-Xlint:all` and `-Werror` (`pom.xml:51-52`), Java 17 throughout (`:16-17`, `:48-49`), and dependencies are version-pinned, including H2 at 2.2.224 (`:19`, `:28`). Two process observations, deliberately not findings: H2 carries no `<scope>` element (`:36` is the JUnit `test` scope only), so the embedded database ships inside the shaded fat jar — appropriate here because the application genuinely needs it at runtime — and no software-composition-analysis plugin runs in the build, so a future H2 CVE will not be caught automatically.

**Test claims.** The test sources contain 29 `@Test` methods plus 2 `@ParameterizedTest` methods across six classes (`InputValidatorTest` 6, `AuthenticationServiceTest` 6, `SecurityAdversarialTest` 6, `RateLimiterTest` 4, `PasswordHasherTest` 4, `SessionManagerTest` 3). The README claims "45 unit and adversarial security tests"; the discrepancy is documentation drift, not a security defect, and is noted here only so the coverage claims behind several controls above are not taken at face value. The tests themselves were not executed.
