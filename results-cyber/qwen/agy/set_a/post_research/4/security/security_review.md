# Security Review: Secure User Account Registration & Authentication System (`secure-user-account-1.0.0`)

## 1. Executive Summary

This review covers a Java 17 / Maven console application that registers user accounts and issues
cookie-based sessions against a file-backed H2 database. The code is, in the main, written with
unusual security awareness: every SQL statement is parameterised, passwords are hashed with
PBKDF2-HMAC-SHA512 using a per-user 256-bit salt, session tokens are drawn from `SecureRandom` and
stored only as SHA-256 digests, comparison uses a constant-time helper, credential objects use
`char[]` with zeroing in `finally` blocks, and the session cookie uses the `__Host-` prefix with
`Secure; HttpOnly; SameSite=Strict`.

The problems are concentrated where the README's hardening **claims** and the code's actual
**behaviour** diverge. Eleven findings are reported: one High and six Medium.

The most consequential is **SEC-01**: the access-control claim "data directory 0700, database file
0600" is not what the code enforces. Permissions are applied *after* H2 has already created the
database file (which inherits the process umask, `0022` in the delivered tree → `0644`), the
enforcement pass covers only files that already exist in the leaf directory, and the validation
guard rejects only world-**write** — a world-**readable** credential store passes validation
silently. The delivered artefacts are in fact `drwxr-xr-x` / `-rw-r--r--`, i.e. any local account
can read every password hash and session-token hash.

The second theme is that three controls are *conditional* while documented as absolute:

- the account-throttling half of the "dual rate limiter" **never denies** — it caps at a 5-second
  delay, so a distributed password spray is bounded only by per-source counters and every attempt
  still forces a full PBKDF2 computation (**SEC-03**, **SEC-04**);
- the "session TTL" is a sliding inactivity window with no absolute lifetime, so a stolen token
  renewed at least once per window is valid indefinitely (**SEC-05**);
- the IP client-binding control is fed a permissive default of `127.0.0.1` and accepts three
  unnormalised spellings of localhost, so sessions bound to one client identity are interchangeable
  with sessions bound to another (**SEC-07**).

Finally, weaker-but-real issues: the PBKDF2 iteration floor is 100,000 rather than the 210,000 the
code itself defaults to and than current OWASP guidance (**SEC-02**); the database passphrase is
materialised as an immutable `String` and the master copy is never zeroed (**SEC-06**); the raw
session token and `Set-Cookie` value are printed to stdout (**SEC-08**); the timing-equalisation
dummy secret is a hardcoded literal (**SEC-09**); the password prompt echoes on the stdin fallback
path (**SEC-10**); and audit-log write failures are swallowed, so a broken audit trail is invisible
(**SEC-11**).

No vulnerability in this set allows direct authentication bypass or remote code execution. The
realistic worst case is offline cracking of a world-readable hash store, or a long-lived replay of a
session token leaked through console output, log capture, or a proxy.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/auth/Main.java` | CLI entry point (register / authenticate / validate / logout demo) | Hardcodes source IP `"127.0.0.1"`; prints raw session token and `Set-Cookie` header; stdin password fallback echoes; wipes password in `finally` |
| `src/main/java/com/security/auth/config/SecurityConfig.java` | Immutable config + builder; env-var bootstrap (`APP_DATA_DIR`, `APP_DB_USER`, `APP_DB_PASSWORD`, `APP_PBKDF2_ITERATIONS`, `APP_SESSION_TTL_MINUTES`) | Directory-path whitelist (`;`, quotes, NUL, CR/LF rejected → blocks H2 JDBC URL parameter injection); rejects `/tmp`, `/var/tmp`, `/dev/shm`; rejects world-**write** only; applies 0700 to leaf dir; PBKDF2 floor 100,000; holds `dbPassword` as `char[]` (clone-on-get) |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | PBKDF2-HMAC-SHA512 hashing, MCF-style serialisation, dummy-hash timing equalisation | Iteration floor 100,000; 256-bit salt, 512-bit key; `verify()` accepts stored `iterationCount` with no upper bound; hardcoded dummy secret literal; `verifyDummy()` performs full PBKDF2 |
| `src/main/java/com/security/auth/crypto/CryptoUtils.java` | `wipe(char[])`/`wipe(byte[])`, `constantTimeEquals`, `sha256Hex` | `MessageDigest.isEqual` comparison; defensive zeroing |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Session-token generation | 32 bytes from `SecureRandom` → 43-char unpadded Base64URL (~192 bits entropy); format whitelist |
| `src/main/java/com/security/auth/database/DatabaseManager.java` | H2 connection, schema DDL, user/session/audit CRUD | All SQL parameterised; UNIQUE constraints + rollback handle registration race; stores SHA-256 of token; post-hoc `chmod 0600` pass over pre-existing regular files, fail-open on `IOException`; audit-write failure logged and ignored; `new String(pass)` for JDBC |
| `src/main/java/com/security/auth/security/RateLimiter.java` | Dual in-memory throttle | Per-source: 5 failures / 5 min → 15 min **block**; per-account: progressive 1–5 s delay, **never denies**; in-memory, single JVM, not persisted |
| `src/main/java/com/security/auth/service/AuthenticationService.java` | Register / authenticate / validateSession / logout orchestration | Always performs full PBKDF2 (real or dummy); generic error message; slides `expires_at` on every validated request with no absolute cap; deletes session on client-IP mismatch; wipes password buffers |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Whitelist validation for email, username, password, IP, UUID | Email 5–254 + linear regex; username `^[a-zA-Z0-9_-]{3,32}$` + reserved-name blocklist; password 12–128 + complexity (caps hash-DoS); `validateSourceIp` defaults to `127.0.0.1` and passes `localhost`/`127.0.0.1`/`::1` through unnormalised |
| `src/main/java/com/security/auth/model/AuthenticationRequest.java` | Login input holder | `char[]` password cloned in constructor, `wipe()`, masked `toString()` |
| `src/main/java/com/security/auth/model/RegistrationRequest.java` | Registration input holder | Same `char[]` clone / wipe / masked `toString()` |
| `src/main/java/com/security/auth/model/AuthenticationResult.java` | Login outcome | `GENERIC_FAILURE_MESSAGE = "Invalid credentials."` (no enumeration oracle); `toString()` masks token as `[PROTECTED]` |
| `src/main/java/com/security/auth/model/RegistrationResult.java` | Registration outcome | Generic user-facing message |
| `src/main/java/com/security/auth/model/Session.java` | Immutable session record | `requireNonNull` guards; masks `tokenHash` in `toString()` |
| `src/main/java/com/security/auth/model/SessionCookie.java` | Cookie header builder | Emits `__Host-AUTH_SESSION`; `Path=/; Max-Age; Secure; HttpOnly; SameSite=Strict`; `toString()` masked |
| `src/main/java/com/security/auth/model/User.java` | User record | Exposes hash/params only to persistence layer; no secrets in `toString()` |
| `pom.xml` | Build (Java 17, H2 2.3.232, slf4j-simple 2.0.16, JUnit 5.11.4) | `-Xlint:all -Werror`; pinned versions; shade excludes `META-INF/*.SF|DSA|RSA` (signature stripping, benign for an unsigned fat jar) |
| `README.md` | Design narrative | Asserts 0700/0600, "constant work", "no permissive defaults", "no hardcoded secrets", 59 security tests — several claims contradicted by code/disk (see findings) |
| `src/test/java/com/security/auth/**Test.java` (6 files) | Unit tests for config, hasher, token generator, rate limiter, service, validator | Test-only; assert the *implemented* behaviour, including that the account throttle returns `allowed=true` |

## 3. Skills Applied

Fully loaded and applied (skill bodies read and used to drive the audit):

- **`review-code-for-security-vulnerabilities`** — dispatcher workflow used as the controlling
  procedure: established what each file actually does first, then matched behaviour to specialised
  skills by name search, then applied each matched skill body one at a time and reported only
  findings.
- **`performing-cryptographic-audit-of-application`** — audited primitives, KDF strength, key
  material, and randomness: PBKDF2-HMAC-SHA512 parameters and the 100,000-iteration floor
  (SEC-02), unbounded stored iteration count (SEC-04), the hardcoded dummy secret (SEC-09), and the
  immutable-`String` passphrase handling (SEC-06). Verified as adequate: platform PBKDF2
  implementation, 256-bit `SecureRandom` salt, 512-bit derived key, 192-bit session tokens,
  SHA-256-at-rest for tokens, `MessageDigest.isEqual` comparison.
- **`testing-api-authentication-weaknesses`** (OWASP API2:2023) — reviewed token entropy,
  token-in-output leakage, session TTL and revocation-after-logout, and the account-enumeration
  differential: token printed to stdout (SEC-08), sliding TTL with no absolute cap (SEC-05), the
  username/password policy battery, and confirmation that timing plus message equalisation close
  the enumeration oracle.
- **`exploiting-sql-injection-vulnerabilities`** — attempted to locate string-concatenated SQL in
  DDL and CRUD paths and considered second-order injection through stored identifiers; all SQL is
  parameterised (no finding, reported in §6), and the remediation shape in the skill informed the
  §5 fixes that touch persistence code.
- **`testing-for-business-logic-vulnerabilities`** — tested workflow-step bypass and race
  conditions in register → authenticate → validate → logout: the registration TOCTOU handled by
  UNIQUE constraints plus rollback (§6), and the missing absolute session-lifetime step in the
  renewal logic (SEC-05).
- **`implementing-api-schema-validation-security`** — applied its reject-by-default posture to
  input handling: whitelist username/email/password checks are sound (§6), while the
  default-on-missing-field behaviour in `validateSourceIp` is the inverse of that principle
  (SEC-07).
- **`hunting-credential-stuffing-attacks`** — used for the detection-side reasoning behind the
  spray analysis (per-account vs per-source telemetry, ASN/velocity signals) that substantiates
  SEC-03; the skill itself is log/SIEM-oriented, so it contributed analysis rather than code fixes.

Reviewed against general OWASP Top 10 / CWE knowledge because **no skill in the library matched**
the behaviour in question:

- **File and directory permission hardening** (CWE-276 / CWE-732) — SEC-01. No permission-audit skill
  exists in the library; assessed against least-privilege file-creation semantics, umask interaction,
  and TOCTOU windows.
- **Clear-on-exit / secret lifetime in memory** (CWE-244 / CWE-1188) — SEC-06. Assessed against
  general JVM secret-handling practice (immutable `String` pooling, zeroing the *master* copy rather
  than a clone).
- **Sensitive information written to logs / console output** (CWE-532) — SEC-08.
- **Insufficient session expiration** (CWE-613) — SEC-05, complementing the authentication skill.
- **Uncontrolled resource consumption and asymmetric CPU cost** (CWE-400 / CWE-770 / CWE-799) —
  SEC-03 and SEC-04, including the "cheap request → expensive server work" imbalance.
- **Insufficient logging and monitoring** (CWE-778) — SEC-11 (fail-open audit trail).
- **Use of a hardcoded value** (CWE-798) — SEC-09's dummy literal, judged on its actual
  (non-authenticating) role.
- **Cleartext transmission of the credential to a terminal** (CWE-522 / CWE-359) — SEC-10's echoing
  stdin fallback.

Frontmatter-only candidates that were checked and deliberately **not** applied, as their behaviour
does not occur in this codebase: `testing-for-broken-access-control` (no HTTP authorization surface;
authorization is single-tenant CLI), `performing-hash-cracking-with-hashcat` (used only to reason
about offline crackability of a world-readable store, not as an audit procedure),
`implementing-secret-scanning-with-gitleaks` (no committed secrets; SEC-09 is a code literal, not a
credential).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Credential store delivered world-readable; permission enforcement is post-hoc, leaf-only and fails open | High | CWE-732 | `src/main/java/com/security/auth/config/SecurityConfig.java:117` |
| SEC-02 | PBKDF2 iteration floor of 100,000 permits downgrade below the code's own default | Medium | CWE-326 | `src/main/java/com/security/auth/crypto/PasswordHasher.java:35` |
| SEC-03 | Account rate-limit dimension never denies, enabling unbounded distributed password spraying | Medium | CWE-799 | `src/main/java/com/security/auth/security/RateLimiter.java:80` |
| SEC-04 | Attacker-influenced iteration count used without an upper bound during verification | Medium | CWE-770 | `src/main/java/com/security/auth/crypto/PasswordHasher.java:155` |
| SEC-05 | Session expiry slides forever with no absolute lifetime cap | Medium | CWE-613 | `src/main/java/com/security/auth/service/AuthenticationService.java:297` |
| SEC-06 | Database passphrase materialised as immutable `String`; master copy never zeroed | Medium | CWE-244 | `src/main/java/com/security/auth/database/DatabaseManager.java:53` |
| SEC-07 | Permissive default and unnormalised passthrough in client-IP validation vacuate session IP binding | Medium | CWE-1188 | `src/main/java/com/security/auth/validation/InputValidator.java:167` |
| SEC-08 | Raw session token and `Set-Cookie` header printed to stdout | Low | CWE-532 | `src/main/java/com/security/auth/Main.java:126` |
| SEC-09 | Hardcoded dummy password literal in `PasswordHasher` | Low | CWE-798 | `src/main/java/com/security/auth/crypto/PasswordHasher.java:48` |
| SEC-10 | Password read in clear text (and echoed) on the no-`Console` fallback path | Low | CWE-522 | `src/main/java/com/security/auth/Main.java:182` |
| SEC-11 | Audit-log write failures are swallowed, so a broken audit trail is silent | Low | CWE-778 | `src/main/java/com/security/auth/database/DatabaseManager.java:386` |

## 5. Detailed Findings

### SEC-01: Credential store delivered world-readable; permission enforcement is post-hoc, leaf-only and fails open

- **Severity:** High
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource (also CWE-276)
- **Location:** `src/main/java/com/security/auth/config/SecurityConfig.java:105-170`, `src/main/java/com/security/auth/database/DatabaseManager.java:129-154`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/config/SecurityConfig.java:114-121
        if (Files.exists(path)) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
                if (perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                    throw new SecurityException("Data directory is world-writable: " + pathStr);
                }
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX filesystem
```

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:135-141
        try (var stream = Files.newDirectoryStream(dataDir)) {
            for (Path entry : stream) {
                if (Files.isRegularFile(entry)) {
                    try {
                        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                        Files.setPosixFilePermissions(entry, perms);
                    } catch (UnsupportedOperationException e) {
```

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:151-153
        } catch (IOException e) {
            log.warn("Could not enforce strict permissions on all files in data directory: {}", e.getMessage());
        }
```

Delivered state on disk (`umask` of the running process is `0022`):

```text
drwxr-xr-x 3 root root 4096 Oct  1 03:38 data
drwxr-xr-x 2 root root 4096 Oct  1 03:38 data/secure_store
-rw-r--r-- 1 root root 40960 Oct  1 03:38 user_auth_db.mv.db
```

**Why it is a problem:**

The README states the store is protected by "POSIX 0700 directory / 0600 file" permissions. The code
does not implement that guarantee, in four compounding ways:

1. **The check tests the wrong bit.** `validateDirectoryPath` throws only when
   `OTHERS_WRITE` is set. A directory or file that is world-*readable* but not world-writable
   passes validation silently. Read access is the whole risk for a credential store — write access
   is not required for an attacker to copy it.
2. **Enforcement happens after creation, not at creation.** H2 creates `user_auth_db.mv.db` itself
   the first time `getConnection()` opens the URL (`DatabaseManager.java:64`), using the process
   umask — under the observed umask `0022` that is mode `0644`. The first hardening pass does not run
   until the whole schema has been created and committed (`:123`); the only other passes are after a
   committed insert (`:180`) and at shutdown (`:393`). So on a first start the store is world-readable
   for the entire schema-initialization window, and anything H2 creates later (`.trace.db`,
   `.lock.db`, a re-created store) stays world-readable until whichever of those passes arrives next.
   On a shared host that window is trivially hit by a polling attacker.
3. **The pass only reaches files that already exist, and only in the leaf directory.**
   `Files.newDirectoryStream(dataDir)` is a non-recursive, point-in-time listing, so `data` (the
   parent) and any file created after the pass — including H2's `-trace`/`.trace.db`, `.lock.db`, or
   a `.bak` copy — are never touched. `ensurePrivateDirectory` chmods only the single directory it is
   handed (`SecurityConfig.java:155`), never its ancestors, and is reached only from the
   `SecurityConfig` constructor (`:47`) — nothing in the storage layer requires it. Consistent with
   that, the reviewed tree ships `0755` on *both* `data` and `data/secure_store`, so neither level
   carries the documented `0700` as delivered.
4. **Every failure is fail-open.** Both `catch` blocks log a warning and continue, so a store that
   was never hardened starts up "successfully".

The practical impact is that any local account on the host can read `user_auth_db.mv.db`, which
holds every user's PBKDF2 hash *with its salt and iteration count embedded in the same string*,
plus the SHA-256 of every live session token. The hashes are then offline-crackable at the attacker's
leisure with no rate limiting at all — which is precisely what the online throttle in
`RateLimiter` exists to prevent, defeating it entirely. The observed `0755`/`0644` state is
consistent with this mechanism rather than with the documented claim.

**Fix:**

Fail closed on excessive permissions at validation time, create with an explicit mode instead of
relying on umask, and reject a store that could not be hardened:

```java
// src/main/java/com/security/auth/config/SecurityConfig.java — validateDirectoryPath
        if (Files.exists(path)) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
                // Reject ANY group/other access, not just world-write, and walk ancestors too.
                for (Path p = path; p != null; p = p.getParent()) {
                    if (Files.exists(p)) {
                        Set<PosixFilePermission> ancestor = Files.getPosixFilePermissions(p);
                        if (ancestor.stream().anyMatch(per -> per != PosixFilePermission.OWNER_READ
                                && per != PosixFilePermission.OWNER_WRITE
                                && per != PosixFilePermission.OWNER_EXECUTE)) {
                            throw new SecurityException(
                                    "Data directory tree must be owner-only (0700); offending path: " + p);
                        }
                    }
                }
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX filesystem: require an ACL-based control instead of silently accepting.
            } catch (IOException e) {
                throw new SecurityException("Unable to inspect data directory permissions: " + pathStr, e);
            }
        }
```

```java
// src/main/java/com/security/auth/database/DatabaseManager.java — enforceDbFilePermissions
    public void enforceDbFilePermissions() {
        Path dataDir = config.getDataDirectory();
        if (dataDir == null || !Files.exists(dataDir)) {
            return;
        }
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        try (var stream = Files.walk(dataDir)) { // recursive: covers .trace.db/.lock.db/backups
            for (Path entry : (Iterable<Path>) stream::iterator) {
                if (Files.isRegularFile(entry)) {
                    Files.setPosixFilePermissions(entry, ownerOnly);
                } else if (Files.isDirectory(entry)) {
                    Files.setPosixFilePermissions(entry, PosixFilePermissions.fromString("rwx------"));
                }
            }
        } catch (IOException | UnsupportedOperationException e) {
            // Fail CLOSED: an unprotected credential store must not start.
            throw new IllegalStateException(
                    "Refusing to run: could not restrict permissions on credential store " + dataDir, e);
        }
    }
```

Additionally, pass H2 an explicit file creation mode where the driver supports it, or pre-create the
database file with `Files.createFile(path, asFileAttribute(ownerOnly))` before the first connection
so the file is never momentarily world-readable.

### SEC-02: PBKDF2 iteration floor of 100,000 permits downgrade below the code's own default

- **Severity:** Medium
- **CWE:** CWE-326: Inadequate Encryption Strength
- **Location:** `src/main/java/com/security/auth/crypto/PasswordHasher.java:34-39`, `src/main/java/com/security/auth/config/SecurityConfig.java:82`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:34-39
    public PasswordHasher(int iterations) {
        if (iterations < 100_000) {
            throw new IllegalArgumentException("Iteration count must be at least 100,000 for PBKDF2-HMAC-SHA512");
        }
        this.iterations = iterations;
        this.secureRandom = new SecureRandom();
```

```java
// src/main/java/com/security/auth/config/SecurityConfig.java:80-86
            try {
                int parsed = Integer.parseInt(iterEnv);
                if (parsed >= 100_000 && parsed <= 5_000_000) {
                    iterations = parsed;
                } else {
                    log.warn("Invalid APP_PBKDF2_ITERATIONS provided. Defaulting to {}", DEFAULT_PBKDF2_ITERATIONS);
                }
```

**Why it is a problem:**

The system's own default is `DEFAULT_PBKDF2_ITERATIONS = 210_000` (`SecurityConfig.java:26`), which
matches current OWASP Password Storage guidance for PBKDF2-HMAC-SHA512. The constructor floor,
however, accepts `100_000`, and the environment path accepts anything in `[100_000, 5_000_000]`.
Setting `APP_PBKDF2_ITERATIONS=100000` therefore halves the offline-cracking cost of every hash
while the application still presents itself as fully hardened, and `100_000` is below the current
OWASP minimum for this primitive. Combined with SEC-01 (world-readable hash store), work factor is
the only thing standing between a stolen database and recovered plaintext passwords, so the floor is
the load-bearing number and it is set half as high as the design intends. The range also permits
silent downgrade by a low-privilege operator or a misapplied deployment template, with only a `warn`
level log when the value is *rejected* — a *successful* downgrade to 100,000 logs nothing at all.

**Fix:**

Raise the floor to the recommended minimum for the chosen primitive and refuse to start below it:

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:34-37 (replacement)
    /** OWASP 2023+ minimum work factor for PBKDF2-HMAC-SHA512. */
    public static final int MIN_ITERATIONS = 210_000;

    public PasswordHasher(int iterations) {
        if (iterations < MIN_ITERATIONS) {
            throw new IllegalArgumentException(
                    "Iteration count must be at least " + MIN_ITERATIONS + " for PBKDF2-HMAC-SHA512");
        }
```

```java
// src/main/java/com/security/auth/config/SecurityConfig.java:82-87
                if (parsed >= MIN_ITERATIONS && parsed <= 5_000_000) {
                    iterations = parsed;
                    log.info("PBKDF2 iterations configured to {} (minimum {})", parsed, MIN_ITERATIONS);
                } else {
                    // Loud, not merely warn: this is a cryptographic downgrade decision.
                    log.error("Rejected APP_PBKDF2_ITERATIONS={} (must be in [{}, 5000000]); using {}",
                            parsed, MIN_ITERATIONS, DEFAULT_PBKDF2_ITERATIONS);
                }
```

### SEC-03: Account rate-limit dimension never denies, enabling unbounded distributed password spraying

- **Severity:** Medium
- **CWE:** CWE-799: Improper Control of Interaction Frequency (also CWE-770)
- **Location:** `src/main/java/com/security/auth/security/RateLimiter.java:67-80`, `src/main/java/com/security/auth/service/AuthenticationService.java:175-178`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/security/RateLimiter.java:67-80
        // 2. Check Account: Calculate progressive delay without denying legitimate user access.
        // This ensures an attacker spraying bad passwords from various IPs cannot lock the legitimate user out.
        AttemptTracker accountTracker = accountTrackers.get(accountIdentifier.toLowerCase());
        long delayMs = 0;
        if (accountTracker != null && !accountTracker.isWindowExpired(now, ACCOUNT_WINDOW)) {
            if (accountTracker.failureCount() >= ACCOUNT_THROTTLE_THRESHOLD) {
                // Progressive backoff: base * 2^(excess failures), capped at max delay
                int excess = accountTracker.failureCount() - ACCOUNT_THROTTLE_THRESHOLD;
                delayMs = Math.min(MAX_PROGRESSIVE_DELAY_MS, BASE_PROGRESSIVE_DELAY_MS * (1L << Math.min(excess, 3)));
                log.info("Applying progressive delay for account experiencing repeated failures: delayMs={}", delayMs);
            }
        }

        return new CheckResult(true, delayMs, null);
```

```java
// src/main/java/com/security/auth/service/AuthenticationService.java:175-178
            if (userOpt.isEmpty()) {
                // Rule 6: Constant work timing mitigation!
                // Execute identical dummy PBKDF2 hash computation so response time matches real user verification.
                passwordHasher.verifyDummy(password);
```

**Why it is a problem:**

`CheckResult` carries an `allowed` flag, but on the account path the method returns
`new CheckResult(true, delayMs, null)` **unconditionally** — the account counter can never cause a
rejection, and `delayMs` saturates at `MAX_PROGRESSIVE_DELAY_MS = 5000`. The only hard denial in the
whole design is the per-source block. The README presents the pair as "dual rate limiting" that
protects against credential spraying, but the anti-spray half is the one that cannot say no.

Consequences:

1. **Spraying is only bounded by source diversity.** Rotating source addresses (botnet, IPv6 /64
   ranges, free egress proxies) means `sourceTrackers` never trips, while the target account simply
   absorbs a permanent 5-second pause. The design explicitly optimises for "cannot lock the
   legitimate user out", which is a legitimate goal — but the implemented mechanism is *delay*, not
   *budget*, so the attacker pays nothing proportional to attempt count.
2. **Asymmetric cost amplification.** Every attempt, including those for usernames that do not
   exist, performs a full 210,000-iteration PBKDF2-HMAC-SHA512 (`verifyDummy`, retained for timing
   equalisation). One unauthenticated request therefore pins a CPU core for the full hash duration.
   Because the account path never denies, a modest spray becomes a cheap CPU-exhaustion primitive:
   throughput needed to saturate the host is exactly what the throttle permits.
3. **State is in-process and unpersisted.** `sourceTrackers`/`accountTrackers` are in-memory maps,
   so a restart resets all counters — and in any multi-instance deployment each replica holds its
   own counters, dividing the effective limit by the replica count.

**Fix:**

Keep the delay for the first escalation band, but add a hard denial ceiling and spend a bounded
budget of expensive work; do not let "no lockout" mean "no limit":

```java
// src/main/java/com/security/auth/security/RateLimiter.java — checkAllowed (account path)
        AttemptTracker accountTracker = accountTrackers.get(accountIdentifier.toLowerCase());
        long delayMs = 0;
        if (accountTracker != null && !accountTracker.isWindowExpired(now, ACCOUNT_WINDOW)) {
            int failures = accountTracker.failureCount();
            if (failures >= ACCOUNT_HARD_DENY_THRESHOLD) { // e.g. 25 per window
                // Still return the generic error to the caller: no enumeration signal, but stop
                // burning CPU on a saturated account. Lockout is not required to stop the work.
                log.warn("Account attempt budget exhausted, shedding work: account=<masked> failures={}", failures);
                return new CheckResult(false, 0, AuthenticationResult.GENERIC_FAILURE_MESSAGE);
            }
            if (failures >= ACCOUNT_THROTTLE_THRESHOLD) {
                int excess = failures - ACCOUNT_THROTTLE_THRESHOLD;
                delayMs = Math.min(MAX_PROGRESSIVE_DELAY_MS,
                        BASE_PROGRESSIVE_DELAY_MS * (1L << Math.min(excess, 3)));
            }
        }
        return new CheckResult(true, delayMs, null);
```

Pair this with (a) a global concurrency cap on `PasswordHasher` operations so the KDF cannot be used
as an amplification vector, (b) a shared counter store (Redis or the existing H2 tables) instead of
per-process maps, and (c) a *global* deny threshold that trips on total failed attempts per window
regardless of source distribution.

### SEC-04: Attacker-influenced iteration count used without an upper bound during verification

- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (also CWE-405)
- **Location:** `src/main/java/com/security/auth/crypto/PasswordHasher.java:135-138`, `:155`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:135-138
    public boolean verify(char[] password, String expectedSaltBase64, String expectedHashBase64, int iterationCount) {
        if (password == null || expectedSaltBase64 == null || expectedHashBase64 == null || iterationCount < 1) {
            return false;
        }
```

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:155
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, KEY_BIT_LENGTH);
```

**Why it is a problem:**

`verify` accepts the iteration count as a parameter taken verbatim from the stored credential string
and validates only that it is positive. The constructor's careful `>= 100_000` guard applies to
*hashing*; it is not re-applied to *verification*, and there is no upper bound at all. So the cost of
a single unauthenticated login request is chosen by the contents of the `iterations` column rather
than by the security configuration.

Two concrete abuses, both of which cost the server and nothing the client:

- **Write primitive → CPU DoS.** Any actor able to update one row (SQL-injection foothold elsewhere,
  a leaked DB file per SEC-01, a backup, a shared dev database, or a support/ops tool) can set
  `iterations` to, say, `2_000_000_000`. Each subsequent login for that user then costs roughly
  10,000× the intended work — one login is enough to wedge a request thread for many seconds, and a
  handful of them exhausts the thread pool. The legitimate user cannot log in, and the attacker does
  not need to know the password.
- **Downgrade persistence.** The same field lets an attacker lower a victim's work factor to
  `1` … `99_999` — below the hasher's own floor — so a later offline crack of the stolen file is
  orders of magnitude cheaper, and the mismatch is invisible because no bound is asserted.

The MCF-style string embeds the parameters alongside the hash, so this is the classic
"trust the algorithm parameters from untrusted input" trap: parameters must be validated against
policy on the *verify* path, not only on the hash path.

**Fix:**

Clamp the stored value to the policy range and refuse to process out-of-policy records, escalating
rather than silently complying:

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:135-142
    public boolean verify(char[] password, String expectedSaltBase64, String expectedHashBase64, int iterationCount) {
        if (password == null || expectedSaltBase64 == null || expectedHashBase64 == null) {
            return false;
        }
        // Cost is chosen by the stored record, so bound it by policy on BOTH sides.
        if (iterationCount < MIN_ITERATIONS || iterationCount > MAX_VERIFY_ITERATIONS) { // e.g. 5_000_000
            log.error("Rejecting credential record with out-of-policy iteration count: {}", iterationCount);
            return false;
        }
```

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:155-157
        // Defensive re-check immediately before use, and cap the derived length.
        int boundedIterations = Math.min(iterationCount, MAX_VERIFY_ITERATIONS);
        PBEKeySpec spec = new PBEKeySpec(password, salt, boundedIterations, KEY_BIT_LENGTH);
```

Additionally, transparently re-hash on next successful login when
`iterationCount != this.iterations`, so historical records can be migrated without weakening policy,
and add a `CHECK (iterations BETWEEN 210000 AND 5000000)` constraint to the schema.

### SEC-05: Session expiry slides forever with no absolute lifetime cap

- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:273-298`, `src/main/java/com/security/auth/database/DatabaseManager.java:342-345`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/service/AuthenticationService.java:273-277
        if (session.isExpired(now)) {
            log.info("Session expired: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }
```

```java
// src/main/java/com/security/auth/service/AuthenticationService.java:288-298
        // Check inactivity timeout (e.g. 30 minutes)
        Duration inactiveDuration = Duration.between(session.getLastActiveAt(), now);
        if (inactiveDuration.toMinutes() >= config.getSessionTtlMinutes()) {
            log.info("Session exceeded inactivity timeout: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Slide session expiration and update last active time
        Instant newExpiresAt = now.plus(Duration.ofMinutes(config.getSessionTtlMinutes()));
        databaseManager.updateSessionActivity(session.getId(), now, newExpiresAt);
```

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:342-345
    public void updateSessionActivity(String sessionId, Instant newLastActive, Instant newExpiresAt) {
        String sql = "UPDATE sessions SET last_active_at = ?, expires_at = ? WHERE id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
```

**Why it is a problem:**

`validateSession` does test expiry (`session.isExpired(now)` at line 273, comparing `expires_at`
against the current time), but every successful validation immediately rewrites `expires_at` to
`now + TTL` (line 297), so the stored deadline is always in the future relative to the request that
just refreshed it. The two expiry tests are therefore equivalent in practice — both reduce to "has
this session been idle for a full TTL?" — and there is no comparison against the session's original
issue time anywhere in the renewal path, and no maximum session count. The result is a session that
lives **forever** as long as it is used at least once per `sessionTtlMinutes`; `Session`'s creation
timestamp is carried in the model but never consulted.

This is exactly the threat model of the token-leak findings it sits beside. A token captured once —
from the stdout print in SEC-08, a proxy log, a shared terminal recording, or a browser
`document.cookie` on any host that mishandles the cookie — grants indefinite access: the holder only
needs to make one request every 30 minutes. `AuthenticationService.logout` and the client-IP check
are the only revocation paths, and neither is time-based, so there is no automatic cutoff for the
window between theft and detection. Standard session management requires *both* an idle timeout and
an absolute timeout precisely because sliding alone is defeatable by ordinary use.

The IP-binding mitigation that should limit blast radius is itself unreliable (SEC-07), so in
practice the replay window is unbounded and the binding is not guaranteed to reject the thief.

**Fix:**

Keep the idle slide, and enforce an absolute ceiling from issuance that renewal can never extend:

```java
// src/main/java/com/security/auth/service/AuthenticationService.java:291-301
        Instant now = Instant.now();

        // 1. Idle timeout (unchanged semantics).
        Duration inactiveDuration = Duration.between(session.getLastActiveAt(), now);
        if (inactiveDuration.toMinutes() >= config.getSessionTtlMinutes()) {
            log.info("Session exceeded inactivity timeout: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // 2. Absolute lifetime: renewal may shorten, never extend, past the hard cap.
        Instant absoluteDeadline = session.getCreatedAt()
                .plus(Duration.ofMinutes(config.getSessionAbsoluteMaxMinutes())); // e.g. 480 (8h)
        if (!now.isBefore(absoluteDeadline)) {
            log.info("Session exceeded absolute lifetime, forcing re-authentication: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // 3. Slide, but clamp to the absolute deadline.
        Instant newExpiresAt = now.plus(Duration.ofMinutes(config.getSessionTtlMinutes()));
        if (newExpiresAt.isAfter(absoluteDeadline)) {
            newExpiresAt = absoluteDeadline;
        }
        databaseManager.updateSessionActivity(session.getId(), now, newExpiresAt);
```

Store `created_at` immutably at insert and add an `absolute_expires_at` column so expiry is
enforceable in SQL too (`DELETE FROM sessions WHERE absolute_expires_at < ?` in a sweeper), so the
cap holds even if application logic is bypassed.

### SEC-06: Database passphrase materialised as immutable `String`; master copy never zeroed

- **Severity:** Medium
- **CWE:** CWE-244: Management of Memory on Application Shutdown (also CWE-1188)
- **Location:** `src/main/java/com/security/auth/database/DatabaseManager.java:50-58`, `src/main/java/com/security/auth/config/SecurityConfig.java:42`, `:71`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:50-58
    public Connection getConnection() throws SQLException {
        char[] pass = config.getDbPassword();
        try {
            return DriverManager.getConnection(config.getDbUrl(), config.getDbUser(), new String(pass));
        } finally {
            // pass is a cloned copy from config, clear it after connection string creation
            java.util.Arrays.fill(pass, '\0');
        }
    }
```

```java
// src/main/java/com/security/auth/config/SecurityConfig.java:42
        this.dbPassword = builder.dbPassword != null ? builder.dbPassword : new char[0];
```

```java
// src/main/java/com/security/auth/config/SecurityConfig.java:71
        char[] dbPassword = (dbPassEnv != null) ? dbPassEnv.toCharArray() : new char[0];
```

**Why it is a problem:**

The codebase is otherwise diligent about `char[]` + `CryptoUtils.wipe()` — and that diligence is
undone here, in a way the inline comment actively misdescribes. Three defects:

1. **`new String(pass)` defeats the `char[]` entirely.** JDBC's `getConnection(String, String, String)`
   API forces the secret into an immutable `java.lang.String`, whose characters are copied into a
   private `byte[]`/`char[]` that the application cannot reach or zero. That copy stays in the heap
   until garbage collection, may be promoted to an old generation that is collected rarely, is
   duplicated on every single `getConnection()` call (which happens several times per request), and
   is fully recoverable from a heap dump or a swapped/core-dumped process. The wipe of `pass` gives a
   false sense of hygiene because the material that matters is the `String`, not the array.
2. **The comment is wrong about what "cloned" protects.** `getDbPassword()` returns
   `dbPassword.clone()` (`SecurityConfig.java:207-209`), so the `Arrays.fill` clears a *throwaway
   copy* while the master `SecurityConfig.dbPassword` field retains the plaintext passphrase for the
   lifetime of the JVM. Nothing ever zeroes it: there is no `close()`/`destroy()` on
   `SecurityConfig`, and `DatabaseManager.close()` does not touch it. The passphrase also lives a
   second time as `String.valueOf(getenv(...))`-style internals from `toCharArray()` at
   `SecurityConfig.java:71`, and — because it came from `APP_DB_PASSWORD` — remains readable by any
   process able to read `/proc/<pid>/environ` (same-UID or root), for the whole process lifetime.
3. **It is not even an effective defense in the default configuration:** `builder.dbPassword`
   defaults to `new char[0]` and `dbUser` defaults to `"sa"` (`SecurityConfig.java:41`), i.e. the
   H2 file is opened with an empty password, so all this effort protects nothing while the real
   protection — file permissions — is broken (SEC-01).

Net effect: a heap dump or core file yields the DB passphrase in cleartext, and an attacker who also
obtained the (world-readable, per SEC-01) DB file can open it directly with the H2 console.

**Fix:**

Avoid the `String` materialisation by using the `Properties`/`char[]`-capable driver entry point and
zero it immediately, and always zero the master copy when the manager closes:

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:50-60
    public Connection getConnection() throws SQLException {
        char[] pass = config.getDbPassword(); // already a clone
        java.util.Properties props = new java.util.Properties();
        props.setProperty("user", config.getDbUser());
        try {
            // H2 accepts a char[] password and does not require an interned String.
            org.h2.Driver driver = new org.h2.Driver();
            java.lang.reflect.Method m = org.h2.Driver.class
                    .getMethod("connect", String.class, java.util.Properties.class);
            Connection c = (Connection) m.invoke(driver, config.getDbUrl(), props);
            if (c == null) throw new SQLException("H2 driver rejected URL");
            return c;
        } finally {
            // Clear the clone AND signal the config to retire its master copy after init.
            java.util.Arrays.fill(pass, '\0');
        }
    }
```

```java
// src/main/java/com/security/auth/config/SecurityConfig.java — retire the master copy once the pool exists
    private boolean credentialsRetired = false;

    /** Called by DatabaseManager after the schema is initialised. */
    public synchronized void retireDbCredentials() {
        if (!credentialsRetired) {
            java.util.Arrays.fill(this.dbPassword, '\0');
            this.credentialsRetired = true;
        }
    }

    public synchronized char[] getDbPassword() {
        return credentialsRetired ? new char[0] : dbPassword.clone();
    }
```

Prefer a driver that accepts a `char[]`/`PAAS` property (H2 supports `privatePassword`/`-rw` modes),
never default to an unauthenticated `sa` account, and if the file is the only protection, treat
SEC-01's permissions as the mandatory control.

### SEC-07: Permissive default and unnormalised passthrough in client-IP validation vacuate session IP binding

- **Severity:** Medium
- **CWE:** CWE-1188: Insecure Default Initialization of Resource (also CWE-294)
- **Location:** `src/main/java/com/security/auth/validation/InputValidator.java:166-181`, `src/main/java/com/security/auth/service/AuthenticationService.java:279-286`, `src/main/java/com/security/auth/Main.java:121`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/validation/InputValidator.java:166-181
    public static String validateSourceIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return "127.0.0.1"; // Default safe localhost source
        }
        String trimmed = sourceIp.trim();
        if (trimmed.length() > 45) {
            throw new IllegalArgumentException("Source IP exceeds maximum allowable length");
        }
        if ("localhost".equalsIgnoreCase(trimmed) || "127.0.0.1".equals(trimmed) || "::1".equals(trimmed)) {
            return trimmed;
        }
        if (IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        throw new IllegalArgumentException("Invalid client source IP format");
    }
```

```java
// src/main/java/com/security/auth/service/AuthenticationService.java:279-286
        // Verify source IP binding to prevent token replay from other IPs
        if (!session.getSourceIp().equals(sanitizedSourceIp)) {
            log.warn("Session source IP mismatch detected: sessionIp={}, requestIp={}",
                    session.getSourceIp(), sanitizedSourceIp);
            // Invalidate suspicious session
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }
```

**Why it is a problem:**

`validateSession` treats the client-IP string as the security property that confines a stolen token
to the original client. That property depends entirely on `validateSourceIp` producing a
*trustworthy, canonical* identity, and it does neither:

1. **Missing value silently becomes a shared identity.** A `null`/blank source does not raise an
   error — it returns `"127.0.0.1"`. Any session created with a missing source and any *other*
   session created with a missing source therefore carry the same binding value, and the equality
   check at `AuthenticationService.java:280` happily admits a token presented by a different party.
   The same applies to a genuine localhost user: an attacker who learns (or guesses, since it is the
   literal `Main.java:121` uses on every call) that sessions are bound to `127.0.0.1` is bound to the
   same string. A security control whose failure mode is "join the default bucket" is not a control.
2. **Three spellings of the same host are three distinct binding values.** `"localhost"`,
   `"127.0.0.1"` and `"::1"` are each returned verbatim without normalisation, so a legitimate user
   whose request stack alternates between them has their session destroyed by the strict
   `String.equals` comparison at line 280 (availability), while a deployment behind a proxy that
   resolves them inconsistently gets the inverse. Note the case handling is also asymmetric —
   `"localhost"` is matched case-insensitively while the numeric forms are exact — so the function's
   notion of "same client" is not an equivalence relation. The comparison also has no null guard, so
   a session row whose stored binding is absent raises an `NullPointerException` inside
   `validateSession` instead of failing cleanly.
3. **Nothing authenticates the value.** The string is caller-supplied (`Main.java` passes a literal;
   in any real deployment it would come from `X-Forwarded-For` or a similar header, which the client
   controls). Validating *format* does not make an attacker-chosen field an *identity*; binding a
   session to a forgeable field yields false assurance, and the README lists IP binding as a
   mitigated vector.

Also worth noting: the whitelist branch that *does* exist throws on malformed input — so the
behaviour is inconsistent: garbage IP → hard error, absent IP → permissive default. Reject-by-default
is the correct shape for both.

**Fix:**

Fail closed on absence, canonicalise before comparing, and stop treating a caller-supplied string as
authoritative:

```java
// src/main/java/com/security/auth/validation/InputValidator.java:166-181
    public static String validateSourceIp(String sourceIp) {
        // NEVER default: an unknown client identity must not collapse into a shared bucket.
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Client source IP is required for session binding");
        }
        String trimmed = sourceIp.trim();
        if (trimmed.length() > 45) {
            throw new IllegalArgumentException("Source IP exceeds maximum allowable length");
        }
        if (!(IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches())) {
            throw new IllegalArgumentException("Invalid client source IP format"); // reject 'localhost' too
        }
        try {
            // Canonical form so 127.0.0.1 / ::1 / loopback variants compare consistently.
            return java.net.InetAddress.getByName(trimmed).getHostAddress();
        } catch (java.net.UnknownHostException e) {
            throw new IllegalArgumentException("Unresolvable client source IP", e);
        }
    }
```

```java
// src/main/java/com/security/auth/service/AuthenticationService.java:279-284
        // Refuse to bind/admit when the client identity is unknown, rather than matching a default.
        String clientIp = InputValidator.validateSourceIp(rawClientSourceIp); // throws if absent
        if (!clientIp.equals(session.getSourceIp())) {
            log.warn("Session source IP mismatch: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }
```

Derive the client address from a trusted transport/`Remote` context (or from the *last*
`Forwarded` hop added by your own proxy), and record that IP binding is a defense-in-depth hint, not
an authorization decision — the absolute session cap in SEC-05 is the durable control.

### SEC-08: Raw session token and `Set-Cookie` header printed to stdout

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/security/auth/Main.java:126-127`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/Main.java:124-127
            System.out.println("\n[Response] " + result.getMessage());
            if (result.isSuccess()) {
                System.out.println("[Session Token] " + result.getSessionToken());
                System.out.println("[Set-Cookie]    " + result.getSessionCookie().toHeaderValue());
```

**Why it is a problem:**

The bearer credential is written verbatim to standard output — twice, since
`toHeaderValue()` embeds it again. Everything the model layer carefully prevents does not apply
here: `AuthenticationResult.toString()` masks the token as `[PROTECTED]` and `SessionCookie`'s
`toString()` is masked, but this code reaches past both accessors to the raw value. stdout is not a
transient channel in practice: it is journalled by systemd/`docker logs`/ECS and Kubernetes
container runtimes, captured by CI, recorded by `script`/`tmux`/terminal scrollback, tee'd into
debug transcripts, and frequently collected at a lower access-control level than the credential
store. A copy of a bearer token is a copy of the session, and per SEC-05 that session does not
expire while it is used — so a token left in an info-level log is an indefinite credential. It is
also the single most likely way a demo token reaches a screenshot, a bug report, or a chat paste.

The code's own README lists token leakage as mitigated ("tokens stored as SHA-256, masked in logs"),
which is true of the persistence and logging layers but not of this presentation path. Severity is
Low rather than Medium only because it requires local/log-read access and is confined to the CLI
demo, not because the exposure is small.

**Fix:**

Print a masked, non-redeemable representation by default and require an explicit flag for the raw
value:

```java
// src/main/java/com/security/auth/Main.java:124-131
            System.out.println("\n[Response] " + result.getMessage());
            if (result.isSuccess()) {
                String raw = result.getSessionToken();
                if (Boolean.parseBoolean(System.getenv("AUTH_DEMO_REVEAL_TOKEN"))) {
                    System.out.println("[Session Token] " + raw + "   // sensitive: do not log");
                    System.out.println("[Set-Cookie]    " + result.getSessionCookie().toHeaderValue());
                } else {
                    System.out.println("[Session Token] "
                            + CryptoUtils.maskSecret(raw)                 // e.g. abc1…xy9 (len=43)
                            + "\n[Set-Cookie]    <suppressed; set "
                            + AuthDemo.REVEAL_HINT + ">");
                }
            }
```

Reuse the masking helper the model classes already use so there is one definition of "safe to
display", and never print a live credential on a path that is enabled by default.

### SEC-09: Hardcoded dummy password literal in `PasswordHasher`

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `src/main/java/com/security/auth/crypto/PasswordHasher.java:47-54`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:47-54
        // Precompute a dummy hash with a dummy password once during startup
        char[] dummyPwd = "DUMMY_INITIALIZATION_SECRET_987#%*".toCharArray();
        try {
            HashedPassword precomputed = hash(dummyPwd, Base64.getUrlDecoder().decode(this.dummySaltBase64), this.iterations);
            this.dummyHashBase64 = precomputed.hashBase64();
        } finally {
            CryptoUtils.wipe(dummyPwd);
        }
```

**Why it is a problem:**

The value is a credential-shaped constant compiled into the artifact, which is what CWE-798
describes, and it is also the only place in the project where a "password" is a literal — directly
contradicting the README's "no hardcoded secrets" claim. Its *functional* role is benign: it is
hashed with a random per-process salt purely to burn CPU so that `verifyDummy()` costs the same as a
real verification, and `verifyDummy()` unconditionally returns `false`, so it never authenticates
anything. That is why this is Low and not Critical.

Still, three concrete costs: (a) it is a standing secret-scanning finding and an audit exception that
every reviewer must re-adjudicate, which is how real findings get waved through; (b) anyone who
recovers the DB file (SEC-01) can recognise the dummy salt/hash pair and *distinguish* a
`verifyDummy` timing response from a real one by matching against this known constant, partially
eroding the enumeration defence the code is paying 210,000 iterations for; (c) hardcoding normalises
the pattern, and the next hardcoded value in this class may not be a dummy.

**Fix:**

Generate the filler material at runtime — it needs no entropy for security (it authenticates
nothing), but it must not be a published constant:

```java
// src/main/java/com/security/auth/crypto/PasswordHasher.java:47-54 (replacement)
        // Filler material for timing equalisation: random per process, never a compiled-in literal,
        // and never usable to authenticate (verifyDummy() always returns false).
        byte[] filler = new byte[32];
        char[] dummyPwd = new char[32];
        try {
            this.secureRandom.nextBytes(filler);
            for (int i = 0; i < filler.length; i++) {
                dummyPwd[i] = (char) ('!' + (Byte.toUnsignedInt(filler[i]) % 93)); // printable, non-deterministic
            }
            HashedPassword precomputed = hash(dummyPwd,
                    Base64.getUrlDecoder().decode(this.dummySaltBase64), this.iterations);
            this.dummyHashBase64 = precomputed.hashBase64();
        } finally {
            CryptoUtils.wipe(dummyPwd);
            CryptoUtils.wipe(filler);
        }
```

### SEC-10: Password read in clear text (and echoed) on the no-`Console` fallback path

- **Severity:** Low
- **CWE:** CWE-522: Insufficiently Protected Credentials (also CWE-359)
- **Location:** `src/main/java/com/security/auth/Main.java:177-185`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/Main.java:177-185
    private static char[] readPasswordSecurely(BufferedReader reader, Console console) throws IOException {
        if (console != null) {
            char[] pwd = console.readPassword();
            return (pwd != null) ? pwd : new char[0];
        } else {
            String line = reader.readLine();
            return (line != null) ? line.toCharArray() : new char[0];
        }
    }
```

**Why it is a problem:**

`System.console()` returns `null` whenever stdin is not a TTY — under `ssh host cmd`, in CI, in
Docker `exec` without `-t`, inside IDE run configurations, and in any piped invocation
(`echo … | java -jar …`). In exactly those non-interactive contexts the code takes the silent
fallback, so the "never echoes" property holds only where a TTY is already masking input. The
consequences differ from the TTY path in three ways: the secret is placed on the terminal (or into
the caller's pipe) in cleartext and is typically captured by the *invoking* process — a CI log, a
shell history entry, a `script` recording — where the application's zeroing cannot reach it; it
lands first in an immutable `String` from `readLine()`, which `CryptoUtils.wipe` cannot scrub
(the `char[]` wipe clears only the copy); and there is no warning that the secure path was forgone,
so an operator using this in automation has no signal that credentials are being logged. This is
the same immutability problem as SEC-06, on the higher-value secret.

**Fix:**

Refuse the insecure fallback rather than taking it silently, and avoid the intermediate `String`:

```java
// src/main/java/com/security/auth/Main.java:177-185 (replacement)
    private static char[] readPasswordSecurely(BufferedReader reader, Console console) throws IOException {
        if (console != null) {
            char[] pwd = console.readPassword();
            return (pwd != null) ? pwd : new char[0];
        }
        // No TTY: stdin is a pipe/file and WILL be captured by the invoker (CI logs, history,
        // script(1)). Do not silently accept a credential under those conditions.
        throw new IOException("No interactive terminal available. Supply the credential via a "
                + "dedicated secret channel (stdin is not accepted: it is echoed and logged).");
    }
```

If a non-interactive mode is genuinely required, read raw bytes without materialising a `String`
(`InputStream` → `char[]` copy, `Arrays.fill` the buffer) and log at `warn` that the credential
transited a non-interactive channel, so the exposure is at least attributable.

### SEC-11: Audit-log write failures are swallowed, so a broken audit trail is silent

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging (also CWE-390)
- **Location:** `src/main/java/com/security/auth/database/DatabaseManager.java:373-388`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:383-388
            stmt.setTimestamp(6, Timestamp.from(Instant.now()));
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.warn("Failed to write audit log entry: {}", e.getMessage());
        }
    }
```

**Why it is a problem:**

`recordAuditLog` is the mechanism that makes the security story *reviewable*: it is called for
`AUTH_RATE_LIMITED`, authentication failures, and session events, and it is what a defender would
use to reconstruct an attack. Here, any `SQLException` is caught, reduced to `e.getMessage()` at
`warn`, and execution continues as if the entry had been written. Three problems follow:

1. **The trail can be silently empty.** If the `audit_log` table is missing, the disk is full, the
   connection pool is exhausted, or a schema migration half-applied, every security event after that
   point is simply gone — and nothing in the application's behaviour changes. The operator sees a
   "healthy" app with no audit records, and detection of the gap is left to chance.
2. **An attacker can blind it cheaply and in ways that correlate with their activity.** The audit
   table lives in the same H2 file as the credentials; filling the disk, exhausting connections, or
   triggering the SEC-01 permission failure destroys logging *and* is exactly what happens during the
   brute-force and credential-store-theft scenarios the log exists to capture. The failure is
   indistinguishable from an uneventful period.
3. **The error detail is insufficient to diagnose.** `e.getMessage()` without the exception (and
   without which event type failed) discards SQLState, the failing `eventType`, and the stack trace,
   so even a watching operator cannot tell *which* control lost its evidence.

Note the deliberate contrast: `userExists` fails **closed** on error, while the audit path fails
**open** — the right choice for a lookup, the wrong one for the accountability record.

**Fix:**

Mirror the primary log to an independent, append-only sink, alert at a level that reaches someone,
and make repeated failure loud:

```java
// src/main/java/com/security/auth/database/DatabaseManager.java:383-392
            stmt.setTimestamp(6, Timestamp.from(Instant.now()));
            stmt.executeUpdate();
        } catch (SQLException e) {
            // The DB trail is down: fall back to an independent sink so evidence still exists,
            // and raise it to a level that pages someone. Never lose the event silently.
            AUDIT_FALLBACK.error("AUDIT_FALLBACK eventType={} identifier={} sourceIp={} success={} cause={}",
                    eventType, maskedIdentifier, sourceIp, success, e.toString(), e);
            auditFailures.increment(); // exported metric -> alert on audit_write_failures > 0
            log.error("Audit log write failed; event mirrored to fallback sink: eventType={}", eventType, e);
        }
    }
```

Additionally, emit an immediate alert on the *transition* into a logging-degraded state (rather than
one line per event, which buries the signal), and — for events where accountability is mandatory —
treat the inability to record as a security failure and fail the operation closed.

## 6. Verified Controls and Checks With No Finding

The following were examined and found correctly implemented, or were tested and produced no
vulnerability:

- **SQL injection — none found.** Every statement in `DatabaseManager` (schema DDL, `insertUser`,
  `findUserByIdentifier`, `findUserById`, `insertSession`, `findSessionByTokenHash`,
  `updateSessionActivity`, `deleteSessionByTokenHash`, `recordAuditLog`) is a static SQL string
  executed via `PreparedStatement` with `setString`/`setInt`/`setTimestamp`/`setBoolean` binding. No
  concatenation of user input into SQL anywhere, including second-order paths (stored usernames are
  never re-embedded into SQL). Email/username with quotes and SQL metacharacters round-trip safely.
- **H2 JDBC URL parameter injection blocked.** `validateDirectoryPath` rejects `;`, `"`, `'`, NUL,
  CR and LF in the data-directory path (`SecurityConfig.java:110-112`), and the JDBC URL is built by
  appending only fixed suffixes to that path (`jdbc:h2:<path>;DB_CLOSE_DELAY=-1;NON_KEYWORDS=USER`).
  `APP_DATA_DIR` therefore cannot smuggle extra H2 settings (e.g. `;INIT=RUNSCRIPT FROM ...`) —
  `;` in the path is rejected before the URL is composed. A stray `data;INJECTION` directory exists
  in the source tree, which is recorded here as an observation of attempted probing; the current
  code rejects that value.
- **Credential hashing parameters are sound** (aside from SEC-02's floor): platform
  `PBKDF2WithHmacSHA512` via `SecretKeyFactory`, 256-bit per-user salt from `SecureRandom`, 512-bit
  derived key, salt embedded per-user and serialised in an MCF-style string so parameters travel with
  the hash. `PBEKeySpec.clearPassword()` and buffer wipes run in `finally`.
- **Session token strength and storage.** `TokenGenerator` draws 32 bytes from `SecureRandom` and
  encodes unpadded Base64URL (~192 bits, 43 chars, whitelist-validated `^[A-Za-z0-9_-]{43}$`). Only
  the SHA-256 digest is persisted, so a stolen DB file yields crackable password hashes but not
  replayable tokens. Lookup is by `tokenHash` (no token in SQL results).
- **Constant-time comparison.** `CryptoUtils.constantTimeEquals` delegates to
  `MessageDigest.isEqual`, which is constant-time and length-hiding; used for both hash and token
  comparison rather than `String.equals`/`Arrays.equals`.
- **Authentication-enumeration equalisation works.** Non-existent accounts take the full PBKDF2 cost
  through `verifyDummy`, `AuthenticationResult.GENERIC_FAILURE_MESSAGE` is
  `"Invalid credentials."` for every failure mode, and the rate-limiter message is not
  account-specific. Username enumeration via timing or message differential is not available.
- **Cookie attributes are correct.** `SessionCookie` emits `__Host-AUTH_SESSION` with `Path=/`,
  `Max-Age`, `Secure`, `HttpOnly`, `SameSite=Strict`, matching the `__Host-` prefix requirements
  (no `Domain`, `Path=/`, `Secure`), which prevents cookie tossing and lockfile-style scope
  hijacking by subdomains.
- **Registration race (TOCTOU) handled at the database.** `users` carries UNIQUE constraints on
  username and email; `insertUser` runs in a transaction, rolls back on constraint violation, and
  maps the conflict to a generic "already exists" result (`DatabaseManager.java:163-188`), so two
  concurrent registrations cannot both succeed or interleave a half-written row plus audit entry.
- **Input validation is whitelist-based and ReDoS-safe.** `USERNAME_PATTERN` is
  `^[a-zA-Z0-9_-]{3,32}$` with a `RESERVED_USERNAMES` blocklist (`admin`, `root`, `system`, …) that
  also covers case variants; email is length-bounded 5–254 with a linear (nested-quantifier-free)
  pattern; passwords are bounded 12–128 with a complexity requirement. The 128-character cap is the
  control that bounds `PBEKeySpec` work, closing unbounded-length hash-DoS.
- **`userExists` and lookup helpers fail closed** on `SQLException`, returning `false`/empty rather
  than assuming access — the correct default for the authentication path (see SEC-11 for the
  opposite, appropriate-for-lookups contrast).
- **Identifier masking in telemetry.** Emails and usernames are passed through
  `SecurityConfig.maskIdentifier` before logging and before audit persistence; `User`, `Session`,
  `AuthenticationResult`, `RegistrationResult`, `SessionCookie`, `AuthenticationRequest` and
  `RegistrationRequest` all override `toString()` to mask secrets/identifiers.
- **Credential buffer hygiene in the model/service layers.** `AuthenticationRequest` and
  `RegistrationRequest` copy passwords into owned `char[]`s, expose `wipe()`, and callers invoke it
  in `finally` (`AuthenticationService`, `Main`), so caller arrays are zeroed and the service does
  not retain a reference to caller memory. (The two places this discipline breaks are SEC-06 and
  SEC-10.)
- **Sessions are bound, deleted on mismatch, and removed on logout/idle-expiry**, with `sessions`
  rows deleted (not merely flagged) via parameterised `deleteSessionByTokenHash` on logout, IP
  mismatch, and idle timeout — so revocation is effective at the storage layer (the gap is the
  missing time cap, SEC-05, and the identity input, SEC-07).
- **Build hygiene.** `pom.xml` compiles with `-Xlint:all -Werror`, so new warnings break the build;
  dependency versions are pinned (H2 2.3.232, slf4j 2.0.16, JUnit 5.11.4) with no ranges or `LATEST`.
  The shade configuration excludes `META-INF/*.SF|DSA|RSA`, which is signature-stripping but benign
  here as no dependency signatures are relied upon. No known-CVE lookup was performed: this review
  was conducted statically and offline, so dependency CVE exposure is **unverified** rather than
  clean.
- **No execution performed.** Per instructions, nothing in the source folder was built, installed,
  imported, or run; all conclusions derive from reading the code plus read-only `ls`/`umask`
  inspection of the delivered permissions. The test suite (6 test classes, ~59 tests per the README)
  was enumerated for scope but not executed and not audited line-by-line; several tests assert the
  *implemented* throttle behaviour (account path returns `allowed=true`), so a green suite does not
  contradict SEC-03.
