# Security Review: `com.example.auth` email/password authentication CLI (H2-backed)

## 1. Executive Summary

The reviewed component is a self-contained Java command-line program that authenticates an email
address and password against credentials stored in an embedded H2 SQL database, issues a
server-side session row on success, and writes an audit trail. It also has a `seed` command that
creates accounts. All configuration (database path, JDBC user/password, table names, KDF iteration
count, throttle limits, session TTL, audit path) comes from environment variables.

The code is unusually defensive for generated code, and the classic high-severity classes are
genuinely absent: **no SQL injection** (every value is a `?` bind parameter; the only interpolated
text is a table identifier restricted by an allowlist, denied against a reserved-word list, and
double-quoted), **no hardcoded production credential**, **no fail-open path** (every exception
leads to `DENIED`), constant-time digest comparison, PBKDF2 with per-account `SecureRandom` salts,
256-bit `SecureRandom` session tokens stored only as SHA-256, single-statement/`FOR UPDATE`
transactional rate limiting, uniform failure message and uniform KDF work on every denial path, and
log-injection-proof audit writing.

The findings that remain are design-level and trust-boundary issues rather than injection bugs. The
two most important:

* **SEC-01 (Medium)** – the "is this file owned by me?" guard that protects the credential store and
  the audit log compares the file owner against the `user.name` **JVM system property**
  (`DbPathGuard.java:72`). That property is settable from the untrusted environment the program
  itself declares hostile (`JDK_JAVA_OPTIONS=-Duser.name=…`), so the ownership half of the guard can
  be made to pass for a store or audit file planted by another local account.
* **SEC-02 (Medium)** – the per-source attempt budget, the control that is supposed to stop one
  attacker spraying many accounts, is keyed on `AUTH_SOURCE_ID`, an environment value the caller
  controls, so it can be reset at will. The project documents this as residual risk R6, but it is
  still the only cross-account cap in the design.

The remaining seven findings are Low: PBKDF2-HMAC-SHA256 at 210,000 iterations is below current
OWASP guidance (600,000), the audit-log size cap is per-process and ignores the existing file length
(so the documented 4 MiB bound does not hold and events can be silently dropped), account email
addresses are stored as unsalted SHA-256, only the immediate parent directory of the store is
permission-checked, a successful login consumes per-source budget that is never refunded (contrary
to the documented design), the engine-file hardening sweep misses sibling engine files, and the
advertised cookie `Max-Age` is a constant that ignores the configured session TTL.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/Main.java` | CLI front end: `login`, `seed`, `help` | Reads email/password from `Console`/stdin with byte caps and strict UTF-8; keeps secrets in `char[]` and wipes them; prints exactly one generic failure string; prints a session token to stderr when opted in; refuses non-UTF-8 consoles; `Runtime.halt()` on exit |
| `src/main/java/com/example/auth/Config.java` | Loads and validates all configuration from the environment | No defaults for store path/user; every numeric bound range-checked; refuses `sourceMax < identityMax`; holds the DB credential as `char[]` handed out once via `takeDbPassword()` |
| `src/main/java/com/example/auth/InputValidator.java` | Central allowlist validation | Email syntax/charset/length (printable ASCII, punycode refused), password policy (control chars, edge spaces, unpaired surrogates, UTF-8 byte cap), session-token shape (64 lowercase hex), SQL identifier allowlist + reserved-word denylist, DB path canonicalisation rejecting `;` and `=` (JDBC-URL option injection) |
| `src/main/java/com/example/auth/AuthService.java` | The authentication decision | Order: validate → reserve budget → read row → derive → constant-time compare → grant; one PBKDF2 derivation on *every* path (blind salt when no row exists); wall-clock floor per attempt; fail-closed on any storage error; internal reason codes never rendered |
| `src/main/java/com/example/auth/Database.java` | JDBC connection, schema, all SQL | Builds the H2 URL from a validated path with fixed options (`TRACE_LEVEL_FILE=0`, `DB_CLOSE_ON_EXIT=FALSE`); DB credential passed via `Properties`, never in the URL; all value-carrying SQL uses bind parameters; validates every column read back from storage; re-asserts 0600 on engine files |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2-HMAC-SHA256 KDF | 16-byte salt, 256-bit output, iteration range 100k–1.5M enforced on both write and read; `PBEKeySpec.clearPassword()` in `finally`; deterministic domain-separated "blind salt" for equal-work derivations |
| `src/main/java/com/example/auth/CryptoUtils.java` | Crypto helpers | `SecureRandom` draws, SHA-256, length-independent constant-time compare, hex codec, buffer wiping |
| `src/main/java/com/example/auth/SessionStore.java` | Server-side session rows | 256-bit `SecureRandom` token, only SHA-256 stored, expiry enforced inside the `WHERE` clause, revoke is one `DELETE` whose row count is the answer, cookie attribute advice string |
| `src/main/java/com/example/auth/ThrottleStore.java` | Per-identity and per-source rate limiting | `SELECT … FOR UPDATE` in an explicit transaction, budget rows locked in sorted key order, fail-closed on engine error or nonsense counter, fixed-window reset, refund on success |
| `src/main/java/com/example/auth/AccountSeeder.java` | Account creation (`seed`) | Fresh random salt per account; refuses to overwrite an existing address (detected by SQL state `23*`); never logs or returns the password |
| `src/main/java/com/example/auth/LogWriter.java` | Append-only audit log | Event text comes only from an enum; reason codes matched against `[a-z0-9_]{1,40}`; every rendered line re-validated against a CR/LF-free allowlist; email masked to `a***@domain`; file created 0600 with symlink/owner checks; total-byte cap |
| `src/main/java/com/example/auth/DbPathGuard.java` | Fail-closed filesystem checks | Refuses symlinks, group/world permission bits, and foreign ownership for the store directory and audit file |
| `src/main/java/com/example/auth/DbFiles.java` | Private file/directory creation | `CREATE_NEW` + POSIX attrs, re-asserts and verifies 0600/0700 after creation (umask-proof) |
| `src/main/java/com/example/auth/PosixPermissions.java` | Permission-set constants | `rw-------` and `rwx------` definitions |
| `src/test/java/com/example/auth/{AllTests,AuthServiceTests,E2ETests,T}.java` | Test suites and harness | Assert no SQL interpolation in main sources, timing/CPU equality across denial paths, throttle races, file modes; create 0700 scratch stores; contain throwaway test passwords only |
| `THREAT-MODEL.md` | Pre-written threat model | Input inventory, blocked-attack list, and accepted residual risks (R6 source-id spoofing, unsalted email hashes, stderr session emission) |
| `libs/h2-2.3.232.jar` (+ `.sha1`, `.sha256`) | Pinned embedded database engine | Dependency is version-pinned with digest files alongside; not executed or analysed during this static review |

Reviewed statically only. Nothing in the source tree was compiled, executed, or imported; the
bundled JAR and the `out/` class files were not run or decompiled.

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: the router workflow itself — per-file behaviour
  inventory, keyword extraction (sql injection, cryptography, password storage, session tokens,
  rate limiting, secrets, file permissions, logging, race conditions), skill selection, then audit.
- `performing-cryptographic-audit-of-application`: applied to `CryptoUtils.java`,
  `PasswordHasher.java`, `SessionStore.java` and `Config.java` — algorithm choice, KDF parameters
  (its guidance of 600,000 PBKDF2-HMAC-SHA256 iterations / CWE-916 drives SEC-03), salt handling,
  RNG source, constant-time comparison, and hardcoded-key scanning.
- `testing-api-authentication-weaknesses`: applied to `AuthService.java`, `SessionStore.java` and
  `Main.java` — account enumeration via differing messages/timings, token entropy, token
  revocation, token leakage into logs, password policy, credential-stuffing resistance.
- `exploiting-sql-injection-vulnerabilities` and `performing-second-order-sql-injection`
  (descriptions applied as a checklist): applied to every statement in `Database.java`,
  `SessionStore.java` and `ThrottleStore.java`, including the identifier-interpolation sites and
  the re-use of stored values read back from the database.
- `exploiting-race-condition-vulnerabilities`: applied to the check-then-act pairs —
  `ThrottleStore.reserve`/`refund`, `SessionStore.revoke`, `AccountSeeder.seed`, and the
  file create-then-chmod-then-verify sequences in `DbFiles`/`LogWriter`.
- `implementing-api-rate-limiting-and-throttling`: applied to `ThrottleStore.java` and the
  `Config` limit validation — per-principal vs per-source budgets, window algorithm, lockout
  weaponisation (SEC-02, SEC-07).
- `testing-for-sensitive-data-exposure`: applied to `LogWriter.java`, `Main.java`,
  `DbFiles.java`, `DbPathGuard.java` and `Database.java` — secrets in logs/argv/exception text,
  file modes, and in-memory lifetime of credentials.
- `performing-hash-cracking-with-hashcat` (description applied as offline-cracking cost model):
  used to judge the stored-credential format (PBKDF2-HMAC-SHA256, 16-byte salt, 210k iterations)
  against an attacker holding a store dump.
- `testing-for-broken-access-control`: applied to `AuthService.resolveSession`/`SessionStore.verify`
  — every authorisation answer is resolved from a server-side row, never from caller-presented data.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:
  the POSIX permission and ownership guards and the TOCTOU/ancestor-directory questions
  (CWE-732, CWE-367, CWE-807 — SEC-01, SEC-06, SEC-08); audit-log capacity and completeness
  (CWE-400, CWE-779 — SEC-04); JDBC URL option injection through a configured path; the
  charset/Unicode handling of credentials; CLI argument and exit-code handling; and the
  supply-chain posture of the pinned `libs/h2-2.3.232.jar`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | File-ownership guard trusts the `user.name` JVM property, which the untrusted environment can set | Medium | CWE-807 | `src/main/java/com/example/auth/DbPathGuard.java:72` |
| SEC-02 | Per-source attempt budget is keyed on caller-controlled `AUTH_SOURCE_ID`, so the cross-account cap is bypassable | Medium | CWE-807 | `src/main/java/com/example/auth/Config.java:156`, `src/main/java/com/example/auth/ThrottleStore.java:299` |
| SEC-03 | PBKDF2-HMAC-SHA256 default of 210,000 iterations is below current OWASP guidance | Low | CWE-916 | `src/main/java/com/example/auth/Config.java:39` |
| SEC-04 | Audit-log byte cap ignores the pre-existing file length and silently stops logging once reached | Low | CWE-779 | `src/main/java/com/example/auth/LogWriter.java:123` |
| SEC-05 | Account addresses stored as unsalted SHA-256, allowing offline recovery from a store dump | Low | CWE-759 | `src/main/java/com/example/auth/AuthService.java:184` |
| SEC-06 | Only the immediate parent directory of the store is permission-checked; ancestors are not | Low | CWE-732 | `src/main/java/com/example/auth/DbPathGuard.java:87` |
| SEC-07 | Successful logins consume per-source budget that is never refunded, enabling self-inflicted lockout | Low | CWE-645 | `src/main/java/com/example/auth/AuthService.java:281` |
| SEC-08 | Engine-file hardening sweep misses sibling engine files such as `.lock.db` / `.trace.db` | Low | CWE-732 | `src/main/java/com/example/auth/Database.java:187` |
| SEC-09 | Advertised cookie `Max-Age` is a constant that ignores the configured session TTL | Low | CWE-613 | `src/main/java/com/example/auth/SessionStore.java:152` |

## 5. Detailed Findings

### SEC-01: File-ownership guard trusts the `user.name` JVM property, which the untrusted environment can set

- **Severity:** Medium
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/example/auth/DbPathGuard.java:65-76` (decision at line 72)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/DbPathGuard.java:65-76
    private static void requireOwnedByCurrentUser(Path p) throws IOException {
        java.nio.file.attribute.FileOwnerAttributeView view = Files.getFileAttributeView(p,
                java.nio.file.attribute.FileOwnerAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("owner_attribute_unsupported");
        }
        String owner = view.getOwner().getName();
        String self = System.getProperty("user.name");
        if (self == null || !owner.equals(self)) {
            throw new IOException("path_not_owned_by_current_user");
        }
    }
```

**Why it is a problem:** `user.name` is an ordinary writable JVM system property, not a kernel
fact. Anyone who can influence how the program is launched — including the `JDK_JAVA_OPTIONS`
environment variable, which the `java` launcher silently prepends to the command line — can make
it say anything: `JDK_JAVA_OPTIONS=-Duser.name=mallory java -cp … com.example.auth.Main`. This is
the same environment the program's own threat model declares attacker-controlled (input I13), and
`Config` carefully validates every other environment value. The property gates the ownership half
of every filesystem guard in the program: `requirePrivateDirectory` (store directory, via
`Database.open` → `DbPathGuard.verifiedParentDirectory`) and `requirePrivateRegularFile` (the
`.mv.db` files and the audit log, via `DbFiles.hardenToOwnerOnly` and `LogWriter.open`). With the
property forged to match a planted file's owner, the program will open a credential store or an
audit log belonging to another local account — exactly the substitution the guard exists to stop —
instead of refusing to start. The permission-bit half of the check (`requireNoForeignAccess`) still
applies, so the planted object must be mode 0600/0700, which the attacker controls on their own
files.

**Fix:** Compare owners against the real identity of the process, never against a mutable property.
The portable way on this platform is to compare the target's owner with the owner of an object the
OS attributed to this process (for example `/proc/self`, or a file just created by this process),
or to compare the numeric `unix:uid` of the target with that of such a reference object.

```java
    private static void requireOwnedByCurrentUser(Path p) throws IOException {
        java.nio.file.attribute.FileOwnerAttributeView view = Files.getFileAttributeView(p,
                java.nio.file.attribute.FileOwnerAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("owner_attribute_unsupported");
        }
        // The kernel's own view of this process, not a JVM property an attacker can set with
        // -Duser.name / JDK_JAVA_OPTIONS.
        Object self = Files.getAttribute(Path.of("/proc/self"), "unix:uid", LinkOption.NOFOLLOW_LINKS);
        Object target = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        if (!(self instanceof Integer) || !(target instanceof Integer)
                || !self.equals(target)) {
            throw new IOException("path_not_owned_by_current_user");
        }
        if (view.getOwner() == null) {
            throw new IOException("owner_attribute_unsupported");
        }
    }
```

### SEC-02: Per-source attempt budget is keyed on caller-controlled `AUTH_SOURCE_ID`, so the cross-account cap is bypassable

- **Severity:** Medium
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/example/auth/Config.java:154-160`, `src/main/java/com/example/auth/ThrottleStore.java:298-302`, consumed at `src/main/java/com/example/auth/AuthService.java:130-135`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Config.java:154-160
        String sourceId;
        try {
            sourceId = InputValidator.requireSourceId(
                    orDefault(env.get(ENV_SOURCE_ID), DEFAULT_SOURCE_ID));
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("source_" + e.getMessage());
        }
```
```java
// src/main/java/com/example/auth/ThrottleStore.java:298-302
    static BudgetKey sourceBudget(String sourceId, int limit, int windowSec) {
        String h = CryptoUtils.toHex(CryptoUtils.sha256(
                PasswordHasher.utf8(sourceId))).substring(0, 32);
        return new BudgetKey(SOURCE_PREFIX + h, limit, windowSec * 1000L);
    }
```

**Why it is a problem:** The design has exactly two rate limits: per identity (default 8 failures /
15 min) and per source (default 120 attempts / 15 min). The per-identity budget is keyed on the
account hash and is sound. The per-source budget — the only control that bounds how many *different*
accounts one attacker can attack, and the one `Config.java:150` is written to protect — is keyed on
a label the attacker supplies in their own environment. `AUTH_SOURCE_ID=run-0001`,
`run-0002`, … yields a fresh 120-attempt budget per invocation, so password spraying and account
enumeration across many addresses are bounded only by the 8-per-account budget, not globally. The
validator only constrains the label's *shape* (48 chars from `[A-Za-z0-9._-]`), which does not make
it trustworthy. `THREAT-MODEL.md` records this honestly as accepted residual risk R6, and in a
single-user local CLI the attacker usually owns the environment anyway — but the rule the code sets
out to satisfy ("limit repeated attempts per source as well as per account") is not actually
enforced against an attacker, so it is reported here rather than silently accepted.

**Fix:** Derive the source key from server-side state rather than from the caller: the authenticated
tenant id, the peer address of the connection, or — for a local CLI where no such state exists — a
value the caller cannot choose, such as the process's real UID plus the controlling terminal. Accept
`AUTH_SOURCE_ID` only as an additional, *narrowing* label and refuse to let it widen a budget.

```java
// Config.java - the source label is no longer taken from the caller's environment.
        String sourceId;
        try {
            // Server-side state: the real UID of the process plus its controlling terminal. An
            // attacker-supplied AUTH_SOURCE_ID may only be appended for diagnostics, never used
            // as the budget key, so it cannot mint a fresh budget.
            sourceId = InputValidator.requireSourceId(serverSideSourceLabel());
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("source_" + e.getMessage());
        }
...
    private static String serverSideSourceLabel() {
        Object uid;
        try {
            uid = java.nio.file.Files.getAttribute(java.nio.file.Path.of("/proc/self"), "unix:uid");
        } catch (java.io.IOException e) {
            uid = "unknown";
        }
        return "uid-" + uid;
    }
```

### SEC-03: PBKDF2-HMAC-SHA256 default of 210,000 iterations is below current OWASP guidance

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/Config.java:39`, floor enforced at `src/main/java/com/example/auth/PasswordHasher.java:29`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Config.java:39
    static final int DEFAULT_ITERATIONS = 210_000;
```
```java
// src/main/java/com/example/auth/PasswordHasher.java:25-30
    static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    static final int SALT_BYTES = 16;
    static final int DERIVED_BITS = 256;
    static final int DERIVED_BYTES = DERIVED_BITS / 8;
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 1_500_000;
```

**Why it is a problem:** 210,000 is the OWASP Password Storage figure for PBKDF2-**HMAC-SHA512**,
not for HMAC-SHA256; for SHA-256 the current recommendation is 600,000 iterations, and the
configurable floor here is lower still at 100,000. Everything else about the stored format is
right (unique 16-byte `SecureRandom` salt per account, 256-bit output, constant-time compare), so
this only matters to an attacker who has already taken a copy of the `.mv.db` file — but that is
precisely the scenario the parameter exists for, and at 210k the GPU cost per candidate is roughly
a third of the intended figure. `PasswordHasher`'s own Javadoc notes PBKDF2 was chosen over a
memory-hard KDF deliberately, which makes the iteration count the only remaining cost lever.

**Fix:** Raise the default (and the accepted floor) to the OWASP figure for the algorithm actually
in use, or switch the KDF to Argon2id, which `PasswordHasher`'s Javadoc already identifies as the
better choice. The stored `pw_iterations` column means existing rows keep verifying while new
and re-hashed rows use the higher cost.

```java
// Config.java
    static final int DEFAULT_ITERATIONS = 600_000;   // OWASP guidance for PBKDF2-HMAC-SHA256
```
```java
// PasswordHasher.java
    static final int MIN_ITERATIONS = 600_000;       // refuse to run weaker than guidance
    static final int MAX_ITERATIONS = 4_000_000;
```

### SEC-04: Audit-log byte cap ignores the pre-existing file length and silently stops logging once reached

- **Severity:** Low
- **CWE:** CWE-779: Logging of Excessive Data / insufficient logging once the cap is hit (see also CWE-400: Uncontrolled Resource Consumption)
- **Location:** `src/main/java/com/example/auth/LogWriter.java:61-73`, `92-93`, `120-136`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LogWriter.java:120-136
    private void write(String candidate) {
        String line = sanitize(candidate);
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        if (written + bytes.length > MAX_TOTAL_BYTES) {
            if (capNotified) {
                return;
            }
            capNotified = true;
            bytes = ("ev=" + Event.AUDIT_CAP_REACHED.text() + "\n").getBytes(StandardCharsets.UTF_8);
            if (written + bytes.length > MAX_TOTAL_BYTES) {
                return;
            }
            emit(bytes);
            return;
        }
        emit(bytes);
    }
```
```java
// src/main/java/com/example/auth/LogWriter.java:92-93
        return new LogWriter(file, Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND));
```

**Why it is a problem:** `written` starts at 0 in every new `LogWriter` while the file is opened in
APPEND mode, so the counter measures only what *this process* appended, not the file's size. The
class Javadoc claims "Total bytes written are capped, so a request flood cannot be turned into disk
exhaustion", and that property does not hold: this CLI runs one authentication per process, so the
cap essentially never engages and the audit file grows without bound across runs (there is no
rotation either). Conversely, in the long-lived/embedded use the class is written for, the first
process to reach 4 MiB stops recording security events entirely — `LOGIN_DENIED`,
`LOGIN_THROTTLED`, `DB_ROW_REJECTED`, `SESSION_ISSUED` — after a single `audit_cap_reached` line,
and authentication keeps succeeding unaudited. Either way the bound is not the control it is
documented to be, and an attacker who can generate failures chooses which half they get.

**Fix:** Seed `written` from the file's actual length on open so the cap bounds the file rather than
the process, and roll the file over at the cap instead of going silent, so the audit trail stays
both bounded and complete.

```java
// LogWriter.open(...)
        DbPathGuard.requirePrivateRegularFile(file);
        long existing = Files.size(file);
        if (existing >= MAX_TOTAL_BYTES) {
            // Bounded *and* complete: retire the full file (owner-only) and start a fresh one
            // rather than silently dropping security events.
            Path rolled = file.resolveSibling(file.getFileName() + "." + System.currentTimeMillis());
            Files.move(file, rolled);
            DbFiles.hardenToOwnerOnly(rolled);
            DbFiles.newPrivateFile(file).close();
            DbPathGuard.requirePrivateRegularFile(file);
            existing = 0L;
        }
        LogWriter w = new LogWriter(file, Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND));
        w.written = existing;
        return w;
```

### SEC-05: Account addresses stored as unsalted SHA-256, allowing offline recovery from a store dump

- **Severity:** Low
- **CWE:** CWE-759: Use of a One-Way Hash without a Salt
- **Location:** `src/main/java/com/example/auth/AuthService.java:182-185`, stored at `src/main/java/com/example/auth/Database.java:259-265`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:182-185
    /** SHA-256 of the normalised address; the only form of the address ever sent to the database. */
    static String identityHash(String normalisedEmail) {
        return CryptoUtils.toHex(CryptoUtils.sha256(PasswordHasher.utf8(normalisedEmail)));
    }
```

**Why it is a problem:** `email_hash` must be deterministic to support lookup, but an unkeyed,
unsalted, single-round SHA-256 of a low-entropy value offers no resistance to a dictionary attack:
anyone who obtains the `.mv.db` file (or the throttle table, whose `i:` keys are the same hashes)
can confirm whether any candidate address has an account at billions of guesses per second, which
turns a file read into a full subscriber list. The same hashes also key the throttle rows, so the
leak extends to who has been attacked recently. `THREAT-MODEL.md` lists this as a deliberate
data-minimisation trade-off; it is reported because the protection it implies ("no cleartext address
in the DB") is weaker in practice than it reads.

**Fix:** Use a keyed hash — HMAC-SHA-256 under a pepper loaded from configuration (the same place the
DB credential comes from) — so the mapping cannot be recomputed without the key. Document that
losing the pepper orphans the accounts, and keep the pepper out of the database file.

```java
    /** HMAC-SHA-256 of the normalised address under the configured pepper. */
    static String identityHash(String normalisedEmail, byte[] pepper) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(pepper, "HmacSHA256"));
            return CryptoUtils.toHex(mac.doFinal(PasswordHasher.utf8(normalisedEmail)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("hmac_unavailable", e);
        }
    }
```

### SEC-06: Only the immediate parent directory of the store is permission-checked; ancestors are not

- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/auth/DbPathGuard.java:78-89`, used by `src/main/java/com/example/auth/Database.java:72` and `src/main/java/com/example/auth/LogWriter.java:84`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/DbPathGuard.java:82-89
    static Path verifiedParentDirectory(String canonicalDbPath) throws IOException {
        Path parent = Path.of(canonicalDbPath).getParent();
        if (parent == null) {
            throw new IOException("db_parent_missing");
        }
        requirePrivateDirectory(parent);
        return parent;
    }
```

**Why it is a problem:** The guard proves that the leaf directory holding the credential store and
audit log is a non-symlink, owner-only directory, but says nothing about the path above it. If any
ancestor is world-writable without the sticky bit (`/var/tmp/shared/`, a mis-created
`/opt/app/`), another local account can rename the verified directory aside and substitute its own
0700 directory — the leaf then passes every check — or can swap an ancestor for a symlink. The
substituted store is where `AccountSeeder` writes and `findAccount` reads, so the attacker chooses
which credentials the program believes in; the substituted audit directory loses the trail. Mode
0600/0700 on the leaf is not sufficient when the path to it is writable; this is the standard
reason path checks must walk to the root.

**Fix:** Walk every component from the root and require that no ancestor is a symlink and that any
world- or group-writable ancestor at least carries the sticky bit.

```java
    static Path verifiedParentDirectory(String canonicalDbPath) throws IOException {
        Path parent = Path.of(canonicalDbPath).getParent();
        if (parent == null) {
            throw new IOException("db_parent_missing");
        }
        // A writable ancestor lets another account swap the directory we just verified.
        for (Path a = parent.getParent(); a != null; a = a.getParent()) {
            if (Files.isSymbolicLink(a)) {
                throw new IOException("ancestor_is_symlink");
            }
            Set<PosixFilePermission> m = Files.getPosixFilePermissions(a, LinkOption.NOFOLLOW_LINKS);
            boolean foreignWrite = m.contains(PosixFilePermission.OTHERS_WRITE)
                    || m.contains(PosixFilePermission.GROUP_WRITE);
            if (foreignWrite && !Boolean.TRUE.equals(
                    Files.getAttribute(a, "unix:sticky", LinkOption.NOFOLLOW_LINKS))) {
                throw new IOException("ancestor_writable_by_others");
            }
        }
        requirePrivateDirectory(parent);
        return parent;
    }
```

### SEC-07: Successful logins consume per-source budget that is never refunded, enabling self-inflicted lockout

- **Severity:** Low
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/example/auth/AuthService.java:272-291` (refund at 280-283), reservation at `src/main/java/com/example/auth/AuthService.java:130-135`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:280-283
        try {
            throttles.refund(ThrottleStore.identityBudget(identityHash,
                    config.identityMaxFailures(), config.identityWindowSec()), clock.epochMillis());
            log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
```

**Why it is a problem:** `authenticate` reserves a slot on *both* budgets before the credential is
read (`attemptBudgets` returns the identity budget and the source budget), but `grant` refunds only
the identity budget. `ThrottleStore`'s own Javadoc states the opposite — "a *successful* login
refunds its own account budget and consumes no source slot … Only failed and refused attempts are
charged" — and the documented rationale is precisely that charging successes turns the limiter into
a denial-of-service tool. As written, 120 successful logins (the default `AUTH_SOURCE_MAX_ATTEMPTS`)
within a 15-minute window exhaust the shared source budget and every subsequent attempt from that
source is refused with the generic failure message, regardless of correct credentials. Because the
source label is shared by all users of a deployment, legitimate traffic alone can produce the
lockout, and an attacker holding one valid credential can produce it deliberately with
authentications that never look like failures.

**Fix:** Refund the source budget on a successful authentication too, so the behaviour matches the
documented design and successes are not charged.

```java
    private String grant(long identityId, String identityHash, String masked) {
        String token;
        try {
            token = sessions.issue(identityId, config.sessionTtlSec(), config.sourceId());
        } catch (Database.StorageException e) {
            logDbFailure(e);
            return null;
        }
        try {
            // Only failed and refused attempts are charged: give back both slots this attempt took.
            throttles.refund(ThrottleStore.identityBudget(identityHash,
                    config.identityMaxFailures(), config.identityWindowSec()), clock.epochMillis());
            throttles.refund(ThrottleStore.sourceBudget(config.sourceId(),
                    config.sourceMaxAttempts(), config.sourceWindowSec()), clock.epochMillis());
            log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
        } catch (Database.StorageException e) {
            logDbFailure(e);
        }
        log.log(LogWriter.Event.SESSION_ISSUED, masked, 0);
        return token;
    }
```

### SEC-08: Engine-file hardening sweep misses sibling engine files such as `.lock.db` / `.trace.db`

- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/auth/Database.java:178-199` (prefix at 183, match at 187)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Database.java:183-187
        String prefix = dbFile.getFileName().toString();
        try (var stream = Files.newDirectoryStream(parent)) {
            for (Path p : stream) {
                String name = p.getFileName().toString();
                if (name.startsWith(prefix) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
```

**Why it is a problem:** `dbFile` is `<dbPath>.mv.db` (`Database.java:70`), so `prefix` is
`"<name>.mv.db"`. The sweep therefore covers `<name>.mv.db` and its compaction temporaries, but not
the engine's other siblings, which are `<name>.lock.db`, `<name>.trace.db` and `<name>.newFile`
— none of which start with `.mv.db`. The class Javadoc and `DbFiles`' Javadoc both state that H2
creates these at mode 0644 under the default umask and that the program therefore re-asserts 0600 on
"every file the engine owns in our directory"; it does not. Impact is limited because the parent
directory must pass `requirePrivateDirectory` (no group/other bits), so the files are unreachable
to other accounts anyway — this is a failed defence-in-depth layer rather than a direct exposure —
but the layer is relied on in the documentation and should match it.

**Fix:** Derive the prefix from the database base name rather than from the `.mv.db` file name, so
every engine sibling is matched.

```java
    void hardenEngineFiles() {
        Path parent = dbFile.getParent();
        if (parent == null) {
            return;
        }
        // Match every engine sibling (.mv.db, .lock.db, .trace.db, .newFile), not just .mv.db*.
        String name = dbFile.getFileName().toString();
        String prefix = name.endsWith(".mv.db")
                ? name.substring(0, name.length() - ".mv.db".length())
                : name;
        try (var stream = Files.newDirectoryStream(parent)) {
            for (Path p : stream) {
                String entry = p.getFileName().toString();
                if (entry.startsWith(prefix) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                    try {
                        DbFiles.hardenToOwnerOnly(p);
                    } catch (IOException ignored) {
                        // Best effort; the directory is already owner-only.
                    }
                }
            }
        } catch (IOException ignored) {
            // Startup checks already verified the directory itself.
        }
    }
```

### SEC-09: Advertised cookie `Max-Age` is a constant that ignores the configured session TTL

- **Severity:** Low
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/SessionStore.java:147-153`, rendered at `src/main/java/com/example/auth/Main.java:177-179`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionStore.java:151-153
    static String cookieAttributesFor() {
        return "HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900";
    }
```

**Why it is a problem:** The attribute string is the contract this component hands a future HTTP
front end ("these values are not optional if one is added"), and `Main.java:177-179` prints it next
to the real `config.sessionTtlSec()`. `AUTH_SESSION_TTL_SEC` is configurable from 60 to 86,400
seconds, so the hardcoded `Max-Age=900` is wrong for every value other than the default: a front end
that copies it verbatim under a 60-second TTL leaves the client holding a cookie for 15 minutes
after the server row has expired, and under an 86,400-second TTL it truncates sessions to 15
minutes. The server-side check in `verify` (`expires_at_epoch_sec > ?`) means the mismatch cannot
grant access past expiry, which keeps this Low — the defect is that the exported guidance and the
enforced lifetime disagree.

**Fix:** Derive `Max-Age` from the configured TTL so the advertised attributes cannot drift from the
lifetime actually enforced.

```java
    /** The attributes a front end must set when it carries this token in a cookie. */
    static String cookieAttributesFor(int sessionTtlSec) {
        return "HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=" + sessionTtlSec;
    }
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (CWE-89), parameterisation:** every statement carrying a value uses `?` bind
  parameters — `Database.insertAccountLocked` (`Database.java:259-272`),
  `Database.findAccountLocked` (`Database.java:307-311`), all four `SessionStore` statements
  (`SessionStore.java:56-64, 89-93, 123-125, 137-139`), and all five `ThrottleStore` statements
  (`ThrottleStore.java:93-112, 142-149, 164-168, 185-188, 197-199`). No user-supplied text is
  concatenated into any statement; the email never reaches SQL at all, only its hash.
- **SQL identifier injection:** the only interpolated text is a table name validated by
  `InputValidator.requireSqlIdentifier` (`InputValidator.java:253-272`, `^[A-Za-z_][A-Za-z0-9_]{0,29}$`
  plus a 45-word reserved-word denylist) and double-quoted at the use site (`Database.quote`,
  `Database.java:130-132`). The three table names are additionally required to differ
  (`Config.java:128-132`).
- **Second-order injection / untrusted storage:** every column read back is validated before use —
  algorithm allowlist, iteration range, salt and digest lengths, status allowlist, positive ids,
  duplicate-row refusal (`Database.java:322-353`); throttle counters outside the writable range are
  refused (`ThrottleStore.java:129-134`); a malformed row denies and logs instead of being trusted.
- **JDBC URL / H2 option injection (`;INIT=RUNSCRIPT FROM …`):** `requireDbPath`
  (`InputValidator.java:332-356`) rejects `;`, `=`, every character outside printable ASCII,
  relative paths, `..`, non-canonical paths and trailing separators; the URL options are fixed
  literals and `TRACE_LEVEL_FILE=0` / `TRACE_LEVEL_SYSTEM_OUT=0` are set
  (`Database.java:76-81`). Because the validated path must begin with `/`, it cannot be reinterpreted
  as an H2 `mem:`/`tcp:`/`zip:` sub-URL.
- **Hardcoded secrets (CWE-798):** none that would work against a real deployment. There is no
  credential constant; the DB credential comes from `AUTH_DB_PASSWORD` or a hidden prompt
  (`Main.java:101-118`), and the program refuses to start rather than default to an empty one
  (`Main.java:109`, `114-117`). `AuthService.WORK_SAMPLE` (`AuthService.java:67`) is a timing-work
  string never compared or stored; the passwords in `AuthServiceTests.java:43` belong to throwaway
  per-PID scratch stores (`T.java:82-90`).
- **Secrets in argv / logs / errors:** no code path accepts a secret as an argument
  (`Main.run` only accepts `login`/`seed`/`help`); `LogWriter` has no API that takes a password,
  hash, salt or token; every message echoed to the user is a fixed token
  (`Config.ConfigException`, `Database.StorageException`, `InputValidator.ValidationException` all
  carry code strings only). The session token is printed to stderr only when `AUTH_EMIT_SESSION=true`
  (default `false`, `Config.java:162-170`) and never to the log — accepted and documented.
- **Password handling in memory:** the credential lives only in `char[]`, is wiped in `finally` on
  every path (`Main.java:123-125, 185-187, 215-218`), and `PBEKeySpec.clearPassword()` runs even
  when the derivation throws (`PasswordHasher.java:78-80`). The one unavoidable `String` is the JDBC
  credential (`Database.java:86`), which the JDBC contract requires; it is local, never logged and
  never in the URL — a documented CWE-316 residual, not a finding.
- **Password storage:** PBKDF2-HMAC-SHA256, unique 16-byte `SecureRandom` salt per account
  (`PasswordHasher.java:47-49`), 256-bit output, iteration count stored per row and range-checked on
  read and write. Iteration count itself is SEC-03.
- **Constant-time comparison (CWE-208):** digests are compared with a length-folded constant-time
  loop (`CryptoUtils.java:38-48`) and never with `Arrays.equals`/`String.equals`.
- **Randomness (CWE-338):** all tokens and salts come from a single `SecureRandom`
  (`CryptoUtils.java:15, 107-114`); no `Random`, no time-based seed, and the draw length is bounded.
- **Session management:** 256-bit token generated server-side only, never accepted or derived from
  the caller; only SHA-256 of the token is stored (`SessionStore.java:60`); expiry is enforced inside
  the `WHERE` clause (`SessionStore.java:91`); revocation is a single `DELETE` whose affected-row
  count is the answer (`SessionStore.java:126`); a presented token is shape-validated to 64 lowercase
  hex first (`InputValidator.java:234-246`); a session that cannot be recorded denies rather than
  granting (`AuthService.java:160-163`, `SessionStore.java:65-68`).
- **Account enumeration / uniform failure (CWE-203, CWE-204):** one failure string for every reason
  (`Main.java:40-41, 183`), one exit code for every denial, and exactly one PBKDF2 derivation on
  every path including unknown address, throttled, malformed email, malformed password and storage
  failure (`AuthService.java:143-177, 217-238, 252-266`), keyed by a domain-separated blind salt
  (`PasswordHasher.java:91-94`). Wall-clock duration is floored at `AUTH_MIN_LOGIN_MS`
  (`AuthService.java:302-324`). Budget rows are written for unknown addresses too, so the write
  pattern does not disclose existence either. Reason codes exist only in the audit log.
- **Fail-closed behaviour (CWE-636):** `authenticate` initialises `outcome = DENIED`
  (`AuthService.java:121`) and no `catch` block can reach `GRANTED`; a throttle-store failure refuses
  the attempt rather than allowing it (`AuthService.java:136-146`); `ThrottleStore` rolls back and
  refuses on any engine error (`ThrottleStore.java:237-257`); unknown CLI commands and invalid
  configuration refuse to start (`Main.java:85-98`) with no permissive defaults.
- **Check-then-act races (CWE-367, CWE-366):** the budget reservation is one transaction holding
  `SELECT … FOR UPDATE` on each row, taken in sorted key order to avoid deadlock
  (`ThrottleStore.java:76-87, 93-96`); the refund is one conditional `UPDATE … WHERE used > 0`
  (`ThrottleStore.java:164-168`); seeding relies on the `UNIQUE (email_hash)` constraint rather than
  a read-then-insert (`Database.java:150`, `AccountSeeder.java:283-296`); the generated key is read
  from the inserting statement, not from `MAX(id)` (`Database.java:278-287`); JDBC access is
  serialised on two distinct monitors with a documented no-nesting rule (`Database.java:209-232`).
- **Log injection (CWE-117):** log text comes only from the `Event` enum; reason codes must match
  `[a-z0-9_]{1,40}` or are replaced (`LogWriter.java:106-114`); every rendered line is re-validated
  against a CR/LF-free allowlist and replaced wholesale if it fails (`LogWriter.java:153-170`); the
  email is masked to `a***@domain` and collapses to `*` if it is not a clean validated address
  (`LogWriter.java:177-202`). Emails cannot contain control characters in the first place
  (`InputValidator.java:77-82`).
- **Input validation (CWE-20) at the boundary:** email charset/length/shape with punycode and
  IP-literal refusal (`InputValidator.java:68-163`); password policy rejecting control characters,
  NUL, edge spaces and unpaired surrogates — the last of which `PBEKeySpec` would otherwise fold to
  `?` and make distinct passwords verify alike (`InputValidator.java:177-213`); stdin reads capped at
  4096 bytes with over-long lines refused rather than truncated and strict UTF-8 decoding
  (`Main.java:336-366, 281-288`); a non-UTF-8 console aborts startup rather than authenticating over
  a lossy transport (`Main.java:245-250`). All integer configuration is shape- then range-checked and
  never clamped (`InputValidator.java:294-311`, `Config.java:207-218`).
- **File permissions and symlink handling (CWE-732, CWE-61):** store directory required
  owner-only and non-symlink, audit file created `CREATE_NEW` with 0600 and re-verified after the
  umask (`DbFiles.java:33-70`, `LogWriter.java:79-94`), permissions verified by mode rather than by
  an accessibility probe (correct, since root bypasses mode bits), and all attribute reads use
  `NOFOLLOW_LINKS`. Because the containing directory must grant no group/other access, no other
  account can win a create/chmod TOCTOU in it. Gaps are SEC-06 and SEC-08.
- **Account takeover via seeding:** `seed` refuses an existing address instead of overwriting it,
  detected from the SQL state class rather than the engine's message
  (`AccountSeeder.java:283-315`); there is no change-password or delete-account path.
- **Dependency posture (CWE-494, CWE-1104):** one third-party dependency, pinned at a specific
  version from an official source with `.sha1` and `.sha256` digest files alongside
  (`libs/h2-2.3.232.jar`); no code is downloaded, loaded from a shared or world-writable location, or
  resolved at runtime. Worth noting for the operator: nothing in the reviewed source verifies those
  digests, so verification is a documented manual build step rather than an enforced control.
- **Dangerous APIs:** no `Runtime.exec`, no reflection, no `ObjectInputStream`/`readObject`, no
  deserialization of untrusted data, no XML or template parsing, no network listener, and no HTTP
  layer — so the deserialization, XXE, SSRF, XSS and CSRF classes do not arise in this component.
- **Clock dependence:** a backwards clock step restarts the throttle window rather than extending it
  (`ThrottleStore.java:120-128`) — a local operator who can set the system clock can reset budgets,
  which is inherent to a wall-clock limiter on a machine they control and is noted here rather than
  filed as a finding.
