# Security Review: Java CLI Account/Session Service (`app` package)

## 1. Executive Summary

The component is a Java 17 command-line account, sign-in and session service backed by a single
embedded H2 file database, with Argon2id (Bouncy Castle) password hashing, opaque bearer sessions,
a per-account/per-source throttle, and a fail-closed JSONL audit trail. Reviewed statically
(read-only, nothing executed, built or imported) across 15 production classes, 3 test-only helpers,
4 shell scripts and the dependency lock.

This is unusually careful code: every SQL statement is parameterised, the KDF validates stored cost
parameters *before* deriving, session tokens are 256-bit CSPRNG values persisted only as SHA-256
digests, audit values are escaped and length-bounded, all audit opens refuse symlinks, comparisons
are constant-time, and every refusal path pays one derivation and prints one uniform message. The
classic vulnerability classes that dominate generated code — SQL injection, broken authentication,
log injection, token predictability, path traversal, insecure temp files — were tested for and are
**not** present (§6).

The findings are concentrated in three areas the design does not protect:

1. **Audit evidence is destroyed by design under resource pressure, and the destruction is
   reachable by an unauthenticated local caller.** The registration path writes audit records
   *before* it consults the throttle, so the per-source budget does not bound trail growth; a busy
   local loop fills the 64 MiB budget and the overflow policy is `Files.delete` of the entire trail
   (`AuditLog.java:151`). An attacker can erase every `LOGIN_SUCCESS`, `ACCOUNT_LOCKED` and
   `ADMIN_REVOKE_REQUESTED` ever recorded (SEC-01, High).
2. **The deliberately expensive key derivation runs while the single-connection store monitor is
   held**, serialising every concurrent command behind it — contradicting the invariant stated in
   the code's own comment at `AuthService.java:166-171` (SEC-02, High).
3. **Secret-hygiene and configuration gaps**: a check-then-open race on the database password file
   whose mode check follows symlinks (SEC-03, Medium), credentials copied into immutable `String`s
   that the erasure policy cannot reach (SEC-04, Medium), and an account store written to disk in
   cleartext while the audit trail goes out of its way never to name a user (SEC-05, Medium).

Five further Low findings cover a live bearer token on stdout, an unauthenticated administrative
command, silent carriage-return deletion on the piped input path, silently ignored unknown options,
and exception-type disclosure. No finding yields remote code execution, remote authentication
bypass, or remote data access; the attacker model throughout is a **local process running as the
owning or another unprivileged uid**, which is the model this component states for itself.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/app/Main.java` | CLI entry point, command dispatch, stdin reader | Argument parsing (`--data-dir`, `--help`), exit-code mapping, generic-failure handling, TTY vs piped credential reads, session-token input refusal, `Set-Cookie` emitted on stdout, per-source key derived from the kernel uid |
| `src/main/java/app/Config.java` | Environment/argument configuration, data-directory guarding, password-file read, JDBC URL | 0600/0700 pre-guarding with symlink-component rejection, password-file mode check + read, Argon2 cost bounds, no `CIPHER=` in the JDBC URL |
| `src/main/java/app/Db.java` | Single `Connection` wrapper | `public synchronized <T> T inTransaction(...)` — one process-wide monitor serialising all SQL; rollback on `SQLException`/`AuditException`/`RuntimeException`; `LOCK_TIMEOUT_MILLIS=2000` |
| `src/main/java/app/PasswordHasher.java` | Argon2id encode/verify | PHC string parse, stored-cost validation *before* derivation, `MessageDigest.isEqual` comparison, `weakerThanPolicy` upgrade trigger |
| `src/main/java/app/AuthService.java` | Login orchestration | Uniform refusal wording, timing equalisation (`dummyHash`, `WORK_FILLER`), pre-KDF length guard, derivation inside the store transaction |
| `src/main/java/app/AccountStore.java` | Account registration/lookup | Registration audit written before the throttle gate, `hasher.encode` inside the transaction, duplicate-charging transaction, uniform CREATED/DUPLICATE wording |
| `src/main/java/app/SessionStore.java` | Opaque bearer sessions | 32-byte `SecureRandom` token, only SHA-256 stored, `SELECT ... FOR UPDATE`, 8 h hard expiry, revoke-all-per-account |
| `src/main/java/app/Throttle.java` | Per-account lockout, per-source token bucket | Single atomic `UPDATE` bucket, `FOR UPDATE` guard row, 5 fails/900 s ⇒ 900 s lock, 10 attempts/300 s per source, retention-bounded prune |
| `src/main/java/app/AuditLog.java` | Fail-closed JSONL audit trail | `NOFOLLOW_LINKS` on every open, 0600 create attributes, value escaping and 256-char bounds, 64 MiB budget whose overflow deletes and restarts the trail |
| `src/main/java/app/Gate.java` | Audit facade used by every store | Every record attempt throws on failure (fail-closed ⇒ denial), per-process random salt, 16-hex identifier tags, fixed event vocabulary |
| `src/main/java/app/InputPolicy.java` | Input validation | Email/username/password bounds, control-character and invisible-whitespace rejection, canonicalisation |
| `src/main/java/app/CookiePolicy.java` | Session cookie rendering | `HttpOnly; Secure; SameSite=Strict` unconditional, path restricted by `[A-Za-z0-9/_-]{1,128}` |
| `src/main/java/app/Secrets.java` | Secret holder | `char[]` storage with erasing `close()`, redacted `toString()` |
| `src/main/java/app/Digests.java` | SHA-256 hex helper | Digest of session tokens and source keys |
| `src/main/java/app/Maintenance.java` | Pre-command housekeeping | Sweeps expired sessions and stale throttle state; sweep failure downgraded to a stderr `NOTE` |
| `src/test/java/app/*.java` | 13 test classes plus a bespoke `Harness` | Not shipped; asserts audit fail-closed, schema bounds, source discipline. Custom runner, not JUnit |
| `scripts/run.sh` | Launcher | Auto-rebuilds and auto-runs `get-deps.sh`; runtime classpath is `bin/` + H2 + Bouncy Castle only |
| `scripts/build.sh` | Compiler front end | `-Xlint:all -Werror`; spring-security-crypto excluded from the compile classpath |
| `scripts/get-deps.sh` | Dependency fetcher | Pinned SHA-256 from `deps.lock`, TLS-only fetch, dual-distributor digest match, published SHA-1 for the signed jar, jar-entry and jar-signature checks |
| `scripts/test.sh` | Test driver | Compiles main + test sources, runs each `*Test` standalone |
| `deps.lock` | Dependency manifest | h2-2.5.252, bcprov-jdk18on-1.82 (runtime); spring-security-crypto-6.5.11 + commons-logging-1.3.5 (test only) |
| `README.md` | Threat model and security claims | Nine self-declared residual risks; used as claims to falsify, not as evidence |
| `bin/app/*.class`, `build/test-classes/` | Compiled output | Present in the tree; not executed or inspected as bytecode during this review |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: the driving workflow — establish what each class
  actually does, select the specialised skills below by name, skim each matched `description` before
  applying it, then audit one skill at a time and report only (nothing in the source was modified).
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher` (Argon2id variant,
  PHC parsing, stored-cost validation before derivation, constant-time compare), `Digests`,
  `Secrets`, `SessionStore` token generation/persistence, `Config` cost bounds and `Config.jdbcUrl`
  (SEC-05), and `AuthService`'s timing equalisation (SEC-02).
- `exploiting-sql-injection-vulnerabilities`: applied to every statement in `Db`, `AccountStore`,
  `SessionStore`, `Throttle` and `AuthService` — all values are bound via `?` placeholders; only
  code-supplied predicate fragments (`"email = ?"`) are concatenated. Nothing found (§6).
- `testing-api-authentication-weaknesses`: applied to the login flow — session entropy and storage,
  hard expiry, row locking on redemption, lockout/bucket interaction, uniform wording and timing
  (SEC-02, SEC-07). Note: the "API" here is a stdio command interface, so HTTP-session-specific
  checks (cookie scope, CSRF, fixation) were assessed against `CookiePolicy` and the CLI's absence
  of ambient authority rather than against browser semantics.
- `testing-for-broken-access-control`: applied to the CLI as the authorisation boundary — command
  reachability without credentials, `revoke-sessions` as an administrative action (SEC-07), token
  handling in `verify`/`logout`, and the uid-as-principal throttle keying (verified fail-closed, §6).
- `testing-for-sensitive-data-exposure`: applied to the audit trail's content and integrity
  (SEC-01), the `Set-Cookie` line on stdout (SEC-06), `String` copies of credentials (SEC-04), the
  cleartext account store (SEC-05), and exception disclosure (SEC-10).
- `exploiting-insecure-deserialization`: applied to the input paths of all classes — there is no
  `ObjectInputStream`/`readObject`, no parsing of untrusted JSON/YAML/XML, and the audit trail is
  write-only from the application's perspective, so no deserialization sink exists. Nothing found (§6).

Reviewed against general OWASP Top 10 and CWE knowledge only, with no specialised skill in this
library matching: CLI option handling and expectation violations (SEC-08, SEC-09), the audit-budget
overflow *policy* as an integrity control (SEC-01), check-then-use/symlink races on configuration
files (SEC-03), and the shell scripts' dependency-integrity chain (no finding — see §6).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Audit trail is deleted outright when its byte budget is exhausted, and unauthenticated callers can reach that path | High | CWE-400 | `src/main/java/app/AuditLog.java:151` |
| SEC-02 | Argon2id derivation runs while the store monitor is held, serialising every request | High | CWE-400 | `src/main/java/app/AuthService.java:186` |
| SEC-03 | Password file is validated by path, then opened by path: TOCTOU plus mode check follows symlinks | Medium | CWE-367 | `src/main/java/app/Config.java:194` |
| SEC-04 | Credentials copied into immutable `String`s the erasure policy cannot reach | Medium | CWE-244 | `src/main/java/app/Config.java:128` |
| SEC-05 | Account store written to disk in cleartext; no at-rest encryption | Medium | CWE-312 | `src/main/java/app/Config.java:148` |
| SEC-06 | Live 8-hour bearer token printed to stdout | Low | CWE-532 | `src/main/java/app/Main.java:255` |
| SEC-07 | `revoke-sessions` performs a destructive administrative action with no authentication step | Low | CWE-306 | `src/main/java/app/Main.java:327` |
| SEC-08 | Piped input silently deletes every carriage return before validation | Low | CWE-20 | `src/main/java/app/Main.java:523` |
| SEC-09 | Unknown long options are silently ignored, so a typo silently retargets the data directory | Low | CWE-20 | `src/main/java/app/Main.java:82` |
| SEC-10 | Internal exception class name disclosed on the operator stream | Low | CWE-209 | `src/main/java/app/Main.java:159` |

## 5. Detailed Findings

### SEC-01: Audit trail is deleted outright when its byte budget is exhausted, and unauthenticated callers can reach that path

- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/app/AuditLog.java:151`

**Vulnerable code:**

```java
// src/main/java/app/AuditLog.java:150-151
    private void restartTrail(long retiredBytes) throws IOException, AuditException {
        Files.delete(file);
```

**Why it is a problem:**

`record()` compares the running byte count against `MAX_BYTES` (64 MiB, `AuditLog.java:38`) and, on
overflow, calls `truncateToFit()` (`AuditLog.java:94`, `:138`), which calls `restartTrail()` —
whose first act is to **delete the only copy of the trail** and start a new file. The
`TRAIL_RETURED` marker it then writes proves *that* a cut happened and how many bytes were dropped,
but preserves none of it: every `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCOUNT_LOCKED`,
`REGISTRATION_ACCEPTED` and `ADMIN_REVOKE_REQUESTED` record is gone. The class comment at
`AuditLog.java:131-137` states this consequence explicitly and accepts it, on the reasoning that
refusing instead would turn a full log into a denial of service against sign-in. That reasoning is
sound; the chosen remedy is not — rotation, not deletion, is what keeps both availability *and*
evidence.

The consequence is severe because the overflow path is reachable by a caller with **no credentials
and no rate limit**. `AccountStore.register()` records `REGISTRATION_ATTEMPTED` *before* it asks the
throttle (`AccountStore.java:84-86`, checked at `:87`) and records `REGISTRATION_THROTTLED` when the
budget is spent (`AccountStore.java:88-89`). So after a source's 10 tokens are gone, each further
registration attempt still writes **two** audit records and costs the caller nothing but a process
spawn — the per-source budget bounds account creation and the expensive derivation, but by
construction it cannot bound trail growth. A local loop invoking `register` writes on the order of
300 bytes per iteration with no derivation and no sleep; tens of minutes to a couple of hours of
such a loop is enough to reach 64 MiB and wipe the trail. An attacker who floods the trail
immediately before or during an intrusion therefore destroys the record of their own earlier
activity, using a control that is running exactly as designed — so no integrity alarm, no
fail-closed denial and no anomalous exit code fires. The `NOTE` written to stderr is not a
durable record, and `Maintenance.java:48-49` and `:64-67` show the same pattern of downgrading an
unwritable audit trail to a best-effort message rather than denying.

**Fix:**

Seal the full trail by renaming it instead of deleting it, so overflow rotates segments and nothing
is ever destroyed in this code path; capacity pressure past the retained segment count becomes an
alert for the operator or a forwarder, not an implicit `unlink`.

```java
// src/main/java/app/AuditLog.java — replaces restartTrail(long)
    private static final DateTimeFormatter SEGMENT_STAMP =
        DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private void rotateTrail(long retiredBytes) throws IOException, AuditException {
        String stamp = SEGMENT_STAMP.format(Instant.now());
        Path sealed = file.resolveSibling(file.getFileName() + "." + stamp + "." + retiredBytes);
        if (Files.exists(sealed, LinkOption.NOFOLLOW_LINKS)) {
            // Two rotations in the same second: fail closed rather than overwrite a sealed segment.
            throw new AuditException("the audit segment name is already taken");
        }
        // ATOMIC_MOVE: a reader or shipper sees either the whole old trail or the new empty one.
        // The bytes are never destroyed here, so filling the budget cannot erase evidence.
        Files.move(file, sealed, StandardCopyOption.ATOMIC_MOVE);
        bytes = -1;
        guardFile();                                   // recreates the trail 0600, no symlink
        System.err.println("NOTE the audit log reached its " + MAX_BYTES + " byte budget and was"
            + " sealed as " + sealed.getFileName() + " (" + retiredBytes + " bytes retained)");
        // ... write the TRAIL_RETURED marker, now carrying "sealed_file", sealed.getFileName() ...
    }
```

Then alert when `file.resolveSibling("*")` exceeds a retention budget, ship segments out-of-band,
and never let the writer delete a sealed segment automatically.

### SEC-02: Argon2id derivation runs while the store monitor is held, serialising every request

- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/app/AuthService.java:186`

**Vulnerable code:**

```java
// src/main/java/app/AuthService.java:184-186
            if (account == null) {
                paidForWork[0] = true;
                hasher.verify(password, dummyHash);
```

**Why it is a problem:**

`Db.inTransaction` is declared `public synchronized <T> T inTransaction(SqlBody<T> body)`
(`Db.java:157`): one `Connection`, one monitor, and the whole application's SQL is serialised behind
it. The code knows this — the comment at `AuthService.java:166-171` states that the equalising
derivation must run "after the transaction closes - never inside it - because the store monitor is
held for the whole transaction and a padded derivation there would serialise every concurrent
request behind it". The `equaliseWork()` call at the foot of `attempt()` honours that for the
throttled branch. The three branches that actually check a credential do not: `hasher.verify` runs
inside the lambda at `AuthService.java:186` (unknown identity), `:198` (locked account) and `:206`
(credential mismatch), and `AccountStore.register` holds the monitor across a full `encode` too
(`AccountStore.java:94`).

Every sign-in attempt therefore blocks `register`, `verify`, `logout`, `revoke-sessions` and the
maintenance sweep for the duration of one memory-hard derivation. At the shipped default
(`m=65536 KiB`, `t=5`, `p=2`) that is tens of milliseconds per attempt; both are operator-tunable
upward via the environment within `PasswordHasher.STORED_*` bounds (to 1 GiB and 20 iterations), so
the block can be seconds. The per-source budget (10 attempts / 300 s) does not save availability:
it is keyed on the effective uid (`Main.java:409-412`), so each additional local uid buys another
10 attempts, and the *registration* branch can be invoked unbounded times as described in SEC-01 —
each of those spawns does DB work under the monitor. Availability is the only thing at stake (no
authentication decision changes), but for a service whose sign-in path is its primary function,
"a handful of concurrent local attempts stall every command" is a High-rated defect, and it is
already conceded by the code's own comment.

**Fix:**

For the two `dummyHash` branches the derivation cannot influence the outcome, so the minimal correct
change is to stop paying for it inside the transaction and let the existing tail equaliser pay it
outside the lock. For the mismatch branch, split the flow: read the row and guard state under a
short transaction, derive with no lock held, then charge the strike under a second short transaction
— the same shape `AccountStore.upgradePasswordHash` already uses, deriving at `AccountStore.java:206`
before opening the transaction at `:209`.

```java
// src/main/java/app/AuthService.java — attempt(), refusal branches
            if (account == null) {
                // No comparison is possible, so nothing here may cost a derivation while the store
                // monitor is held. The tail of attempt() pays the equalising derivation instead.
                gate.record(AuditLog.Event.LOGIN_FAILURE, "reason", "no such account",
                    "source", gate.sourceTag(sourceId),
                    "identity", identity.byEmail() ? gate.emailTag(identity.value())
                        : gate.usernameTag(identity.value()));
                outcome[0] = invalid();
                return Boolean.FALSE;                      // paidForWork[0] stays false
            }

            Throttle.AccountGuard guard = throttle.lockAccountGuard(connection, account.id());
            if (guard.isBlocked(clock.instant().getEpochSecond())) {
                gate.record(AuditLog.Event.LOGIN_THROTTLED_ACCOUNT, "account", gate.accountTag(account.id()),
                    "source", gate.sourceTag(sourceId));
                outcome[0] = throttled();
                return Boolean.FALSE;                      // paidForWork[0] stays false
            }
            stashForVerification(connection, account, guard, password);  // copy the PHC string out
            return Boolean.TRUE;                           // verification + strike charge run after
```

```java
// src/main/java/app/AuthService.java — after inTransaction returns, no lock held
        Pending pending = pendingVerification;             // captured row + guard snapshot
        if (pending != null) {
            boolean matched = hasher.verify(password, pending.account().passwordHash());
            outcome[0] = matched
                ? completeSignIn(pending)                  // short transaction: clear, issue, record
                : refuseWithStrike(pending);               // short transaction: charge, record
        }
        if (!paidForWork[0]) {
            equaliseWork();                                // already outside the monitor
        }
```

Apply the same split to `AccountStore.register` (derive before `db.inTransaction`, as
`upgradePasswordHash` does) so the insert and its audit record stay atomic without the derivation
occupying the monitor.

### SEC-03: Password file is validated by path, then opened by path: TOCTOU plus mode check follows symlinks

- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/app/Config.java:194`

**Vulnerable code:**

```java
// src/main/java/app/Config.java:193-202
        Path path = Path.of(file).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " must name a regular file that is not a symlink");
        }
        if (hasGroupOrOtherAccess(path)) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " must not be readable by group or other");
        }
        byte[] raw = new byte[PASSWORD_MAX_BYTES + 1];
        int read;
        try (java.io.InputStream in = Files.newInputStream(path)) {
```

**Why it is a problem:**

Three separate path-based operations are performed on a file that supplies the database credential:
an `isRegularFile` check with `NOFOLLOW_LINKS` (`:194`), a permission check (`:197`), and the open
(`:202`). The open does **not** pass `LinkOption.NOFOLLOW_LINKS`, and the permission check cannot
see a symlink either, because `permissions()` calls `Files.getPosixFilePermissions(path)` without
`NOFOLLOW_LINKS` (`Config.java:385`) and therefore reports the *target's* mode. Between the checks
and the open there is an unrestricted window in which anyone able to create or rename entries in
the directory holding the password file can swap the path for a symlink to a file of their choosing
whose own mode is 0600 — a target the mode check would happily bless. The application then reads the
first line of that file as its database credential, so the attacker controls what the process
believes its own secret is: at minimum a reliable denial of service (the store cannot be opened),
and a read of an unintended file's first line into the process.

Two things make this a real gap rather than a theoretical one. First, the password file lives
*outside* the data directory, so `rejectSymlinkComponents` (`Config.java:373-380`) and
`ensurePrivateDirectory` do not cover it. Second, the codebase already documents and implements the
correct pattern elsewhere: `AuditLog.append` passes `NOFOLLOW_LINKS` to the open itself precisely
because "the kernel - and not a check that completed a few instructions earlier - is what refuses a
trail that was swapped for a link" (`AuditLog.java:175-183`), and `AuditLog.guardFile` reads
attributes with `NOFOLLOW_LINKS`. The password file is the one place the rule is not applied.

**Fix:**

Open once, refuse symlinks at the open, and validate the mode of the descriptor you actually hold —
`FileChannel.getPosixFilePermissions()` is an `fstat` on the open file, so there is no window left.

```java
// src/main/java/app/Config.java — readDbPassword(), replaces the check-then-open sequence
        Path path = Path.of(file).toAbsolutePath().normalize();
        byte[] raw = new byte[PASSWORD_MAX_BYTES + 1];
        int read;
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(
                path, EnumSet.of(StandardOpenOption.READ), LinkOption.NOFOLLOW_LINKS)) {
            Set<PosixFilePermission> mode = channel.getPosixFilePermissions();  // fstat, not stat
            if (mode.contains(PosixFilePermission.GROUP_READ)
                || mode.contains(PosixFilePermission.OTHERS_READ)
                || mode.contains(PosixFilePermission.GROUP_WRITE)
                || mode.contains(PosixFilePermission.OTHERS_WRITE)) {
                throw new ConfigException(ENV_DB_PASSWORD_FILE + " must not be readable or writable by group or other");
            }
            ByteBuffer buffer = ByteBuffer.wrap(raw);
            int total = 0;
            for (int n; total < raw.length && (n = channel.read(buffer)) > 0; ) {
                total += n;
            }
            if (total == raw.length) {                     // one byte too many means oversized
                throw new ConfigException(ENV_DB_PASSWORD_FILE + " is too large to be a password file");
            }
            read = total;
        } catch (IOException | UnsupportedOperationException unreadable) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " could not be read");
        }
        // ... existing CRLF trim, UTF-8 decode, minimum-length rule and zeroing of raw unchanged ...
```

`permissions()`/`hasGroupOrOtherAccess` should likewise take `NOFOLLOW_LINKS` for every remaining
call site, or be replaced by the descriptor form above.

### SEC-04: Credentials copied into immutable `String`s the erasure policy cannot reach

- **Severity:** Medium
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Improper Erasure')
- **Location:** `src/main/java/app/Config.java:128`

**Vulnerable code:**

```java
// src/main/java/app/Config.java:126-128
        Properties props = new Properties();
        props.setProperty("user", "app");
        props.setProperty("password", new String(dbPassword.chars()));
```

**Why it is a problem:**

`Secrets` exists so that a credential can be overwritten once used, and `retireDatabasePassword()`
(`Config.java:135`, called as soon as the connection exists) does erase the held `char[]`. But the
credential is reachable in at least three immutable `String` copies that `close()` cannot touch:
the `Properties` value above; the `String` returned by `System.getenv(...)` or built by
`new String(raw, 0, length, UTF_8)` at `Config.java:217`, which `Secrets.ofString` then duplicates
via `toCharArray()` while leaving the original intact; and, on the piped/redirected input path, the
user's own password — `Reader.readCapped` does `String decoded = new String(exact, UTF_8)`
(`Main.java:542`) and returns `decoded.toCharArray()` (`Main.java:547`), so the careful
`Arrays.fill(exact, (byte) 0)` at `Main.java:543` erases a copy that is no longer the only copy.
`Main.java:377` does the same to a live session token. The stated purpose of the erasure discipline
— that a later core dump, hibernation image, or heap-scraping process in the same uid cannot recover
the credential — is therefore not met for the database password or for any credential supplied over
a pipe; only the `console.readPassword()` TTY path is clean. `Secrets`' own comment and README
residual risk #2 acknowledge the JDBC `Properties` hand-off as unavoidable; the piped-input and
token copies are not, and are fixable at no cost.

**Fix:**

Decode straight into a `char[]` and erase the decode buffer, so the piped path leaves no `String`
behind; erase the token buffer as soon as it is digested. For the JDBC hand-off, record the residual
risk explicitly and reduce its value by shortening credential lifetime and encrypting the store
(SEC-05).

```java
// src/main/java/app/Main.java — Reader.readCapped(), tail of the method
            byte[] exact = Arrays.copyOf(buffer, length);
            Arrays.fill(buffer, (byte) 0);
            CharBuffer decoded = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(exact, 0, length));
            char[] result = new char[decoded.length()];
            decoded.get(result);
            if (decoded.array() != null) {
                Arrays.fill(decoded.array(), 0, decoded.capacity(), '\0');   // no String ever exists
            }
            Arrays.fill(exact, (byte) 0);
            if (echoNewline) {
                promptStream.println();
            }
            return result;
```

```java
// src/main/java/app/Main.java — sessionHandleFrom(): validate in place, no String copy
        char[] entered = reader.readSecret("Session handle: ");
        try {
            for (char c : entered) {                       // shape check on the char[] itself
                if (c > ' ' && c <= '~') {
                    continue;
                }
                return null;                               // refuse without materialising a String
            }
            return sessionStore.consumeAsCharSink(entered); // hash the char[] directly, then close()
        } finally {
            Arrays.fill(entered, '\0');
        }
```

### SEC-05: Account store written to disk in cleartext; no at-rest encryption

- **Severity:** Medium
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **Location:** `src/main/java/app/Config.java:148`

**Vulnerable code:**

```java
// src/main/java/app/Config.java:147-148
    public String jdbcUrl() {
        return "jdbc:h2:file:" + dbBase + DB_OPTIONS;
```

**Why it is a problem:**

`DB_OPTIONS` (`Config.java:70-71`) sets `DB_CLOSE_ON_EXIT`, `AUTO_SERVER` and `TRACE_LEVEL_FILE` but
carries no `CIPHER=`, so `accounts.mv.db` is a plaintext H2 file containing every account's e-mail
address, username, Argon2id hash and cost parameters, the session digest table and the throttle
state. Confidentiality of all of that rests solely on the 0600 file mode and the directory guards —
which defend against a *different* uid reading a live filesystem, and do nothing about the ordinary
ways a file escapes: a backup, a VM or volume snapshot, a rsync/scp copy, a container image layer,
or a sync folder. Whoever holds the file obtains the entire user roster in plaintext and every
credential for **offline** cracking, with no lockout, no throttle and no audit trail to notice it —
the exact opposite of the properties the online path works to guarantee. The database passphrase
does not help here: it gates live access to the database, not readability of the file's contents.
The design is internally inconsistent on this point: the audit trail deliberately refuses to record
a plaintext identifier, using per-process salted tags (`Gate`) so that trail theft reveals nothing,
while the store keeps the identifiers themselves unencrypted a few centimetres away.

**Fix:**

Enable H2's full-database cipher and bind the file key to a secret that is *not* stored beside the
data file, or delegate confidentiality to an encrypted volume and say so in the threat model.

```java
// src/main/java/app/Config.java
    private static final String DB_OPTIONS = ";DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=FALSE"
        + ";TRACE_LEVEL_FILE=0;CIPHER=AES";

    public Db openDatabase() throws AppConfiguredException {
        Properties props = new Properties();
        props.setProperty("user", "app");
        // H2 full-cipher convention: "<file-key> <user-password>", space separated. The file key
        // comes from its own 0400 file (or the encrypted volume's key), never from this directory,
        // so stealing accounts.mv.db yields ciphertext rather than a crackable hash set.
        props.setProperty("password", databaseFileKey() + " " + new String(dbPassword.chars()));
        // ...
    }
```

If H2's native cipher is not acceptable, provision the data directory on an encrypted volume and
record that dependency as a named control in the README — but do not leave the assumption implicit.

### SEC-06: Live 8-hour bearer token printed to stdout

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/app/Main.java:255`

**Vulnerable code:**

```java
// src/main/java/app/Main.java:253-255
            String cookie = CookiePolicy.sessionCookie(result.session().token(),
                result.session().expiresAt(), java.time.Instant.now().getEpochSecond(), "/");
            out.println("Set-Cookie: " + cookie);
```

**Why it is a problem:**

On success the command writes the raw session token to stdout. For a CGI-style front-end that is the
intended hand-off, but stdout is also where this command prints human-readable status text, it
carries none of the protections the code applies everywhere else (no 0600 guarantee, no
`NOFOLLOW_LINKS`, no redaction), and the operator usually controls what it is attached to: a log
redirect, a `tee`, a CI transcript, a terminal recording. Anyone able to read that capture holds a
bearer credential valid for the full 8 hours, with no way to detect the exposure and no way for the
operator to opt out. The asymmetry is what makes this worth reporting: `sessionHandleFrom` refuses to
accept a token in argv specifically because "arguments are visible in other users' process listings"
(`Main.java:363-367`), yet the token's *output* side has no equivalent control at all.

**Fix:**

Emit the cookie only when the caller explicitly asks for it, on a channel the caller has chosen, and
say so in the usage text.

```java
// src/main/java/app/Main.java — login()
            if (emitCookie) {                              // requires --emit-cookie (see SEC-09 allowlist)
                String cookie = CookiePolicy.sessionCookie(result.session().token(),
                    result.session().expiresAt(), java.time.Instant.now().getEpochSecond(), "/");
                out.println("Set-Cookie: " + cookie);      // documented: stdout becomes credential-bearing
            } else {
                out.println("Sign-in complete. Re-run with --emit-cookie to print the session cookie.");
            }
```

A stronger variant writes the header to a caller-provided descriptor or a 0600 file created with
`NOFOLLOW_LINKS`, keeping ordinary stdout credential-free.

### SEC-07: `revoke-sessions` performs a destructive administrative action with no authentication step

- **Severity:** Low
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `src/main/java/app/Main.java:327`

**Vulnerable code:**

```java
// src/main/java/app/Main.java:326-327
            AccountStore.Account account = accounts.findByUsername(username);
            int revoked = account == null ? 0 : sessions.revokeAllForAccount(account.id());
```

**Why it is a problem:**

`revoke-sessions` ends every live session of any named account, and the only precondition is being
able to execute the binary as the owning uid — there is no confirmation, no separate privilege, no
opt-in flag. Any local process running as that uid (a compromised helper, a cron job, a build step,
or simply a mistyped command) can log out every user at will, and can do so repeatedly. Within this
component's identity model that is *by design* — the effective uid is the only principal the design
recognises, which is why the throttle is keyed on it and why `Gate`'s salt is per-process — and the
command is at least enumeration-safe (identical wording on every path) and audited
(`ADMIN_REVOKE_REQUESTED` at `Main.java:330`). It is still a missing authentication step on a
destructive administrative function, and README residual risk #4 concedes it. Impact is confined to
availability: no session is disclosed and no data is read.

**Fix:**

Require a control the operator has and an automated local process does not — an interactive
terminal — plus an explicit confirmation that names the target, so accidental and scripted mass
sign-out both need deliberate human action.

```java
// src/main/java/app/Main.java — revokeSessions(), before the lookup
        java.io.Console console = System.console();
        if (console == null) {
            // No interactive terminal: this is a script, not the operator. Administrative actions
            // require a human in the loop because the uid is not an identity.
            recordQuietly(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT, "non-interactive");
            err.println("revoke-sessions requires an interactive terminal.");
            return REFUSED;
        }
        if (!"revoke".equals(console.readLine("Type 'revoke' to end every session of %s: ", username))) {
            recordQuietly(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT, "confirmation declined");
            return REFUSED;
        }
```

Document in the README that within a single uid there is no way to distinguish the operator from
another process of that uid, so the control must be out-of-band.

### SEC-08: Piped input silently deletes every carriage return before validation

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/main/java/app/Main.java:523`

**Vulnerable code:**

```java
// src/main/java/app/Main.java:523-525
                if (value == '\r') {
                    continue;
                }
```

**Why it is a problem:**

When stdin is not a TTY, `readCapped` reads bytes one at a time and drops *every* carriage return it
sees, anywhere in the line — not just the CR of a trailing CRLF. A credential piped in from a
CRLF-terminated source (a file written on Windows, a clipboard paste, `printf '%s\r\n'`) is therefore
tested as a different string from the one the caller supplied, and an interior CR silently joins two
halves. This cannot bypass authentication: `InputPolicy.password` rejects control characters at
registration (`InputPolicy.java:159-160`), so a CR-containing credential can never become a validly
*stored* password, and dropping CR can only make the attempted string differ from a valid one. The
exposure is a silent correctness/credential-mutation defect on the failure path: the attempt is
refused as a credential mismatch even though the caller supplied the right secret, which burns one
of the account's five strikes and writes a `LOGIN_FAILURE` record blaming a non-existent attacker.
The deletion is also invisible to the caller — nothing distinguishes it from a wrong password.

**Fix:**

Treat CR as a terminator only when it is immediately followed by LF; otherwise it is data, and must
reach the validator and count against the cap.

```java
// src/main/java/app/Main.java — readCapped(), main loop
            boolean pendingCr = false;
            while ((value = in.read()) >= 0) {
                sawByte = true;
                if (value == '\n') {
                    break;                                 // a pending CR here was the CRLF terminator
                }
                if (pendingCr) {
                    buffer[length++] = (byte) '\r';         // it was not: the CR is data
                    pendingCr = false;
                }
                if (value == '\r') {
                    pendingCr = true;
                    continue;
                }
                if (length >= buffer.length) {
                    /* ... existing drain-and-refuse path, unchanged ... */
                }
                buffer[length++] = (byte) value;
            }
```

### SEC-09: Unknown long options are silently ignored, so a typo silently retargets the data directory

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/main/java/app/Main.java:82`

**Vulnerable code:**

```java
// src/main/java/app/Main.java:81-84
        for (String argument : argv) {
            if (argument.startsWith("--")) {
                continue;
            }
```

**Why it is a problem:**

The dispatch loop discards every token that begins with `--` except the `--help`/`-h` handled earlier,
and the one real option is read separately by `Config.firstOption(argv, "--data-dir")`
(`Config.java:97`). So `--datadir=/srv/app`, `--data-dirx=…`, or a stale flag left in a wrapper script
is accepted with no diagnostic, and the command proceeds against the environment-supplied or default
data directory. The result is that a registration, sign-in or administrative revocation can be
carried out against a *different* account store and audit trail than the operator intended, with an
exit code of 0 and nothing on stderr to indicate the mismatch — the kind of silent fallback that
turns a typo into a misdirected administrative action. Note the neighbouring care: a leftover
`<cookie>` operand is deliberately refused rather than used (`Main.java:363-372`), so the codebase's
own standard is to refuse what it cannot interpret.

**Fix:**

Validate long options against an allowlist and fail with `BAD_USAGE` on anything unrecognised, so a
misspelled `--data-dir` cannot quietly change which store the command acts on.

```java
// src/main/java/app/Main.java
    private static final Set<String> LONG_OPTIONS = Set.of("--help", "--data-dir", "--emit-cookie");

        for (String argument : argv) {
            if (argument.startsWith("--")) {
                String key = argument.contains("=") ? argument.substring(0, argument.indexOf('=')) : argument;
                if (!LONG_OPTIONS.contains(key)) {
                    err.println("Unknown option: " + key);   // never silently fall back to a default store
                    err.print(USAGE);
                    return BAD_USAGE;
                }
                continue;
            }
            // ... existing command/operand collection, unchanged ...
```

### SEC-10: Internal exception class name disclosed on the operator stream

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/app/Main.java:159`

**Vulnerable code:**

```java
// src/main/java/app/Main.java:158-159
            err.println(AuthService.INTERNAL_MESSAGE);
            err.println("NOTE unexpected failure of type " + crash.getClass().getName());
```

**Why it is a problem:**

The top-level `catch (RuntimeException crash)` deliberately suppresses the stack trace — a good
decision, since a trace names absolute paths, the dependency layout and anything a message
interpolated — but then prints the exception's fully qualified class name. That still discloses the
internal and third-party type taxonomy to whoever sees stderr: `org.h2.jdbc.JdbcSQLNonTransientException`
versus `java.lang.NullPointerException` versus `app.AuditLog$AuditException` tells an observer which
subsystem faulted, which library versions are in play, and where to aim follow-up probing. It is a
small leak, and README residual risk #7 records it as an accepted operator-ergonomics trade-off; it
is reported because stderr is typically captured alongside stdout by the same front-end that SEC-06
warns about, so the "operator's own terminal" assumption in the surrounding comment does not hold for
the deployment's actual log routing. No message text, cause chain or path is leaked, and access is
refused rather than granted.

**Fix:**

Keep the user-visible line generic and move the diagnostic into the audit trail's bounded tag
namespace, which is 0600, escaped and length-limited — and never put the raw name on the user stream.

```java
// src/main/java/app/Main.java
        } catch (RuntimeException crash) {
            err.println(AuthService.INTERNAL_MESSAGE);
            // The class name goes to the owner-only trail as a bounded tag, not to a stream that a
            // front-end may capture with the rest of the response. Digest, not name, so the trail
            // cannot itself fingerprint the dependency layout.
            recordQuietly(AuditLog.Event.UNEXPECTED_FAILURE,
                "site", Digests.sha256Hex(crash.getClass().getName()).substring(0, 16));
            return UNAVAILABLE;
```

## 6. Verified Checks (no finding)

Confirmed present and correct by reading the implementation, not the README:

- **SQL injection (CWE-89): absent.** Every value reaches the database through `?` placeholders in
  `AccountStore`, `SessionStore`, `Throttle` and `AuthService`; the only string concatenation into
  SQL is of code-supplied predicate fragments such as `"email = ?"` (`AccountStore.java:161-166`,
  `AuthService.java:267-282`), never of user data.
- **KDF resource abuse via a database row: absent.** `PasswordHasher.verify` validates the parsed
  memory/iterations/parallelism against `STORED_MIN_*`/`STORED_MAX_*` bounds *before* deriving, so a
  tampered row cannot request an unbounded derivation, and the PHC string is shape-checked first.
- **Pre-KDF oversized input: absent.** `AuthService.java:112` refuses a password longer than
  `InputPolicy.PASSWORD_MAX` before any derivation, so the KDF never sees an attacker-sized buffer;
  `readCapped` counts bytes and is therefore *stricter* than the character limits in `InputPolicy`,
  never looser (a multi-byte secret over 256 bytes is refused outright rather than truncated).
- **Session strength and redemption (CWE-330/CWE-384): absent.** 32 bytes from `SecureRandom`,
  rendered as 64 hex characters, only the SHA-256 digest persisted, redemption under
  `SELECT ... FOR UPDATE` inside the monitor, hard 8-hour expiry enforced in SQL, malformed tokens
  rejected before any query.
- **Log injection (CWE-117): absent.** `AuditLog.escape` bounds every value to 256 characters,
  escapes `"`, `\`, `\n`, `\r`, `\t`, control bytes and `0x7f`, and the event vocabulary is a fixed
  enum — a caller cannot forge or split a trail line.
- **Timing disclosure: mitigated.** Every refusal branch pays exactly one derivation (the
  `dummyHash` path) and prints one of two fixed messages; the throttled branch's derivation runs
  outside the lock, and the lockout counter is self-cleared by a genuine sign-in.
- **Throttle integrity: sound.** The source bucket is consumed by a single atomic `UPDATE`, the
  account guard is read with `SELECT ... FOR UPDATE`, a duplicate registration re-charges the budget
  in its own committed transaction so the expensive path stays bounded, and pruning only removes
  rows outside the retention window with no live state.
- **Source-key spoofing: absent.** The key is a SHA-256 of the effective uid read from
  `/proc/self/status` (`Main.java:409-412`), not of `user.name`, so it resists `-Duser.name` forgery;
  when the uid cannot be determined the code falls back to a single shared bucket
  (`"shared-local"`, `Main.java:443`), which is the fail-closed direction.
- **Symlink exposure on the trail and store: absent.** `AuditLog.append` passes `NOFOLLOW_LINKS` to
  the open itself and deliberately omits `CREATE`; `guardFile` checks for symlink, regularity and
  0600; `Config` pre-guards directories at 0700 and files at 0600 and rejects symlink components in
  the data path. (The same rule is missing only on the password file — SEC-03.)
- **Fail-closed audit: present.** `Gate` makes every record attempt throw, `AuditException` maps to
  denial and exit code `UNAVAILABLE`, and a registration's acceptance record is written inside its
  transaction so no account can exist without a trail. SEC-01 concerns the *overflow policy*, not
  this property.
- **Cookie hardening: complete.** `HttpOnly; Secure; SameSite=Strict` are appended unconditionally
  (`CookiePolicy.java:49`, `:65`) and the path is constrained by `[A-Za-z0-9/_-]{1,128}`, so CR/LF
  cannot be injected into the header.
- **Credential comparison: constant-time** via `MessageDigest.isEqual`, after shape and bounds
  checks, with no short-circuit on prefix equality.
- **Insecure deserialization (CWE-502): not applicable.** No `ObjectInputStream`/`readObject`, no
  parsing of untrusted JSON/YAML/XML anywhere in the main sources.
- **Path traversal / temp files (CWE-22/CWE-377): absent.** All paths derive from configuration plus
  fixed filenames (`audit.log`, `accounts`, marker names); no user-controlled path component is
  resolved, and no temporary file is created.
- **Dependency integrity: strong.** `deps.lock` pins SHA-256 locally as the out-of-band baseline;
  `get-deps.sh` fetches over TLS with a protocol floor, requires the digest to match both Maven
  Central and the secondary distributor, checks the published SHA-1 and jar entries, and verifies
  Bouncy Castle's jar signature; test-only artifacts never reach the runtime classpath built by
  `run.sh`.
- **Registration enumeration: mitigated.** `AccountStore.OUTCOME_MESSAGE` is the single wording for
  `CREATED`, `DUPLICATE` and `THROTTLED`, so the registration endpoint cannot confirm or deny an
  account; `revoke-sessions` likewise answers every path with "Sign-out is complete."
- **Build hygiene:** `build.sh` compiles with `-Xlint:all -Werror`; the test harness never runs as
  part of `run.sh`'s classpath.
