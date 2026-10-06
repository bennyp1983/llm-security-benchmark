# Security Review: Acme Internal Employee Portal Console Authenticator (Java 17)

## 1. Executive Summary

The reviewed component is a dependency-free Java 17 console program (`com.acme.portal`) that
provisions and verifies employee credentials for an internal portal. `provision` reads a
username/password from an attached terminal and writes a salted PBKDF2-HMAC-SHA-256 verifier to a
fixed-path credential file; `login` reads a username/password, re-loads the store under an
inter-process file lock, verifies the password in constant time, and applies per-source and
per-account throttling before printing a single generic `Access granted.` / `Access denied.`
message.

The cryptographic and storage core is genuinely strong: PBKDF2-HMAC-SHA-256 at 600,000 iterations
with a 16-byte `SecureRandom` salt per record, `MessageDigest.isEqual` comparisons, `char[]`
passwords zeroed in `finally`, allowlist parsing of the store with strict size/format bounds,
0600 file modes, symlink and parent-directory permission checks, private temp file plus
`ATOMIC_MOVE` replacement, equal PBKDF2 work for unknown/invalid users via a dummy record, and no
hardcoded usable credentials anywhere in the tree. No authentication bypass, injection,
deserialization, or weak-crypto issue was found.

The weaknesses are concentrated in the brute-force restriction, which is the one security control
the task statement explicitly required. All throttle state lives in process memory
(`LoginGuard`), and `Main.login` terminates the "long-lived verifier" as soon as the console
returns EOF at the username prompt — an action any unauthenticated person at the console can
perform (Ctrl-D). Under the supervised, auto-restarting deployment the README prescribes, that
restart discards the 15-minute source block and all per-account counters, so the restriction can
be reset at will (SEC-01). The same design means parallel instances multiply the allowance, and
the single global "source" counter lets any attempter deny service to the legitimate console
user for 15 minutes even with a correct password (SEC-02). There is also no authentication
logging at all — not even a category for failures — so brute-force attempts and credential-store
tampering leave no trace (SEC-03). The remaining findings are low-severity robustness issues:
check-then-open TOCTOU on file metadata, an unbounded blocklist line read whose `OutOfMemoryError`
escapes the handler, reliance on `System.nanoTime()` having a non-negative origin, validate-before-
canonicalize ordering on usernames, and holding the exclusive inter-process lock across PBKDF2 and
the throttle sleep.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/acme/portal/Main.java` | CLI entry point; `login` loop and `provision` flow | Argument allowlist, `System.console()` requirement, password reading and zeroing, constant-time confirmation compare, inter-process lock usage, generic error output, exception handling/logging, process exit on EOF |
| `src/main/java/com/acme/portal/Authenticator.java` | Authentication decision | Username canonicalization/validation, password length bounds, dummy-record equal-work path, fail-closed `allowed` conjunction, `synchronized` check-then-grant, throttle invocation and sleep |
| `src/main/java/com/acme/portal/LoginGuard.java` | Brute-force restriction | In-memory rolling source-failure window, 15-minute source block, per-account backoff, salted SHA-256 account keys, bounded state, `System.nanoTime()` time source |
| `src/main/java/com/acme/portal/PasswordHasher.java` | Password KDF | `SecureRandom` salt, PBKDF2WithHmacSHA256 at 600k iterations, 256-bit output, `MessageDigest.isEqual` verification, candidate hash zeroing |
| `src/main/java/com/acme/portal/CredentialStore.java` | Credential file parse/write/lock | Fixed absolute path validation, symlink/regular-file/0600 checks, parent-directory write-permission check, bounded allowlist parsing (header, 2 MB, 10k users, 256-byte lines, strict Base64, fixed salt/hash lengths, duplicate rejection), `FileLock`, private temp file + `ATOMIC_MOVE`, defensive array cloning |
| `src/main/java/com/acme/portal/PasswordBlocklist.java` | Weak-password blocklist | Fixed-path 0600/symlink checks, 66 MB size bound, strict `[0-9a-f]{64}` line syntax, 10k–1M entry bounds, unkeyed SHA-256 membership test, buffer zeroing |
| `src/test/java/com/acme/portal/SecurityTests.java` | Self-test harness | Test-only passwords, 0700 temp directory, asserts private mode, unknown/invalid user denial, oversized password denial, source blocking, malformed/unsafe store rejection |
| `build.sh` | Build/test script | `umask 077`, `set -eu`, JDK-only compilation, no downloads or remote code |
| `README.md`, `prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Documentation and generation artefacts | Documented threat model, deployment instructions, residual-risk statements; no secrets present |
| `build/classes/**`, `build/test-classes/**` | Compiled `.class` artefacts | Not reviewed as source; no separate behaviour (compiled output of the above sources) |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove file-by-file behaviour
  enumeration (Step 1), keyword-based library search for password storage, authentication,
  rate limiting, secrets, file handling and concurrency (Step 2), and the per-skill audit below.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java`,
  `PasswordBlocklist.java`, `LoginGuard.key()` and `CredentialStore.Record` — checked for
  deprecated hashes, weak KDF parameters, hardcoded keys/secrets, RNG quality, salt handling,
  and non-constant-time comparison. No finding; parameters meet current OWASP guidance.
- `testing-api-authentication-weaknesses`: applied to `Authenticator.authenticate`,
  `Main.login` and `Main.provision` — checked password policy strength, account enumeration via
  differing messages or work, credential-stuffing resistance, and credential leakage into
  arguments/output. Enumeration and policy checks passed; brute-force resistance produced
  SEC-01/SEC-02.
- `performing-api-rate-limiting-bypass`: applied to `LoginGuard` and `Main.login` — applied the
  identifier-rotation, state-reset and parallel/distributed-client bypass categories to the
  process-local counters, producing SEC-01 and SEC-02.
- `testing-for-sensitive-data-exposure`: applied to `Main`, `CredentialStore.write`,
  `PasswordBlocklist.contains` and the logging paths — checked for secrets in source, secrets in
  arguments/logs/errors, insecure storage modes, and memory hygiene. Verifier storage and memory
  clearing passed; the absence of any security logging produced SEC-03.
- `exploiting-race-condition-vulnerabilities`: applied the TOCTOU model to
  `CredentialStore.load`/`lockForUpdate`/`PasswordBlocklist.load` (metadata validated by path,
  then re-opened by path) and to the verify-then-grant sequence in `Authenticator.authenticate`.
  The verify/grant/count sequence is correctly atomic; the file checks produced SEC-04.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill matched these
  behaviours directly: fail-closed parsing of untrusted file content and resource bounds
  (CWE-400/CWE-789 → SEC-05), time-source assumptions in security decisions (CWE-754 → SEC-06),
  validate-before-canonicalize ordering of the username (CWE-178/CWE-180 → SEC-07), lock-holding
  and availability (CWE-667 → SEC-08), insufficient logging (CWE-778 → SEC-03), and
  OS-command/path-injection and deserialization exposure (none present — no `Runtime.exec`,
  no `ProcessBuilder`, no `ObjectInputStream`, no reflection, no network or SQL use).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Failed-attempt restriction is process-local and resettable by an unauthenticated console EOF | High | CWE-307 | `src/main/java/com/acme/portal/Main.java:60-64` |
| SEC-02 | Single global source counter lets any attempter block the legitimate console for 15 minutes | Medium | CWE-645 | `src/main/java/com/acme/portal/LoginGuard.java:41-54` |
| SEC-03 | No logging of authentication successes, failures, or store-integrity rejections | Medium | CWE-778 | `src/main/java/com/acme/portal/Main.java:44-49` |
| SEC-04 | Credential-store and lock-file safety checks are performed by path, then the file is re-opened by path (TOCTOU) | Low | CWE-367 | `src/main/java/com/acme/portal/CredentialStore.java:111-124` |
| SEC-05 | Unbounded single-line read of the 66 MB blocklist raises `OutOfMemoryError`, which the handler does not catch | Low | CWE-789 | `src/main/java/com/acme/portal/PasswordBlocklist.java:45-52` |
| SEC-06 | Source-block check assumes a non-negative `System.nanoTime()` origin, which can deny all logins | Low | CWE-754 | `src/main/java/com/acme/portal/LoginGuard.java:24-33` |
| SEC-07 | Username length is validated before case canonicalization, so non-ASCII input folds into the allowlist | Low | CWE-180 | `src/main/java/com/acme/portal/Authenticator.java:52-58` |
| SEC-08 | Exclusive inter-process credential lock is held across PBKDF2 and the throttle sleep | Low | CWE-667 | `src/main/java/com/acme/portal/Main.java:70-79` |

## 5. Detailed Findings

### SEC-01: Failed-attempt restriction is process-local and resettable by an unauthenticated console EOF

- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/acme/portal/Main.java:56-64`, `src/main/java/com/acme/portal/LoginGuard.java:12-28`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:56-64
        CredentialStore.load(STORE_PATH);
        Authenticator authenticator = new Authenticator();
        // This is a long-lived verifier. Failed attempts must not restart the process and
        // thereby reset its source/account throttles.
        while (true) {
            String username = console.readLine("Username: ");
            if (username == null) {
                return 1;
            }
```
```java
// src/main/java/com/acme/portal/LoginGuard.java:12-28
/** In-memory limits are deliberately process-local; deployment must prevent parallel instances. */
final class LoginGuard {
    static final int SOURCE_FAILURE_LIMIT = 5;
    static final Duration SOURCE_WINDOW = Duration.ofMinutes(5);
    static final Duration SOURCE_BLOCK = Duration.ofMinutes(15);
    static final int ACCOUNT_BACKOFF_START = 5;
    static final long MAX_ACCOUNT_DELAY_MILLIS = 2_000;
    private static final int MAX_ACCOUNT_STATES = 10_000;

    private final byte[] accountKeySalt = new byte[32];
    private final ArrayDeque<Long> sourceFailures = new ArrayDeque<>();
    private final Map<Key, Integer> accountFailures = new HashMap<>();
    private long sourceBlockedUntil;

    LoginGuard() {
        new SecureRandom().nextBytes(accountKeySalt);
    }
```

**Why it is a problem:** The entire restriction — the rolling five-minute failure window, the
15-minute source block, and every per-account failure counter — exists only in the heap of one
`LoginGuard` instance that is constructed fresh on each `login()` call
(`Authenticator.java:14-21` via `Main.java:57`). Nothing is persisted, so any process restart
restores a clean slate.

The design depends on the process never ending, and the code itself breaks that assumption: at
`Main.java:62-64`, an EOF at the username prompt (`console.readLine` returning `null`) makes
`login` return `1`, and `Main.main` then calls `System.exit(1)`. Pressing Ctrl-D is available to
anyone standing at the console *before* authenticating — it requires no credential and no
service-manager privilege, which is the one precondition the README relies on ("The service
manager must not give employees permission to start, stop, or restart it"). An attacker therefore
runs the restriction to its limit (5 failures), sends EOF to kill the verifier, and the supervised
service manager — which must restart a crashed long-running service for the console to remain
usable — brings it back with `sourceBlockedUntil == 0` and an empty `accountFailures`. The 15-minute
block and the per-account backoff are reduced to a ~1-second-per-guess inconvenience, which for a
password-guessing campaign against a 15-character-minimum password is still a meaningful cost but is
not the control the requirement asks for. Any uncaught `Error` (see SEC-05) and any `IOException`
from a transient store/lock problem (`Main.java:44-49`) produce the same reset. The same property
means N concurrent instances grant 5·N attempts per window, since `synchronized` and the
`LoginGuard` fields are per-JVM while only the credential file lock is shared.

**Fix:** Persist throttle state outside the process so it survives exit, and stop letting an
unauthenticated console action terminate the verifier. Minimal hardening: keep the counters in a
file (or the organization's rate-limit service) in the same 0700 directory, updated under the
existing `UpdateLock` so the record is atomic and shared across instances; and treat EOF as a
failed attempt that re-prompts rather than an exit path, exiting only on an administrative signal.

```java
// src/main/java/com/acme/portal/Main.java — persist throttle state; do not exit on EOF
        CredentialStore.load(STORE_PATH);
        // State is loaded from, and flushed to, a 0600 file in the store directory under the
        // same inter-process UpdateLock, so a restart or a parallel instance cannot reset it.
        Authenticator authenticator = new Authenticator(GuardState.path(STORE_PATH));
        int consecutiveEof = 0;
        while (true) {
            String username = console.readLine("Username: ");
            if (username == null) {
                // EOF is an attempt outcome, not an exit path: count it and keep the process up.
                authenticator.recordAbortedAttempt();
                System.out.println("Access denied.");
                if (++consecutiveEof >= 3) {
                    // The terminal is gone; let the supervisor re-attach rather than spin.
                    return 1;
                }
                continue;
            }
            consecutiveEof = 0;
```
```java
// src/main/java/com/acme/portal/LoginGuard.java — back the counters with shared, durable state
final class LoginGuard {
    // ... limits unchanged ...
    private final GuardState state; // durable, lock-protected: block deadline + per-key counters

    LoginGuard(GuardState state) {
        this.state = state;
    }

    synchronized Decision beforeAttempt(String canonicalUsername) {
        Instant now = Instant.now(Clock.systemUTC());      // persisted deadlines need wall time
        state.reload();                                     // under CredentialStore.UpdateLock
        boolean sourceAllowed = !now.isBefore(state.sourceBlockedUntil());
        int failures = state.failures(key(canonicalUsername));
        long delay = failures < ACCOUNT_BACKOFF_START ? 0L
                : Math.min(MAX_ACCOUNT_DELAY_MILLIS,
                        125L << Math.min(4, failures - ACCOUNT_BACKOFF_START));
        return new Decision(sourceAllowed, delay);
    }

    synchronized void recordFailure(String canonicalUsername) {
        state.mutateAndFlush(key(canonicalUsername));       // atomic write, survives restart
    }
}
```

### SEC-02: Single global source counter lets any attempter block the legitimate console for 15 minutes

- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/acme/portal/LoginGuard.java:41-54`, `src/main/java/com/acme/portal/Authenticator.java:42-43`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/LoginGuard.java:41-54
    synchronized void recordFailure(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        sourceFailures.addLast(now);
        if (sourceFailures.size() >= SOURCE_FAILURE_LIMIT) {
            sourceBlockedUntil = now + SOURCE_BLOCK.toNanos();
            sourceFailures.clear();
        }
        Key key = key(canonicalUsername);
        if (accountFailures.size() >= MAX_ACCOUNT_STATES && !accountFailures.containsKey(key)) {
            // Fail closed for account-spray storage exhaustion; the source limit still expires.
            sourceBlockedUntil = now + SOURCE_BLOCK.toNanos();
            return;
        }
```

**Why it is a problem:** The verifier has exactly one source — the attached console — so the
"per-source" counter is in practice a single global counter, and `sourceBlockedUntil` is a global
deny switch. `Authenticator.java:42` ANDs `decision.sourceAllowed()` into the grant, so once the
block is set, *every* account is denied even with the correct password (the README states this
outcome explicitly). Five deliberately wrong attempts — attributable to no account, since invalid
usernames all map to the `"invalid-input"` bucket at `Authenticator.java:32` and still call
`recordFailure` — put the console out of service for 15 minutes, and the attacker can renew the
block indefinitely with five more attempts each time. The storage-exhaustion branch at lines 50-53
is a second path to the same global block that is reachable by spraying 10,000 distinct valid-format
usernames. The task requirement was specifically that "an attacker cannot use your own limit to
lock a legitimate user out"; the per-account design correctly avoids a hard account lock, but the
source dimension reintroduces exactly that denial of service for every user of that console.

**Fix:** Do not make the source block an unconditional deny for all principals. Keep it as
escalating cost (progressive delay, capped per attempt) and scope hard blocking to the
`(source, account)` pair so a victim who presents a correct password is not punished for another
person's failures, while a guessing campaign still pays an increasing price. The
state-exhaustion branch should evict the oldest entries rather than block the whole console.

```java
// src/main/java/com/acme/portal/LoginGuard.java — escalating cost instead of a global deny
    synchronized void recordFailure(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        sourceFailures.addLast(now);
        Key key = key(canonicalUsername);
        if (accountFailures.size() >= MAX_ACCOUNT_STATES && !accountFailures.containsKey(key)) {
            // Bound the map by evicting the oldest key; never deny every account because the
            // attacker chose to spray fresh usernames.
            evictOldestAccountState();
        }
        accountFailures.merge(key, 1, (oldValue, one) -> Math.min(oldValue + 1, 32));
    }

    synchronized Decision beforeAttempt(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        int sourceFailureCount = sourceFailures.size();
        int accountFailureCount = accountFailures.getOrDefault(key(canonicalUsername), 0);
        // A correct password is still accepted; cost grows with both dimensions.
        long delay = Math.min(MAX_SOURCE_DELAY_MILLIS,
                backoffMillis(sourceFailureCount, SOURCE_FAILURE_LIMIT)
                        + backoffMillis(accountFailureCount, ACCOUNT_BACKOFF_START));
        // Hard denial only for this account from this source, and only while it is being guessed.
        boolean sourceAllowed = accountFailureCount < ACCOUNT_HARD_BLOCK_FAILURES
                || now - accountBlockedUntil(canonicalUsername) >= 0;
        return new Decision(sourceAllowed, delay);
    }
```

### SEC-03: No logging of authentication successes, failures, or store-integrity rejections

- **Severity:** Medium
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/acme/portal/Main.java:44-49`, `src/main/java/com/acme/portal/Main.java:80-85`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:44-49
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // No paths, usernames, credentials, or exception text are emitted.
            LOG.log(Level.SEVERE, "Authentication operation failed internally");
        }
        System.err.println("Unable to process the request securely.");
        return 2;
```
```java
// src/main/java/com/acme/portal/Main.java:80-85
            // All authentication failures, including throttling, have one response.
            System.out.println(allowed ? "Access granted." : "Access denied.");
            if (allowed) {
                return 0;
            }
```

**Why it is a problem:** The program emits no security event record of any kind. There is no log
line for a failed authentication, a successful authentication, activation of the 15-minute source
block, account-state exhaustion, or credential provisioning. The only two log statements are the
`WARNING`/`SEVERE` lines in `run`, and both deliberately discard the exception (the `Throwable`
`e` is never passed to `LOG.log`), so a rejected credential store — malformed content, non-0600
mode, symlink substitution, a lost file lock — is indistinguishable in the logs from a missing
crypto provider. The requirement is that details go to the log while the *user* sees only a
generic message; here the details go nowhere. Consequences: a slow guessing campaign (SEC-01) and
tamper attempts against the store or blocklist produce no detectable signal, and post-incident
investigation has no record of which accounts were targeted or whether a grant ever occurred.
Note that the fix must keep passwords out of the log and must not log the raw username at a level
that makes the log itself an account-enumeration artefact for low-privilege readers.

**Fix:** Log every authentication outcome and every fail-closed rejection at an appropriate level,
with the exception attached for internal errors, to a log sink whose file mode is as restrictive as
the credential store. Keep secrets out: log the canonical username (it is not a secret, and it is
required for triage) but never the password, and log a stable reason code rather than raw file
content.

```java
// src/main/java/com/acme/portal/Main.java — record outcomes and real error detail
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // Detail goes to the (0600) log only; the user still sees the generic message.
            LOG.log(Level.SEVERE, "Authentication operation failed internally", e);
        }
        System.err.println("Unable to process the request securely.");
        return 2;
```
```java
// src/main/java/com/acme/portal/Main.java — one audit record per attempt
            // All authentication failures, including throttling, have one response.
            LOG.log(allowed ? Level.INFO : Level.WARNING,
                    () -> "authentication outcome=" + (allowed ? "granted" : "denied")
                            + " user=" + Authenticator.logSafeUsername(username)
                            + " reason=" + authenticator.lastOutcomeCode());
            System.out.println(allowed ? "Access granted." : "Access denied.");
            if (allowed) {
                return 0;
            }
```

### SEC-04: Credential-store and lock-file safety checks are performed by path, then the file is re-opened by path (TOCTOU)

- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/acme/portal/CredentialStore.java:111-124`, `src/main/java/com/acme/portal/CredentialStore.java:65-76`, `src/main/java/com/acme/portal/PasswordBlocklist.java:34-45`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/CredentialStore.java:111-124
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(path)) {
            throw new IOException("credential store is not a regular, non-symbolic file");
        }
        if (!Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(FILE_PERMISSIONS)) {
            throw new IOException("credential store permissions must be 0600");
        }
        long size = Files.size(path);
        if (size <= 0 || size > MAX_FILE_BYTES) {
            throw new IOException("credential store size is invalid");
        }

        Map<String, Record> parsed = new HashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII)) {
```

**Why it is a problem:** Every safety property (regular file, not a symlink, mode 0600, size
bound) is established against the *path* by three separate `stat` calls, and the file is then
opened by the same path a fourth time without `NOFOLLOW_LINKS`. Between the last check and the
open, anything that can rename or replace the path substitutes a different file — including a
symlink, which `Files.newBufferedReader` will follow — so the verifier can be made to authenticate
against an attacker-chosen credential database, which is precisely the risk the fixed-path design
set out to eliminate. `lockForUpdate` has the same shape (create → check → `FileChannel.open`, where
the open at line 75 does pass `NOFOLLOW_LINKS`, so only the mode/regular-file check is racy), as does
`PasswordBlocklist.load`. Exploitation requires write access to the parent directory; `validateParent`
rejects group- and other-writable parents, so this is limited to the service account itself (or root),
which keeps severity low — but a compromised co-process running as that account turns a
read-only-store assumption into a full authentication bypass.

**Fix:** Open the file once with `O_NOFOLLOW` and validate the metadata of the *open descriptor*,
so check and use refer to the same inode. In Java, open a `FileChannel` with
`LinkOption.NOFOLLOW_LINKS` and read the attributes through that channel's file key / stat rather
than re-resolving the path.

```java
// src/main/java/com/acme/portal/CredentialStore.java — validate the opened descriptor, not the path
        Map<String, Record> parsed = new HashMap<>();
        try (FileChannel channel = FileChannel.open(path,
                EnumSet.of(StandardOpenOption.READ), /* O_NOFOLLOW */ LinkOption.NOFOLLOW_LINKS)) {
            // All checks below describe the inode now held open; the path cannot be swapped
            // between check and use.
            // O_NOFOLLOW above removes the symlink-substitution vector outright. The checks
            // below run after the descriptor exists, and the fileKey (st_dev/st_ino) is
            // re-compared after parsing, so a rename/replace during the read is detected
            // instead of silently accepted.
            PosixFileAttributes before =
                    Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || !before.permissions().equals(FILE_PERMISSIONS)) {
                throw new IOException("credential store is unsafe");
            }
            long size = channel.size();
            if (size <= 0 || size > MAX_FILE_BYTES) {
                throw new IOException("credential store size is invalid");
            }
            try (BufferedReader reader = new BufferedReader(
                    Channels.newReader(channel, StandardCharsets.US_ASCII.newDecoder(), -1))) {
                // ... existing bounded, allowlist parsing unchanged ...
            }
            PosixFileAttributes after =
                    Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.fileKey().equals(after.fileKey())) {
                throw new IOException("credential store was replaced while being read");
            }
        }
```

### SEC-05: Unbounded single-line read of the 66 MB blocklist raises `OutOfMemoryError`, which the handler does not catch

- **Severity:** Low
- **CWE:** CWE-789: Memory Allocation with Excessive Size Value
- **Location:** `src/main/java/com/acme/portal/PasswordBlocklist.java:40-52`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/PasswordBlocklist.java:40-52
        long size = Files.size(PATH);
        if (size <= 0 || size > MAX_BYTES) {
            throw new IOException("password blocklist size is invalid");
        }
        Set<HashValue> values = new HashSet<>();
        try (BufferedReader reader = Files.newBufferedReader(PATH, StandardCharsets.US_ASCII)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (values.size() >= MAX_ENTRIES || !HASH.matcher(line).matches()
                        || !values.add(new HashValue(fromHex(line), false))) {
                    throw new IOException("password blocklist content is invalid");
                }
            }
        }
```

**Why it is a problem:** The total file size is bounded at 66 MB, but no per-line bound exists.
`BufferedReader.readLine()` accumulates until a newline, so a 66 MB file containing no newline
allocates a ~66-million-char `String` (~132 MB of heap plus the intermediate `StringBuilder`
growth) before the `HASH.matcher(line).matches()` check can reject it. On a JVM started with a
modest heap this throws `OutOfMemoryError`, which is an `Error`, not a `RuntimeException`, so it
is not caught by `catch (IOException | GeneralSecurityException | RuntimeException e)` at
`Main.java:44` — it propagates out of `main` and terminates the process. The authors' own threat
model treats this file as attacker-controlled input, and the "fails closed" claim does not hold
for an uncaught `Error`: the process dies rather than reporting the generic message, and that
death is also a throttle reset per SEC-01. `CredentialStore.load` is not affected to the same
degree because its own 2 MB file bound caps the worst-case line. Impact is limited by the 0600
mode and service-account ownership of the blocklist.

**Fix:** Bound each line before materializing it, by reading a fixed number of characters at a
time instead of using `readLine()` on untrusted data (a 64-hex-digit entry plus a newline is at
most 65 characters).

```java
// src/main/java/com/acme/portal/PasswordBlocklist.java — bound every line, not just the file
    private static final int MAX_LINE_CHARS = 64; // one lowercase SHA-256 hex digest

    // ...
        Set<HashValue> values = new HashSet<>();
        try (BufferedReader reader = Files.newBufferedReader(PATH, StandardCharsets.US_ASCII)) {
            char[] buffer = new char[MAX_LINE_CHARS + 2];
            String line;
            while ((line = readBoundedLine(reader, buffer)) != null) {
                if (values.size() >= MAX_ENTRIES || !HASH.matcher(line).matches()
                        || !values.add(new HashValue(fromHex(line), false))) {
                    throw new IOException("password blocklist content is invalid");
                }
            }
        }

    /** Reads at most MAX_LINE_CHARS characters; a longer line is rejected, never buffered. */
    private static String readBoundedLine(BufferedReader reader, char[] buffer) throws IOException {
        int length = 0;
        int c;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                return new String(buffer, 0, length);
            }
            if (length == buffer.length) {
                throw new IOException("password blocklist line is too long");
            }
            buffer[length++] = (char) c;
        }
        return length == 0 ? null : new String(buffer, 0, length);
    }
```

### SEC-06: Source-block check assumes a non-negative `System.nanoTime()` origin, which can deny all logins

- **Severity:** Low
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `src/main/java/com/acme/portal/LoginGuard.java:24`, `src/main/java/com/acme/portal/LoginGuard.java:30-33`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/LoginGuard.java:24,30-33
    private long sourceBlockedUntil;
...
    synchronized Decision beforeAttempt(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        boolean sourceAllowed = now - sourceBlockedUntil >= 0;
```

**Why it is a problem:** `sourceBlockedUntil` defaults to `0`, which is used as the sentinel for
"never blocked", but `0` is also a legitimate value of `System.nanoTime()`. The JDK specifies
only that `nanoTime()` is monotonic with an *arbitrary* origin, and explicitly permits negative
values; some JVM/platform combinations start it negative deliberately to catch exactly this bug.
When `now` is negative, `now - 0 >= 0` is false, so `sourceAllowed` is false on a freshly started
verifier and **every** login — including one with the correct password — is denied until the clock
crosses zero, with no log line (SEC-03) and no distinguishable message to explain it. The delta
arithmetic elsewhere in the class is correctly overflow-safe; the defect is solely the use of a
magic `0` as "unset".

**Fix:** Track the blocked state explicitly rather than encoding it in a timestamp value that the
clock can legitimately produce.

```java
// src/main/java/com/acme/portal/LoginGuard.java — explicit "unset", no magic zero
    private boolean sourceBlocked;
    private long sourceBlockedUntil;

    synchronized Decision beforeAttempt(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        if (sourceBlocked && now - sourceBlockedUntil >= 0) {
            sourceBlocked = false; // the block expired
        }
        boolean sourceAllowed = !sourceBlocked;
```
```java
// src/main/java/com/acme/portal/LoginGuard.java — set both fields together on block
        if (sourceFailures.size() >= SOURCE_FAILURE_LIMIT) {
            sourceBlocked = true;
            sourceBlockedUntil = now + SOURCE_BLOCK.toNanos();
            sourceFailures.clear();
        }
```

### SEC-07: Username length is validated before case canonicalization, so non-ASCII input folds into the allowlist

- **Severity:** Low
- **CWE:** CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
- **Location:** `src/main/java/com/acme/portal/Authenticator.java:52-58`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Authenticator.java:52-58
    static String canonicalUsername(String input) {
        if (input == null || input.length() < 3 || input.length() > 64) {
            return null;
        }
        String canonical = input.toLowerCase(Locale.ROOT);
        return CredentialStore.USERNAME.matcher(canonical).matches() ? canonical : null;
    }
```

**Why it is a problem:** The 3–64 bound is measured on the raw input, but the value that is
actually used as the account key is the post-`toLowerCase` string, and Unicode case folding is not
length-preserving or ASCII-preserving. `U+212A KELVIN SIGN` lowercases to ASCII `k`, so non-ASCII
input passes the `[a-z0-9._-]` allowlist after canonicalization — the README's claim that the
username is "3–64 ASCII characters" does not hold for the pre-canonical input. Likewise
`U+0130` expands to two code units, so a 64-char input can canonicalize to a longer string than
the stated bound. The practical impact is limited: the same canonicalization runs in both
`provision` (`Main.java:89`) and `login`, so the mapping is consistent and no password check is
skipped; the consequences are that visually distinct identifiers collide onto one account (a
spoofing/confusion risk in any audit trail that records the raw input) and that the documented
length contract is not enforced on the value that becomes the key. The fix is cheap, so the
ordering should be corrected.

**Fix:** Canonicalize first, then validate the canonical form — and reject non-ASCII input before
folding, so that case mapping can never introduce an allowlisted character.

```java
// src/main/java/com/acme/portal/Authenticator.java — reject non-ASCII, then canonicalize, then validate
    static String canonicalUsername(String input) {
        if (input == null) {
            return null;
        }
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) > 0x7F) {
                return null; // no non-ASCII code unit may fold into the allowlist
            }
        }
        String canonical = input.toLowerCase(Locale.ROOT);
        if (canonical.length() < 3 || canonical.length() > 64) {
            return null; // the bound is enforced on the value used as the account key
        }
        return CredentialStore.USERNAME.matcher(canonical).matches() ? canonical : null;
    }
```

### SEC-08: Exclusive inter-process credential lock is held across PBKDF2 and the throttle sleep

- **Severity:** Low
- **CWE:** CWE-667: Improper Locking
- **Location:** `src/main/java/com/acme/portal/Main.java:70-79`, `src/main/java/com/acme/portal/Authenticator.java:33-36`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:70-79
            try {
                try (CredentialStore.UpdateLock updateLock =
                        CredentialStore.lockForUpdate(STORE_PATH)) {
                    updateLock.requireHeld();
                    allowed = authenticator.authenticate(
                            CredentialStore.load(STORE_PATH), username, password);
                }
            } finally {
                Arrays.fill(password, '\0');
            }
```
```java
// src/main/java/com/acme/portal/Authenticator.java:33-36
        LoginGuard.Decision decision = guard.beforeAttempt(guardName);
        if (decision.accountDelayMillis() > 0) {
            Thread.sleep(decision.accountDelayMillis());
        }
```

**Why it is a problem:** `lockForUpdate` takes a blocking, exclusive OS file lock
(`channel.lock()` at `CredentialStore.java:78`) and `Main.login` holds it for the whole attempt:
store reload, the deliberately expensive 600,000-iteration PBKDF2 derivation, and the
`Thread.sleep` of up to 2,000 ms that the account backoff imposes. Each failed attempt therefore
occupies the single global lock for roughly one to three seconds. A person at one console who sits
in the `while (true)` loop entering wrong passwords keeps the lock almost continuously held, and
every other verifier instance and every administrative `provision` run blocks indefinitely on
`channel.lock()` with no timeout — so the attacker's own throttle penalty becomes a denial of
service against password resets and other consoles. The throttle delay in particular has no reason
to be inside the critical section: it protects nothing.

**Fix:** Keep the lock around only the operations that must be serialized against a credential
change — reload the store and derive the candidate hash under the lock — and move the throttling
delay outside it. Use a bounded lock acquisition so a stuck holder surfaces as the generic error
instead of an indefinite hang.

```java
// src/main/java/com/acme/portal/Main.java — delay outside the lock; lock only the reload+verify
            boolean allowed;
            try {
                // Throttling cost is paid before the global lock is taken, so a guessing
                // session cannot starve provisioning or other consoles.
                authenticator.awaitThrottleDelay(username);
                try (CredentialStore.UpdateLock updateLock =
                        CredentialStore.lockForUpdate(STORE_PATH)) {
                    updateLock.requireHeld();
                    allowed = authenticator.authenticate(
                            CredentialStore.load(STORE_PATH), username, password);
                }
            } finally {
                Arrays.fill(password, '\0');
            }
```
```java
// src/main/java/com/acme/portal/Authenticator.java — split the sleep out of the locked decision
    /** Pays the per-account backoff before any shared lock is acquired. */
    void awaitThrottleDelay(String suppliedUsername) throws InterruptedException {
        String canonical = canonicalUsername(suppliedUsername);
        long delay = guard.pendingDelayMillis(canonical != null ? canonical : "invalid-input");
        if (delay > 0) {
            Thread.sleep(delay);
        }
    }

    synchronized boolean authenticate(CredentialStore store, String suppliedUsername,
            char[] suppliedPassword)
            throws GeneralSecurityException {
        // ... unchanged, minus the Thread.sleep: check, verify, decide and count stay atomic ...
    }
```

## 6. Verified Controls and Checks With No Finding

- **Password storage work factor and primitives**: PBKDF2WithHmacSHA256, 600,000 iterations,
  128-bit `SecureRandom` salt per record, 256-bit output
  (`PasswordHasher.java:11-13`, `18-32`). Meets/exceeds the current OWASP Password Storage
  Cheat Sheet minimum for PBKDF2-HMAC-SHA-256; no MD5, SHA-1, DES/3DES, RC4, ECB, or
  home-rolled KDF anywhere in the tree.
- **Constant-time comparison of secrets**: verifier comparison uses `MessageDigest.isEqual`
  (`PasswordHasher.java:38`); the provisioning confirmation compare and the password-equals-username
  check are branch-free over the maximum length (`Main.java:128-149`); rate-limit keys compare with
  `MessageDigest.isEqual` (`LoginGuard.java:84-86`) as do blocklist entries
  (`PasswordBlocklist.java:94-97`).
- **Randomness**: all security randomness comes from `java.security.SecureRandom`
  (`PasswordHasher.java:14`, `LoginGuard.java:27`). No `java.util.Random`, no time-derived seed,
  no predictable salt or IV.
- **No usable hardcoded credential**: no key, password, or token in the repository works against a
  deployed instance. `Authenticator.DUMMY_PASSWORD` (`Authenticator.java:9`) is an equal-work
  placeholder bound to a random per-process salt and can never grant access, because
  `allowed` requires `actual != null` (`Authenticator.java:42-43`); the password in
  `SecurityTests.java:20` is test-only and used against a freshly created temp store.
- **Account enumeration resistance**: unknown, invalid-format, and wrong-password attempts all
  derive a PBKDF2 hash against a real-shaped record (`Authenticator.java:38-41`), all produce the
  identical `Access denied.` string (`Main.java:81`), and all provisioning rejections produce the
  identical `Unable to process the request securely.` string (`Main.java:101-107`). Return codes do
  not vary by account existence.
- **Fail-closed authorization conjunction**: the grant is a single AND of source allowance,
  username validity, password validity, record existence, and hash match
  (`Authenticator.java:42-43`); no branch grants access on a missing or errored check, and no
  default-permit path exists.
- **Check-then-grant atomicity**: the whole sequence (throttle read, store lookup, verification,
  decision, counter update) is inside one `synchronized` method (`Authenticator.java:24`), and
  `login` reloads the store while holding the same inter-process `FileLock` that credential
  updates use (`Main.java:71-76`, `CredentialStore.java:61-83`), so a grant cannot race a
  password change. `LoginGuard`'s three mutating methods are all `synchronized`
  (`LoginGuard.java:30,41,58`).
- **Credential-store parsing is allowlist-based and bounded**: fixed version header, 2 MB file
  cap, 10,000-record cap, 256-byte line cap, blank-line rejection, exactly three colon-separated
  fields, `[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?` username pattern, strict Base64, exact
  16-byte salt and 32-byte hash lengths, duplicate-username rejection via `putIfAbsent`, and
  rejection of an empty store (`CredentialStore.java:109-156`). Any single malformed value rejects
  the entire store rather than being coerced to a default.
- **Blocklist parsing is allowlist-based and bounded**: 0600/regular/non-symlink precondition,
  66 MB size cap, strict `[0-9a-f]{64}` line syntax, duplicate rejection, and a 10,000-entry
  minimum that fails closed (`PasswordBlocklist.java:33-58`). (Per-line memory bound: SEC-05.)
- **File permission and path hardening**: fixed absolute path, rejection of non-normalized paths,
  parent must be a non-symlinked directory that is neither group- nor other-writable
  (`CredentialStore.java:207-220`); store, lock file, and temp file are all created and required to
  be `rw-------` (`CredentialStore.java:32-33`, `65`, `172-173`); symlinks are rejected with
  `LinkOption.NOFOLLOW_LINKS` on every metadata check. No path component is taken from user input,
  an environment variable, or configuration, so there is no path-traversal surface.
- **Atomic, private credential writes**: write goes to a 0600 `Files.createTempFile` in the same
  directory, is size-checked, then replaces the target with `ATOMIC_MOVE`, and the temp file is
  deleted on any failure (`CredentialStore.java:172-204`). No partially written or
  broadly readable store can be observed.
- **Secret hygiene in memory and output**: passwords are read with `Console.readPassword` (never
  echoed, never an argument, never from a pipe since `System.console()` is required —
  `Main.java:21,28`), kept as `char[]`, and zeroed in `finally` along with derived salt/hash
  buffers (`Main.java:77-79`, `120-125`); `PBEKeySpec.clearPassword()` is called in `finally`
  (`PasswordHasher.java:30`); candidate hashes and blocklist digests are zeroed
  (`PasswordHasher.java:40`, `PasswordBlocklist.java:68-71`); `CredentialStore.Record` clones on
  both construction and access so callers cannot mutate or retain stored arrays
  (`CredentialStore.java:37-45`). No password or username is written to stdout, stderr, or a log.
- **Rate-limit state is bounded and does not store usernames**: account keys are salted SHA-256
  values under a per-process random salt, the map is capped at 10,000 entries, and per-key counts
  saturate at 32 (`LoginGuard.java:19-23`, `50-55`, `69-77`), so neither memory growth nor
  plaintext-identifier retention is unbounded.
- **Monotonic time source**: throttle windows use `System.nanoTime()` with overflow-safe delta
  comparisons (`LoginGuard.java:33`, `46`, `64`), not wall-clock time, so an adjusted system clock
  cannot shorten a block. (Origin-sign assumption: SEC-06.)
- **Password policy**: 15–128 character minimum for provisioning, confirmation match required, an
  organization-supplied compromised-password blocklist of 10k–1M entries, and rejection of a
  password equal to the username (`Main.java:97-108`). This follows NIST SP 800-63B's
  length-and-blocklist model rather than composition rules.
- **Injection and deserialization surface**: no SQL, no ORM, no `Runtime.exec`/`ProcessBuilder`,
  no `ObjectInputStream`/`readObject`, no XML/YAML/JSON parser, no reflection, no class loading,
  no HTTP/socket client, and no template rendering anywhere in the tree (verified across all six
  main sources and the test). SQL injection, OS command injection, XXE, SSRF, XSS, and insecure
  deserialization are structurally not reachable.
- **Tokens, sessions, and cookies**: the program issues and accepts none, so there is no
  predictable-identifier or cookie-attribute surface; the README documents the requirements that
  would apply if a web layer were added.
- **Crypto provider availability fails closed**: a missing `PBKDF2WithHmacSHA256` or `SHA-256`
  raises `GeneralSecurityException`/`IllegalStateException` (`PasswordHasher.java:24-32`,
  `LoginGuard.java:74-76`), which ends in the generic error path rather than a weaker fallback
  algorithm.
- **No third-party or remote code**: `build.sh` compiles only `src/main` and `src/test` against the
  JDK with `umask 077`, `set -eu`, `-Xlint:all -Werror`; nothing is downloaded, and no code is
  loaded from a shared or world-writable location.
- **Argument handling**: exactly one argument accepted, matched against the literal allowlist
  `login`/`provision`, with any other input (including a missing console) producing the generic
  message and exit code 2 (`Main.java:27-40`).
- **Documented residual risks confirmed as design decisions, not code defects**: `provision`
  authorizes the operator solely through filesystem ownership of the 0700 store directory and can
  overwrite an existing employee's verifier without the old password; credential verifiers are
  stored unencrypted (standard practice — the PBKDF2 work factor is the control); and the parent
  directory is permitted to be world-readable/traversable since the files within are 0600. These
  match the README's stated trusted-computing-base boundary.
