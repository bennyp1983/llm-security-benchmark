# Security Review: `com.example.auth` Authentication Component

## 1. Executive Summary

The component validates username/password login attempts, loads PBKDF2 credential records and a keystore-held pepper, applies per-source and per-account throttling, issues server-side session identifiers, and durably appends redacted audit events. The production code contains several strong controls, including canonical input validation, constant-time digest comparison, cryptographically random tokens, bounded parsing, fail-closed audit writes, and explicit secret redaction.

Six vulnerabilities were identified. Most importantly, credential and keystore files are validated by pathname and then reopened, allowing a local attacker who can modify a containing directory to race the checks and substitute a symlink or different file. The PBKDF2-HMAC-SHA-256 defaults are also materially below the current OWASP recommendation. Concurrent admission can overrun both throttle-map caps, full session storage evicts still-valid sessions, mutation-tool logs use predictable shared temporary paths, and audit account identifiers use an unkeyed hash that permits offline username guessing.

This was a static review only. No source, class, test, build, script, or import from the untrusted source tree was executed.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/AccountCredentials.java` | Immutable credential record. | Holds salts and password verifiers; clones arrays returned to callers. |
| `src/main/java/com/example/auth/AccountField.java` | Produces redacted audit account fields. | Hashes submitted usernames and emits presence metadata. |
| `src/main/java/com/example/auth/AttemptThrottle.java` | Per-source sliding-window limiter and per-account lockout. | Maintains concurrent, capped attacker-keyed state and retry decisions. |
| `src/main/java/com/example/auth/AuditLogger.java` | Durable append-only authentication event logger. | Creates private files, checks inode/mode, repairs torn records, limits size, and fails authentication closed on write failure. |
| `src/main/java/com/example/auth/AuditPersistenceException.java` | Represents audit persistence failure. | Carries a fixed diagnostic and redacted unsaved event without an exception cause. |
| `src/main/java/com/example/auth/AuthConfig.java` | Parses and validates authentication configuration. | Enforces numeric bounds, path/mode checks, keystore access, and secret erasure. |
| `src/main/java/com/example/auth/AuthEvent.java` | Builds and renders audit events. | Enforces a fixed single-line grammar and redacts usernames and session identifiers. |
| `src/main/java/com/example/auth/AuthException.java` | Internal authentication failure. | Exposes fixed diagnostic categories rather than sensitive causes. |
| `src/main/java/com/example/auth/AuthOutcome.java` | Authentication outcome enum. | Defines the externally observable success/denial states. |
| `src/main/java/com/example/auth/AuthResult.java` | Authentication result value. | Carries session identifiers on success while omitting them from `toString()`. |
| `src/main/java/com/example/auth/AuthenticationService.java` | Orchestrates login, throttling, verification, sessions, and audit. | Defines security-control ordering, denial behavior, token rollback, and cookie generation. |
| `src/main/java/com/example/auth/ConfigSource.java` | Snapshots environment or map configuration. | Treats configuration as untrusted and avoids rendering values. |
| `src/main/java/com/example/auth/CredentialStore.java` | Credential lookup interface. | Restricts authentication to server-side records. |
| `src/main/java/com/example/auth/CredentialVerifier.java` | Performs equalized credential verification. | Bounds concurrent PBKDF2 work, uses decoy records, and pads response latency. |
| `src/main/java/com/example/auth/Diagnostic.java` | Fixed diagnostic catalog. | Prevents attacker-controlled values and sensitive paths from entering errors/logs. |
| `src/main/java/com/example/auth/EventType.java` | Audit event categories. | Restricts log event types to fixed tokens. |
| `src/main/java/com/example/auth/FileCredentialStore.java` | Loads and parses the credential file. | Checks file size and record bounds, canonical Base64, work factors, and duplicate names. |
| `src/main/java/com/example/auth/InputValidator.java` | Validates usernames, passwords, and peer addresses. | Applies allowlists, canonical address parsing, length bounds, and exact UTF-8 encoding. |
| `src/main/java/com/example/auth/InvalidConfigException.java` | Reports startup configuration errors. | Sanitizes environment key names and suppresses sensitive causes. |
| `src/main/java/com/example/auth/KeystorePepperProvider.java` | Loads the password-hash pepper from a keystore. | Validates alias/type and extracts symmetric secret material. |
| `src/main/java/com/example/auth/LatencyBudget.java` | Pads login outcomes to a common latency floor. | Reduces username and branch timing differences. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Derives and verifies password digests. | Uses salted PBKDF2-HMAC-SHA-256, HMAC peppering, constant-time comparison, and buffer wiping. |
| `src/main/java/com/example/auth/PosixMode.java` | Centralizes POSIX permission checks. | Fails closed when permissions cannot be read and checks links without following them. |
| `src/main/java/com/example/auth/SessionTokenStore.java` | Issues, validates, expires, and revokes sessions. | Generates 128-bit random tokens, maintains bounded server-side state, and constructs hardened cookies. |
| `src/main/java/com/example/auth/TimeSource.java` | Supplies production and mutable test clocks. | Drives lockout windows, session expiry, and audit timestamps. |
| `src/test/java/com/example/auth/AuditLogChild.java` | Cross-process audit writer fixture. | Exercises multiple writers against one audit file. |
| `src/test/java/com/example/auth/AuthTestKeys.java` | Test-only keystore constants. | Contains fixture credentials that are explicitly outside production. |
| `src/test/java/com/example/auth/Check.java` | Minimal test assertion/cleanup helper. | Prints assertion data and deletes test scratch trees. |
| `src/test/java/com/example/auth/Fixture.java` | Creates authentication test fixtures. | Provisions temporary credentials, keystores, logs, configuration, and login attempts. |
| `src/test/java/com/example/auth/FixtureProvisioner.java` | Produces test credential records. | Uses the production hashing shape to create salts and verifiers for tests. |
| `src/test/java/com/example/auth/ProductionSource.java` | Reads production source for structural assertions. | Resolves a configurable source root and strips comments for mutation checks. |
| `src/test/java/com/example/auth/SmokeProbe.java` | Manual end-to-end timing probe. | Prints timing and redacted authentication/audit observations. |
| `src/test/java/com/example/auth/Suite1Validation.java` | Validation and configuration test suite. | Covers input, filesystem, credential-store, session-shape, and redaction controls. |
| `src/test/java/com/example/auth/Suite2LoginBehavior.java` | Login behavior test suite. | Covers generic denial, lockout, source limiting, cookies, and audit-outage behavior. |
| `src/test/java/com/example/auth/Suite3Latency.java` | Timing test suite. | Compares wall-clock and CPU costs across credential outcomes. |
| `src/test/java/com/example/auth/Suite4AuditDurability.java` | Audit safety test suite. | Covers injection, symlinks, inode replacement, permissions, torn tails, and file limits. |
| `src/test/java/com/example/auth/Suite5Concurrency.java` | Concurrent-state test suite. | Exercises lock, source, session, and audit behavior under concurrent calls. |
| `tools/mutation-battery.sh` | Applies security-control mutations and runs selected suites. | Copies and rewrites source in temporary storage, compiles it, executes tests, and writes shared temporary logs. |
| `tools/mutation-timing.sh` | Applies timing mutations and runs the latency suite. | Rewrites scratch source and writes a shared temporary timing log. |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: Used to inventory every source file, identify security-relevant behaviors, select specialized reviews, and require CWE/file-line evidence.
- `exploiting-race-condition-vulnerabilities`: Applied statically to pathname check/use windows, concurrent table-cap admission, and limit-overrun behavior; its dynamic exploitation steps were not run.
- `performing-cryptographic-audit-of-application`: Applied to password KDF parameters, salts, pepper handling, random generation, comparisons, token entropy, and audit pseudonyms.
- `implementing-api-rate-limiting-and-throttling`: Applied to per-source/per-account limits, atomicity, key trust, retry behavior, capacity, and single-process scope.
- `testing-api-authentication-weaknesses`: Applied to generic failures, account enumeration, password verification, session entropy/lifecycle/revocation, cookie flags, and token leakage.
- General OWASP Top 10 / CWE knowledge: Applied to filesystem race resistance, secure temporary files, audit privacy, resource exhaustion, log injection, error handling, and secrets exposure where no closer specialized skill matched.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Credential and keystore files can be replaced between validation and use | High | CWE-367 | `src/main/java/com/example/auth/FileCredentialStore.java:64-81` |
| SEC-02 | PBKDF2 work-factor floor is below current guidance | Medium | CWE-916 | `src/main/java/com/example/auth/AuthConfig.java:59-63` |
| SEC-03 | Concurrent new keys can overrun throttle table caps | Medium | CWE-362 | `src/main/java/com/example/auth/AttemptThrottle.java:141-150` |
| SEC-04 | Session-capacity handling evicts valid sessions | Medium | CWE-664 | `src/main/java/com/example/auth/SessionTokenStore.java:78-90` |
| SEC-05 | Mutation tools truncate predictable files in a shared temporary directory | Medium | CWE-377 | `tools/mutation-battery.sh:15-24` |
| SEC-06 | Audit account identifiers permit offline username guessing | Low | CWE-759 | `src/main/java/com/example/auth/AccountField.java:43-50` |

## 5. Detailed Findings

### SEC-01: Credential and keystore files can be replaced between validation and use
- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/auth/FileCredentialStore.java:64-81`; related instances at `src/main/java/com/example/auth/KeystorePepperProvider.java:60-72` and `src/main/java/com/example/auth/AuthConfig.java:445-460`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/FileCredentialStore.java:64-81
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            problems.add("credential file is not a regular file");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        final long size;
        try {
            size = Files.size(file);
        } catch (IOException e) {
            problems.add("credential file size could not be determined");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        if (size > MAX_FILE_BYTES) {
            problems.add("credential file is larger than the accepted size");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        final List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
```

**Why it is a problem:** The regular-file, permission, and size checks apply to whatever the path names at check time, while `readAllLines` later resolves and opens the path again. Unlike the audit-log directory, the accounts-file and keystore parent directories are not required to be non-writable by group/other users. An attacker able to rename entries in such a directory can replace the checked file with a symlink or a different file during the window. This can bypass the 8 MiB input bound, substitute attacker-chosen credential records, or make the runtime load a different pepper than the one validated during configuration. In a privileged deployment, credential substitution can lead to authentication bypass. `NOFOLLOW_LINKS` on the earlier metadata query does not constrain the later open.

**Fix:** Require a trusted, non-writable directory for both sensitive files and open the final component with no-follow semantics once. Perform size-bounded reading and keystore loading through that already-open handle. On platforms where Java cannot verify the opened descriptor's identity and mode, use a native `openat`/`O_NOFOLLOW` plus `fstat` wrapper or refuse startup.
```java
Path parent = file.getParent();
if (parent == null || PosixMode.writableByGroupOrOther(parent)) {
    problems.add("credential file directory is not trusted");
    return new FileCredentialStore(Map.of(), Map.of());
}

try (FileChannel channel = FileChannel.open(
        file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
    long size = channel.size();
    if (size > MAX_FILE_BYTES) {
        problems.add("credential file is larger than the accepted size");
        return new FileCredentialStore(Map.of(), Map.of());
    }
    byte[] bytes = new byte[Math.toIntExact(size)];
    ByteBuffer target = ByteBuffer.wrap(bytes);
    while (target.hasRemaining()) {
        if (channel.read(target) < 0) {
            throw new IOException("credential file changed while being read");
        }
    }
    List<String> lines = new String(bytes, StandardCharsets.UTF_8).lines().toList();
    // Parse only these bounded bytes from the already-open, no-follow handle.
}
```

### SEC-02: PBKDF2 work-factor floor is below current guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/AuthConfig.java:59-63`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthConfig.java:59-63
    public static final int MIN_PBKDF2_ITERATIONS = 120_000;

    private static final int MAX_ITERATIONS = 5_000_000;
    private static final int MIN_STORED_ITERATIONS = 10_000;
    private static final int MAX_STORED_ITERATIONS = 10_000_000;
```

**Why it is a problem:** The builder defaults the active PBKDF2 cost to 120,000 and the accepted stored-record floor to only 50,000 (`AuthConfig.java:623-624`). Current [OWASP Password Storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommends 600,000 or more iterations for PBKDF2-HMAC-SHA-256, or preferably a memory-hard KDF such as Argon2id where available. The pepper provides defense in depth, but if both credential data and the pepper are compromised, these lower costs make offline guessing substantially cheaper. The accepted-record floor means some accounts may be weaker still.

**Fix:** Prefer Argon2id with deployment-calibrated memory and CPU settings. If PBKDF2 must remain, raise both the active and accepted floors to at least 600,000, benchmark production hardware, and migrate or reset records below policy rather than continuing to accept them.
```java
public static final int MIN_PBKDF2_ITERATIONS = 600_000;

private static final int MAX_ITERATIONS = 5_000_000;
private static final int MIN_STORED_ITERATIONS = 600_000;
private static final int MAX_STORED_ITERATIONS = 5_000_000;

// Builder defaults must not admit weaker records.
private int pbkdf2Iterations = MIN_PBKDF2_ITERATIONS;
private int minAcceptedIterations = MIN_STORED_ITERATIONS;
```

### SEC-03: Concurrent new keys can overrun throttle table caps
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/auth/AttemptThrottle.java:141-150`; equivalent account-table code at `src/main/java/com/example/auth/AttemptThrottle.java:201-209`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AttemptThrottle.java:141-150
        sources.compute(canonicalSource, (key, existing) -> {
            SourceBucket bucket = existing;
            long horizon = nowMillis - windowSeconds * 1000L;
            if (bucket == null) {
                if (sources.size() >= MAX_SOURCE_KEYS && !evictIdleSources(horizon)) {
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return null;
                }
                bucket = new SourceBucket();
            }
```

**Why it is a problem:** `ConcurrentHashMap.compute` is atomic only for the supplied key. Requests using many distinct source addresses or usernames can all observe a size below the cap and then each insert a new bucket. Consequently, neither 20,000-entry cap is a true global bound under concurrency. A coordinated spray can retain more attacker-controlled buckets and timestamp queues than intended, increasing memory consumption and weakening the code's fail-closed capacity guarantee.

**Fix:** Make admission of a previously unseen key a globally atomic reserve/check/insert operation. A dedicated lock is sufficient for this in-process design; updates to an already-admitted bucket can remain per-bucket synchronized. Apply the same pattern to the account map.
```java
private final Object sourceAdmissionLock = new Object();

private SourceBucket sourceBucketForAdmission(String key, long horizon) {
    SourceBucket bucket = sources.get(key);
    if (bucket != null) {
        return bucket;
    }
    synchronized (sourceAdmissionLock) {
        bucket = sources.get(key);
        if (bucket != null) {
            return bucket;
        }
        evictIdleSources(horizon);
        if (sources.size() >= MAX_SOURCE_KEYS) {
            return null;
        }
        bucket = new SourceBucket();
        sources.put(key, bucket);
        return bucket;
    }
}
```

### SEC-04: Session-capacity handling evicts valid sessions
- **Severity:** Medium
- **CWE:** CWE-664: Improper Control of a Resource Through its Lifetime
- **Location:** `src/main/java/com/example/auth/SessionTokenStore.java:78-90`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionTokenStore.java:78-90
    synchronized String issue() {
        long now = time.nowMillis();
        dropExpiredLocked(now);
        if (expiresAtMillis.size() >= maxActiveSessions) {
            if (!evictOldestExpiringLocked(now)) {
                return null;
            }
            evictedCount++;
        }
        String token = newToken();
        expiresAtMillis.put(token, now + ttlSeconds * 1000L);
        issuedCount++;
        return token;
```

**Why it is a problem:** Once the table is full, `evictOldestExpiringLocked` removes a still-valid session as soon as it is at least one second old. A user or attacker with any valid credential can repeatedly authenticate and force unrelated users' sessions out of the store, turning the capacity control into a deterministic forced-logout/availability attack. Sliding expiration makes active sessions candidates based on their computed issuance age, so activity does not guarantee protection.

**Fix:** After expired entries are removed, refuse to issue another token while the table remains full. If product requirements call for a per-user session limit, store the account identity with the session and revoke only sessions belonging to that same authenticated account under an explicit policy.
```java
synchronized String issue() {
    long now = time.nowMillis();
    dropExpiredLocked(now);
    if (expiresAtMillis.size() >= maxActiveSessions) {
        return null;
    }
    String token;
    do {
        token = newToken();
    } while (expiresAtMillis.containsKey(token));
    expiresAtMillis.put(token, now + ttlSeconds * 1000L);
    issuedCount++;
    return token;
}
```

### SEC-05: Mutation tools truncate predictable files in a shared temporary directory
- **Severity:** Medium
- **CWE:** CWE-377: Insecure Temporary File
- **Location:** `tools/mutation-battery.sh:15-24`; equivalent log handling at `tools/mutation-timing.sh:6-8`

**Vulnerable code:**
```bash
# tools/mutation-battery.sh:15-24
WORK=/tmp/mut-$$.d
# The mutant tree is laid out as <TREE>/src/main/java/... because the suites read shipped sources
# through -Dauth.source.dir. Pointing that at a flat copy instead would have those assertions open
# the pristine tree and pronounce every mutant intact.
TREE="$WORK/tree"
SRC="$TREE/src/main"
MAIN="$WORK/main"
TEST="$WORK/test"
LOG="${LOG:-/tmp/mut-battery.log}"
: > "$LOG"
```

**Why it is a problem:** The default log name is fixed in a shared directory and is truncated without checking whether it is a symbolic link. Another local user can pre-create `/tmp/mut-battery.log` or `/tmp/mut-timing.log` as a symlink to a file writable by the script's user, causing that file to be truncated when the tools run. The main battery's PID-derived work directory is also predictable and is created without an atomic `mktemp`, permitting pre-creation and manipulation of the scratch tree. The impact is greater if these developer tools are run by a privileged CI or release account.

**Fix:** Create a private directory atomically with `mktemp -d`, place the default log inside it, set a restrictive umask, and reject unsafe caller-supplied log paths rather than blindly truncating them.
```bash
umask 077
WORK=$(mktemp -d "${TMPDIR:-/tmp}/mutation-battery.XXXXXX") || exit 1
trap 'rm -rf -- "$WORK"' EXIT

if [[ -z ${LOG+x} ]]; then
  LOG="$WORK/mutation-battery.log"
else
  if [[ -L "$LOG" ]]; then
    echo "refusing symbolic-link LOG path" >&2
    exit 1
  fi
  (set -o noclobber; : > "$LOG") || exit 1
fi
```

### SEC-06: Audit account identifiers permit offline username guessing
- **Severity:** Low
- **CWE:** CWE-759: Use of a One-Way Hash without a Salt
- **Location:** `src/main/java/com/example/auth/AccountField.java:43-50`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AccountField.java:43-50
    static String accountId(String username) {
        if (username == null) {
            return repeat('0', 64);
        }
        byte[] canonical = lowerAscii(username).getBytes(StandardCharsets.UTF_8);
        final byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(canonical);
```

**Why it is a problem:** Usernames usually have a small, enumerable candidate space. Anyone who obtains the audit log can hash email addresses or known usernames and compare them with `account_id`, recovering which accounts appear in the log and their activity patterns. SHA-256's preimage resistance does not protect low-entropy identifiers against a dictionary attack, and using the same unkeyed function makes identifiers correlate across deployments.

**Fix:** Generate the audit identifier with HMAC-SHA-256 under a separate, deployment-specific log-pseudonym key stored outside the log. Do not reuse the password pepper, so compromise or rotation of one purpose does not affect the other.
```java
static String accountId(String username, SecretKey auditPseudonymKey)
        throws GeneralSecurityException {
    if (username == null) {
        return repeat('0', 64);
    }
    byte[] canonical = lowerAscii(username).getBytes(StandardCharsets.UTF_8);
    try {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(auditPseudonymKey);
        return HexFormat.of().formatHex(mac.doFinal(canonical));
    } finally {
        Arrays.fill(canonical, (byte) 0);
    }
}
```

## 6. Verified Controls and Checks With No Finding

- Password verification: salted PBKDF2-HMAC-SHA-256 is post-processed with a keystore-held HMAC pepper, and `MessageDigest.isEqual` is used at `PasswordHasher.java:147-157`; the work-factor finding is limited to the configured cost.
- Randomness and token shape: salts and 128-bit session identifiers are generated by `SecureRandom`, token input is shape-checked before lookup, and tokens are held in server-side state at `SessionTokenStore.java:78-119` and `248-257`.
- Cookie hardening: the helper refuses non-TLS transport and emits `HttpOnly`, `SameSite=Strict`, `Secure`, a bounded path, and `Max-Age` at `SessionTokenStore.java:188-207`.
- Credential parsing: file, record, and line sizes are bounded; Base64 is canonicalized; iteration text is strict; and duplicate/case-colliding users fail startup at `FileCredentialStore.java:75-123` and `126-175`. These controls do not close SEC-01's pathname race.
- Input validation: usernames, passwords, and source literals are bounded and allowlisted; password encoding rejects malformed Unicode; IPv4 spellings are strict; and accepted addresses are canonicalized at `InputValidator.java:75-207` and `235-387`.
- Generic authentication behavior: known-user, unknown-user, malformed-name, lockout, and work-failure branches return generic denial objects, while decoy PBKDF2 and a latency floor reduce account enumeration at `AuthenticationService.java:181-223`, `CredentialVerifier.java:65-97`, and `LatencyBudget.java:86-105`.
- Account/source enforcement: source attempts are consumed before credential work and per-key counter mutations use atomic `ConcurrentHashMap.compute`; no per-key check/act bypass was found at `AttemptThrottle.java:137-227`. SEC-03 concerns only global capacity admission across distinct keys.
- Secret handling: production source contains no hardcoded credential or pepper; password arrays and intermediate derived material are wiped on normal/error paths, result and attempt `toString()` methods omit secrets, and test-only fixture secrets are isolated under `src/test`.
- Audit injection and durability: event fields use fixed grammars, unsafe lines are rejected, writes are forced, short/torn records are repaired, modes and inode identity are rechecked, and failed persistence denies authentication at `AuthEvent.java:128-172`, `AuditLogger.java:211-364`, and `AuthenticationService.java:255-295`.
- Sensitive error handling: configuration and authentication exceptions suppress underlying causes that could contain paths or values, and unknown environment key names are sanitized at `InvalidConfigException.java:25-62`.
- Session rollback and revocation: a token issued before an audit failure is revoked in `AuthenticationService.java:281-295`, explicit logout removes server-side state, and expired tokens are rejected. SEC-04 concerns eviction of unrelated unexpired sessions at capacity.
- Filesystem permissions: sensitive files are required to be owner-only, inability to read POSIX permissions fails closed, and the audit log refuses group/other-writable parents at `PosixMode.java:45-100` and `AuditLogger.java:132-173`. SEC-01 concerns accounts/keystore directory trust and atomic open/use.
- Shell mutation semantics: replacements require unique anchors and report drift; baseline failure aborts the main mutation battery; scratch cleanup uses quoted paths. The finding is confined to predictable creation/truncation in shared temporary storage.
