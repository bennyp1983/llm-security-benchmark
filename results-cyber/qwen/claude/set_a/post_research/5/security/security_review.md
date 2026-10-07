# Security Review: Employee Portal Authentication Component (`com.example.portal.auth`)

## 1. Executive Summary

The component is a dependency-free Java 17 credential authenticator: it enrolls and verifies PBKDF2-HMAC-SHA256 password hashes stored in a flat file, throttles guessing attempts with per-account and per-source budgets persisted to a state file, issues opaque 256-bit bearer session tokens, renders a `__Host-` session cookie, and writes a masked audit log. A command-line front end (`PortalCli`) drives it, and an adversarial self-test suite (`SelfTest`, 20 cases) exercises many attack paths.

This is, by a wide margin, better-engineered code than the average deliverable of its size. Most of the hardening claims in `README.md` check out against the source: the KDF parameters are current (600,000 iterations, 16-byte salt, 256-bit key), comparison is constant-time, an unknown account costs the same as a wrong password, attempt slots are reserved *before* verification under a lock, malformed records are dropped rather than guessed at, identifiers are masked in the log, and the tracker fails closed when it cannot be consulted. The review confirmed these rather than accepting them (see section 6).

No authentication bypass, credential disclosure, injection, or token-forgery defect was found. The findings are concentrated in **availability** and **defence-in-depth**:

- **One High.** The rate limiter is keyed on strings an attacker can supply and vary freely (the `source` identifier and any syntactically valid username). Both key maps are capped at `maxTrackedKeys = 100_000`, and when the cap is reached the limiter returns `CAPACITY_EXHAUSTED` for *every* new key — which `Authenticator` translates into a denial. Filling the maps therefore switches off authentication for the whole organisation, and each probe still costs a 600,000-iteration derivation. Fail-closed is the right instinct; making one attacker's key cardinality a global kill switch is not.
- **Four Medium.** Ownership of the credential file is proven by comparing the file's owner name to `System.getProperty("user.name")` — a launcher-settable string, not the effective UID. The `enroll` path appends to the authoritative credential file without the owner-only re-check that the login path performs. The persisted rate-limit state is rewritten in place with `truncate(0)` followed by a write, so a crash between the two silently clears every active restriction. Audit writes go through a `PrintStream`, which swallows `IOException`, so security-relevant denials can vanish with no signal, and the append-only log has no size bound.
- **Four Low.** The bearer token is retained in an immutable `String`, contrary to the project's own zeroing policy; thirty prebuilt `.class` files ship with nothing binding them to `src/`; the cookie's javadoc contradicts the code on a `__Host-` invariant; stdin is decoded byte-by-byte as Latin-1, so a non-ASCII passphrase commits to a different secret than the operator typed.

Everything below is static analysis. Nothing in the source folder was executed, built, or modified; line numbers refer to the files as read.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/portal/auth/PasswordHasher.java` | PBKDF2-HMAC-SHA256 hash/verify/parse | 600k iterations, 16 B salt, 256-bit key; accepts only 100k–10M iterations; `MessageDigest.isEqual`; zeroes derived key and `PBEKeySpec`; decoy derivation for timing parity; redacting `toString()` |
| `src/main/java/com/example/portal/auth/InputPolicy.java` | Whitelist validation of externally supplied values | Username 3–64 `[A-Za-z0-9._-]`, letter-initial, lower-cased; password length-only on login, ≥12 on enroll; source ≤64 chars of `[A-Za-z0-9.:%_-]` (**not** required to be an address literal) |
| `src/main/java/com/example/portal/auth/Authenticator.java` | Login flow | validate → reserve slot → lookup → verify → issue session; every failure path returns the identical denial and pays one KDF; logs masked identifiers |
| `src/main/java/com/example/portal/auth/SessionManager.java` | Opaque bearer sessions | 32 random bytes → 43-char Base64url; table keyed by SHA-256 of token; idle + absolute expiry; validate inside `compute()`; 20,000-session cap; strict `hasTokenShape` |
| `src/main/java/com/example/portal/auth/Session.java` | Session value object | `toString()` renders a 12-hex-char non-secret handle, never the token |
| `src/main/java/com/example/portal/auth/AuthResult.java` | Grant/denial result | Holds bearer token as immutable `String`; always `GENERIC_FAILURE_MESSAGE` on denial; `toString()` redacts |
| `src/main/java/com/example/portal/auth/SessionCookie.java` | `Set-Cookie` rendering | `__Host-portal_session`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, no `Domain=`; refuses malformed tokens and non-positive `Max-Age` |
| `src/main/java/com/example/portal/auth/CredentialStore.java` | Store interface | Lookup by canonical username only |
| `src/main/java/com/example/portal/auth/FileCredentialStore.java` | Flat-file credential store | Owner-only + non-world-writable-dir check; 8 MiB / 50,000-record / 512-char caps; splits on first `:`; duplicate account is fatal; immutable snapshot, `find()` does no I/O |
| `src/main/java/com/example/portal/auth/PrivateFiles.java` | File privacy gate | Creates `rw-------` at create time; re-verifies mode, owner and parent directory on every use; **owner proven via `user.name` property** |
| `src/main/java/com/example/portal/auth/AttemptLimiter.java` | Limiter interface + limits | 5/15 min per account, 50/15 min per source, 15-min restrictions, `maxTrackedKeys = 100_000`; `CAPACITY_EXHAUSTED` and `UNAVAILABLE` decisions |
| `src/main/java/com/example/portal/auth/AttemptCounters.java` | Window/restriction arithmetic | Creates a map entry per unseen key; returns `CAPACITY_EXHAUSTED` once the cap survives pruning; clamps clock-skewed timestamps |
| `src/main/java/com/example/portal/auth/InMemoryAttemptLimiter.java` | Heap tracker | `ReentrantLock`; source budget drawn before account budget |
| `src/main/java/com/example/portal/auth/FileAttemptLimiter.java` | Persisted tracker | Per-path `ReentrantLock` + exclusive `FileLock`; 16 MiB / 160-char bounds; re-checks file privacy per open; `commit()` truncates then rewrites; any I/O error → `UNAVAILABLE` |
| `src/main/java/com/example/portal/auth/AuditLog.java` | Security/operational log | Owner-only append-only file; masks accounts and sources; strips control characters; truncates fields at 200; `PrintStream` sink swallows I/O errors; unbounded growth |
| `src/main/java/com/example/portal/auth/PortalCli.java` | Command-line front end | Refuses `--password`; zeroes passwords in `finally`; `--source` operator-supplied, else constant `console-local`; enroll appends under a `FileLock`; byte-wise stdin decode |
| `src/main/java/com/example/portal/auth/ValidationException.java` | Validation failure | Message documented as audit-log-only, never returned to the caller |
| `src/test/java/com/example/portal/auth/SelfTest.java` | 20 adversarial self-tests | Asserts budget enforcement under 32-thread contention, restart persistence, fail-closed tracker, masking, cookie attributes, no CLI password |
| `build.sh` | JDK-only build | `-Xlint:all -Werror`; compiles to `out/classes`, runs `SelfTest`; unquoted `$(find …)` (cosmetic) |
| `out/**/*.class` (30 files) | Prebuilt binaries shipped in the deliverable | No manifest, checksum, signature, or provenance binding them to `src/` |

## 3. Skills Applied

- **`performing-cryptographic-audit-of-application`** — applied to `PasswordHasher.java` (algorithm, iteration count and accepted range, salt length, derived-key length, `PBEKeySpec` clearing, `MessageDigest.isEqual`, decoy-work timing parity) and `SessionManager.java` (`SecureRandom` token generation, digest-keyed session table, collision handling).
- **`testing-api-authentication-weaknesses`** — applied to `Authenticator.java` (validate-before-consume ordering, unknown-account indistinguishability, denial-path completeness) and `SessionManager.java` / `AuthResult.java` (token entropy and shape validation, idle and absolute expiry, revocation, token leakage into logs and `toString()`).
- **`testing-for-sensitive-data-exposure`** — applied to `PrivateFiles.java`, `FileCredentialStore.java`, `AuditLog.java` (file privacy enforcement, masking, control-character stripping, secret-free rendering) and to the retained-token question in `SessionManager.Issued`.
- **`performing-security-headers-audit`** — applied to `SessionCookie.java` (`__Host-` prefix invariants: `Secure`, no `Domain=`, `Path=/`, plus `HttpOnly` / `SameSite=Strict`).
- **`implementing-api-rate-limiting-and-throttling`** — applied to `AttemptLimiter.java`, `AttemptCounters.java`, `InMemoryAttemptLimiter.java`, `FileAttemptLimiter.java` (bucket-key design, window and restriction arithmetic, cardinality bounds, capacity-exhaustion behaviour, crash durability).
- **`implementing-api-abuse-detection-with-rate-limiting`** — applied to the dual per-account / per-source budget design and its fail-closed versus degrade behaviour under adversarial key growth.
- **`implementing-log-integrity-with-blockchain`** — applied to `AuditLog.java` for append-only integrity and tamper/loss detectability (not its anchoring machinery, which the component does not need).
- **`verifying-build-provenance-with-slsa-sigstore`** — applied to the shipped `out/**/*.class` artifacts and `build.sh`, as the reference model for binding artifacts to source.

**Name-matched but not applicable:** `testing-jwt-token-security`, `testing-for-json-web-token-vulnerabilities`, `exploiting-jwt-algorithm-confusion-attack` (the component issues opaque random tokens, not JWTs — no `alg`/`kid`/`jku` surface exists); `exploiting-race-condition-vulnerabilities` and `testing-for-broken-access-control` (both are request-driven Burp workflows; the analogue issues here are on-disk, so they are covered by the rate-limiting and sensitive-data skills plus general OWASP A01/A05 and CWE-276/CWE-367 coverage); `implementing-secrets-management-with-vault`, `detecting-aws-credential-exposure-with-trufflehog` (no secrets in source, no cloud surface); `implementing-file-integrity-monitoring-with-aide` (host agent, out of scope for a library). **Behaviours with no specialised skill in the library** — the `enroll` path's missing privacy re-check (SEC-03), stdin character decoding (SEC-09), and CLI argument handling — were audited against general OWASP Top 10 (A01 Broken Access Control, A05 Security Misconfiguration) and CWE-276 / CWE-172 coverage.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate-limiter key space is attacker-controlled; filling it locks out all authentication | High | CWE-770 | `src/main/java/com/example/portal/auth/AttemptCounters.java:64-74` |
| SEC-02 | File ownership proven via the spoofable `user.name` JVM property instead of the effective UID | Medium | CWE-287 | `src/main/java/com/example/portal/auth/PrivateFiles.java:78-82` |
| SEC-03 | `enroll` appends to the credential file without the privacy check the login path performs | Medium | CWE-276 | `src/main/java/com/example/portal/auth/PortalCli.java:212-231` |
| SEC-04 | Rate-limit state rewritten non-atomically; a crash wipes every active restriction | Medium | CWE-693 | `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:242-249` |
| SEC-05 | Audit sink swallows write failures; append-only log is unbounded | Medium | CWE-778 | `src/main/java/com/example/portal/auth/AuditLog.java:59-62, 80-84` |
| SEC-06 | Bearer session token retained in an immutable `String` | Low | CWE-922 | `src/main/java/com/example/portal/auth/SessionManager.java:211` |
| SEC-07 | Prebuilt class files shipped with no provenance or integrity binding | Low | CWE-494 | `build.sh:15` |
| SEC-08 | Cookie javadoc contradicts the emitted `Path`, on a `__Host-` correctness invariant | Low | CWE-1110 | `src/main/java/com/example/portal/auth/SessionCookie.java:21, 34` |
| SEC-09 | Stdin decoded byte-by-byte as Latin-1; committed secret differs from typed secret | Low | CWE-172 | `src/main/java/com/example/portal/auth/PortalCli.java:301-315` |

## 5. Detailed Findings

### SEC-01 — Rate-limiter key space is attacker-controlled; filling it locks out all authentication

**Severity:** High

**CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (secondary: CWE-400 Uncontrolled Resource Consumption)

**Location:** `src/main/java/com/example/portal/auth/AttemptCounters.java:64-74`

**Vulnerable code:**

```java
// AttemptCounters.java:64-74
        State state = map.get(key);
        if (state == null) {
            if (map.size() >= maxKeys) {
                prune(map, windowMillis, now);
            }
            if (map.size() >= maxKeys) {
                return Slot.CAPACITY_EXHAUSTED;
            }
            state = new State(now);
            map.put(key, state);
        }
```

```java
// Authenticator.java:92-98
        if (!reservation.permitted()) {
            // Still pay the KDF cost: a restricted account must not answer faster than a live one.
            hasher.performDecoyWork();
            audit.security("authentication refused: " + reservation.decision(),
                    "account=" + AuditLog.maskAccount(username) + " source=" + AuditLog.maskSource(source));
            return AuthResult.denied();
        }
```

**Why it is a problem:**

A map entry is created for every key the limiter has not seen inside the current window, in both maps (`accounts` and `sources`), and both are capped at `AttemptLimiter.Limits.maxTrackedKeys = 100_000`. The keys themselves come from attacker-influenced input:

- **Source keys.** `InputPolicy.requireValidSource` (`InputPolicy.java:120-136`) checks only length and a character whitelist — letters, digits, `.` `:` `-` `_` `%`. It does not require the value to *be* an address. A 64-character string over that alphabet is drawn from a space far larger than 100,000, so an unauthenticated caller who controls the source value (the README concedes the identifier "is only as trustworthy as the front end"; a front end that forwards `X-Forwarded-For` or any client-supplied tag does this) can mint a fresh bucket per probe. The `javadoc` at `InputPolicy.java:112-116` reasons that varying the value "can only spread their attempts across buckets, never escape the per-account limit" — true, but it understates the cost: the spreading is exactly what grows `sources` to the cap.
- **Account keys.** Any syntactically valid username creates an entry, even one that has no credential on file (`Authenticator` reserves the slot at `Authenticator.java:83` *before* `store.find`), so enumerating names like `employee000001` … grows `accounts` too.

Once `prune` fails to bring a map under 100,000 entries — trivially achieved inside the 15-minute window by keeping the unique sources fresh — `consume` returns `CAPACITY_EXHAUSTED` for **any key not already present**, including the account key of an employee typing a correct password. `map()` in both limiters (`InMemoryAttemptLimiter.java:86-88`, `FileAttemptLimiter.java:140-142`) turns that into `Decision.CAPACITY_EXHAUSTED`, `reservation.permitted()` is false, and every subsequent login is denied with the generic message. That is an unauthenticated, low-cost switch that turns off authentication for the entire organisation and is invisible to the operator as anything other than a wave of ordinary denials. Two amplifiers ride along: each refused probe still executes `hasher.performDecoyWork()` (`Authenticator.java:94`), a 600,000-iteration derivation, so the DoS also consumes the CPU the KDF deliberately reserves; and in the file-backed configuration the state file grows toward 100,000 lines, so every subsequent login pays a read-modify-write over it under an exclusive lock.

Fail-closed on limiter failure is the correct default — `SelfTest.trackerFailsClosed` is right to assert it. The defect is that an attacker's *key cardinality* is allowed to become a global condition, rather than being bounded per-actor and degraded locally.

**Fix:**

Stop letting a client-supplied string name a budget bucket: require a numeric address, then bucket it coarsely so the key space is bounded by the address space rather than by the whitelist grammar, and derive it from the socket peer in the front end rather than from a header.

```java
// InputPolicy.java — replace the whitelist body of requireValidSource (lines 120-136)
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern IPV6 = Pattern.compile("(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}(?:%\\d{1,3})?");

    public static String requireValidSource(String source) throws ValidationException {
        if (source == null) {
            throw new ValidationException("source identifier is absent");
        }
        String normalized = source.toLowerCase(Locale.ROOT);
        if (normalized.isEmpty() || normalized.length() > SOURCE_MAX_LENGTH) {
            throw new ValidationException("source identifier length out of range");
        }
        if (!IPV4.matcher(normalized).matches() && !IPV6.matcher(normalized).matches()) {
            // Only a numeric address may name a budget bucket: a free-form tag lets the caller
            // choose how many buckets exist. No DNS lookup here -- getByName() would resolve
            // attacker-chosen hostnames and invent buckets that way too.
            throw new ValidationException("source identifier is not a numeric address");
        }
        return normalized;
    }
```

```java
// AttemptLimiter.java — collapse neighbouring addresses into one bucket before keying
    static String sourceBucket(String address) {
        int dot = address.lastIndexOf('.');
        if (dot > 0) {
            return address.substring(0, dot);                       // IPv4 /24
        }
        String[] groups = address.split(":");
        return String.join(":", Arrays.copyOf(groups, 3)) + ":*";   // IPv6 /48
    }
```

Then bound the consequence: when capacity is reached, evict the coldest non-restricted entries and keep serving rather than refusing the next legitimate employee, and keep `CAPACITY_EXHAUSTED` only for the case where eviction cannot help.

```java
// AttemptCounters.java:64-74 — degrade instead of going dark
        State state = map.get(key);
        if (state == null) {
            if (map.size() >= maxKeys) {
                prune(map, windowMillis, now);
            }
            if (map.size() >= maxKeys) {
                evictColdest(map, now);   // coldest-first, never a still-restricted key
            }
            if (map.size() >= maxKeys) {
                return Slot.CAPACITY_EXHAUSTED;
            }
            state = new State(now);
            map.put(key, state);
        }
```

Whichever degradation is chosen must be loud: emit an `audit.warn` when capacity pressure is hit, so an operator sees "the limiter is being saturated" instead of discovering it as unexplained login failures.

### SEC-02 — File ownership proven via the spoofable `user.name` JVM property instead of the effective UID

**Severity:** Medium

**CWE:** CWE-287: Improper Authentication (secondary: CWE-639 Authorization Bypass Through User-Controlled Key)

**Location:** `src/main/java/com/example/portal/auth/PrivateFiles.java:78-82`

**Vulnerable code:**

```java
// PrivateFiles.java:78-82
        String fileOwner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName();
        String processUser = System.getProperty("user.name");
        if (processUser == null || !processUser.equals(fileOwner)) {
            throw new ValidationException(kind + " is not owned by the portal user");
        }
```

**Why it is a problem:**

`user.name` is not an assertion about the process; it is a JVM system property, initialised from the environment and overridable by anyone who can influence the launch command line — `-Duser.name=portal`, `JAVA_TOOL_OPTIONS`, a shared unit file, an entrypoint wrapper, a configuration-management template. The kernel-level fact this check is trying to establish (does this *effective UID* own the file?) is never consulted. Anything that can set a `-D` flag against the portal's JVM can therefore make a file owned by a different account pass as "owned by the portal user". In a container that is the common case: run as UID 0 with `-Duser.name=portal`, and a root-owned credential file planted by another process in the image or in a mounted volume is accepted, defeating exactly the check whose comment at `PrivateFiles.java:56-58` says exists because "a file owned by another account could have been planted".

The comparison is also unreliable in the other direction. `UserPrincipal.getName()` is a name-service lookup, so on NFS, on AD-mapped filesystems, or in an image where the UID has no `/etc/passwd` entry, the owner name and `user.name` can diverge for a genuinely correct file (spurious refusal of a good store) or resolve to the same name for two different UIDs (spurious acceptance). Name equality is the wrong primitive; numeric IDs are the right one. The permission and parent-directory checks surrounding this one (`PrivateFiles.java:74-77`, `83-89`) are sound — this is the single weakest link in an otherwise careful gate, and it guards the credential file, the tracker state file, and the audit log alike.

**Fix:**

Compare numeric IDs, and refuse rather than guess when the ID cannot be established — the same posture the code already takes for non-POSIX filesystems.

```java
// PrivateFiles.java — replace lines 78-82
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        if (!(owner instanceof UidPrincipal fileOwner)) {
            throw new ValidationException(kind + " owner cannot be expressed as a uid on this system");
        }
        long effectiveUid = effectiveUid();
        if (fileOwner.uid() != effectiveUid) {
            // The effective uid, never user.name: the property is whatever the launcher declared.
            throw new ValidationException(kind + " is not owned by the portal user");
        }
```

```java
// PrivateFiles.java — new helper
    private static long effectiveUid() throws IOException, ValidationException {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("Uid:")) {
                    // Fields are real, effective, saved, filesystem.
                    return Long.parseLong(line.split("\\s+")[2]);
                }
            }
        } catch (NumberFormatException | IOException e) {
            throw new ValidationException("cannot determine the effective uid of this process", e);
        }
        throw new ValidationException("cannot determine the effective uid of this process");
    }
```

If `/proc` is unavailable, fail the check rather than falling back to the property. Additionally, treat a file whose owner UID is `0` as untrusted when the process is also UID 0 — a root-owned credential file is not evidence of portal ownership.

### SEC-03 — `enroll` appends to the credential file without the privacy check the login path performs

**Severity:** Medium

**CWE:** CWE-276: Incorrect Default Permissions (secondary: CWE-732 Incorrect Permission Assignment for Critical Resource)

**Location:** `src/main/java/com/example/portal/auth/PortalCli.java:212-231`

**Vulnerable code:**

```java
// PortalCli.java:212-231
    private static void appendRecord(Path storePath, String username, String record)
            throws IOException, ValidationException {
        Path resolved = storePath.toAbsolutePath().normalize();
        try (FileChannel channel = FileChannel.open(resolved, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
            for (String line : Files.readAllLines(resolved, StandardCharsets.UTF_8)) {
                int separator = line.indexOf(':');
                if (separator > 0 && line.substring(0, separator).equalsIgnoreCase(username)) {
                    throw new ValidationException("that account already has a credential on file");
                }
            }
            channel.position(channel.size());
            byte[] bytes = (record + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            channel.write(java.nio.ByteBuffer.wrap(bytes));
            channel.force(true);
            Arrays.fill(bytes, (byte) 0);
        }
    }
```

**Why it is a problem:**

Reading the credential store is gated: `FileCredentialStore.load` calls `PrivateFiles.requireOwnerOnly(resolved, "credential file")` (`FileCredentialStore.java:60`), and the tracker re-checks on every single open (`FileAttemptLimiter.java:157`). Writing the store is not. `enroll` calls `FileCredentialStore.createIfAbsent(storePath)` (`PortalCli.java:187`), which delegates to `PrivateFiles.createPrivateIfAbsent` — and that method returns immediately if the path already exists (`PrivateFiles.java:41-43`), applying the `rw-------` attribute only to files it creates itself. `appendRecord` then opens the file for writing and appends a freshly derived hash, checking only the file size and username uniqueness.

The consequence is that the one operation that writes secrets to disk is the operation that never verifies they will stay private. If the store is absent, privacy holds. If the path was created by anything else — another tool, an unquoted shell redirect, a restored backup, an automated provisioning step that left mode `0664` or `0644`, a file owned by a sibling service account — `enroll` silently writes into it and reports success. A group-writable store means any account in that group can now read every PBKDF2 hash in it (offline cracking of the whole directory at once) and, if writable, plant or swap a record; the duplicate-account check at `PortalCli.java:220-225` only protects against an *exact* username collision and is case-insensitive-only, not authoritative, because `load` rejects the file entirely on duplicates (`FileCredentialStore.java:97`) rather than telling the operator which record was tampered with.

The asymmetry is also the whole reason the login path's check exists, so this is not a theoretical gap: the codebase's own comment at `PrivateFiles.java:57-59` states the threat — "group or world *read* on a credential file hands over the hashes; group or world *write* lets another local account enrol itself as any employee or quietly reset the attempt counters." The read path enforces that; the write path does not.

**Fix:**

Run the same gate as the read path, and run it *after* acquiring the lock so the check cannot be raced — which is exactly what `FileAttemptLimiter.Transaction` already does.

```java
// PortalCli.java — inside appendRecord, immediately after the FileLock is held (line 216)
        try (FileChannel channel = FileChannel.open(resolved, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            // Under the lock, so the mode and owner cannot be changed between the check and the
            // write. Enroll must vet the file exactly as strictly as login does.
            PrivateFiles.requireOwnerOnly(resolved, "credential file");
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
```

If the file may legitimately not exist yet, create it under the same lock (`Files.createFile` with the `rw-------` file attribute) before opening the channel, rather than relying on `createPrivateIfAbsent`'s existence short-circuit.

### SEC-04 — Rate-limit state rewritten non-atomically; a crash wipes every active restriction

**Severity:** Medium

**CWE:** CWE-693: Protection Mechanism Failure

**Location:** `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:242-249`

**Vulnerable code:**

```java
// FileAttemptLimiter.java:242-249
            byte[] bytes = out.toString().getBytes(StandardCharsets.UTF_8);

            channel.truncate(0);
            channel.position(0);
            channel.write(ByteBuffer.wrap(bytes));
            // Durability matters for a security control: a restriction lost to a crash is a
            // restriction an attacker can provoke by crashing the host.
            channel.force(true);
```

**Why it is a problem:**

`commit()` destroys the old contents before the new contents are durable. `truncate(0)` discards the entire state file immediately; the replacement bytes are then staged in the page cache by `write` and only reach storage at `force(true)`. Any interruption inside that window — process kill, host crash, power loss, OOM, a panicked operator restarting the service mid-transaction — leaves the file empty or partially written, not in its previous state. `SelfTest.trackerFailsClosed` covers a state file that cannot be *read*; it does not cover a state file that has been validly truncated to zero, which loads as an empty tracker and is indistinguishable from a healthy one.

The security effect is that the persisted rate limit is switched off silently. Every account restriction and every in-flight attempt count disappears, and the next `tryReserve` for a previously-burning account succeeds with a fresh 5-attempt budget. Because the file is plaintext and self-describing, this is not recoverable after the fact — there is no record that a restriction existed, and the audit log line recording the restriction is now the only evidence, and see SEC-05 for the reliability of that sink.

The comment at lines 247-248 shows the author understood the requirement ("a restriction lost to a crash is a restriction an attacker can provoke") but `truncate`-then-`force` is the one sequence that cannot meet it: the destructive step precedes the durable step. Note also that the current in-place rewrite is what preserves the `FileLock`'s identity across processes, so a naive fix that renames a new file over the locked inode would silently break inter-process mutual exclusion — the lock has to move off the data file first.

**Fix:**

Write a complete new file, fsync it, then publish it with an atomic rename — and take the lock on a companion file whose inode never changes, so replacing the state file cannot split the lock.

```java
// FileAttemptLimiter.java — Transaction.open: lock a stable companion, not the data file
    private static final String LOCK_SUFFIX = ".lock";

    static Path lockFileFor(Path statePath) {
        return statePath.resolveSibling(statePath.getFileName() + LOCK_SUFFIX);
    }
```

```java
// FileAttemptLimiter.java — Transaction.commit(): replace lines 244-249
            Path temp = Files.createTempFile(statePath.getParent(),
                    statePath.getFileName() + ".", ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            try {
                try (FileChannel written = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                    written.write(ByteBuffer.wrap(bytes));
                    written.force(true);          // durable *before* it becomes the live file
                }
                Files.move(temp, statePath, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException | RuntimeException e) {
                Files.deleteIfExists(temp);       // leave the previous, still-valid state in place
                throw e;
            }
```

Readers now observe either the whole previous file or the whole new one, never a truncated middle, and an interruption costs the one uncommitted transaction rather than the tracker's entire memory. The companion lock file must be created with the same owner-only attribute and vetted by `PrivateFiles.requireOwnerOnly` alongside the state file.

### SEC-05 — Audit sink swallows write failures; append-only log is unbounded

**Severity:** Medium

**CWE:** CWE-778: Insufficient Logging (secondary: CWE-770 unbounded resource growth)

**Location:** `src/main/java/com/example/portal/auth/AuditLog.java:59-62, 80-84`

**Vulnerable code:**

```java
// AuditLog.java:59-62
        PrintStream stream = new PrintStream(
                Files.newOutputStream(resolved, StandardOpenOption.CREATE, StandardOpenOption.APPEND),
                true, StandardCharsets.UTF_8);
        return new AuditLog(stream, true);
```

```java
// AuditLog.java:80-84
    private synchronized void write(String level, String event, String detail) {
        String line = Instant.now() + " " + level + " " + sanitise(event)
                + (detail == null || detail.isEmpty() ? "" : " | " + sanitise(detail));
        sink.println(line);
    }
```

**Why it is a problem:**

`PrintStream` is specified to swallow `IOException` from its underlying stream and merely set an internal `trouble` flag; nothing in this class ever consults `checkError()`. So a failed audit write is indistinguishable from a successful one, at every call site — `info`, `warn`, and `security` all return `void`. Disk full, quota exceeded, immutable file, a filesystem remounted read-only after an error, a deleted-then-recreated log inode: in each case the component continues to serve grants and denials while believing it is recording them. `Authenticator` logs every outcome through this sink (`Authenticator.java:95-96`, `105-106`, `119-121`, `128-129`), so what silently disappears is precisely the record of who was refused and from where — the evidence an investigator would need after the SEC-01 saturation attack or a brute-force campaign. `AuditLog` is the component's only integrity mechanism for security decisions, and it has no detectability at all. The class also has no size bound: the only constant is `MAX_FIELD_LENGTH = 200` (`AuditLog.java:32`), which truncates fields, not the file. A peer that can drive denials at volume (`source`-varied probes, per SEC-01) writes a permanent, unrotated `SECURITY` line per attempt into a `0600` file on the portal host, and filling that filesystem takes the authentication service with it.

This is not a "logging is nice to have" point: the component's own design leans on the log as the compensating control for masking everything from the user (identical denial messages, decoy KDF work, no restriction announcement), so an audit sink that fails quietly removes the one channel that distinguishes an employee's typo from a campaign.

**Fix:**

Make lost writes observable, and bound growth.

```java
// AuditLog.java — replace write() at lines 80-84
    private synchronized void write(String level, String event, String detail) {
        String line = Instant.now() + " " + level + " " + sanitise(event)
                + (detail == null || detail.isEmpty() ? "" : " | " + sanitise(detail));
        sink.println(line);
        sink.flush();
        if (sink.checkError()) {
            // PrintStream swallows IOException; without this check a lost denial is invisible and
            // every security decision becomes unverifiable. Surface it and mark the log degraded.
            degraded = true;
            System.err.println("AUDIT SINK FAILURE: entry not persisted -- " + line);
        }
    }

    /** True once any audit write has failed; expose this to the health check. */
    public boolean isDegraded() {
        return degraded;
    }
```

For durability that survives the process, propagate the failure instead of only flagging it: throw on a failed `security`-level write so `Authenticator`'s fail-closed philosophy extends to logging, or write through a `FileChannel` with `force(true)` and let `IOException` reach the caller. For unbounded growth, rotate on size before appending:

```java
// AuditLog.java — bound the file before appending
    private static final long MAX_LOG_BYTES = 64L * 1024 * 1024;

    private static void rotateIfNeeded(Path resolved) throws IOException {
        if (Files.size(resolved) > MAX_LOG_BYTES) {
            Files.move(resolved, resolved.resolveSibling(resolved.getFileName() + ".1"),
                    StandardCopyOption.REPLACE_EXISTING);
        }
    }
```

and call it from `toFile` (or from a size-aware appender if the handle is long-lived), keeping at least one retained generation so history is not simply discarded.

### SEC-06 — Bearer session token retained in an immutable `String`

**Severity:** Low

**CWE:** CWE-922: Insecure Storage of Sensitive Information

**Location:** `src/main/java/com/example/portal/auth/SessionManager.java:211`

**Vulnerable code:**

```java
// SessionManager.java:211
    public record Issued(String token, Session session) {
```

```java
// SessionManager.java:99-102 (the String survives at 104 and is returned at 111)
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        java.util.Arrays.fill(raw, (byte) 0);
```

**Why it is a problem:**

The raw bytes are erased, but the secret they encode is then copied into a `String` at line 101 and kept alive in two places: `Issued.token` and `AuthResult.token` (`AuthResult.java:28`, exposed by `sessionToken()` at `AuthResult.java:66-67`). `String` is immutable and uneraseable — it cannot be zeroed, it may be duplicated by concatenation, formatting, or debugging, and it is copied by `encodeToString` into an intermediate `char[]` that the caller cannot reach. In the in-process deployment that `PortalCli` models, the result object outlives the printed line and the token remains readable in the heap until collection, in a heap dump, or in a core file — while `SessionManager`'s own table deliberately stores only the SHA-256 digest precisely so the table cannot leak it. The component applies a stricter standard to the password (`PasswordHasher.derive` zeroes the derived key and clears the `PBEKeySpec`; `PortalCli` zeroes every password buffer in a `finally`) and to the hash (`StoredHash.toString()` redacts), so this is a policy inconsistency as much as an exposure. The `toString()` redaction on `Issued`, `Session`, and `AuthResult` is good and prevents accidental rendering, but redaction in `toString()` does not remove the field from memory.

Severity is Low because the token is short-lived (15-minute idle), the exposure requires local memory or dump access, and no `String` concatenation of the token exists in this codebase.

**Fix:**

Carry the token as eraseable characters, and confine the `String` to the shortest possible scope.

```java
// SessionManager.java — replace the record at line 211 and the return at line 111
    public static final class Issued {

        private final char[] token;
        private final Session session;

        Issued(char[] token, Session session) {
            this.token = token;
            this.session = session;
        }

        /** The caller must hand this to the transport and then call {@link #erase()}. */
        public char[] token() {
            return token.clone();
        }

        public Session session() {
            return session;
        }

        /** Erases the bearer value once it has been written to the response. */
        public void erase() {
            Arrays.fill(token, '\0');
        }

        @Override
        public String toString() {
            return "Issued[token=<redacted>, session=" + session + "]";
        }
    }
```

```java
// SessionManager.java:99-104 — decode straight into characters, no intermediate String
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        char[] token = Base64.getUrlEncoder().withoutPadding()
                .encode(raw).toCharArray();
        java.util.Arrays.fill(raw, (byte) 0);

        String digest = digestOf(new String(token));   // scope kept to this one expression
```

`SessionCookie.setCookieHeader` should accept `char[]` and `AuthResult` should hold the `Session` plus a one-shot reference rather than the token. If a `String` must remain for API ergonomics, document the residual risk in the same "Residual risk" section of `README.md` that already lists the other accepted exposures, rather than leaving the char[] policy apparently applied to only the password.

### SEC-07 — Prebuilt class files shipped with no provenance or integrity binding

**Severity:** Low

**CWE:** CWE-494: Download of Code Without Integrity Check

**Location:** `build.sh:15`

**Vulnerable code:**

```sh
# build.sh:7-8
# No third-party dependency is downloaded or required, so there is no artefact to verify and no
# chance of pulling code from an unexpected place. Everything used is in the Java standard library.

# build.sh:14-15
mkdir -p "$out"
javac -Xlint:all -Werror -d "$out" $(find src/main/java -name '*.java')
```

**Why it is a problem:**

The claim at lines 7-8 is true of the *build*, but the deliverable does not stop at source: it also contains 30 compiled artifacts under `out/classes/` and `out/test-classes/`, including `Authenticator.class`, `SessionManager.class`, and `PasswordHasher.class`. Nothing in the tree binds those bytes to the `src/` beside them — no checksum file, no manifest, no signature, no attestation, and no recorded toolchain version. A consumer who skips `./build.sh` and runs `java -cp out/classes com.example.portal.auth.PortalCli` executes code that cannot be shown to correspond to the audited source, and anything that modified those files en route would be undetectable without recompiling and diffing by hand. This matters more than usual here because the artifacts *are* the security control: swapping one class in a shipped `out/` tree is a quieter path to a backdoored authenticator than editing the `.java`, and the README's "no artefact to verify" framing discourages exactly the check that would catch it. The same tree ships compiled test classes, which no consumer should be running in production at all.

Severity is Low because anyone receiving the source can rebuild and compare, and because there is no evidence the binaries are stale or tampered with — the timestamps match the sources. The defect is the absence of verifiability, not observed divergence.

**Fix:**

Ship source only, or bind the artifacts to the source cryptographically.

```sh
# build.sh — record and verify what the compiled tree is supposed to contain
mkdir -p "$out"
javac -Xlint:all -Werror -d "$out" $(find src/main/java -name '*.java')

(cd out/classes && find . -name '*.class' -print0 | sort -z | xargs -0 sha256sum) > build-SHA256SUMS
echo "wrote build-SHA256SUMS"
```

```sh
# build.sh — refuse to run prebuilt classes that do not match the recorded digests
verify() {
    (cd out/classes && sha256sum -c ../../build-SHA256SUMS) || {
        echo "prebuilt classes do not match build-SHA256SUMS; rebuild from src/" >&2
        exit 1
    }
}
```

For a build that must be distributable, sign the digest list and have consumers verify it — the Sigstore/SLSA model in `verifying-build-provenance-with-slsa-sigstore` (keyless signing plus an attestation naming the source repository and builder identity). Simplest correct option: delete `out/` from the deliverable and let `./build.sh` be the only way to obtain classes, which is what the README's own argument implies. Also quote the `find` substitutions at lines 15 and 20 (`javac … -d "$out" $(find …)`) so a path containing whitespace cannot split into multiple arguments.

### SEC-08 — Cookie javadoc contradicts the emitted `Path`, on a `__Host-` correctness invariant

**Severity:** Low

**CWE:** CWE-1110: Incorrect Interaction Between Components / specification-consistency defect (documentation of a security invariant)

**Location:** `src/main/java/com/example/portal/auth/SessionCookie.java:21, 34`

**Vulnerable code:**

```java
// SessionCookie.java:21
 *   <li>{@code Path=/portal} -- scoped to the application rather than the whole origin, so it is not
```

```java
// SessionCookie.java:32-34
    /** The cookie name. A {@code __Host-} prefix additionally pins the cookie to this exact host. */
    public static final String NAME = "__Host-portal_session";
    private static final String PATH = "/";
```

**Why it is a problem:**

The class documentation lists `Path=/portal` as one of the attributes it applies, and the prose justifies it as narrowing the scope "rather than the whole origin". The code emits `Path=/` (`SessionCookie.java:58`, `65`), and `SelfTest.cookieAttributes` asserts `Path=/`. The code is the one that is right: RFC 6265bis / RFC 9651 require a `__Host-` prefixed cookie to carry `Path=/` in addition to `Secure` and no `Domain` attribute, so `Path=/portal` would make the browser reject the `Set-Cookie` outright.

The file therefore contradicts *itself*: 22 lines below the wrong claim, its own class javadoc states the correct invariant — `and {@code Path=/}; those are fixed here rather than parameterised so the prefix cannot be` weakened (`SessionCookie.java:43`). Two mutually exclusive statements about the same constant sit in one file, which is the real defect: the risk is not the emitted value but that a maintainer who reads the class-level bullet at `:21` instead of the one at `:43` will "fix" `PATH` to `/portal` to match the documentation. The cookie would then be silently dropped by every browser — the session stops being set at all — and because no test asserts the documented value, the symptom would surface as employees unable to stay signed in rather than as a failed assertion.

**Fix:**

Correct the documentation to state the invariant and why it is not negotiable.

```java
// SessionCookie.java:21 — replace the bullet
 *   <li>{@code Path=/} -- required by the {@code __Host-} prefix. A narrower path makes the browser
 *       reject the cookie entirely, so this is not a scope knob; host-only isolation comes from the
 *       omitted {@code Domain} attribute instead.
```

Add the paired regression test so the two cannot drift again:

```java
// SelfTest.java — inside cookieAttributes()
        check(SessionCookie.setCookieHeader(token, Duration.ofMinutes(15)).contains("Path=/;"),
                "a __Host- cookie must use Path=/ or the browser rejects it");
```

### SEC-09 — Stdin decoded byte-by-byte as Latin-1; committed secret differs from typed secret

**Severity:** Low

**CWE:** CWE-172: Encoding Error

**Location:** `src/main/java/com/example/portal/auth/PortalCli.java:301-315`

**Vulnerable code:**

```java
// PortalCli.java:301-315
    private static char[] readBoundedChars() throws IOException {
        int limit = InputPolicy.PASSWORD_MAX_LENGTH;
        char[] buffer = new char[limit];
        int length = 0;
        int c;
        while ((c = System.in.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (length == limit) {
                Arrays.fill(buffer, '\0');
                throw new IOException("input line exceeds the accepted length");
            }
            buffer[length++] = (char) c;
        }
```

**Why it is a problem:**

`System.in.read()` yields a byte; the cast at line 314 turns each byte above `0x7F` into the `char` of the same code point, which is a Latin-1 decode of what a terminal almost certainly sent as UTF-8. A passphrase containing one non-ASCII character is therefore enrolled as a different sequence than the operator typed: `é` (two UTF-8 bytes, `0xC3 0xA9`) becomes `Ã©` (two `char`s). Because `PasswordHasher` hashes the `char[]` as UTF-8, the stored hash commits to the mojibake form, not to the passphrase. `requireEnrollablePassword` does not prevent this — its loop only rejects `c < 0x20 || c == 0x7F` (`InputPolicy.java:101-103`), so characters above `0x7F` are accepted at enroll despite the same method's `@throws` line describing the rule as "not printable ASCII" (`InputPolicy.java:91`).

Enroll and login through this same CLI mangle identically, so the credential keeps working locally; it breaks at the boundary. The first party to type that passphrase into a correctly-implemented UTF-8 front end submits the intended characters, computes a different pre-image, and is denied — an account that is permanently unreachable by its legitimate holder, discovered only when someone actually needs to log in. The same cast makes the effective length cap 256 *bytes* rather than the 256 *characters* `InputPolicy` documents, and there is no Unicode normalisation anywhere in the path, so NFC and NFD spellings of one visually identical passphrase hash to different credentials across platforms. The zeroing discipline in this method is otherwise correct and deliberate; the encoding is the defect.

**Fix:**

Decode the bytes as UTF-8 into characters, and normalise so the same typed passphrase always reaches the KDF identically.

```java
// PortalCli.java — replace readBoundedChars() at lines 301-319
    private static char[] readBoundedChars() throws IOException {
        int limitBytes = InputPolicy.PASSWORD_MAX_LENGTH * 4;   // UTF-8 upper bound per character
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        int c;
        while ((c = System.in.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (raw.size() == limitBytes) {
                raw.reset();
                throw new IOException("input line exceeds the accepted length");
            }
            raw.write(c);
        }
        byte[] bytes = raw.toByteArray();
        raw.reset();
        try {
            CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            char[] line = Normalizer.normalize(decoded, Normalizer.Form.NFKC).array();
            Arrays.fill(bytes, (byte) 0);
            return line.length > InputPolicy.PASSWORD_MAX_LENGTH ? new char[0] : line;
        } catch (CharacterCodingException e) {
            Arrays.fill(bytes, (byte) 0);
            throw new IOException("input is not valid UTF-8", e);
        }
    }
```

Then make the length rule that is actually documented match the code: either reject characters above `0x7E` explicitly in `requireEnrollablePassword` if ASCII-only credentials are the intent, or correct that javadoc and keep the wider charset. The front end that real employees type into must apply the same decode-and-normalise rule, or enrolled and submitted passphrases will keep disagreeing.

## 6. Verified Controls and Checks With No Finding

Confirmed by reading the code, not by trusting `README.md` or the test names:

- **Key derivation.** `PBKDF2WithHmacSHA256`, 600,000 iterations by default (`PasswordHasher.DEFAULT_ITERATIONS`), 16-byte `SecureRandom` salt, 256-bit derived key. `parse()` rejects any stored record whose iteration count falls outside 100,000–10,000,000, so a hostile credential file cannot downgrade a hash to 1 iteration — and `SelfTest.malformedRecordsDropped` exercises exactly that (`trickster:pbkdf2-sha256$1$…`). Salt and hash are length- and encoding-validated; `StoredHash` clones its arrays and `toString()` redacts.
- **Comparison and timing.** Verification uses `MessageDigest.isEqual`, which is constant-time for equal-length inputs and prevents a byte-by-byte early exit. Both the unknown-account and the limited-account paths pay one derivation (`Authenticator.java:87`, `94`, via `performDecoyWork()`), so the directory cannot be enumerated by response time and a restriction cannot be used as an oracle.
- **Password handling in memory.** The KDF zeroes the derived key in a `finally` and calls `PBEKeySpec.clearPassword()`; `PortalCli` zeroes every password and username buffer in a `finally`; the submitted `char[]` is cleared by its owner (`PortalCli`), which is why `Authenticator` correctly does not clear it; `Arrays.fill` is applied to the token's raw bytes and to the appended record bytes.
- **Command-line secret hygiene.** `--password` and `--password=` are refused with exit status 2 and a message telling the operator to rotate the credential (`SelfTest.noPasswordOnCommandLine`); secrets come only from stdin.
- **Session tokens.** 32 `SecureRandom` bytes → 43-character unpadded Base64url; the lookup table is keyed by SHA-256 of the token, so a table dump does not yield usable bearer values; `hasTokenShape` rejects wrong length and non-alphabet characters before any map access, so `validate(null)`, `""`, a username, a mutated token, and a path all return empty; idle (15 min) and absolute (8 h) expiry are both enforced; validate-then-act runs inside `ConcurrentHashMap.compute`, so an expired session cannot be resurrected concurrently; `MAX_SESSIONS = 20_000` is enforced after pruning; a digest collision raises rather than overwrites.
- **Cookie attributes.** `__Host-portal_session` with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, `Max-Age`, and no `Domain=` — the `__Host-` invariants all hold (see SEC-08 for the documentation defect, not the emitted value); `setCookieHeader` refuses a token that does not match `hasTokenShape` and a non-positive `Max-Age`, so a malformed value cannot be laundered into a header.
- **Input validation.** All three externally supplied values pass a whitelist before use: no free-form characters, no CR/LF, no `:`, no `;`, no NUL, no path separators, no `..` traversal (`SelfTest.invalidInputRejected` covers `../../etc/passwd`, `new\nline`, `alice:smith`, `alice\u0000smith`, and over-length values). Rejected input consumes no attempt budget, which is why it cannot be used to lock out a legitimate employee. Password length is bounded *before* the KDF, so an oversized submission cannot be used as a CPU weapon.
- **Credential file parsing.** 8 MiB / 50,000-record / 512-char-per-line ceilings; records split on the first `:` so a username cannot smuggle fields; malformed records are dropped and counted; a duplicate account is fatal rather than last-or-first-wins; the parsed map is immutable and `find()` performs no I/O, so post-load validation cannot be raced.
- **Rate-limit integrity.** The slot is reserved before verification (`Authenticator.java:83`), so no verification error path leaks a free guess and a burst cannot be settled later; the source budget is drawn before the account budget; `giveBack()` on success stops a successful login from contributing to a source lockout; `windowStart` and `restrictedUntil` are clamped against clock skew so a rolled-back or advanced clock cannot erase a restriction; `ReentrantLock` plus an exclusive `FileLock` serialise both intra- and inter-process updates, with `SelfTest.concurrentAttemptsRespectBudget` (32 threads) and `concurrentFileBackedAttemptsRespectBudget` (16 threads) asserting exactly 5 grants rather than `OverlappingFileLockException`; `parseInto()` range-checks every persisted field, so a tampered state file cannot smuggle a negative or absurd counter; `SelfTest.restrictionSurvivesRestart` confirms persistence.
- **Fail-closed behaviour.** An unreadable or unwritable tracker yields `UNAVAILABLE`, and `Authenticator` denies rather than proceeding uncounted (`SelfTest.trackerFailsClosed`); an unusable tracker, an over-capacity session table, a broken RNG, and a duplicate credential record all raise rather than degrade quietly.
- **File privacy.** Mode `rw-------` is applied at creation time through a `PosixFileAttributeView` file attribute rather than create-then-chmod, closing the umask window; mode, regular-file-ness, and parent-directory world-writability are re-verified on every use (`PrivateFiles.java:64-89`, and again per transaction in `FileAttemptLimiter.java:157`); a non-POSIX filesystem is refused outright rather than assumed safe; `NOFOLLOW_LINKS` is used throughout so the checks cannot be redirected by a symlink. The owner comparison itself is SEC-02.
- **Audit log content.** Accounts mask to `a***(len=11)` and sources to the first three octets / three groups; fields are truncated at 200 characters; control characters and `0x7F` are mapped to `.` after masking, so neither a newline-embedded fake entry nor a terminal escape sequence survives; passwords, hashes, and session tokens never reach the sink; `toString()` redacts in `AuthResult`, `Session`, `Issued`, and `StoredHash` (`SelfTest.logHoldsNoSecrets`, `toStringNeverLeaks`); `ValidationException` messages are documented as audit-log-only and are never returned to the unauthenticated caller.
- **No injection or execution surface.** No shell invocation, no `Runtime.exec`, no reflection over user input, no deserialization, no template or SQL construction, no third-party dependency, and no network client. `FileLock` is held for its block's whole lifetime (`@SuppressWarnings("try")` is correct here — JDK 17 would otherwise reclaim an unused lock). No secrets, tokens, hostnames, or credentials appear in source or in `build.sh`.
- **Build discipline.** `set -eu`, `-Xlint:all -Werror`, JDK-only, so a warning is a build failure and there is no dependency to compromise. The unquoted `$(find …)` at `build.sh:15` and `:20` is a robustness nit folded into SEC-07's fix rather than a separate finding.

**Coverage note:** the review was static, as instructed — `build.sh test` was not run, so the 20 self-tests are asserted to exist and to be written against the right properties, not observed to pass. `out/**/*.class` was not decompiled or compared against `src/` (SEC-07 recommends the mechanism rather than claiming divergence).
