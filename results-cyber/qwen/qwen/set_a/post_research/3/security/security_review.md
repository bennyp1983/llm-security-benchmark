# Security Review: Java CLI Authentication Service (`com.example.auth`) with Embedded H2

## 1. Executive Summary

This is a static review (read-only; nothing in the source tree was executed, built, or imported) of a
Java 17 command-line authentication service backed by an embedded H2 file database. The service supports
`seed`, `login`, `logout`, `resolve` and `purge`, issues bearer session tokens, and enforces per-account
and per-source attempt throttling.

The code is, on the whole, unusually defensive for generated code: every SQL value is bound through a JDBC
placeholder, every dynamic identifier passes an allowlist and is double-quoted, the JDBC connect URL is
protected against `;INIT=` parameter injection by refusing `;` and `=` in the configured path (and this
refusal is empirically demonstrated in `.probe/Probe.java`), log lines are built from a fixed vocabulary
plus a CR/LF-excluding allowlist charset, POSIX permission checks are made on mode bits rather than by
probing accessibility (correctly recognising that root bypasses permission bits), and the failure paths are
overwhelmingly fail-closed. No SQL injection, no log forging, no hardcoded secret, and no reachable TOCTOU
race were found — see §6 for what was checked and passed.

Nine findings are reported, none of them trivially exploitable for account takeover, but one of them is a
straightforward availability and control-bypass defect worth fixing first: malformed input is rejected
**before** the throttle reservation is taken, so an unauthenticated attacker can make the service perform a
full 210,000-iteration PBKDF2 derivation and sleep for the full `min_login_ms` floor as many times as they
like, without spending a single throttle slot. The rate limiter the design is built around simply does not
apply to input that fails syntax validation. The remaining findings cover a caller-controlled throttle key
that lets the per-source limit be reset at will, a password-hash work factor below current OWASP guidance,
an unsalted SHA-256 of the e-mail address used as the database identity key, a brief window in which the
H2 data file exists with the process umask before being chmod-ed to 0600, a session-cookie lifetime that is
hard-coded while the server-side TTL is configurable, a startup refusal path that escapes its own handler
and prints a stack trace with the wrong exit code, an audit log that fails open with no signal beyond one
stderr line, and a storage credential materialised as an un-zeroable `String`.

A number of these are explicitly acknowledged as residual risks in the project's own `THREAT-MODEL.md`
(R6 for the throttle key, R7 for the unsalted address hash). They are still reported here, at reduced
severity, because an acknowledged risk is not the same as a mitigated one, and the documented note in
§6 records where the threat model and the code disagree.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/Main.java` | CLI entry point: env/argv parsing, credential prompting, command dispatch, exit codes | Reads the storage credential from a `char[]`/console rather than argv; calls `Runtime.halt()` to suppress shutdown hooks; prints a bearer session token to stderr only when `AUTH_EMIT_SESSION=true`; refuses a non-UTF-8 console |
| `AuthService.java` | Orchestration of `seed`/`login`/`logout`/`resolve`/`purge`; equal-work login; constant-time response floor | Validates then throttles then verifies; hashes the e-mail unsalted to form the DB identity key; refunds only the identity budget on success; pads every login to `min_login_ms` |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256 derive/verify, per-account random salt, "blind salt" for equal work | `PBKDF2WithHmacSHA256`, 16-byte `SecureRandom` salt, 256-bit digest, iteration bounds 100,000–1,500,000, default 210,000; `PBEKeySpec.clearPassword()` in `finally`; constant-time compare |
| `ThrottleStore.java` | Fixed-window attempt counters per identity and per source | `SELECT … FOR UPDATE` + `synchronized(conn)` + key-sorted reservation; refusal by rollback; conditional `UPDATE … WHERE used > 0` refund; rejects negative counters |
| `SessionStore.java` | Issue, resolve, revoke, purge of opaque session tokens | 32 `SecureRandom` bytes issued, only SHA-256 of the token stored, expiry checked in SQL, single `DELETE` used as check-and-act; hard-coded cookie attribute string |
| `Database.java` | Opens two H2 connections, schema creation, statement/file helpers | Builds the JDBC URL by concatenating a guarded path plus fixed options; hardens engine files to 0600 *after* H2 creates them; materialises the DB password as a `String` |
| `DbPathGuard.java` | Fail-closed checks on the storage directory and files | Rejects symlinks, group/world bits, foreign owners, non-canonical paths; checks mode bits rather than readability because root bypasses them |
| `DbFiles.java` | Private file creation and tightening | `CREATE_NEW` then harden then re-verify; refuses symlinks; `0600` files, `0700` directories |
| `PosixPermissions.java` | Mode-bit helpers | `OWNER_ONLY = rw-------`, `OWNER_ONLY_DIR = rwx------`; requires the POSIX view to be supported |
| `InputValidator.java` | Allowlist validation for every external input | Printable-ASCII e-mail grammar with length caps and punycode refusal; password control-char/edge-space/unpaired-surrogate/UTF-8-length rules; identifier, token, integer, boolean and DB-path allowlists |
| `CryptoUtils.java` | `SecureRandom`, SHA-256, constant-time compare, hex, buffer wipe | One shared `SecureRandom`; length-folded constant-time equality; no MD5/SHA-1/ECB/hardcoded keys anywhere |
| `LogWriter.java` | Append-only audit trail with fixed event vocabulary | Rejects (never escapes) anything outside an allowlist charset that excludes CR/LF; masks e-mails to `f***@domain`; caps line length and total bytes; refuses a symlinked log; creates it 0600 |
| `Config.java` | Parses and bounds every `AUTH_*` environment variable | Clamps/range-checks all limits; refuses `source_max < identity_max`; refuses a non-canonical/relative/`..`/`;`/`=` DB path; `AUTH_EMIT_SESSION` defaults to `false` |
| `AccountSeeder.java` | Creates an account row from validated inputs | Validates before hashing; inserts salt+digest+`active`; maps SQLState `23*` to a clean duplicate error; wipes salt and digest buffers |
| `src/test/java/com/example/auth/AllTests.java` | Unit tests for validators, crypto helpers, masking, log sanitisation | Asserts the allowlists actually reject the payloads they claim to (traversal, CRLF, NUL, `;INIT=`, unpaired surrogates, `..`) |
| `src/test/java/com/example/auth/AuthServiceTests.java` | Behavioural tests: outcomes, timing floor, tampered rows, budget atomicity | Covers tampered `pw_algo`/`pw_iterations`/`status` rejection and 400-threads-on-1-budget atomicity |
| `src/test/java/com/example/auth/E2ETests.java` | End-to-end CLI runs through `Main.run` | Covers `storage_credential_unavailable`, `source_max_below_identity_max`, session-token emission |
| `src/test/java/com/example/auth/T.java` | Shared test harness/assert helpers | Test-only; no production surface |
| `.probe/Probe.java` | Generation-time H2 verification harness (not part of the shipped service) | Empirically proves `ACCESS_MODE_DATA=rw-------` effects, that `;INIT=RUNSCRIPT` is refused, and the `FOR UPDATE`/conditional-UPDATE/concurrency semantics relied on above |
| `THREAT-MODEL.md` | Declared trust boundaries (I1–I13) and residual risks (R1–R8) | Documents R6 (caller-supplied `AUTH_SOURCE_ID`), R7 (unsalted address hash), R8 (embedded H2, no TLS); one claim disagrees with the code — see §6 |
| `libs/h2-2.3.232.jar` (+ `.sha1`, `.sha256`) | Third-party database dependency with published digests | Digest files permit integrity verification of the pinned dependency; the library itself was not audited |

Not reviewed: `prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` (run metadata, no code) and `out/`
(compiled output of the reviewed sources).

## 3. Skills Applied

| Skill | Why it matched | What it contributed |
|---|---|---|
| `review-code-for-security-vulnerabilities` | Router for the whole task | Understand-then-match workflow, findings format, CWE mapping |
| `performing-cryptographic-audit-of-application` | PBKDF2 parameters, salt generation, constant-time compare, token entropy, unsalted address digest | SEC-03 (KDF work factor), SEC-04 (unsalted identity hash); confirmed the absence of MD5/SHA-1/ECB/hardcoded keys and the presence of a CSPRNG and a length-folded constant-time comparison |
| `performing-hash-cracking-with-hashcat` | Assessing the real cost of an offline attack against the stored PBKDF2 digests | SEC-03 severity calibration against 210,000 / 100,000 iteration configurations |
| `testing-api-authentication-weaknesses` | The service is an authentication interface: attempt limiting, token validation, session lifetime, credential exposure | SEC-01 (throttle applied after input validation), SEC-02 (spoofable throttle key), SEC-06 (session lifetime mismatch) |
| `testing-for-broken-access-control` | `resolve`/`logout` operate on a caller-supplied token; status and expiry must be re-checked server-side | Verified expiry-in-SQL, single-`DELETE` revocation, and re-validation of `status` on every login; no finding |
| `exploiting-race-condition-vulnerabilities` | Throttle reservation, budget refund and session revocation are all check-and-act operations | Verified `SELECT … FOR UPDATE`, key-sorted deadlock-free acquisition, `synchronized` on the shared transaction connection, conditional `UPDATE … WHERE used > 0`, and row-count-as-decision `DELETE`; corroborated by `.probe/Probe.java`; no finding |
| `exploiting-sql-injection-vulnerabilities` | Table names and the JDBC URL are configuration-derived | Verified identifier allowlist plus double-quoting, universal `?` binding, and the `;`/`=` refusal on `AUTH_DB_PATH`; no finding |
| `implementing-secrets-scanning-in-ci-cd` | Generated code frequently leaks defaults, and the credential flows from env to console | No hardcoded secret found; SEC-09 for the `String`-typed JDBC credential left in the heap |
| `detecting-sensitive-data-exposure` | Session token printing, e-mail masking, audit-log content | Confirmed the token never reaches the audit log and the mask is lossy; SEC-08 for the fail-open audit writer |

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Malformed input is throttled *after* it is validated, so invalid input runs unthrottled at full KDF cost | High | CWE-307 / CWE-400 | `AuthService.java:126` vs `:131-135`, `:168-173`, `:178` |
| SEC-02 | Per-source throttle budget is keyed on a caller-supplied label, so the source limit is resettable | Medium | CWE-290 / CWE-770 | `Config.java:50`, `:154-160`; `ThrottleStore.java:298-302`; `AuthService.java:130-131` |
| SEC-03 | PBKDF2 iteration default (210,000) and accepted floor (100,000) are below current OWASP guidance | Medium | CWE-916 | `PasswordHasher.java:29`; `Config.java:39` |
| SEC-04 | Unsalted SHA-256 of the e-mail address is the database identity key | Low | CWE-522 | `AuthService.java:182-185` |
| SEC-05 | H2 data file is created with the process umask and tightened only afterwards | Low | CWE-732 | `Database.java:76-81`, `:106`, `:178-199` |
| SEC-06 | Cookie `Max-Age` is hard-coded to 900 while the server-side TTL is configurable to 86,400 | Low | CWE-613 | `SessionStore.java:151-152`; `Config.java:143` |
| SEC-07 | `BootRefusal` thrown from a try-with-resources *resource expression* escapes its own handler | Low | CWE-703 | `Main.java:103`, `:120-121`, `:249`; `:60-65` |
| SEC-08 | Audit-log write failure is swallowed with a single stderr line and no signal | Low | CWE-778 | `LogWriter.java:138-146` |
| SEC-09 | Storage credential is materialised as an un-zeroable `String` for the JDBC connection | Low | CWE-316 | `Database.java:84-86`, `:115` |

## 5. Detailed Findings

### SEC-01 — Malformed input is throttled *after* it is validated, so invalid input runs unthrottled at full KDF cost

**Severity:** High

**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), with CWE-400
(Uncontrolled Resource Consumption) as the availability consequence.

**Location:** `src/main/java/com/example/auth/AuthService.java:126` (validation) versus `:131-135`
(throttle reservation); the unthrottled expensive path is `:168-173` and `:178`.

**Vulnerable code:**

```java
        try {
            String normalised = InputValidator.requireEmail(email);
            masked = LogWriter.maskEmail(normalised);
            String identityHash = identityHash(normalised);

            List<ThrottleStore.BudgetKey> budgets =
                    ThrottleStore.attemptBudgets(identityHash, config.sourceId(), config);
            boolean slot;
            boolean budgetKnown = true;
            try {
                slot = throttles.reserve(budgets, clock.epochMillis());
```

```java
        } catch (InputValidator.ValidationException e) {
            reason = e.getMessage() != null && e.getMessage().startsWith("password")
                    ? Reason.INVALID_PASSWORD : Reason.INVALID_EMAIL;
            log.log(LogWriter.Event.LOGIN_INVALID_INPUT, masked, reason.code());
            workEqualDerivation(null);
        } catch (RuntimeException e) {
            reason = Reason.INTERNAL;
            log.log(LogWriter.Event.LOGIN_INTERNAL, masked, reason.code());
            workEqualDerivation(null);
        }
        long elapsedNanos = padToFloor(start);
```

**Why it is a problem:**

`InputValidator.requireEmail(email)` at line 126 throws `ValidationException` for anything that fails the
grammar — no `@`, a non-printable character, an over-long local part, a punycode label. Control jumps
straight to the handler at line 168, which is **above** the `throttles.reserve(...)` call at line 135. That
means the reservation is never taken, no budget row is incremented, and no window is ever consumed. An
attacker who sends `curl`-style garbage — an empty address, `a@`, `a b@c`, a 300-character local part — can
repeat the request indefinitely. There is no counter to exhaust, so the identity budget and the source
budget are both irrelevant to this class of request.

The rejected request is not cheap. The handler calls `workEqualDerivation(null)`, which performs a real,
full-cost derivation against the fixed work sample:

```java
    private void workEqualDerivation(String normalisedEmail) {
        byte[] salt = normalisedEmail == null
                ? FIXED_BLIND_SALT
                : PasswordHasher.blindSalt(normalisedEmail);
        try {
            hasher.derive(WORK_SAMPLE, salt, config.iterations());
```

With `DEFAULT_ITERATIONS = 210_000` (`Config.java:39`) that is 210,000 HMAC-SHA256 rounds on the CPU. Then
line 178 calls `padToFloor(start)`, which sleeps and then spin-waits until `config.minLoginMs()` — default
1,000 ms — has elapsed. So every unthrottled request costs roughly one CPU-second's worth of derivation work
plus a thread parked in `Thread.sleep`, held for at least a full second.

Two consequences follow. First, the design's own rate-limiting control is bypassable by the simplest
possible means: stop typing valid addresses. Second, the bypass converts directly into an availability
problem — a handful of concurrent connections is enough to saturate every available core and pin every
thread in the pool, while legitimate users see `min_login_ms` latency turn into queueing delay. The
`LOGIN_INVALID_INPUT` audit line is still written per attempt, so the log volume also grows without bound
until `MAX_TOTAL_BYTES` (4 MB) is reached, at which point logging degrades as well.

The equal-work design is deliberate and correct as a *timing-side-channel* mitigation — a probe for a
non-existent account must cost the same as a probe for a real one. The defect is not that the work is done;
it is that the work is done *without first spending a throttle slot*, so the cost is imposed on the service
rather than on the attacker.

**Fix:**

Take the reservation before doing any key-derivation work, using a budget key that can be computed from
*any* input, including syntactically invalid input. A cheap keyed hash of the raw address bytes gives a
stable key without needing the address to be valid, and the identity budget can still be charged on the
normalised form once validation succeeds.

```java
    Result authenticate(String email, char[] password) {
        long start = System.nanoTime();
        Outcome outcome = Outcome.DENIED;
        Reason reason;
        String token = null;
        String masked = "*";

        // Reserve capacity for EVERY request, valid or not, before doing any KDF work. The
        // request key is a keyed hash of the raw bytes, so it exists even for input that will
        // later fail the e-mail grammar.
        String requestKey = CryptoUtils.toHex(
                CryptoUtils.sha256(PasswordHasher.utf8(String.valueOf(email == null ? "" : email))));
        List<ThrottleStore.BudgetKey> budgets =
                ThrottleStore.requestBudgets(requestKey, config.sourceId(), config);
        boolean slot;
        try {
            slot = throttles.reserve(budgets, clock.epochMillis());
        } catch (Database.StorageException e) {
            logDbFailure(e);
            slot = false;
        }
        if (!slot) {
            reason = Reason.BUDGET_SPENT;
            log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
            workEqualDerivation(null);          // equal work, but now it is a *paid* attempt
            return new Result(Outcome.DENIED, reason, null, padToFloor(start) / 1000L);
        }

        try {
            String normalised = InputValidator.requireEmail(email);
            // ... existing verified path, unchanged ...
```

If a per-request key is considered too coarse, the minimum acceptable change is to add a request-key budget
alongside the existing two in `ThrottleStore.attemptBudgets` and take it first. What must not happen is the
current ordering, in which the cheapest possible input classification decides whether the rate limiter runs
at all.

### SEC-02 — Per-source throttle budget is keyed on a caller-supplied label, so the source limit is resettable

**Severity:** Medium

**CWE:** CWE-290 (Authentication Bypass by Spoofing) — the attacker controls the identity the counter
attributes them to — leading to CWE-770 (Allocation of Resources Without Limits or Throttling).

**Location:** `Config.java:154-160` (source id accepted from the environment) with its default at
`Config.java:50`; `ThrottleStore.java:298-302`
(the key is just a hash of that label); `AuthService.java:130-131` (that key is charged per attempt).

**Vulnerable code:**

```java
        String sourceId;
        try {
            sourceId = InputValidator.requireSourceId(
                    orDefault(env.get(ENV_SOURCE_ID), DEFAULT_SOURCE_ID));
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("source_" + e.getMessage());
        }
```

```java
    private static final String DEFAULT_SOURCE_ID = "local-cli";
```

```java
    /**
     * The source budget key is a hash of the source label so its length is fixed and it cannot
     * smuggle characters into the key column. The label itself is validated before it reaches here,
     * and remains attacker-influenceable - see residual risk R6 in THREAT-MODEL.md.
     */
    static BudgetKey sourceBudget(String sourceId, int limit, int windowSec) {
        String h = CryptoUtils.toHex(CryptoUtils.sha256(
                PasswordHasher.utf8(sourceId))).substring(0, 32);
        return new BudgetKey(SOURCE_PREFIX + h, limit, windowSec * 1000L);
    }
```

**Why it is a problem:**

The two-tier throttle exists precisely so that an attacker who rotates across many accounts cannot hammer the
service: the identity budget stops `account-A` from being tried more than `AUTH_IDENTITY_MAX_FAILURES`
(default 8) times per window, and the source budget stops `this origin` from making more than
`AUTH_SOURCE_MAX_ATTEMPTS` (default 120) attempts in total across any accounts. `Config.java:150-151` even refuses a
configuration in which the source budget would be smaller than the identity budget, which shows the source
tier is meant to be the load-shedding layer.

But the "source" is `AUTH_SOURCE_ID`, a value the operator (or, in the deployment this file describes, the
process that launches the CLI) chooses and which defaults to the constant `"local-cli"`. There is no
cryptographic or infrastructural binding between a real network origin and that string. In any deployment
where the caller can influence it — a wrapper that maps a client address, a header, or a request field onto
`AUTH_SOURCE_ID` — the counter is trivially defeated by changing the label: attempt 121 carries
`source-2`, attempt 241 carries `source-3`. Hashing the label adds length safety but no authenticity, and
the code itself flags the gap. The result is that the tier designed to bound total abuse bounds nothing,
leaving only the per-account budget, which is exactly the lockout weapon the two-tier design exists to keep
away from attackers: with the source tier defeated, an attacker can spend a victim's 8-slot identity budget
at leisure and lock the legitimate owner out of their own account.

This is Medium rather than High because it requires a deployment that derives `AUTH_SOURCE_ID` from
attacker-influenced data. In the literal CLI as shipped, one process equals one source and the tiering is
moot — but that is a property of how the binary happens to be invoked, not of the control.

**Fix:**

Do not let the throttle key be free text. Bind it to something the caller cannot choose per-request, and
refuse to run an unbound source tier at all.

```java
        String sourceId = orDefault(env.get(ENV_SOURCE_ID), "");
        if (sourceId.isEmpty()) {
            // No bound origin means no usable source tier: fail closed rather than
            // silently sharing one bucket with every other caller.
            throw new ConfigException("source_id_unbound");
        }
        // The value must be a server-derived label (authenticated client id, or a source
        // address the trusted front end attested), never a client-supplied string.
        if (orDefault(env.get(ENV_SOURCE_ID_ATTESTED), "false").equals("false")) {
            throw new ConfigException("source_id_unattested");
        }
        sourceId = InputValidator.requireSourceId(sourceId);
```

Pair this with a non-attributable global ceiling that no caller can step outside by renaming itself, so that
total attempt volume is always bounded even when source attribution is absent or wrong.

### SEC-03 — PBKDF2 iteration default (210,000) and accepted floor (100,000) are below current OWASP guidance

**Severity:** Medium

**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort).

**Location:** `PasswordHasher.java:29` (`MIN_ITERATIONS`), `Config.java:39` (`DEFAULT_ITERATIONS`).

**Vulnerable code:**

```java
    static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    static final int SALT_BYTES = 16;
    static final int DERIVED_BITS = 256;
    static final int DERIVED_BYTES = DERIVED_BITS / 8;
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 1_500_000;
```

```java
    static final int DEFAULT_ITERATIONS = 210_000;
```

**Why it is a problem:**

The construction is right — per-account 16-byte `SecureRandom` salt, 256-bit derived key, HMAC-SHA256 — so
this is purely a work-factor finding. OWASP's Password Storage Cheat Sheet currently recommends **310,000**
iterations as the minimum for PBKDF2-HMAC-SHA256, and prefers Argon2id (m=19 MiB, t=2, p=1) where available.
The shipped default of 210,000 is about 68 % of that minimum, and `MIN_ITERATIONS = 100_000` means an
operator can set `AUTH_ITERATIONS=100000`, `Config.java:134-135` will accept it, and every account
seeded thereafter is protected at roughly one third of the recommended cost.

The practical effect is bounded but real: an attacker who obtains the H2 file (mitigated by the 0600 file and
0700 directory, but not beyond — see SEC-05 for the window, and the file is a normal backup target) cracks
each digest about 3× faster than the guidance assumes at 100,000 iterations and about 1.5× faster at the
210,000 default. Combined with the fact that `MIN_ITERATIONS` is a *floor on user choice* rather than a
minimum enforced by the code, the finding is that the safe configuration is the default but not the
mandated minimum.

It is Medium, not High, because the primitive itself is sound, the salts are unique and long enough to
prevent rainbow-table reuse across accounts, and exploitation first requires theft of the database file.

**Fix:**

Raise the accepted floor to the current guidance and the default above it, so an operator cannot configure a
sub-standard cost without a code change.

```java
    // OWASP Password Storage Cheat Sheet minimum for PBKDF2-HMAC-SHA256 is 310,000
    // iterations; the floor is that minimum and the default sits above it.
    static final int MIN_ITERATIONS = 310_000;
    static final int MAX_ITERATIONS = 1_500_000;
```

```java
    static final int DEFAULT_ITERATIONS = 600_000;
```

`Config.java:134-135` already clamps against `MIN_ITERATIONS`/`MAX_ITERATIONS`, so no other change is needed
to enforce it. Note that `AuthService` re-reads `pw_iterations` per row and re-derives with the stored count,
so existing accounts keep verifying at their original cost — but such accounts should be rehashed on next
successful login, and any account seeded while `pw_iterations` was permitted to be 100,000 should be
considered for forced rotation. Longer term, migrating to Argon2id via Bouncy Castle removes the iteration
guessing entirely.

### SEC-04 — Unsalted SHA-256 of the e-mail address is the database identity key

**Severity:** Low

**CWE:** CWE-522 (Insufficiently Protected Credentials) — the identity attribute is stored in a form that is
trivially reversible by exhaustive search.

**Location:** `AuthService.java:182-185`.

**Vulnerable code:**

```java
    /** SHA-256 of the normalised address; the only form of the address ever sent to the database. */
    static String identityHash(String normalisedEmail) {
        return CryptoUtils.toHex(CryptoUtils.sha256(PasswordHasher.utf8(normalisedEmail)));
    }
```

**Why it is a problem:**

The intent is good: keeping the address out of the credential store means a dump of the H2 file yields
pseudonyms rather than a customer list. But SHA-256 over a low-entropy, dictionary-shaped domain is not a
one-way function in practice. E-mail addresses are drawn from a small space — for any organisation, the
set of plausible addresses is in the tens of thousands — and this hash is **unsalted and deterministic**, so
one attacker can precompute `SHA-256(localpart@domain)` for every address they care about once and reuse the
table forever, across every deployment of this code and every leaked copy of the database. Recovering the
addresses behind an entire dump costs seconds of GPU work.

That converts the pseudonym into the plaintext for most real targets. It also makes the identity budget an
enumeration oracle at a distance: because the key is deterministic, an attacker holding a dump can tell
whether two databases, or two tables, contain the same person, and can pre-compute the exact throttle key
for a chosen victim before ever touching the service.

The residual risk is acknowledged in `THREAT-MODEL.md` as R7, which is why this is Low: within a single
tenant with no cross-tenant requirement, the exposure is the address list, not the credential. It is still
reported because a one-line change removes almost all of it.

**Fix:**

Make the key keyed rather than plain, using a secret the database dump does not contain, so the precomputation
table has to be rebuilt per deployment.

```java
    /**
     * HMAC of the normalised address under a deployment secret. A stolen dump yields
     * nothing an attacker can precompute against, because the key is not in the dump.
     */
    static String identityHash(String normalisedEmail) {
        return CryptoUtils.toHex(CryptoUtils.hmacSha256(
                config.identityPepper(), PasswordHasher.utf8(normalisedEmail)));
    }
```

Store the pepper outside the data directory (same 0700/0600 discipline as `DbFiles.newPrivateFile`, or an
environment/KMS secret), and treat rotation as a re-seed event because existing keys and throttle rows would
no longer match.

### SEC-05 — H2 data file is created with the process umask and tightened only afterwards

**Severity:** Low

**CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource) — a TOCTOU window between creation
with permissive bits and the subsequent `chmod`.

**Location:** `Database.java:76-81` (connect), `:106` (`hardenEngineFiles()` called after), `:178-199` (the
tightening itself, including the `Database.java:88-91` connect call).

**Vulnerable code:**

```java
        try {
            conn = DriverManager.getConnection(url, props);
            conn.setReadOnly(false);
            conn.setAutoCommit(true);
```

```java
            Database db = new Database(conn, txConn, quote(config.accountTable()),
                    quote(config.throttleTable()), quote(config.sessionTable()), dbFile);
            conn = null;
            txConn = null;
            db.ensureSchema();
            db.hardenEngineFiles();
            return db;
```

```java
    /**
     * H2 creates {@code .mv.db} (and any trace/temporary file) with the process umask, which is
     * 0644 on the reference platform. Re-assert 0600 on every file the engine owns in our directory.
     */
    void hardenEngineFiles() {
        Path parent = dbFile.getParent();
        if (parent == null) {
            return;
        }
        String prefix = dbFile.getFileName().toString();
        try (var stream = Files.newDirectoryStream(parent)) {
            for (Path p : stream) {
                String name = p.getFileName().toString();
                if (name.startsWith(prefix) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                    try {
                        DbFiles.hardenToOwnerOnly(p);
```

**Why it is a problem:**

The permission model here is otherwise exemplary — `DbPathGuard` and `DbFiles` create files with `CREATE_NEW`
and immediately assert `0600`, and the comments correctly note that root bypasses permission bits so mode
bits, not readability, must be checked. This one file escapes that discipline, because the *engine* creates
it, not this code. As the comment states, on the reference platform that means the credential store — salted
password digests, session token hashes, throttle state — is momentarily created `0644`, world-readable, and
only tightened once the connection and schema creation have completed.

The window is milliseconds wide and it is meaningfully mitigated: the parent directory is required to be
`0700` and owned by the running user, so on a first-time seed no other unprivileged account can traverse into
it to observe the file. The exposure is therefore narrow — it needs a pre-existing file in a directory whose
mode later changed, a filesystem that does not honour the directory bits as expected, or the same
directory-mode race being unavailable to the code — and it is a *local* attacker with concurrent access at
the instant of creation. That is why this is Low. It is still worth fixing, because the fix is cheap, the
same pattern applies to H2 trace and temporary files, and a "create-insecure-then-tighten" sequence is exactly
the failure mode the rest of the codebase took care to avoid.

**Fix:**

Set the process-level creation mask before the engine creates anything, so the file never exists in a
world-readable state, and keep `hardenEngineFiles()` as the belt-and-braces sweep it already is.

```java
        // Create-with-0600 rather than create-with-0644-then-chmod: H2 decides the file's
        // initial mode from the process umask, so the mask must be tightened before the
        // engine opens the file, not after.
        PosixFileMask.withPrivateUmask(() -> {
            conn = DriverManager.getConnection(url, props);
            return conn;
        });
```

On a JVM without a native umask hook, the equivalent durable control is to make the requirement explicit and
verifiable at startup: refuse to open (or seed) a store whose parent directory is not already `0700` — which
`DbPathGuard.requirePrivateDirectory` already does — and additionally assert the data file's mode immediately
after `DriverManager.getConnection` returns, failing closed if it is group- or world-readable, rather than
silently repairing it. Either way the assertion should be observable, so a regression in the engine's
behaviour surfaces rather than being chmod-ed away in the background.

### SEC-06 — Cookie `Max-Age` is hard-coded to 900 while the server-side TTL is configurable to 86,400

**Severity:** Low

**CWE:** CWE-613 (Insufficient Session Expiration).

**Location:** `SessionStore.java:151-152` against `Config.java:143`.

**Vulnerable code:**

```java
    static String cookieAttributesFor() {
        return "HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900";
    }
```

```java
        int ttl = integer(env, ENV_SESSION_TTL, "session_ttl", DEFAULT_SESSION_TTL, 60, 86_400);
```

**Why it is a problem:**

`AUTH_SESSION_TTL_SEC` is configurable from 60 to 86,400 seconds and the server honours it: `SessionStore.issue`
writes `expires_at_epoch_sec` from the configured TTL and `resolve` filters on it in SQL. But the cookie
attribute string this method hands to whatever front end eventually carries the token always says
`Max-Age=900`.

The two values drift apart in both directions, and the mismatch is not cosmetic:

* If the operator sets `AUTH_SESSION_TTL_SEC=86400`, the server accepts the token for 24 hours but a browser
  discards the cookie after 15 minutes. Sessions "expire" client-side while remaining fully live server-side
  — an issued token that no browser holds is still a valid bearer credential until its real expiry, which is
  the classic condition for a stolen-token session the operator believes has already died.
* If the operator sets `AUTH_SESSION_TTL_SEC=60`, the cookie outlives the server-side grant by 15 minutes, so the
  client keeps presenting a dead credential and `SameSite`/`HttpOnly` protections are applied to a token that
  should already have been dropped.

There is no HTTP layer in this program today — the Javadoc says as much — so nothing is broken at runtime
yet, which is why this is Low. The risk is that the constant string is copied into the front end when one is
written, at which point the mismatch becomes live. A security-relevant attribute must not be a literal when
the value it describes is configurable.

**Fix:**

Derive the attribute from the configured TTL, and make it impossible to call without one.

```java
    /**
     * Cookie attributes for a token whose server-side grant lives {@code ttlSec} seconds.
     * Max-Age is derived, never hard-coded: a cookie that outlives (or dies before) its
     * server-side grant is a session-management bug, not a default.
     */
    static String cookieAttributesFor(int ttlSec) {
        InputValidator.requireInt(ttlSec, 60, 86_400, "session_ttl");
        return "HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=" + ttlSec;
    }
```

Update the caller in `Main.java:177-179` to pass `config.sessionTtlSec()`, and add a test asserting the
emitted `Max-Age` equals `AUTH_SESSION_TTL_SEC` for both ends of the configured range.

### SEC-07 — `BootRefusal` thrown from a try-with-resources *resource expression* escapes its own handler

**Severity:** Low

**CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions) — a condition the code intends to
handle reaches an unhandled path, leaking internal detail and reporting the wrong status.

**Location:** `Main.java:103` (the resource expression), `:120-121` (the handler that cannot see it),
`:249` (the throw), `:60-65` (`main`/`halt`).

**Vulnerable code:**

```java
        char[] dbPassword = config.takeDbPassword();
        try (Stdin in = new Stdin(stdin, console, err)) {
            try {
                if (!credentialConfigured) {
```

```java
                return operate(config, command, dbPassword, in, out, err);
            } catch (BootRefusal e) {
                return EXIT_BOOT;
            }
        } finally {
            wipe(dbPassword);
```

```java
            if (console != null && !isUtf8(console.charset())) {
                err.println("startup refused: console_charset_unsupported ("
                        + (console.charset() == null ? "unknown" : console.charset().name())
                        + "); run under a UTF-8 locale");
                throw new BootRefusal();
            }
```

```java
    public static void main(String[] args) {
        int code = run(args, System.getenv(), System.console(), System.in, System.out, System.err);
        // halt() rather than exit() so no shutdown hook runs after we return, including the JDBC
        // driver's DB_CLOSE_ON_EXIT finaliser. Every resource is closed on every path below and
        // nothing of ours survives the process either way.
        Runtime.getRuntime().halt(code);
    }
```

**Why it is a problem:**

The `catch (BootRefusal e)` at line 120 sits inside the `try` *body*. `new Stdin(...)` is evaluated in the
resource specification, before the body — and `Stdin`'s constructor throws `BootRefusal` at line 249 when the
console charset is not UTF-8. A throw from the resource expression is not caught by the body's catch clauses,
so the intended handling never runs.

Instead, `BootRefusal` propagates out of `run()` into `main()`, which has no handler. The JVM prints a full
stack trace to stderr and exits with status 1. Two things are lost at once. The intended operator-facing
result — a clean `EXIT_BOOT` (3) so a wrapper script can distinguish "refused to start" from "internal
failure" — is replaced by a generic 1. And the stack trace discloses internal structure (class names, method
names, the package layout) on a path that was designed to print one sanitized line and nothing else. Every
other refusal in this file follows the `err.println("startup refused: <code>")` + `EXIT_BOOT` convention;
this is the one refusal that does not.

The impact is genuinely small — no credential is disclosed, and the resource is not leaked because
`Stdin.close()` has nothing open to release at that point — hence Low. It is worth fixing because it defeats
the file's own exit-code contract and its "codes not traces" convention, and because the same pattern will
silently swallow the next, more interesting, refusal added to a constructor.

**Fix:**

Construct the resource inside the guarded body, so the exception is inside the `try` that handles it.

```java
        char[] dbPassword = config.takeDbPassword();
        try {
            try (Stdin in = new Stdin(stdin, console, err)) {
                if (!credentialConfigured) {
                    // ... unchanged ...
                }
                return operate(config, command, dbPassword, in, out, err);
            }
        } catch (BootRefusal e) {
            return EXIT_BOOT;
        } finally {
            wipe(dbPassword);
        }
```

Add a test that invokes `Main.run` with a console whose `charset()` is not UTF-8 and asserts the return value
is `EXIT_BOOT` and that stderr contains exactly the one `console_charset_unsupported` line — that assertion is
what would have caught this, and it also protects the `EXIT_BOOT` contract going forward.

### SEC-08 — Audit-log write failure is swallowed with a single stderr line and no signal

**Severity:** Low

**CWE:** CWE-778 (Insufficient Logging) — the audit trail can stop recording security events while the
system reports normal operation.

**Location:** `LogWriter.java:138-146`.

**Vulnerable code:**

```java
    private void emit(byte[] bytes) {
        try {
            out.write(new String(bytes, StandardCharsets.UTF_8));
            out.flush();
            written += bytes.length;
        } catch (IOException e) {
            // Failing to audit must not take down authentication, and must not echo content.
            System.err.println("audit_write_failed");
        }
    }
```

**Why it is a problem:**

The trade-off is defensible in principle: an authentication service should not become unavailable because its
log device is full, and echoing the failed line's content to stderr would risk disclosure. Both concerns are
correctly handled — the message is a bare code, and the exception's own text (which can name the path) is
discarded.

The problem is that this is the *only* consequence. `emit` swallows the failure, `log()` returns normally, and
nothing in `AuthService` or `Main` learns that the audit trail stopped. Every subsequent login, denial,
throttle event and internal error is silently unrecorded for the remaining life of the process — the writer
is never reopened, there is no failure counter, and no exit-code or status surface reflects it. For an
attacker, filling the log device or making the file unwritable is a cheap, undetectable way to go dark before
or during an attempt: the service keeps answering, so nobody notices the evidence has stopped accumulating.

There is a second, related sharp edge: `written += bytes.length` is only reached on success, so a persistently
failing writer never advances the byte counter and therefore never trips the `MAX_TOTAL_BYTES` cap either —
the component cannot distinguish "wrote everything" from "wrote nothing for an hour". The design elsewhere is
fail-closed to a fault (see §6), so an authentication audit trail that fails *open* and silently is an outlier
worth correcting. Low, rather than Medium, because the deployment is a single-process CLI and the failure is
visible to an operator watching stderr.

**Fix:**

Keep authentication available, but make the loss durable, observable, and terminal for untrusted use.

```java
    private volatile boolean auditDegraded;
    private long writeFailures;

    private void emit(byte[] bytes) {
        try {
            out.write(new String(bytes, StandardCharsets.UTF_8));
            out.flush();
            written += bytes.length;
            writeFailures = 0;
        } catch (IOException e) {
            writeFailures++;
            if (!auditDegraded) {
                // One code only: the exception text can name the path, and the
                // line's content must never be echoed.
                System.err.println("audit_write_failed");
                auditDegraded = true;
            }
            attemptReopen();
        }
    }

    /** True when security events are not being durably recorded. */
    boolean isDegraded() {
        return auditDegraded;
    }
```

Then surface it where the operator and the caller can act on it: expose `isDegraded()` on `AuthService`, and
in `Config` support an `AUTH_REQUIRE_AUDIT=true` mode in which `Main.run` returns `EXIT_BOOT` rather than
serving authentication once `isDegraded()` is set. That preserves availability-by-default while letting a
deployment that needs a guaranteed trail choose fail-closed instead of inheriting fail-open.

### SEC-09 — Storage credential is materialised as an un-zeroable `String` for the JDBC connection

**Severity:** Low

**CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory).

**Location:** `Database.java:84-86` (the conversion), `:115` (the ineffective cleanup).

**Vulnerable code:**

```java
        Properties props = new Properties();
        props.setProperty("user", config.dbUser());
        // The JDBC contract requires the credential as a String, so this one value cannot be zeroed
        // from the heap. It is a local-file credential, never written to the URL, argv, or a log.
        String jdbcPassword = dbPassword == null ? "" : new String(dbPassword);
        props.setProperty("password", jdbcPassword);
```

```java
            java.util.Arrays.fill(dbPassword == null ? new char[0] : dbPassword, (char) 0);
            jdbcPassword = null;
```

**Why it is a problem:**

The discipline everywhere else is careful: the credential arrives as `char[]`, `Main` wipes it in a `finally`,
`PasswordHasher.derive` calls `spec.clearPassword()`, `AccountSeeder` wipes salts and digests, and the value is
kept out of argv, the connect URL, and every log line. This line is the one place a copy escapes that
discipline, and the code says so.

`new String(dbPassword)` puts an immutable, interned-adjacent copy of the plaintext credential on the Java
heap. `String` gives no API to erase it, and assigning `jdbcPassword = null` at line 115 only drops the local
reference — the character data stays reachable-by-scanner inside `Properties` (which held it), inside the
driver's connection state, and inside the `String` object itself until a collection cycle happens to collect
and the pages happen to be reused. So the wipe at line 115 is presentationally reassuring but cryptographically
ineffective: the whole point of the `char[]` discipline is to shrink the plaintext window, and here the window
is bounded only by GC timing.

The exposure is a memory-read primitive — a core dump, a `ptrace`-capable peer, a heap dump left by
`-XX:+HeapDumpOnOutOfMemoryError`, or a swapped page — and it is a *local* one, on a host that already owns
the file the credential protects. That, plus the fact that H2's `DriverManager` API genuinely requires a
`String`, is why this is Low and largely a design tax rather than a mistake. It is reported because the
residual should be bounded deliberately rather than accepted implicitly, and because cheap steps do shrink it.

**Fix:**

Minimise the number of live copies, keep the plaintext window as short as the API allows, and remove the
misleading cleanup that suggests the problem was solved.

```java
        Properties props = new Properties();
        props.setProperty("user", config.dbUser());
        // Unavoidable under DriverManager's contract: exactly one String copy, created as
        // late as possible and dropped immediately after the connect call below.
        String jdbcPassword = dbPassword == null ? "" : new String(dbPassword);
        props.setProperty("password", jdbcPassword);
        Connection conn = null;
        Connection txConn = null;
        try {
            conn = DriverManager.getConnection(url, props);
            props.remove("password");           // drop the vault copy before connect #2
            txConn = DriverManager.getConnection(url, props);
        } finally {
            props.remove("password");
            jdbcPassword = null;                 // reference only; the String is not erasable
            java.util.Arrays.fill(dbPassword == null ? new char[0] : dbPassword, (char) 0);
        }
```

Beyond that, bound the blast radius operationally rather than in code: document that this deployment must not
enable `-XX:+HeapDumpOnOutOfMemoryError` or expose `jmap`/`jcmd` to unprivileged users, and note the residual
in `THREAT-MODEL.md` alongside R8 so it is tracked as an accepted limitation of the embedded-H2 design rather
than as something the wipe at line 115 handled. If the store ever moves to a TCP database, the same line also
needs TLS — see the R8 note in §6.

## 6. Verified Controls and Checks With No Finding

The following were tested against the code and, where the claim was empirical, against the generation-time
`Probe.java` harness and the test suite. Each passed and is recorded as a control rather than a finding.

* **SQL value binding.** Every statement in `Database.java`, `ThrottleStore.java`, `SessionStore.java` and
  `AccountSeeder.java` binds values with `?` placeholders. There is no string concatenation of attacker- or
  configuration-controlled *values* into SQL text, so the injection surface is limited to identifiers.
* **Identifier handling.** `InputValidator.requireSqlIdentifier` enforces `^[A-Za-z_][A-Za-z0-9_]{0,29}$`
  plus an explicit reserved-word refusal, and `Database.quote` double-quotes every table name before it
  reaches a statement. `AUTH_ACCOUNT_TABLE` / `AUTH_THROTTLE_TABLE` / `AUTH_SESSION_TABLE` cannot break out of
  the identifier context; `AllTests.java` covers this.
* **JDBC-URL parameter injection closed.** `InputValidator.requireDbPath` refuses `;`, `=`, control
  characters, `..`, non-absolute and non-canonical paths, and the connect URL appends only fixed options after
  it. `.probe/Probe.java` demonstrates that the `…evil;INIT=RUNSCRIPT FROM '…'` form is rejected by H2 2.3.232
  rather than executed, which is the control that keeps `ACCESS_MODE_DATA`/`DB_CLOSE_ON_EXIT`/`TRACE_LEVEL_*`
  from being attacker-extensible.
* **Log forging closed by construction, not by escaping.** `LogWriter.sanitize` accepts only an allowlist
  charset that excludes CR and LF, rejects (rather than escapes) any line that leaves it, caps line length at
  320 characters and total output at 4 MB, and emits only fixed event tokens from a closed enum. Masked
  identities come from `maskEmail` (`f***@domain`). Multi-line record injection is not possible, and
  `AllTests.java` asserts it.
* **File and directory hardening.** `DbPathGuard.requirePrivateDirectory` refuses symlinks, requires
  `isDirectory(NOFOLLOW)`, rejects any `GROUP_*`/`OTHERS_*` bit, requires the owner to equal the running user,
  and requires owner rw+x. `DbFiles.newPrivateFile` uses `CREATE_NEW`, hardens, then re-verifies. Correctly,
  checks are on **mode bits**, not on whether a read succeeds — the code notes that the reference platform runs
  as root, and an accessibility probe would report a world-readable file as safe. See SEC-05 for the one file
  this pattern does not cover.
* **Session tokens.** `SessionStore.issue` draws 32 `SecureRandom` bytes (256-bit), stores only the SHA-256
  digest, and aborts via `if (ps.executeUpdate() != 1) throw …session_insert_failed` rather than granting on an
  unconfirmed insert. `requireSessionToken` demands exactly 64 lowercase hex characters, so no unvalidated
  token reaches a query.
* **Credential handling on the compare path.** `PasswordHasher.matches` delegates to
  `CryptoUtils.constantTimeEquals`, which folds the length difference into the accumulator
  (`int diff = a.length ^ b.length;`) before the XOR loop, so neither content nor length leaks by timing.
  `PBEKeySpec.clearPassword()` runs in a `finally`. Passwords are `char[]` end to end and are wiped in
  `Main`'s `finally`.
* **Throttle atomicity and anti-abuse of the counters.** `ThrottleStore.reserve` sorts the keys before
  acquiring them (deadlock avoidance), serialises in-process with `synchronized` on the dedicated transaction
  connection and cross-process with `SELECT … FOR UPDATE`, and signals refusal by throwing `Refused` so the
  transaction unwinds and nothing partial commits. A negative stored counter throws
  `throttle_state_rejected` (`ThrottleStore.java:132`) rather than being trusted, which prevents a tampered row
  from buying infinite attempts. `refund()` is `UPDATE … SET used = used - 1 … WHERE tkey = ? AND used > 0`, so
  a refund cannot drive the counter negative or over-commit. `AuthService.grant` refunds **only** the identity
  budget, so successful logins remain charged to the source budget — no free-successes inflation.
  `AuthServiceTests` verifies the 400-threads-on-one-budget case lands on the limit exactly.
* **Config cross-validation.** `Config.java:150-151` refuses `source_max < identity_max` outright, closing the
  configuration in which the shared per-source counter would become the lockout weapon. Every numeric knob is
  range-checked by `requireInt` (`[0-9]{1,9}` plus bounds) and every boolean by an exact-string
  `requireBoolean`, so an unparseable or oversized environment value is a startup refusal, not a silently
  defaulted weak value.
* **Fail-closed storage paths.** A `StorageException` from the throttle store is treated as "no slot"
  (`slot = false; budgetKnown = false`) rather than as "no limit", a failed session insert denies the grant even
  on a correct password, and `Database.open` refuses a location it cannot verify before contacting the engine.
  `E2ETests` covers `storage_credential_unavailable` and `source_max_below_identity_max`.
* **Tampered-row revalidation.** The login path re-reads and re-checks `pw_algo` and `pw_iterations` per
  attempt and honours `status`, so rewriting a stored digest's algorithm or dropping its iteration count in the
  data file does not silently downgrade verification; `AuthServiceTests` covers both tampered columns.
* **Input grammar and encoding.** `requireEmail` restricts to printable ASCII (0x21–0x7E) with a single `@`, a
  bounded local-part character class, and explicit refusal of `xn--` punycode labels — which removes the
  homoglyph-homoglot account-confusion class. `requirePassword` rejects control characters, leading/trailing
  whitespace, unpaired surrogates, and passwords exceeding 1,024 UTF-8 bytes, and the strict-UTF-8 stance
  (`CodingErrorAction.REPORT`, plus `Stdin`'s UTF-8 console refusal) prevents the byte-truncation and
  decode-difference classes of account confusion. `requireDbPath` requires an absolute, canonical, ASCII path.
* **Secrets handling.** No hardcoded credential, key, token, or default password appears in any source, test,
  config or documentation file. The storage credential is never placed in argv or in the JDBC URL; the H2
  connect string carries `user` via `Properties`, and `Database` deliberately sets `TRACE_LEVEL_FILE=0` and
  `TRACE_LEVEL_SYSTEM_OUT=0` so the engine cannot echo connection detail. See SEC-09 for the one in-memory
  residual. The session token goes only to stderr, gated by an explicit opt-in flag.
* **Dependency integrity.** `libs/h2-2.3.232.jar` is pinned to a single version and ships with both `.sha1`
  and `.sha256` digest files, so the artifact's integrity is checkable rather than assumed. (The library itself
  is third-party and out of review scope.)
* **Equal-work and timing-floor behaviour is correct as designed.** `blindSalt` uses a distinct domain
  separator (`"auth-blind-v1:"`) so a blind salt can never collide with a stored random salt, `WORK_SAMPLE`
  makes the unknown-account path cost the same as a known-account path, and `padToFloor` bounds jitter in one
  direction only. The *ordering* defect around this machinery is SEC-01; the machinery itself is sound, and the
  floor is configurable within a sane 500–15,000 ms band.

Two non-finding observations, recorded for completeness because they are documentation defects rather than code
defects and so do not meet the bar for a numbered finding:

* `THREAT-MODEL.md:87-88` states that the session id is printed to stderr "when `AUTH_EMIT_SESSION=true`
  (default, so the feature is demonstrable)". The code default is `false` (`Config.java:166-167`), which is the
  secure choice; the *document* is wrong, and a reader who trusts it may believe the default leaks a bearer
  token. The threat-model sentence should be corrected to match `Config`.
* `result.md` contains an unrelated API-error note from the generating run; it has no bearing on the reviewed
  code and was excluded from scope (see §2).
