# Security Code Review — Employee Portal Authentication

**Scope:** `src/com/example/portal/**` (7 Java files), `cli/PortalLogin.java`, `test/com/example/portal/AuthTests.java`, `build.sh`.
**Method:** the `review-code-for-security-vulnerabilities` router skill — Step 1 code comprehension, Step 2 library skill selection by keyword, Step 3 application of each selected skill's checklist against the code, Step 4 this report.
**Date:** 2026-09-09

---

## 1. What the code does

| File | Role | Security-relevant behaviour |
| --- | --- | --- |
| `auth/PasswordHasher.java` | PBKDF2-HMAC-SHA256 hash/verify, format `iterations:saltB64:hashB64` | KDF choice and parameters, salt generation (`SecureRandom`), constant-time compare, parsing of an untrusted stored-hash string, key material lifetime in memory |
| `auth/UserRecord.java` | Immutable credential record (username, hash, enabled flag) | Hash omitted from `toString()` (log hygiene) |
| `auth/CredentialStore.java` | Read interface over the record store | Extension point — a JDBC/LDAP implementation would receive the canonical username |
| `auth/InMemoryCredentialStore.java` | Demo store; canonicalises usernames | Username canonicalisation (lockout-key integrity), password acceptance policy, wiping of the caller's password array |
| `auth/LockoutPolicy.java` | Per-account consecutive-failure counter + time lock | Anti-brute-force control, concurrency, unbounded in-memory state keyed on attacker-controlled input |
| `auth/AuthenticationService.java` | Orchestrates lockout → lookup → verify → result | Authentication decision logic, account-enumeration / timing uniformity, TOCTOU between check and record, password wiping |
| `auth/AuthResult.java` | Result record + user-facing message | Response-content uniformity (enumeration oracle surface) |
| `cli/PortalLogin.java` | Console front end | Hardcoded demo credentials, password echo on non-TTY input, password as an immutable `String` |
| `test/AuthTests.java` | Dependency-free harness, 18 assertions | Test-only; asserts lockout, expiry, case-evasion, concurrency |
| `build.sh` | `javac` + run tests | No network fetch, no credentials, `set -e`; no issues |

**Keywords derived:** password storage / KDF, authentication, brute-force & lockout, account enumeration, timing side channel, hardcoded secrets, sensitive data in memory, race condition / TOCTOU, rate limiting & resource exhaustion, input validation, logging.

---

## 2. Findings

### F-1 — Disabled-account password oracle (observable response discrepancy) — **HIGH**
- **CWE-204: Observable Response Discrepancy** (also CWE-203)
- **Evidence:** `src/com/example/portal/auth/AuthenticationService.java:80-83`, `src/com/example/portal/auth/AuthResult.java:42-44` and `:29-32`, surfaced at `src/com/example/portal/cli/PortalLogin.java:53-56`

The code takes deliberate care to make the *message* identical for every failure, but the rest of the response is not identical. For a disabled account:

- wrong password → `recordFailure` → `AuthResult.invalid(...)` with `status = INVALID_CREDENTIALS` and `remainingAttempts = 4`
- **correct** password → `AuthResult.disabled()` with `status = ACCOUNT_DISABLED` and `remainingAttempts = 0` (`AuthResult.java:44`)

The CLI branches on exactly those two fields (`PortalLogin.java:53-56`: it prints `Attempts remaining before lockout: N` only when the status is `INVALID_CREDENTIALS` **and** `remainingAttempts > 0`). So against the seeded `rgone` account, a wrong guess prints the "Attempts remaining" line and a correct guess does not. That is a working password oracle: an attacker brute-forcing an offboarded account learns exactly when they hit the right password, even though access is refused. Offboarded-staff passwords are high value — they are frequently reused on other systems and the account may later be re-enabled. This directly contradicts the `README.md` claim that "unknown username, wrong password, and disabled account all return the identical message".

**Fix:** do not distinguish the disabled case in anything an unauthenticated caller can observe. Either drop the `ACCOUNT_DISABLED` branch entirely and return `AuthResult.invalid(remaining)` (recording the failure exactly as for a bad password), or keep `ACCOUNT_DISABLED` for internal/audit use only while making `remainingAttempts` and every other observable field byte-identical to the `invalid` result:

```java
if (record.isPresent() && !record.get().enabled() && passwordMatches) {
    return AuthResult.disabled(Math.max(0, lockoutPolicy.maxAttempts() - after.consecutiveFailures()));
}
```
and have the CLI print the remaining-attempts line for `ACCOUNT_DISABLED` too — or, more robustly, never print it at all (see F-11).

---

### F-2 — TOCTOU between the lockout check and the failure record allows limit overrun — **MEDIUM**
- **CWE-367: Time-of-check Time-of-use Race Condition** (leading to CWE-307: Improper Restriction of Excessive Authentication Attempts)
- **Evidence:** `src/com/example/portal/auth/AuthenticationService.java:57-60` (check) vs `:76` (record), with the expensive `PasswordHasher.verify` at `:66` sitting between them

`LockoutPolicy` is internally thread-safe — each individual `compute` is atomic (`LockoutPolicy.java:70,83`) — but the *service* performs a non-atomic check-then-act. Between `check()` at line 57 and `recordFailure()` at line 76 the code runs a full 210,000-iteration PBKDF2 derivation (~100 ms). Any number of attempts that enter that window concurrently all observe "not locked" and all get a guess evaluated. With a 5-attempt policy, an attacker firing 500 parallel requests gets 500 password guesses accepted, not 5; the lock only engages after the batch drains. The existing test `concurrentFailuresAllCount()` only proves that failures are not *lost*, not that the limit cannot be *overrun* — so the README's race-safety claim does not cover this case.

**Fix:** make "check the lock and consume an attempt" a single atomic operation. Reserve the attempt slot up front in one `compute` (returning "denied — locked" or "slot taken"), run the verification, then either confirm the failure or clear the counter on success. Concretely, add a `LockoutPolicy.tryAcquire(account)` that atomically expires stale locks, rejects when locked, and pre-increments the failure count; `AuthenticationService` then calls it once instead of `check()`+`recordFailure()`.

---

### F-3 — Unbounded lockout state keyed on unvalidated, attacker-controlled usernames — **MEDIUM**
- **CWE-770: Allocation of Resources Without Limits or Throttling** (with CWE-20: Improper Input Validation)
- **Evidence:** `src/com/example/portal/auth/LockoutPolicy.java:44` (`state` map), `:83` (entry created on every failure), `:109-118` (`expireIfDue` only prunes *locked* entries, and only when that key is touched again); `src/com/example/portal/auth/AuthenticationService.java:51` and `src/com/example/portal/auth/InMemoryCredentialStore.java:20-22` (`canonical` trims and lowercases but imposes **no length limit and no character/format validation**)

Every failed attempt on *any* string — existing account or not — inserts a permanent entry into the `ConcurrentHashMap`. An entry is removed only on a successful sign-in (`:100`) or when a *locked* entry is re-touched after expiry (`:113`). An entry that stopped at 1–4 failures is never reclaimed, and a locked entry that is never queried again is never reclaimed either. An attacker cycling random usernames therefore grows the map without bound until the JVM heap is exhausted, taking the portal down for everyone. Because `canonical()` does not bound the username length, a single attempt with a multi-megabyte username is stored verbatim as a map key, amplifying the cost per request by orders of magnitude.

**Fix:** (a) validate the username before it is used as a key — reject anything over a sane length (e.g. 64 chars) or outside the permitted charset, at `AuthenticationService.java:51`; (b) bound and expire the map: give every `Attempts` entry a `lastSeen` timestamp and evict entries idle longer than `lockoutDuration` via a periodic sweep, or replace the raw map with a size-capped LRU/TTL cache.

---

### F-4 — Hardcoded credentials in source — **MEDIUM**
- **CWE-798: Use of Hard-coded Credentials** (also CWE-259)
- **Evidence:** `src/com/example/portal/cli/PortalLogin.java:24-26`

```java
store.addUser("jsmith", "Correct-Horse-Battery-7".toCharArray(), true);
store.addUser("adepth", "Tr0ubador!Staple-Bank".toCharArray(), true);
store.addUser("rgone", "OffboardedAccount-2024".toCharArray(), false);
```

These are documented as demo seeds, but they are real, working credentials in a file compiled into the shipped `out/` artifacts (`out/com/example/portal/cli/PortalLogin.class` is present in this tree and the strings are recoverable from it). Demo seeding code has a strong tendency to survive into production builds, at which point these become three guaranteed-valid accounts; the same passwords also commonly get reused in test and staging environments. `AuthTests.java` contains a fixture password for the same reason.

**Fix:** move the seeding out of the shipped class — read demo accounts from an external file or environment variable that is absent in production, gate it behind an explicit `-Dportal.demo=true` flag, or generate random passwords at startup and print them once. Add a secret scanner (gitleaks or equivalent) to the build so new literals are caught.

---

### F-5 — Lockout is process-local: no shared counter store and no per-IP throttle — **MEDIUM**
- **CWE-307: Improper Restriction of Excessive Authentication Attempts**
- **Evidence:** `src/com/example/portal/auth/LockoutPolicy.java:44`; `src/com/example/portal/auth/AuthenticationService.java:31-38` (no IP/source parameter exists anywhere in the authenticate signature at `:50`)

The failure counter lives in a plain in-JVM `ConcurrentHashMap`. The moment this service runs behind a load balancer with more than one instance — which the `CredentialStore` interface at `CredentialStore.java` is explicitly designed to enable ("swap for LDAP/JDBC") — the effective limit becomes `maxAttempts × instanceCount`, and a rolling restart resets every counter to zero. Additionally the only throttle dimension is the account, so a password-spraying attacker (one guess against each of 10,000 usernames) never trips any control at all, and there is nothing limiting a single source IP. `LockoutPolicy.java:16-19` acknowledges the missing per-IP control in a comment, which makes it a known gap rather than an oversight, but it is still unimplemented.

**Fix:** back the counter with a shared, atomic store (Redis `INCR`+`EXPIRE`, or a database row with an atomic update) so the limit holds across instances and restarts; add a second, independent per-source-IP/subnet limiter and a global failed-login rate ceiling to cover spraying. Thread the source identity into `AuthenticationService.authenticate`.

---

### F-6 — `verify()` accepts an unvalidated iteration count from the stored hash — **MEDIUM**
- **CWE-916: Use of Password Hash With Insufficient Computational Effort** (also CWE-1284: Improper Validation of Specified Quantity in Input)
- **Evidence:** `src/com/example/portal/auth/PasswordHasher.java:54` (`int iterations = Integer.parseInt(parts[0]);`) and `:58` (used directly in `derive`), with no bounds check between them

The iteration count is read from the stored record and used as-is. Two consequences:

- **Silent downgrade.** Anyone who can write to the credential store (a SQL-injection write, a compromised directory, a bad migration, a malicious admin) can rewrite a record to `1:<salt>:<hash>`. Verification still succeeds, but every subsequent authentication derives with a single iteration — and, more importantly, the stored hash for that account is now trivially crackable offline. The downgrade is invisible: no error, no log, tests still pass.
- **CPU denial of service.** `Integer.parseInt` happily returns `2147483647`. A single record with that iteration count makes every authentication attempt against it occupy a CPU core for hours. It also cannot be reached by an attacker who only controls the client, so this is second-order — but it is a free hardening win.

**Fix:** validate immediately after parsing:

```java
int iterations = Integer.parseInt(parts[0]);
if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    return false;   // and log a tamper alert
}
```
with `MIN_ITERATIONS` set to the current policy floor. Also verify the decoded salt and hash lengths match `SALT_BYTES` and `KEY_BITS/8` before use (`:56-57`). Re-hash records at the current parameters on the next successful sign-in.

---

### F-7 — Cleartext password copies are left in the heap — **LOW**
- **CWE-316: Cleartext Storage of Sensitive Information in Memory**
- **Evidence:** `src/com/example/portal/auth/PasswordHasher.java:66-74`; `src/com/example/portal/cli/PortalLogin.java:74-75`

Two leaks undercut the otherwise careful wiping (`AuthenticationService.java:84-88`, `InMemoryCredentialStore.java:26`, `PortalLogin.java:52`):

1. `new PBEKeySpec(password, ...)` at `PasswordHasher.java:66` **clones** the password into the spec's own internal array. The `finally` block at `:72-74` sets the local reference `spec = null`, which does nothing to that clone — it just makes it eligible for GC, so the cleartext sits in the heap until a collection happens and would appear verbatim in a heap dump or core file. `PBEKeySpec.clearPassword()` exists precisely for this.
2. `PortalLogin.readPassword` at `:74` reads the non-TTY fallback into a `String` (`reader.readLine()`). Java strings are immutable and interned in the heap; converting to `char[]` at `:75` does not remove the `String`, and it cannot be wiped.

**Fix:** in `derive`, hold the spec in a `PBEKeySpec` typed local and call `spec.clearPassword()` in the `finally` block. For the CLI fallback, read character-by-character into a `char[]` (or accept that the non-TTY path is demo-only and refuse to run without a console).

---

### F-8 — PBKDF2 iteration count is below current OWASP guidance for SHA-256 — **LOW**
- **CWE-916: Use of Password Hash With Insufficient Computational Effort**
- **Evidence:** `src/com/example/portal/auth/PasswordHasher.java:20-23`

The construction itself is correct — PBKDF2-HMAC-SHA256, 16-byte per-password salt from `SecureRandom` (`:25,32-33`), 256-bit output, `MessageDigest.isEqual` for the comparison (`:59`). The parameter is the weak point: 210,000 is the OWASP Password Storage Cheat Sheet figure for PBKDF2-**HMAC-SHA512**; the corresponding recommendation for HMAC-**SHA256** is 600,000. At 210k the stored hashes are roughly 3× cheaper to attack offline than intended if the store is ever exfiltrated. More broadly, PBKDF2 is not memory-hard and offers little resistance to GPU/ASIC cracking regardless of the count.

**Fix:** raise `ITERATIONS` to at least 600,000 for SHA-256, or move to Argon2id (19 MiB memory, t=2, p=1) or scrypt, which are memory-hard. Store the algorithm identifier in the hash string alongside the parameters so records can be migrated in place; combined with F-6, upgrade each record on next successful login.

---

### F-9 — No authentication logging or monitoring anywhere — **LOW**
- **CWE-778: Insufficient Logging** (also CWE-223: Omission of Security-relevant Information)
- **Evidence:** no logging call exists in any file under `src/`; the only output is user-facing `System.out` in `src/com/example/portal/cli/PortalLogin.java:33-59`. `AuthenticationService.authenticate` (`:50-89`) records nothing on failure, lockout, disabled-account access, or success.

Lockout is a last-resort control (as `LockoutPolicy.java:16-19` itself argues); without an event stream there is no way to detect a spray in progress, to alert on lockouts, to notice the tampering described in F-6, or to reconstruct an incident afterwards. This is OWASP A09:2021.

**Fix:** emit a structured event (timestamp, canonical account, source, outcome, failure count, correlation id) on every authentication outcome and on every lockout transition, at `AuthenticationService.java:69-83`. Never log the password, the candidate password, or the stored hash. Alert on lockout rate and on distinct-accounts-per-source.

---

### F-10 — No password policy enforced when accounts are created — **LOW**
- **CWE-521: Weak Password Requirements**
- **Evidence:** `src/com/example/portal/auth/InMemoryCredentialStore.java:25-29` — `addUser` hashes and stores whatever it is handed; no length, complexity, or breached-password check exists in the codebase.

A one-character or known-breached password is accepted, which makes the 5-attempt lockout the *only* barrier — and F-2 and F-5 both weaken that barrier. Credential stuffing is unaffected by lockout when the first guess is correct.

**Fix:** validate in `addUser` (and any future password-change path): minimum length 12, no upper limit below 64, reject against a breached-password list (k-anonymity range query against Have I Been Pwned or a local Bloom filter), per NIST SP 800-63B. Reject before hashing, and wipe the array on the rejection path too.

---

### F-11 — Failure count for an arbitrary account is disclosed without spending an attempt — **LOW**
- **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**
- **Evidence:** `src/com/example/portal/auth/AuthenticationService.java:53-54`

```java
if (account.isEmpty() || password == null || password.length == 0) {
    return AuthResult.invalid(lockoutPolicy.remainingAttempts(account));
}
```

Submitting an empty password returns the live `remainingAttempts` for any username, *without* incrementing the counter and without the PBKDF2 cost. An attacker can poll this to watch another user's failure count, time guesses to leave the victim one attempt short of a lock (or to top up a targeted lockout DoS as it expires), and confirm when a lock has cleared. The remaining-attempts value is also echoed on every ordinary failure (`:83`, printed at `PortalLogin.java:53-56`), which hands attackers a precise budget for free.

**Fix:** return a fixed `AuthResult.invalid(0)` for the malformed-input path and count it as a failure like any other, so probing is not free. Consider removing `remainingAttempts` from the unauthenticated response entirely — legitimate users are served just as well by the generic lockout warning.

---

### F-12 — Unauthenticated requests trigger expensive key derivation (CPU amplification) — **INFORMATIONAL**
- **CWE-400: Uncontrolled Resource Consumption**
- **Evidence:** `src/com/example/portal/auth/AuthenticationService.java:62-66` — a full 210,000-iteration PBKDF2 runs for *every* attempt, including unknown accounts (against `DUMMY_HASH`, `:25-26`)

The dummy-hash verification is the correct fix for the username-enumeration timing channel (see §3) and should be kept. The side effect is that each unauthenticated request costs the server ~100 ms of CPU while costing the attacker almost nothing, and — because per-account lockout does not fire when every request uses a different username — nothing caps the aggregate. This is the resource-consumption face of the same gap as F-3 and F-5.

**Fix:** covered by the per-IP and global rate limiting in F-5, plus a bounded work queue / concurrency semaphore around the verification call so hashing cannot consume every core.

---

## 3. Controls checked and found sound

- **Username-enumeration via message text** — identical `"Invalid username or password."` for unknown user, wrong password, and disabled account (`AuthResult.java:30,44`). Sound; the leak is in the *other* response fields, see F-1.
- **Username-enumeration via timing** — unknown accounts still run a real derivation against `DUMMY_HASH` at `AuthenticationService.java:65-66`, keeping the known/unknown paths comparable. Sound. (Residual: a record stored with a non-default iteration count would derive at a different cost; F-6's bounds check narrows this.)
- **Username-enumeration via lockout behaviour** — unknown accounts are failure-counted too (`AuthenticationService.java:76`), so the lock does not reveal which accounts exist. Sound.
- **Lockout-key canonicalisation** — `canonical()` at `InMemoryCredentialStore.java:20-22` trims and lowercases with `Locale.ROOT`, and the same function keys both lookup and lockout, so `jsmith` / `JSmith` / ` JSMITH ` cannot be alternated to reset the counter. Using `Locale.ROOT` specifically avoids the Turkish dotless-i case-mapping bug. Correct.
- **Lock ordering** — the lock is evaluated before the password (`AuthenticationService.java:57-60`), so a correct password during a lock is still refused. Correct, and asserted by `correctPasswordRefusedWhileLocked()`.
- **Lock does not self-extend** — `LockoutPolicy.java:84-86` returns early when already locked, so an attacker cannot hold a victim locked indefinitely by continuing to hammer. Correct.
- **Constant-time hash comparison** — `MessageDigest.isEqual` at `PasswordHasher.java:59`. Correct; note it is only constant-time for equal-length inputs, which F-6's length validation would guarantee.
- **Salt generation** — `SecureRandom` (`PasswordHasher.java:25,32-33`), 16 bytes, unique per password, verified by the `distinct salts per hash` assertion. Correct; no `Random`, no time-based seed, no fixed IV/salt anywhere.
- **Malformed stored hash** — `verify` returns `false` rather than throwing (`PasswordHasher.java:49-52,60-62`), so a corrupt record denies rather than grants. Fail-closed, correct. The `IllegalStateException` from a missing JCE provider (`:69-71`) deliberately propagates rather than being mistaken for a failed login — also correct.
- **Hash never logged** — `UserRecord.toString()` omits `passwordHash` (`UserRecord.java:31-35`); no cleartext password is stored or compared anywhere.
- **Terminal echo** — `console.readPassword` is used when a TTY is attached (`PortalLogin.java:69-70`). The `BufferedReader` fallback at `:72-75` echoes, but only applies to piped/redirected input; noted under F-7 rather than raised separately.
- **`build.sh`** — no network fetch, no credentials, `set -e`, fixed relative paths. No issues.
- **Injection surfaces** — reviewed against general OWASP/CWE knowledge as no library skill matched: there is **no** SQL/JDBC, no OS command execution, no file or path handling, no deserialization, no XML/XXE parsing, no reflection, no HTTP client, no TLS configuration and no template rendering anywhere in this codebase, so SQLi, command injection, path traversal, SSRF, XXE and insecure-deserialization classes do not apply. The `CredentialStore` interface (`CredentialStore.java:8-11`) is the future risk boundary: a JDBC implementation must bind the username as a parameter and an LDAP implementation must escape it per RFC 4515 — `canonical()` performs no such escaping, and F-3's missing length/charset validation would feed it unfiltered.
- **XSS / output encoding** — no web layer; the only sink is `System.out` in the CLI. `AuthResult.success` echoes the *stored* username (`AuthResult.java:26`), not the raw user input, so it is not an injection sink.
- **Access control** — the code performs authentication only; there is no authorisation, session, token or JWT logic in scope, so the broken-access-control and JWT weakness classes have no target here. If a session is issued downstream of `AuthResult.authenticated()`, session fixation and token handling will need their own review.

---

## 4. Summary

| ID | Severity | CWE | Location | Issue |
| --- | --- | --- | --- | --- |
| F-1 | High | CWE-204 | `AuthenticationService.java:80-83` | Disabled-account password oracle via `status`/`remainingAttempts` |
| F-2 | Medium | CWE-367 / CWE-307 | `AuthenticationService.java:57-76` | TOCTOU between lock check and failure record — limit overrun |
| F-3 | Medium | CWE-770 / CWE-20 | `LockoutPolicy.java:44,83`; `AuthenticationService.java:51` | Unbounded state keyed on unvalidated usernames |
| F-4 | Medium | CWE-798 | `PortalLogin.java:24-26` | Hardcoded working credentials |
| F-5 | Medium | CWE-307 | `LockoutPolicy.java:44` | Process-local lockout; no shared store, no per-IP throttle |
| F-6 | Medium | CWE-916 / CWE-1284 | `PasswordHasher.java:54,58` | Iteration count taken unvalidated from the stored hash |
| F-7 | Low | CWE-316 | `PasswordHasher.java:66-74`; `PortalLogin.java:74-75` | Cleartext password copies left in heap |
| F-8 | Low | CWE-916 | `PasswordHasher.java:23` | 210k iterations is below OWASP guidance for SHA-256 |
| F-9 | Low | CWE-778 | `src/**` (no logging present) | No authentication logging or alerting |
| F-10 | Low | CWE-521 | `InMemoryCredentialStore.java:25-29` | No password strength policy |
| F-11 | Low | CWE-200 | `AuthenticationService.java:53-54` | Failure count probeable for free via empty password |
| F-12 | Info | CWE-400 | `AuthenticationService.java:62-66` | Unauthenticated PBKDF2 CPU amplification |

The cryptography and the enumeration-resistance design are the strongest parts of this code, and most of what is here is done deliberately and correctly. The issues that matter are at the edges of those designs: one response field that the "identical message" strategy did not cover (F-1), and an anti-brute-force control that is atomic in the wrong place and holds no state beyond a single process (F-2, F-5).

---

## 5. Skills applied

Selected from the skill library by grepping skill names against the Step 1 keywords and skimming candidate descriptions, then applied in priority order:

1. **`performing-cryptographic-audit-of-application`** — weak-hashing / weak-KDF / hardcoded-secret / entropy checklist → F-4, F-6, F-8; confirmed `SecureRandom`, per-password salt and constant-time compare (§3).
2. **`testing-api-authentication-weaknesses`** — Step 6 account-enumeration differential (valid vs invalid response comparison) and weak-password-policy probes → F-1, F-10, F-11; confirmed message-text and lockout-behaviour uniformity (§3).
3. **`exploiting-race-condition-vulnerabilities`** — TOCTOU / limit-overrun concepts → F-2.
4. **`implementing-api-rate-limiting-and-throttling`** — brute-force and resource-exhaustion controls, including the documented "in-memory rate limiting without shared state" pitfall → F-3, F-5, F-12.
5. **`testing-for-sensitive-data-exposure`** — insecure storage and secret-leakage checks → F-4, F-7, F-9.

Behaviours with no matching library skill (in-memory secret lifetime in Java, authentication event logging, and the absence of injection sinks) were reviewed against general OWASP Top 10 (A02, A04, A07, A09) and CWE knowledge, as recorded in F-7, F-9 and §3.
