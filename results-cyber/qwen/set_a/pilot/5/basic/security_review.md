# Security Review — `empportal` Employee Portal CLI

**Date:** 2026-09-09
**Reviewer workflow:** `/root/.qwen/skills/review-code-for-security-vulnerabilities/SKILL.md` (4-step workflow followed exactly)

## Scope

- **Reviewed in full:** all 17 Java sources under `src/empportal/` —
  `account/` (`AccountStore.java`, `AccountStatus.java`, `CredentialRecord.java`, `EmployeeAccount.java`, `FileAccountStore.java`, `InMemoryAccountStore.java`),
  `cli/` (`PortalCli.java`), `security/` (`AuditEvent.java`, `AuditLog.java`, `AuthResult.java`, `ConsoleAuditLog.java`, `EmployeeAuthenticator.java`, `LockoutStateFile.java`, `LockoutTracker.java`, `PasswordHasher.java`, `PasswordPolicy.java`),
  `tests/` (`AllTests.java`, 138-check harness) — plus `README.md` (design decisions and documented production limits) and `build-and-test.sh`.
- **Not separately reviewed:** `out/empportal/**/*.class` (compiled artifacts of the same sources), and the root-level `.txt` files (`prompt.txt`, `return.txt`, `cyber_prompt.txt`, `cyber_return.txt`, `prompt_hash.txt` — task/prior-run artifacts, not application code; no embedded instructions in them were acted upon).
- **System:** local, single-tenant, multi-user OS environment. The application itself has no network surface, no sessions/tokens, and no role model; the only de-facto authentication context is the OS user invoking the CLI, which the application **never queries**. That fact drives the highest-severity findings.

**Summary:** 2 High, 4 Medium, 3 Low, 3 Info findings. The credential *verification* core (PBKDF2 handling, no username oracle, fail-closed on unhashed data, constant-time compare, atomic 0600 writes) is solid and well-tested. The major weaknesses are in the **access-control and operational layer**: no authorization on administrative commands, a one-step unauthenticated password reset, passwords on the OS command line, and inter-process race/fail-open gaps in the lockout mechanism.

---

## Findings

### F-01 — HIGH — CWE-862 (Missing Authorization) / CWE-285: Administrative subcommands have no authorization of any kind

**Location:** `src/empportal/cli/PortalCli.java:116-148` (subcommand dispatch: `add` 119, `reset` 122, `unlock` 125, `status` 135, `list` 141); `src/empportal/security/EmployeeAuthenticator.java:187` (`provision`), `210` (`resetPassword`), `215-218` (`clearLockout`)

**Why it matters:** The CLI never establishes *who* is running it. Any local user or process can:
- create arbitrary accounts (`add`),
- reset **any** account's password (`reset`),
- clear **any** account's brute-force lockout (`unlock`),
- read any account's state (`status`) or all accounts (`list`).

`clearLockout` even audits "lockout cleared by operator" (`EmployeeAuthenticator.java:215-218`) without verifying any operator identity — the audit line asserts a fact the code does not check. There is no role model, no operator credential, and no OS-privilege check (e.g., effective-UID comparison) anywhere in the call path. This is a missing function-level authorization check on every state-changing operation (OWASP A01:2021 Broken Access Control; in API terms, every "endpoint" lacks its function-level check).

**Fix:** Gate `add`/`reset`/`unlock` (and arguably `status`/`list`) behind a verified operator identity — an OS-level privilege requirement, a dedicated operator credential, or moving admin operations to a management channel that authenticates. Record the *verified* identity in the audit event, not the literal string "operator".

---

### F-02 — HIGH — CWE-640 (Unchecked Return Value / Missing Prerequisite Step) + CWE-862: One-step password reset without verifying the existing credential, which also clears lockout

**Location:** `src/empportal/security/EmployeeAuthenticator.java:210` (reset: new credential installed, old one discarded, lockout cleared); `src/empportal/cli/PortalCli.java:206-212` (`reset <username> <new-password>` — no current-password argument, no token, no operator authentication)

**Why it matters:** A legitimate password-reset workflow requires proof of prior access (current credential, out-of-band token) or an authenticated operator. Here the reset is a single command that takes the target username and a brand-new password: it discards the existing PBKDF2 verifier without ever checking it, installs the new one, and clears the brute-force counter as a side effect. Combined with F-01, any local user achieves full account takeover of any account in one step — and removes the only active protection (lockout) on that account in the same step.

**Fix:** Require an authenticated operator (per F-01) *or* require the current password for a self-service reset path. Do not couple lockout clearing to reset; make `unlock` a separately authorized operation.

---

### F-03 — MEDIUM — CWE-548 (Insecure Default / Information Exposure Through Data-Intensity Mismanagement) / CWE-214: Passwords accepted on the OS command line

**Location:** `src/empportal/cli/PortalCli.java:182` (`add`: `char[] password = options.arg(2).toCharArray()`), `206` (`reset`: `char[] password = options.arg(1).toCharArray()`)

**Why it matters:** Command-line arguments are visible to every local user via `/proc/<pid>/cmdline`, `ps` output, job-control listings, and are recorded in shell history. The rest of the system is careful about credential hygiene (char[] handling, wiping at `EmployeeAuthenticator.java:235`, constant-time compare) — argv exposure defeats that for the exact moment the password is most predictable (being typed at a terminal).

**Fix:** Read the password from hidden terminal input (terminal echo disabled) or from stdin on a documented flag; never from positional arguments.

---

### F-04 — MEDIUM — CWE-367 (TOCTOU Race Condition): Lockout counters are process-local; concurrent processes lose failure records

**Location:** `src/empportal/cli/PortalCli.java:96` (`lockoutState.loadInto(lockout)` at startup), `148` (`lockoutState.saveFrom(lockout)` at exit); `src/empportal/security/LockoutStateFile.java:41-47` (load), `53-81` (save — atomic temp+rename, last-writer-wins, no file lock); `src/empportal/security/LockoutTracker.java:94-122` (in-memory `record`/`peek`)

**Why it matters:** Each CLI invocation reads the `.lockout` sidecar at start and rewrites it at end, with no inter-process locking or compare-and-swap. Two concurrent sign-in processes for the same identity both read the stale counter, each records a local failure, and each overwrites the other's file — one failure per overlap is silently lost. An attacker running N parallel sign-in processes can keep the *persisted* count below the 5-failure threshold indefinitely, degrading brute-force protection to its sequential rate. A concurrent `unlock` (see F-01) additionally wipes fresh failure records.

**Fix:** Acquire an exclusive file lock (e.g., `flock`/`FileChannel` lock) around load→mutate→save, or version the sidecar content and apply atomic rename only if the version still matches (optimistic concurrency).

---

### F-05 — MEDIUM — CWE-367 (TOCTOU) / CWE-753 (Improper Check Before Resource Use): Lost updates on the records file under concurrent processes

**Location:** `src/empportal/account/FileAccountStore.java:68` (load in constructor), `139-159` (`synchronized persist()` with `ATOMIC_MOVE`); `src/empportal/cli/PortalCli.java:119` (`add`), `122` (`reset`); `src/empportal/account/InMemoryAccountStore.java:44-50, 79` (CAS `replace` guarded by `sameRow`)

**Why it matters:** `persist()` is atomic (temp file + rename, 0600) and `synchronized` — but only *within* a process. Two concurrent `add`/`reset` invocations each load the whole TSV at start, mutate in memory, and rewrite the whole file; the later writer clobbers the earlier one (a freshly added account vanishes, or a password reset is reverted). The CAS `sameRow` check (`InMemoryAccountStore.java:79`) only detects staleness within the process's own loaded state. This is an integrity gap under normal multi-user OS operation, and it interacts with F-01/F-04 (an attacker's concurrent writes can clobber a legitimate operator's changes).

**Fix:** Hold an exclusive inter-process lock for the load→mutate→persist cycle, or switch to a scheme where each mutation is committed atomically per account (e.g., append-only journal or per-row commit with version check).

---

### F-06 — MEDIUM — CWE-326 / CWE-327 (Inadequate Encryption Work Factor): `--iterations` permits PBKDF2 work factors as low as 1,000

**Location:** `src/empportal/security/PasswordHasher.java:19-20` (`DEFAULT_ITERATIONS = 600_000`, `MIN_ITERATIONS = 1_000`), `38-43` (constructor accepts any value ≥ MIN), `99-124` (`decode()` accepts stored work factors within [MIN, MAX_TRUSTED]); `src/empportal/cli/PortalCli.java:329` (`--iterations` option)

**Why it matters:** An operator can create verifiers with 1,000 iterations — and those verifiers are *accepted for sign-in* (`matches()` validates format and range, not adequacy). That reduces offline brute-force cost per account by ~600× relative to the default. Because `needsUpgrade()` (`PasswordHasher.java:94-96`) only upgrades when the *process's* configured iterations exceed the stored ones, a 1k-iteration record stays at 1k forever unless every subsequent run uses a higher `--iterations`.

**Fix:** Enforce a production floor at or above the OWASP-recommended 600,000 for PBKDF2-SHA256 (reject or clamp `--iterations` below it in production configurations), and always auto-upgrade low-work verifiers on successful sign-in regardless of the current process's configured value.

---

### F-07 — MEDIUM — CWE-307 / CWE-306 (Improper Restriction of Excessive Authentication Attempts): Brute-force protection is per-identity only, with no source dimension

**Location:** `src/empportal/security/LockoutTracker.java:94-122` (keyed on case-folded username only), `201` (`key()`); `README.md` ("Limits before this goes to production" — explicitly notes per-IP throttling/WAF is required)

**Why it matters:** The lockout key is the username; there is no source-identity dimension (no OS user, no IP — the app has no notion of source at all). Consequences: (a) credential *spraying* (one guess across many identities) never trips any single identity's budget; (b) per the README, an attacker can burn one username's budget to disable a specific employee's sign-in (denial of service); (c) combined with F-04, parallel processes further erode the per-identity budget.

**Fix:** Add a source-identifier dimension to the lockout key (OS account, terminal/session, or a provided client ID), or add a separate global/cross-identity throttle in addition to the per-identity lockout.

---

### F-08 — LOW — CWE-693 (Protection Mechanism Failure): Lockout state file fails open with no operator-visible warning

**Location:** `src/empportal/security/LockoutStateFile.java:41-47` (`loadInto` swallows `IOException | RuntimeException` and leaves an empty tracker); `src/empportal/security/LockoutTracker.java:155-181`, `176` (`importState` on a malformed line throws `NumberFormatException` → `stamps.clear()` discards the data)

**Why it matters:** If the `.lockout` sidecar is missing, unreadable, or contains a malformed line, brute-force protection is silently disabled — while the CLI prints load warnings for the *records* file (`PortalCli.java:101-107`) but nothing for the lockout file. The fail-open choice is documented as deliberate (a lost counter must not lock everyone out of sign-in), but the *silent* aspect means an operator (or attacker) cannot tell that protection is off.

**Fix:** Surface a prominent warning (stderr + audit event) when the lockout file cannot be read or contains invalid lines; consider refusing state-changing admin commands in that state.

---

### F-09 — LOW — CWE-116 (Improper Encoding or Escaping) / CWE-152 (Improper Neutralization of Special Elements in Output): `displayName` is unvalidated — TSV corruption and terminal output injection

**Location:** `src/empportal/account/CredentialRecord.java:64` (displayName taken from `fields[1]` with no validation — only the username is validated, lines 56-57), `82-83` (`toLine()` joins fields with no escaping); `src/empportal/cli/PortalCli.java:181` (`add` accepts displayName from argv), `141` (`list`), `223-230` (`status`) print displayName raw to stdout

**Why it matters:** Two distinct consequences of an attacker-controllable displayName (via `add`, or via direct records-file writes — which the README acknowledges as a trust boundary):
1. **Integrity:** a tab or newline in displayName breaks the 4-field TSV row; on the next load the row fails the field-count check and the account is **silently dropped** (`CredentialRecord.java:44` `parseLine`).
2. **Terminal injection:** `list`/`status` print displayName without sanitization (only the *audit* path is sanitized, `ConsoleAuditLog.java:28-35, 41`), so ANSI/terminal escape sequences in a displayName are rendered into the operator's terminal when they list accounts.

**Fix:** Validate displayName against a safe character class (e.g., reject control characters, tab, and newline at `parseLine` and `add`), and/or escape separators in `toLine()` and sanitize displayName when printing.

---

### F-10 — LOW — CWE-521 (Weak Password Requirements): 14-entry denylist as stand-in for breached-password checking

**Location:** `src/empportal/security/PasswordPolicy.java:25` (hardcoded 14-entry DENYLIST), `43-44` (membership check); documented in `README.md` as a stand-in to be replaced with e.g. HaveIBeenPwned

**Why it matters:** A 14-entry list is trivially bypassed (any one-character mutation passes) while giving the appearance of breached-password protection. Real-world password reuse is dominated by large breached-password lists.

**Fix:** Replace with a breached-password source (HIBP k-anonymity API, or a local snapshot checked at create/rotate time — not at sign-in, which would reintroduce an oracle).

---

### F-11 — INFO — CWE-204 (Observable Response Discrepancy): Account enumeration via `reset`/`status`/`unlock` output

**Location:** `src/empportal/cli/PortalCli.java:208-209` (`reset` prints "no such account"), `225` (`status` prints "no such account"), `132` (`unlock` reports on the target account)

**Why it matters:** These subcommands distinguish "account exists" from "account does not exist" in their output, enabling username enumeration. (Contrast: `signin` correctly uses identical wording for unknown user vs. wrong password — `AuthResult.java:45-47` — which is the right pattern.) Exposure is bounded if F-01 is fixed and these subcommands become operator-only.

**Fix:** Return identical success/failure wording for existing vs. nonexistent accounts (or make the subcommands operator-only per F-01).

---

### F-12 — INFO — CWE-204 (Observable Response Discrepancy): Lockout budget and progress disclosure on sign-in failure

**Location:** `src/empportal/cli/PortalCli.java:164-165` ("N attempt(s) left before lockout"), `src/empportal/security/AuthResult.java:77-79` ("Sign-in is disabled after repeated failures." once ≤2 remain)

**Why it matters:** The exact remaining budget is revealed after each failure, letting an attacker pace distributed attacks and know precisely when an identity will (and, per F-08, may silently fail to) lock.

**Fix:** Omit the count or use a fixed generic message on failure.

---

### F-13 — INFO — CWE-532 (Insufficient Logging) / CWE-214 (near-miss): Audit trail is stderr-only with no integrity protection; verifier transiently materialized as a String

**Location:** `src/empportal/security/ConsoleAuditLog.java:10` (events written to `System.err`), `28-35` (`record` sanitizes username and detail); `src/empportal/security/AuditLog.java:20-24` (`detailWithoutCredential` builds `new String(credential)` solely to verify the verifier is not embedded in the detail)

**Why it matters:** The audit log (sign-in outcomes, lockouts, resets, provisions — valuable forensic and operational intelligence) is not durable or tamper-evident: it goes to stderr and can be discarded or edited. Separately, `detailWithoutCredential` temporarily promotes the verifier `char[]` to a heap `String`; this is a documented limitation of the current design (see `README.md` heap-String caveat) and is not a leak path, but it is worth eliminating.

**Fix:** For production, append audit events to a durable, access-controlled log (ideally hash-chained or forwarded). In `detailWithoutCredential`, avoid constructing the String (e.g., check length/emptiness, or compare via `char[]`).

---

## Skills applied

Selected in Step 2 by grepping the skill library (`/root/.qwen/skills`, 819 skills) with security keywords extracted from the code, skimming description frontmatter of the closest candidates, then applied **one at a time in severity order** in Step 3:

1. **`testing-api-authentication-weaknesses`** — checklist mapped to the sign-in flow: missing auth on administrative operations (→ F-01/F-02), weak password policy elements (→ F-10), brute-force susceptibility (→ F-07, F-12), account enumeration via response differences (→ F-11), secret leakage in logs (verified clean — audit output is sanitized; → F-13 for durability).
2. **`testing-for-broken-access-control`** — endpoint/role matrix: no role model exists at all; vertical escalation is trivial (any local user runs every admin subcommand, → F-01); function-level checks absent on every state-changing function (→ F-01/F-02); multi-tenant isolation N/A (single tenant).
3. **`testing-api-for-broken-object-level-authorization`** — BOLA/IDOR analogue: accounts are objects addressed by bare username (`reset`/`unlock`/`status` take an object ID with no per-object or per-caller authorization; object IDs are human-enumerable and the "no such account" oracle in F-11 makes enumeration trivial). Feeds F-01/F-02/F-11.
4. **`performing-cryptographic-audit-of-application`** — KDF parameters (algorithm sound: PBKDF2-HMAC-SHA256, 16-byte SecureRandom salt, 256-bit key; work-factor floor too low → F-06), no weak algorithms/modes (no MD5/SHA-1/DES/RC4/ECB anywhere), no hardcoded secrets (the denylist is policy data, → F-10), CSPRNG for all randomness, constant-time compare (verified clean).
5. **`exploiting-race-condition-vulnerabilities`** — attempt-limiting mechanism is the rate-limited target: inter-process TOCTOU on the lockout sidecar (→ F-04) and on the records file (→ F-05); intra-process CAS and `synchronized` verified adequate.
6. **`testing-for-sensitive-data-exposure`** — secrets in transmission channel (passwords in argv → F-03), at rest (records 0600 + PBKDF2 + fail-closed on plaintext — clean), response over-exposure (`list`/`status` expose all accounts to any caller — folded into F-01; unvalidated displayName → F-09), masking/redaction (EmployeeAccount.toString omits credential — clean), error-message leakage (→ F-11).
7. **`testing-for-business-logic-vulnerabilities`** — workflow bypass: the reset workflow has no prerequisite step (no current-credential proof, no operator auth → F-02); `unlock` is a one-step bypass of the brute-force protection workflow (→ F-01/F-08); `add` is self-service privileged provisioning with no approval step (→ F-01); state-ordering rules (lockout only gates sign-in, not admin paths) reviewed and consistent.

**Explicitly excluded candidates (with reason):** `testing-for-xss-vulnerabilities` (browser/JS-specific; this codebase's analogue — terminal output injection — was assessed under general CWE-152/OWASP knowledge, → F-09) and `performing-hash-cracking-with-hashcat` (offensive cracking workflow; the relevant check here is KDF *configuration*, covered by the cryptographic-audit skill). All remaining library skills (cloud/AD/ICS/OAuth/JWT/container/OT domains, 800+) have no matching surface in a local, single-tenant, network-less Java CLI.

**Statement on non-matched behaviour:** security-relevant behaviour with no matching library skill — terminal output injection (CWE-152), audit-log integrity/tamper-evidence (CWE-532), CLI account enumeration (CWE-204), and inter-process TOCTOU on shared state files — was reviewed against general OWASP Top 10 (A01 Broken Access Control, A02 Cryptographic Failures, A04 Insecure Design) and CWE knowledge, and is reflected in the findings above.

## Areas reviewed and found sound (no finding raised)

- **No username oracle:** unknown identities burn an equal-cost PBKDF2 against a per-process dummy verifier (`EmployeeAuthenticator.java:36, 43, 80`) and receive byte-identical wording to a wrong password (`AuthResult.java:45-47`); the test harness measures the timing ratio.
- **Fail-closed on unhashed/legacy credentials:** plaintext or non-strong stored verifiers are refused for sign-in with a distinct operator-facing warning, never silently accepted (`EmployeeAuthenticator.java:85-87`; `PortalCli.java:101-104`).
- **Constant-time verifier comparison** (`PasswordHasher.java:80`, `MessageDigest.isEqual`).
- **No work-factor downgrade path:** upgrades only when stored < configured (`PasswordHasher.java:94-96`); crafted verifiers with out-of-range work factor are refused at parse time (`99-124`), so a maliciously edited records file cannot force cheap or unbounded KDF work.
- **Records file hygiene:** 0600 permissions, same-directory temp file, atomic rename (`FileAccountStore.java:151-159`); in-process concurrent mutation protected by `synchronized` + CAS `replace`/`sameRow` (`FileAccountStore.java:139`, `InMemoryAccountStore.java:44-50, 79`).
- **Audit output sanitization:** control characters stripped from usernames and details before printing (anti log-forging, `ConsoleAuditLog.java:28-35, 41`); verifiers are never emitted (checked by tests).
- **Password length cap** (1024 chars, `EmployeeAuthenticator.java:28, 57`) bounds allocation cost of hostile inputs.
- **Account status gating** (PENDING_ACTIVATION/DISABLED) is checked after verification for timing uniformity (`EmployeeAuthenticator.java:106, 112`); credential char[] is wiped after use (`235`).
- **Consistent username normalization** (trim + case-fold) across store, authentication, and lockout keying (`InMemoryAccountStore.java:85`, `CredentialRecord.java:56-57`, `LockoutTracker.java:201`) — case variants of a username share one lockout bucket, which is the *safe* direction.
- **Test coverage:** `tests/AllTests.java` (138 checks) empirically verifies most of the above, including timing uniformity, file permissions, atomic rewrite, CAS behavior, cross-process lockout persistence, upgrade/no-downgrade, and the absence of passwords in any CLI/audit output.
