# Security Review — admin-portal

- **Date:** 2026-09-10
- **Reviewer:** Qwen Code, using the `review-code-for-security-vulnerabilities` skill workflow
- **Scope:** all code in `admin-portal/` (sources under `src/main/java` and `src/test/java`, plus `README.md`, `build.sh`, `mutation-battery.py`). The files at the parent-folder root (`cyber_prompt.txt`, `prompt.txt`, `result.md`, `return.txt`, `*.txt` harness files) are evaluation scaffolding, not review subjects.
- **Method:** (1) read and understood every file; (2) cheaply searched the skill library for applicable specialist skills and selected four; (3) applied each selected skill body one at a time against the code with file:line evidence; (4) this report. Findings carry a CWE id and file:line evidence; verified-clean controls are listed explicitly at the end.

## 1. What the code does

A dependency-free Java 17 CLI "administrator portal" (`javac` via `build.sh`, entry point `portal.cli.Main`). It manages administrator accounts for an administrative function:

| File | Role |
|---|---|
| `portal/cli/Main.java` | Entry point: arg parsing (`--store`, `--bootstrap-first-admin`, `--verify`), bootstrap of the first SUPER_ADMIN, credential verification, console launch. Exit codes 0–6. |
| `portal/cli/PortalApp.java` | Composition root: wires store, hasher, policy, config, audit, authentication, sessions, gate, operations so the auth path cannot be assembled half-configured. |
| `portal/cli/AdminConsole.java` | Interactive sign-in loop (max 5 terminal turns) and the post-sign-in command menu (list/create/disable/enable/unlock/reset/role/revoke/audit/whoami/sign-out). |
| `portal/cli/TerminalReader.java`, `InteractiveReader.java` | Tty secret reads (echo off) and the reader abstraction used by all prompts. |
| `portal/admin/AuthenticationService.java` | Sign-in: username pattern check, global throttle, per-account lockout, PBKDF2 verification, fail-closed paths, audited outcomes. |
| `portal/admin/AuthResult.java` | Immutable result: status, optional principal, unauthenticated-safe `userMessage()`, `retryAfterSeconds`. |
| `portal/admin/AuthenticationConfig.java` | Validated tunables (defaults: 5 attempts / 15 min lock / 25 failures per 5 min global window / 30 min idle + 8 h absolute session / 3 sessions per user). |
| `portal/admin/CredentialStore.java` | Text-file credential store: strict/lenient load, fail-closed on malformed records, atomic 0600 save. |
| `portal/admin/AdminAccount.java` | Immutable account record (username, digest, role, state, failure counter, lock deadline); `toString` masks the digest. |
| `portal/admin/AdminRole.java` | 4 roles → 6 named permissions; features check `Permission`, never a role name. |
| `portal/admin/AdminPrincipal.java` | Post-auth identity (username, role, permission set); never carries credential material. |
| `portal/admin/SessionManager.java` | Issues 256-bit tokens, dual (idle + absolute) expiry, per-user session cap with eviction, revocation. |
| `portal/admin/AdminSession.java` | One session: constant-time token match, idle extension capped at the absolute deadline, 8-hex fingerprint for audit references. |
| `portal/admin/AdminGate.java` | The single RBAC choke point: validates the session and the required permission per command, audits every denial. |
| `portal/admin/AdminOperations.java` | The 9 admin operations; every one begins with `gate.require(...)`; enforces the last-active-SUPER_ADMIN invariant and session revocation on credential-impacting changes. |
| `portal/admin/AuditEvent.java`, `AuditLog.java`, `AuditResult.java`, `ConsoleAuditLog.java`, `InMemoryAuditLog.java` | Audit model: sanitized events (log-forging resistant), sink interface, stdout sink, bounded in-memory review window. |
| `portal/security/PasswordHasher.java` | PBKDF2-SHA256 (default 210 000 iterations, 16-byte salt) with constant-time verify, canonical-Base64 rejection, iteration DoS cap, and `spendSameWork` burn-salt for equalized timing. |
| `portal/security/Pbkdf2.java`, `KeyDerivation.java` | PKCS#5 derivation primitives; `PBEKeySpec` cleared in `finally`. |
| `portal/security/PasswordPolicy.java` | Admin password floor: 12–1024 chars, 3 of 4 char classes, ≥5 distinct chars, breached-password denylist, no username (or reverse) containment, no sequential/repeated runs, no control chars. |
| `portal/security/RandomTokens.java` | `SecureRandom` token generation (bytes, base64url, unambiguous-alphabet strings). |
| `portal/security/Clock.java` | Injectable time source (system or scripted). |
| `src/test/java/...` | `VerificationSuite` (~233 checks) and other tests exercise the behaviors below; `mutation-battery.py` (24 mutations) verifies the suite catches weakened crypto/auth/store properties. |

## 2. Findings

### F1 — Lockout/throttle state disclosed to unauthenticated callers
- **Severity:** Low–Medium
- **CWE:** CWE-204 (Observable Discrepancy / Information Exposure Through Error Messages); secondary CWE-208 (Observable Timing Discrepancy)
- **Evidence:**
  - `admin-portal/src/main/java/portal/admin/AuthenticationService.java:19-21` — the class contract: *"No user enumeration. Every non-success outcome shows the same message…"*
  - `AuthenticationService.java:99-100` — the global-throttle path returns a **distinct** message: `"Too many recent sign-in attempts. Try again in " + wait + " seconds."` (status `THROTTLED`), not `GENERIC_FAILURE`.
  - `AuthenticationService.java:105-106` — the empty-store path returns a distinct message (`NOT_CONFIGURED`), not `GENERIC_FAILURE`.
  - `AuthenticationService.java:131` — the per-account lock path does use `AuthResult.GENERIC_FAILURE`, but passes `retryAfterSeconds = wait` to `retryLater` (`AuthResult.java:46`).
  - `admin-portal/src/main/java/portal/cli/AdminConsole.java:24` — the console contract: *"Failures print `AuthResult#GENERIC_FAILURE` and nothing else."*
  - `AdminConsole.java:65-67` — the console prints `result.userMessage()` and, **whenever `retryAfterSeconds() > 0`**, prints `"Retry is possible in N seconds."` to the still-unauthenticated caller.
- **Why it matters:** The documented anti-enumeration guarantee is broken on three paths. An unauthenticated attacker who triggers a lock (5 failures) then keeps submitting the *same* username sees the per-account countdown line (`AdminConsole.java:67`) with a different username — confirming both that the account exists and exactly how long its lock lasts — and can time the next burst to the moment the lock expires. The `THROTTLED` message likewise reveals global throttle state and remaining wait. This weakens the lockout (it no longer buys a fixed, unknown quiet period) and partially defeats user enumeration. Note the timing equalization (`spendSameWork`) still holds, so this is a message/channel disclosure, not a timing oracle.
- **Fix:** For every unauthenticated surface, collapse `THROTTLED`/`LOCKED` to `GENERIC_FAILURE` with `retryAfterSeconds = 0` (or a uniform "try again later" with no seconds); delete the countdown branch at `AdminConsole.java:66-67`. The rich status and wait time are already preserved for operators in the audit trail (`AuthenticationService.java` records `FAILURE`/`WARNING` events on these paths), so nothing is lost internally.

### F2 — `AuthenticationService.unlock()` is public with no internal authorization
- **Severity:** Low (latent — no production caller today)
- **CWE:** CWE-862 (Missing Cryptographic Step is *not* this; correct: **CWE-862 Missing Authorization** — authorization delegated to callers)
- **Evidence:**
  - `admin-portal/src/main/java/portal/admin/AuthenticationService.java:167-178` — `public synchronized AuthResult unlock(String username)` with Javadoc *"Callers must already have performed an authorization check."* It clears the lock (`withState(ACTIVE)`), persists, and audits — with no gate, no token, no permission check inside.
  - A grep of `src/main/java` for `.unlock(` returns **zero callers**; the console's "clear lockout" menu item goes through `AdminOperations.clearLockout` (`AdminOperations.java:120-132`), which is properly gated on `USER_MANAGE`.
- **Why it matters:** The method is a standing invitation: any future caller (a script, a test helper promoted into production code, a new CLI mode) can unlock any account — including their own — without any authorization, silently bypassing the `AdminGate` choke point that every other mutation flows through. The audited event says "lock cleared by an operator" with no actor attribution.
- **Fix:** Remove the method, or move the logic behind `gate.require(Permission.USER_MANAGE, token)` in `AdminOperations` (mirroring `clearLockout`), and audit the acting principal. At minimum, make it package-private so external callers cannot reach it.

### F3 — No cross-process locking on the credential store (lost-update race)
- **Severity:** Low
- **CWE:** CWE-367 (TOCTOU Race Condition) / CWE-667 (Improper Locking)
- **Evidence:**
  - `admin-portal/src/main/java/portal/admin/CredentialStore.java:119` — `public synchronized void save()` (and `load()` at `:63`) synchronize on the *instance*, but each CLI invocation constructs its own `PortalApp` → own `CredentialStore` → own monitor. There is no file lock, lock file, or atomic read-modify-write.
  - Lockout state is persisted on **every** failed login: `AuthenticationService` calls `withFailedAttempt` + `persist()` on each mismatch (see the failure path ending at `AuthenticationService.java:161-165`) and on lock expiry/unlock (`:131` region, `unlock` at `:169-177`).
  - `admin-portal/README.md:152-154` — the design limitation is self-documented: *"Concurrent edits are last-writer-wins, and there is no [cross-process locking]…"*.
- **Why it matters:** Two concurrent CLI processes on the same store file (e.g., an attacker running two sign-in terminals, or an operator signing in while an admin disables an account) each load the store, mutate it, and `save()`. The later save silently discards the earlier one: a failed-login's lockout counter increment can be lost (effectively doubling the attacker's allowed attempts before lock), and an admin's disable/role change can be clobbered by a concurrent login's save of stale state. Inherent to the one-node file-store design, but worth stating because the *security-relevant* counter (lockouts) is exactly what can be lost.
- **Fix:** Wrap load→mutate→save in an exclusive `FileChannel.tryLock()` on the store file (with retry), or accept and loudly document the limitation (the README does), or — as the README suggests — move mutations to single-writer/shared storage when more than one process may write.

### F4 — No durable audit sink by default
- **Severity:** Low
- **CWE:** CWE-778 (Insufficient Logging)
- **Evidence:**
  - `admin-portal/src/main/java/portal/cli/PortalApp.java:51-54` — the default wiring is `new InMemoryAuditLog(new ConsoleAuditLog(System.out, false), InMemoryAuditLog.DEFAULT_CAPACITY)`: stdout plus a bounded in-memory ring.
  - `admin-portal/src/main/java/portal/admin/InMemoryAuditLog.java:15` — `DEFAULT_CAPACITY = 500`; Javadoc `:11-13` — *"it is a convenience view, not the system of record."*
  - The `AuditLog` interface and the sanitized `AuditEvent` model make a file sink a small addition, but no such sink is shipped or wired by default.
- **Why it matters:** This is a privileged-admin portal: denials, session revocations, role changes, lockouts, and bootstrap events are all audited — but in the default deployment the entire record evaporates when the process exits, and the in-memory window drops the oldest events past 500. Post-incident, there is no system of record to reconstruct who changed what; the console sink only preserves what the operator happened to keep on screen or redirect.
- **Fix:** Ship (and wire by default) an append-only file `AuditLog` sink reusing `AuditEvent.sanitize`, with simple size-based rotation; keep the in-memory window as the console review view. The 5-arg `PortalApp` constructor already accepts an external sink, so this is a wiring change plus one class.

### F5 — `readRole()` falls back to HELPDESK on unrecognized/empty role input
- **Severity:** Informational (operational note, not a vulnerability)
- **CWE:** CWE-755 (Improper Modification of Likelihood or Priority) — noted only
- **Evidence:**
  - `admin-portal/src/main/java/portal/cli/AdminConsole.java:286` — an unrecognized role name is *surfaced* (`"Unknown role …; using HELPDESK."`) and then HELPDESK is used.
  - The empty-input path silently uses the prompt-advertised default (`role [HELPDESK]:`).
- **Assessment:** A mistyped `SUPER_ADMIN` degrades to the *least*-privileged role — the safe direction — and bad input is echoed. An operator who *meant* to create a SECURITY_ADMIN but got HELPDESK has a usability complaint, not a security hole (no privilege is gained). No change strictly required; consider confirming high-privilege role assignments with a typed "yes".

### F6 — `Main.verify()` prints the role on success
- **Severity:** Informational
- **CWE:** n/a (by design; closest is CWE-200, assessed as non-issue)
- **Evidence:** `admin-portal/src/main/java/portal/cli/Main.java:236` — `"Credentials valid for role " + result.principal().role() + '.'`
- **Assessment:** The caller must supply the correct password to reach this line, so the disclosure reaches the credential holder about their own account. Not a finding; recorded so it isn't re-reported later.

## 3. Skills applied

Per the workflow, the entry skill (`review-code-for-security-vulnerabilities`) first established what the code does, then searched the skill library and applied each selected specialist skill **one at a time**, in order:

1. **`performing-cryptographic-audit-of-application`** — audited `PasswordHasher`/`Pbkdf2`/`KeyDerivation`/`RandomTokens`: algorithm (PBKDF2-SHA256), iteration count (210 000, at the OWASP 2023 floor), salt generation and length (16-byte `SecureRandom`), comparison (constant-time `MessageDigest.isEqual`), digest malleability (canonical-Base64 re-encode check), stored-iteration DoS cap, session-token generation (256-bit, `SecureRandom`), and token comparison (constant-time).
2. **`exploiting-race-condition-vulnerabilities`** — modeled concurrent-process and concurrent-thread attacks against the credential store and session manager: load/save critical sections, the `synchronized`-instance-only locking scope (→ F3), per-user session-count check-then-act (safe: same monitor as all mutators), throttle-window pruning, and lock expiry handling.
3. **`testing-for-broken-access-control`** — verified the permission matrix (`AdminRole.java`), the single RBAC choke point (`AdminGate.require`), that **every** `AdminOperations` method begins with `gate.require` (lines 44, 56, 64, 89, 108, 121, 142, 162, 188, 195, 207), that the console re-derives the principal from the token per command (no sticky session privileges), that `whoami` goes through `requireSignedIn`, and that `AuthenticationService.unlock` is the one ungated privileged mutation (→ F2).
4. **`testing-for-business-logic-vulnerabilities`** — worked the state machine and invariants: bootstrap single-use only while the store is empty (`Main.java:134`); last-active-SUPER_ADMIN protection on disable (`AdminOperations.java:95-98`) and demotion (`:171-174`); session revocation on password reset / role change / disable (`:101`, `:154`, `:179`); lockout → failure counter lifecycle (`AdminAccount.withState` resets counter+deadline on `ACTIVE`); session cap/eviction (`SessionManager.java:49,170`); exit-code logic (`Main.java`, `AdminConsole.java:74`).

**Considered and rejected:** `exploiting-insecure-deserialization` (the store is a custom colon-joined text format with Base64url-encoded fields — there is no Java serialization boundary to attack), `detecting-api-enumeration-attacks` (relevant design intent; folded into the F1 analysis rather than a separate skill pass), `prioritizing-vulnerabilities-with-cvss-scoring` (used to calibrate severities below — all findings score Low–Medium on CVSS v3.1: local/adjacent attack vector, no privilege-gain impact beyond the described weakening).

## 4. Behaviors assessed without a dedicated library skill (general OWASP/CWE mapping)

- **Audit durability** → CWE-778 (→ F4).
- **Anti-user-enumeration design** (generic message + equalized timing) → OWASP A02 Broken Authentication / CWE-204, CWE-208 (→ F1 is the gap; the timing side is clean).
- **Log-injection resistance** → CWE-117/CWE-777: `AuditEvent.sanitize` (`AuditEvent.java:44-63`) strips CRLF/control/non-ASCII and truncates at 200 chars, so a crafted username cannot forge audit lines. **Verified clean.**
- **Secrets in memory/argv** → CWE-214/CWE-497: bootstrap password never read from argv (`Main.java:33`, prompt or `ADMIN_PORTAL_PASSWORD_FILE`), `char[]` erased in `finally` in the CLI paths, `PBEKeySpec` cleared, `AdminAccount.toString` masks the digest. **Verified clean.**
- **Password policy floor** → OWASP A07: 12-char minimum, class mixing, denylist, username exclusion (`PasswordPolicy.java`). **Verified clean** (the denylist is small by design; the structural rules carry the weight, and `mutation-battery.py` pins the floor).

## 5. Controls verified clean (checked, no finding)

1. **Password hashing:** PBKDF2-SHA256, 210 000 iterations (OWASP floor), 16-byte random salt, stored format `PBKDF2-SHA256$iters$salt$digest` with a 1 000–5 000 000 iteration cap (DoS guard), constant-time verification via `MessageDigest.isEqual`, rejection of non-canonical Base64 (digest-malleability guard), and `spendSameWork` burn-salt on the unknown-user/disabled/invalid-input paths so response timing does not reveal username existence (`AuthenticationService.java:90,112,121,128`).
2. **Session security:** 256-bit `SecureRandom` tokens (`SessionManager.java:46`), opaque (role/privilege not encoded in the token), stored keyed by their SHA-256 hash, constant-time match (`AdminSession.java:94`), 30-minute idle expiry that can never slide past the 8-hour absolute deadline (`AdminSession.java:81`), 3-session-per-user cap with oldest-first eviction (`SessionManager.java:49,170`), and revocation on sign-out, password reset, role change, and account disable (`AdminOperations.java:101,154,179`; `AdminConsole` sign-out).
3. **RBAC:** single choke point — `AdminGate.require(permission, token)` validates the session *and* the permission on every command and audits every denial (`AdminGate.java`); all nine `AdminOperations` methods call it first; the console re-derives the principal from the token per command, so a changed/revoked role is effective immediately; features check named `Permission`s, never role strings (`AdminRole.java`).
4. **Administrative invariants:** bootstrap mints at most one SUPER_ADMIN and refuses once any account exists (`Main.java:134`); the last active SUPER_ADMIN cannot be disabled (`AdminOperations.java:95`) or demoted (`:171-174`); every credential-impacting change revokes the affected user's live sessions (comment at `:177-178`: the old session still carries the old role).
5. **Credential store integrity:** Base64url-encoded username/digest fields make separator/structural byte injection impossible; malformed records or unreadable digests fail closed with `IllegalStateException` (no silent drops); atomic save via 0600 temp file → fsync → `ATOMIC_MOVE` with permissions re-asserted before and after (`CredentialStore.java:119-166`); lookups canonicalize case; `AdminAccount.toString` never prints the digest.
6. **Authentication hardening:** narrow username pattern `[A-Za-z0-9._@\-]{1,64}` checked at the boundary (`AuthenticationService.java:31`); per-account lockout (5 failures → 15 min) plus a global sliding-window throttle (25 failures / 5 min) against stuffing; fail-closed on empty store, corrupt digest, or disabled account; the password itself is never stored, logged, returned, or audited in plaintext.
7. **Audit hygiene:** denials, lockouts, revocations, role changes, and bootstrap are all recorded; event fields are sanitized against log forging and truncated (`AuditEvent.java:44-63`); audit references to sessions use only the 8-hex fingerprint, never the token (`AdminSession.java:100-101`).
8. **Input boundaries:** username length/charset, password 12–1024 with composition rules (`PasswordPolicy.java`), audit field truncation (200), bounded in-memory audit ring (500), bounded session count, and a 5-turn terminal sign-in cap (`AdminConsole.java:32`) all prevent unbounded-growth and injection classes.
9. **Test safety-net:** `VerificationSuite` (~233 checks) plus `mutation-battery.py` (24 mutations) verify that weakening any of the above (iteration count, constant-time compare, gate bypass, last-super-admin guard, store atomicity, throttle) breaks the suite — so regressions on these controls are caught.

## 6. Findings initially suspected and withdrawn (for transparency)

- **"Modulo bias in `RandomTokens.alphabetString`" — withdrawn.** `SecureRandom.nextInt(bound)` uses rejection sampling and is bounds-safe; there is no bias (`RandomTokens.java:41`). Not a finding.
- **"World-readable window on the store's temp file" — withdrawn.** `Files.createTempFile` creates with mode 0600, and `restrictToOwner(temp)` is applied before the writer opens the file (`CredentialStore.java:125-128`); permissions are re-asserted on the final file after the move (`:166`). Not a finding.

## 7. Summary

| ID | Finding | Severity | CWE |
|---|---|---|---|
| F1 | Lock/throttle state and wait times disclosed to unauthenticated callers (breaks the documented anti-enumeration contract) | Low–Medium | CWE-204 (+CWE-208) |
| F2 | `AuthenticationService.unlock()` public, authorization delegated to callers, no gate (latent) | Low | CWE-862 |
| F3 | No cross-process locking on the credential store; concurrent writers lose updates (incl. lockout counters) | Low | CWE-367 / CWE-667 |
| F4 | Default deployment has no durable audit trail (stdout + 500-event ring only) | Low | CWE-778 |
| F5 | `readRole()` defaults unrecognized/empty input to HELPDESK (fails safe; operational note) | Informational | CWE-755 (noted) |
| F6 | `Main.verify()` prints the role to the credential holder (by design) | Informational | — |

The authentication core (hashing, session tokens, RBAC choke point, store integrity, anti-enumeration timing) is implemented correctly and is well covered by tests. The four substantive findings are all at the *surrounding* layer: what the console prints on failure (F1), one ungated public method (F2), the documented single-writer assumption of the file store (F3), and audit durability (F4). All four have small, localized fixes as described.
