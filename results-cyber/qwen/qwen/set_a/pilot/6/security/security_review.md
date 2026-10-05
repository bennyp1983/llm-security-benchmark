# Security Review — `adminportal`

**Date:** 2026-09-10
**Scope:** all code in this folder: `src/adminportal/*.java` (7 files), `test/adminportal/AdminPortalTests.java`, `README.md`, `build.sh`, `demo.sh`, `mutation-check.py`.
**Out of scope:** harness files (`prompt.txt`, `cyber_prompt.txt`, `cyber_return.txt`, `prompt_hash.txt`, `result.md`, `return.txt`) and compiled outputs (`build/`, `build-test/`).

---

## 1. What the code does

| File | Responsibility |
|---|---|
| `AdminPortal.java` | CLI entry point. Commands: `verify-log`, `add-user`, `login`, `audit`, `accounts`, `set-password`, `disable`, `enable`, `unlock`. Resolves the data-directory layout (`--home`, `--store`, `--audit`, `--key`, `--lockouts`), opens the shared services, dispatches, and gates every privileged command behind `requireAdmin`. |
| `AdminUserStore.java` | Persistent administrator registry. Validates usernames against a strict grammar, stores `pbkdf2$iters$salt$hash` records, loads fail-closed on corruption, saves atomically (temp file + `ATOMIC_MOVE`) with 0600 permissions. |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256 hashing (default 310,000 iterations, 16-byte `SecureRandom` salt, 256-bit key). Constant-time comparison via `MessageDigest.isEqual`, `dummyEncoded()` timing-equalizer for unknown users, `PBEKeySpec`/`char[]` wiping. |
| `AuthenticationService.java` | Authentication and session lifecycle: per-account lockout (5 failures → 10 min), global backoff (20 failures → 30 s), disabled-account handling, transparent rehash when stored iterations differ, in-process sessions (24-byte `SecureRandom` token, 15-min TTL, first-8-char fingerprint for display only). All denials emit generic messages; the real reason goes to the audit trail. |
| `AuditLog.java` | Append-only, HMAC-SHA256 hash-chained JSONL trail (GENESIS → prevHash → canonical payload seal). Durability via `FileChannel.force(true)` before the sequence advances; fail-closed `AuditFailureException`; 32-byte HMAC key in a separate 0600 file; chain verification including keyId consistency; key material zeroed on close. |
| `AuditEvent.java` | One trail record. Field sanitization (CR/LF/tab → space, control/non-ASCII → `?`, 200-char cap), canonical 0x1F-separated payload seal, strict JSON serialization that rejects duplicate keys. |
| `AuditReviewer.java` | Query/filter over the trail (case-insensitive substring, tail limit), table/JSON export, chain verification, summary. |
| `LockoutStore.java` | Durable, cross-process failed-attempt state (`user|count|until` lines, atomic 0600 rewrite). Corrupt state is fail-closed. The reserved key `@` carries the global backoff. |
| `AdminPortalTests.java` | 18 test sections / 215 expectations covering the grammar, hashing, fail-closed loading, lockout (incl. cross-process), chain integrity and tamper detection (edit / middle-delete / tail-truncate / forged append / foreign key / reorder), sanitization, credential-leak sweeps, and CLI end-to-end. |

Threat model per `README.md`: local single-host CLI; no network surface; integrity claims are only as strong as the 0600 key file; an attacker who can already write arbitrary files as the same uid is out of scope (the trail records that they did).

---

## 2. Findings

Ordered by severity.

### F-1 — High — `audit --out` is an arbitrary file overwrite for any authenticated admin

- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Containing Directory) / CWE-73 (External Control of File Name or Path)
- **Location:** `src/adminportal/AdminPortal.java:387-391`
- **Detail:**
  ```java
  String target = inv.opt("out", null);          // :387
  Path out = Paths.get(target).toAbsolutePath(); // :389
  Files.createDirectories(out.getParent());      // :390
  fileSink = new PrintStream(Files.newOutputStream(out), true, UTF_8); // :391
  ```
  The `audit` command accepts a caller-supplied path with **no containment**. An authenticated admin (the only privilege tier this app has — see `AuthenticationService.java:424`) can point the export at any file the uid owns or any directory it can create. Concrete impacts:
  - `--out ~/.admin-portal/administrators.dat` destroys the credential store (the export stream opens with `TRUNCATE`);
  - `--out ~/.admin-portal/audit-log.key` replaces the HMAC key — the same admin can then rewrite `audit-log.jsonl` and forge a chain that verifies;
  - `--out` of any other uid-owned secret (SSH keys, other app state) is a plain overwrite.
  In an environment with multiple human admins, this is one compromised or coerced account silently erasing or forging the audit history of all the others. The traversal-testing skill's remediation guidance applies directly: resolve the canonical path and verify it stays within the intended directory.
- **Fix:** confine exports to a dedicated directory (e.g. `home.resolve("exports")`), reject any `--out` whose normalized path falls outside it or equals the store/audit/key/lockout paths, and do not create parent directories. Never derive an output path from a value that can coincide with application state.

### F-2 — Medium — Timing oracle: `--iterations` mismatch defeats the account-existence timing parity

- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Location:** `src/adminportal/AuthenticationService.java:222-225` (unknown-user path runs the dummy digest at *current* hasher cost) vs. `PasswordHasher.verify` (known-user path runs at the *stored* iteration count); flag surface at `AdminPortal.java:143` + `parseIterations` `:540-553` (any value ≥ 1,000 accepted).
- **Detail:** The design intent (stated in `AuthenticationService` and enforced by the timing-parity tests) is that login latency reveals nothing about whether an account exists. That only holds when the CLI's iteration count equals the stored one. A brute-forcer who passes `--iterations 1000` against a store provisioned at the 310,000 default gets:
  - known user → `verify` executes the stored 310k PBKDF2 rounds (slow),
  - unknown user → `dummyEncoded()` executes only 1,000 rounds (fast).
  The ratio is ~300× — a trivially measurable difference — which enumerates valid usernames despite the dummy digest. The reverse mismatch (CLI > stored) leaks in the other direction. The fix must make both branches cost at least as much as the most expensive stored hash.
- **Fix:** compute the dummy digest at `max(current iterations, max stored iterations)` (the store can expose that in O(n) over usernames), or refuse to run authentication when the CLI iterations differ from the stored minimum; either way, re-verify the timing-parity test with a mismatched `--iterations`.

### F-3 — Medium — Bootstrap `add-user` race: concurrent first-run provisioning can plant or clobber an admin account

- **CWE:** CWE-362 (Race Condition) / CWE-367 (TOCTOU)
- **Location:** `src/adminportal/AdminPortal.java:162` (`!store.isEmpty()` gate) and `:292` (`boolean bootstrap = store.isEmpty()` inside `provision`); `AdminUserStore.java:91-109` (`isEmpty()`/`create()` are `synchronized` **per JVM**; `save()` rewrites the whole file — last writer wins).
- **Detail:** On first run the portal deliberately allows an unauthenticated `add-user` (there is nobody to authenticate against — the correct design for initial provisioning). But the check (`store.isEmpty()`) and the act (`create()` + full-file `save()`) are not atomic across processes. Two `add-user` invocations started before either persists both observe an empty store, both create, and the second `save()` silently discards the first account's record. A local attacker who can race the operator's first run plants their own admin account (or wipes the operator's). `synchronized` gives no cross-JVM guarantee here.
- **Fix:** make bootstrap atomic — e.g. create the data directory with `Files.createDirectory` (fails if it exists) as the claim, or open the store file with `StandardOpenOption.CREATE_NEW` before first write; on contention, the loser must authenticate or abort rather than provision.

### F-4 — Low — No password minimum or complexity policy

- **CWE:** CWE-521 (Weak Password Requirements)
- **Location:** `src/adminportal/AuthenticationService.java:191-194` (only empty and >256-char secrets refused); `AdminPortal.java:501-521` (`readSecret` refuses only empty input); `PasswordHasher.encode` (no policy checks).
- **Detail:** A one-character password is accepted for both `add-user` and `set-password`. The auth-weaknesses skill's weak-password checklist (1-char, dictionary words) fails against this code by construction — the lockout (5 fails/10 min) bounds online brute force, but a 1-char password is inside even a locked-down search space, and scripted offline attacks on a stolen `administrators.dat` are unbounded.
- **Fix:** enforce a minimum length (≥ 12 is reasonable for a local admin store) and reject a small deny-list of trivial passwords at `encode` time; keep the check server-side (it already is, since hashing happens in `PasswordHasher`).

### F-5 — Low — Unvalidated data-directory options let unauthenticated commands create state at caller-chosen paths

- **CWE:** CWE-73 (External Control of File Name or Path), mild variant of F-1
- **Location:** `src/adminportal/AdminPortal.java:139-142` (`--store/--audit/--key/--lockouts` resolved with `Paths.get` and no validation); `AuditLog.openWithKey` creates the audit file (0600) when absent and `createDirectories` for its parent (`AuditLog.java:99`-area, `resumeChain` `:108-124`).
- **Detail:** `verify-log` requires no authentication, yet it will create an empty `audit-log.jsonl` (and its parent directories) and a key file at whatever paths the caller supplies. `add-user` on first run does the same for all four files. For an operator CLI this is largely by design (the README frames these flags as deployment layout), but combined with F-1 it means *unauthenticated* commands already reach file-creation at arbitrary paths, so the authenticated `--out` hole is one step away from being the only authenticated-only risk in the app.
- **Fix:** treat the five path options as operator configuration and validate them at parse time: absolute or under `--home`, refuse paths equal to each other, and (with F-1 fixed) refuse export paths that alias them. At minimum, `verify-log` should not create files when the caller only asked to verify.

### F-6 — Low — HMAC key stored in cleartext (0600 file)

- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information) / CWE-320
- **Location:** `src/adminportal/AuditLog.java:331-360` (`loadOrCreateKey`: 32 random bytes written in the clear), `:373` (0600 permissions); own javadoc `:36-37` states the production floor.
- **Detail:** The key that seals the entire audit chain lives on disk in plaintext, protected only by POSIX permissions. Any read of the file (backup systems, snapshots, a same-uid process, an admin running `cat`) yields total audit-forgery capability. The code's own javadoc acknowledges this: *"In production the key belongs in a KMS or an HSM; a 0600 file … is the honest floor."* Reported here because the sensitive-data-exposure skill's data-at-rest category flags it even when acknowledged.
- **Fix (production):** move key custody to a KMS/HSM or at least encrypt the key file with a passphrase or envelope key; until then, document it as an accepted residual risk (the README does) and ensure key files are excluded from backups.

### F-7 — Low — Global backoff self-latches: once tripped, *any* single failure re-triggers the 30 s lockout for everyone

- **CWE:** CWE-400 (Uncontrolled Resource Consumption) — self-inflicted availability
- **Location:** `src/adminportal/AuthenticationService.java:380-396` (`registerFailure`): the global counter is only ever cleared on a *successful* login (`clearGlobal`) or by the threshold branch clearing the *per-account* key (`:388-391`), never the global key.
- **Detail:** After 20 cumulative failures (across all accounts), `global.count` stays ≥ 20 forever (short of a success). From that point, the `count >= threshold` test is true on **every** subsequent `recordFailure`, so a single typo by a legitimate admin imposes a 30-second backoff on *all* logins, indefinitely re-armed. This is a resilience quirk rather than an attacker-enabler (it throttles attackers even harder), but it converts one human mistake into a permanent global tax until the next successful login — worth fixing because "unlock" does not clear it either (`unlock` only clears the per-account state, `AdminPortal.java:248-258`).
- **Fix:** reset `global.count` to 0 when the 30 s deadline is set (the backoff is the penalty; the counter's job is detecting *runs*), or decay it with wall-clock time; include the global bucket in `unlock`.

---

## 3. Documented limitations (not re-reported as findings)

These are explicitly scoped out in `README.md` / javadoc and are restated here for completeness:

1. **Same-uid attacker can delete `lockout-state.dat` or the whole trail** — the LockoutStore javadoc (`LockoutStore.java:20-23`) and README both state integrity is bounded by the key file; an attacker with arbitrary same-uid file write already owns the box. Host-level controls are the remedy.
2. **Tail truncation of the JSONL is undetectable** — the chain detects edits, middle deletions, reordering, and forged appends (all covered by tests), but deleting the *last* N lines and re-appending a forged tail verifies if the attacker knows the key (i.e. only when the key is also compromised). Documented as a known limit.
3. **No MFA / single admin role** — every account has the full privilege set (`AuthenticationService.java:424`); there is no second factor. README lists this as a deliberate scope decision for a local CLI.
4. **In-process sessions** — tokens exist only for the lifetime of one CLI invocation (the `login` command's dashboard); there is no token persistence, so replay across processes is structurally impossible.
5. **Wall-clock lockout deadlines** — NTP step-back on the host shortens lockouts; documented.
6. **`--actor` is caller-settable on `verify-log`** (`AdminPortal.java:523-525`) — it is sanitized by `AuditEvent.sanitize` and recorded, but never verified; the CLI injection test confirms it stays inert (no structural tampering of the trail).

---

## 4. Skills applied

Per the router skill's workflow, I searched the sibling library at `/root/.qwen/skills/` (819 skills) by name/keyword and applied the selected skills one at a time, in order:

1. **`performing-cryptographic-audit-of-application`** — cross-checked every primitive against the skill's weakness categories (weak hashing, insecure ciphers/modes, small keys, weak KDF parameters, hardcoded secrets, entropy sources). Result: PBKDF2-HMAC-SHA256 at 310k iterations with random salts, HMAC-SHA256 chain seals, `SecureRandom` throughout, constant-time comparison, no hardcoded keys — clean; exposed F-4 (no KDF floor: `MIN_ACCEPTABLE_ITERATIONS` defined at `PasswordHasher.java:28` but never enforced — the constructor accepts ≥ 1,000) and F-6 (key at rest).
2. **`testing-api-authentication-weaknesses`** — worked the skill's checklist: unauthenticated endpoint discovery (bootstrap `add-user` → F-3), session-token entropy/expiration/revocation (24-byte `SecureRandom`, 15-min TTL, `recordAction` requires an active session — clean), token leakage (only 8-char fingerprints reach the trail; leak-sweep tests confirm — clean), account enumeration (generic denials + dummy-digest parity — clean *until* F-2's iteration mismatch), password policy (→ F-4), weak-password acceptance.
3. **`performing-directory-traversal-testing`** — mapped every path parameter (`--out`, `--store/--audit/--key/--lockouts/--home`), applied the skill's "read high-value files" step to the app's own high-value files (credential store, HMAC key), and used its remediation section (allowlist of permitted names; canonical path must stay within the intended directory) as the fix language for F-1 and F-5.
4. **`implementing-log-integrity-with-blockchain`** — evaluated the hash-chained trail against the skill's tamper-detection model (per-entry hash chaining, verification by replay, external anchoring). The chain design is sound and exceeds the skill's baseline (durability `force(true)`, keyId rotation support, fail-closed); the skill's "anchor hashes externally" step is the missing piece — nothing outside the key file pins the chain, which frames F-6's impact and the documented tail-truncation limit.
5. **`testing-for-broken-access-control`** — built the skill's endpoint × privilege matrix for all 9 commands. Every privileged command calls `requireAdmin` inside its handler *before* any store mutation (verified per command: `audit` :180, `accounts` :191, `set-password` :207, `disable`/`enable` :229/:240, `unlock` :249). The skill's mass-assignment/role-manipulation scenario does not apply: there is no client-influenceable role field — the privilege set is server-side fixed by `privilegesFor` (`AuthenticationService.java:424`). The matrix's single unauthenticated write path is the bootstrap `add-user` → F-3. No horizontal tier exists (single role), so IDOR-style escalation is not applicable; `set-password`/`disable` on other accounts is by-design admin behavior and is fully attributed in the trail.
6. **`testing-for-sensitive-data-exposure`** — scanned source for hardcoded secrets (none), checked data at rest (hashes only in the store → clean; cleartext HMAC key → F-6), checked response over-exposure (`accounts` prints username/state/iterations/lockout only — no hashes, no tokens), checked logs (no password or full session token in the trail; denials generic), checked transmission (no network surface; secrets entered via `Console.readPassword` or stdin, never argv, so no `ps`/history exposure).

## 5. General-knowledge areas (no matching library skill)

The following findings/assessments rely on general OWASP/CWE/security knowledge rather than a specific library skill, per the router's reporting requirement:

- **F-2 (timing oracle)** — general timing-side-channel reasoning applied to the mismatch between the dummy digest's cost and the stored hash's cost; no skill in the library covers KDF-cost side channels.
- **F-3 (bootstrap TOCTOU)** — general race-condition/atomic-file-creation knowledge (`CREATE_NEW`, directory-claim patterns); the access-control skill supplied the matrix context, but the race itself is standard CWE-362 analysis.
- **F-7 (global backoff latch)** — functional/availability analysis of the counter lifecycle; CWE-400 mapping from general knowledge.
- File-permission semantics (0600, atomic rename, `force(true)` durability ordering) and the "same-uid attacker" threat-model boundary are general POSIX knowledge.

## 6. Checked and clean

- **Hashing:** PBKDF2-HMAC-SHA256, 16-byte random salts, distinct salt per encode, 256-bit derived key; malformed/foreign/short encoded strings rejected without exception-based short-circuits; constant-time `MessageDigest.isEqual` (`PasswordHasher.java:93`); `PBEKeySpec` + `char[]` wiped on every path (`PasswordHasher.java`, `AdminPortal.java` finally-blocks).
- **Account enumeration (nominal):** identical denial text for unknown user / wrong password / disabled / locked out (`AuthenticationService.java:375-376`); unknown-user path performs a real PBKDF2 run of the same nominal cost; timing-parity tests at 0.75–1.35× ratio. (Caveat: F-2.)
- **Session handling:** 24-byte (192-bit) tokens from `SecureRandom`, 15-minute TTL, revocation on close, `recordAction` refuses inactive sessions (`AuthenticationService.java:294-299`), only an 8-char fingerprint is ever displayed or logged.
- **Audit trail integrity:** chain verification catches field edit, middle deletion, record reorder, forged append, and foreign-key append (tests 497–575); sequence gaps and mixed keyIds rejected; `force(true)` precedes the sequence advance so a crash cannot skip records; audit open/append failures fail closed (`AuditFailureException`) rather than silently skipping records.
- **Input hardening:** all trail fields sanitized (CR/LF/tab → space, control/non-ASCII → `?`, 200-char cap, `AuditEvent.java:27-39`); strict JSON parser rejects duplicate keys and malformed lines (no structural injection via `--actor` — CLI test); username grammar `[A-Za-z0-9][A-Za-z0-9._@-]{0,63}` (`AdminUserStore.java:32`, `:78`).
- **File hygiene:** every state file written atomically (temp + `ATOMIC_MOVE`) with 0600; corrupt store/lockout state is fail-closed (`AdminUserStore.load`, `LockoutStore.open`); HMAC key bytes zeroed in `close()` (`AuditLog.java:323-328`).
- **Credential hygiene:** no plaintext passwords, full tokens, or keys in the trail (dedicated leak-sweep tests); secrets entered via non-echoing `Console.readPassword` or `--pw-stdin`, never via argv.
- **No applicable surface:** no HTTP/SQL/shell-exec/deserialization/network code paths exist in `src/`, so injection-class findings (SQLi, XSS, RCE, SSRF, deserialization gadget chains) are not applicable. `build.sh`/`demo.sh`/`mutation-check.py` are development harnesses (javac flags, command runners, a 15-mutation detection battery) and introduce no runtime attack surface.

---

**Summary:** 1 High (F-1), 2 Medium (F-2, F-3), 4 Low (F-4–F-7), plus six documented-by-design limitations. The cryptographic core, input sanitization, fail-closed behavior, and audit-chain design are consistently strong; the residual risks concentrate in the two caller-controlled path surfaces (F-1, F-5), one timing side channel (F-2), one first-run race (F-3), and policy/availability gaps (F-4, F-6, F-7).
