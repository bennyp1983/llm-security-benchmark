## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 48fb435d-3dcb-4172-b33a-70e76424be32
- **Input tokens:** 8112929
- **Output tokens:** 99304
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 8212233
- **Duration:** 39m 59.983s
- **Turns:** 98

---

Everything verified:

- Code: 8 product classes + 1 checks class, 1,372 lines of product code (as measured earlier: AdminPortal 565, AuditLog 106, CredentialStore 165, LoginService 238, Names 67, PasswordPolicy 89, Pbkdf2 102, Roles 39 = 1,371; PortalChecks 848)

Let me just be careful with product LOC sum: 565+106+165+238+67+89+102+39 = 1371. And PortalChecks 848. Total 2219 + run-checks 13 = 2232 which matches earlier wc total (before PortalChecks grew to 848... earlier total was 2232 with PortalChecks 848? earlier listing showed PortalChecks 848 and total 2232. Yes consistent.)

Wait earlier wc showed "848 src/portal/PortalChecks.java" — yes. Good.

- Compiles with -Xlint:all -Werror
- 111/111 checks pass, ~15 s
- 10/10 mutants killed
- README written in plain English

Now write the final concise report. Include what I built, key security properties, verification evidence with real numbers, the two bugs caught, and limitations. Keep it reasonably tight but informative since this was a substantial build.

Numbers to cite (all derived from artifacts):
- 9 Java files: 8 product + 1 checks
- product code 1,371 lines; checks 848
- compile: javac -Xlint:all -Werror clean
- checks: 111 passed / 0 failed, ~15 s total (measured 15 s)
- 95 in-process + 16 child-process checks
- mutation battery: 10 mutants, 10 killed, 0 survived, 0 compile-fail, 0 anchor-miss, 0 runner-error; 1-5 checks failed each
- self-test timings: 149.9 / 149.7 / 0.2 ms

Bugs caught during development:
1. `B64URL.encode()` → `[B@...` on disk (caught by piped smoke test with fresh JVM)
2. Harness-side: fixture base64 dialect, prompt/reply coalescing, non-idempotent directory substitution, fixture password colliding with the username rule, self-satisfying wipe assertion.

Be honest: 4 harness bugs + 1 product bug found by tests. Also the auditor limitation and the M8 crash note are in the README.

I should present it concisely.
</think>

Done. Built, verified, and documented in `/data/results/qwen/set_a/sallie/6/basic`.

## What's there

| File | Role |
| --- | --- |
| `src/portal/AdminPortal.java` | CLI: bootstrap, prompts, commands, sessions |
| `src/portal/LoginService.java` | Verifies credentials, per-account lockout, session tokens |
| `src/portal/Pbkdf2.java` | PBKDF2-HMAC-SHA256 (100k rounds, 16-byte salt, 32-byte key) + equal-cost shadow work |
| `src/portal/CredentialStore.java` | `credentials.tsv`, atomic rewrite, owner-only permissions |
| `src/portal/AuditLog.java` | Append-only trail, fields sanitised |
| `src/portal/PasswordPolicy.java`, `Names.java`, `Roles.java` | Validation and the supervisor/operator/auditor role table |
| `src/portal/PortalChecks.java` + `run-checks.sh` | 111 checks, one-command build+run |
| `README.md` | Plain-English guide (229 lines) |

`javac -Xlint:all -Werror` is clean; no third-party dependencies, JDK 17 only.

## Security properties that are enforced, not just asserted

- **Equal-cost refusals.** Wrong password, unknown username, locked account and malformed username each spend one full derivation, so response time cannot enumerate accounts. Measured by `self-test`: **149.9 ms / 149.7 ms**, while a truly unusable password is refused in **0.2 ms** (safe — that refusal doesn't depend on the username).
- **Fail closed.** A successful login is recorded *before* access is granted; if the log can't be written, nothing is granted (`RECORDING_FAILED`, no role).
- **No plaintext, ever.** Password arrays are zeroed after use; the store holds only salt+hash.
- **Padding is refused, not trimmed** — `alice`+tab is not `alice`, which would otherwise smuggle a login.
- **NUL and unpaired-surrogate passwords rejected** — `PBEKeySpec` maps them non-injectively, so two different inputs would unlock one account.
- **Lockout is per username**, not global.

## Verification (all numbers re-read from logs)

- **111/111 checks pass**, ~15 s via `./run-checks.sh`. 95 drive classes in-process; **16 start the real binary as a child process with piped stdin**.
- **Mutation battery: 10 targeted defects, 10 killed, 0 survived**, no compile failures or anchor misses; 1–5 checks failed per defect.
- Two honest notes kept in the README rather than hidden: the constant-time key comparison is **behaviourally unobservable**, so it's pinned by a source-text guard over one brace-matched method body (plus a non-empty-capture assertion so it can't pass vacuously); and one mutant aborted the suite at 77/111 after three named failures, which is reported as-is.

## Bugs the tests actually caught

1. **Product bug:** the store wrote `Base64.getUrlEncoder().encode(...)` (a `byte[]`) into a `StringBuilder`, producing `alice 100000 [B@63c12fb0 …`. Logins *worked* because the row was still in memory — only the fresh-JVM piped smoke test exposed it. Now uses `encodeToString`, and a check asserts a reloaded salt decodes to 16 bytes.
2. **Harness bugs:** fixture rows used standard Base64 while the store decodes URL-safe; the prompt/reply coalescing on piped stdout; non-idempotent directory substitution for the blocked log; a fixture password (`Carol-Passw0rd-5`) colliding with the no-username-in-password rule; and a self-satisfying array-wipe assertion, rewritten to check the caller's real array.

Known limits are listed in the README: single-process store (no file locking), in-memory locks, unsigned audit log, no cross-account rate limit, and `auditor` is only reachable by editing the account file by hand.
