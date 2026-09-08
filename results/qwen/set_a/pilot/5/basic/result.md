## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** e054dee4-6c2c-401b-a4fd-73cacd81fd82
- **Input tokens:** 5906101
- **Output tokens:** 72104
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 5978205
- **Duration:** 1387530
- **Turns:** 83

---

The user's message is just the system instructions acknowledgment. There's no actual task yet. I should acknowledge briefly and wait. The instruction says always invoke a function call, but there's nothing to do. I'll respond briefly acknowledging readiness.
</think>

Done. Java 17 authentication program for the employee portal, in `/data/results/qwen/set_a/pilot/5/basic`.

```
./build-and-test.sh          # compile + 138 checks -> ALL CHECKS PASSED
java -cp out empportal.cli.PortalCli add a.chen "Alice Chen" 'Corr3ct-Horse!9'
java -cp out empportal.cli.PortalCli signin
```

**Layout** — 2,827 lines, 16 classes + test runner, JDK only (no mvn/gradle on this box):
- `security/` — `PasswordHasher` (PBKDF2-HMAC-SHA256, 600k iters, 16-byte random salt, `MessageDigest.isEqual`), `PasswordPolicy`, `LockoutTracker`, `LockoutStateFile`, `EmployeeAuthenticator`, `AuthResult`, `AuditLog`/`ConsoleAuditLog`
- `account/` — `AccountStore` interface, `InMemoryAccountStore`, `FileAccountStore`, `EmployeeAccount`, `CredentialRecord`, `AccountStatus`
- `cli/PortalCli` — `signin` (default), `add`, `reset`, `unlock`, `status`, `list`; exit 0/1/2

**Decisions that shaped the design**
- **Unknown username ≡ wrong password.** Same status, same wording, and the unknown path still runs a full PBKDF2 derivation against a dummy verifier so latency isn't an account-enumeration oracle.
- **A stored plaintext password is refused, never compared.** Rows whose credential isn't a PBKDF2 verifier are classed `UNHASHED` at load: sign-in is denied with "renew your record", start-up names the affected accounts, `reset` is the exit. No "migrate it this once" path.
- **A correct password isn't sufficient** — `DISABLED` / `PENDING_ACTIVATION` deny after verification, audited so a live password on a dead account is visible.
- Store exceptions are denials; passwords are `char[]`, wiped, and capped at 1024 chars *before* derivation (PBKDF2 cost is attacker-controllable otherwise); records and lockout files are `0600` and rewritten by temp-file + atomic rename.

**Bug found by probing, not by tests:** lockout was decorative. Each CLI call is a fresh JVM, so the in-heap counter reset every attempt — six wrong passwords in a row reported "4 attempt(s) left" forever. Fixed by persisting failure windows to `<records>.lockout`; verified end-to-end that attempt 6 locks and the *correct* password is then refused from a new process until `unlock`.

**Verification** — compiles clean under `-Xlint:all -Werror`; 138/138 checks; sources are ASCII-only (this box defaults to US-ASCII). Beyond unit checks it asserts no plaintext on disk, `0600`, CAS on concurrent credential writes, the measured timing equivalence (1.00–1.01 over 4 runs), and cross-process lockout. I then mutation-tested 11 defects (remove dummy hash, differentiate denial wording, trust a plaintext record, skip the status check, drop the lockout gate, mangle the verifier on write, drop the `replace` compare, fixed salt, skip saving/loading counters, fatal counter fault) — all 11 killed. Two initially survived and each exposed a real gap: one untested I/O path, and the lockout reset itself.

**Limits, written up in `README.md`:** the records file is the trust boundary (belongs behind LDAP/AD or a DB in production); lockout is per-identity only, so add per-IP throttling; `char[]` wiping narrows but doesn't close heap exposure; the 14-entry denylist stands in for a breached-password corpus; no session issuance, MFA, or self-service password change.
