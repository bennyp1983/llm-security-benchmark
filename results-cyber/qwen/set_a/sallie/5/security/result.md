## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 407ff184-be27-4c48-920f-9bd6bf0c6df2
- **Input tokens:** 10607873
- **Output tokens:** 101924
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 10709797
- **Duration:** 35m 16.039s
- **Turns:** 103

---

Done. Let me write the final summary. Keep it structured but not bloated. Include:
- what was built + where
- how the guessing prevention works (the core ask)
- how to run
- verification results (381 checks, 11/11 mutants, CLI runs)
- two design notes worth knowing (uniform timing decoy; the status/strip issues found & fixed)
- limits

Also mention README.md is plain English as asked.
</think>

Done. Built and verified a Java 17 sign-in module in `/data/results/qwen/set_a/sallie/5/security`.

**Code** — `src/main/java/portal/auth/` (12 files, compiles clean under `-Xlint:all -Werror`):

| File | Role |
|---|---|
| `Authenticator.java` | the login decision |
| `LoginAttemptTracker.java` | consecutive-failure counters + lock |
| `PasswordHash.java` | salted PBKDF2-SHA256, constant-time compare |
| `CredentialValidator.java` | username/password syntax rules |
| `CredentialStore`, `InMemoryCredentialStore`, `TextFileCredentialStore`, `EmployeeRecord` | the records store |
| `AuthResult`, `LoginResult`, `CredentialPrompter`, `EmployeePortalApp` | results, console I/O, the CLI |

`README.md` is the plain-English guide; `samples/employees.txt` is a working records file.

**Guessing prevention** — 5 consecutive failures on one username ⇒ 15-minute lock (`--max-failures`, `--lock-minutes`). While locked the password is never tested, so the *correct* password is refused too. The lock expires by itself and the counter restarts; a success resets it; guessing during a lock neither extends it nor spends more attempts. Failures are counted for **non-existent usernames too**, so "which names are real" can't be probed via the lock. Verified live: 4 plain refusals, the 5th announces the lock, and `C0ffee#Mug77` (Bob's real password) is then refused.

**Verification** — 381 assertions (`AuthenticationTest`), no framework needed, all passing; `tools/mutation-check.sh` breaks one guard at a time and all **11 mutants are killed by assertions**, 0 survivors, 0 harness errors. Timing across six answer types (unknown name, wrong password, locked, bad name, bad password, granted) is within 1.04x, with each branch paying ~70 ms — the decoy PBKDF2 run that stops a stopwatch from revealing which usernames exist.

**Two defects my own review caught and fixed:** the CLI's `input.strip()` was silently repairing `alice.jones<tab>` into the real account (undoing the validator's rule — now passed through raw, with a test that counts grants), and the unauthenticated `status` command printed `account exists : true`, handing back exactly the fact the sign-in path works to hide.

**Limits stated in the README:** counters are in-memory (restart clears locks), no per-IP limit, `status`/`unlock` need an admin role, no password-strength policy, no session or transport layer.
