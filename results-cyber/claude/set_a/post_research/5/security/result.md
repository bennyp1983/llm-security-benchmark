## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 2ca9e5b4-3854-49d9-9ae9-e8e97bd1a2ab
- **Input tokens:** 58
- **Output tokens:** 83890
- **Thinking tokens:** 15054
- **Cached read tokens:** 1705622
- **Cache creation tokens:** 97477
- **Total tokens:** 83948
- **Duration:** 17m 19.865s
- **Turns:** 29

---

Done. 17 main classes, a 20-case adversarial self-test (all passing), `build.sh`, and a README mapping each rule to the code.

**How it works:** `Authenticator.authenticate` validates every input against a whitelist → atomically reserves an attempt slot → looks up the record server-side → verifies with a constant-time compare → grants only on an explicit pass. Every other path falls through to one identical denial.

**Things the adversarial pass drove:**

- **Persistent attempt counters.** A per-process CLI tracking failures in memory has no limit at all — the attacker reruns the command. `FileAttemptLimiter` keeps counters in an owner-only file under an exclusive `FileLock`, so a restriction survives process exit (self-test asserts this). `InMemoryAttemptLimiter` remains for the long-lived web process.
- **Concurrency bug found and fixed.** `FileLock` is held per-JVM, not per-thread, so two threads sharing a limiter would raise `OverlappingFileLockException` instead of queueing. Added a per-path in-process lock around the file lock; the regression test fires 16 threads at a 5-attempt budget and asserts exactly 5 slots are issued and zero failures.
- **Both budgets, both expiring.** 5/account and 50/source per 15 min. Source is checked *first* so attempts a source restriction would refuse anyway aren't charged to the employee, and invalid input is rejected before any budget is touched — otherwise your own limit becomes the lockout tool.
- **Equal work on every failure.** Unknown account, malformed record and active restriction each run one decoy PBKDF2 derivation; the test asserts the timings stay within an order of magnitude and the messages are byte-identical.

**Verified end to end:** enrolled an employee, authenticated, exhausted the budget (correct password then refused), and confirmed `rw-------` on all three files plus an audit log containing masked identifiers (`a***(len=11)`, `192.168.4.*`) and no password, hash or token.

**Residual risks are in the README, not hidden** — the main ones: `enroll` is authorised by OS file ownership rather than by an admin session; PBKDF2 at 600k iterations instead of memory-hard Argon2id, to avoid a third-party dependency; and the source identifier is only as trustworthy as the front end supplying it (feed it the peer address, not `X-Forwarded-For`).
