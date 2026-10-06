## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 43a3d1fe-7aa6-43e7-b332-fdd94a07da51
- **Input tokens:** 9736238
- **Output tokens:** 116283
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 9852521
- **Duration:** 1h 5m 47.17s
- **Turns:** 55

---



The late-returning survey agent's report on the test suites and `tools/mutate.py` has now arrived. I cross-checked its claims directly against the read-only source before incorporating anything:

**Verified and added to §6 of `security_review.md` (as observations, not new findings):**
- **Production test seams** — five `*ForTesting` methods ship in `src/main`: `AuditClock.useForTesting` (public static clock override, `AuditClock.java:32`), `ThrottleManager.setTimingControlsForTesting` (`:332`, can disable timing padding), `ThrottleManager.clearAccountForTesting` (`:387`, public lockout reset), and two public `AuditLog` accessors (`:84,:88`). Grep confirms they are definition-only in production code paths — reachable only in-process, which requires prior code execution, so they're residual hardening surface rather than a vulnerability.
- **Mutation-harness footguns** — `mutate.py:414` unconditionally `rmtree`s the `MUT_WORK`-overridable scratch path (`/tmp/qmut`) at startup, and mutant M13's cleanup `os.rmdir`s the empty root-owned `/etc/portal-x` (`:294-303`). Dev-tool-only hazards, documented; all subprocess calls use argument lists, so the `shell=isinstance(cmd, str)` helper at `:206` never fires.

**Corroborations needing no change:** the agent independently found no test asserting insecure behavior (matching §6), and the suites' `sourceTextGuards()`/identical-header-set assertions pinning past regressions (removed `withHsts` flag, CR line-folding auth bypass) enriched the existing coverage bullet. Its note that the 100k-iteration PBKDF2 floor sits below current OWASP guidance was considered and left as-is: it's a documented, config-tunable policy floor that the README already acknowledges as a limitation, not a code defect.

The five findings (SEC-01 High → SEC-05 Low) and the rest of the report are unchanged. `security_review.md` remains the only file written; the source folder was never modified.
