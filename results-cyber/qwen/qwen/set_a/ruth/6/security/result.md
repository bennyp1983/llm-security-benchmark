## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 13ecc480-7964-43c5-96db-4f842128e9de
- **Input tokens:** 16082916
- **Output tokens:** 175265
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 16258181
- **Duration:** 1h 6m 23.526s
- **Turns:** 176

---

Everything is done. Let me write the final report — concise but complete, covering deliverables, what the log records, verification results (including the honest survivor), and how to run.

Also, should I save any project memory? The instructions say memory is for cross-conversation knowledge. The mutation lesson is already saved (user-level feedback). Project memory dir is empty. Is there anything worth saving project-scoped? This is a one-shot deliverable directory (`/data/results/qwen/set_a/...` looks like an eval harness dir), so project memory is low-value here. The durable lessons are already saved in user memory. I'll skip additional memory writes.

Final report.
</think>

Done. Both deliverables are in `/data/results/qwen/set_a/ruth/6/security`.

## What's there

| File | |
| --- | --- |
| `AuthService.java` | The implementation (JDK 17 only, no deps) + runnable demo |
| `AuthServiceTest.java` | 242 self-contained checks, no test framework |
| `README.md` | Behaviour, full log field legend, compile/run, measured costs, verification results, limitations |

```bash
javac -d out AuthService.java AuthServiceTest.java   # clean under -Xlint:all -Werror
java -cp out AuthService          # scripted scenario, prints the audit log as it is written
java -cp out AuthServiceTest      # exits non-zero on failure
```

## What the log records

One ASCII line per attempt, ordered `key=value`, absent values written as `-` so every record has the same shape:

```
event outcome reason attempt subject subjectState account accountState ip session agent
failures lockedUntil previousSuccess previousSuccessIp policy recordError elapsedMs
```

The log-adequacy decisions that matter: `previousSuccess`/`previousSuccessIp` and the failure counter are carried **on the failure records** (that's what separates a typo from an intrusion, and it's useless on the success line only); `subject` records the name *typed* plus `subjectState=malformed(<cause>)`, so a probe is distinguishable from a real account miss; the threshold-crossing attempt is one record escalated to `WARNING` rather than two lines, so a record count equals an attempt count; `attempt` is the same id the subject was shown, which ties a support ticket to a line.

## Verification

- `javac -Xlint:all -Werror` clean; `RESULT: all 242 checks passed`; demo and README's API snippet both compile/run from a clean directory.
- Equal-cost refusal measured: 81–88 ms across all five refusal shapes (86/88/85/87/87 on the documented run). Absolute numbers drift between runs — what the suite pins is the ratio window `[0.75, 1.4]` plus a 20 ms floor.
- **Mutation battery: 45 of 46 mutants killed, 0 harness problems.** The two mutants that survived the previous pass were real test gaps, not noise — the suite checked the request's `toString` redaction but never the *stored record's*, and it asserted "the caller's buffer still holds the password" which stays true even when the request adopts the caller's array. Both are now pinned (record redaction; array identity + "destroying the request leaves the caller's buffer alone").
- **1 survivor, reported rather than deleted:** `login-does-not-wipe-working-copy` deletes the `finally` wipe of `login()`'s local `candidate`, which comes from `request.passwordCopy()`, never escapes the method, and can't be captured because `PasswordHasher` is `final`. No assertion against the public API can distinguish that build. Killing it would mean un-`final`ing a class to let a fake retain a password array — so it's documented as an equivalent mutant in the README instead. The wipes that *are* observable (`destroy()`, caller-buffer survival) are all killed.

Removed the `out/` build directory from the deliverables; the documented `javac` command regenerates it.
