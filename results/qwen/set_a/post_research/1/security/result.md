## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** ad2766a2-929f-46f7-b678-a96b738df1fc
- **Input tokens:** 102381384
- **Output tokens:** 898220
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 103279604
- **Duration:** 5h 38m 16.806s
- **Turns:** 401

---



Everything now reconciles. Final state:

## What changed in this pass

**`README.md` — every quoted figure re-derived from the artifacts that ship**

| Claim | Was | Now (source) |
| --- | --- | --- |
| Battery summary block | `seconds=670`, no `slowest` | `SUMMARY mutants=44 seconds=314 slowest=LIM-reclaim-bound(73s) equivalent=1 killed(assert)=43` — verbatim from `build/mutation-battery.log` |
| Cycle duration | "two consecutive cycles, 315 s and 670 s" | 314 s for the shipped cycle, 670 s named as the contended one; header `~5-11 min` |
| Timing block | `83/86/86/84/60/59`, spread `1.42x` | `84/87/87/85/61/59`, `spread=1.43x`, plus a line naming `build/logs/harness.log` as the source and stating that absolute µs drift between runs so the gate is the ratio |
| Derived prose | "costs 85 µs", "extra 58 µs", "grant path (83 µs)" | 87 µs, 59 µs, 84 µs (10⁶/84 ≈ 12 000) |
| Green-for-the-wrong-reason story | "reported 43/43 killed" | `killed(assert)=44` of 44 — the number that actually reveals the broken sweep check |
| Per-section tallies | "of that run" | names `build/logs/harness.log` (detailed) vs `build/full-run.log` (summaries only) |

I also wrote one log line into the README from memory before reading the log back; caught it while verifying and replaced it with the real `seconds=314 slowest=…` pair.

**`tools/mutants.py`** — each mutant now prints its own elapsed time and `SUMMARY` reports `slowest=NAME(NNs)`. That is what makes the `--timeout` claim checkable instead of anecdotal: the shipped cycle shows the slowest mutant at 73 s against a 900 s default (≈12× headroom for a hang), and it corrected a belief of mine that two mutants "took ~302 s" — 314 s is the *cycle*, not a mutant.

## Verification (all re-run after the final edit)

- `./build.sh` → exit 0, `RESULT all suites green`; `SUMMARY checks=408 / 95 / 16 / 11`, all `failures=0` (= **530**, matching the README table and the per-section split 53/10/5/37/26/23/33/58/28/21/94/14/6, re-tallied from the PASS lines).
- War-contents gate fires in all three modes: `harness=0 e2eclient=0 probe=0 stubs=4`.
- Battery: `ACCOUNTED mutants=44 assertion-kills=43 build-failures=0 equivalent=1 needs-attention=0`; 44 per-mutant logs reconcile with `--list` (no orphans, none missing); exactly one log has zero `FAILED` lines — `ADDR-allowlist`, the declared equivalent, whose own run reports `SUMMARY checks=408 failures=0` (the differential proof).
- `--dry` → `44 mutant(s), 0 anchor problem(s)`; tree is 16 classes / 2725 lines as the README header says.

Memory: corrected the mutant-vs-cycle timeout misattribution in `mutation-runner-preflight-and-semaphore.md` and added to `prose-numbers-must-be-derived-from-logs.md` that a quoted log figure goes stale twice (the file is regenerated; timings differ run to run), so logs must be regenerated *after* the last source edit, each figure must name its file, and a pending "README says X but code says Y" item must be grepped for before editing — several of mine described text that no longer existed.
