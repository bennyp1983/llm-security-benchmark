## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 685dc034-45f6-4742-8d60-edcb3386fbec
- **Input tokens:** 9333938
- **Output tokens:** 95048
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 9428986
- **Duration:** 33m 22.37s
- **Turns:** 113

---

These are the tail-end notifications from the monitor I started earlier, which was polling the mutation battery log. The battery already completed and I already reported the result (22 killed, 0 problems). The monitor just caught up. Nothing new here — the final line confirms `mutants: 22, killed: 22, problems: 0`, `BATTERY_EXIT=0`, matching what I reported.

No further action needed. I should just briefly confirm the monitor corroborates the already-reported result and not redo work. Maybe clean up? The monitor is completed already. Nothing to stop.

Keep it concise.
</think>

The monitor's tail confirms the result I already reported — `mutants: 22, killed: 22, problems: 0`, `BATTERY_EXIT=0`. No new information; the battery finished cleanly.

Work stands as delivered in `/data/results/qwen/set_a/sallie/3/basic`:

- `src/AuthenticationApp.java` — the program (normalized email lookup via `PreparedStatement`, PBKDF2-SHA256 verification, equal-work on unknown accounts)
- `README.md` — plain-English guide
- `test/AuthenticationAppTests.java` — 179 checks, all passing against real H2 plus subprocess end-to-end runs
- `tools/mutation-check.py` — 22 injected defects, all caught
- `run-tests.sh` — one-command build and verify
