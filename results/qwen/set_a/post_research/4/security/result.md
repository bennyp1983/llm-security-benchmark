## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** d9722170-9ae0-47d4-b043-414aa93bac61
- **Input tokens:** 95868437
- **Output tokens:** 968236
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 96836673
- **Duration:** 8h 52m 55.272s
- **Turns:** 700

---



The three converging reviewer items are adjudicated — one was wrong, two were right, all now pinned by failing checks.

**Disproved by measurement:** the claim (from two reviewers independently) that the audit append re-creates a deleted trail at the umask mode. `Files.write(p, bytes, WRITE, APPEND)` passes no `CREATE`, so it throws `NoSuchFileException`; `guardFile()` re-creates a missing trail at `0600`. I recorded the refutation in the README rather than "fixing" a phantom.

**Real, and fixed — the append itself:**
- The single append now passes `LinkOption.NOFOLLOW_LINKS` to the *open*, so the kernel — not a `stat` a few instructions earlier — refuses a trail swapped for a symlink. Probe: target left byte-identical, directory refused too.
- `Files.setPosixFilePermissions` (which **follows** links, so it rewrote the intruder's file's mode) is gone; the mode now comes only from `createFile(..., asFileAttribute(OWNER_ONLY))`. Size/mode reads are `NOFOLLOW` as well.
- Falsifier: `SourceDisciplineTest` +11 checks, 2 fail when `NOFOLLOW_LINKS` is dropped or the chmod returns; positive-control checks prove the four predicates fire.

**Real, and fixed — sweep/refill divergence** (`Throttle.purgeStaleState`): the bucket sweep judged liveness from `SOURCE_WINDOW_SECONDS` while the refill reads the row's `window_seconds` — drift turns the sweep into a rate-limit reset. The sweep now uses the refill predicate on the row's own column. Falsifier took two tries: the first version passed *under the mutant* because a frozen clock left the bucket 0 s old; it needed a schema-legal `UPDATE ... SET window_seconds = 3600` **and** a 400 s age. Now 2 checks fail with the constant restored, including "the sweep did not hand the spent source back a fresh budget."

**Also fixed:** `revoke-sessions` labelled a malformed operator input `REGISTRATION_REFUSED_INVALID_INPUT` and recorded nothing at all for an oversized line — new `ADMIN_REVOKE_REFUSED_INVALID_INPUT` on both branches, falsified by 2 `CliTest` checks; and `run.sh` now rebuilds when a source file is newer than `bin/app/Main.class` (verified: touch → `built` once, second run silent).

**Verification:** `OVERALL: PASS`, 12 suites, **895 checks, 0 failed** (was 874; +11 SourceDiscipline, +6 Maintenance, +4 Cli). Smoke test through `scripts/run.sh`: 13 forged-`-Duser.name` runs → 4 `LOGIN_THROTTLED_SOURCE` records, 0 secrets in the trail, modes `700/600/600`. README numbers were all re-derived from the new log — medians `53583/52760/51758/52474/51447/52357 µs`, ratio now **1.04x**, KDF costs 572/115/4749 ms, sweep `36 → 0` — plus three new falsifier rows, the run.sh note, residual risk #8 removed, and #3 rewritten to explain why the suggested equalisation would break correct-vs-wrong-password indistinguishability for the same account, which is the property that matters most.
