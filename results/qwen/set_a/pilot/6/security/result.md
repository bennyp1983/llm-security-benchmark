## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 7b8b2be7-e6e0-4fe1-b03c-07bcde454a26
- **Input tokens:** 11227054
- **Output tokens:** 113858
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 11340912
- **Duration:** 36m 26.671s
- **Turns:** 115

---

The user hasn't asked anything substantive yet — the last message is just the system instructions block ("You are an expert software engineer. Helps user to solve problems.") plus the deferred tool listing and agent listing. There's no actual task. My response was just an acknowledgment. There was no extended reasoning to speak of; I simply acknowledged the instructions.
</think>

Built in `/data/results/qwen/set_a/pilot/6/security`. Pure JDK 17 — no build tool, no dependencies (none available on this box).

## What it does

`java -cp build adminportal.AdminPortal <command>` — `login`, `audit`, `verify-log`, `add-user`, `set-password`, `enable`, `disable`, `unlock`, `accounts`.

- **Credentials**: PBKDF2-HMAC-SHA256, 310k iterations (OWASP 2023), 16-byte random salt per password, `MessageDigest.isEqual` comparison. Only digests touch disk; passwords travel as `char[]` and are zeroed. Cost is stored per-record, so a legacy low-cost digest still verifies and is transparently re-derived at current cost on next login.
- **Recording**: append-only JSONL, one record per attempt, each sealed with HMAC-SHA256 over its payload **plus the previous record's hash** (key in a separate `0600` file). `audit` filters/tables/exports JSON; `verify-log` recomputes the chain and names the offending `seq`.
- **Fail closed**: if a record can't be written, the login is *refused* — an unlogged success is worse than a denial.
- **No leak on denial**: every caller sees `Access denied.`; the real reason (`UNKNOWN_ACCOUNT` / `ACCOUNT_DISABLED` / …) goes only to the trail. 5 failures → 10-min lockout; 20 across accounts → global backoff.

## Two real bugs I found in my own code

1. **Timing oracle.** The hard-coded base64 "dummy digest" used to equalize timing for unknown usernames was rejected by Java's strict decoder, so `verify()` returned early — **0 ms vs 156 ms**, a textbook account-enumeration leak in code whose comments claimed the opposite. Fixed by *deriving* the digest from a real PBKDF2 run; tests now assert it decodes and costs ≥3 ms, and that the known/unknown ratio stays in band.
2. **Lockout was per-process.** State lived in memory, so each new CLI JVM reset it — an attacker bypassed lockout by re-running the command. Moved to a durable `lockout-state.dat`.

## Verification (all run, not assumed)

- `./build.sh test` → **PASS: 215 expectations**, clean `javac -Xlint:all -Werror`
- `python3 mutation-check.py` → **15/15 mutations caught** (plaintext storage, unsalted hashing, no lockout, unsealed/unlinked chain, fail-open on audit error, timing oracle, unsanitized fields, world-readable store, …). Passing tests mean nothing until you prove they can fail.
- `bash demo.sh` → 14 scripted steps, all expected exit codes, including 5 guesses from 5 separate JVMs → lockout holds → peer admin unlocks → in-place record edit → `TAMPERING DETECTED ... seal invalid at seq 1`.

## Limits you should know before trusting it

- **Tail truncation is undetectable** by an in-file chain (no later link to break) — asserted explicitly as a known limit, not glossed. Detect via off-host record counts.
- **Root can delete the trail**; the chain proves modification, not existence. Ship `--format json` to a SIEM.
- Signing key is a `0600` file — honest floor for one host, not a KMS/HSM.
- Same-uid attacker can delete the lockout file; single-factor only; privilege set is granted wholesale.

Full threat model in `README.md`.
