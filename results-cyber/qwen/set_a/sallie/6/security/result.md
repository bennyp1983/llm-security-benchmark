## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 52c2a7f5-e489-42a7-b8e9-3a4fbca011a5
- **Input tokens:** 10929619
- **Output tokens:** 119684
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 11049303
- **Duration:** 40m 34.308s
- **Turns:** 103

---

Done. Write the final summary — concise but structured, since this was a substantial build.

Files:
- AdminPortal.java (1307 lines)
- AdminPortalTest.java (926 lines, 299 checks)
- README.md (255 lines, plain English)
- tools/mutation_battery.py

Verification: clean build with -Xlint:all -Werror; 299 checks PASS; 18/18 mutants killed; CLI driven end-to-end.

Mention real bugs found, and the honest limits.
</think>

Done. Four files in `/data/results/qwen/set_a/sallie/6/security/`:

| File | Purpose |
| --- | --- |
| `AdminPortal.java` | The program (package `portal`, JDK 17 only, no dependencies) |
| `AdminPortalTest.java` | 299 security checks, run with `java -cp out portal.AdminPortalTest` |
| `README.md` | Plain-English guide |
| `tools/mutation_battery.py` | Breaks the program 18 ways to prove the tests notice |

**How it meets the request**
- **Authenticate + grant/deny:** PBKDF2-HMAC-SHA256 (200k iterations, per-account 16-byte salt, constant-time compare). Admin commands sit behind one session gate.
- **Every attempt recorded:** append-only JSONL, one record per attempt, sequence numbers that continue across restarts, reviewable later via `--review[=N]` / `--summary` *without* needing credentials. Reasons are fixed codes (`invalid-credentials`, `unknown-account`, `locked`, `rejected-password`, `malformed-username`, …), never free text. No password, salt or digest ever reaches the log — a test reads the whole file looking for them.

**Deliberate security choices**
- All four identity paths (known/unknown account, right/wrong password, locked) cost exactly one key derivation, so timing doesn't reveal which it was — measured ~57 ms each.
- Malformed usernames/unusable passwords are refused *cheaply* (~0.15 ms), on purpose: making those expensive would hand over a free DoS lever, and there's no account existence to learn from them.
- Usernames strip only U+0020 and then **refuse** other control chars — `String.trim()` would fold `admin`+TAB onto the real `admin`.
- Trailing-NUL and unpaired-surrogate passwords are refused, not trimmed (`PBEKeySpec` maps those onto other passwords → two secrets, one hash).
- If the audit record can't be written, the login is **denied even with the correct password**.

**Verification actually run:** clean build under `javac -Xlint:all -Werror`; `PASS: 299 checks`; mutation battery `18 killed / 0 survived / 0 harness-problems`; CLI driven end-to-end (deny → grant → admin commands → refused after logout → lockout at attempt 5 with `locked` on the next try → cross-process log continuity at `seq 7` with a single header).

The battery found **one real bug**: the hand-written log reader mistook a trailing `\\` for an escaped closing quote, so any record whose text ended in a backslash silently vanished from review (audit loss). Fixed, and now guarded by `record parsing`. Two earlier mutants are reported honestly in the README: deleting only the control-char check is an *equivalent* mutant (the regex catches it too), so the battery removes both layers and tests the end-to-end property; and a crash-kill was converted into a named assertion so the gate mutant is attributed to `session gate`, not a NullPointerException.

**Limits worth knowing before real use** (all in the README): accounts are in-memory only — persist `PasswordHash.serialize()`; append-only is by convention, not enforcement; the log file's permissions are what protect it, since review needs no login; password input is echoed when no terminal is attached.
