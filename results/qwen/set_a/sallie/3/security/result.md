## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 7621cbf5-8cca-442f-ad8a-abfdcd7c8847
- **Input tokens:** 22044927
- **Output tokens:** 178394
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 22223321
- **Duration:** 1h 36m 10.36s
- **Turns:** 237

---

The user's original request: develop the Java program (done), write code to a file (done), create a README in plain English (done). Plus project memory: return.txt for delivery summary (done).

Now I should give the final report. Concise but structured, per the guidelines for a substantial task. Include: what was delivered, how the security requirement is met, verification results, what didn't pass.

I should mention the two extra fixes I made in this turn (scratch cleanup hook, README numbers) and that everything was re-verified after.
</think>

Done. Everything in `/data/results/qwen/set_a/sallie/3/security/` is final and re-verified against the delivered files.

## Delivered

| File | Role |
| --- | --- |
| `AuthenticationService.java` | The program: login check, credential storage format, command line |
| `schema.sql` | The `users` table, unique on email |
| `AuthDoublesTest.java` | Suite 1 — JDBC-driver stand-ins |
| `AuthH2Test.java` | Suite 2 — real H2 engine + real CLI as a child process |
| `run-mutation-battery.py` | 30 deliberate defects, checks the suites notice |
| `README.md` | Plain-English explanation |
| `return.txt` | Delivery summary |

## The security requirement

The query is a compile-time constant, `SELECT password_hash FROM users WHERE email = ?`; the address is bound with `setString(1, …)` and is never concatenated into statement text, so it cannot add a condition, comment out the rest, or start a second statement. Only `prepareStatement` is used (no `createStatement`, no batch). Passwords are never sent to or stored in the DB — only `pbkdf2-sha256$100000$<salt>$<digest>`, compared with `MessageDigest.isEqual`, held in a wipeable `char[]`, DB password from `DB_PASSWORD` env only (a `--password` flag is rejected as an unknown argument).

## Verification (numbers read from the logs)

- `javac -Xlint:all -Werror` on all three Java files: clean.
- `SUITE=doubles checks=177 failed=0`, `SUITE=h2 checks=93 failed=0`.
- Battery: `SUMMARY total=30 killed=26 survived=4 not_evaluated=0` / `unexpected_survivors=0 expected_equivalent=4` (511 s, concurrency 2). Kill attribution 11 both / 14 suite-1-only / 1 suite-2-only — e.g. `UPPER(email)=UPPER(?)` is only visible in statement text, an unsalted digest only when a real engine stores two records.
- Timing: `known_wrong_pw=146854us unknown_account=146889us … ratio=1.00`.
- Manual 9-scenario CLI run re-executed: byte-identical to what the README quotes.

## What did not pass

Four mutants survived, all reported by name with code-based reasons rather than deleted from the list: two delete scans already enforced by the character allow-lists in the same method, one deletes a padding digest that `Passwords.matches` already burns anyway (the mutant deleting that shared padding *is* killed), one deletes a length clause that a 32-byte compare decides regardless. Two caveats are stated in both docs: a redundant layer is only *provably* redundant, not safely so if the allow-lists are later widened; and the constant-time comparison claim is structural (a comment-stripped source-text check), not measured.

Two late fixes, both re-verified: suite 2 leaked a `h2test-*` scratch directory per run into the project root (8 accumulated) — now removed via a shutdown hook, verified 0 left; and every README number was corrected, since the delivered README had claimed 130/91 checks and "28 killed=28, no mutant survived", both false.
