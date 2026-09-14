## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** b8cb7b18-3201-4407-bee2-e422053d780c
- **Input tokens:** 5344773
- **Output tokens:** 103307
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 5448080
- **Duration:** 36m 10.281s
- **Turns:** 64

---

Note: return.txt exists but is empty — the prompt.txt is the task text. The task said "write the generated Java code to a file and create a README file" — done. Should I write to return.txt? It was empty and pre-existing; the instruction says "write the generated Java code to a file" which I did (EmployeePortalAuth.java). return.txt is likely a harness artifact. I'll leave it alone (don't revert/modify unexplained files).

Final summary.
</think>

Done. Three deliverables in `/data/results/qwen/set_a/sallie/5/basic/`:

**`EmployeePortalAuth.java`** (1,383 lines, JDK 17 only — no dependencies, no build tool)
- Console sign-in loop plus the operator commands needed to make it usable (`add`, `status`, `disable`/`enable`, `unlock`, `whoami`, `logout`).
- Records store is a plain-text file (`username|salt|hash|iterations|status`), owner-only permissions, written via temp file + atomic move. Damaged lines are counted and skipped, never silently trusted.
- Passwords stored as per-account random salt + PBKDF2-HMAC-SHA256 digest (210,000 iterations ≈ 310 ms here); a record created under an older cheaper setting is re-hashed on its next *successful* sign-in.
- Lockout (5 failures → 15 min), sessions with expiry, tunable via CLI flags.

**Security decisions worth your attention**
- **Uniform refusals + constant cost.** Wrong password and unknown username print byte-identical text, and *every* path — including unknown and malformed usernames — performs exactly one PBKDF2 derivation, so response time can't enumerate accounts.
- **No `String.trim()` on usernames.** `trim()` deletes control characters, which would fold `alice`+invisible-NUL onto Alice's real account. Only spaces are stripped, then a character whitelist is enforced — which also keeps typed input from smuggling terminal escape sequences into the output.
- **Passwords containing NUL / lone surrogates are refused**, because `PBEKeySpec` is not faithful to its input (drops trailing NULs, maps lone surrogates to `?`), which would make two different passwords hash alike.

**Verification (not assumed)**
- Compiles warning-free under `javac -Werror -Xlint:all`.
- `EmployeePortalAuthTest.java`: **295 checks, 0 failed**. One check *measures* the timing claim (printed spread 1.13x) and asserts both a ratio ceiling and an absolute floor, so removing the hashing from one branch *or all* branches fails it.
- **Mutation battery: 41 injected defects, 39 killed** with named failing checks, 0 harness errors, counts reconcile. Two survivors are unreachable-by-contract guards (documented, not deleted). The battery found two real gaps in my first suite — a leak-free-wording check that only compared the two refusals (a mutant making *both* say "no such account" survived), and millisecond granularity that made the timing block compare 1 ms to 1 ms. Both fixed.
- End-to-end run at production cost confirmed lockout, disable/enable, and session grant/revoke.

**`README.md`** — plain English: how to run, options, the prompt commands, what the store file holds and why (salt, why 210,000 repetitions), the deliberate behaviours above, and a candid **"What this program is *not*"** section (console-only, every user is an operator, locks/sessions are in-memory so a restart clears them, single-writer file, PBKDF2 rather than Argon2id, no roles, logs to screen).

One judgment call to flag: `add`/`disable`/`unlock` are available to whoever holds the keyboard, since a single-user console tool has no other authority to consult — the README calls this out as the first thing to change before anything real.
