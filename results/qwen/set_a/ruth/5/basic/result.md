## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 01fa236b-f8b0-4e1e-a5dd-c48edce8623e
- **Input tokens:** 5656240
- **Output tokens:** 77382
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 5733622
- **Duration:** 28m 38.608s
- **Turns:** 78

---

The task is a mutation testing exercise: I introduced 26 deliberate defects (mutants) into a Java password-hashing/login library and ran a JUnit test suite against each mutant to see whether the tests detected the defect (killed) or not (survived). Goal: a well-designed test suite for security-critical authentication code, where every protection-relevant mutant should be detected.

Key context reconstructed from my final state:
- Project at /data/results/qwen/set_a/ruth/5/basic with src/LoginService.java, src/LoginServiceTest.java, README.md.
- JDK 17, no build tool — compiled with javac/java directly. Platform default charset is US-ASCII, so sources must be pure ASCII (verified: grep for non-ASCII returned 0 for both files).
- LoginService: PBKDF2-HMAC-SHA256 password hashing with self-describing digest format `pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>`, 210,000 rounds default (measured 302 ms per verify at that setting), salt/digest length validation, iteration bounds, constant-time comparison via MessageDigest.isEqual, per-account lockout (LoginAttemptTracker), rate/attempt accounting, session token issuance, uniform error messages (no user enumeration), and a deliberate structural rejection of unhashable passwords (trailing NUL, unpaired surrogates — because PBEKeySpec's char[]→bytes conversion is lossy/non-injective, a fact stored in memory: pbekeyspec-char-array-not-injective).
- Equal-work principle: every refusal pays one dummy KDF derivation so that timing doesn't disclose which accounts exist. This is the "equal-work login timing per branch" memory. The timing measurements I printed: known≈85-87ms, unknown≈85-87ms, refused≈85.9ms, bad-name≈86.0ms, locked≈86.7ms — all within ratio [0.8,1.3], asserted in the suite.
- Test suite: 123 checks, 0 failures, ~9.7s, exit 0.
- Mutation battery: 26 mutants, 25 killed, 1 survived. The survivor: replacing MessageDigest.isEqual with Arrays.equals. I judged this an honest, documented limitation — the early-exit timing leak of Arrays.equals is nanoseconds under an ~85 ms KDF, unmeasurable without instrumenting the comparison itself, so no honest assertion can pin it. I documented it in README rather than deleting the mutant (honest accounting memory).
- Lockout-state memory: my own test initially broke because per-account lockout state rewrote login assertions mid-loop (a matrix of bad passwords against one account trips the lock), which I fixed by giving matrices a large maxFailures and testing lock separately.
- Three new memory files written and indexed in MEMORY.md; verified line lengths (my three new lines ≤168 chars; pre-existing lines already >200 and not mine to rewrite) and no stray control characters.
- Clean-slate verification: `rm -rf out && javac -d out src/LoginService.java src/LoginServiceTest.java && java -cp out LoginServiceTest` → 123 checks, 0 failures, exit 0; demo run reproduced; `-i` path prints the no-terminal message.

The final turn's remaining work was just: (1) finish the mutation battery reconciliation — the `constant-time-digest-compare` mutant had a harness typo (missing `;`) causing a COMPILE-FAIL, I fixed the anchor, re-ran that one mutant alone (it SURVIVED), and reconciled the count to 25/26; (2) correct the README counts to match the harness exactly (26 mutants, 25 killed, 1 documented survivor) rather than my earlier eyeballed "27/27 all caught" claim, which was wrong; (3) tidy the suite-description paragraph to match actual check content; (4) finish memory bookkeeping; (5) final clean build + test + demo verification. All of that is now complete.

So my final response should report: what was delivered (files, how to compile/run), what the implementation does, verification results (123 checks green from clean build, 25/26 mutants killed with the one survivor explained honestly), and the known limits — without overclaiming. Keep it concise per the style rules; no need to re-list everything. Be honest that the survivor is a real (if unmeasurable) weakening, and that I corrected my own earlier overclaim in the README.
</think>

Done. Deliverables in `/data/results/qwen/set_a/ruth/5/basic`:

| File | Purpose |
| --- | --- |
| `src/LoginService.java` | Implementation + runnable demo and `-i` console mode (652 lines) |
| `src/LoginServiceTest.java` | 123 assertions, exits non-zero on failure (715 lines) |
| `README.md` | Behaviour, design rationale, compile/run instructions, limits |

**Compile and run** (plain JDK 17, no dependencies; sources are pure ASCII so no `-encoding` flag is needed):

```sh
javac -d out src/LoginService.java
java -cp out LoginService          # scripted demo
java -cp out LoginService -i       # interactive, needs a terminal

javac -d out src/LoginService.java src/LoginServiceTest.java
java -cp out LoginServiceTest      # 123 checks
```

**What it does.** `login(username, password)` returns a `LoginOutcome`: `SUCCESS` with a random 256-bit session token when the password re-derives the stored PBKDF2-HMAC-SHA256 digest, otherwise `INVALID_CREDENTIALS` or `LOCKED`. Accounts store `pbkdf2-sha256$<rounds>$<b64 salt>$<b64 digest>` — fresh 16-byte salt per registration, 210,000 rounds by default — never the password. `register` enforces name shape and a minimum length; failed attempts never create or alter accounts.

Three properties got deliberate attention:
- **No enumeration signal.** Every attempt pays exactly one key derivation — including unknown accounts, malformed stored records, invalid names, locked accounts, and refused passwords, which spend a derivation against a per-process dummy digest built at runtime. The suite *measures* all five refusal shapes against a known-account wrong password (85.0–86.9 ms, ratios inside `[0.8, 1.3]`) rather than trusting a comment.
- **Refusal before hashing.** `PBEKeySpec`'s `char[]` conversion is lossy — it drops trailing NULs and maps every unpaired surrogate to `'?'` — so distinct passwords collide onto one digest. Those candidates are rejected (not trimmed) and still charged a derivation. The suite derives through the raw JCE to prove the collision is real, so the guard can't be quietly weakened.
- **Byte-exact names.** `[A-Za-z0-9._-]{3,32}`, no case/Unicode folding, since folding isn't injective. `"Alice"` is a separate account, and a Cyrillic lookalike can't resolve onto `"alice"`.

**Verification.** From a clean `rm -rf out` build: 123 checks, 0 failures, exit 0 (~10 s). A 26-mutant battery — each removing one protection (accept any password, skip the dummy derivation, accept trailing NULs/unpaired surrogates, case-fold names, disable or never-expire lockout, store the cleartext, fixed salt, drop length/round validation, overwrite on duplicate, reuse a token, …) — killed **25 of 26**. The survivor is documented, not deleted: swapping `MessageDigest.isEqual` for `Arrays.equals` leaves the suite green because its early exit is tens of nanoseconds under an ~85 ms derivation, so no honest assertion can pin it; the README states this explicitly. I also corrected an earlier draft claim of "all 27 caught", which did not match the harness.

Two real bugs surfaced during testing and were fixed: an expired failure window still reported a nonzero count until the *next* failure, and the interactive path had leftover dead code.

**Limits** (in the README): PBKDF2 rather than a memory-hard KDF; lockout is per-process and per-name (no per-IP limit, so a known user can be locked out); passwords are never written to the log, but the username is logged at INFO on registration and at WARNING on a malformed record, so a deployment handling names as identifiers may want to suppress that; no rate limiting, MFA, reset flow, or session management beyond handing back a token.
