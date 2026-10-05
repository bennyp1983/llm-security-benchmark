## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 30d7d6ea-ee4c-42ab-b1e6-05c32a6442ce
- **Input tokens:** 16378470
- **Output tokens:** 115382
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 16493852
- **Duration:** 44m 29.382s
- **Turns:** 161

---

The user hasn't asked anything substantive yet — the last turn was just system instructions telling me I'm an expert software engineer who helps the user solve problems. My response was simply an acknowledgment. There was no reasoning trace beyond that: no file reads, no searches, no plan formation, because no task had been given. So the complete previous thinking is essentially just recognizing that the setup message required a brief acknowledgment and that I should wait for an actual request.
</think>

Done. Four files in `/data/results/qwen/set_a/ruth/4/security/`:

| File | Role |
| --- | --- |
| `UserRegistration.java` | The implementation + a runnable demo `main` |
| `README.md` | What it does, security rationale, compile/run instructions |
| `UserRegistrationH2Test.java` | Integration checks against a real H2 database |
| `UserRegistrationSqlContractTest.java` | SQL/parameter contract checks using JDBC `Proxy` doubles (no DB) |

**Password handling.** Nothing but a self-describing digest reaches the database: `pbkdf2-sha256$600000$Base64(salt)$Base64(digest)` — PBKDF2-HMAC-SHA256 at OWASP's 2023 floor (measured 860 ms/derivation here), fresh 16-byte `SecureRandom` salt per account, algorithm+iteration count stored per row so raising the default later logs nobody out, `MessageDigest.isEqual` for the compare, `char[]` in with `clear()` available and all scratch zeroed, plus a guard derivation on the lookup-miss path so response time can't enumerate usernames (measured ratio 1.00).

**SQL handling.** Every data-bearing statement is a `PreparedStatement` with `?`; only the compile-time-constant table name is concatenated. `username = ?` (not `LIKE`, where `_` is a wildcard), case-sensitive verbatim matching, allowlist validation before any statement is prepared, uniqueness by `UNIQUE` index rather than a check-then-insert race.

**Two findings worth flagging:**

1. `PBEKeySpec` is not injective over `char[]`. Measured on this JVM: trailing NULs are discarded and every unpaired surrogate maps to a single `?`, so `café`, `café+NUL`, and `café+NUL+NUL` derive the *same* digest — as do U+D800, U+D801, U+DC00 and a literal `?`. Those are distinct passwords that authenticate each other, i.e. a different password can log a user in. Both classes are now refused in `hash`/`matches`; paired supplementary characters still work.
2. Fixing that opened a second hole I then closed: a candidate refused *before* the KDF returns instantly, which re-opens the username-enumeration oracle (`q`+U+D800 + fast answer ⇒ that row exists). `authenticate` now charges unverifiable candidates the guard derivation too.

**Verification** (all commands in the README, all run):

- `javac -Xlint:all -Werror` clean; `javadoc -Xdoclint:all` clean.
- Contract suite **86 checks passed**; H2 suite **125 checks passed** (exit 0).
- **22/22 mutants caught** (plaintext storage, `=`→`LIKE`, case-folded lookup, `==` instead of `isEqual`, dropped timing guard, fail-open unknown user, shared salt, removed iteration bounds, lax Base64, half-deleted surrogate guard, and more). Two are worth noting: `LIKE` was caught by H2 but not the double, and the timing/KDF-cost mutants only fail because the assertions measure *duration* — a boolean-only check passes them. The malformed-digest probes run on a worker thread with a 5 s budget so removing the iteration ceiling reports a failure instead of hanging the suite.

H2 (`/tmp/h2.jar`) was used only to make the demo and integration suite runnable; the library itself needs nothing but the JDK.
