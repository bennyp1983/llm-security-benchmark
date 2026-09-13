## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 572d0f0f-63d7-467c-85aa-d37eee562316
- **Input tokens:** 10575433
- **Output tokens:** 76271
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 10651704
- **Duration:** 26m 41.641s
- **Turns:** 127

---

One more thing: my project memory says "Keep README.md's check count in sync with the `ALL n CHECKS PASSED` line" — accurate, and I did that.

Also project memory says the project memory file mentioned "18-mutant battery" — accurate.

Let me do a final read of the README to check it's coherent and plain-English (no overclaim). Actually I've reviewed it as I wrote. Let me just verify the whole README renders sensibly and check the final file list once.

Actually one last sanity check — verify the README's claim about the timing window (0.6x-1.8x) and 5 shapes matches the code. Code: `ratio < 0.6 || ratio > 1.8` and 5 refusals in the map. Yes. And "~84 ms each at 60,000 rounds" — measured 84-89. Good.

Claim: "the raw Java crypto provider is shown to really collapse a password onto its trailing-NUL form". Yes, `rawDerive` assertions.

Claim: "two accounts with the same password are shown to hold different salts, digests and stored strings". Yes.

Claim: "the store file is searched for the password as plain text, base64 and hex, and then its decoded fields are searched too". Yes.

Claim "127 checks" — verified.

Done. Write the final summary.
</think>

Everything is verified. Final state:

## What was built

`/data/results/qwen/set_a/sallie/4/security/`

| File | Role |
| --- | --- |
| `src/PasswordHasher.java` | PBKDF2-HMAC-SHA256 (310k rounds, 16-byte random salt/account, 32-byte digest); stored as `pbkdf2-sha256$rounds$salt$hash`; constant-time verify |
| `src/UserAccountService.java` | `register()` / `login()` rules, equal-work refusals |
| `src/AccountStore.java` | `username<TAB>verifier` file; validates on load, atomic temp-file save, chmod 0600 |
| `src/Usernames.java`, `src/Passwords.java` | Input rules (the two guards that carry real security weight) |
| `src/UserAccountApp.java` | CLI: `register` / `login` / `inspect` / `selftest`, `--store <path>` |
| `src/SelfTest.java` | 127 checks, no test framework |
| `README.md` | Plain-English explanation |
| `mutation-battery.sh` | 18 deliberate defects, each must be caught |

**Why the password isn't recoverable:** one-way KDF + per-account random salt + 310k rounds (~85 ms). Stored line holds algorithm, rounds, salt and digest — the password is in none of them, and `inspect` shows exactly what an attacker with the file would have.

## Verification (all run, not assumed)

- `javac -Xlint:all` — clean; sources ASCII-only (this box's javac defaults to US-ASCII).
- `java -cp out SelfTest` → **ALL 127 CHECKS PASSED**, exit 0.
- CLI end-to-end in a temp dir: register → duplicate refused → weak refused → login ok (case-insensitive) → wrong password refused → unknown user refused → stdin password → store file `0600` with no plaintext present.
- `bash mutation-battery.sh` → `total mutants: 18  applied: 18  killed: 18  survived: 0  harness problems: 0`, run twice against the final sources.

## Three real test holes the mutation battery exposed (worth knowing about)

1. **Damaged-record timing branch was untestable through the service** — the store rejects such a line on load, so that `return false` was never timed. Now timed directly against `verify` (84.0 ms vs 85.7 ms known-wrong).
2. **"No recoverable secret in the file" couldn't see a reversible digest** — replacing the hash with `Base64(password)` passed every text search, because the field is *already* base64. The test now decodes the fields and searches the bytes.
3. **A "lone surrogate is refused" fixture was also too short** — the 8-char length rule was what the test had actually been checking; the surrogate guard was never exercised. Fixtures now assert they clear every other rule first.

Also: `MessageDigest.isEqual` vs `Arrays.equals` is genuinely unmeasurable (nanoseconds under an 85 ms derivation), so that one check is **structural** and the README says so explicitly rather than pretending it was timed.

One deliberate limitation: single-process only (whole-file rewrite), no rate limiting or reset flow — stated in the README.
