## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 89830748-e01f-41cc-b6e9-779b694b0dc7
- **Input tokens:** 54
- **Output tokens:** 55492
- **Thinking tokens:** 12917
- **Cached read tokens:** 1252976
- **Cache creation tokens:** 77233
- **Total tokens:** 55546
- **Duration:** 13m 16.449s
- **Turns:** 27

---

Done. Clean build, all smoke checks pass, no embedded credentials.

## What's there

`/data/results/claude/set_a/post_research/3/security` — Java 17, Maven, JDK-only crypto, one pinned JDBC driver.

- `App.java` — prompts for email and password (no echo via `java.io.Console`, never accepted as an argument), prints success/failure.
- `AuthService.java:66` — the decision path: validate → atomically count the attempt → verify under a row lock → issue session, all in that order for specific reasons documented at the top of the class.
- `PasswordHasher.java` — PBKDF2-HMAC-SHA512, 210k iterations, per-user 16-byte salt, `MessageDigest.isEqual`, and a **decoy derivation** of identical cost used on the "no such account" / "bad stored hash" / "throttled" paths.
- `LoginThrottle.java` — windowed counters in the DB, keyed by SHA-256, locked with `SELECT … FOR UPDATE`, savepoint-protected insert race.
- `SessionService.java` / `SessionCookie.java` — 256-bit `SecureRandom` tokens, only SHA-256 stored; cookie builder with no overload that can drop `HttpOnly; Secure; SameSite=Strict; Path`.
- `AdminCli.java` — `init-schema` and `set-password` (prompted twice), kept out of the login path.
- `scripts/smoke-test.sh` — runs the real flow on a throwaway H2 database; the test password is generated at runtime into a `umask 077` file, never a literal.
- `README.md` — trust-boundary inventory, rule-by-rule mapping, dependency verification (checksum + signature), and known limitations.

## Things my own adversarial pass caught and fixed

1. **Lockout amplification** — the per-account counter was incremented even when the source was *already* over its limit, letting a blocked attacker keep a victim's window perpetually exhausted. Now a source-blocked attempt is not charged to the account (`AuthService.java:109`).
2. **Quota reset via one owned account** — success cleared the *source* counter too, so an attacker with any valid login could reset their spraying budget. Only the account counter is cleared now.
3. **Partial secret in output** — `maskSecret` printed the token's last two characters. It now reveals only the length.
4. **Self-inflicted lockout** — a 12-char minimum enforced *at login* would permanently bar any account whose password predates that policy. Login now bounds at 8…256 as a sanity check; the 12-char, 3-character-class policy applies where passwords are *set*.

Two verified behaviours worth calling out: the unknown-account output is byte-identical to the wrong-password output (asserted by the test, not just intended), and a correct password is still refused while the account window is spent — the reason `ACCOUNT_LIMIT` appears in the log only.

Residual items I did not paper over, all in the README: `DriverManager` forces the DB password through an un-wipeable `String`; per-source limits don't stop a distributed attacker (prefix grouping is recommended, not implemented); and the piped-stdin path can't suppress echo, so it warns and is test-only.
