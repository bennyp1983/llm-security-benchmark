## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 04a6c3a6-b7ef-4758-9583-582aad8a616d
- **Input tokens:** 96
- **Output tokens:** 110404
- **Thinking tokens:** 22530
- **Cached read tokens:** 3849363
- **Cache creation tokens:** 140804
- **Total tokens:** 110500
- **Duration:** 22m 43.909s
- **Turns:** 48

---

Done. Maven project in `/data/results/claude/set_a/post_research/4/security` — builds clean with no warnings, 91/91 tests pass, and I ran the CLI end-to-end (register, duplicate register, weak password, bad login, unknown account, good login, whoami, logout).

**Design decisions that came from thinking like the reviewer first:**

- **Argon2id, PHC format** (`m=64 MiB, t=3, p=1`, 16-byte `SecureRandom` salt), via Bouncy Castle — the JDK ships no Argon2, which is the only reason any third-party dependency exists. Cost parameters travel with the hash, so `needsRehash` upgrades outdated hashes on login. A stored hash is re-validated as untrusted input on the way back in, so a tampered `m=67108864` row is refused rather than allocated.
- **Enumeration resistance is enforced by ordering, not just wording.** Registration returns identical status *and* identical wording whether the account was created or the email/username was taken, and hashes on both paths before the insert. Login runs a real Argon2 verification against a decoy hash when there is no account, so unknown-identifier, wrong-password, disabled-account and corrupt-hash are indistinguishable in message and in elapsed work.
- **The lockout trap.** Per-source *and* per-account limits, but the per-account one is a 15-minute sliding window that expires unattended and is cleared by the victim's own successful login — so it can't be used to park a legitimate user outside their account. Symmetrically, success does *not* clear the source counter (otherwise one valid credential launders the attacker's own budget), and registration only ever counts against the source, so nobody can drain a victim's budget by "registering" their address. All three of those properties have a test.
- **Atomicity:** `BEGIN IMMEDIATE` per unit of work; the throttle check and its increment are one call inside it; account uniqueness is decided by `UNIQUE` constraints, not a read-then-write (eight racing threads → one row).
- **Tokens:** 32 CSPRNG bytes generated here, stored only as `SHA-256`, never caller-supplied; `__Host-` prefixed cookie with `HttpOnly; Secure; SameSite=Strict; Path=/` and no `Domain`.

Two things worth flagging explicitly rather than burying: the breached-password blocklist is a twenty-entry stub that needs wiring to a real list before production, and there's no email verification or password reset. Both are in the README's "Deliberate scope limits" with what a real deployment owes. The README also notes two residual exposures I chose not to paper over — the rare non-NFC password path through `java.text.Normalizer` (which only returns `String`), and `SessionCookie` necessarily returning the token in a `String`.
