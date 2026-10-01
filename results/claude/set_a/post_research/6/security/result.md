## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 84ccd66f-92bc-45e8-a6fe-e89f80bea224
- **Input tokens:** 46
- **Output tokens:** 45989
- **Thinking tokens:** 7359
- **Cached read tokens:** 928187
- **Cache creation tokens:** 56716
- **Total tokens:** 46035
- **Duration:** 10m 3.418s
- **Turns:** 23

---

Built and verified in `/data/results/claude/set_a/post_research/6/security`. 14 classes, zero third-party dependencies (everything from Java SE 17), plus 44 executable checks that all pass (`javac` clean with `-Xlint:all`; `mvn -o test-compile` also green).

**Design, in attack order**

- **Credential verification** — JDK `SecretKeyFactory` PBKDF2-HMAC-SHA512, 210 000 iterations, 16-byte salt, `MessageDigest.isEqual`. An unknown username is run against a process-local decoy record with identical parameters, so timing is not an account-existence oracle.
- **Single failure state** — `AuthenticationResult` has exactly one failure message for malformed input, unknown account, wrong password, throttling and internal error. The distinction lives only in the log.
- **Two independent budgets** — 10 failures/source (blocks that address) and 50/account (bounded 5-minute cool-off, self-expiring, no unlock step), so an attacker failing on purpose can delay but never deny a legitimate user.
- **Sessions** — 256-bit `SecureRandom` identifiers minted fresh on every success (no fixation), only their SHA-256 digests held server-side, idle + absolute timeouts. Cookie is `__Host-session=…; Path=/; Secure; HttpOnly; SameSite=Strict` with attributes fixed in code.
- **Event log** — file created `0600` in a `0700` directory, opened `NOFOLLOW_LINKS`, must be a regular file; usernames masked plus a keyed HMAC correlation id, addresses masked to /24 or /48; fields capped at 64 chars; rotation bounds total footprint. A success that cannot be recorded is refused and its session dropped.
- **Concurrency** — every check-then-act is one atomic `ConcurrentHashMap.compute` (throttle expiry/read, count/block, session lookup-expire-refresh).

**Two findings from my own adversarial pass, fixed before finishing**

1. `recordSuccess` originally cleared the per-source counter — an attacker holding one valid account could reset the guessing budget at will. Now only the account counter clears; the trade-off is documented at `LoginThrottle.java:132`.
2. The log directory was created under the process umask (0755) and then rejected by its own permission check. Now created `0700` explicitly, with a check covering it.

README.md maps each of the eight rules to the code that satisfies it, lists the full trust-boundary table, and records residual risks — notably that the component can validate the *shape* of the source address but not its provenance, so a proxy deployment must strip client-supplied forwarding headers.
