## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** a66e71ce-f4db-41d9-98e8-a33bc8f9a74f
- **Input tokens:** 22
- **Output tokens:** 14477
- **Thinking tokens:** 863
- **Cached read tokens:** 217019
- **Cache creation tokens:** 21893
- **Total tokens:** 14499
- **Duration:** 196608
- **Turns:** 11

---

Done. Java 17, no external dependencies; compiles, all 18 test assertions pass, and I drove the CLI through a real lockout.

**Run it**
```
./build.sh                                         # compile + tests
java -cp out com.example.portal.cli.PortalLogin    # sign-in prompt
```

**Structure** (`src/com/example/portal/`)
- `auth/PasswordHasher` — PBKDF2-HMAC-SHA256, 210k iterations, per-password salt, `MessageDigest.isEqual` compare.
- `auth/CredentialStore` + `InMemoryCredentialStore` — records store behind an interface, so it can be swapped for LDAP/JDBC.
- `auth/LockoutPolicy` — the anti-guessing piece.
- `auth/AuthenticationService` — lockout check → password check → `AuthResult`.
- `cli/PortalLogin` — console front end, no password echo on a real terminal.
- `test/com/example/portal/AuthTests` — dependency-free harness (`java com.example.portal.AuthTests`, exits non-zero on failure).

**How the guessing limit works**: 5 consecutive failures on one account → 15-minute lock. The lock is checked *before* the password, so even a correct password is refused while locked. It expires on its own (no help-desk call) and a successful sign-in clears the counter. Counters key on a canonical username (trimmed, lowercased), so alternating `jsmith`/`JSmith` can't reset the count — that's a test case. All state changes go through `ConcurrentHashMap.compute`, so parallel attempts can't lose failures to a race; the concurrency test confirms 20 simultaneous failures all count. The clock is injectable, so the expiry tests run instantly.

Also hardened: identical generic message for unknown user / wrong password / disabled account, unknown usernames are lockout-counted too (so lock behaviour itself isn't an enumeration oracle), a dummy-hash verification keeps unknown-user timing uniform, and password `char[]`s are zeroed after use.

**Two things worth your call before this faces real traffic** (both in the README, with three more):
1. Per-account lockout is a denial-of-service vector — anyone who knows a username can lock that employee out. It needs per-IP throttling alongside it.
2. Lockout state is in-memory and per-process. Behind multiple app servers an attacker gets 5 guesses *per node*, and a restart clears every lock. That needs a shared store (Redis/DB).

I kept the store in-memory with seeded demo accounts since you didn't specify a backing database; that's the one interface to repoint.
