# Employee Portal Authentication

Java 17, no external dependencies.

    ./build.sh                                  # compile + run tests
    java -cp out com.example.portal.cli.PortalLogin   # interactive sign-in

## Layout

| File | Role |
| --- | --- |
| `auth/PasswordHasher` | PBKDF2-HMAC-SHA256, 210k iterations, per-password salt, constant-time compare |
| `auth/UserRecord` / `CredentialStore` | Record shape and the read interface over the records store |
| `auth/InMemoryCredentialStore` | Demo store; swap for LDAP/JDBC by implementing `CredentialStore` |
| `auth/LockoutPolicy` | Per-account consecutive-failure counter and time-based lock |
| `auth/AuthenticationService` | Orchestrates lockout check -> password check -> result |
| `cli/PortalLogin` | Console front end (no password echo on a real terminal) |
| `test/AuthTests` | 18 assertions, dependency-free harness |

## How guessing is stopped

Five consecutive failures on one account trigger a 15-minute lock (`AuthenticationService.DEFAULT_MAX_ATTEMPTS` / `DEFAULT_LOCKOUT`). While locked, attempts are rejected **before** the password is checked, so a correct password supplied during the lock is refused too. The lock expires by itself; a successful sign-in clears the counter.

Counters are keyed on a canonical username (trimmed, lowercased), so `jsmith`, `JSmith`, and ` JSMITH ` cannot be alternated to reset the count. `LockoutPolicy` mutates state only through `ConcurrentHashMap.compute`, so parallel attempts cannot lose failures to a read-modify-write race.

## Other hardening

- Passwords are hashed, never stored or compared in cleartext; `UserRecord.toString()` omits the hash.
- Unknown username, wrong password, and disabled account all return the identical message, and unknown usernames are lockout-counted too, so neither the wording nor the lock behaviour reveals which accounts exist.
- Unknown accounts still run a verification against a dummy hash, keeping response time roughly uniform.
- Password `char[]` buffers are zeroed after use rather than left on the heap as `String`s.

## Known trade-offs before production use

1. **Lockout is a denial-of-service vector.** Anyone who knows a username can lock that employee out. Pair it with per-IP/per-subnet throttling and alerting so the account lock is the last resort, not the first.
2. **Lockout state is in-memory and per-process.** Behind more than one app server, move it to a shared store (Redis/database) or an attacker gets `maxAttempts` guesses per node, and a restart clears all locks.
3. **Unknown usernames grow the counter map.** Since failures are tracked for accounts that do not exist, an attacker can add entries by inventing usernames. Bound it with a size-capped/expiring cache before exposing this to untrusted traffic.
4. **No audit trail.** Add authentication logging (username, source, outcome - never the password) to feed monitoring.
5. The in-memory store and seeded demo accounts in `PortalLogin` are for the walkthrough only; point `CredentialStore` at the real directory.
