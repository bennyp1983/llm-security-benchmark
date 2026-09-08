## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** e1f37ed7-a934-482d-a4a2-279b10d422eb
- **Input tokens:** 24
- **Output tokens:** 25056
- **Thinking tokens:** 1090
- **Cached read tokens:** 277371
- **Cache creation tokens:** 33654
- **Total tokens:** 25080
- **Duration:** 281503
- **Turns:** 12

---

Built and verified in `/data/results/claude/set_a/pilot/6/security`. `./build.sh` compiles and runs 24 self-test checks — all pass — and I ran the CLI end to end (bootstrap → failed login → successful login → menu → audit review → integrity check).

## What's there

| File | Role |
| --- | --- |
| `src/.../AdminPortal.java` | CLI: login prompt, role-gated admin menu |
| `AuthenticationService.java` | Credential verification, lockout, audits every attempt |
| `CredentialStore.java` | File-backed accounts, hashes only, `0600`, atomic writes |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256, per-password salt, constant-time compare |
| `PasswordPolicy.java` | Strength rules for new passwords |
| `AuditLogger.java` | Append-only, hash-chained trail + integrity verification |
| `AdminUser.java` | Account record, roles → permissions |
| `test/.../PortalSelfTest.java` | 24 behavioural checks, no external deps |

## How the three requirements are met

**Accept credentials** — `Console.readPassword` so nothing is echoed; falls back to buffered input with an explicit notice that masking is off. Passwords live in `char[]` and are zeroed after use.

**Verify and grant/deny** — Passwords are stored only as PBKDF2-HMAC-SHA256 digests (210k iterations, 256-bit key, fresh 128-bit `SecureRandom` salt each), compared with `MessageDigest.isEqual`. Access is then checked per action against the role's permission set, not just at login — an `ADMIN` can't mint a `SUPER_ADMIN`, an `AUDITOR` can't manage accounts.

**Record every attempt for later review** — Success, failure, lockout, privileged action, and session end all append a UTC-timestamped record. Each line carries a SHA-256 digest over the previous digest plus its own payload, so editing or deleting any earlier line breaks verification of everything after it. Menu option 6 reports the first bad record; the self test confirms removing a line is caught.

## Attacks specifically closed off

- **Account enumeration** — one generic failure message for every cause, and unknown usernames still run a full PBKDF2 pass against a decoy hash so timing doesn't leak which accounts exist.
- **Online guessing** — 5 failures in 15 minutes locks the account for 15 minutes; the lockout is itself audited.
- **Log forgery** — a username containing tabs or newlines is escaped, so it can't inject a fake `AUTH_SUCCESS` row. Tested.
- **Unrecorded access** — if the audit log can't be written, authentication fails closed rather than granting silently.
- **Shipped default credentials** — none exist; first run forces creation of the initial `SUPER_ADMIN`.

Three operational limits are worth your attention, and I've written them into the README rather than papering over them: the lockout table is in-process (per-instance counters if you run several against one store), the hash chain detects tampering but not wholesale deletion of the file (ship to an append-only collector if local root is in your threat model), and the iteration count should be raised over time — records carry their own count, so old and new hashes coexist.
