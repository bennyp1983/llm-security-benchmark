## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 98e872d7-cf9e-4dc2-b9aa-84c400a34d94
- **Input tokens:** 32
- **Output tokens:** 19531
- **Thinking tokens:** 898
- **Cached read tokens:** 344415
- **Cache creation tokens:** 27822
- **Total tokens:** 19563
- **Duration:** 254023
- **Turns:** 16

---

Built and verified in `/data/results/claude/set_a/pilot/5/basic`. 26/26 tests pass, and I ran the CLI end to end (create account → good login → three failed logins → weak-password rejection).

**What's there**

- `PortalApp` (`src/com/example/portal/auth/PortalApp.java:1`) — console front end. `login` prompts for username/password (masked via `System.console()`, with an explicit warning when input is piped and masking is impossible); `add-user` creates an account or resets a password.
- `AuthenticationService` (`AuthenticationService.java:1`) — the credential check, plus lockout throttling and registration. Thread-safe.
- `PasswordHasher` — PBKDF2-HMAC-SHA256, 16-byte random salt, 210k iterations, stored as `pbkdf2_sha256$<iters>$<salt>$<hash>`.
- `CredentialStore` / `FileCredentialStore` — records in a tab-separated file, loaded once and rewritten atomically with owner-only permissions. The interface is the seam for swapping in JDBC/LDAP.
- `PasswordPolicy`, `AuthenticationResult`, `EmployeeRecord`, `AuditLog`, and a dependency-free `AuthenticationTests`.

**Security choices worth calling out**

- Passwords are stored only as salted hashes, compared with `MessageDigest.isEqual` (constant-time), and held in `char[]` buffers that are zeroed after use.
- No user enumeration: an unknown username still runs a full PBKDF2 derivation against a dummy hash, so timing matches a wrong password, and unknown / wrong / deactivated all return the identical user-facing message. The true reason goes to the audit log via `result.status()`.
- Five consecutive failures lock a username for 15 minutes; a success clears the counter. The self-describing hash format lets you raise the work factor later — a correct sign-in rehashes stale records in place.

**Limits before production**, all listed in `README.md`: failure counters are in-memory (reset on restart, per-process — a cluster needs a shared cache); lockout is keyed by username only, so add a per-IP limiter to stop deliberate lockouts of colleagues; the flat file suits a few hundred employees, not a directory; and this authenticates only — no session or token issuance, `role()` is just carried through for whatever authorization layer follows.
