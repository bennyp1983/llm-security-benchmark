# Administrator Portal

A console Java program that authenticates administrator users and gates admin-level
functionality behind that authentication. No third-party dependencies; Java 17+.

## Build and run

```bash
javac -d out $(find src -name '*.java')

# Run the portal (creates ./data/admin-users.txt and ./data/admin-audit.log)
java -cp out com.example.adminportal.AdminPortal

# Override file locations
java -cp out -Dadminportal.store=/etc/adminportal/users.txt \
             -Dadminportal.audit=/var/log/adminportal/audit.log \
             com.example.adminportal.AdminPortal

# Tests
java -cp out com.example.adminportal.AuthenticationTests
```

On first run there are no accounts, so the portal prompts you to create the initial
`SUPER_ADMIN`. After that it prompts for a username and password, verifies them and either
opens the administrator menu or denies access.

## Layout

| File | Role |
| --- | --- |
| `AdminPortal` | Entry point: first-run setup, credential prompt loop |
| `AuthenticationService` | Credential verification, lockout, audit calls |
| `AuthenticationResult` | Granted / denied / locked-out outcome |
| `PasswordHasher` | PBKDF2-HMAC-SHA256 hashing and constant-time verification |
| `CredentialStore` | File-backed account records (hashes only) |
| `AdminUser`, `AdminSession` | Account record; bounded authenticated session |
| `AdminConsole` | Admin functionality, each action role-checked |
| `PasswordPolicy`, `AuditLog`, `TextIo` | Strength rules, event log, console I/O |

## Security properties

- **No plaintext passwords anywhere.** Only PBKDF2-HMAC-SHA256 hashes (210,000 iterations,
  per-user 128-bit salt) are stored. Parameters are encoded alongside the hash so the work
  factor can be raised without invalidating existing credentials.
- **No hardcoded or default credentials.** The first administrator is created interactively,
  so there is no shipped account to forget to change.
- **Constant-time comparison** via `MessageDigest.isEqual`, so verification time does not leak
  how much of a guess was correct.
- **No user enumeration.** Unknown user, wrong password and disabled account all return the
  same message, and an unknown username still runs the full KDF so the timing matches.
- **Brute-force throttling.** Five failures lock an account for 15 minutes; a correct password
  is refused while the lockout holds, and the counter resets on success.
- **Bounded sessions.** 10-minute idle timeout and a 4-hour absolute lifetime.
- **Authorisation checked per action,** not just at the menu: privileged operations re-verify
  the session is live and holds the required role.
- **Audit log** of every authentication and privileged action, with control characters stripped
  from usernames so a crafted input cannot forge log lines. Passwords and hashes are never logged.
- **Least-privilege files.** The credential store is written `rw-------` via an atomic
  temp-file-and-move, so a partial write cannot leave it readable or corrupt.
- **Password buffers are zeroed** after use, and a strength policy (12+ chars, mixed classes)
  applies whenever a password is set.

## Deliberate limits

This is a self-contained console program, so state is process-local and file-backed. For a
multi-user or networked deployment you would want: the account store in a database with the
lockout counters shared across nodes (they are in-memory here, so a restart clears them);
TLS-terminated transport; MFA for admin accounts; and log shipping to a collector the portal
itself cannot rewrite.
