# Administrator Portal

A command-line Java program that authenticates administrator users, grants access
to admin-level functions according to role, and records every authentication
attempt in a reviewable, tamper-evident audit trail.

## Build and test

    ./build.sh                                   # compile + run the self test
    java -cp out com.example.adminportal.AdminPortal

On first start, when no accounts exist, the portal asks you to create the initial
`SUPER_ADMIN`. There is no default or built-in password.

Storage locations default to `~/.adminportal/` and can be overridden:

    java -Dadminportal.credentials=/var/lib/adminportal/admins.db \
         -Dadminportal.auditlog=/var/log/adminportal/audit.log \
         -cp out com.example.adminportal.AdminPortal

## Source layout

| File | Responsibility |
| --- | --- |
| `AdminPortal.java` | CLI: login prompt, admin menu, permission gating |
| `AuthenticationService.java` | Credential verification, lockout, audit of every attempt |
| `CredentialStore.java` | File-backed accounts (hashes only, owner-only permissions) |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256, per-password salt, constant-time compare |
| `PasswordPolicy.java` | Strength rules applied when a password is chosen |
| `AuditLogger.java` | Append-only, hash-chained audit trail with integrity check |
| `AdminUser.java` | Account record, roles and permissions |
| `test/.../PortalSelfTest.java` | 24 behavioural checks, no external dependencies |

## Security properties

**Credentials**
- Passwords are stored only as PBKDF2-HMAC-SHA256 digests: 210,000 iterations,
  256-bit key, a fresh 128-bit random salt per password from `SecureRandom`.
  Plaintext and reversible encryption are never written to disk.
- Comparison uses `MessageDigest.isEqual`, so a wrong password cannot be
  recovered byte by byte through response timing.
- Password characters are held in `char[]` and zeroed after use rather than
  lingering in the interned string pool.
- New passwords must be at least 12 characters, mix three character classes,
  avoid the username, and are screened against a list of common choices
  (extensible via a `weak-passwords.txt` resource on the classpath).

**Authentication**
- Failures return one generic message. Whether the account exists, is disabled,
  or simply had the wrong password is visible only in the audit trail.
- An unknown username is still run through a full PBKDF2 verification against a
  decoy hash, so response time does not enumerate valid accounts.
- Five failed attempts within 15 minutes lock the account for 15 minutes, which
  makes online guessing impractical; the lockout itself is audited.
- Interactive input is read with `Console.readPassword`, so the password is not
  echoed; if no terminal is attached the program says that masking is off.

**Authorisation**
- Access is checked per action against the role's permission set, not just at
  login, and denials are recorded. `ADMIN` cannot create a `SUPER_ADMIN`, and an
  operator cannot disable their own account.
- Sessions expire after 30 minutes.

**Audit trail**
- Every attempt — success, failure, lockout — plus every privileged action and
  session end is appended with a UTC timestamp, the submitted username, the
  origin, and non-sensitive context. Passwords are never passed to the logger.
- Each record carries a SHA-256 digest over the previous digest and the current
  payload. Editing or deleting any earlier line breaks verification of every
  line after it, so the trail is tamper-evident: menu option 6, or
  `AuditLogger.verifyIntegrity()`, reports the first record that fails.
- Field values are escaped, so a username containing tabs or newlines cannot
  forge additional records.
- The log and credential store are created with owner-only (`0600`) permissions,
  and the credential file is replaced atomically so a crash cannot truncate it.
- If the audit log cannot be written, authentication fails closed rather than
  granting access that would go unrecorded.

## Deployment notes

- Run the portal under a dedicated service account that owns the credential and
  log files; no other local user should be able to read them.
- The hash chain detects tampering but not wholesale deletion. Ship records to
  an append-only or remote collector (syslog, SIEM) if an attacker with local
  root is in scope, and back up the trail on the retention schedule you need.
- The lockout table is in-process. Running several instances against one store
  means counters are per instance; move that state into the shared store or a
  cache before scaling out.
- Raise the PBKDF2 iteration count as hardware improves; existing records carry
  their own iteration count, so old and new hashes coexist.
