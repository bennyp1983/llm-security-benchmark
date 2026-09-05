# Employee Portal Authentication

A console Java 17 program that authenticates internal employees against a credential
records store.

## Build

```sh
javac -encoding UTF-8 -d out $(find src -name '*.java')
```

## Use

```sh
# create an account (or reset a password); prompts twice for the new password
java -cp out com.example.portal.auth.PortalApp add-user jdoe "Jane Doe" analyst

# sign in
java -cp out com.example.portal.auth.PortalApp login
```

The store defaults to `employees.tsv` in the working directory; override it with
`--store <file>` or the `PORTAL_STORE` environment variable. Audit lines go to stderr,
so `2>/dev/null` keeps them out of the interactive transcript.

Run the tests with:

```sh
java -cp out com.example.portal.auth.AuthenticationTests
```

## Design

| Class | Responsibility |
| --- | --- |
| `PortalApp` | Console I/O: prompts, masked password entry, exit codes |
| `AuthenticationService` | Credential check, lockout throttling, registration |
| `AuthenticationResult` | Outcome + the single message shown to the user |
| `PasswordHasher` | PBKDF2-HMAC-SHA256 hashing and verification |
| `PasswordPolicy` | Rules for new passwords |
| `CredentialStore` / `FileCredentialStore` | Record lookup and persistence |
| `EmployeeRecord` | One employee row |
| `AuditLog` | One line per sign-in attempt |

### Security properties

- **Passwords are never stored or logged in the clear.** Each record holds
  `pbkdf2_sha256$<iterations>$<salt>$<hash>` with a 16-byte random salt and 210,000
  iterations. The format is self-describing, so raising the work factor later does not
  invalidate old records — a correct sign-in transparently rehashes a stale record.
- **Constant-time comparison** (`MessageDigest.isEqual`) avoids leaking how much of a
  hash matched.
- **No user enumeration.** An unknown username still runs a full PBKDF2 derivation
  against a dummy hash, so timing does not distinguish it from a wrong password, and
  unknown / wrong / deactivated all produce the identical user-facing message. The real
  reason is available in `result.status()` for the audit log only.
- **Online guessing is throttled.** Five consecutive failures lock a username for 15
  minutes; a success clears the counter.
- **Password buffers are `char[]`** and are zeroed after use rather than left as
  interned `String`s on the heap.
- **The store file is written atomically** (temp file + rename) with owner-only
  permissions where the filesystem supports them.

### Limits worth knowing before this goes to production

- Failure counters live in memory, so they reset on restart and are per-process. A
  clustered deployment needs a shared cache (Redis, or a `failed_attempts` column).
- The flat file is read fully into memory and rewritten on every change — fine for a few
  hundred employees, not for a directory. `CredentialStore` is the seam to swap in JDBC
  or LDAP.
- Lockout is keyed by username only. Add a per-source-IP limiter as well to keep an
  attacker from locking out colleagues on purpose.
- There is no session or token issuance: this authenticates, it does not authorize.
  `EmployeeRecord.role()` is carried through for whatever authorization layer follows.
- The weak-password deny-list is illustrative; wire it to a breached-password corpus
  (e.g. Have I Been Pwned's k-anonymity API) for real use.
