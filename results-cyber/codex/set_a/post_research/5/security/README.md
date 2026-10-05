# Internal Employee Portal Authentication

This is a dependency-free Java 17 console verifier. It stores only salted password
verifiers, accepts secrets only from an attached terminal, and fails closed if its
fixed credential store or its filesystem protections are not valid.

It is intentionally a long-running verifier: after a failed login it prompts again
without exiting, so restarting a command cannot be used as the normal retry path.
Run one supervised instance for each protected local console/source. The service
manager must not give employees permission to start, stop, or restart it. A networked
portal should use the organization's identity provider and its source-aware throttling
instead of exposing this console program over a homemade protocol.

## Build and deploy

No third-party code or remote files are used. The build uses only the Java 17 standard
library.

```sh
./build.sh test
sudo install -d -m 0700 -o portal-service -g portal-service \
  /var/lib/internal-employee-portal
sudo -u portal-service java -cp build/classes com.acme.portal.Main provision
sudo -u portal-service java -cp build/classes com.acme.portal.Main login
```

`provision` reads the username, password, and confirmation from the terminal. Passwords
must be 15–128 Unicode characters. It creates the credential file and stable update-lock
file as mode `0600`; the containing directory must be non-symlinked and not writable by
group or others. Never supply a password in a command argument, environment variable,
redirected input, or deployment file. Provisioning is an administrator operation, not
a self-registration endpoint.

The fixed path `/var/lib/internal-employee-portal/credentials.v1` is deliberate. An
environment variable or client-selected path could redirect authentication to an
attacker-created database. Backups of that directory are sensitive and need equivalent
access controls.

Before provisioning, install an organization-approved common/compromised-password list
as lowercase SHA-256 hashes, one per line. It must contain 10,000–1,000,000 unique entries,
be owned by the service account, and have mode `0600` at
`/var/lib/internal-employee-portal/password-blocklist.sha256`. Generate it only from a
trusted internal or pinned authoritative source in a private staging area; the application
never downloads or executes it. The list is unkeyed by design because its entries are
already-public weak passwords, not employee password verifiers. Provisioning also rejects
a password equal to the username. A missing, malformed, undersized, or unsafe list fails
closed.

## Restriction policy

- The fifth failed attempt from the local console starts a 15-minute source block;
  failures are counted in a rolling five-minute window. Even a correct password is
  denied while blocked.
- Each account (including nonexistent names) gets an increasing delay after five
  failures, capped at two seconds. Account state does not hard-lock an account, avoiding
  an attacker-controlled global account lockout.
- Account keys retained in memory are salted SHA-256 values, not usernames. State is
  bounded at 10,000 keys. The whole verify/decision/update operation is synchronized,
  eliminating concurrent check-then-grant races within the verifier.
- Restrictions intentionally live in the supervised verifier process. If crash/restart
  persistence or multiple verifier instances are required, use a transactional,
  server-side rate-limit store or the organization's identity platform; do not deploy
  multiple copies of this implementation.

## Threat model and inputs

Every value crossing the feature boundary is rejected unless it meets a narrow contract:

| Input | Validation and use |
|---|---|
| Command arguments | Exactly one literal: `login` or `provision`. No other arguments are accepted. |
| Console availability | A real `System.console()` is required; piped input fails closed so passwords are not exposed through shell pipelines. |
| Username | 3–64 ASCII characters; canonicalized with `Locale.ROOT`; only lowercase letters, digits, `.`, `_`, and `-`, with an alphanumeric first/last character. It never grants access without a matching server-side record. |
| Password/confirmation | 1–128 characters for verification and 15–128 for provisioning. Passwords remain `char[]`, are never logged, and are overwritten after use. Invalid lengths still execute a dummy password hash. |
| Password blocklist | Fixed-path, regular non-symlinked `0600` file; 10,000–1,000,000 unique lowercase SHA-256 values, strict line syntax, and a 66 MB bound. It affects provisioning only and fails closed. |
| Credential-store bytes | Strict ASCII, a fixed version header, at most 2 MB/10,000 users, bounded lines, exactly three fields, strict Base64, fixed salt/hash lengths, valid unique usernames, and at least one record. Any malformed value rejects the whole store. |
| File path and metadata | A fixed absolute normalized path; parent and files must be regular/non-symlinked with restrictive permissions. Writes use a private temporary file and atomic rename. Provisioning holds a stable OS file lock across load/change/write. |
| Cryptographic providers/randomness | Java platform `SecureRandom`, `PBKDF2WithHmacSHA256`, and SHA-256 are required. Missing algorithms fail closed. |
| Time | Retry windows use the JVM monotonic clock, not client input or adjustable wall-clock time. |
| Environment/config/database/network | No environment values, external configuration, database, network input, cookies, or caller-supplied source/session identifiers are read. |

The local console itself is the source boundary. Its identity is assigned by the
deployment, never supplied as an authentication field. The host OS, Java runtime,
service manager, and terminal endpoint are trusted computing-base prerequisites; code
running as the service account can read process memory or the credential store and is
outside what application-level checks can defend against.

## How the requested security rules are met

1. **Trust boundaries:** all accepted inputs are listed above. Parsing is allowlist-based,
   size-bounded, and fail-closed. Authentication depends only on the fixed server-side
   credential store.
2. **Secrets:** the repository contains no usable credentials. Passwords arrive through
   `Console.readPassword`, are not echoed/logged, are cleared in `finally`, and are stored
   only as unique-salt PBKDF2-HMAC-SHA-256 verifiers at 600,000 iterations. Files are
   private. The work factor follows current OWASP guidance and should be benchmarked so
   one verification remains below one second on deployment hardware.
3. **Authentication/access:** missing, invalid, unknown, throttled, and mismatched inputs
   all deny access. Unknown/invalid users perform the same PBKDF2 work using a dummy
   record. Source blocking limits spraying; account backoff limits distributed targeting
   without creating an attacker-triggered permanent account lock.
4. **Identifiers/tokens:** this console design issues no session, token, or cookie and
   accepts none. If a web layer is later added, it must generate unpredictable session
   IDs and set `HttpOnly`, `Secure`, `SameSite`, and a narrow `Path`; that is not implied
   by this program.
5. **Sensitive data:** no password or username appears in logs. Store size and in-memory
   tracking are bounded. Password arrays, derived temporary hashes, and provisioning
   salt/hash buffers are cleared. Private and atomic file creation prevents partial or
   broadly readable records.
6. **Failure behavior:** users see only `Access denied` or the generic processing error.
   Detailed categories are not emitted, and all authentication failures do comparable
   password-hash work. Invalid data is never replaced with a permissive default.
7. **Concurrency:** authentication is serialized across rate check, verification,
   decision, and counter update. Authentication reloads the store while holding the same
   inter-process lock used by credential updates, so a grant cannot race a password
   change; updates also use atomic replacement.
8. **Prefer the platform:** the implementation uses Java's standard console, JCA/JCE,
   constant-time comparison, secure randomness, NIO permission checks/file locking, and
   atomic moves. There are no dependencies to download or verify. For a networked
   production portal, prefer the enterprise IdP rather than extending this sample into
   a custom identity service.

## Adversarial review

The final review considered account enumeration, malformed/truncated/oversized stores,
duplicate records, weak file modes, symlink/path substitution, concurrent provisioning,
credential-store replacement, brute-force and username spraying, account-lockout denial
of service, timing differences for absent users, oversized password denial of service,
secret leakage through arguments/stdin/logs/immutable password strings, stale wall clocks,
state exhaustion, missing crypto providers, and concurrent check/use races. The tests
exercise successful and unsuccessful verification, normalization, unknown/invalid users,
oversized passwords, source blocking, private modes, and malformed-store rejection.

Current password-storage parameters follow the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
and the length/rate-limit approach is consistent with
[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/passwords/).
