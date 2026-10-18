# Administrator portal

A Java 17 command-line administrator portal: it authenticates administrator accounts,
issues a session, and gates privileged operations behind role checks.

There is no framework and no dependency to fetch. Everything uses the JDK
(`javax.crypto`, `java.security`, `java.nio.file`), so the only build step is `javac`.

```
./build.sh          # compile, build admin-portal.jar
./build.sh test     # compile and run the verification suite (233 checks)
```

## Try it

```sh
./build.sh

# 1. Provision the first administrator. Prompts for the password twice.
java -cp out portal.cli.Main --bootstrap-first-admin

# Non-interactive provisioning: point at a one-line file the service account can read.
umask 077
printf '%s\n' 'Correct-Horse-9' > /tmp/provision.pw && chmod 600 /tmp/provision.pw
ADMIN_PORTAL_PASSWORD_FILE=/tmp/provision.pw \
  java -cp out portal.cli.Main --bootstrap-first-admin alice
shred -u /tmp/provision.pw

# 2. Sign in.
java -cp out portal.cli.Main

# Check credentials without a menu (exit 0 = valid, 1 = not valid).
java -cp out portal.cli.Main --verify alice
```

`--store <path>` overrides the credential file location (also `ADMIN_PORTAL_STORE`); the
default is `$HOME/.admin-portal/administrators.dat`.

## Sign-in flow

`portal.cli.Main` -> `portal.cli.PortalApp` (wiring) -> `portal.cli.AdminConsole`
(prompt + menu) -> `portal.admin.AuthenticationService` (verify) ->
`portal.admin.SessionManager` (issue) -> `portal.admin.AdminGate` (authorize each command)
-> `portal.admin.AdminOperations` (the admin-level functionality).

After signing in, the menu offers account listing, creation, password reset,
enable/disable, role change, session revocation and audit review. A wrong password prints
`Invalid username or password.` and nothing else.

## Design decisions that matter for a privileged portal

**Passwords are stored as PBKDF2-HMAC-SHA256, 210 000 iterations, 16-byte random salt,
256-bit output** (`portal.security.PasswordHasher`). The stored string
`PBKDF2-SHA256$<iterations>$<salt>$<digest>` records its own cost so it can be re-hashed on
upgrade rather than invalidated. Verification re-derives and compares with
`MessageDigest.isEqual`, which is constant time for equal-length operands. A plaintext
password has no field, getter, `toString()` or log path anywhere in the code.

**Failed logins do not reveal whether the username exists.** Three separate mechanisms
would otherwise leak it, and each is checked:

- The response text is one constant string, including for disabled and locked accounts.
  `AuthResult.status()` carries the real reason, but only for the audit trail and operator
  views.
- The response *time* is equalised: a login for a name that is not in the store still
  performs one full PBKDF2 derivation via `PasswordHasher.spendSameWork`. `CountingKdf` in
  the suite asserts that an unknown name costs exactly one derivation, the same as a real
  one.
- A truncated base64 digest is *refused*, not decoded. Base64 discards trailing bits, so
  without a canonical-form check one stored digest could be rewritten into an equivalent
  spelling that still verifies.

**Attempts are bounded twice.** Five consecutive failures lock one account for 15 minutes,
and a correct password cannot rescue it while the lock is live; the lock expires on its own.
Separately, a sliding window of 25 failures across *any* usernames throttles further sign-in
attempts for the process, which is what blunts a credential-stuffing sweep.

**It fails closed.** An empty store, a record with an unparseable digest, a malformed line,
a disabled account and a null password all refuse access. A malformed record aborts the load
rather than being skipped: silently dropping a line would delete an administrator and their
lockout counters on the next save.

**There is no built-in administrator.** The store starts empty and `--bootstrap-first-admin`
refuses to run once any account exists, so an unauthenticated bootstrap cannot mint a second
super-administrator. The provisioning password comes from a `Console.readPassword` prompt or
the file named by `ADMIN_PORTAL_PASSWORD_FILE` - never from `argv`, where `ps` and shell
history would expose it. There is no `--password` option, and the suite asserts that.

**Sessions are opaque 256-bit `SecureRandom` bearer tokens**, held server-side keyed by their
SHA-256 digest. They expire on inactivity (30 min) *and* at an absolute deadline (8 h),
whichever comes first, so activity cannot keep a privileged session alive indefinitely. Each
administrator is capped at three concurrent sessions, with the oldest displaced. Every
command re-validates the token through `AdminGate` rather than reusing an earlier principal,
so a revoked session fails on the next keystroke.

**Roles gate permissions, not features by name.** `AdminRole` maps to a set of
`Permission`s; `AdminGate.require(permission, token)` is the single choke point in front of
every operation in `AdminOperations`, and denials are themselves audited. Only `SUPER_ADMIN`
may change system configuration.

**Two invariants are enforced in code rather than left to the operator**, because breaking
either is unrecoverable or invisible:

- The last active `SUPER_ADMIN` cannot be disabled, demoted or deleted - that would lock
  everybody out of the portal with no way back.
- Changing a password, role, or enabled state revokes that account's live sessions. A
  password reset that leaves old tokens valid lets an attacker who already had the password
  keep the session they stole. The check is behavioural: the suite issues a session, resets
  the password, and asserts the token is dead and the old password no longer works.

**Credential records are base64url-encoded field by field.** A username such as
`mallory:SUPER_ADMIN:ACTIVE:0:0:0` cannot break out of its record and forge a second one,
because no structural character is ever written raw. Saves go to a temporary file that is
fsynced and atomically moved into place with `0600` modes applied *before* content is written
and re-applied after the move, so a crash cannot leave a truncated or world-readable store.

**Log lines cannot be forged by input.** `AuditEvent` flattens CR/LF, strips control
characters, rejects non-canonical input and truncates at 200 characters, so a username like
`alice\nAUDIT ... SUCCESS admin logged in` cannot produce a second line. The audit trail
never records a password, a digest, or a session token (only an 8-hex fingerprint).

**The password floor for administrators is above the usual minimum**: 12 characters, at
least three character classes, five distinct characters, plus a deny-list of common and
default credentials and a rejection of username-derived and sequential passwords.
`PasswordPolicy` returns every violation at once so the operator is not prompted three times.

## Tests

No test-framework jar exists on this machine (no Maven or Gradle either), so the suite is a
plain `main` that counts checks and exits non-zero on the first failure:

```
./build.sh test
```

It covers hashing and digest tampering, password policy, store round-trips and hostile
usernames, lockout and throttling, enumeration resistance, session expiry/revocation/cap,
RBAC denials, the privileged operations including both invariants, audit sanitisation, and
the console and CLI driven end to end through `Main.run` with a scripted reader. `Clock.Fake`
makes lockouts and expiry exact rather than sleep-based, and a `KeyDerivation` seam both
speeds the suite up and makes derivation counts observable.

`python3 mutation-battery.py` then checks that those assertions are load-bearing. It copies
the tree, weakens one control at a time (24 in total: prefix-only digest compare, no lockout,
no throttle, skipped role check, world-readable store, sessions surviving a role change,
deterministic tokens, bootstrap-mints-a-second-admin, audit records the password, and so on),
rebuilds, and requires the suite to go red. A mutation the suite does not catch is reported
as a survivor and the run exits non-zero.

## Limits worth knowing

- A file store is right for one node. Concurrent edits are last-writer-wins, and there is no
  cross-process advisory lock; two simultaneous saves can lose one. Behind a load balancer,
  or wherever more than one process may write, sessions must move to shared storage
  (revocation is in-process) and the store needs a database or a locking layer.
- PBKDF2 is a sound, JDK-only choice, but Argon2id is the current recommendation for new
  privileged systems; `KeyDerivation` exists so that swap is one class.
- Input is read through `Console.readPassword` when a terminal is attached and echoed with a
  loud warning otherwise; a deployment with redirected stdin should use the password file.
- The audit sink is the console plus a bounded in-memory review window. For real operations,
  implement `AuditLog` against a append-only file or SIEM.
- Sessions live in process memory, so a restart signs everyone out. That is the safe failure
  mode for a privileged portal, but it is a behaviour change on deploy.
- No rate limiting per source address (this is not a network service), no TLS, and no
  second factor. `InteractiveReader` and `AuditLog` are the seams for those.
