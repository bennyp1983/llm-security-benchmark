# Employee portal authentication module

Credential checking for an internal employee portal, with a hard stop on password guessing.

Pure JDK 17, no third-party dependencies, no build tool required.

```bash
./run.sh            # compile + 130-check verification + scripted demo
./run.sh verify     # just the verification (exit code is the verdict)
./run.sh app        # interactive sign-in prompt
./run.sh mutants    # re-run the verification against seven broken copies of the module
```

Seeded demo accounts (`PortalAuthApp.build`): `demo / Correct-Horse-9`, `jchen / another-secret-passphrase`,
and `terminated.user` which is `DISABLED`.

---

## How password guessing is prevented

`LoginAttemptTracker` counts failed checks **per account**, and `AuthenticationService` consults it
*before* it looks at the password:

```
1. tracker.state(user)  -> locked?  -> refuse. Password is never hashed, store is never queried.
2. store.findByUsername  -> unknown? -> hash a decoy digest anyway, count a failure, generic refusal
3. status != ACTIVE      -> refuse (hash a decoy so timing matches an active account)
4. verify digest         -> success: clear history | failure: count, apply policy
```

Step 1 is the whole point. Once the threshold is reached, further guesses cost the portal nothing and
return nothing, so there is no reason to keep going and no signal to guide the next guess. Measured:
500 guesses after lockout produce **zero** store lookups (`noStoreLookupWhileLocked`).

`LoginPolicy.DEFAULT` is 5 failures inside a 15-minute window -> 15-minute refusal. Defaults follow
NIST SP 800-63B: throttle rather than forbid, keep the throttle short enough that a legitimate user
who fat-fingered their password is back in a few minutes, and make `permanentLockAfterLocks` (off by
default) the knob for escalating a persistent target to admin intervention.

### Four decisions worth defending

- **Attempts during a lock do not push the expiry out.** Otherwise continuous arrival holds an account
  shut indefinitely, and the anti-guessing control becomes a denial-of-service tool handed to the
  attacker. The lift time is fixed at lock time.
- **Counting survives address rotation.** State is keyed by account, not source IP, so rotating
  addresses buys nothing. `MAX_TRACKED_ACCOUNTS` (100k, LRU-evicting unlocked entries) bounds what a
  username-spray costs -  losing an idle account's history is cheaper than exhausting the heap.
- **Lockout beats the correct password.** While locked, the right password is also refused
  (`lockoutBlocksCorrectPasswordToo`), so the state is unambiguous and an operator can reason about it.
- **Failure history clears on success and when the window ages out**, so a stale count from yesterday
  cannot lock someone out today.

### Supporting measures

| Concern | Implementation |
|---|---|
| Stored passwords | Salted PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023), 16-byte `SecureRandom` salt, 256-bit key, self-describing encoding `$pbkdf2-sha256$<iters>$<salt>$<hash>` |
| Guessing the digest | `MessageDigest.isEqual` compares full length with no early exit |
| Username enumeration by timing | unknown usernames hash a fixed decoy digest, so both paths cost the same (measured ratio **1.00**) |
| Username enumeration by wording | one generic message for wrong password and unknown user; one for locked / hard-locked / disabled |
| Username enumeration by countdown | `PortalAuthApp.render` never reads the audit-only `accountExists` flag |
| Passwords lingering in the heap | passwords are `char[]` and wiped in a `finally` on every path; `PBEKeySpec.clearPassword()` |
| Log forging | usernames are control-character-stripped, quote-escaped and length-capped: one event renders to exactly one line |
| Secret leakage in logs | audit events can only carry `AuditEvent` fields; asserted never to contain a candidate or digest |
| DoS via a tampered record | a stored digest claiming >5M iterations is refused, not honoured |
| Memory pressure via username spray | bounded, LRU-pruned tracker state |

`toString()` on both `Credential` and `AuditEvent` cannot print a secret -  the digest is `<redacted>`
and no `AuditEvent` field can hold one.

## Layout

```
src/main/java/com/portal/auth/
  PasswordHasher.java          PBKDF2 hashing and verification
  Credential.java              one records-store row; redacting toString
  UserStatus.java              ACTIVE / LOCKED / DISABLED
  CredentialStore.java         the records-store interface
  InMemoryCredentialStore.java process-local implementation
  LoginPolicy.java             thresholds
  LoginAttemptTracker.java     per-account counting and lockout
  AuthenticationService.java   the ordered checks above
  LoginResult.java             sealed outcome; user-safe wording
  AuditEvent.java / AuditLog.java / ConsoleAuditLog.java
  AdminService.java            unlock, status change, password reset, create
  PortalAuthApp.java           console entry point
src/test/java/com/portal/auth/
  AuthVerification.java        130 executable checks
tools/mutation-check.py        re-breaks the module to prove the checks fail
run.sh                         compile / verify / demo / mutants
```

## Verification

`AuthVerification` is a `main` that counts expectations and exits non-zero on failure -  this machine
has no build tool and no test-framework jar. It drives the module through a `CredentialStore` and
`AuditLog` double plus a mutable `Clock`, so assertions are about observable behaviour (which
usernames reached the store, what landed in the audit log, what each path cost) rather than private
fields.

130 checks, all passing, covering: hashing and malformed-digest rejection; happy path; the countdown;
lockout holding against 500 further guesses; the correct password refused while locked; unknown
usernames behaving identically to real ones; lock expiry; the no-lock-extension invariant; window
ageing; history clearing on success; escalation to admin lock and recovery; `LOCKED`/`DISABLED`
records; wording and rendered-output non-leakage; audit secrecy and log-forging resistance; zero
store lookups while locked; candidate-array wiping; 16-thread contention (one lock, no lost updates,
no escape); bounded state under a 105k-username spray; and timing parity.

**Mutation-checked.** The suite was re-run against seven broken copies of the module (final run, this
tree). Every one was detected, so the checks are load-bearing rather than decorative:

| Broken copy | Failing checks |
|---|---|
| drop the pre-hash lock gate | 5 |
| let logged failures extend an active lock | 3 |
| disable the lockout threshold | 1 |
| remove the decoy hash for unknown usernames | 1 (timing ratio broke) |
| log the candidate password in the audit trail | 3 |
| make the failure wording depend on account existence | 4 |
| print the countdown only for accounts that exist | 1 |

Reproduce with `python3 tools/mutation-check.py` (tree-copy + `javac` + suite per mutant; a few
minutes, exit code is the verdict). Two caveats learned the hard way while building it: the copy is a
snapshot, so do not edit `src/` while it runs, and a mutant that survives is usually a weak mutant
rather than a weak test - break the value, not just its wiring.

## Known limits, read before deploying

- **Lockout state is in-process.** `LoginAttemptTracker` is per-JVM, so N app instances multiply the
  guess budget by N. Back it with shared store (SQL table or Redis) before running more than one
  instance; the interface is already the right seam for that.
- **Account lockout is itself a harassment vector.** Anyone can spend 5 guesses and make an employee's
  next sign-in fail. That is the accepted cost of the requirement as stated; NIST prefers rate
  limiting plus a strong password policy for this reason. `permanentLockAfterLocks` is left `0` so the
  default is a self-clearing 15-minute refusal rather than a ticket for the help desk.
- **No source-address or fleet-wide dimension.** Per-account counting is what the requirement asks
  for; a distributed spray across many accounts is only bounded by `MAX_TRACKED_ACCOUNTS`. Add a
  per-IP / per-session throttle at the edge for that.
- **No session, MFA, or password-policy layer.** This module answers "do these credentials open the
  door" and nothing else. `authenticate` clears the failure history on success, so the caller's next
  step -- issuing a session -- is the seam where that belongs.
- **`AdminService` does not authenticate its caller.** It records the operator identity for audit and
  expects the portal's admin boundary to have authorised them already.
- **`InMemoryCredentialStore` is heap-only and the seeded accounts are public.** Replace it with the
  real store; the console app's piped-input fallback echoes passwords, which is why the seeded ones
  are low-value.
- **Passwords are compared byte-exactly** (the key derivation digests the UTF-8 bytes of the `char[]`,
  with no Unicode normalisation and no case folding), so they are case-sensitive and
  whitespace-significant. The UI must not lowercase or trim a password, and `AuthenticationService`
  trims the *username* only. Whatever normalisation the portal applies at registration must be applied
  identically at read time by the caller.
- **600k iterations measured ~900ms per verification** on this machine (4-core Debian box, OpenJDK
  17.0.20.1; first hash ~1.0s including warmup). Budget for it on the request path, and prefer raising
  the count on better hardware over lowering it here. The verification suite runs at 1k iterations so
  it finishes in seconds; only the timing check uses 60k.
