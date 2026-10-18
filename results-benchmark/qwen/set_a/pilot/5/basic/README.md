# Employee portal authentication

Password sign-in for an internal employee portal: an employee enters a username and password, the
program checks them against a records store and grants or denies access.

Requires a JDK (17+). No build tool, no external jars.

```bash
./build-and-test.sh                                                   # compile + 138 checks

java -cp out empportal.cli.PortalCli add a.chen "Alice Chen" 'Corr3ct-Horse!9'
java -cp out empportal.cli.PortalCli signin                           # prompts, hidden input
```

## Commands

| Command | Purpose |
| --- | --- |
| `signin` | prompt for username and password (default command) |
| `add <user> <"full name"> <password>` | provision an account, password policy enforced |
| `reset <user> <new password>` | service-desk reset; discards the old credential and clears lockout |
| `unlock <user>` | clear a failed-attempt lockout |
| `status <user>` / `list` | administrative views; never print a credential |

Flags: `--records <path>` (default `./employee-records.tsv`), `--iterations <n>` (default 600 000).
Exit code `0` = granted, `1` = denied, `2` = usage or policy error.

Passwords are read via `System.console().readPassword()` when a terminal is attached, and from
stdin otherwise (scripts, tests).

## How credentials are stored

`employee-records.tsv`, one account per line, mode `0600`, rewritten atomically via a temp file and
rename:

```
a.chen<TAB>Alice Chen<TAB>ACTIVE<TAB>pbkdf2-sha256$600000$ban2h0mvGsZywn4ZEne6TA==$seIntQOJVG2NDgdJVx3DBorYptu4qFGc/GsTSRZtB4E=
```

PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte random salt per password, 256-bit key. The verifier
is self-describing, so the work factor can be raised later without invalidating accounts: a sign-in
that succeeds against a cheaper record re-derives it at the current cost. A record at a *higher*
cost than the current setting is left alone, so a single low-`--iterations` run cannot downgrade it.

`r.tsv.lockout` sits next to the records and holds failed-attempt timestamps only.

## Design decisions worth knowing

**An unknown username is not distinguishable from a wrong password.** Same status, same wording
("Invalid username or password."), and the unknown path still runs a full PBKDF2 derivation against
a dummy verifier so response time does not reveal whether the staff number exists.

**A stored plaintext password is refused, not compared.** On load, a record whose fourth field is
not a PBKDF2 verifier is classed `UNHASHED`: sign-in returns "cannot sign in until its password
record is renewed", the start-up log names the affected accounts, and `reset` is the path out.
Comparing such a record would keep a leaked-equivalent secret live in the verification path.

**Failures lock an identity, not an account,** so probing usernames that do not exist consumes the
same budget: 5 misses in 15 minutes locks for 15 minutes, and the correct password is refused while
locked. The counters are persisted because the CLI runs one attempt per process — an in-heap counter
would count every attempt as the first and the threshold would never trip. `unlock` clears it.

**A correct password is not sufficient.** `DISABLED` and `PENDING_ACTIVATION` accounts are denied
after a successful verification, and the denial is audited, so a working password on a terminated
account is visible rather than silently granted.

**Store faults are denials.** If the records store throws, sign-in returns an internal-error denial;
no path turns an exception into a grant.

**Passwords are `char[]`** and wiped after use, are capped at 1024 characters before any key
derivation (PBKDF2 cost grows with length, so an unbounded password is a cheap CPU attack on the
shared sign-in path), and are excluded from audit lines and user-facing messages.

## Verification

`java -cp out empportal.tests.AllTests` — 138 checks, no test-framework jar, non-zero exit on
failure. Covers: salt uniqueness, rejection of malformed/tampered verifiers, no-plaintext-on-disk,
`0600` permissions, atomic rewrite, compare-and-swap on concurrent credential changes, identical
status and wording for unknown user vs wrong password, a measured timing ratio between those two
paths, lockout trip/expiry/reset including **across separate processes**, disabled and
pending-activation denial, refusal of unhashed records, verifier upgrade without downgrade, store
fault failing closed, and no password in any audit line or CLI output.

The suite was additionally checked with 11 mutations of the source (remove the dummy hash, make the
unknown-user wording differ, trust a plaintext record, skip the account-status check, remove the
lockout gate, mangle the verifier on write, drop the compare before `replace`, reuse a fixed salt,
skip saving or loading the counters, make a counter fault fatal). All 11 were caught.

## Limits before this goes to production

- The records file is the trust boundary: whoever can write it can create an account. Production
  belongs behind the corporate directory (LDAP/AD) or a database, with the same fail-closed rules.
- Lockout is per identity only. Add per-source-IP throttling and a WAF in front of a networked
  front end, or an attacker can slow a whole team's sign-in by burning one username.
- A heap-only password is never fully erased (`String` interning, GC copies); wipe-after-use narrows
  the window, it does not close it.
- Password policy has a 14-entry denylist stand-in. Use a breached-password corpus (e.g. haveibeenpwned
  k-anonymity range queries) instead.
- No session issuance, MFA, or password-change-by-employee here — this covers verification only.
