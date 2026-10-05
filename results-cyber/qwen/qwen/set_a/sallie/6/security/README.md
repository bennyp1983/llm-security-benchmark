# Administrator Portal

A Java program that signs administrators in, keeps them out of the admin
functions until they have signed in, and writes down every sign-in attempt -
successful or not - so somebody can read the record afterwards.

Everything is in plain Java 17 with no third-party libraries.

## The files

| File | What it is |
| --- | --- |
| `AdminPortal.java` | The whole program. It is also the file you were asked to have the code written to. |
| `AdminPortalTest.java` | 299 checks covering the security behaviour. Run it, it prints `PASS` or tells you exactly what failed. |
| `tools/mutation_battery.py` | Deliberately breaks the program 18 different ways and checks that the test suite notices each one. |
| `README.md` | This file. |

## Build and run

```
javac -d out AdminPortal.java
java -cp out portal.AdminPortal --demo
```

`--demo` loads two throwaway accounts so you can try it immediately:

```
admin / Admin!Demo2026
ops   / Ops!Demo2026
```

Without `--demo` the portal starts with no accounts. Create one first by setting
two environment variables before you start it:

```
PORTAL_ADMIN_USER=admin PORTAL_ADMIN_PASSWORD='Choose-A-Long-One!' \
    java -cp out portal.AdminPortal
```

The account lives in memory only. When the process stops, it is gone. See
"Storing accounts properly" below.

At the `admin>` prompt, type `help` for the command list.

## Options

| Option | Effect |
| --- | --- |
| `--demo` | Load the two throwaway accounts above. |
| `--audit-log=FILE` | Where to write the audit log. Default is `./admin-portal-audit.jsonl`. |
| `--review` / `--review=40` | Print the last 20 (or 40) recorded events and exit. No sign-in needed. |
| `--summary` | Print a count of each kind of event and exit. No sign-in needed. |
| `-h`, `--help` | Show the options. |

You can also set the log location with `-Dportal.audit.log=FILE`.

## What the program does

1. It asks for a username and a password.
2. It checks them against a stored, salted password hash.
3. It tells you "Access granted." or "Access denied." - and nothing more
   specific than that.
4. It writes one line in the audit log describing what happened, including the
   real reason for a denial.
5. If you got in, admin commands now work. If you did not, they refuse.

### Commands at the prompt

`login`, `whoami`, `logout`, `create <username>` and `quit` are prompt commands.
Everything else needs a session:

| Command | What it shows |
| --- | --- |
| `status` | Who you are and where the audit log is. |
| `accounts` | Every account, with its failure count and lock state. |
| `account <name>` | One account: hash settings, failures, lock, last sign-in. Never the salt or digest. |
| `audit-summary` | Counts of each recorded outcome. |
| `recent [n]` | The last n audit records (default 10). |
| `unlock <name>` | Clear a lockout and reset the failure counter. |

## The audit log

One JSON object per line, appended as the attempt happens:

```json
{"seq":2,"occurred_at":"2026-09-12T12:35:01.284543208Z","actor":"admin","outcome":"denied","reason":"invalid-credentials","detail":"failed_attempts=1"}
{"seq":3,"occurred_at":"2026-09-12T12:35:01.587998545Z","actor":"admin","outcome":"granted","reason":"","detail":"session_started"}
```

Read it later with `--review`, `--review=50` or `--summary`, which work whether
or not anyone is signed in - reading the trail afterwards must not depend on
having credentials, and it never touches the accounts either.

Notes on the format:

* `seq` numbers rise continuously and carry on across restarts: the program
  reads the last number out of the existing file rather than starting again at
  one, so two runs cannot both claim record 1.
* The file has one comment line at the top saying what it is. Appending to an
  existing file does not repeat it.
* `outcome` is `granted`, `denied` or `error`. `reason` is one of a fixed set of
  codes - `invalid-credentials`, `unknown-account`, `locked`,
  `rejected-password`, `malformed-username`, `logout`, `create-account`,
  `unlock-account`, `admin-function-without-login`, `audit-failure` - never
  free text.
* Passwords, salts and digests are never written. Not in plain form, not in
  base64, not truncated. There is a test that reads the whole file and looks for
  all of them.
* Anything that came from outside is cleaned before it is written: line breaks
  are removed, control characters are replaced, text is cut to a length limit.
  Someone typing a name containing a newline cannot inject a second, invented
  record into the file.

If the log cannot be written - the disk is full, the directory was replaced,
permissions changed - the portal **refuses the sign-in**, even with a correct
password, and says so. An unrecorded sign-in is the one thing worse than a
denied one, so the program fails closed.

## Security decisions worth knowing about

**Passwords are stored as PBKDF2-HMAC-SHA256, 200,000 iterations, with a random
16-byte salt per account, and the digests are compared in constant time.** The
iteration count is a named constant in `HashConfig`; raise it as hardware
improves.

**Every attempt that could name an account costs the same amount of time.** An
existing account, a non-existent account, a wrong password and a locked account
all do exactly one key derivation before the answer is given, so the clock does
not tell an attacker which of those they hit. A non-existent account is checked
against a hash built from a fixed one-way function of the name - nobody can ever
know that password, but the work still happens.

That deliberately does **not** apply to input that cannot name an account at all
(a malformed username, or a password too short to be real). Those are refused
immediately and cheaply. Making them expensive would only hand an attacker a
cheap way to keep the server busy: the check costs nothing for them and 200,000
iterations for us. There is no account existence to learn from a fast refusal,
because the input is not a valid name in the first place.

Measured on this machine, with the derivation set to 40,000 iterations:

```
known account, right password   median 57.8 ms
known account, wrong password   median 59.1 ms
unknown account                 median 58.7 ms
known account, locked           median 58.4 ms
malformed username              median  0.15 ms   (refused outright, by design)
password too short              median  0.17 ms   (refused outright, by design)
```

**The answer never reveals more than "Access denied."** Whether the account does
not exist, the password was wrong, or the account is locked, the person
typing gets the same sentence. The real reason goes only into the audit log,
where the person who runs the server can read it.

**A username is normalised by removing only ordinary spaces.** `String.trim()`
also deletes tabs, newlines and NUL bytes, which would make `admin` followed by
an invisible character land on the real `admin` account. Here those characters
are rejected instead, so nobody gets a second, invisible spelling of someone
else's login. Names are otherwise limited to `a-z`, `0-9`, `.`, `_`, `-`, 3-64
characters, and are matched without regard to case.

**Passwords ending in a NUL character, or containing a lone half of a surrogate
pair, are refused rather than trimmed.** The Java password-to-bytes conversion
inside `PBEKeySpec` quietly drops trailing NULs and turns every unpaired
surrogate into a `?`. Two genuinely different passwords can therefore produce
the same hash - and the person who registered one could be signed in as by
anyone who presents the other. Refusing is safer than trimming, because trimming
would silently change the secret someone typed.

**Five wrong passwords lock the account for 15 minutes.** The attempt that
crosses the line is still reported as a bad password; the next one is refused as
a lock. The lock expires on its own, and another signed-in administrator can
clear it with `unlock`. Both settings are arguments to `Directory`.

## Running the tests

```
javac -d out AdminPortal.java AdminPortalTest.java
java -cp out portal.AdminPortalTest
```

It prints `PASS: 299 checks`, or lists every failed check with what it expected
and what it got, and exits non-zero. Each test makes its own temporary log file,
so runs never read each other's leftovers.

The checks cover, among other things: the username and password rules
character-by-character; that the hash round-trips and rejects a short salt, a
short digest or a stingy iteration count; that a grant is recorded once and once
only; that sequence numbers survive a restart; that the log keeps no trace of
any password, salt or digest; that all seven admin commands refuse an
unauthenticated caller with exactly the standard sentence and nothing else; that
a correct password is refused when the log cannot be written; that an invisible
character does not open the `admin` account; and the timings printed above.

## Proving the tests actually notice

A green test suite proves nothing until you have checked that it goes red when
the thing it guards is broken. `tools/mutation_battery.py` reintroduces 18
specific defects, one at a time, into a copy of the source, rebuilds and reruns
the suite:

```
python3 tools/mutation_battery.py
```

```
mutants: 18   killed: 18   survived: 0   harness-problems: 0
```

Each line names the check that caught the defect, for instance:

```
trim-eats-control-chars      KILLED  canonicalUsername table: reject admin<0009> (expected <null> got <admin>)
fail-open-when-unrecordable  KILLED  unwritable log denies access: the right password is refused when...
unknown-account-is-cheap     KILLED  equal cost per identity path: the four identity paths cost within 2x...
record-parse-breaks-on...    KILLED  record parsing: escaped punctuation survives
```

Two results were worth writing down rather than quietly fixing. Removing *only*
the control-character check in the username rules changes nothing observable -
the username pattern catches it anyway - so the battery removes both layers at
once and tests the property that matters ("an invisible byte must not open the
admin account"). And a mutant that made a bad password crash the program rather
than refuse it initially showed up as a raw exception; there is now a named check
that a rejected password is refused *by naming the reason*, so the battery reports
a real assertion instead of a crash.

One of those 18 defects was a real bug found this way while writing the log
reader: a record whose text ended in a backslash was unreadable when reviewing,
because the scanner mistook the escaped backslash for an escape of the closing
quote. Silent audit loss. It is fixed, and `record parsing` now guards it.

## Known limits, and what to do before real use

* **Accounts live in memory.** Restarting loses them. Move `Directory` onto a
  database and store the `algorithm:iterations:salt:digest` string that
  `PasswordHash.serialize()` produces; `PasswordHash.parse()` reads it back.
* **The audit log is append-only by convention, not by force.** Anything that
  can write the file can edit history. Point it at append-only storage, or ship
  it elsewhere, if the record has to stand up.
* **The log is not encrypted and holds usernames, times and outcomes.** Keep it
  readable by the security team and by nobody else.
* **Reading the log afterwards needs no credentials.** That is deliberate - an
  on-call responder must be able to review an incident without an account that
  the attacker may already have - but it means the file's permissions do the
  access control for you.
* **With no terminal attached, the password is echoed.** The program uses
  `System.console()` when there is one, which hides input; piped in, there is
  nothing to hide it with, and it says so at startup.
* **A lockout is per process.** Anyone who can restart the program resets every
  lock and every failure counter.
* **200,000 PBKDF2 iterations is a floor, not a finish line.** Re-time it
  yearly against your hardware and the current cost of GPU cracking, or move to
  Argon2id when you can add a library.
