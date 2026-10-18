# Administrator Portal

A small command line program in Java that signs an administrator in and, if the
password is right, lets them run administrator-only commands. It keeps its
accounts in a file, remembers nothing in plain text, and writes down every login
attempt.

Written for Java 17. No libraries, no build tool, nothing to download: only the
Java Development Kit.

## What it does

1. It asks for a username, then a password (hidden while you type it).
2. It checks the password against a stored, salted hash.
3. If the check passes, you get a session that lasts 15 minutes and can run the
   administrator commands. If it fails, you are told only that the username or
   password is not correct.
4. Every attempt, successful or not, is appended to an audit log.

The first time you run it there are no accounts at all, so it asks you to create
the first supervisor before it will accept any login.

## How to build it, run it and check it

```sh
# compile
javac -Xlint:all -Werror -d out $(find src -name '*.java')

# run it (accounts and log go in ~/.admin-portal by default)
java -cp out portal.AdminPortal

# choose somewhere else for its files
java -cp out -Dportal.home=/var/lib/admin-portal portal.AdminPortal

# run the checks (compiles again, then reports one line per check)
./run-checks.sh
```

`java -cp out portal.AdminPortal self-test` is also available. It creates
nothing new; it just tries three wrong logins and prints how long each took, so
you can see the timing behaviour described below with your own eyes.

## Files

| Path | What it is |
| --- | --- |
| `src/portal/AdminPortal.java` | The command line program: prompts, commands, sessions. |
| `src/portal/LoginService.java` | Verifies a username and password, counts failures, hands out sessions. |
| `src/portal/Pbkdf2.java` | Turns a password into a hash, and does the same amount of work for refusals. |
| `src/portal/CredentialStore.java` | Reads and writes the account file atomically. |
| `src/portal/PasswordPolicy.java` | Rules a new password has to satisfy. |
| `src/portal/Names.java` | Rules for usernames. |
| `src/portal/AuditLog.java` | The append-only record of what happened. |
| `src/portal/Roles.java` | Which role is allowed to do what. |
| `src/portal/PortalChecks.java` | The checks. Not needed to run the portal. |
| `run-checks.sh` | Compiles everything and runs the checks. |

In the directory the portal uses (its "home") it keeps two files:

- `credentials.tsv` - one line per account: username, iteration count, salt,
  hash, role. The password itself is never in this file. The file is created so
  that only its owner can read or write it.
- `audit.log` - one line per event: a number, the time, the event, who it was
  about, and a short note.

## Commands

Once you are signed in (`help` lists these too). Everything except `help` needs
a live session.

| Command | Who may use it | What it does |
| --- | --- | --- |
| `whoami` | anyone signed in | name and role, and when the session ends |
| `status` | anyone signed in | how many accounts there are and where the files are |
| `audit [n]` | anyone signed in | the last `n` log records, 20 if you leave `n` out |
| `admins` | supervisor | list accounts, their roles, and who is locked |
| `create [name]` | supervisor | add an operator and set their password |
| `reset [name]` | supervisor | set somebody's new password and clear their lock |
| `remove [name]` | supervisor | delete an account |
| `unlock [name]` | supervisor | clear an account's lock early |
| `logout` | anyone signed in | drop the session, stay connected |
| `quit` | anyone signed in | close the portal (`exit` works too) |

`remove` refuses to delete the last remaining account, because that would lock
everyone out of their own portal.

## How it protects the password and the login

**Passwords are stored as salted hashes.** Each account gets its own random
16-byte salt and its password is stretched with PBKDF2-HMAC-SHA256, 100,000
rounds, into a 32-byte key. A stolen account file therefore gives an attacker
nothing they can use directly, and one slow hash per guess makes guessing
expensive. When a password is checked the array holding it is overwritten
immediately afterwards, whether the check succeeded or not.

**A wrong answer tells you nothing useful.** Whether the username does not
exist, the account is locked, or the password is simply wrong, the message is the
same: *"the username or password is not correct"*.

**Answering time is the same in all three cases.** Checking a password takes
about 150 milliseconds here, and that cost would be a giveaway: an unknown
username could be answered for free, so anyone could sweep through a list of names
and see which ones have accounts, without ever guessing a password. So the
branches that cannot possibly succeed spend the same 150 milliseconds on a
look-alike hash that is never compared against anything. A refusal that is
deliberately cheap is the *unusable input* one (an empty password, a password
with a null character in it), which is answered in well under a millisecond -
that is safe because those refusals do not depend on the username at all.

**Failures are counted per account, not globally.** Five wrong tries lock that
one username for 15 minutes; a supervisor can clear the lock early with
`unlock`. A successful sign-in clears the count. Another administrator keeps
working normally while somebody else is locked out.

**Passwords have to be worth storing.** At least 10 characters, no more than
1024, containing a letter and a digit and drawing on at least three kinds of
character (upper case, lower case, digits, other), and it must not contain the
username. New passwords are typed twice; they are checked *before* you are asked
to type them a second time, so a rejected password does not swallow the line you
meant for the next question.

**Two odd inputs are refused rather than stored, because they would let two
different passwords unlock the same account:** a password containing a null
character (the hashing API quietly drops a trailing one) and one with an
incomplete character in it (the API quietly replaces it with a question mark).

**Usernames are matched ignoring case, and padding is refused, not trimmed.**
`Alice` and `alice` are the same account, on purpose. But `alice` followed by a
tab or a newline is *not* `alice`: trimming would quietly turn a mistyped or
crafted name into a valid login. Usernames are limited to `a-z`, `0-9`, `.`, `_`
and `-`, which also keeps them safe to put in the account file and the log.

**Nothing is granted unless it was written down.** A successful login is
recorded in the audit log *before* access is given. If the log cannot be written
- the disk is full, the path is broken - the login is refused with *"access
refused: the login could not be recorded"*. A portal that cannot tell you who
came in is not one worth opening. The same rule applies to `create`, `reset`,
`remove` and `unlock`.

**The log cannot be forged by its own input.** Text that arrives from user input
is written with any newline or tab replaced by `?` and any over-long field cut
short, so nobody can end a record early and append a fake one, or use the log to
speak terminal control codes at whoever reads it.

**A damaged account file is skipped, not trusted.** A row whose salt or hash has
the wrong length, whose iteration count is absurd, or whose role is unknown is
counted and ignored; the portal starts with the remaining rows and `status`
reports how many were unreadable. The file is rewritten through a temporary file
and moved into place, so a crash mid-write cannot leave a half-written account
file.

## What was actually verified

`./run-checks.sh` runs 111 checks and finishes in about 15 seconds. All 111 pass.
95 of them drive the classes directly in one process; the other 16 start the real
program as a separate process with piped input, because answering questions in
memory does not reproduce how a terminal consumes lines one at a time.

The checks cover, among others: the right password is accepted and a wrong one
is not; the wrong password and an unknown username produce the *same* sentence
from the real command line program; a padded username is refused instead of
trimmed; a null character in a password cannot smuggle a login through; the file
contains no plaintext and can only be read by its owner; a genuine account stops
working if an attacker swaps its stored hash; the failure count locks one account
and leaves the others alone; hostile text cannot forge a second log record; and
when the log cannot be written, nothing is granted.

The timing claims are checked by measuring each branch three times and insisting
that all four branches land within a factor of two of each other, while an
unusable password must come back at least ten times faster. Measured once on this
machine by `self-test`: wrong password 149.9 ms, unknown username 149.7 ms,
unusable password 0.2 ms.

Checks that pass by accident are the real risk, so 10 deliberate defects were
introduced one at a time and the suite re-run each time: drop the equal-cost work
from the unknown-username branch, from the bad-username branch and from the
locked-account branch (three defects); let one failure lock every account; grant
access even when the log write failed; accept a null character inside a password;
trim usernames instead of refusing them; write log fields unfiltered; compare keys
with a shortcutting comparison; let every role manage accounts. The checks noticed
every one (10 caught, 0 missed, no compile failures, no runner errors). Between one
and five checks failed per defect, and the failure named the broken behaviour.

Two of those deserve a note. The shortcutting key comparison changes no
observable behaviour at all, so the only honest way to pin it is a check that
reads the source text of that one method and insists it uses the constant-time
comparison - with a companion check that the method was found in the first place,
so the guard cannot pass on an empty capture. And when the log-filtering defect
was inserted, the suite caught it but then stopped early with an
array-out-of-bounds error inside the checks themselves: the forged record had
fewer fields than the next check expected. It was still a clear failure, only a
noisier one than it should be.

One limitation is stated plainly rather than tested away: `create` always makes an
`operator` and the bootstrap makes a `supervisor`, so the third role, `auditor`,
can only appear if the account file is edited by hand. Its permissions are
defined and checked, but no command can produce it.

## Known limits

- **One process at a time.** The account file is read at start-up and rewritten
  whole. Two portals sharing one home directory will overwrite each other's
  changes. There is no file locking.
- **Locks live in memory.** Restarting the portal clears every lock, deliberately
  simple, but it also means a restart is an escape hatch.
- **The account file must be protected by the operating system.** Everything here
  assumes nobody else can read it; run the portal as a dedicated user and keep
  the directory owner-only.
- **The audit log is append-only by convention.** It is not signed or chained, so
  someone who can write that file can add records (they cannot use user input to
  do it, and they cannot make a record look like two). Rotate and ship it
  elsewhere if you need real evidence.
- **No limit on username guessing across accounts.** Locks are per username, so
  spreading attempts over many names is not slowed down. Put a rate limit in
  front of it if it is ever reachable over a network.
- **Piped input is not private.** When standard input is not a terminal, passwords
  arrive as plain lines from whatever is feeding the pipe. On a real terminal the
  password is hidden by the console.
- **Timing results are statistical.** The equal-cost checks use ratios on a
  loaded machine; they are sound as a regression guard, not as a claim about your
  hardware.

## Passwords used by the checks

The checks create throwaway accounts in a temporary directory and delete them
again. Those passwords (`Alice-Passw0rd-1`, `Bob-Passw0rd-22` and the ones in
`PortalChecks.java`) are visible in this repository and exist only to make the
checks reproducible. Never reuse one of them, and never point the portal's home
directory at anything you care about while running the checks.
