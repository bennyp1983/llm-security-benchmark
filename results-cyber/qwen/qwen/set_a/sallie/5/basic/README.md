# Employee Portal Sign-In

A small Java program that does the sign-in part of an internal employee portal. An employee
types a username and a password, the program looks the username up in a store of records, and it
either grants access or turns the attempt away.

There are two files:

| File | What it is |
| --- | --- |
| `EmployeePortalAuth.java` | The program. |
| `EmployeePortalAuthTest.java` | Checks that prove the program behaves as described here. |

The program is about 1,400 lines and needs nothing but a Java Development Kit (JDK 17 or newer).
No downloads, no build tool, no database server.

---

## Running it

```
javac EmployeePortalAuth.java
java EmployeePortalAuth
```

You will see something like this:

```
employee portal - records store: /home/you/portal-records.txt
accounts on file: 0, password cost: 210000 PBKDF2 iterations
No accounts exist yet. Create one with: add <username>
Type your username, or help for the list of commands.
portal>
```

Start by making an account:

```
portal> add alice
new password: 
repeat it:    
done
```

Then sign in by typing the username on its own line:

```
portal> alice
password: 
Access granted for alice.
Session 0a_R64G8 is valid until 2026-09-12T11:13:19Z
```

A wrong password gets a flat refusal, and so does a username that does not exist. That is on
purpose; more on that below.

Typing `quit` ends the program, and it revokes your session on the way out.

### Options

| Option | Meaning | Default |
| --- | --- | --- |
| `--store <file>` | Where the records live. | `portal-records.txt` |
| `--iterations <n>` | How hard the program works to protect each new password. Higher is safer and slower. | `210000` |
| `--max-failures <n>` | How many wrong passwords in a row before an account is frozen. | `5` |
| `--lock-minutes <n>` | How long a frozen account stays frozen. | `15` |
| `--session-minutes <n>` | How long a granted sign-in stays valid. | `30` |
| `--help` | Print the option list and stop. | |

So `java EmployeePortalAuth --store /var/lib/portal/records.txt --max-failures 3` is a normal way
to start it.

There is also `--iterations 1000`, which is much faster. Use it only when you want quick runs
while trying things out. It protects passwords far less well, and it does not change passwords
that are already stored.

---

## What you can type at the prompt

| You type | What happens |
| --- | --- |
| `alice` | Asks for a password and tries to sign in. |
| `add alice` | Creates an account, asking for the password twice. |
| `status alice` | Shows whether the account works and how many failed sign-ins it has. |
| `disable alice` | Stops that account from signing in at all. |
| `enable alice` | Allows it again and clears any freeze. |
| `unlock alice` | Clears a freeze without changing anything else. |
| `whoami` | Shows who is signed in, if anyone. |
| `logout` | Ends the current sign-in. |
| `quit` | Leaves the program. |
| `help` | Lists all of this. |

Names are not fussy about capitalisation or stray spaces around the edges: `ALICE`, ` alice ` and
`alice` are all the same account. Anything else about the name has to be plain letters, numbers,
dots, underscores or hyphens, between 3 and 64 characters, starting and ending with a letter or
number.

A new password must be at least 10 characters and contain at least one letter and one digit. On
the way in, when someone is only signing in, the password is not judged - only checked.

---

## Where the records live

The store is a plain text file you can open and read. It looks like this:

```
# employee-portal records v1: username|salt|hash|iterations|status
alice|asNi+tyWzHhj3LEW9f3iHg==|ouvSaa9Nb//dmnpf/SCy/MkTpOKdZmTH4+QOM74IZug=|210000|ACTIVE
```

The important thing is what is **not** there: nobody's password. In place of the password the file
holds two numbers produced from it.

One is the **salt**, a random string given to that account alone. The other is the **hash**, a
fingerprint computed from the salt and the password together by repeating one arithmetic recipe
210,000 times. Reversing that recipe is not practical, so the file does not need to hold the
password itself. Checking a sign-in means running the same recipe on the typed password with the
same salt and comparing the fingerprints.

Why the salt matters: without one, two people who pick the same password would have identical
entries, and anyone holding the file could see that - and look the fingerprints up in a list of
common ones. With a private random salt per account, every entry has to be attacked separately.

Why the 210,000 repetitions matter: they make a single guess cost about a third of a second. That
is nothing for a person signing in once, and everything for a thief trying a million guesses.

The file is written so that only its owner can read it. When it is updated the program writes a
temporary file and swaps it into place, so a crash part way through cannot leave a half-written
store behind.

If a line in the file is damaged - a typo, a truncated line, a fingerprint of the wrong length -
the program ignores that line, says how many it ignored when it starts up, and carries on. It
never quietly accepts a record it cannot fully understand.

---

## Things this program does on purpose

**Refusals are worded identically.** Whether the username is unknown or the password was wrong,
the screen says `Access denied: invalid username or password.` Someone typing names to see which
ones exist learns nothing. The reason is written to the log for the administrator, never to the
screen.

**Turning a name in does not leak through the clock.** A program that only does the expensive
password recipe when the username exists answers unknown names noticeably faster, and that speed
difference is enough to find out which names are real. So this program runs the recipe exactly
once every time, including for names that do not exist and names in a nonsense format. Measured on
the machine this was written on, with all four cases side by side:

| Case | Time taken |
| --- | --- |
| right password | 1.8 ms |
| wrong password | 1.6 ms |
| account that does not exist | 1.6 ms |
| name in a nonsense format | 1.6 ms |

(Those are from the checks, which deliberately use a cheap setting of 1,000 repetitions so the
checks finish quickly. At the normal setting every one of those costs about 310 ms.)

**Freezing after repeated failures.** Five wrong passwords on one account and that account is
frozen for fifteen minutes, even for the correct password. Signing in successfully resets the
count, so an employee who mistypes twice and then gets in is back to a clean slate. An operator
can clear a freeze early with `unlock`.

**Passwords are not kept in memory longer than they must be.** The password you type is used and
then overwritten. It never appears in the log, on the screen, or in the store file.

**Names are checked character by character before they are used or printed.** This sounds
fussy. The reason is that a username is typed by a stranger to the program, and printing it back
out without checking lets them send your terminal a control sequence that changes the screen or
pretends to be a different message. An invisible character stuck on the end of a name is also a
problem in the other direction: Java's usual `trim()` routine deletes invisible characters, so
`alice` with an invisible character on the end would look like a second valid spelling of Alice's
account. This program only removes ordinary spaces, and refuses everything else outright.

**Passwords are refused if they contain characters the password recipe would handle
inconsistently.** In Java, a password ending in an invisible null character is quietly shortened,
and half of a two-character symbol is quietly replaced with a question mark. Two different
passwords would then look the same to the store. Rather than accept that, such passwords are
rejected at the door, with the reason given.

**A granted sign-in gets a session.** Each success produces a random one-off token with an expiry.
`whoami` confirms it is still live; `logout` or exiting destroys it.

**Old records get quietly strengthened.** If the portal's setting for effort goes up, an account
created under the older, cheaper setting is re-protected at today's level the next time its owner
signs in successfully - because that is the only moment the plain password is available. A failed
attempt changes nothing at all.

---

## What this program is *not*

Be honest with yourself about these before using it for anything real.

- **It is a console program, not a website.** There is no login page, no network listener, and
  nothing to defend on the network. Real portals need that whole other layer, and its protections
  (HTTPS, protection against scripted guessing across many machines, protection against session
  theft) are not here.
- **Anyone at the keyboard is an operator.** `add`, `disable` and `unlock` are available to
  whoever is running the program, because a single-user console tool has no one else to ask. A
  real portal needs a separate identity for administrators, and the ability to sign in must not
  grant the ability to create accounts.
- **Freezes and sessions live in memory.** Restarting the program clears every freeze and logs
  everyone out. That is convenient and also means a restart is a way round a freeze. A real
  deployment keeps this state in the database.
- **One machine, one file.** Several instances running at once will overwrite each other's
  changes. The store has no locking.
- **A stolen store file can still be attacked offline.** The 210,000 repetitions make it slow, and
  the per-account salt stops bulk lookup tables, but a determined attacker with the file works
  through it one account at a time. Weak human passwords will fall. Protect the file, and back it
  up somewhere equally protected.
- **The recipe is PBKDF2, which is sound but not the newest choice.** Modern systems often prefer
  Argon2id, which resists purpose-built cracking hardware better. Switching means changing one
  class in this program (`PasswordHash`) plus the version marker in the file.
- **There are no groups, roles, or per-page permissions.** It answers one question: may this
  person in?
- **Nothing is audited to a durable place.** Log lines go to the screen. A real portal needs them
  in a store the person being logged cannot rewrite.

---

## Running the checks

```
javac -Xlint:all,-auxiliaryclass -d /tmp/build EmployeePortalAuth.java EmployeePortalAuthTest.java
java -cp /tmp/build EmployeePortalAuthTest < /dev/null
```

(The `-Xlint:all,-auxiliaryclass` part keeps the compiler's warnings-as-errors discipline useful
while the checks sit in a second file next to the program. The `-Werror` flag can be added to the
`javac` line to make it refuse to build with any warning at all. `< /dev/null` is there because
the checks feed passwords in directly rather than typing at a real keyboard.)

It prints one line per check and ends with a count. On the machine this was written on:
**295 checks, 0 failed**.

The checks cover the name and password rules, the hashing, the reading and writing of the store
file, right and wrong credentials, disabled accounts, freezes including what happens when the
clock moves past the end of one, sessions and their expiry, the wording the terminal shows, and
the command line options.

One check is worth singling out, because it verifies the timing claim above rather than just
asserting it. It measures all four sign-in paths, prints the numbers, and fails if the slowest
path costs more than twice the cheapest - or if the cheapest is under half of one password recipe,
which would mean a path that skipped the work. Deleting the equalising work from the program makes
that check shout: the spread becomes 46 times instead of 1.1.

The checks were themselves checked, by deliberately breaking 41 things in the program one at a
time - accepting any password, ignoring a freeze, letting a disabled account in, using Java's
`trim()` on names, skipping the timing work, and so on - and confirming the suite noticed every
one and named the check that caught it. 39 of the 41 were caught. The other 2 cannot change any
behaviour at all (they sit in defensive branches that the platform's own guarantees make
unreachable) and are listed as such rather than quietly ignored.
