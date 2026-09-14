# Employee Portal Login Program

This is a small Java program that controls who can get into the internal employee portal.
An employee types a username and password. The program checks them against the saved
account records and either lets the person in or turns them away.

It also stops people from guessing passwords. If someone gets an account's password wrong
too many times in a row, that account is locked for a while and no more guesses are accepted.

All of the code is in one file: `EmployeePortalAuth.java`.

---

## What you need

- Java 17 or newer. Type `java -version` in a terminal to check.

## Building it

In the folder that holds `EmployeePortalAuth.java`, run:

```
javac EmployeePortalAuth.java
```

## Setting up accounts (administrators)

There are no accounts at first. To create one, run:

```
java EmployeePortalAuth add-user jsmith
```

You will be asked to type the new password twice. Passwords must be 12 to 128 characters long.
If the account already exists, the same command sets a new password and clears any lockout.

## Logging in (employees)

Run the program with nothing after it:

```
java EmployeePortalAuth
```

Type your username and password when asked. What you see next:

| Message                                              | Meaning                                              |
|------------------------------------------------------|------------------------------------------------------|
| `Access granted. Welcome, jsmith.`                   | You are in.                                          |
| `Access denied. Invalid username or password.`       | Something was wrong. Try again.                      |
| `Access denied. Too many failed attempts ...`        | The account is locked until the time shown.          |

Leave the username blank and press Enter to quit.

The message does not say whether the username or the password was wrong. This is on purpose,
so an outsider cannot find out which usernames exist.

## How password guessing is stopped

1. **Five strikes.** After 5 wrong passwords in a row, the account is locked.
2. **Locks get longer.** The first lock lasts 15 minutes. Each further lock lasts twice as
   long as the one before (30 minutes, 1 hour, 2 hours, and so on), up to 24 hours.
3. **No guessing while locked.** During a lock, the password is not even checked. A correct
   password typed during a lock is still refused. This way an attacker learns nothing.
4. **A pause after each mistake.** Each wrong attempt makes the program wait one second.
   This slows down automated guessing tools.
5. **Restarting does not help.** Lock information is saved to disk, so closing and reopening
   the program does not clear a lock.
6. **Trying many attempts at once does not help.** Attempts against the same account are
   handled one at a time, so firing many attempts together cannot slip past the limit.
7. **Fake usernames are treated the same.** Unknown usernames also get "locked". This stops
   an attacker from using the lock message to find out which usernames are real.
8. **Getting back to normal.** A successful login clears the count. After 24 quiet hours
   with no failures and no active lock, the lock lengths start again at 15 minutes.

### Unlocking an account early (administrators)

If a real employee is locked out and you have confirmed who they are, run:

```
java EmployeePortalAuth unlock jsmith
```

## How passwords are kept safe

- Passwords are **never saved as plain text**. Each one goes through a slow one-way scramble
  (PBKDF2 with SHA-256, 210,000 rounds) with its own random "salt". Even someone who copies
  the records file cannot simply read the passwords.
- Passwords are checked in a way that takes the same time whether the guess is close or not.
  Unknown usernames take the same time too.
- Passwords are wiped from memory as soon as they have been checked.
- When the program runs in a normal terminal, what you type as a password is not shown on screen.

## Where the data is kept

By default the program creates a folder called `portal-data` in the current directory.
Only the user who runs the program can open it. It contains:

| File           | What it holds                                                                  |
|----------------|--------------------------------------------------------------------------------|
| `users.db`     | Usernames and scrambled (hashed) passwords.                                    |
| `lockouts.db`  | Failure counts and lock end times.                                             |
| `audit.log`    | A dated list of logins, failures, locks and admin actions. No passwords.       |

To use a different folder, do either of these:

```
java -Dportal.dataDir=/srv/portal/auth EmployeePortalAuth
PORTAL_DATA_DIR=/srv/portal/auth java EmployeePortalAuth
```

Do not edit `lockouts.db` by hand. If the program cannot read it, the program refuses to
start rather than quietly forgetting the locks.

## Changing the rules

The settings are near the top of `EmployeePortalAuth.java`:

| Setting                     | Default     | What it controls                                   |
|-----------------------------|-------------|----------------------------------------------------|
| `MAX_CONSECUTIVE_FAILURES`  | 5           | Wrong attempts in a row before a lock              |
| `BASE_LOCKOUT`              | 15 minutes  | Length of the first lock                           |
| `MAX_LOCKOUT`               | 24 hours    | Longest a single lock can last                     |
| `ESCALATION_RESET_WINDOW`   | 24 hours    | Quiet time before lock lengths start over          |
| `FAILURE_DELAY_MILLIS`      | 1000        | Pause after each wrong attempt (in milliseconds)   |
| `MIN_PASSWORD_LENGTH`       | 12          | Shortest password allowed when setting one         |

Rebuild with `javac` after changing any of them.

## Things to know

- **An attacker can lock someone out on purpose** by typing wrong passwords for that person's
  account. This is the price of stopping guessing. Watch `audit.log` for repeated failures,
  and use the `unlock` command when needed.
- The limit is **per account**. It stops heavy guessing against one person. It does not, on its
  own, stop someone who tries one or two common passwords against many different accounts.
  For a portal reachable from outside the office, also add limits per network address,
  two-step login, or a company sign-in system.
- The records are plain files meant for a single server. If several servers run the portal,
  move the account and lock data to a shared database so that all servers see the same locks.
- If you run the program without a real terminal (for example, with input piped in), typed
  passwords can be seen. The program prints a warning when this happens.
