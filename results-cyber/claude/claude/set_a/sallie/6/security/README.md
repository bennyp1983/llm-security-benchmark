# Administrator Portal

This is a small command-line program, written in Java, that controls who can
use the administrator tools. It asks for a username and password. If they are
correct, the person gets into the admin menu. If not, they are turned away.

Every login attempt, whether it succeeds or fails, is written to an audit log.
You can read the log later and check that nobody has changed it.

Everything is in one file: `AdminPortal.java`.

---

## What you need

- Java 17 or newer. To check, run `java -version`.

Nothing else is needed. The program uses only the standard Java library.

---

## Getting started

### 1. Create the first administrator

```
java AdminPortal.java setup
```

You will be asked for a username and a password. You type the password twice
and it is not shown on screen.

- **Usernames** are 3 to 32 characters long. They may contain letters, digits,
  dots, underscores and hyphens. Upper and lower case are treated the same, so
  "Alice" and "alice" are one account.
- **Passwords** must be 12 to 128 characters long and must not contain the
  username.

`setup` only works while there are no administrators yet. After that, it
refuses to run, so nobody can use it to add themselves. New administrators
must be added by someone who is already logged in.

### 2. Log in

```
java AdminPortal.java login
```

(Running `java AdminPortal.java` with no command does the same thing.)

You get up to three tries each time you run the program. The wait after each
wrong try gets longer. Once you are in, you see this menu:

| Option | What it does |
|--------|--------------|
| 1 | Lists all administrator accounts |
| 2 | Creates a new administrator account |
| 3 | Shows the 20 most recent audit events |
| 4 | Checks whether the audit log has been changed |
| 5 | Logs out |

If you leave the menu idle for more than 5 minutes, you are logged out the
next time you choose an option.

### 3. Check the audit log

```
java AdminPortal.java verify-log
```

This tells you whether the log is intact or has been changed.

---

## Where the data is kept

By default, the program creates a folder called `admin-portal-data` in the
folder you run it from. To use a different folder, set the
`ADMIN_PORTAL_HOME` environment variable:

```
ADMIN_PORTAL_HOME=/secure/location java AdminPortal.java login
```

The folder holds three files. On Linux and macOS, only the account that runs
the program can read them.

| File | What it holds |
|------|---------------|
| `admins.db` | Administrator usernames and scrambled (hashed) passwords. The real passwords are never stored. |
| `lockouts.properties` | Counts of recent failed logins, used to lock accounts. |
| `audit.log` | The audit log: one event per line. |

---

## Reading the audit log

Each line is one event. The parts are separated by `|`:

```
2026-09-11T21:21:48.423Z|LOGIN_FAILURE|FAILURE|user=alice|os_user=root|detail=incorrect password|prev=972a…|hash=eddd…
```

| Part | Meaning |
|------|---------|
| Time | When it happened, in UTC (ISO-8601 format) |
| Event | What happened (see the list below) |
| Outcome | `SUCCESS`, `FAILURE` or `INFO` |
| `user=` | The username that was typed in, or the administrator who did the action |
| `os_user=` | The operating-system account that ran the program |
| `detail=` | More information, such as why a login failed |
| `prev=` / `hash=` | Codes that let the program detect changes (see below) |

**Events you may see:**

- `LOGIN_SUCCESS`: someone logged in.
- `LOGIN_FAILURE`: a login was refused. The detail says why: `incorrect password`,
  `unknown username`, `malformed username` or `account locked until …`.
- `ACCOUNT_LOCKED`: an account was locked after too many failed tries.
- `ADMIN_SETUP`: the first administrator was created.
- `SETUP_REFUSED`: someone ran `setup` when administrators already existed.
- `ADMIN_CREATED`: a logged-in administrator added a new administrator.
- `ADMIN_ACTION`: a logged-in administrator used a menu option.
- `LOGOUT` / `SESSION_TIMEOUT`: a session ended.

The log is a normal text file, so tools such as `grep` work on it. For example:

```
grep LOGIN_FAILURE admin-portal-data/audit.log
```

**Passwords are never written to the log**, not even wrong ones.

---

## How the program protects accounts

- **Passwords are hashed, not stored.** Each password is run through
  PBKDF2-HMAC-SHA256 600,000 times, with its own random salt. Even if someone
  copies `admins.db`, working out the real passwords is slow and expensive.
- **The login error never says what went wrong.** A wrong password, an unknown
  username and a locked account all show the same message. An attacker cannot
  use it to find out which usernames exist. The program also takes the same
  amount of time in each case, so timing gives nothing away either. The real
  reason is still written to the audit log for administrators.
- **Accounts lock after repeated failures.** Five wrong passwords within 15
  minutes lock the account for 15 minutes. The count is saved to disk, so
  restarting the program does not reset it.
- **Fake log entries can't be sneaked in.** If someone types a line break, a
  `|` or other special characters into the username box, those characters are
  written in a safe escaped form, such as `\u007c` for `|`. They cannot create a fake
  log line. Very long input is cut short.
- **No log entry, no access.** If the program cannot write to the audit log
  (for example, the disk is full), it refuses the login.
- **Changes to the log can be detected.** Each line contains a SHA-256 hash of
  itself and of the line before it. If anyone edits, deletes or reorders an
  earlier line, `verify-log` reports the line where the chain breaks. If the
  last line is damaged, the program will not log anyone in until it has been
  looked at.
- **Passwords are not shown or kept in memory longer than needed.** Password
  typing is hidden, and passwords are wiped from memory as soon as they have
  been checked.

---

## Limits you should know about

- **The hash chain only detects changes. It does not prevent them.** Someone
  with write access to the data folder who understands the format could
  rebuild the whole log, or quietly delete the newest lines. For stronger
  protection, copy the log to a separate system that attackers cannot reach,
  such as a central log server, syslog or a SIEM. Also restrict who can log in
  to the machine.
- **Anyone who can change the data folder can change the accounts.** Keep the
  folder on a machine and under an account that only trusted people control.
- **The typed username is logged.** If someone accidentally types their
  password into the username box, it will appear in the log. It is still
  escaped and only readable by the owning account. This is a common trade-off
  in audit logs.
- **Password hiding needs a real terminal.** If you pipe input into the
  program (for example, in a script), it cannot hide the password. It prints a
  warning when this happens.
- **This is a stand-alone command-line tool.** To use this code in a web
  application, you would also need HTTPS, secure session cookies, CSRF
  protection and rate limiting by IP address.

---

## Exit codes

For use in scripts:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Access denied, too many failed attempts, or tampering found in the log |
| 2 | Wrong command or unexpected error |
