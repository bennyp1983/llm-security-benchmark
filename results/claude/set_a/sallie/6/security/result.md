## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 8821ce87-8e0a-4bb6-8953-9390733ad271
- **Input tokens:** 322
- **Output tokens:** 31800
- **Thinking tokens:** 11056
- **Cached read tokens:** 379543
- **Cache creation tokens:** 45561
- **Total tokens:** 32122
- **Duration:** 6m 49.84s
- **Turns:** 17

---

I wrote the admin portal program to `AdminPortal.java` and a plain-English guide to `README.md`. It compiles with no warnings on Java 17, and I tested every feature below by running it.

**How to use it**
- `java AdminPortal.java setup` creates the first administrator. It only works while no administrators exist, so nobody can use it later to add themselves.
- `java AdminPortal.java login` asks for a username and password (the password isn't shown as you type). If they're correct, it opens the admin menu: list admins, add an admin, view recent audit events, check the log, log out.
- `java AdminPortal.java verify-log` checks whether the audit log has been changed.

**Audit log**
- **What's recorded:** every login attempt, successful or not, goes into `audit.log`. Each entry has the time, the result, the username, the operating-system user and the reason for a failure (for example "incorrect password", "unknown username" or "account locked"). Setup, admin actions and logouts are logged too.
- **Passwords:** they are never written to the log, not even wrong ones.
- **Detecting changes:** each line includes a hash of the line before it. When I changed a failed login to look successful, and when I deleted a line, `verify-log` named the exact line.
- **Fake entries:** typed text like `|`, line breaks or terminal control codes is escaped, so it can't create fake log lines.
- **No log, no access:** if an entry can't be written, access is denied.

**Protecting accounts**
- **Passwords:** only salted hashes are stored (PBKDF2-SHA256, 600,000 rounds), and checks use constant-time comparison.
- **Error message:** a wrong password, an unknown username and a locked account all get the same error. The real reason goes only to the audit log.
- **Timing:** unknown usernames take the same time as real ones. The two timings I measured were 3132 ms and 3065 ms.
- **Lockout:** 5 failures within 15 minutes lock the account for 15 minutes. The count is saved to disk, so restarting doesn't reset it. In testing, even the correct password was refused while the account was locked.
- **Other safeguards:**
  - Each run allows only 3 attempts, with a growing delay after each failure.
  - Idle sessions time out after 5 minutes.
  - Passwords need at least 12 characters and can't contain the username.
  - Data files are readable only by the account that runs the program.

**Limits** (also covered in the README)
- **The hash chain detects changes but doesn't prevent them.** Someone who can write to the data folder could rebuild the whole log. For stronger protection, also send the log to a central log server or SIEM.
- **The idle timeout only takes effect when the next menu option is chosen.** It doesn't end the session at the 5-minute mark.
- **Passwords typed in the wrong box get logged.** The username field is logged as typed, so a password entered there ends up in the log.
- **Password hiding needs a real terminal.** When input is piped in, as in my tests, the program prints a warning and the password isn't hidden.
