## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** ae136223-1e67-4506-bda6-b4dfc8dab18c
- **Input tokens:** 162
- **Output tokens:** 22673
- **Thinking tokens:** 7026
- **Cached read tokens:** 114305
- **Cache creation tokens:** 29132
- **Total tokens:** 22835
- **Duration:** 4m 39.885s
- **Turns:** 7

---

I wrote the Java login program and a plain-English README, compiled the code on Java 17 and tested it. All tests passed.

**Files:**
- `EmployeePortalAuth.java`: the whole program in one file.
- `README.md`: how to build, set up accounts, log in and unlock accounts, how guessing is stopped, and the known limits.

**How it works:**
- **Records store:** accounts are kept in `portal-data/users.db`, one per line. Passwords are never stored as plain text, only salted PBKDF2-SHA256 hashes (210,000 rounds), and they're compared in a way that doesn't leak timing.
- **Login:** the employee types a username and a password, which isn't shown on screen. Every failure gets the same message, "Invalid username or password", so an outsider can't tell which usernames exist.
- **Stopping repeated guessing:**
  - After 5 wrong passwords in a row, the account locks for 15 minutes. Each further lock doubles, up to 24 hours. The lengths start over after a successful login, or after 24 hours with no failures and no active lock.
  - While an account is locked, the password isn't checked at all, so a correct guess during a lock gets refused too.
  - Lock information is saved to disk, so restarting the program doesn't clear it.
  - Attempts on the same account are handled one at a time, so firing many guesses at once can't get past the limit.
  - Unknown usernames lock the same way as real ones, and every wrong attempt adds a one-second pause.
- **Admin commands:** `add-user <name>` creates an account or resets its password, and `unlock <name>` clears a lock. Logins, failures and admin actions are written to `audit.log`, without passwords.
- **Failing safely:** if the lock file can't be saved or read, the program refuses access instead of forgetting the locks.

**Tests run:**
- Creating an account and logging in worked.
- 5 wrong passwords locked the account, and the correct password was then refused.
- After a restart, the account was still locked.
- An unknown username locked the same way, and `unlock` restored access.
- In a test with 30 guesses at one account at the same time, only 5 passwords were actually checked and the other 26 were refused. The correct password was still refused afterwards.
- Lock lengths grew as expected: 15, 30, 60 … 1440 minutes, then stayed at 1440. The test builds and data went to `/tmp`, not your project folder.

**Limits (also in the README):**
- **Deliberate lockouts:** anyone can lock a colleague out on purpose by typing wrong passwords for their account.
- **Many accounts:** the limit is per account, so it doesn't stop someone trying one common password on many different accounts. If the portal can be reached from outside the office, add limits per network address or two-step login.
- **One server only:** the records are plain files for a single server. If several servers run the portal, they need a shared database so they all see the same locks.

Also, the Google Drive connector needs to be authorized in your claude.ai connector settings before it can be used. This task didn't need it.
