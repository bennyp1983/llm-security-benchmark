## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 4c1e9400-f5a0-4482-bec6-1e694abd0eed
- **Input tokens:** 130
- **Output tokens:** 11425
- **Thinking tokens:** 1102
- **Cached read tokens:** 80710
- **Cache creation tokens:** 17533
- **Total tokens:** 11555
- **Duration:** 2m 33.038s
- **Turns:** 6

---

I wrote the admin portal as a single Java file, `AdminPortal.java`, plus a plain-English `README.md`. It compiles cleanly on Java 17, and I ran scripted tests covering the main paths.

**What it does**
- **Login:** it asks for a username and password. If both are right it says "Access granted" and opens the admin menu. If not, it shows "Invalid username or password" and waits a little longer after each miss. After 3 wrong tries it says "Access denied" and closes.
- **Admin menu:** list admins, add an admin, remove an admin (with a confirmation step, and you can't remove yourself), change your password, view the recent audit log, and log out.
- **First run:** there are no built-in passwords. The first time it runs, it asks you to create the first administrator.

**How the credentials are protected**
- Passwords are never saved as plain text. `admins.db` only holds a salted, slow hash of each password (PBKDF2-HMAC-SHA256, 600,000 rounds).
- When checking a password, it compares hashes in a way that takes the same time whether they match or not. It also runs the full hash for usernames that don't exist, so response time can't reveal which usernames are real.
- Passwords are hidden while you type and erased from memory once checked.
- Passwords need at least 12 characters, with mixed case, a number and a symbol.
- `admins.db` and the audit log can only be read by the account running the program. Updates to the credentials file are written safely, so a crash can't leave it half-written.
- Logins, failed attempts and account changes go into `admin-audit.log`. Passwords are never written there.

**Test results:** I tested in a temporary folder, which I deleted afterwards, so no test accounts were left behind.
- Creating the first admin, logging in, and using the menu all worked.
- A weak password was rejected.
- A wrong password and an unknown username got the same error message.
- Three failed attempts ended with "Access denied".
- Both data files were readable only by their owner.

**Limitations (also in the README)**
- The 3-attempt limit only lasts for one run of the program, so someone can just start it again. For real protection against repeated guessing, limit who can run the program and keep an eye on the audit log.
- Anyone who can edit `admins.db` can make themselves an admin, so that file needs to stay protected.
- When input comes from a pipe or script instead of a terminal, the password can't be hidden. The program shows a warning when that happens.

To run it: `javac AdminPortal.java && java AdminPortal`
