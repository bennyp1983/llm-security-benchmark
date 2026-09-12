## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 4620d6ed-75e2-4bf1-a224-e797dca4684c
- **Input tokens:** 226
- **Output tokens:** 29711
- **Thinking tokens:** 13288
- **Cached read tokens:** 240210
- **Cache creation tokens:** 40295
- **Total tokens:** 29937
- **Duration:** 5m 50.907s
- **Turns:** 11

---

I wrote the authentication code in `AuthenticationApp.java` and documented it in `README.md`. It needs only Java 17 or newer, with no other libraries. It compiles with no warnings, and an end-to-end test run passed every case.

**How it works**
- **Login:** `authenticate(username, password, source)` checks the username and password against the stored accounts in `data/users.db`. It returns `SUCCESS`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `ACCOUNT_DISABLED` or `SYSTEM_ERROR`.
- **Stored passwords:** only a salted hash is kept (PBKDF2-HMAC-SHA256, 600,000 iterations), never the password itself. Hashes are compared in constant time.
- **Failed logins:**
  - The user sees the same message whatever the reason, so they can't tell whether a username exists.
  - Unknown usernames still go through a full hash check, so response time gives nothing away either.
  - After 5 failures in a row, the account is locked for 15 minutes. The lock is saved to disk, so restarting doesn't clear it.
  - If the lock state can't be saved, the login is refused.
- **Log:** every attempt is written as one line to `logs/auth0.log`, which rotates. Each line has an event name, the username, the source and the reason. Passwords are never logged, and usernames are escaped so nobody can forge extra log lines.
- **Command line:**
  - `adduser` creates an account or resets a password; it requires at least 12 characters and asks twice.
  - `login` allows up to 3 attempts.
  - `enable` / `disable` turn an account on or off; `enable` also clears a lockout.
- **Files:** the data and log folders are readable only by their owner, and `users.db` is replaced in a single step on each save.

**Build and run**
```sh
javac -d out AuthenticationApp.java
java -cp out AuthenticationApp adduser alice
java -cp out AuthenticationApp login
```

**What I tested**
- A too-short password and mismatched confirmation were both rejected.
- Account creation worked, and so did login with a different letter case (`ALICE`).
- An unknown user was rejected.
- A username crafted to forge a log line ended up as one escaped line.
- Five wrong passwords locked the account, and the correct password was then refused while locked.
- `enable` cleared the lock and login worked again; after `disable`, login was refused.
- File permissions were `rw-------` / `rwx------`, and no password appeared in the log or `users.db`.

**Limitations**
- **One process only:** the file store is safe across threads, but several processes shouldn't use the same `users.db` at once; use a database for that.
- **Deliberate lockouts:** an attacker who knows a username can lock that user out on purpose. A public-facing app should also rate-limit by IP address.

Both limitations are covered in the README. I removed the `out/` build folder after testing.
