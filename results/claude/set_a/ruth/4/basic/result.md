## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** f63a8364-8e3e-46ba-9f7f-1f5b67b13d1b
- **Input tokens:** 226
- **Output tokens:** 14302
- **Thinking tokens:** 2703
- **Cached read tokens:** 150107
- **Cache creation tokens:** 20921
- **Total tokens:** 14528
- **Duration:** 3m 13.481s
- **Turns:** 14

---

I wrote the Java class and a README. Both compile without warnings and work against real H2 and SQLite databases.

## Files
- **`UserRegistration.java`**: one class that uses only the JDK and works on a JDBC `Connection` you already have open.
  - `register(username, char[] password)` checks the input, hashes the password and inserts the row. If the name is taken it throws `UsernameTakenException`; if the username or password is invalid it throws `IllegalArgumentException`.
  - `authenticate(username, char[] password)` returns `true` only when the user exists and the password matches.
  - `createTableIfNotExists()` sets up a `users` table (`username` as primary key, `password_hash`, `created_at`).
  - A `main` method demonstrates registering a user and then logging in.
- **`README.md`**: explains what the code does, the security choices, the table layout, how to call it from your own code, and how to compile (`javac UserRegistration.java`) and run it with H2, SQLite, PostgreSQL or MySQL.

## Security choices
- **Passwords are hashed, never stored as plain text.** It uses PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt per user. The iteration count is saved with each hash, so you can raise it later and old passwords still work.
- **No SQL injection:** every query uses a `PreparedStatement`.
- **Hash comparison takes the same time whether it matches or not.**
- **Timing doesn't reveal which usernames exist.**
- **Duplicate names are caught by the database's unique constraint.** Two people registering the same name at once can't both succeed.
- **Usernames aren't case-sensitive:** "Alice" and "alice" are the same account.

## Testing
- **H2:**
  - Registering a user and logging in with the right password works; the wrong password is rejected.
  - Registering "alice" after "Alice" is caught as a duplicate.
  - Short passwords and usernames like `x' OR 1=1--` are rejected.
  - The stored value is a hash, not the password.
- **Timing:** a login for a missing username first took about twice as long as a wrong password (1776ms vs 869ms), which let an attacker tell whether a name exists. I fixed it; afterwards both took about the same time (935ms vs 847ms).
- **SQLite:** registration, login and duplicate detection all work. The first attempt failed with "No suitable driver found" because the SQLite driver also needs the `slf4j-api` jar. The README's SQLite example now includes it.
- **Not tested:** PostgreSQL, MySQL and SQL Server, since none were available. The README notes that on SQL Server you need to create the table yourself.

Each password check takes about 0.9 seconds on this machine. That is on purpose, because it makes guessing passwords from stolen hashes slow. If your connection has auto-commit turned off, you need to call `commit()` after `register` yourself.
