## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 9434f3ec-3395-4e03-8d72-3918520a4193
- **Input tokens:** 258
- **Output tokens:** 11862
- **Thinking tokens:** 1415
- **Cached read tokens:** 168862
- **Cache creation tokens:** 19777
- **Total tokens:** 12120
- **Duration:** 2m 31.584s
- **Turns:** 15

---

I wrote a Java login checker and a plain-English README. I compiled it and ran it against a real SQLite database, and it gave the right result in every case I tried.

## Files
- **`UserAuthenticator.java`**: the program.
- **`README.md`**: plain-English guide to setting up, adding users, logging in, switching databases, how passwords are protected, and fixes for common errors.
- **`schema.sql`**: the layout of the `users` table. The program creates the table itself, so this is only for anyone who wants to create it by hand.
- **`lib/`**: the SQLite database driver and two small libraries it needs.

## How it works
- **Login:** run `java -cp ".:lib/*" UserAuthenticator`. It asks for an email and password, looks the email up in the database and prints either "Authentication successful" or "Authentication failed: invalid email address or password."
- **Adding users:** run `UserAuthenticator add-user`. I added this because the database starts out empty and there has to be a way to create accounts. Running it for an existing email resets that user's password.
- **Databases:** it uses SQLite (`users.db`) by default. You can point it at MySQL, PostgreSQL or another SQL database with the `DB_URL`, `DB_USER` and `DB_PASSWORD` environment variables and that database's driver.
- **Exit codes** for scripts: `0` = success, `1` = wrong email or password, `2` = bad input or a database error.

## Security choices
- **No plain-text passwords:** each user has a random salt and a slow hash (PBKDF2-HMAC-SHA256, 600,000 rounds). I checked the database file and the password itself was not in it.
- **SQL injection:** queries use parameters, so input like `' OR '1'='1` has no effect. I tested this.
- **Same message for both failures:** a wrong email and a wrong password give the same message and take about the same time, so nobody can use it to find out which emails have accounts.
- **Hidden password:** the password is hidden while typed and can't be passed on the command line, where other users could see it.

## Tests run
All of these gave the expected message and exit code: adding a user, correct login (including a differently capitalised email), wrong password, unknown email, the SQL injection attempt, password reset and login with the new password, an invalid email, an unknown command, and a missing driver.

The SQLite driver printed an SLF4J logging warning on every run. Adding `slf4j-nop` to `lib/` stopped it. I deleted the test database and compiled `.class` files afterwards, so you'll need to compile before the first run.
