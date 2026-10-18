## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** c4577f2c-ef5e-4ca0-9d99-7bd0902c25c0
- **Input tokens:** 194
- **Output tokens:** 8523
- **Thinking tokens:** 1531
- **Cached read tokens:** 111148
- **Cache creation tokens:** 14285
- **Total tokens:** 8717
- **Duration:** 1m 50.409s
- **Turns:** 10

---

I wrote the lookup code in Java and a README. I tested it against an in-memory H2 database and it works.

**Files**
- `UserAccountLookup.java`
- `README.md`: what the code does, the expected `users` table, how to call it from your code, how to compile (`javac UserAccountLookup.java`), how to run it with a driver JAR, and the exit codes.

**How the username is handled**
- **The username is never put into the SQL text.** The query is a fixed string, `... FROM users WHERE username = ?`, and the username is passed in with `stmt.setString(1, username)`. The database treats it only as a value to match, so SQL injection can't change the query.
- **The input is checked first as an extra layer.** The username is trimmed, must not be empty, can be at most 64 characters, and may only contain letters, digits, `.`, `_` and `-`. Anything else is rejected before the database is queried. The binding above is still what actually stops injection.
- **Password hashes are never read.** The query selects only `id`, `username`, `email`, `full_name`, `active` and `created_at`.
- **Other safeguards:** statements and results are always closed, the query times out after 5 seconds, and if two accounts share a username you get an error instead of one picked at random.

**Usage**
- `new UserAccountLookup(conn).findByUsername(input)` returns an `Optional<UserAccount>`, which is empty if no account matches. It doesn't close your connection.
- The class also has a small command-line demo. It reads the connection details from the `DB_URL`, `DB_USER` and `DB_PASSWORD` environment variables, so the password isn't typed on the command line.

**Test results**
- The code compiles with no warnings on JDK 17. It needs JDK 17 or newer.
- Looking up `alice` and `bob` returned the correct records, including a missing `created_at`. An unknown user gave exit code 1. Surrounding spaces were trimmed, and empty input or no argument was rejected.
- `' OR '1'='1` and `alice'; DROP TABLE users; --` were rejected by the input check.
- Those checks stop the attack strings before the query runs, so I also sent the same two strings straight through the same prepared query. Each matched 0 rows and the `users` table was untouched.

The table and column names are assumptions, and the README shows the schema they expect. If your table is different, change the SQL constant and `mapRow` in `UserAccountLookup.java`.
