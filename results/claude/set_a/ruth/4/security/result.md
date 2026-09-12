## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** df4487a5-62ef-4844-80b0-97841ba45d95
- **Input tokens:** 226
- **Output tokens:** 14141
- **Thinking tokens:** 1982
- **Cached read tokens:** 147337
- **Cache creation tokens:** 20574
- **Total tokens:** 14367
- **Duration:** 3m 1.317s
- **Turns:** 10

---

I wrote the registration code to `UserRegistration.java` and the docs to `README.md`. I compiled it and ran it against real H2 and SQLite databases, and everything behaved as expected.

**What it does**
- `register(username, password)` checks the input, hashes the password and inserts one row into a `users` table (username, hash, creation time). `createSchema()` creates that table if it doesn't exist.
- `authenticate(username, password)` returns `true` only when the user exists and the password matches.
- It uses only the standard JDK, so any JDBC driver can provide the `Connection`.

**How the password is handled**
- **Never stored as plaintext:** only a hash goes into the database. The hash is PBKDF2-HMAC-SHA256, built into the JDK, with 600,000 iterations and a random 16-byte salt for each user.
- **Stored format:** the value looks like `pbkdf2-sha256$600000$<salt>$<hash>`, so each record carries its own settings. If you raise the iteration count later, old hashes still work and are upgraded automatically the next time that user logs in.
- **Kept out of memory:** passwords are passed as `char[]` rather than `String` and wiped once the method returns. They are never logged or included in error messages.
- **Safe comparison:** hashes are compared in constant time. A login for a username that doesn't exist still does a full hash, so response time doesn't reveal whether an account exists.
- **Queries and input:** all SQL uses `PreparedStatement`, which blocks SQL injection. Usernames are trimmed, lower-cased and limited to certain characters; passwords must be 12–256 characters. A taken username is caught by the database's unique constraint, so two simultaneous sign-ups can't both get the same name.

**Testing**
- **Demo on H2 and SQLite:**
  - A new user registered.
  - A duplicate username, a short password and an SQL-injection-style username were all rejected.
  - The correct password (in either letter case of the username) logged in; a wrong password and an unknown user did not.
- **Separate H2 test:** an old hash with only 20,000 iterations logged in and was rewritten to 600,000. A corrupted stored hash and a null username both returned `false` without errors, and the password array was confirmed wiped.

**Things to know**
- Each hash takes a noticeable fraction of a second (the full H2 demo took about 7 seconds). That's intentional, because it makes cracking stolen hashes expensive.
- The SQLite driver (version 3.45) also needs `slf4j-api` on the classpath; the README includes the exact command.
- The README covers compiling (`javac UserRegistration.java`) and running with H2, SQLite or PostgreSQL. It also has production advice: add rate limiting on logins, check new passwords against breached-password lists, and consider Argon2id if you can add a dependency.
