## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 84a7e90c-da41-4df6-b0f5-8e94209fa5fa
- **Input tokens:** 194
- **Output tokens:** 11511
- **Thinking tokens:** 1512
- **Cached read tokens:** 113799
- **Cache creation tokens:** 17997
- **Total tokens:** 11705
- **Duration:** 2m 53.899s
- **Turns:** 10

---

I wrote the program and a plain-English README. I tested it against a real database (H2), including SQL injection attempts, and all 21 tests gave the expected result.

**Files**
- `UserAuthenticator.java`: the program. It uses only standard Java 17 and works with any database that has a JDBC driver.
- `README.md`: covers setting up the database, adding users, running the program and how it stays secure.

**How the input is kept out of the query**
- **Fixed query:** the SQL is always `SELECT password_hash FROM users WHERE email = ?`. The email is passed in separately with `setString`, so the database treats it as plain text and never as part of the command.
- **Hashed passwords:** the database stores a salted PBKDF2-SHA256 hash (600,000 rounds), not the password. The program checks the password in Java, and the typed password never goes into the query at all.
- **Nothing given away:** a wrong password and an unknown email get the same message. An unknown email still runs a full check against a fake hash, so it takes about as long. Hashes are compared in constant time, and database error details aren't shown to the user.
- **Other protections:** the password isn't shown while typing and is wiped from memory after the check. Input length and email format are checked first. Database login details come from the `DB_URL`, `DB_USER` and `DB_PASSWORD` environment variables. The password can't be given on the command line, where other users could see it.
- **Adding users:** `java UserAuthenticator --hash` creates the hash to store for a new user.

**Test results**
- **Normal logins:** the correct login succeeded, including with different capital letters and extra spaces in the email. Wrong passwords, unknown emails, empty passwords and a damaged stored hash were all rejected.
- **Injection attempts:** `' OR '1'='1`, comment tricks (`'--`, `'/*`), `UNION SELECT`, `DROP TABLE` and the wildcard `%@%` all failed, in both the email and the password.
- **First round didn't prove much:** my first injection payloads contained spaces, so the email check rejected them before they reached the database. I ran space-free versions that do reach the database. Those also failed, and the `users` table was untouched afterwards.
- **Errors:** a missing `DB_URL` or an unreachable database returns exit code 2 with a short message.

The test database and compiled classes are in `/tmp/authtest`, so the project folder only has the two files. The program checks one login at a time and doesn't limit repeated guesses. A real login page would need to add that; the README mentions it.
