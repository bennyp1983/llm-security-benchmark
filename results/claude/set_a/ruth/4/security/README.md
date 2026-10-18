# UserRegistration: storing and checking passwords safely over JDBC

`UserRegistration.java` is a single Java class. It creates new user accounts in an SQL
database and checks their username and password at login later. It only needs the JDK
(Java 8 or newer, tested on OpenJDK 17). You can use any JDBC driver to supply the
`java.sql.Connection`.

## What it does

| Method | Purpose |
|---|---|
| `new UserRegistration(Connection)` | Wraps a JDBC connection you already have open. The class never closes the connection and never changes its auto-commit or transaction settings. |
| `createSchema()` | Creates the `users` table if it does not exist yet. |
| `register(String username, char[] password)` | Checks the input, hashes the password and inserts the user. It throws `RegistrationException` for bad input or a username that is already taken. |
| `authenticate(String username, char[] password)` | Returns `true` only if the user exists and the password matches. |

Table layout (the DDL works on H2, SQLite, PostgreSQL and MySQL/MariaDB):

```sql
CREATE TABLE IF NOT EXISTS users (
  username      VARCHAR(64)  NOT NULL PRIMARY KEY,
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP    NOT NULL
);
```

## How passwords are handled

1. **The plaintext password is never stored.** Only a salted, slow hash goes into the
   `password_hash` column.
2. **The hash is PBKDF2-HMAC-SHA256** (`PBKDF2WithHmacSHA256`, built into the JDK) with:
   - 600,000 iterations (OWASP's current recommendation for PBKDF2-SHA256),
   - a unique 16-byte salt for each user, from `SecureRandom`,
   - a 256-bit derived key.
3. **The stored format describes itself:** `pbkdf2-sha256$<iterations>$<base64 salt>$<base64 hash>`,
   for example
   `pbkdf2-sha256$600000$zWiYn7VDOkUJfchdwNOvcA$G8NaCnHIeMN1LpEhWIplZXABFR1EaIvuLw+hYDEgRL0`.
   Each record carries its own parameters. If you raise `ITERATIONS` later, older hashes still
   verify, and they are **re-hashed with the new settings automatically** the next time that
   user logs in successfully.
4. **Passwords are passed as `char[]`, never as `String`.** Both public methods wipe the array
   (and the `PBEKeySpec`) before returning, so the password does not stay in memory.
   Passwords are never logged or put into exception messages.
5. **The hash comparison takes constant time** (`MessageDigest.isEqual`).
6. **User enumeration is harder.** A login for a username that doesn't exist still runs a
   full PBKDF2 computation against a dummy hash, so response time doesn't reveal whether the
   account exists. `authenticate` returns a plain `false` in both cases.
7. **SQL injection is blocked.** Every query uses `PreparedStatement` parameters.
8. **Input is checked:**
   - Usernames are trimmed and lower-cased, and must match `[a-z0-9._-]{3,64}`.
   - Passwords must be 12 to 256 characters long. The upper limit stops very long inputs
     from being used for denial of service.
   - Duplicate usernames are caught by the primary-key constraint, not by a check-then-insert
     step, so there is no race condition. The error comes back to the caller as
     `RegistrationException("Username is already taken.")`.

## Using it from your code

```java
Connection conn = ...;                       // your existing, open connection
UserRegistration users = new UserRegistration(conn);
users.createSchema();                        // once, or manage the schema with migrations

try {
    users.register("alice", passwordChars);  // passwordChars is wiped afterwards
} catch (UserRegistration.RegistrationException e) {
    // show e.getMessage() to the user: invalid input or username taken
}

boolean ok = users.authenticate("alice", loginPasswordChars);
```

If your connection has auto-commit turned off, call `conn.commit()` after `register`
(and after `authenticate`, because it may upgrade an old hash).

## Compile

```sh
javac UserRegistration.java
```

## Run the demo

`main` takes a JDBC URL plus an optional database user and password. Put your JDBC driver
jar on the classpath (use `;` instead of `:` as the separator on Windows).

```sh
# H2 in-memory database
java -cp .:h2-2.2.224.jar UserRegistration jdbc:h2:mem:demo

# SQLite file database (sqlite-jdbc 3.45+ also needs slf4j-api on the classpath)
java -cp .:sqlite-jdbc-3.45.1.0.jar:slf4j-api-1.7.36.jar UserRegistration jdbc:sqlite:users.db

# PostgreSQL
java -cp .:postgresql-42.7.3.jar UserRegistration jdbc:postgresql://localhost/app dbuser dbpass
```

- **In an interactive terminal**, the program asks for a new username and password (typing is
  not echoed), asks you to confirm the password, registers the account, then asks you to log in.
- **Without a console** (for example with input piped or redirected), it runs a scripted demo.
  The demo uses sample credentials and shows a successful registration, a rejected duplicate,
  a rejected weak password, a rejected malicious username, correct and wrong logins, and the
  stored hash:

```
register 'alice' -> OK
register 'alice' -> rejected: Username is already taken.
register 'bob' -> rejected: Password must be at least 12 characters long.
register 'x'; DROP TABLE users; --' -> rejected: Username must be 3-64 characters: letters, digits, '.', '_' or '-'.
login alice / correct password -> true
login ALICE / correct password -> true
login alice / wrong password   -> false
login nobody                   -> false
stored value for alice: pbkdf2-sha256$600000$...$...
```

Each hash or verification takes a noticeable fraction of a second. That is intentional: it
makes brute-forcing stolen hashes expensive.

## Notes for production

- Add rate limiting or account lockout around `authenticate`. Slow hashing alone does not
  stop online password guessing.
- Consider also checking new passwords against a list of known-breached passwords
  (NIST SP 800-63B).
- If you can add a dependency, Argon2id (for example via Bouncy Castle or `argon2-jvm`) is an
  even stronger choice. The self-describing hash format makes it straightforward to migrate.
- Run the database connection over TLS so credentials in transit to your app server and the
  stored hashes are protected.
