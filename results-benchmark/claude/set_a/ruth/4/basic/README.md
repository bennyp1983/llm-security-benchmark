# UserRegistration — JDBC user sign-up and login

`UserRegistration.java` is a single, dependency-free Java class (JDK 11+) that
registers user accounts in an SQL database through an existing JDBC `Connection`
and later checks a username/password against the stored credentials.

## What it does

| Method | Purpose |
|---|---|
| `new UserRegistration(Connection)` | Wraps an already-open JDBC connection. The class never closes it or changes its transaction settings. |
| `createTableIfNotExists()` | Creates the `users` table (optional if you manage the schema yourself). |
| `register(String username, char[] password)` | Validates input, hashes the password and inserts the account. Throws `UsernameTakenException` if the name exists, `IllegalArgumentException` on invalid input. |
| `authenticate(String username, char[] password)` | Returns `true` only if the user exists and the password matches. |

### Security design

- **No plaintext passwords are stored.** Passwords are hashed with
  **PBKDF2-HMAC-SHA256**, 600,000 iterations, a 16-byte random salt per user
  (from `SecureRandom`), and a 256-bit output. This uses only the JDK, so there are
  no third-party crypto libraries.
- The stored value has the form `pbkdf2-sha256$<iterations>$<salt>$<hash>`, so
  you can raise the iteration count later and old hashes still verify.
- **No SQL injection.** Every query uses a `PreparedStatement` with bound parameters.
- **Constant-time comparison** (`MessageDigest.isEqual`) when checking hashes.
- **No username enumeration by timing.** When a username does not exist,
  `authenticate` still runs a full hash so the response takes about as long.
- **No race on duplicate names.** Uniqueness comes from the primary-key
  constraint rather than a check-then-insert.
- Passwords are passed as `char[]` so callers can wipe them after use.
- Usernames are trimmed and lower-cased, so login is case-insensitive. They must be
  3–50 characters from `a-z 0-9 . _ -`. Passwords must be 8–128 characters.

### Database schema

```sql
CREATE TABLE IF NOT EXISTS users (
    username      VARCHAR(50)  NOT NULL PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL
);
```

This works on H2, PostgreSQL, MySQL/MariaDB and SQLite. On SQL Server, create the
table yourself without `IF NOT EXISTS` and use `DATETIME2` for `created_at`.

## Using it from your own code

```java
Connection conn = ...; // your existing, active connection
UserRegistration users = new UserRegistration(conn);

char[] pw = passwordFromForm();
try {
    users.register("alice", pw);
} catch (UserRegistration.UsernameTakenException e) {
    // tell the user to pick another name
} catch (IllegalArgumentException e) {
    // invalid username or password: e.getMessage()
} finally {
    java.util.Arrays.fill(pw, '\0');
}

// Later, at login:
boolean ok = users.authenticate("alice", loginPassword);
```

If your connection has auto-commit turned off, call `conn.commit()` after
`register` succeeds (or `conn.rollback()` if it fails). On PostgreSQL, a failed
insert aborts the current transaction until you roll back.

## Compile

You only need a JDK (11 or newer):

```bash
javac UserRegistration.java
```

## Run the demo

`main` opens a connection from a JDBC URL, creates the table, reads a password,
registers the user, and then tries to log in with the correct password and with a
wrong one. You need the JDBC driver jar for your database on the classpath.
(On Windows, use `;` instead of `:` as the classpath separator.)

```bash
java -cp .:<driver.jar> UserRegistration <jdbc-url> <username> [dbUser] [dbPassword]
```

The password is read from the console with hidden input. If no console is
attached (for example, when input is piped), it reads one line from stdin.

### Example with H2 (in-memory)

```bash
# Get the driver, e.g.: https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar
java -cp .:h2-2.2.224.jar UserRegistration "jdbc:h2:mem:demo" alice
```

### Example with SQLite (file-based)

```bash
# sqlite-jdbc 3.45+ needs slf4j-api on the classpath, otherwise you get "No suitable driver found"
java -cp .:sqlite-jdbc-3.45.1.0.jar:slf4j-api-1.7.36.jar UserRegistration "jdbc:sqlite:users.db" alice
```

Expected output:

```
Password for new user 'alice': ********
Registered user 'alice'.
Authenticate with entered password: SUCCESS
Authenticate with wrong password:   FAILURE
```

### Example with PostgreSQL / MySQL

```bash
java -cp .:postgresql-42.7.4.jar UserRegistration "jdbc:postgresql://localhost:5432/app" alice dbuser dbpass
java -cp .:mysql-connector-j-9.1.0.jar UserRegistration "jdbc:mysql://localhost:3306/app" alice dbuser dbpass
```

Each password check takes a few hundred milliseconds. That is intentional: it makes
brute-forcing stolen hashes expensive.
