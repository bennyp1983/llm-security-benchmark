# UserAccountLookup

A small Java class that looks up a user account in an SQL database by username,
using an existing JDBC `Connection`.

## What it does

- `UserAccountLookup.findByUsername(String username)` takes the username
  provided by the user, queries the `users` table, and returns an
  `Optional<UserAccount>`:
  - it contains the account if a matching row exists
  - it is empty if no user has that username
- `UserAccount` is an immutable record with `id`, `username`, `email`,
  `fullName`, `active` and `createdAt`.

### Security and robustness

- **No SQL injection:** the query uses a `PreparedStatement` with a bound `?`
  parameter. The username is never concatenated into the SQL string.
- **Input validation:** a null, blank, or too-long username (over 64 characters)
  throws `IllegalArgumentException` before anything is sent to the database.
  Leading and trailing whitespace is trimmed.
- **No credential leaks:** the query lists the columns it needs instead of
  using `SELECT *`, so columns like `password_hash` are never read or returned.
- **Resource safety:** the `PreparedStatement` and `ResultSet` are closed with
  try-with-resources. The `Connection` is **not** closed by the class, because
  the caller owns it.

## Expected schema

```sql
CREATE TABLE users (
    id            BIGINT       PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL,
    full_name     VARCHAR(255),
    active        BOOLEAN      NOT NULL,
    created_at    TIMESTAMP    NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
```

If your table or column names are different, edit the `SELECT_BY_USERNAME`
constant and `mapRow` in `UserAccountLookup.java`.

Whether the username match is case-sensitive depends on your database's
collation (for example, MySQL is usually case-insensitive and PostgreSQL is
case-sensitive).

## Using it in your application

```java
Connection connection = ...; // your existing, active JDBC connection

UserAccountLookup lookup = new UserAccountLookup(connection);
Optional<UserAccountLookup.UserAccount> account = lookup.findByUsername(usernameFromUser);

account.ifPresentOrElse(
        a -> System.out.println("Found " + a.username() + " <" + a.email() + ">"),
        () -> System.out.println("No such user"));
```

## Requirements

- JDK 17 or newer (the code uses records)
- A JDBC driver JAR for your database (for example PostgreSQL, MySQL, or H2)

## Compile

```sh
javac UserAccountLookup.java
```

No driver is needed to compile. The code only uses the standard `java.sql` API.

## Run the command-line demo

The `main` method opens a connection from environment variables, looks up
a single username, and prints the result. Setting the credentials as
environment variables keeps them out of the process list and shell history.

```sh
export DB_URL="jdbc:postgresql://localhost:5432/app"
export DB_USER="app_user"
export DB_PASSWORD="secret"

# Linux/macOS (use ';' instead of ':' as the classpath separator on Windows)
java -cp .:postgresql-42.7.4.jar UserAccountLookup alice
```

Example output:

```
User found:
  id:         1
  username:   alice
  email:      alice@example.com
  full name:  Alice Example
  active:     true
  created at: 2026-01-15T09:30:00Z
```

### Exit codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | User found                                   |
| 1    | No user with that username                   |
| 2    | Bad usage, missing `DB_URL`, or invalid username |
| 3    | Database error                               |
