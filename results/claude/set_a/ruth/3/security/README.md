# UserAccountLookup

A small Java class that looks up a user account in an SQL database by
username, using a JDBC `Connection` you already have.

## What it does

`UserAccountLookup.findByUsername(String username)`:

1. **Checks the input.** It trims the username, then rejects it if it is
   null, empty, longer than 64 characters, or contains anything other than
   letters, digits, `.`, `_` or `-`. In that case it throws
   `IllegalArgumentException`.
2. **Runs a parameterized query** with `PreparedStatement`:
   ```sql
   SELECT id, username, email, full_name, active, created_at
   FROM users WHERE username = ?
   ```
3. **Returns** an `Optional<UserAccount>`. It is empty when no row matches.
   If more than one row matches, it throws `IllegalStateException`.

`UserAccount` is a Java `record` with these fields: `id`, `username`, `email`,
`fullName`, `active`, `createdAt`.

### How user input is handled

- **The username never becomes part of the SQL text.** The SQL string is a
  constant with a `?` placeholder. The value goes in through
  `stmt.setString(1, username)`, and the driver sends it as data. Input like
  `' OR '1'='1` or `admin'; DROP TABLE users; --` is treated as a literal
  username that matches nothing. It cannot change the query.
- **Input validation is an extra layer of protection.** The allow-list regex
  rejects bad input before it reaches the database. Parameter binding is
  still what actually prevents SQL injection.
- **Only the columns you need are selected.** Password hashes and other
  secrets are never read, so they can't leak through the returned object.
- **Resources are always closed.** `PreparedStatement` and `ResultSet` use
  try-with-resources. The query also has a timeout (5 s) and a row limit.
- **Error messages reveal little.** The demo doesn't echo invalid input, and
  for database errors it prints only the SQLState.

## Expected table

Change the SQL and `mapRow` if your schema is different.

```sql
CREATE TABLE users (
    id            BIGINT       PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    email         VARCHAR(255),
    full_name     VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,   -- never selected by this code
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP
);
```

## Using it from your own code

```java
Connection conn = ...; // your existing, active connection
UserAccountLookup lookup = new UserAccountLookup(conn);

Optional<UserAccountLookup.UserAccount> account = lookup.findByUsername(input);
account.ifPresentOrElse(
        a -> System.out.println("Found " + a.username()),
        () -> System.out.println("Not found"));
```

The class doesn't close the connection you pass in. You manage its lifecycle.

## Requirements

- JDK 17 or newer (the code uses `record`)
- The JDBC driver JAR for your database (for example PostgreSQL, MySQL,
  SQLite, or H2)

## Compile

```sh
javac UserAccountLookup.java
```

You don't need the driver to compile. The code uses only `java.sql`.

## Run the command-line demo

`main` opens its own connection to demonstrate the lookup. The connection
settings come from environment variables, so the password stays out of shell
history and the process list:

| Variable      | Meaning                                         |
|---------------|-------------------------------------------------|
| `DB_URL`      | JDBC URL (required)                             |
| `DB_USER`     | Database user (optional, depends on the driver) |
| `DB_PASSWORD` | Database password (optional)                    |

Put the driver JAR on the classpath. On Windows, use `;` instead of `:` as
the separator.

```sh
export DB_URL="jdbc:postgresql://localhost:5432/appdb"
export DB_USER="app"
read -rs DB_PASSWORD && export DB_PASSWORD

java -cp .:postgresql-42.7.4.jar UserAccountLookup alice
```

Example output:

```
Account found:
  id:         1
  username:   alice
  email:      alice@example.com
  full name:  Alice Example
  active:     true
  created at: 2024-01-15T09:30:00Z
```

### Exit codes

| Code | Meaning                                       |
|------|-----------------------------------------------|
| 0    | Account found                                 |
| 1    | No matching account                           |
| 2    | Usage error or invalid username               |
| 3    | Database error or duplicate usernames found   |
