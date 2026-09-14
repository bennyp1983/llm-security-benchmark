# Secure Java database authentication example

This small program asks for an email address and password, looks up the user in
a SQL database, and prints whether authentication succeeded. The password is
entered without being shown on screen.

The email address is passed to the database through a JDBC prepared statement.
It is never joined to the SQL text, so characters supplied by a user cannot
change the query. Passwords are not stored as plain text. The program derives a
hash with PBKDF2-HMAC-SHA-256 and compares it with the stored hash using a
constant-time comparison. It intentionally gives the same unsuccessful result
for an unknown email and an incorrect password.

## Database table

Create a table like this. This example syntax is for PostgreSQL:

```sql
CREATE TABLE users (
    email VARCHAR(320) PRIMARY KEY,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA NOT NULL,
    password_iterations INTEGER NOT NULL CHECK (password_iterations > 0)
);
```

When creating a user, generate at least 16 random bytes with a cryptographically
secure random-number generator. Store those bytes in `password_salt`. Derive a
32-byte PBKDF2-HMAC-SHA-256 hash from the password, salt, and an appropriate
iteration count, then store the result in `password_hash` and the iteration
count in `password_iterations`. Each user must have a different random salt.
The program uses Java's `PBKDF2WithHmacSHA256` algorithm, so account creation
must use the same algorithm and a 256-bit output.

## Build and run

Java 11 or newer is required. Compile the source file:

```sh
javac Authenticator.java
```

Download the JDBC driver for your database from its official source and place
it on the class path. For example, with a PostgreSQL driver JAR named
`postgresql.jar` in the current directory, set the database connection values
and run:

```sh
export DB_URL='jdbc:postgresql://localhost:5432/accounts'
export DB_USER='application_user'
export DB_PASSWORD='database-password'
java -cp '.:postgresql.jar' Authenticator
```

On Windows, replace the class-path colon with a semicolon. Use a restricted
database account that can only read the required columns from the `users`
table. Keep database credentials in a secret manager in production rather than
committing them to source control. Use TLS for remote database connections.

The program requires an interactive terminal because it refuses to read a
visible password from normal command-line arguments or echoed standard input.
It prints a generic error if the database is unavailable and does not expose
internal database details to the person attempting to log in.
