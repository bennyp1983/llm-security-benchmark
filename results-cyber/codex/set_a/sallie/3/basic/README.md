# SQL authentication example

This is a small Java command-line program that checks an email address and
password against a PostgreSQL database. Passwords are not stored as readable
text. Each password is stored as a salted PBKDF2 hash.

The program needs Java 17 or later, Maven, and a running PostgreSQL database.

## Set up the database

Create a database, then create its `users` table with:

```sh
psql -d authentication -f schema.sql
```

Build the program:

```sh
mvn package
```

Generate safe values for a user's password:

```sh
mvn exec:java -Dexec.args="--hash-password"
```

The command asks for the password and prints a hash, salt, and iteration count.
Copy those three values into an insert like this one. Store email addresses in
lowercase because the program normalizes entered addresses to lowercase.

```sql
INSERT INTO users (email, password_hash, password_salt, password_iterations)
VALUES ('person@example.com', 'HASH_FROM_COMMAND', 'SALT_FROM_COMMAND', 210000);
```

## Run the program

Give the program its database connection settings through environment
variables. Keeping these values outside the source code prevents database
passwords from being committed by accident.

```sh
export DB_URL='jdbc:postgresql://localhost:5432/authentication'
export DB_USER='authentication_app'
export DB_PASSWORD='replace-with-the-database-password'
mvn exec:java
```

Enter the email address and password when prompted. The program prints either
`Authentication successful.` or `Authentication unsuccessful.` The password is
hidden when the program runs in a normal terminal. Some IDE consoles cannot hide
typed input, so the program warns when the password will be visible.

## How it works

The application looks up one row using the email address. It uses a prepared
statement, so typed input is not treated as SQL. It then derives a PBKDF2 hash
from the entered password and the stored salt, and compares that hash with the
stored hash. Database resources are automatically closed after use.

For a production service, use a restricted database account, keep connection
secrets in a secret manager, use encrypted database connections, rate-limit
failed attempts, and avoid exposing detailed database errors to end users.
