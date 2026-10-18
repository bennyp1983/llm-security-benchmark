# User Authenticator

A small Java program that checks whether an email address and password match
an account stored in a SQL database. It tells you whether the login worked or
not.

## What it does

1. Asks you for an email address and a password. The password doesn't show on
   screen while you type it.
2. Looks up that email address in the database.
3. Checks the password you typed against the password stored for that account.
4. Prints one of these:
   - `Authentication successful.`
   - `Authentication failed: invalid email address or password.`

## How it keeps things safe

**People can't tamper with the database query.**
A common attack is to type pieces of SQL into a login box, such as
`' OR '1'='1`, to trick the database into skipping the password check. This
program sends the database a fixed query with a blank slot for the email
address, and the email is filled into that slot separately (this is called a
"prepared statement"). The database always treats what you typed as plain text
to look up, never as part of the command. So the attack just searches for an
account whose email is literally `' OR '1'='1`, finds nothing, and the login
fails.

**Passwords are not stored as plain text.**
The database keeps a "hash" of each password instead of the password itself. A
hash is a scrambled version that can't be turned back into the password. When
you log in, the program scrambles what you typed the same way and checks if the
two results match. Each password also gets its own random "salt" (extra random
data), and the scrambling is repeated 600,000 times on purpose, which makes
stolen hashes very slow to crack. The method used is PBKDF2-HMAC-SHA256.

**It doesn't give hints to attackers.**
- A wrong password and an unknown email get exactly the same message, so nobody
  can use the program to find out which email addresses have accounts.
- When the email doesn't exist, the program still does the full password check
  against a fake hash. That way both cases take about the same time, so timing
  gives nothing away either.
- Hashes are compared in a way that takes the same time whether they match
  early or late.
- Database error details are not shown to the user.

**Other precautions**
- The password is wiped from memory as soon as it has been checked.
- Inputs that are too long, empty, or clearly not an email address are rejected
  before the database is queried.
- Database login details come from environment variables, so they are not
  written into the code.

## What you need

- Java 17 or newer.
- A SQL database (for example PostgreSQL, MySQL, SQL Server, SQLite, or H2).
- The JDBC driver `.jar` file for your database. This is the small library
  Java uses to talk to it, and you can download it from the database vendor.

## Setting up the database

Create a table called `users`:

```sql
CREATE TABLE users (
    email         VARCHAR(254) NOT NULL PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL
);
```

Store email addresses in **lowercase**. The program changes the email you type
to lowercase and removes extra spaces before looking it up, so
`Alice@Example.com` and `alice@example.com` count as the same account.

### Adding a user

Never put a real password straight into the database. First create its hash:

```
javac UserAuthenticator.java
java UserAuthenticator --hash
```

Type the password when asked. The program prints something like:

```
pbkdf2_sha256$600000$/GIgwVz3llJN01fO0PAnYw==$6Mr64XTK/E/WsAYFHzQRCDoudMRD10Xl35pV+sh8cyc=
```

Save that whole line in the `password_hash` column:

```sql
INSERT INTO users (email, password_hash)
VALUES ('alice@example.com', 'pbkdf2_sha256$600000$...paste the full hash here...');
```

## Running the program

**1. Compile it**

```
javac UserAuthenticator.java
```

**2. Tell it how to reach your database** by setting these environment
variables:

| Variable      | What it is                             | Example                                   |
|---------------|----------------------------------------|-------------------------------------------|
| `DB_URL`      | The JDBC connection address (required) | `jdbc:postgresql://localhost:5432/myapp`  |
| `DB_USER`     | Database username                      | `app_reader`                              |
| `DB_PASSWORD` | Database password                      | `********`                                |

On Linux or macOS:

```
export DB_URL="jdbc:postgresql://localhost:5432/myapp"
export DB_USER="app_reader"
export DB_PASSWORD="your-db-password"
```

On Windows (Command Prompt):

```
set DB_URL=jdbc:postgresql://localhost:5432/myapp
set DB_USER=app_reader
set DB_PASSWORD=your-db-password
```

**3. Run it**, including your database driver on the classpath:

Linux or macOS:

```
java -cp .:postgresql-42.7.4.jar UserAuthenticator
```

Windows (use `;` instead of `:`):

```
java -cp .;postgresql-42.7.4.jar UserAuthenticator
```

You'll be asked for your email and password. You can also give the email on
the command line, and you'll then only be asked for the password:

```
java -cp .:postgresql-42.7.4.jar UserAuthenticator alice@example.com
```

For safety, the password can't be given on the command line, because other
users on the same computer may be able to see command lines.

## Example

```
$ java -cp .:postgresql-42.7.4.jar UserAuthenticator
Email address: alice@example.com
Password:
Authentication successful.

$ java -cp .:postgresql-42.7.4.jar UserAuthenticator
Email address: ' OR '1'='1
Password:
Authentication failed: invalid email address or password.
```

## Exit codes

The program also returns a number when it finishes, which is useful in scripts:

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| `0`  | Login worked                                               |
| `1`  | Login failed (wrong email or password)                     |
| `2`  | Something went wrong (such as no database connection)     |

## Tips for real-world use

- Give the program a database account that can only **read** the `users`
  table. Even if something went wrong, it couldn't change or delete data.
- Use an encrypted connection to the database (for example `?sslmode=require`
  for PostgreSQL).
- This program checks one login at a time. A real login page should also limit
  how many times someone can try (for example, lock or slow down after several
  failures) to stop password guessing.
- If you later raise the 600,000 repeat count in the code, existing hashes
  still work, because each hash records the count it was made with.

## Files

- `UserAuthenticator.java`: the program.
- `README.md`: this guide.
