# User Authenticator

## What this program does

This is a small Java program that checks whether someone can log in.

You give it an email address and a password. It looks up that email address
in a database and checks whether the password is correct. It then tells you
one of two things:

- **"Authentication successful"**: the email exists and the password is right.
- **"Authentication failed"**: the email does not exist, or the password is wrong.

On purpose, the program does not say *which* of the two was wrong. If it did,
someone could use it to find out which email addresses have accounts.

## What's in this folder

| File | What it is |
|------|------------|
| `UserAuthenticator.java` | The program itself. |
| `schema.sql` | The layout of the database table. You don't need to run it; the program creates the table for you. |
| `lib/` | The database driver the program needs to talk to SQLite, plus two small logging libraries the driver depends on. |
| `README.md` | This file. |

## What you need

- Java 17 or newer. Check by running `java -version`.
- Nothing else. The program uses SQLite by default, which saves the database
  as a single file called `users.db` in this folder. The driver is already in `lib/`.

## Step 1: Compile the program

Open a terminal in this folder and run:

```
javac UserAuthenticator.java
```

This creates `UserAuthenticator.class`, which is the version Java can run.

## Step 2: Add a user

The database starts out empty, so add at least one user first:

```
java -cp ".:lib/*" UserAuthenticator add-user
```

The program asks for an email address and a password. Your password is hidden
while you type it. You'll see:

```
User alice@example.com created.
```

If you run `add-user` again with an email that already exists, that user's
password is replaced with the new one.

> **Windows users:** use a semicolon instead of a colon in the classpath:
> `java -cp ".;lib/*" UserAuthenticator add-user`

## Step 3: Log in

```
java -cp ".:lib/*" UserAuthenticator
```

Type the email address and password when asked.

If they are correct:

```
Authentication successful. Welcome, alice@example.com!
```

If they are not:

```
Authentication failed: invalid email address or password.
```

You can also put the email address on the command line so only the password
is asked for:

```
java -cp ".:lib/*" UserAuthenticator login alice@example.com
```

The password can't be given on the command line. Other people on the same
computer can see command lines, so the password is always typed at the prompt.

## Using it from a script

When the program finishes, it returns a number (the "exit code") that scripts
can check:

| Exit code | Meaning |
|-----------|---------|
| `0` | Login succeeded (or, for `add-user`, the user was saved). |
| `1` | Login failed: wrong email or password. |
| `2` | Something else went wrong: bad input, bad command, or a database problem. |

If input is piped in instead of typed, the program reads the email from the
first line and the password from the second line.

## Using a different database

SQLite is the default, but the program works with any SQL database that has a
Java (JDBC) driver, such as MySQL, PostgreSQL, or SQL Server. Tell it where
the database is with these environment variables:

| Variable | What it's for | Example |
|----------|---------------|---------|
| `DB_URL` | Where the database is | `jdbc:postgresql://localhost:5432/myapp` |
| `DB_USER` | Database username | `app_user` |
| `DB_PASSWORD` | Database password | `...` |

For example, on Linux or macOS:

```
export DB_URL="jdbc:postgresql://localhost:5432/myapp"
export DB_USER="app_user"
export DB_PASSWORD="your-db-password"
java -cp ".:lib/*:/path/to/postgresql-driver.jar" UserAuthenticator
```

Download the driver `.jar` file for your database and add it to the
classpath, as shown above.

## How passwords are kept safe

- **Passwords are never saved as they are typed.** The program saves a
  scrambled version called a *hash*. A hash can't be turned back into the
  password. To check a login, the program hashes what you typed and compares
  it with the saved hash.
- **Every user gets their own random "salt".** Two people with the same
  password end up with different hashes. This also stops attackers from using
  pre-built lists of common password hashes.
- **Hashing is deliberately slow** (600,000 rounds of PBKDF2-HMAC-SHA256).
  You won't notice it for one login, but it makes guessing millions of
  passwords very expensive for an attacker who steals the database.
- **The database can't be tricked with typed input.** Emails are passed to
  the database as data, never pasted into the SQL command, so input like
  `' OR '1'='1` does nothing. This protects against "SQL injection".
- **Unknown emails take as long to reject as wrong passwords.** An attacker
  can't tell whether an account exists by timing the response.
- **Email addresses aren't case-sensitive.** `Alice@Example.com` and
  `alice@example.com` are the same account.

## The database table

The program creates this table the first time it runs:

| Column | What it holds |
|--------|---------------|
| `email` | The user's email address, in lower case. Each email appears only once. |
| `password_hash` | The scrambled password. |
| `salt` | The random value used when scrambling that user's password. |
| `iterations` | How many hashing rounds were used, so this can be raised later without breaking old accounts. |

Always add users with `add-user`. If you type rows into the table by hand,
the hashes won't match and those users won't be able to log in.

## Common problems

**"No suitable driver found"**
Java can't find the database driver. Make sure `lib/*` (or your own driver
`.jar`) is in the `-cp` part of the command, and that you run the command
from this folder.

**"Error: please enter a valid email address."**
The email must have one `@` with text on both sides and no spaces.

**Login always fails**
Check that you added the user with `add-user` and that you are using the same
database. If `DB_URL` isn't set, the program uses `users.db` in the folder
you ran the command from.
