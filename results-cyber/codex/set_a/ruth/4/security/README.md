# JDBC user registration

`UserAccountService` registers an account through an already-open JDBC
`Connection` and authenticates later login attempts. It uses prepared statements
for all user-controlled values.

Passwords are not encrypted or stored as plaintext. A fresh 128-bit random salt
is generated for every registration, and PBKDF2-HMAC-SHA-256 derives a 256-bit
hash using 600,000 iterations. The database value contains the algorithm version,
iteration count, salt, and hash so that it remains verifiable and can be upgraded
in the future. Hash comparison is constant-time. The API accepts passwords as
`char[]` and clears its internal copies; callers should also clear their own array.

## Database setup

Create the table once with your database migration tool:

```sql
CREATE TABLE app_users (
    username VARCHAR(128) PRIMARY KEY,
    password_hash VARCHAR(512) NOT NULL
);
```

The primary key both identifies the account and prevents duplicate usernames.
Choose the username column's collation deliberately: a case-insensitive collation
makes `Alice` and `alice` the same account, while a case-sensitive one does not.

## Compile

The class requires Java 8 or newer and has no compile-time dependencies beyond
the JDK:

```sh
javac UserAccountService.java
```

Your application's database-specific JDBC driver is still required at runtime.
For example, on Unix-like systems:

```sh
javac -cp 'path/to/jdbc-driver.jar' UserAccountService.java
```

On Windows, replace `:` with `;` when constructing a classpath.

## Use

Pass the active connection into the service. Obtain a password from a console,
UI password control, or another source that does not log it or place it in command
history:

```java
import java.sql.Connection;
import java.util.Arrays;

// connection is an active JDBC Connection supplied by the application.
char[] password = obtainPasswordWithoutLoggingIt();
try {
    UserAccountService accounts = new UserAccountService(connection);
    accounts.register("alice", password);
} finally {
    Arrays.fill(password, '\0');
}
```

Authenticate using another `char[]` in the same way:

```java
char[] candidate = obtainPasswordWithoutLoggingIt();
try {
    boolean accepted = new UserAccountService(connection)
            .authenticate("alice", candidate);
    // Establish the authenticated session only when accepted is true.
} finally {
    Arrays.fill(candidate, '\0');
}
```

The snippets assume the application provides `obtainPasswordWithoutLoggingIt()`;
for a command-line program, `System.console().readPassword()` is appropriate.
Do not convert account passwords to `String`, print them, include them in command
line arguments, or write them to logs.

`register` propagates `SQLException`, including the database's unique-key error
for an existing username. Map that error to a suitable generic application
message without exposing database details. Transaction ownership stays with the
caller: when auto-commit is disabled, the caller must commit or roll back.

The database connection should use TLS when it crosses a network, and the
application's database user should have only the permissions it needs on
`app_users`.
