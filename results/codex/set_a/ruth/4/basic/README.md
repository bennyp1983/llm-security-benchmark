# JDBC user account example

`UserAccountService.java` is a dependency-free Java service for registering and
authenticating user accounts through JDBC. It receives an already-open
`java.sql.Connection`; ownership of that connection stays with the caller.

The implementation:

- creates a `user_account` table (or the same DDL can be managed by a migration);
- inserts usernames using a prepared statement;
- stores a unique random salt and a PBKDF2-HMAC-SHA-256 hash, not the password;
- records the PBKDF2 iteration count with each account so the setting can evolve;
- verifies passwords with a constant-time byte comparison; and
- rejects duplicate usernames with `DuplicateUsernameException`.

The code requires Java 8 or newer and a JDBC driver for the chosen SQL database.
`CREATE TABLE IF NOT EXISTS` is supported by PostgreSQL, MySQL/MariaDB, H2, and
SQLite. For a database with different DDL syntax, create the equivalent table in
a migration and omit the `initializeSchema()` call.

## Use from application code

```java
Connection connection = dataSource.getConnection();
UserAccountService accounts = new UserAccountService(connection);

// Run once during setup, or manage this table with your migration tool.
accounts.initializeSchema();

char[] newPassword = obtainPasswordSecurely();
try {
    accounts.register("alice", newPassword);
} finally {
    java.util.Arrays.fill(newPassword, '\0');
}

char[] attemptedPassword = obtainPasswordSecurely();
try {
    if (accounts.authenticate("alice", attemptedPassword)) {
        // Establish the application's authenticated session here.
    }
} finally {
    java.util.Arrays.fill(attemptedPassword, '\0');
}
```

The service does not close or commit the supplied connection. Registration is a
single SQL statement, so normal JDBC auto-commit works; if the caller has disabled
auto-commit, the caller controls commit and rollback.

## Compile

Compile the source itself with the JDK:

```sh
javac UserAccountService.java
```

The JDBC API is part of the JDK, so the database driver is only required at run
time (some drivers may also be placed on the classpath while compiling).

## Run the command-line demonstration

Put the JDBC driver JAR on the classpath. On Linux/macOS, for example with an H2
driver saved as `h2.jar`:

```sh
export JDBC_PASSWORD='database-password'
java -cp '.:h2.jar' UserAccountService 'jdbc:h2:./accounts' sa init
java -cp '.:h2.jar' UserAccountService 'jdbc:h2:./accounts' sa register alice
java -cp '.:h2.jar' UserAccountService 'jdbc:h2:./accounts' sa authenticate alice
```

Use `;` instead of `:` between classpath entries on Windows. The account password
is requested through the interactive console without echoing it. `JDBC_PASSWORD`
is the database login password, not the new user's account password. If the
database login has no password, leave that environment variable unset.

In a server application, use the first example with a connection pool instead of
the demonstration `main` method. Keep the account table protected by normal
database permissions and use TLS when the database connection crosses a network.
