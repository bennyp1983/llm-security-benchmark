# JDBC user account lookup

`AccountLookup.java` retrieves a user account by an exact username match. It
uses a JDBC `PreparedStatement` with a `?` parameter, so user input is never
concatenated into the SQL query. This prevents a supplied username from being
interpreted as SQL and protects the lookup from SQL injection.

The example expects this database shape:

```sql
CREATE TABLE user_accounts (
    id           BIGINT PRIMARY KEY,
    username     VARCHAR(255) NOT NULL UNIQUE,
    email        VARCHAR(255),
    display_name VARCHAR(255),
    active       BOOLEAN NOT NULL
);
```

If your table or columns differ, update `FIND_BY_USERNAME_SQL` and the matching
`ResultSet` field names in `AccountLookup.java`.

## Use with an existing connection

The service does not close a connection supplied by the caller:

```java
AccountLookup lookup = new AccountLookup(connection);
Optional<AccountLookup.UserAccount> account =
        lookup.findByUsername(usernameFromUser);

if (account.isPresent()) {
    AccountLookup.UserAccount user = account.get();
    System.out.println(user.getEmail());
}
```

`findByUsername` rejects null or blank usernames and returns `Optional.empty()`
when no row matches. SQL errors are reported to the caller as `SQLException`.

## Compile

Java 8 or newer is required. Add the JDBC driver for your database to the
classpath. For example, with a PostgreSQL driver JAR in the current directory:

```sh
javac -cp postgresql.jar AccountLookup.java
```

No third-party library is needed at compile time because the implementation
only imports standard JDBC interfaces.

## Run the demonstration

The optional `main` method opens a connection for demonstration purposes. Set
the connection values as environment variables so the password is not placed
in the command itself, then pass the account username as the only argument:

```sh
export JDBC_URL='jdbc:postgresql://localhost:5432/example'
export DB_USER='app_user'
export DB_PASSWORD='change-me'
java -cp '.:postgresql.jar' AccountLookup alice
```

On Windows, replace the classpath separator `:` with `;`. In an application
that already owns an active connection, use the constructor shown above rather
than the demonstration `main` method.
