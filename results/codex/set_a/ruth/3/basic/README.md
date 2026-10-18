# JDBC user account lookup

`UserAccountLookup` retrieves one user account by username from an SQL database.
The reusable API accepts an active JDBC `Connection`, binds the username through
a `PreparedStatement`, and returns `Optional<UserAccount>`. It leaves connection
ownership with the caller, while closing its own statement and result set.

## Expected database table

The example expects this shape (adjust the SQL and field mapping if your schema
uses different names or types):

```sql
CREATE TABLE users (
    id         BIGINT PRIMARY KEY,
    username   VARCHAR(255) NOT NULL UNIQUE,
    email      VARCHAR(255),
    full_name  VARCHAR(255),
    created_at TIMESTAMP
);
```

## Use with an existing connection

```java
Optional<UserAccountLookup.UserAccount> account =
        UserAccountLookup.findByUsername(connection, usernameFromUser);

if (account.isPresent()) {
    System.out.println(account.get().getEmail());
} else {
    System.out.println("Account not found");
}
```

The method throws `SQLException` for database errors and
`IllegalArgumentException` for a blank username. It deliberately does not close
or commit the supplied connection. The prepared statement prevents the username
from being interpreted as SQL.

## Compile

Java 8 or newer is sufficient. Compile the source into an output directory:

```sh
mkdir -p out
javac -d out src/UserAccountLookup.java
```

The JDBC interfaces are part of Java. To run the command-line demonstration, a
JDBC driver for the chosen database must also be downloaded and placed on the
runtime classpath. For example, if the driver JAR is at `lib/database-driver.jar`:

```sh
export JDBC_URL='jdbc:postgresql://localhost:5432/example'
export JDBC_USER='app_user'
export JDBC_PASSWORD='change-me'

java -cp 'out:lib/database-driver.jar' UserAccountLookup alice
```

On Windows, replace the classpath separator `:` with `;`. If no username argument
is supplied, the program prompts for one:

```sh
java -cp 'out:lib/database-driver.jar' UserAccountLookup
```

The standalone command owns and closes the connection it creates. Applications
that already have an active connection should call `findByUsername` directly as
shown above.
