# Java Authentication Example

`AuthenticationApp.java` is a dependency-free command-line authentication
application. It:

- prompts for a username and password;
- verifies the password against a salted PBKDF2-HMAC-SHA256 hash;
- performs a password-hash operation even when the username is unknown;
- reports successful and unsuccessful logins without revealing which field was
  incorrect; and
- appends timestamped outcomes to `application-auth.log` without logging the
  submitted password.

The application creates `users.properties` on its first run. This file contains
a demonstration account stored as a salted hash:

```text
username: demo
password: changeMe123!
```

The demonstration password is intentionally public and must be replaced before
using this code in a real application. Restrict filesystem access to both
`users.properties` and `application-auth.log` in a deployed environment.

## Requirements

- JDK 17 or newer (the implementation uses a Java record and `Path.of`)

Confirm Java is installed:

```sh
java -version
javac -version
```

## Compile and run

From this directory, compile the source:

```sh
javac AuthenticationApp.java
```

Run the application:

```sh
java AuthenticationApp
```

Enter `demo` and `changeMe123!` to exercise the successful path. Enter an
incorrect username or password to exercise the unsuccessful path.

When run in a normal terminal, the password is hidden. Some IDE consoles and
redirected-input environments cannot hide it; the application prints a warning
in that case.

## Generated files

- `users.properties` stores one property per account. Each value has the form
  `iterations:base64-salt:base64-hash`.
- `application-auth.log` records the time, outcome, and sanitized username for
  every completed login attempt. It never records passwords.

Both paths are relative to the directory from which the application is run.
Delete the generated files if you want to reset this demonstration. A production
application should provide a separate administrative enrollment/password-change
workflow, use strict file permissions or a database/identity provider, rate-limit
attempts, and replace the bundled demonstration account.

## Quick non-interactive check

For a local test (where visible password input is acceptable):

```sh
printf 'demo\nchangeMe123!\n' | java AuthenticationApp
printf 'demo\nwrong-password\n' | java AuthenticationApp
cat application-auth.log
```
