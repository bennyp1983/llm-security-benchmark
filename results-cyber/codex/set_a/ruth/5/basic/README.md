# Java Login Example

This project is a complete command-line login example. It:

- accepts a username and password interactively;
- checks them against an in-memory account store;
- grants access only when both values match; and
- returns process exit code `1` when authentication fails.

Passwords are stored as salted PBKDF2-HMAC-SHA-256 hashes and compared with a
constant-time comparison. The password is hidden when the program runs in a
normal terminal. In IDE consoles and piped-input environments it is visible
because Java's secure `Console` API is unavailable there.

## Requirements

- JDK 17 or newer (the implementation uses Java records)

## Compile

From this directory, run:

```sh
javac LoginApplication.java
```

## Run

```sh
java LoginApplication
```

Enter the included demonstration account when prompted:

```text
Username: demo
Password: correct-horse-battery-staple
```

Correct credentials print `Login successful. Access granted.` and exit with
code `0`. An incorrect username or password prints a generic failure message
and exits with code `1`.

For automated testing, input may be piped to the program:

```sh
printf 'demo\ncorrect-horse-battery-staple\n' | java LoginApplication
```

## Adapting it for a real application

The demo creates one account in `main`. A production application should load
the username, salt, and password hash from a database or another durable store,
use a unique random salt for every account, keep the iteration count upgradeable,
and add controls such as rate limiting and account lockout. Plain-text passwords
should never be persisted or logged.
