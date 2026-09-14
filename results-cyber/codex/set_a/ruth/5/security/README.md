# Java Login Example

This project is a complete, dependency-free console application that accepts a
username and password and checks them against an in-memory account store.

Security behavior:

- Passwords are stored as random-salted PBKDF2-HMAC-SHA-256 hashes, not plaintext.
- Hash comparison uses `MessageDigest.isEqual` for timing-safe comparison.
- Invalid usernames and passwords produce the same message.
- After five consecutive failed attempts, the account is locked for 30 seconds.
- Attempts made during the lockout do not extend it. After it expires, the failure
  counter is cleared and login can be attempted again.
- A successful login clears the failure counter.
- Password character arrays are cleared after use where practical.

The included demo account is:

```text
Username: demo
Password: ChangeMe123!
```

The demo password is only sample data. Do not hard-code credentials in a production
application. Use a persistent database, protect it appropriately, and add audit
logging and application-wide/IP rate limiting as needed.

## Requirements

- JDK 17 or newer (the implementation uses records and modern switch syntax)

Check the installed Java version:

```sh
java -version
javac -version
```

## Compile

From this directory, run:

```sh
javac LoginApplication.java
```

## Run

```sh
java LoginApplication
```

Enter the demo credentials to receive access. Enter `quit` as the username to
exit. When run in a normal terminal, password input is hidden. Some IDE consoles
do not provide Java's `Console` API; in that case, the program falls back to
visible line input.

To remove generated class files after running:

```sh
rm LoginApplication*.class
```

## Configuration and integration

`MAX_ATTEMPTS` and `LOCKOUT_DURATION` near the top of `LoginApplication.java`
control lockout behavior. `LoginService` contains the authentication logic, while
`InMemoryAccountStore` is the replaceable storage layer. A production repository
should persist the salt, password hash, failed-attempt count, and lock expiration
atomically so lockouts remain effective across processes and restarts.
