# LoginSystem: User Login Handling in Java

`LoginSystem.java` handles login attempts for an application. It takes a
username and password, checks them against stored account information, and
grants access only when both are correct. Any other attempt fails.

It uses only the Java standard library (no external dependencies) and needs
**Java 11 or newer**. It has been tested on OpenJDK 17.

## What the code does

| Component | Purpose |
|---|---|
| `LoginSystem.login(username, password)` | Handles a login attempt and returns `SUCCESS`, `INVALID_CREDENTIALS`, or `ACCOUNT_LOCKED`. |
| `LoginSystem.registerUser(username, password)` | Creates an account and stores a salted hash of the password. |
| `PasswordHasher` | Hashes passwords with PBKDF2-HMAC-SHA256 (210,000 iterations, 16-byte random salt) and compares hashes in constant time. |
| `Account` | Stored account data: username, salt, password hash, count of failed attempts, and lock expiry. |
| `AccountRepository` / `InMemoryAccountRepository` | Storage interface plus a thread-safe in-memory version. You can swap in a database-backed version. |
| `main` | Interactive command-line demo, plus a `--self-test` mode. |

### How a login attempt is checked

1. The username is trimmed and lower-cased, so usernames are case-insensitive.
   Passwords stay case-sensitive.
2. The account is looked up in the repository.
3. If the account doesn't exist or the input is invalid, the code still hashes
   against a dummy value, then returns `INVALID_CREDENTIALS`. Because both
   paths take the same time, an attacker can't use timing to find out which
   usernames exist.
4. If the account is locked, the result is `ACCOUNT_LOCKED`.
5. Otherwise the submitted password is hashed with the account's salt and
   compared to the stored hash in constant time.
   - **Match:** the failure counter resets and the result is `SUCCESS`.
   - **No match:** the failure counter goes up. After 5 failures in a row, the
     account is locked for 15 minutes. The result is `INVALID_CREDENTIALS`.

### Security measures

- Passwords are never stored in plain text. Only a salt and a PBKDF2 hash are kept.
- Hashes are compared in constant time with `MessageDigest.isEqual`.
- Failed logins always give the same message, so the response never says
  whether the username or the password was wrong.
- Repeated failures lock the account, which blocks brute-force guessing.
- Passwords are passed as `char[]` and wiped after use. The demo reads the
  password through `Console.readPassword`, so it isn't shown on screen.
- Username and password lengths are capped, so very long inputs can't be used
  to overload the hashing step.

## Compile

From the directory containing `LoginSystem.java`:

```bash
javac LoginSystem.java
```

## Run

### Interactive demo

```bash
java LoginSystem
```

The demo creates one sample account:

- username: `alice`
- password: `CorrectHorse42!`

Example session:

```
Demo account created: username 'alice', password 'CorrectHorse42!'
Type an empty username to quit.
Username: alice
Password:
Login successful. Access granted.
Username: alice
Password:
Login failed: invalid username or password.
Username:
Goodbye.
```

To exit, press Enter at the username prompt without typing anything.

### Built-in self-test

```bash
java LoginSystem --self-test
```

This checks that correct credentials succeed, and that wrong passwords, unknown
users, and empty input fail. It also checks case handling, duplicate
registration, password wiping, lockout, and unlocking. The exit code is `0`
when every check passes.

## Using it in your application

```java
LoginSystem auth = new LoginSystem(new LoginSystem.InMemoryAccountRepository());
auth.registerUser("alice", "CorrectHorse42!".toCharArray());

LoginSystem.LoginResult result = auth.login(submittedUsername, submittedPasswordChars);
if (result == LoginSystem.LoginResult.SUCCESS) {
    // grant access / create session
} else {
    // deny access
}
```

Notes for production use:

- **Persistent storage:** `InMemoryAccountRepository` loses all accounts when
  the program exits. Implement `AccountRepository` against a database, and
  store the salt, hash, failure count, and lock expiry.
- **Clustered deployments:** lockout state is kept per `Account` object. If you
  run several servers, keep that state in the shared store.
- **Transport:** send credentials only over TLS (HTTPS).
