# User Authentication (Java)

`AuthenticationApp.java` is a self-contained user authentication component with a small
command-line front end. It:

- takes a **username and password**,
- checks them against **stored account information** (`data/users.db`),
- writes every authentication event to an **application log** (`logs/auth0.log`),
- handles **successful and failed** logins, including account lockout after repeated failures.

It needs only the JDK (Java 17 or newer). There are no third-party dependencies.

## Components

All of these classes are in the single source file.

| Class | Responsibility |
|---|---|
| `AuthenticationApp` | CLI entry point: `adduser`, `login`, `enable`, `disable` |
| `AuthenticationService` | Verifies credentials, enforces lockout, writes audit events |
| `AuthResult` | Result of an attempt: `SUCCESS`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `ACCOUNT_DISABLED`, `SYSTEM_ERROR` |
| `UserAccount` | Stored record: username, password hash, enabled flag, failure count, lock expiry |
| `FileCredentialStore` | Loads accounts and saves them to a flat file, replacing the whole file in one step on each change |
| `PasswordHasher` | PBKDF2-HMAC-SHA256 hashing and verification |
| `UsernamePolicy` | Username validation and case normalization |
| `LogSanitizer` | Escapes untrusted values before they reach the log |
| `AuditLog` | Sets up the rotating log file (`java.util.logging`) |
| `Terminal` | Reads input; passwords are not echoed when a console is present |

## Security measures

- **Passwords are never stored or logged.** Only a salted hash is stored:
  PBKDF2-HMAC-SHA256, 600,000 iterations, a random 16-byte salt per password, 256-bit output.
- **Constant-time comparison** of hashes (`MessageDigest.isEqual`).
- **No username enumeration.**
  - The user sees the same message for an unknown user, a wrong password, a locked account
    and a disabled account.
  - For unknown users the code still checks the password against a dummy hash, so response
    time doesn't reveal whether an account exists. Locked and disabled accounts also get a
    full hash check.
- **Account lockout.**
  - 5 failed attempts in a row lock the account for 15 minutes.
  - The failure count and lock expiry are saved in `users.db`, so restarting the program
    doesn't reset them.
  - During a lockout, even the correct password is rejected.
  - A successful login resets the count.
- **Fail closed.** If the lockout state can't be written to disk, the login is refused
  (`SYSTEM_ERROR`) and a `SEVERE` event is logged.
- **Log injection protection.**
  - Untrusted values (usernames, source) are quoted.
  - Control characters, spaces and Unicode line/format characters are escaped.
  - Values are truncated to 128 characters.
  - As a result, an attacker can't forge extra log lines or fields.
- **Input limits.**
  - Usernames: 3–64 characters from `[A-Za-z0-9._@-]`. Case doesn't matter.
  - Passwords: at least 12 characters (enforced on `adduser`) and at most 1024 characters.
- **File protection.**
  - On POSIX systems, the `data/` and `logs/` directories are created with owner-only
    permissions (`rwx------`), and `users.db` is written with `rw-------`.
  - Password `char[]` buffers are wiped after use.

## Compile

```sh
javac -d out AuthenticationApp.java
```

## Run

```sh
# Create an account (or reset its password). You are prompted for the password twice.
java -cp out AuthenticationApp adduser alice

# Log in. Prompts for username and password; up to 3 attempts per run.
java -cp out AuthenticationApp login
java -cp out AuthenticationApp login alice     # username given on the command line

# Account administration
java -cp out AuthenticationApp disable alice
java -cp out AuthenticationApp enable alice    # also clears any active lockout
```

You can also skip compiling and run the source file directly:
`java AuthenticationApp.java login`.

Exit codes: `0` success, `1` authentication or operation failed, `2` usage error.

Optional system properties:

| Property | Default | Meaning |
|---|---|---|
| `-Dauth.dataDir=<dir>` | `data` | Directory that holds `users.db` |
| `-Dauth.logDir=<dir>` | `logs` | Directory that holds `auth0.log` … `auth4.log` |

Example: `java -Dauth.dataDir=/var/lib/myapp -Dauth.logDir=/var/log/myapp -cp out AuthenticationApp login`

Passwords are read through `System.console()` so they aren't echoed. If there is no console
(for example, when input is piped in scripts or tests), the program prints a warning and reads
the password from standard input instead:

```sh
printf 'alice\nCorrect-Horse-Battery\n' | java -cp out AuthenticationApp login
```

## Stored account format (`data/users.db`)

```
# username:enabled:failedAttempts:lockedUntilEpochSeconds:passwordHash
alice:true:0:0:pbkdf2-sha256$600000$<base64 salt>$<base64 hash>
```

Lines that are malformed are skipped, and a `STORE_WARNING` is logged. The line's contents are
not logged.

## Log format (`logs/auth0.log`)

Each event is one line: an ISO-8601 UTC timestamp, the level, then `key=value` fields.

```
2026-09-11T15:08:16.304122880Z INFO    event=ACCOUNT_CREATED user="alice"
2026-09-11T15:08:18.435589685Z INFO    event=AUTH_SUCCESS user="alice" source="cli(osUser=root)"
2026-09-11T15:08:20.535750115Z WARNING event=AUTH_FAILURE user="mallory" source="cli(osUser=root)" reason=UNKNOWN_USER
2026-09-11T15:08:28.634244115Z WARNING event=AUTH_FAILURE user="alice" source="cli(osUser=root)" reason=BAD_PASSWORD failedAttempts=5/5
2026-09-11T15:08:28.634773996Z WARNING event=ACCOUNT_LOCKED user="alice" lockedUntil=2026-09-11T15:23:28.632830954Z
2026-09-11T15:08:30.730785795Z WARNING event=AUTH_FAILURE user="alice" source="cli(osUser=root)" reason=ACCOUNT_LOCKED lockedUntil=2026-09-11T15:23:28Z
```

| Event | Meaning |
|---|---|
| `AUTH_SUCCESS` | Credentials verified |
| `AUTH_FAILURE` | Login refused. `reason` is one of `BAD_PASSWORD`, `UNKNOWN_USER`, `ACCOUNT_LOCKED`, `ACCOUNT_DISABLED`, `MALFORMED_INPUT` |
| `ACCOUNT_LOCKED` | Too many failures in a row; the account is locked until `lockedUntil` |
| `AUTH_ERROR` | Internal error (for example, the store couldn't be written); login refused |
| `ACCOUNT_CREATED`, `PASSWORD_RESET`, `ACCOUNT_ENABLED`, `ACCOUNT_DISABLED` | Administrative changes |
| `STORE_WARNING` | A malformed line in `users.db` was skipped |

Log files rotate at 10 MB, and 5 files are kept.

## Using it from application code

```java
Logger audit = AuditLog.create(Paths.get("logs"));
FileCredentialStore store = new FileCredentialStore(Paths.get("data/users.db"), audit);
AuthenticationService auth = new AuthenticationService(store, new PasswordHasher(), audit, Clock.systemUTC());

AuthResult result = auth.authenticate(username, passwordChars, "web(ip=" + clientIp + ")");
Arrays.fill(passwordChars, '\0');
if (result == AuthResult.SUCCESS) { /* start session */ } else { /* show a generic error */ }
```

## Limitations

- The file store is safe for multiple threads in **one process**. Don't run several processes
  against the same `users.db` at the same time; for that, use a database instead.
- Lockout is per account. This stops password guessing against one account, but an attacker
  who knows a username can deliberately lock that user out. Internet-facing deployments
  should also rate-limit by client IP or add a CAPTCHA.
- Failed attempts with unknown usernames are logged with the username that was typed. Users
  sometimes type a password into the username field by mistake, so limit who can read the log.
- Add MFA if the application needs stronger assurance than a password alone.
