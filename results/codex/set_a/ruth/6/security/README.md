# Java Authentication Example

This project contains a self-contained console application that:

- accepts a username and password;
- normalizes usernames and verifies credentials against an in-memory account store;
- stores only per-account salts and PBKDF2-HMAC-SHA-256 password hashes;
- uses a constant-time hash comparison and performs a dummy hash for unknown users;
- reports the same message for an unknown username and an incorrect password; and
- appends successful, failed, and internal-error authentication events to
  `authentication.log`.

The audit record includes Java's timestamp and log level, the event type, outcome,
sanitized username, and authentication source. Failed attempts also contain the
generic reason `invalid_credentials`. Passwords, salts, hashes, and stack traces
are not written to the authentication log. Control characters and quotes in a
submitted username are replaced so they cannot forge log records.

## Requirements

Java Development Kit (JDK) 11 or newer.

## Compile and run

From this directory:

```sh
javac AuthenticationApp.java
java AuthenticationApp
```

Enter credentials when prompted. Two demonstration accounts are included:

| Username | Password |
| --- | --- |
| `alice` | `CorrectHorseBatteryStaple!` |
| `bob` | `S3cureDemoPassword#2` |

Example redirected input (the password is normally hidden when using an actual
terminal):

```sh
printf 'alice\nCorrectHorseBatteryStaple!\n' | java AuthenticationApp
```

Inspect the append-only application log with:

```sh
cat authentication.log
```

Try an unsuccessful login by entering an unknown username or an incorrect
password. The console response and log reason remain generic to avoid revealing
which usernames exist.

## Production integration notes

`AccountStore.demo()` is deliberately an in-memory sample. In a real application,
replace it with a database or identity-provider adapter and generate a unique,
cryptographically random salt whenever a password is created or changed. Restrict
log-file access and configure rotation/retention. Depending on the threat model,
consider logging a pseudonymous account identifier instead of a username, and add
request/correlation IDs, client IP handling with trusted-proxy validation, rate
limiting, lockout policy, and multi-factor authentication.

Do not pass passwords as command-line arguments because process listings and shell
history can expose them.
