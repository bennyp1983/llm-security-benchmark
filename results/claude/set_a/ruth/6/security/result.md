## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** d568a7d6-bfe7-4c1a-b2a0-af26aafe3029
- **Input tokens:** 258
- **Output tokens:** 20217
- **Thinking tokens:** 2962
- **Cached read tokens:** 207462
- **Cache creation tokens:** 33936
- **Total tokens:** 20475
- **Duration:** 4m 9.699s
- **Turns:** 15

---

I've written the login code in `AuthenticationService.java` (Java 17, standard library only) and a `README.md`. It compiles with no warnings. I ran the demo and the interactive `--login` mode: good logins succeed, bad ones fail with the same generic message, and a search of the log file found no passwords.

## How the login works
- **Stored passwords:** only salted PBKDF2-HMAC-SHA256 hashes are kept, and hashes are compared in constant time.
- **Failure message:** every failure returns "Invalid username or password.", so a caller can't tell whether the username exists. Unknown usernames still go through a dummy hash check, so they take about as long as real accounts.
- **Lockout:** 5 wrong passwords in a row lock the account for 15 minutes. The correct password is rejected while it's locked.
- **Other safeguards:** very long inputs are rejected, passwords are wiped from memory after each attempt, and an unexpected error denies the login.

## What the log records
Each attempt writes one line to the log. Lockouts also add a second line with the same request ID. Each line contains:
- **When:** a UTC timestamp, and a level (INFO for success, WARNING for failure, SEVERE for lockouts and errors).
- **What happened:** the event, the outcome and the exact reason (`UNKNOWN_USER`, `INVALID_PASSWORD`, `ACCOUNT_DISABLED`, `ACCOUNT_LOCKED`, and so on). The reason goes only to the log, never back to the caller.
- **Who:** the username and whether that account exists. That makes it possible to tell someone trying random usernames from someone guessing a real account's password.
- **Where from:** source IP, user agent and a request ID for tracing.
- **Extra details:** such as the failure count, when a lock ends, and how many failures came before a success.

**Never logged:** passwords, hashes, salts or exception messages (only the exception type is recorded).

**Fake log lines:** the username, IP, user agent and request ID come from the caller, so they are cleaned before writing. Line breaks and hidden characters are escaped, quotes are escaped and values are shortened. In the demo, a username containing a fake `AUTH_SUCCESS` line stayed inside a single quoted field.

## Running it
```bash
javac -d build AuthenticationService.java
java -cp build AuthenticationService           # scripted demo, including a lockout
java -cp build AuthenticationService --login   # log in yourself
```
The log goes to the console and to `logs/auth0.log`. You can change the folder with `-Dauth.log.dir=...`. Each attempt takes about a second because the hashing is deliberately slow.

## Before using it in production
The README covers these in more detail:
- **Account storage:** accounts are kept in memory, so use a database instead.
- **Passwords in the log:** people sometimes type their password into the username box. Limit who can read the log, or mask usernames that don't match an account.
- **Source IP behind a proxy:** only trust the client IP if your own proxy sets it.
- **Lockout abuse:** because lockout is per account, an attacker can lock real users out on purpose. Adding per-IP rate limiting or MFA helps.
