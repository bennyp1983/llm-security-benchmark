# LoginService: user login with brute-force protection

`LoginService.java` is a self-contained Java 11+ implementation for handling login
attempts. It takes a username and password, checks them against stored account data, and
grants access only when both are correct. It also resists password guessing, account
enumeration and timing attacks.

## What it does

| Concern | How it is handled |
|---|---|
| **Password storage** | Passwords are never stored in plain text. Each is hashed with PBKDF2-HMAC-SHA256 (600,000 iterations and a random 16-byte salt) and stored as `pbkdf2_sha256$iterations$salt$hash`. |
| **Verification** | The hash is recomputed from the submitted password and compared with `MessageDigest.isEqual`, which runs in constant time. |
| **Repeated failed logins** | Failures are counted **per username** and **per client source** (such as an IP address). When a threshold is reached, that key is locked out for a while. Each new lockout doubles in length, up to a cap (default: 5 failures per user or 20 per source, then 30 s → 60 s → 120 s … up to 1 h). |
| **Attempts during a lockout** | They are refused **before the password is checked**, so an attacker can't keep guessing, and even a correct password is refused until the lock ends. |
| **Permanent-lockout DoS** | Lockouts are temporary. An attacker can slow down a victim's logins but can't disable the account for good. |
| **Forgetting old failures** | Once a key has had no failures for a whole `failureWindow` (default 15 min) after its last lock ended, its history is cleared. A successful login clears that username's counter right away. |
| **Source counter vs. success** | A successful login does **not** reset the per-source counter. Otherwise an attacker could log into their own account now and then to clear it while guessing other users' passwords. |
| **Account enumeration** | "Unknown user" and "wrong password" produce the same `INVALID_CREDENTIALS` result and message. Unknown usernames are also hashed (against a dummy hash) so response times match, and they are throttled like real accounts, so a lockout message doesn't reveal that an account exists. |
| **Memory exhaustion** | The failure-tracking tables have a size limit (`maxTrackedKeys`). When a table is full, stale entries are removed first, then the least-recently-used ones. |
| **Secret hygiene** | Passwords are passed as `char[]` and wiped after use. Username and password lengths are capped. Disabled accounts can't log in. |
| **Concurrency** | The trackers are synchronized and the in-memory store uses `ConcurrentHashMap`, so one service instance can be shared across threads. |

### Main types (all nested in `LoginService`)

- `LoginService.login(String username, char[] password, String clientSource)` returns a `LoginResult`.
- `LoginResult` has `status()` (`SUCCESS`, `INVALID_CREDENTIALS` or `LOCKED_OUT`), `isSuccess()`,
  `username()`, `retryAfter()`, and `userMessage()` (text that is safe to show end users).
- `LockoutPolicy` holds the thresholds and durations. `LockoutPolicy.defaults()` gives the values above.
- `UserStore` is the interface to your account storage. Implement it for a database or directory.
  `InMemoryUserStore` is included for demos and tests.
- `PasswordHasher` handles PBKDF2 hashing and verification.

## Requirements

- JDK 11 or newer (tested with OpenJDK 17). No third-party libraries.

## Compile

```sh
javac LoginService.java
```

## Run

Scripted demo. It shows a successful login, an unknown user, three wrong passwords
causing a lockout, the correct password being refused during the lockout, and then a
successful login after the lock ends:

```sh
java LoginService
```

Interactive mode. It prompts for a username and password; the password isn't echoed when
run in a real terminal. Enter an empty username to quit:

```sh
java LoginService --interactive
```

Demo accounts: `alice` / `CorrectHorseBatteryStaple` and `bob` / `s3cure-Passw0rd!`.
The demo uses a shorter policy so the effect is easy to see: 3 failures → 5 s lockout.

## Using it in an application

```java
LoginService.InMemoryUserStore store = new LoginService.InMemoryUserStore();
store.createAccount("alice", passwordChars);           // hashes and wipes passwordChars

LoginService service = new LoginService(store);        // default lockout policy
LoginService.LoginResult result =
        service.login(submittedUser, submittedPasswordChars, request.getRemoteAddr());

if (result.isSuccess()) {
    // start the session for result.username().get()
} else {
    // show result.userMessage(); for LOCKED_OUT you may also send a
    // Retry-After header using result.retryAfter()
}
```

## Deployment notes

- Failure counters are kept **in memory**. They reset when the process restarts and aren't
  shared between instances. If you run several instances, back the tracker with a shared
  store such as Redis or a database.
- Pass the real client address as `clientSource`. Behind a reverse proxy, only trust
  `X-Forwarded-For` values set by your own proxy.
- Always serve login over TLS, log failed attempts and lockouts for monitoring, and add
  MFA for sensitive accounts. Rate limiting reduces the risk of password guessing but
  doesn't remove it.
