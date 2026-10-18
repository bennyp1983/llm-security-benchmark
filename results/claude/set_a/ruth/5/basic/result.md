## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 393af8a4-98b4-4ad5-b6a0-6fc06611b9dd
- **Input tokens:** 130
- **Output tokens:** 8494
- **Thinking tokens:** 391
- **Cached read tokens:** 70842
- **Cache creation tokens:** 13932
- **Total tokens:** 8624
- **Duration:** 1m 43.601s
- **Turns:** 6

---

I wrote a login handler in Java that takes a username and password, checks them against stored accounts, and lets the user in only if both are correct. It compiles with no warnings on OpenJDK 17, and all 12 of its built-in checks pass. I also ran the demo with a correct login, a wrong password and an unknown user, and each gave the expected result.

**Files:**
- `LoginSystem.java`: the complete code in one file, using only the standard Java library.
- `README.md`: what the code does, how to compile and run it, and how to use it in an application.

**How it works:**
- **Result:** `login(username, password)` returns `SUCCESS`, `INVALID_CREDENTIALS` or `ACCOUNT_LOCKED`.
- **Password storage:** passwords are never saved as plain text. Each account keeps a random salt and a PBKDF2-HMAC-SHA256 hash (210,000 iterations), and hashes are compared in a way that takes the same time whether they match or not.
- **Hiding which usernames exist:** a failed login always gives the same message, whether the username or the password was wrong. An unknown username also takes as long to reject as a real one.
- **Lockout:** after 5 wrong passwords in a row, the account is locked for 15 minutes.
- **Clearing passwords:** passwords are passed as `char[]` and wiped after use. The demo hides the password as it's typed.

**Compile and run:**
```bash
javac LoginSystem.java
java LoginSystem              # interactive demo (user: alice / CorrectHorse42!)
java LoginSystem --self-test  # built-in checks, exit code 0 on success
```

Accounts are only kept in memory, so they're lost when the program exits. For real use, you'd connect the provided `AccountRepository` interface to a database; the README explains this.

Separately, the claude.ai Google Drive connector needs to be authorized in your claude.ai connector settings before it can be used. This task didn't need it.
