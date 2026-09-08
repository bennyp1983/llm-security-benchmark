## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 4f931551-bfb8-4958-94e6-5607de7d8e12
- **Input tokens:** 20
- **Output tokens:** 10564
- **Thinking tokens:** 582
- **Cached read tokens:** 174616
- **Cache creation tokens:** 17128
- **Total tokens:** 10584
- **Duration:** 123710
- **Turns:** 10

---

Done — built and verified in `/data/results/claude/set_a/pilot/4/basic`.

**What's there**

| File | Role |
| --- | --- |
| `src/accounts/PasswordHasher.java` | PBKDF2-HMAC-SHA256, salt generation, constant-time compare |
| `src/accounts/UserAccount.java` | One account; hashes on create, verifies, (de)serializes |
| `src/accounts/AccountStore.java` | File-backed registry: load, validate, register, authenticate, atomic save |
| `src/accounts/Main.java` | CLI — interactive menu plus `register` / `login` subcommands |
| `src/accounts/AccountStoreTest.java` | Dependency-free test suite (13 tests, all passing) |
| `README.md` | Build/run instructions and the storage format |

**Storage.** One line per account: `username:iterations:base64(salt):base64(hash)`. The password itself is never stored — each account gets a fresh 16-byte random salt and the password is stretched through PBKDF2-HMAC-SHA256 at 210,000 iterations into a 256-bit hash. I verified the plaintext never reaches the file, and that two accounts sharing a password produce different hashes.

**Authentication.** `AccountStore.authenticate` re-derives the hash with the stored salt and iteration count and compares via `MessageDigest.isEqual`. Unknown usernames still pay the hashing cost, and failures report a single vague "Invalid username or password", so neither timing nor message reveals which accounts exist. Passwords are `char[]`, zeroed after use; the file is written to a temp file and atomically moved into place with `0600` permissions.

I stored the iteration count per account rather than as a global constant, so the work factor can be raised later without invalidating existing accounts.

**Verified end to end:**

```
$ printf 'sw0rdfish-2026\nsw0rdfish-2026\n' | java -cp out accounts.Main register alice
Account 'alice' registered.
$ printf 'sw0rdfish-2026\n' | java -cp out accounts.Main login alice     # exit 0
Welcome back, alice!
$ printf 'wrongpassword\n' | java -cp out accounts.Main login alice      # exit 1
Invalid username or password.
```

Two notes on scope. Credentials persist to a flat file, which suits a single-process program but has no concurrency control — if you need multiple processes registering at once, this wants a database. And when input is piped rather than typed at a terminal, `System.console()` is null and the password can't be masked; that path exists so the program stays scriptable and testable, but real use should be on a TTY.
