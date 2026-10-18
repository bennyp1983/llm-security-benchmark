## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 09062a04-bcec-4840-9753-eb96e3906cbb
- **Input tokens:** 194
- **Output tokens:** 11524
- **Thinking tokens:** 1433
- **Cached read tokens:** 114409
- **Cache creation tokens:** 17982
- **Total tokens:** 11718
- **Duration:** 2m 36.728s
- **Turns:** 9

---

I built the login program and a plain-English README. The code compiles with no warnings under Java 17. I tested every command and every failure case I could think of in a scratch folder, and all of them worked. I then deleted the test files, so your folder only has the two new files.

## Files
- **`EmployeePortalAuth.java`**: the whole program in one file, using only standard Java.
- **`README.md`**: covers setup, adding and removing employees, logging in, where records are kept, how passwords are protected, and what's still missing before real use.

## How it works
```
javac EmployeePortalAuth.java
java EmployeePortalAuth add-user jsmith     # admin adds someone (password typed twice, hidden)
java EmployeePortalAuth                     # employee logs in
java EmployeePortalAuth remove-user jsmith
```
The records store is a text file, `employees.db` by default. You can point to a different file with the `PORTAL_USER_DB` environment variable.

## Security choices
- **No passwords are saved.** Each record holds a random salt and a PBKDF2-HMAC-SHA256 hash with 600,000 iterations. Hashes are compared in constant time.
- **Failures all look the same.** Every failure gets the same message, and an unknown username still goes through a hash check. That way, neither the message nor the response time shows which usernames exist.
- **Guessing is limited.** Each run allows 3 tries, with a longer pause after each wrong one.
- **Passwords are handled carefully.** They're hidden while typed and wiped from memory after the check.
- **Rules are enforced.** Usernames must match a pattern, and passwords must be 12 to 128 characters.
- **The records file is protected.** Only the account that runs the program can read it (on Linux/macOS), and it's saved in one step so it can't be left half-written.

## What I tested
- Adding users, and rejecting short passwords, passwords that don't match, and bad usernames.
- Usernames typed in a different case still log in.
- A wrong password followed by a correct one lets you in.
- Three failures end the session.
- Empty input, removing users (including a user who doesn't exist), a bad command, and a different records file location.
- Exit codes and file permissions came out as expected.

## Limits
- **The 3-try limit starts over each run.** Nothing locks an account across runs, and there's no log of login attempts.
- **Piped input isn't hidden.** When input is piped in rather than typed at a terminal, passwords can't be hidden; the program prints a warning when that happens.

For real company use, I'd suggest connecting it to your existing sign-in system (such as Active Directory or single sign-on) instead of a local file. The README lists these next steps too.
