## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** a13c57eb-00ff-4aff-8b3f-6af69852fd21
- **Input tokens:** 194
- **Output tokens:** 9279
- **Thinking tokens:** 713
- **Cached read tokens:** 115854
- **Cache creation tokens:** 15490
- **Total tokens:** 9473
- **Duration:** 1m 57.216s
- **Turns:** 9

---

I wrote a Java program that creates user accounts and checks logins, plus a README in plain English. It compiles without warnings on Java 17, and every test I ran behaved correctly.

**Files** (in `/data/results/claude/set_a/sallie/4/security/`):
- `UserAccountManager.java`: the program (only uses what comes with Java)
- `README.md`: how to build it, how to use it, and how passwords are protected

**How passwords are stored**
- Passwords are never saved. Each account gets its own random value (a "salt"), and the password is scrambled together with it 600,000 times using a standard method called PBKDF2-HMAC-SHA256. Only the username, the salt and the scrambled result are saved, one account per line:
  `alice:pbkdf2-sha256:600000:<salt>:<hash>`
- You can't work backwards from the saved result to the password. The 600,000 rounds make each guess slow, so trying huge numbers of passwords is very expensive for an attacker.
- At login, the program scrambles the typed password the same way and compares the two results in a way that takes the same time whether they match or not.

**Other protections**
- A failed login always says "Invalid username or password", and takes about as long for a username that doesn't exist. Nobody can use it to find out which usernames exist.
- Passwords are hidden as you type, you have to enter the password twice, and passwords are wiped from memory after use.
- There are rules for usernames, and passwords must be 8 to 128 characters. Capital letters in usernames don't matter, so `Alice` and `alice` are the same user.
- On Linux and macOS, only the file's owner can read the credentials file. The file is saved in one step, so a crash won't leave it half-written.

**Testing:** I tested these cases: creating an account, a username that's already taken (including different capital letters), passwords that don't match, a password that's too short, a bad username, a correct login, a wrong password and an unknown user. The saved file had the expected format with owner-only permissions, and the password text did not appear anywhere in it. The file lives in the current folder by default; `--file <path>` lets you choose another.

**Limitations** (also in the README): it's meant for one computer, not for many programs writing to the same file at once. There's no limit on failed login attempts, and no way to reset a password or delete an account.
