## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 8e82db9e-09e7-4ae7-9dbd-2aee8161eed0
- **Input tokens:** 162
- **Output tokens:** 8390
- **Thinking tokens:** 760
- **Cached read tokens:** 92189
- **Cache creation tokens:** 14491
- **Total tokens:** 8552
- **Duration:** 1m 43.456s
- **Turns:** 7

---

I've written the program and the README. The program compiled with no warnings, and every register and login case I tried worked as expected.

**Files:**
- `UserAccountManager.java`: the program, in one file with no outside libraries.
- `README.md`: plain-English instructions covering setup, running it, an example session, the username and password rules, how passwords are protected, and limits.

**How it works:**
- You run it in a terminal and pick from a menu: register, log in, or quit. You type the password twice when registering, and it's hidden as you type.
- **Passwords are never saved as typed.** Each account gets its own random value (a "salt"), and the password is scrambled with it in a slow, one-way process (PBKDF2-HMAC-SHA256, 600,000 rounds). Only the username, salt and scrambled result are saved, in `users.db` by default. You can give a different file name when starting the program.
- Logging in repeats the scrambling on the typed password and checks it against the saved result.
- Other safeguards:
  - Only the owner can read the accounts file (on Linux and macOS).
  - The file is replaced in one step, so it isn't left half-written if the program is interrupted.
  - A failed login doesn't say whether the username or the password was wrong.
  - Usernames are not case-sensitive, so `Alice` and `alice` are the same account.
  - It stops with an error if the accounts file is damaged.
- Other Java code can also call `register` and `authenticate` directly.

**Testing:** I ran it with Java 17 in a temporary folder:
- **Registering:** creating a new account worked. It correctly refused a username that was already taken (in different capitals), a password that was too short, passwords that didn't match, and a username with invalid characters.
- **Logging in:** the right password got in, and a wrong password was rejected.
- **After restarting:** the saved account still logged in, an unknown username was rejected, and the saved file could only be read by its owner.

The script ended with an error code, but only because it deleted the temporary folder it was still in. None of the tests failed. No test files were left in your project folder.

**Limitations:** There's no lockout after repeated failed logins and no password reset. Only one copy of the program should change the accounts file at a time.
