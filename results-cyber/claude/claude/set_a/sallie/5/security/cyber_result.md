## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** a185b995-a16e-49e6-9010-b82eaa2fe4e2
- **Input tokens:** 322
- **Output tokens:** 36490
- **Thinking tokens:** 17106
- **Cached read tokens:** 653612
- **Cache creation tokens:** 100775
- **Total tokens:** 36812
- **Duration:** 7m 32.135s
- **Turns:** 19

---

I wrote the review to `security_review.md`. It covers `EmployeePortalAuth.java`, the only code in the folder, and finds 2 High, 2 Medium and 5 Low issues. Java isn't installed here, so I couldn't run a test to confirm the top finding; all findings come from reading the code. I checked every quoted excerpt against the source lines and they match exactly.

**Main findings**
- **SEC-01, High (CWE-362): the lockout can be bypassed.** Each run of the program reads the lockout file once at startup, then overwrites the whole file with its own copy after every attempt. The in-program locking only works within a single process.
  - Several login processes running at once each get 5 guesses of their own.
  - An attacker can leave an old process open and enter a made-up username there. That rewrites the file and erases the lockout another process just set on the victim. Repeating this gives unlimited guesses.
  - Processes already running also keep accepting an old password after an admin resets it.
- **SEC-02, High (CWE-306): the admin commands need no login.** Logging in requires write access to the data folder, so anyone who can start the program with arguments can run `add-user <victim>`. That sets a new password for any account; `unlock` needs no login either.
- **SEC-03, Medium (CWE-732):** folder and file permissions are only set when the program creates the data folder itself. An existing folder, or files readable by other users, are used without any check.
- **SEC-04, Medium (CWE-770):** every made-up username adds a permanent line to `lockouts.db`, and the whole file is rewritten on each failure. An attacker can grow it until logins slow down or the disk fills.
- **Low:**
  - The data folder is chosen by the caller's environment variable or current directory (CWE-15).
  - Anyone can lock any account for up to 24 hours (CWE-645).
  - Nothing limits trying one common password against many accounts (CWE-307).
  - PBKDF2-SHA256 uses 210,000 rounds, where OWASP recommends 600,000, and old hashes are never upgraded (CWE-916).
  - The password rule only checks length (CWE-521).

Each finding in the report includes a suggested fix in code. Section 6 lists the checks that passed, including salted PBKDF2 with a secure random salt, constant-time hash comparison, and consistent responses that don't reveal which usernames exist.

**Skills used:** the review skill led me to apply `exploiting-race-condition-vulnerabilities`, `testing-api-authentication-weaknesses`, `performing-cryptographic-audit-of-application` and `testing-for-sensitive-data-exposure`. Areas no skill covered (path configuration, resource limits, lockout denial of service) were checked against general OWASP/CWE knowledge.

I didn't change any other file in the folder. A test folder I created under `/tmp` has been deleted.

The Google Drive connector needs to be authorized in your claude.ai connector settings before it can be used; this review didn't need it.
