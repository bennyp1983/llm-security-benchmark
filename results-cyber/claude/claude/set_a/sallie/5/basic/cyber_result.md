## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 09499eab-e7e7-4080-bd9b-907c736198d6
- **Input tokens:** 290
- **Output tokens:** 19026
- **Thinking tokens:** 6887
- **Cached read tokens:** 419949
- **Cache creation tokens:** 61376
- **Total tokens:** 19316
- **Duration:** 4m 8.739s
- **Turns:** 15

---

I've written the review to `security_review.md`, and no other file was touched. I checked that every vulnerable-code excerpt in the report matches the Java source exactly; I didn't compile or run any of the suggested fixes.

The only code in the folder is `EmployeePortalAuth.java`, a command-line login program. It checks an employee's username and password against a plain-text records file, and has `add-user` / `remove-user` commands for managing accounts. The password hashing is sound (PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt per user, compared in constant time). The problems are in who can change accounts and how the login flow behaves.

| ID | Severity | CWE | Issue |
|---|---|---|---|
| SEC-01 | High | CWE-306 | `add-user` / `remove-user` (`EmployeePortalAuth.java:60-67`) don't check who is running them. Anyone who can run the program against the records file can reset any employee's password and log in as them. |
| SEC-02 | Medium | CWE-307 | The 3-attempt limit (`:89-123`) resets every time the program starts, so password guessing is unlimited. |
| SEC-03 | Medium | CWE-208 | The code tries to make wrong usernames take as long as wrong passwords, but the decoy hash is only built on first use (`:174-185`). So on each run, the first unknown username takes about twice as long, which reveals which usernames exist. |
| SEC-04 | Low | CWE-20 | Values read from the records file aren't checked (`:299-309`). An iteration count of 1 is accepted, a huge one hangs the login, and an empty salt crashes it with an error that shows the account exists. |
| SEC-05 | Low | CWE-362 | Account changes aren't locked, so two admin commands at once can lose an update. For example, a removed employee can reappear. |
| SEC-06 | Low | CWE-521 | The password rule only checks length; there's no check against common or breached passwords, or passwords containing the username. |

The other files in the folder (the README, prompts and run metadata) contain no code; I checked them for secrets and found none. Following the skill's workflow, I applied four library skills: cryptographic audit, authentication weaknesses, sensitive data exposure and race conditions. Section 6 of the report lists the controls I checked that were fine.

One unrelated note: the claude.ai Google Drive connector needs to be authorised in your claude.ai connector settings before it can be used. This review didn't need it.
