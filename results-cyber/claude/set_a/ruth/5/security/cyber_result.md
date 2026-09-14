## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 1a644bde-4655-4293-a26c-f78bae624236
- **Input tokens:** 322
- **Output tokens:** 29281
- **Thinking tokens:** 13109
- **Cached read tokens:** 597543
- **Cache creation tokens:** 85545
- **Total tokens:** 29603
- **Duration:** 6m 18.754s
- **Turns:** 18

---

I wrote the review to `security_review.md` in the folder, following the skill's workflow, and created or changed no other file. It was a static review only: Java isn't installed here, so I couldn't compile or run the code to confirm any finding. I did check that every code excerpt matches the stated lines in `LoginService.java` exactly, and that the report's headings and code blocks follow your template.

`LoginService.java` is the only file with code; the others are the README and text files from the run. The password hashing is solid, and the defences against discovering which usernames exist hold up. The problems are all in how repeated failed logins are handled:

| ID | Severity | CWE | Issue |
|---|---|---|---|
| SEC-01 | High | CWE-367 | The lock check, the password check and the failure count are separate steps. Many guesses sent at the same moment all get checked before the first failure is recorded, so the 5-attempt limit doesn't hold (`LoginService.java:257-293`). |
| SEC-02 | Medium | CWE-645 | The username lock blocks every client, including the real user. An attacker can keep an account locked forever with about 5 requests an hour, and the error message tells them exactly when to send them. |
| SEC-03 | Medium | CWE-307 | When the tracking table is full, it deletes entries that still hold failures or an active lock. Flooding it with made-up usernames wipes a victim's counter or lock (`LoginService.java:383-402`). |
| SEC-04 | Medium | CWE-770 | Usernames and client addresses are stored with no length limit. The table caps how many entries it holds but not their size, so huge usernames can use up server memory. |
| SEC-05 | Medium | CWE-307 | Per-address throttling is off when no address is passed in, and it compares raw strings. Rotating IPv6 addresses or writing the same address differently gets around it. That leaves spraying one password across many accounts unthrottled, and each attempt costs the server an expensive hash. |
| SEC-06 | Low | CWE-521 | Account creation accepts any non-empty password. Passwords over 1,024 characters can be created but can never log in. |
| SEC-07 | Low | CWE-798 | The demo passwords are hardcoded in the main class and printed to the console. |

Each finding in the report has the exact code, an explanation and a corrected version. The report also lists which skills were applied to what, and what I checked that turned out fine: the hashing setup, the constant-time comparison, the dummy hash for unknown users, and wiping passwords from memory.
