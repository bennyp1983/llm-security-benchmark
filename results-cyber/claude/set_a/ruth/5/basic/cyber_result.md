## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 9c3d912a-ae26-4dbb-a955-34a5303aaa95
- **Input tokens:** 290
- **Output tokens:** 30543
- **Thinking tokens:** 15611
- **Cached read tokens:** 442025
- **Cache creation tokens:** 74100
- **Total tokens:** 30833
- **Duration:** 6m 17.276s
- **Turns:** 16

---

I've written the security review to `security_review.md`, following the skill's steps. It's the only file I created or changed. The code is well built: I found no Critical or High issues. There are 3 Medium and 6 Low findings.

**What's in the folder:** `LoginSystem.java` is the only code. It registers users, stores passwords as salted PBKDF2 hashes and checks logins. The other files are the README, the prompts and data from the run that generated the code.

**Skills used:** cryptographic audit, API authentication weaknesses, race conditions, secret scanning and sensitive data exposure. Two issues had no matching skill, so I checked them against general OWASP/CWE guidance: lockout being used to block real users, and look-alike usernames.

**Findings:**

| ID | Severity | CWE | Issue |
|---|---|---|---|
| SEC-01 | Medium | 307 | Brute-force protection is weak. The failure count resets after each lock, nothing limits attempts from one client, and guesses against unknown usernames are never limited. An attacker can try common passwords across many accounts, or keep guessing slowly forever. |
| SEC-02 | Medium | 645 | Anyone can lock any account indefinitely by sending 5 wrong passwords every 15 minutes. |
| SEC-03 | Medium | 204 | A locked account returns its own `ACCOUNT_LOCKED` result and responds faster because it skips the hash. This reveals which usernames exist, even though the code tries to hide that. |
| SEC-04 | Low | 521 | The password rule only checks length, so `password` or `12345678` is accepted. |
| SEC-05 | Low | 916 | 210,000 PBKDF2 iterations is OWASP's figure for SHA-512; for SHA-256 it recommends 600,000. The count also isn't stored with each hash, so it can't be raised later without breaking existing passwords. |
| SEC-06 | Low | 362 | The storage interface has no way to save failure counts or lock times. With a database or several servers, as the README suggests, the lockout silently stops working. |
| SEC-07 | Low | 798 | The demo account `alice` has a hard-coded password that is printed to the console and shown in the README. |
| SEC-08 | Low | 549 | Without a real console, the program shows the password as it's typed and keeps it in a `String` that can't be wiped. |
| SEC-09 | Low | 1007 | Usernames aren't Unicode-normalized, so look-alikes such as a Cyrillic `аdmin` can be registered as separate accounts. |

Each finding has the vulnerable code, why it matters and a corrected version. The fix snippets are sketches, not compiled code. Section 6 lists the controls I checked and found sound, such as the salt, constant-time comparison and password wiping.

I checked the report's format with a script. All 9 code excerpts match `LoginSystem.java` line for line, there is one level-1 heading, and every code block has a language tag.
