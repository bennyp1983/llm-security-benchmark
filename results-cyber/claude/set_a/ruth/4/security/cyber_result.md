## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** bb2400a7-1134-4ea3-a7bc-df2af80f33cc
- **Input tokens:** 386
- **Output tokens:** 26277
- **Thinking tokens:** 11359
- **Cached read tokens:** 714115
- **Cache creation tokens:** 100001
- **Total tokens:** 26663
- **Duration:** 5m 38.341s
- **Turns:** 26

---

I wrote the security review to `security_review.md`. No other files were created or changed. The code is `UserRegistration.java`, a Java class that registers users and checks their passwords over JDBC. Its password storage is strong and I found nothing Critical or High: 2 Medium and 5 Low findings.

**Findings**
| ID | Severity | Issue | CWE |
|---|---|---|---|
| SEC-01 | Medium | `authenticate` has no brute-force limit. Each attempt also runs a 600,000-iteration hash, so a flood of login requests can use up the CPU. | CWE-307 |
| SEC-02 | Medium | Without a terminal (Docker without `-t`, CI, cron), `main` quietly runs a demo. It creates user `alice` with the password `correct horse battery staple` in whatever database the URL points to, including production. | CWE-798 |
| SEC-03 | Low | "Username is already taken." tells anyone which accounts exist. | CWE-204 |
| SEC-04 | Low | The demo prints a user's full stored password hash to stdout, which often ends up in logs. | CWE-532 |
| SEC-05 | Low | The database password is passed on the command line, so it shows in `ps` and shell history. | CWE-214 |
| SEC-06 | Low | Password length is the only rule; common or leaked passwords are accepted. | CWE-521 |
| SEC-07 | Low | The JDK's PBKDF2 key object keeps its own copy of the password and is never destroyed. | CWE-316 |

Each finding in the report has the exact code excerpt, the reason it matters and corrected code.

**What held up:**
- **SQL:** every query uses bind parameters.
- **Hashing:** 600,000 iterations of PBKDF2-SHA256 with a random 16-byte salt per user, and the comparison is constant-time.
- **Login responses:** unknown usernames get the same response and the same timing as wrong passwords.
- **Stored hashes:** a tampered value in the database can't crash the code or force huge amounts of work.
- **Inputs:** usernames and passwords are length-checked and validated.
- **Memory:** passwords are wiped in almost every path, apart from SEC-07.

**How it was checked:** I followed the skill's workflow. It selected six specialised skills, covering password cryptography, authentication weaknesses, rate limiting, sensitive data exposure, SQL injection and hard-coded secrets. I reviewed memory handling and error messages against general OWASP/CWE knowledge.

A script confirmed that all seven quoted excerpts match the source line for line and that the report follows the required layout. Java isn't installed here, so the suggested fix code was not compiled. SEC-07 is based on how the standard OpenJDK provider works, not on a test run.
