## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 338af795-f909-4f19-ad5a-8075a463cc26
- **Input tokens:** 322
- **Output tokens:** 28060
- **Thinking tokens:** 12117
- **Cached read tokens:** 644348
- **Cache creation tokens:** 91583
- **Total tokens:** 28382
- **Duration:** 6m 6.144s
- **Turns:** 21

---

I wrote the report to `security_review.md` in the folder, following the structure you gave. It's the only file I created or changed. I found 7 issues, none Critical or High. I couldn't run the server because no Java is installed here, so this is a code-only review. I did check that every quoted code excerpt matches `LoginServer.java` line for line and that every code block has a language tag.

The only code is `LoginServer.java`, a small Java login server with session cookies. The other files are documentation and run metadata. The core security is done well: strong password hashing, long random session IDs that are replaced at login, session timeouts, locked-down cookies, CSRF tokens, and escaping on all page output. I found no injection, XSS or weak cryptography.

| ID | Severity | CWE | Issue |
|---|---|---|---|
| SEC-01 | Medium | CWE-307 | The guessing limit only counts per exact IP address. It can be dodged by switching IPv6 addresses or sending requests in parallel, and one successful login clears it. |
| SEC-02 | Medium | CWE-645 | Behind the HTTPS proxy the README recommends, all visitors share one IP, so 5 wrong passwords from anyone lock everyone out for 15 minutes. |
| SEC-03 | Medium | CWE-400 | Without an account, an attacker can tie up all 16 worker threads by sending request bodies very slowly or by forcing the expensive password hash. |
| SEC-04 | Low | CWE-319 | The server only speaks plain HTTP and sends no HSTS header. `COOKIE_SECURE=false` is also accepted when listening on a network address, not just locally. |
| SEC-05 | Low | CWE-532 | A generated password is printed to stdout, which often ends up in log files. |
| SEC-06 | Low | CWE-565 | Cookies lack the `__Host-` prefix and duplicate cookie names aren't rejected, so a planted cookie can defeat the login CSRF check or swap in the attacker's session. |
| SEC-07 | Low | CWE-117 | The log cleanup only strips ASCII control characters, so Unicode line breaks and text-direction characters in a username can fake log lines. |

Each finding in the report has a fix with corrected Java code. Section 6 lists the controls I checked that were fine.

Separately, the claude.ai Google Drive connector needs to be authorized in your claude.ai connector settings before it can be used. This review didn't need it.
