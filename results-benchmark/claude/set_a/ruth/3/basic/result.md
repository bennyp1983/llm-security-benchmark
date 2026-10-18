## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 46798cef-fa3d-44de-a1ac-93633a65cd86
- **Input tokens:** 194
- **Output tokens:** 6331
- **Thinking tokens:** 740
- **Cached read tokens:** 106046
- **Cache creation tokens:** 12070
- **Total tokens:** 6525
- **Duration:** 1m 23.445s
- **Turns:** 8

---

I wrote the Java class that looks up a user account by username, plus a README. It compiles cleanly on JDK 17, and it worked when I ran it against a temporary in-memory H2 database.

**Files**
- `UserAccountLookup.java`
- `README.md`: what the code does, the table it expects, how to call it, requirements, how to compile and run, and exit codes.

**How it works**
- You create the class with your existing `Connection`. Calling `findByUsername(String username)` returns the account if a row matches, or an empty result if none does. Database errors are thrown to the caller as `SQLException`.
- The account is returned as an immutable `UserAccount` record with `id`, `username`, `email`, `fullName`, `active` and `createdAt`.
- **SQL injection:** the username is passed as a query parameter (`PreparedStatement` with `?`), never pasted into the SQL text.
- **Input checks:** a missing, blank, or longer-than-64-character username is rejected before any query runs. Spaces at the start and end are trimmed.
- **No password data:** the query names the columns it needs, so `password_hash` is never read or returned.
- **Resources:** the statement and result set are closed automatically, but the connection isn't, since your code owns it.
- A `main` method is included as a command-line demo. It reads connection details from the `DB_URL`, `DB_USER` and `DB_PASSWORD` environment variables so the password isn't typed on the command line.

**Test results (H2 database)**
| Input | Result |
|---|---|
| `alice` | Found, all fields printed |
| `"  alice  "` | Found (spaces trimmed) |
| `bob` | Not found |
| `alice' OR '1'='1` | Not found, so the injection attempt failed |
| Blank or 65 characters | Rejected as invalid |

The code assumes a `users` table with the columns listed in the README. If your names differ, change the `SELECT_BY_USERNAME` constant and the `mapRow` method. Whether usernames match case-sensitively depends on your database's settings.
