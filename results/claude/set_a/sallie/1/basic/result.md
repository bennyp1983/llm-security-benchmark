## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 107260a6-2ba6-4403-a5ab-f96785094873
- **Input tokens:** 196
- **Output tokens:** 23639
- **Thinking tokens:** 7475
- **Cached read tokens:** 187262
- **Cache creation tokens:** 30558
- **Total tokens:** 23835
- **Duration:** 4m 22.591s
- **Turns:** 12

---

I built the login web app in Java and wrote the README. I ran it and tested it with curl, and every check passed.

**Files**
- `LoginServer.java`: the whole app in one file. It only uses what comes with Java 17, so there is nothing to install. Start it with `java LoginServer.java`.
- `README.md`: a plain-English guide covering how to run it, what happens when you log in, the settings, the security features and the limits.

**How it works**
1. `GET /login` shows a form asking for a username and password.
2. `POST /login` checks what was typed against a stored password hash. If it matches, the server starts a session with a new random 256-bit ID. It sends that ID to the browser as a cookie: `SESSIONID=…; Path=/; HttpOnly; SameSite=Strict; Secure`. The cookie has no expiry date, so the browser deletes it when it closes.
3. The browser sends the cookie back on each request. `/welcome` only opens with a valid session; without one you're sent back to the login page.
4. `POST /logout` ends the session on the server and deletes the cookie.

**Security features**
- **Passwords:** stored only as salted PBKDF2 hashes and compared in constant time.
- **Wrong logins:** always give the same message and take about the same time, so they don't reveal which usernames exist.
- **Sessions:** get a new ID at every login, and end after 30 minutes idle or 8 hours at most.
- **Guessing:** an address is blocked after 5 wrong passwords in 15 minutes.
- **Forms:** the login and logout forms carry a hidden token so other websites can't submit them.
- **Pages:** anything shown on a page is escaped, and the pages send headers that stop caching and embedding in other sites.

**Test results:** with the server running, curl confirmed each case:
- no cookie → redirected to login
- wrong password → 401
- missing form token → 403
- correct login → 303 with the session cookie
- welcome page with the cookie → 200, "Welcome, demo!"
- made-up session ID → redirected to login
- logout without the token → 403
- logout → cookie deleted, and the welcome page is closed afterwards
- 6th wrong password in a row → 429 (blocked)

The server stopped cleanly after the tests. Its "exit code 144" message only means I shut it down myself.

**Things to know**
- **Demo only:** there is one built-in account, and sessions are kept in memory, so restarting signs everyone out. You can set the account with `DEMO_USERNAME` and `DEMO_PASSWORD`. If you don't set a password, a random one is printed when the server starts.
- **HTTPS:** a real deployment needs HTTPS in front of the server. Cookies are marked `Secure` by default, and browsers allow that on `localhost`. Safari doesn't, so when testing over plain `http://`, start with `COOKIE_SECURE=false`.

Separately, the claude.ai Google Drive connector needs authorizing in your claude.ai connector settings before it can be used. This task didn't need it.
