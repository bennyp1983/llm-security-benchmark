## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 8bc64c5a-8e0a-4636-9cc4-26c3fa2ec026
- **Input tokens:** 162
- **Output tokens:** 11511
- **Thinking tokens:** 3809
- **Cached read tokens:** 99487
- **Cache creation tokens:** 17254
- **Total tokens:** 11673
- **Duration:** 2m 23.801s
- **Turns:** 8

---

I wrote the servlet and a README. The code compiles against Jakarta Servlet 6.0 on Java 17, and its built-in self-check passed: the cookie came out with the right settings and all 6 malformed session IDs were rejected. I haven't deployed it to a real servlet container, so the full request/response path hasn't been run.

**Files**
- `src/main/java/com/example/auth/SessionCookieServlet.java`
- `README.md`: what the code does, how to compile, run the self-check and deploy as a WAR, and an example of calling it from login code.

**How it works:** your login code checks the credentials, creates a session ID, puts it in a request attribute and forwards to `POST /auth/session`. If you'd rather not forward, you can call `SessionCookieServlet.addSessionCookie(request, response, sessionId)` directly.

**Cookie settings**
- **Name `__Host-SESSIONID`:** browsers only accept this name on an HTTPS-only cookie with `Path=/` and no `Domain`, so subdomains and plain-HTTP pages can't set or overwrite it.
- **`HttpOnly`:** page scripts can't read it, which limits theft through XSS.
- **`Secure`:** only sent over HTTPS.
- **`SameSite=Strict`:** not sent on cross-site requests, which helps against CSRF.
- **`Path=/`, no `Domain`:** sent only to this exact host.
- **No `Max-Age`:** the browser discards it when the session ends and doesn't save it to disk.

**Other safeguards**
- **No authentication, no cookie:** if the session ID attribute is missing, it returns 401. `GET` requests get 405.
- **HTTPS only:** plain HTTP gets 403. Behind a proxy that handles TLS, the container must be set up so it knows the original request was HTTPS.
- **ID check:** the ID must be 32–256 URL-safe characters. This blocks attempts to inject extra cookie settings or headers (`;`, CR/LF) and rejects IDs that are clearly too short. The ID is never logged.
- **Session fixation:** if the server already had a session for this user before login, its ID is changed.
- **No caching:** the response carrying the cookie is sent with `Cache-Control: no-store`.

**What your code still has to do:** generate the ID with `SecureRandom` after login succeeds, store the session and enforce its expiry on the server, and clear the cookie on logout. The README covers each of these. If users arriving from links on other sites need to stay logged in, change `SAME_SITE` to `"Lax"`.
