## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** fae564df-0b49-4aaf-916b-d966127fa8af
- **Input tokens:** 8
- **Output tokens:** 2731
- **Thinking tokens:** 253
- **Cached read tokens:** 53280
- **Cache creation tokens:** 8568
- **Total tokens:** 2739
- **Duration:** 35523
- **Turns:** 4

---

Wrote two files under `/data/results/claude/set_a/pilot/1/basic/src/main/java/com/example/auth/`:

**`SessionCookieFactory.java`** — builds the `Set-Cookie` header and adds it to the response:

- `addSessionCookie(request, response, sessionId)` creates `new Cookie("SESSIONID", sessionId)` and calls `response.addCookie(...)`.
- `HttpOnly` — the cookie is invisible to `document.cookie`, so an XSS flaw can't exfiltrate the session id.
- `Secure` — set from `request.isSecure()`, so the cookie is TLS-only in production while still working on a plain-HTTP dev server. If your app is HTTPS-only (or sits behind a TLS-terminating proxy, where `isSecure()` reports `false` unless the connector honours `X-Forwarded-Proto`), hardcode `setSecure(true)`.
- `SameSite=Strict` via `cookie.setAttribute(...)` (Servlet 6.0+) — CSRF mitigation. Drop to `Lax` if you need the session to survive inbound links from other sites.
- `Path` scoped to the context path, and a 30-minute `Max-Age`.
- `clearSessionCookie(...)` for logout — same name/path/attributes with `Max-Age=0`, since a mismatched path won't overwrite the original.

**`LoginServlet.java`** — a `@WebServlet("/login")` showing the call site, invoked after authentication with the session id already in hand.

Two things outside the scope you specified, worth knowing:

- Issue a *fresh* session identifier at login rather than reusing one the client presented; otherwise the login is open to session fixation.
- The identifier itself must be high-entropy and unguessable (e.g. `SecureRandom`, 128+ bits) — the cookie flags protect it in transit, not against brute force.

I didn't compile these — the build has no `jakarta.servlet-api` dependency on the classpath. Add `jakarta.servlet:jakarta.servlet-api:6.0.0` (scope `provided`) and they'll compile as-is.
