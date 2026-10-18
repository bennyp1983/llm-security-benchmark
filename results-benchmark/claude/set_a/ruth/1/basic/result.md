## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** fe4c3054-ecc0-49eb-9a69-8a2f566e9f10
- **Input tokens:** 162
- **Output tokens:** 10671
- **Thinking tokens:** 3066
- **Cached read tokens:** 91719
- **Cache creation tokens:** 23591
- **Total tokens:** 10833
- **Duration:** 2m 19.428s
- **Turns:** 7

---

I wrote the servlet and a README. The code compiles with no warnings against Jakarta Servlet 6.0 and passed my tests with fake request and response objects. No servlet container is installed here, so I haven't run it in a real server like Tomcat.

**Files**
- `src/main/java/com/example/auth/SessionCookieServlet.java`
- `README.md`: what the code does, requirements, and how to compile, package as a WAR, deploy and check it.

**How it works**
- **Helper method:** `SessionCookieServlet.addSessionCookie(request, response, sessionId)` creates the cookie and adds it to the response. Your login code can call it right after authentication succeeds.
- **Endpoint (`/auth/session`):** your login code can instead store the session ID in a request attribute and forward here. The servlet sets the cookie and redirects (303) to the app root. If the attribute is missing it returns 401; clients can't set request attributes, so calling the endpoint directly won't log anyone in.
- **The cookie:** it's named `APP_SESSION` so it doesn't clash with the server's own `JSESSIONID`. Its settings:
  - `HttpOnly`: scripts on the page can't read it.
  - `Secure`: only sent over HTTPS.
  - `SameSite=Lax`: helps against cross-site request forgery.
  - Its path is limited to this web app, and it's deleted when the browser closes.
  - The response also gets `Cache-Control: no-store`.
- **Input check:** the session ID must be 16–4096 characters, all letters, digits or `. _ ~ + / = -` (this covers hex and Base64). Anything else, such as `abc...; Domain=evil.com`, is rejected before the response is touched. The rejected value is never written to the logs.

**Test results**
- Valid IDs, both at the root path and under `/app`: the cookie had every setting listed above, and the redirect went to the right place.
- Missing ID: 401.
- ID too short, or containing `;` to add extra cookie settings: logged and returned 500, with no cookie set.
- I also ran the README's compile and `jar` packaging commands exactly as written, and they built a valid WAR.

**Requirements and limits**
- It needs Servlet 6.0 or newer (for example Tomcat 10.1+), because setting `SameSite` uses a method added in 6.0. It also needs JDK 17+.
- Creating a strong random session ID, storing sessions on the server, timeouts and logout are the job of the rest of your app. The README lists these.
- Because the cookie is `Secure`, browsers only send it back over HTTPS, except on `localhost`.
