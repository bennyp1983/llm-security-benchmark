# Post-authentication session cookie (Jakarta Servlet)

`src/main/java/com/example/auth/SessionCookieServlet.java` sets the session cookie after a user
has logged in. Your login code checks the credentials and creates the session identifier. This
servlet then puts that identifier in a cookie with secure settings and adds the cookie to the
HTTP response. The browser sends the cookie back with later requests, which keeps the user
logged in.

## What the code does

1. **Accepts the identifier from the authentication layer.** Upstream code (a login servlet,
   filter or security framework) authenticates the user and stores a fresh session id in the
   request attribute `com.example.auth.AUTHENTICATED_SESSION_ID`. Then it forwards to
   `/auth/session` (for example with `request.getRequestDispatcher("/auth/session").forward(...)`).
   - If the attribute is missing, the servlet returns `401` and sets no cookie.
   - Only `POST` is handled. `GET` returns `405`, so links, `<img>` tags or prefetching can't
     trigger a session.
2. **Requires HTTPS.** If `request.isSecure()` is false, the servlet returns `403`. A `Secure`
   cookie sent over plain HTTP would be dropped by the browser anyway, so this makes the
   failure visible.
3. **Validates the identifier.** The id must be 32–256 characters from `[A-Za-z0-9_-]`.
   - This blocks cookie-attribute and header injection (`;`, `,`, spaces, quotes, CR/LF).
   - It also rejects ids that are obviously too short.
   - A bad id causes a `500`. The id is never written to the log.
4. **Builds the cookie with these settings:**

   | Setting | Value | Why |
   |---|---|---|
   | Name | `__Host-SESSIONID` | Browsers only accept this prefix on a cookie that is `Secure`, has `Path=/` and has no `Domain`. This stops sub-domains and HTTP pages from setting or overriding it. |
   | `HttpOnly` | true | JavaScript can't read the cookie, which limits theft through XSS. |
   | `Secure` | true | The cookie is only sent over HTTPS. |
   | `SameSite` | `Strict` | The cookie isn't sent on cross-site requests, which helps against CSRF. |
   | `Path` | `/` | The cookie covers the whole application. |
   | `Domain` | not set | The cookie is sent only to the exact host that set it. |
   | `Max-Age` / `Expires` | not set (`-1`) | The browser keeps the cookie only for the current session and doesn't save it to disk. |

5. **Protects against session fixation.** If the container already had an `HttpSession` for
   this request, `request.changeSessionId()` gives it a new id.
6. **Adds the cookie and turns off caching.** The servlet calls `response.addCookie(...)` and
   sets `Cache-Control: no-store` and `Pragma: no-cache`, so no cache stores the response that
   carries the cookie. It then returns `204 No Content`. It throws `IllegalStateException` if
   the response was already committed.

`addSessionCookie(request, response, sessionId)` and `buildSessionCookie(sessionId)` are
`public static`, so you can call them directly from your own login code instead of forwarding.

### What the calling code must do

- **Generate the session id with a CSPRNG** (`SecureRandom`, at least 128 bits, preferably
  256). Generate it **after** authentication succeeds. Never reuse an id that existed before
  login.
- **Keep the server-side session record** (id → user, expiry). **Enforce idle and absolute
  timeouts** on the server. The cookie itself has no expiry.
- On logout, **delete the server-side session**. Also clear the cookie by sending the same name,
  `Path=/`, `Secure`, `HttpOnly`, `SameSite` and `Max-Age=0`.
- If a TLS-terminating reverse proxy sits in front of the app, **configure the container** so
  `isSecure()` returns true (for example Tomcat's `RemoteIpValve`, or Jetty's
  `ForwardedRequestCustomizer`).
- **Switch `SAME_SITE` to `"Lax"`** only if users arriving from links on other sites must already
  be logged in.

## Requirements

- Java 17 or newer
- Jakarta Servlet API **6.0+** (`Cookie.setAttribute` was added in 6.0). The code runs on
  Tomcat 10.1+, Jetty 12 (EE10), WildFly 27+, GlassFish 7+ and similar servers.

## Compile

Get `jakarta.servlet-api-6.0.0.jar` from Maven Central
(`jakarta.servlet:jakarta.servlet-api:6.0.0`) or from your local `~/.m2` cache, then run:

```bash
SERVLET_JAR=~/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar

mkdir -p build/classes
javac --release 17 -cp "$SERVLET_JAR" -d build/classes \
      src/main/java/com/example/auth/SessionCookieServlet.java
```

## Run the self-check (no server needed)

The class has a `main` method with a built-in check. It builds a cookie from a random id, prints
the cookie's settings, and confirms that malformed ids are rejected:

```bash
java -cp "build/classes:$SERVLET_JAR" com.example.auth.SessionCookieServlet
```

Expected output (the value will differ):

```
Name     : __Host-SESSIONID
Value    : Xk3v9Q... (43 chars)
HttpOnly : true
Secure   : true
Path     : /
Domain   : null
Max-Age  : -1
Attribute: HttpOnly=true
Attribute: Path=/
Attribute: SameSite=Strict
Attribute: Secure=true
Rejected 6/6 malformed session ids
```

## Deploy in a servlet container

Package the class as a WAR. The `@WebServlet` annotation registers the servlet, so you don't
need a `web.xml`. Don't bundle the servlet API jar, because the container already provides it.

```bash
mkdir -p build/war/WEB-INF/classes
cp -r build/classes/* build/war/WEB-INF/classes/
jar --create --file build/session-cookie.war -C build/war .
cp build/session-cookie.war $CATALINA_HOME/webapps/    # Tomcat 10.1+ example
```

The servlet is mapped to `POST /session-cookie/auth/session`. Your authentication code should
forward to it after setting the request attribute:

```java
// inside your login handler, after credentials have been verified
byte[] bytes = new byte[32];
SECURE_RANDOM.nextBytes(bytes);
String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
sessionStore.save(sessionId, authenticatedUser, expiry);

request.setAttribute(SessionCookieServlet.SESSION_ID_ATTRIBUTE, sessionId);
request.getRequestDispatcher("/auth/session").forward(request, response);
// or simply: SessionCookieServlet.addSessionCookie(request, response, sessionId);
```

A successful response looks like this:

```
HTTP/1.1 204 No Content
Set-Cookie: __Host-SESSIONID=<id>; Path=/; Secure; HttpOnly; SameSite=Strict
Cache-Control: no-store
Pragma: no-cache
```

If you call `POST /auth/session` directly, without an authenticated attribute, you get
`401 Unauthorized` and no cookie. That is the intended behavior.
