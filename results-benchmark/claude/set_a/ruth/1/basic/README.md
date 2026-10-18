# Session Cookie Issuance (Jakarta Servlet)

`src/main/java/com/example/auth/SessionCookieServlet.java` creates the session cookie
for a user who has **already been authenticated**. It puts the provided session identifier
in a cookie and adds that cookie to the HTTP response. The browser then sends the cookie
back on later requests, which keeps the authenticated session going.

## What the code does

The class offers two ways to issue the cookie:

1. **Static helper:** `SessionCookieServlet.addSessionCookie(request, response, sessionId)`.
   Call it from any servlet, filter or controller that has just authenticated the user.
2. **Servlet endpoint** `/auth/session` (registered with `@WebServlet`). The authentication
   step stores the session identifier in a request attribute and forwards to it:

   ```java
   // inside your login servlet, after credentials were verified
   request.setAttribute(SessionCookieServlet.SESSION_ID_ATTRIBUTE, sessionId);
   request.getRequestDispatcher("/auth/session").forward(request, response);
   ```

   The servlet sets the cookie and replies with `303 See Other` to the application root
   (Post/Redirect/Get). If the attribute is missing, the servlet returns `401 Unauthorized`.
   Clients can't set request attributes, so calling the endpoint directly won't log anyone in.

### Cookie that gets created

```
Set-Cookie: APP_SESSION=<sessionId>; Path=<contextPath>/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store
```

| Attribute        | Why |
|------------------|-----|
| `HttpOnly`       | JavaScript can't read the cookie, which limits session theft through XSS. |
| `Secure`         | The cookie is only sent over HTTPS. |
| `SameSite=Lax`   | The cookie isn't sent on cross-site subrequests or POSTs, which helps against CSRF. |
| `Path`           | Limits the cookie to this web application's context path. |
| no `Max-Age`     | Makes it a browser-session cookie that is deleted when the browser closes. |
| `Cache-Control: no-store` | Stops shared caches from storing a response that carries a credential. |

Before the cookie is created, the session identifier is checked. It must be 16–4096
characters from `A–Z a–z 0–9 . _ ~ + / = -`, which covers hex, Base64 and Base64URL
encodings. Values with `;`, `,`, spaces or control characters are rejected, so a bad value
can't add cookie attributes or split headers. When an identifier is rejected, nothing is
written to the response and the value is left out of the logs.

### Assumptions and responsibilities outside this code

- **Authentication has already succeeded** before this code runs.
- **Session identifier:** create a new, cryptographically random identifier (for example,
  at least 128 bits from `SecureRandom`) at every login. Never reuse an identifier that
  existed before login, because that allows session fixation.
- **Server-side session store:** the application must link the identifier to the user,
  enforce idle and absolute timeouts, and invalidate the identifier at logout.
- The cookie name `APP_SESSION` is separate from the container's own `JSESSIONID`.

## Requirements

- JDK 17 or newer (the code uses pattern matching for `instanceof`)
- Jakarta Servlet API **6.0** or newer (`Cookie.setAttribute`, used for `SameSite`, was added in 6.0)
- A Servlet 6.0 container to run it, such as Apache Tomcat 10.1+, Jetty 12 (EE10) or
  GlassFish 7+

## Compile

Get the API jar, for example
`https://repo1.maven.org/maven2/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar`.
The container provides this jar at runtime, so don't bundle it.

```bash
mkdir -p build/WEB-INF/classes
javac --release 17 \
      -cp jakarta.servlet-api-6.0.0.jar \
      -d build/WEB-INF/classes \
      src/main/java/com/example/auth/SessionCookieServlet.java
```

## Package and run

Package the classes as a WAR. No `web.xml` is needed because the servlet uses `@WebServlet`.

```bash
jar --create --file session-cookie.war -C build .
```

Deploy the WAR to Tomcat 10.1+:

```bash
cp session-cookie.war $CATALINA_HOME/webapps/
$CATALINA_HOME/bin/catalina.sh run
```

The app is then available under the context path `/session-cookie`.

### Using it from your login code

Put your login servlet in the same WAR (compile it the same way). After it has verified
the credentials, it either forwards to `/auth/session` as shown above, or calls
`SessionCookieServlet.addSessionCookie(request, response, sessionId)` and writes its own
response.

### Checking it

A direct request, with no authentication step, is rejected:

```bash
curl -i -X POST http://localhost:8080/session-cookie/auth/session
# HTTP/1.1 401
```

After a login that forwards to the servlet, the response contains the cookie:

```
HTTP/1.1 303
Set-Cookie: APP_SESSION=...; Path=/session-cookie/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store
Location: /session-cookie/
```

Because the cookie is `Secure`, browsers only send it back over HTTPS. Browsers treat
`http://localhost` as secure, but any other host must use TLS.
