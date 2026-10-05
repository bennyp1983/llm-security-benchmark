# Session cookie on successful authentication

A small Jakarta Servlet 6 web application that turns a session identifier into a session cookie and
puts it on the HTTP response, so the authenticated session survives across subsequent requests.

The code assumes authentication **already succeeded**. It does not check passwords; it is the step
that runs afterwards.

## What it does

`POST /login`

1. Takes the session identifier from the request attribute `com.example.auth.sessionId`, which is
   where the preceding authentication step leaves it. If nothing was stored there, a fresh
   identifier is generated from `SecureRandom` (256 bits, Base64-URL, 43 characters).
2. Validates the identifier against a cookie-safe character set, so a malformed value can never
   break out of the `Set-Cookie` header.
3. Builds a `jakarta.servlet.http.Cookie` carrying the identifier, with `Secure`, `HttpOnly`,
   `Path`, `SameSite` and lifetime set, and adds it to the response with
   `HttpServletResponse#addCookie`.
4. Replies `200` with `Cache-Control: no-store` so the credential-bearing response is not cached.

`GET /whoami`

Reads the cookie back off the request and reports whether the caller presented a session, which is
how you confirm the round trip works. It echoes only the length of the identifier, never the value.

Observed against a real container:

```
$ curl -i -X POST http://localhost:8080/session-cookie-demo/login
HTTP/1.1 200
Set-Cookie: APPSESSION=txMgQg5yFBeGZRNg5jyOX0jCMEbfyT-crx6lVrIaq9E; Path=/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store
Content-Type: text/plain;charset=UTF-8

authenticated; session cookie issued
```

## Cookie attributes and why

| Attribute | Default | Reason |
| --- | --- | --- |
| `Secure` | on | Without it the identifier is sent over cleartext HTTP and can be sniffed. |
| `HttpOnly` | on | Keeps browser scripts (i.e. any XSS) from reading the identifier. |
| `SameSite` | `Lax` | Stops the browser from attaching the cookie to cross-site POSTs (CSRF). |
| `Path` | `/` | Scope of the cookie. |
| `Max-Age` | omitted | Browser-session cookie. A configured `0` is normalised to "omit": a literal `Max-Age=0` tells the browser to delete the cookie the moment it arrives. |
| `Domain` | omitted | Host-only cookie. Setting a domain widens the cookie to subdomains, so it is opt-in. |

`SameSite` has no setter on `jakarta.servlet.http.Cookie`; it is written through the Servlet 6.0
attribute API, `cookie.setAttribute("SameSite", "Lax")`. On the Servlet 5.0 API that method does not
exist - either stay on 5.0 without `SameSite`, or emit the header yourself with
`response.addHeader("Set-Cookie", ...)` and assemble the string manually.

## Layout

```
pom.xml
src/main/java/com/example/auth/
    SessionCookieFactory.java    creates and configures the cookie, validates the identifier
    SessionIdGenerator.java      SecureRandom identifiers for apps with no id store of their own
    LoginServlet.java            /login  - adds the cookie to the response
    SessionProbeServlet.java     /whoami - reads the cookie back on the next request
src/test/java/com/example/auth/
    SessionCookieFactoryTest.java  cookie attributes, injection rejection, configuration
    LoginServletTest.java          what ends up on the response
    SessionProbeServletTest.java   the cookie coming back
    ServletDoubles.java            request/response/config stand-ins (no container needed)
```

## Build

Requires JDK 17 and Maven.

```
mvn clean package
```

Runs the tests and produces `target/session-cookie-demo.war`.

## Run

Any Jakarta EE 10 or later container (Servlet 6.0) - Tomcat 10.1, Jetty 12+ (ee10 module), WildFly
27+, Payara 6+. Tomcat 9, Jetty 11 and older are `javax.servlet` / Servlet 4-5 and will not run this
without recompiling against `jakarta.servlet-api` 5.0 and dropping the `SameSite` line.

```
cp target/session-cookie-demo.war $CATALINA_BASE/webapps/
$CATALINA_HOME/bin/startup.sh
```

Then:

```
# no cookie yet
curl http://localhost:8080/session-cookie-demo/whoami
# -> not authenticated: no APPSESSION cookie on this request

# authenticate, keep the cookie
curl -c jar.txt -X POST http://localhost:8080/session-cookie-demo/login

# replay it on the next request - this is what "maintained across requests" means
curl -b jar.txt http://localhost:8080/session-cookie-demo/whoami
# -> authenticated: replayed session cookie of 43 chars
```

## Configuring the cookie

Declare the servlet in `WEB-INF/web.xml` to override the defaults; remove the `@WebServlet`
annotation from `LoginServlet` first if you want `web.xml` to be the only source of truth:

```xml
<servlet>
  <servlet-name>LoginServlet</servlet-name>
  <servlet-class>com.example.auth.LoginServlet</servlet-class>
  <init-param><param-name>cookieName</param-name><param-value>PORTAL_SESSION</param-value></init-param>
  <init-param><param-name>cookiePath</param-name><param-value>/portal</param-value></init-param>
  <init-param><param-name>cookieMaxAge</param-name><param-value>1800</param-value></init-param>
  <init-param><param-name>cookieSameSite</param-name><param-value>Strict</param-value></init-param>
  <init-param><param-name>cookieSecure</param-name><param-value>true</param-value></init-param>
  <init-param><param-name>cookieHttpOnly</param-name><param-value>true</param-value></init-param>
  <init-param><param-name>cookieDomain</param-name><param-value>app.example.com</param-value></init-param>
</servlet>
<servlet-mapping>
  <servlet-name>LoginServlet</servlet-name>
  <url-pattern>/login</url-pattern>
</servlet-mapping>
```

Anything unparseable (`cookieMaxAge=30m`, `cookieSameSite=Sometimes`, `SameSite=None` without
`Secure`) fails the servlet at startup with the offending parameter named, instead of surprising you
on the first login.

## Hooking in your authentication

`LoginServlet` deliberately contains no credential check - wire yours in front of it and hand over
the identifier it chose:

```java
String sessionId = mySessionStore.create(username);   // persist server side first
request.setAttribute(LoginServlet.SESSION_ID_ATTRIBUTE, sessionId);
request.getRequestDispatcher("/login").forward(request, response);
```

The identifier must exist server-side too. The cookie only names the session; without a matching
record the next request has nothing to look up.

## Security notes

* **The identifier is never read from the request.** Parameters, form fields and headers are ignored,
  so an attacker cannot make you log in under a session id they already know (session fixation).
  Tests cover `?sessionId=...` and a parameter named after the cookie.
* **Cookie values are validated**, not just escaped. An identifier containing a space, `;`, `"`, `,`,
  `=`, a CR/LF or any non-ASCII byte is rejected with `IllegalArgumentException` (surfacing as `500`)
  rather than truncated or written into the header.
* **`Secure` is on by default**, which means the cookie is dropped by the browser over plain `http://`.
  Set `cookieSecure=false` only for a local `localhost` development run - modern browsers treat
  `localhost` as trustworthy, but this shortcut must not reach production.
* **Logout** has to do both halves: invalidate the server-side session and expire the cookie with
  `Max-Age=0`, otherwise the browser keeps replaying an identifier that no longer resolves.
* This example is plain HTTP; `Secure` and `SameSite=Lax` only earn their keep behind TLS.

## Verification

`mvn clean package` - 34 tests, all passing. Coverage: the identifier reaching the cookie, every
attribute, the `maxAge=0` trap, the rejection list for header-breaking identifiers, fixation attempts,
startup validation of bad configuration, and the cookie being recognised on a follow-up request.

Beyond the unit tests, the WAR was deployed on Apache Tomcat 10.1.59 and driven with curl:

| Check | Result |
| --- | --- |
| `POST /login` header | `Set-Cookie: APPSESSION=<43 chars>; Path=/; Secure; HttpOnly; SameSite=Lax` |
| `GET /whoami` with no cookie | `not authenticated` |
| `GET /whoami` replaying the cookie | `authenticated: replayed session cookie of 43 chars` |
| `POST /login?sessionId=ATTACKER123` | issued value is server-generated, `ATTACKER123` not used |
| Two successive logins | different identifiers each time |
| `GET /login` | `405` |

## Scope of the example

There is no credential store, no session table, no TLS configuration and no logout endpoint - the
task begins where authentication ends. The session state a real deployment needs is left to your
`HttpSession`, database or token store, behind `SESSION_ID_ATTRIBUTE`.
