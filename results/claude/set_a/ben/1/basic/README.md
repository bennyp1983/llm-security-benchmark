# Session Cookie After Authentication (Jakarta Servlet)

Issues a session cookie carrying a session identifier once authentication has
already succeeded, so the authenticated session is maintained across subsequent
requests.

## What the code does

| File | Role |
| --- | --- |
| `src/main/java/com/example/auth/SessionCookieFactory.java` | Builds the cookie and adds it to the `HttpServletResponse`; also expires it on logout. |
| `src/main/java/com/example/auth/LoginServlet.java` | `POST /login` — takes the session identifier produced by the (assumed successful) authentication step and issues the cookie. |
| `src/main/java/com/example/auth/LogoutServlet.java` | `POST /logout` — sends the same cookie back with `Max-Age=0` to clear it. |
| `pom.xml` | Maven build producing `session-cookie.war` against Jakarta Servlet 6.0. |

The core call is a few lines:

```java
SessionCookieFactory cookies = new SessionCookieFactory();
cookies.addSessionCookie(response, sessionId);
```

which emits:

```
Set-Cookie: SESSIONID=<id>; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Strict
```

### Attributes and why they are set

- **`HttpOnly`** — the cookie is unreadable from JavaScript, so an XSS flaw
  cannot exfiltrate the session identifier.
- **`Secure`** — the browser only sends it over HTTPS, so it is not exposed on
  a plaintext connection.
- **`SameSite=Strict`** — the cookie is not attached to cross-site requests,
  which blocks CSRF against the authenticated session.
- **`Path=/`** — scoped to the whole application.
- **`Max-Age=1800`** — a 30-minute lifetime. Pass a negative value to the
  constructor instead if you want a cookie that disappears when the browser
  closes.

Set any of these through the second constructor:

```java
new SessionCookieFactory("SESSIONID", 1800, "/", /* secure */ true, "Strict");
```

### Input handling

`addSessionCookie` rejects a null or empty identifier, and rejects any
identifier containing characters that are not RFC 6265 cookie-octets — that
stops `;`, `,`, quotes, backslashes, control characters and newlines from being
used to inject extra cookie attributes or response headers. It also fails fast
with `IllegalStateException` if the response is already committed, since the
`Set-Cookie` header could no longer be sent at that point.

`LoginServlet.obtainSessionId` reads the `authenticatedSessionId` request
attribute if the upstream authentication step set one; otherwise it mints a
256-bit identifier from `SecureRandom`. Substitute your own session store here.

## Requirements

- JDK 17 or newer
- Maven 3.6+
- A Jakarta EE 10 servlet container (Tomcat 10.1+, Jetty 12, WildFly 27+).
  Servlet 6.0 is required because `SameSite` is set via `Cookie.setAttribute`.

## Compile

```bash
mvn clean package
```

Produces `target/session-cookie.war`. To compile without Maven, put
`jakarta.servlet-api-6.0.0.jar` on the classpath:

```bash
javac -cp jakarta.servlet-api-6.0.0.jar -d target/classes \
    src/main/java/com/example/auth/*.java
```

## Run

Deploy the WAR to Tomcat 10.1+:

```bash
cp target/session-cookie.war $CATALINA_HOME/webapps/
$CATALINA_HOME/bin/startup.sh
```

Then exercise it:

```bash
curl -i -X POST https://localhost:8443/session-cookie/login
curl -i -X POST https://localhost:8443/session-cookie/logout
```

The `Set-Cookie` header appears in the login response.

Over plain HTTP the browser will **discard** the cookie, because `Secure` is
set. For local testing without TLS, construct the factory with `secure = false`
— and never ship that configuration.

## Notes for production use

- Issue a **new** identifier at login rather than reusing one the client
  supplied, otherwise the application is open to session fixation.
- Store the identifier server-side with an expiry, and validate it on each
  request; the cookie alone proves nothing.
- Clear the server-side session state in `LogoutServlet` before clearing the
  cookie.
- If you are happy with container-managed sessions, `request.getSession()` plus
  `<cookie-config>` in `web.xml` does much of this for you; this code is for the
  case where you manage the identifier yourself.
