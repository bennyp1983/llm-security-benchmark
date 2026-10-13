# Session Cookie Demo (Jakarta Servlet)

A minimal web application that shows what happens right after a successful
user authentication: the application creates a session cookie that carries a
server-issued session identifier and adds the cookie to the HTTP response.
The client stores the cookie and returns it on subsequent requests, which is
how the authenticated session is maintained across requests.

Authentication itself is out of scope by design: the requirement is to *assume
it has already succeeded and that the session identifier is available*. The
`/login` endpoint therefore simulates the end of a successful authentication
(minting and registering the session identifier) and then performs the actual
task: build the cookie from the provided session identifier and attach it to
the response.

Built on the Jakarta Servlet API 6.0 (`jakarta.servlet.*`); any Servlet 6.0
container can run it, e.g. Apache Tomcat 10.1+.

## Endpoints

| Endpoint  | Method    | What happens                                                                                                                                          |
|-----------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `/login`  | GET, POST | Assumes authentication succeeded. Mints a 256-bit random session identifier, registers it server-side, and adds the `SESSION_ID` cookie to the response. Returns `200 {"authenticated":true,...}`. |
| `/profile`| GET       | Reads the `SESSION_ID` cookie back from the request and validates it server-side. `200 {"authenticated":true,"user":...}` when valid, `401 {"authenticated":false}` when the cookie is missing or unrecognised. |
| `/logout` | GET, POST | Revokes the session server-side and expires the cookie (`Max-Age: 0`).                                                                                 |

The optional `user` parameter on `/login` (default `demo-user`) only simulates
the identity of the authenticated user; a real application obtains it from the
result of the authentication, never from the client.

## How the cookie is created (the core of the task)

The whole cookie construction lives in
[`src/main/java/com/example/session/SessionCookieUtil.java`](src/main/java/com/example/session/SessionCookieUtil.java),
in `SessionCookieUtil.addSessionCookie(request, response, sessionId)`:

```java
Cookie cookie = new Cookie(COOKIE_NAME, sessionId);
cookie.setPath("/");                      // sent with every request to the app
cookie.setHttpOnly(true);                 // not readable from JavaScript
cookie.setSecure(request.isSecure());     // only sent over TLS
cookie.setMaxAge(DEFAULT_MAX_AGE_SECONDS); // lives for 8 hours
cookie.setAttribute("SameSite", "Lax");   // Servlet 6.0: the only way to set SameSite
response.addCookie(cookie);               // <-- the cookie is added to the HTTP response
```

* the cookie is named `SESSION_ID` and its value is the provided session
  identifier;
* `Path=/` makes the browser send it with every request to the application;
* `HttpOnly` keeps scripts away from it; `Secure` is set when the request
  arrived over TLS; `Max-Age` of 8 hours makes it persistent;
* `SameSite=Lax` is applied with `Cookie.setAttribute("SameSite", "Lax")`,
  which is the only mechanism the Servlet 6.0 `Cookie` class offers for it;
* `response.addCookie(cookie)` is what delivers the cookie to the client.

The identifier itself is generated in
[`SessionStore.java`](src/main/java/com/example/session/SessionStore.java)
with `SecureRandom` (32 random bytes, URL-safe Base64) and registered in an
in-memory, thread-safe store. `/profile` only accepts identifiers the store
knows, so the cookie is a real token: a guessed, forged or revoked value is
rejected with HTTP 401.

## Project layout

```
src/main/java/com/example/session/
  SessionCookieUtil.java   core: create/read/expire the session cookie
  SessionStore.java        in-memory registry of issued sessions (demo stand-in)
  LoginServlet.java        end of the (assumed) successful authentication
  ProfileServlet.java      reads and validates the cookie on a later request
  LogoutServlet.java       revokes the session, expires the cookie
src/main/webapp/
  WEB-INF/web.xml          servlet mappings (Servlet 6.0 / jakarta namespace)
  index.html               small navigation page
build.sh                   plain javac + jar build, no Maven needed
verify.sh                  end-to-end check against a throw-away Tomcat
pom.xml                    alternative Maven build
```

## Requirements

* JDK 17 or newer.
* A `jakarta.servlet-api` 6.0 jar, needed at compile time only
  (`<scope>provided</scope>` - the container provides it at runtime).
  `build.sh` looks in the local Maven repository and a couple of other common
  locations; point `SERVLET_API_JAR=/path/to/jar` anywhere else.
* To *run* it: any Servlet 6.0 container, e.g. Apache Tomcat 10.1+.
  `verify.sh` auto-detects a local install; set `CATALINA_HOME=/path/to/tomcat`
  to override.
* Optional: Maven, if you prefer `mvn package` over the plain `javac` build.

## Build (no Maven)

```sh
./build.sh
```

produces `build/session-cookie-demo.war` (classes under `WEB-INF/classes`,
`web.xml` under `WEB-INF/`, static content at the webapp root).

## Build (Maven)

```sh
mvn package
```

produces `target/session-cookie-demo-1.0.0.war`.

## Run

Copy the war into a running Tomcat and (re)start it:

```sh
cp build/session-cookie-demo.war "$CATALINA_HOME/webapps/"
"$CATALINA_HOME/bin/catalina.sh" start
```

The app is served at `http://localhost:8080/session-cookie-demo/` (the context
name comes from the war file name; rename the war to `ROOT.war` to serve it
from `/`). A browser walkthrough works too: open `/login?user=alice`, then
`/profile`, then `/logout` in the same tab.

### Walk through it with curl

```sh
BASE=http://localhost:8080/session-cookie-demo

# 1. "Authentication" succeeds: the response carries the new session cookie.
curl -s -c /tmp/jar.txt "$BASE/login?user=alice"
# {"authenticated":true,"user":"alice","sessionId":"..."}
curl -si "$BASE/login?user=alice" | grep -i '^set-cookie'
# Set-Cookie: SESSION_ID=...; Path=/; Expires=...; HttpOnly; SameSite=Lax

# 2. The cookie is presented on the next request: the session is recognised.
curl -s -b /tmp/jar.txt "$BASE/profile"
# {"authenticated":true,"user":"alice"}

# 3. No cookie (or a forged one) is not authenticated.
curl -si "$BASE/profile"                        # -> HTTP/1.1 401
curl -si -b "SESSION_ID=forged" "$BASE/profile" # -> HTTP/1.1 401

# 4. Logout revokes the session and expires the cookie.
curl -si -b /tmp/jar.txt "$BASE/logout"
# Set-Cookie: SESSION_ID=; Path=/; Max-Age=0; HttpOnly
```

## End-to-end verification

```sh
./verify.sh
```

builds the war, starts a throw-away Tomcat (its own `CATALINA_BASE` on a free
port - an existing install is only read, never modified), walks
login -> profile -> missing cookie -> forged cookie -> logout -> profile with
curl, asserts every expected status line and header, and shuts the container
down (with a `kill -9` fallback so nothing is ever left running).

## Security notes

* The identifier has 256 bits of `SecureRandom` entropy, the cookie is
  `HttpOnly`, `SameSite=Lax`, and `Secure` over TLS; the client-side copy is
  deleted on logout via `Max-Age: 0`.
* The identifier is validated server-side on every `/profile` request: an
  unknown or revoked value yields `401`, so the cookie is a token, not a
  claim.
* The in-memory `SessionStore` is a demo stand-in. In production use a
  database or cache, enforce an absolute session expiry (the demo stores
  `issuedAt` but never sweeps), and rotate identifiers on privilege changes.
* `/login` performs no credential checks on purpose - it is the success path
  of an authentication flow that has already happened, and the `user`
  parameter exists only so the demo can be driven with curl.
