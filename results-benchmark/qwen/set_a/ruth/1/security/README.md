# Session cookie after authentication (Jakarta Servlet 6.0)

A web application that, once a user has authenticated, mints a session identifier, stores the
authenticated state server side, and attaches a session cookie to the HTTP response so subsequent
requests from that browser are recognised as the same authenticated session.

The focus is the cookie's configuration. Most of the code exists to make the attributes on one
`Set-Cookie` header correct, verifiable, and impossible to weaken by accident:

```
Set-Cookie: APPSESSION=K5Kw7LggCQtEduy_M8v6ocvpY04PoCkggCwqFtIlSoc; Path=/; Secure; HttpOnly; SameSite=Lax
```

Recorded from a real Tomcat 10.1.59 (`./smoke-test.sh`), not written by hand.

## Cookie attributes and why each one

| Attribute | Value | What it prevents |
| --- | --- | --- |
| value | 32 random bytes from `SecureRandom`, base64url, 43 chars | Guessable or enumerable sessions. Not derived from the username or a timestamp. |
| `HttpOnly` | always set | A script injected into the page cannot read the identifier from `document.cookie`. |
| `Secure` | always set | The identifier is never sent over plaintext HTTP, so not visible to a network observer or a downgraded link. |
| `SameSite` | `Lax` (default) | Not attached to cross-site POSTs, which is what makes CSRF against a state-changing endpoint fail. `None` is refused unless `Secure` is also set. |
| `Path` | `/` (the application root) | The identifier is not sent to unrelated paths, or to paths the same host serves for third parties. |
| `Domain` | **never emitted** | Stays a host-only cookie. A `Domain` attribute lets every subdomain read *and plant* the session cookie. `SessionCookieConfig` has no domain setting at all, so this cannot be turned on. |
| `Max-Age` / `Expires` | **absent** (`maxAgeSeconds = -1`) | Browser-session cookie: the identifier dies with the browser instead of persisting on a shared machine. Server-side expiry is enforced independently, so a cookie that somehow survives still stops working. |

Two further things are asserted at runtime rather than assumed:

- The identifier is validated against `[A-Za-z0-9._~-]` (RFC 6265 `token` / RFC 4648 base64url)
  *before* it reaches the header, so a value that came from outside cannot smuggle CR, LF, `;` or an
  extra attribute into `Set-Cookie`. Rejection happens before the response is touched.
- After `response.addCookie(...)`, the header the container actually produced is read back
  (`SessionCookieIssuer.assertHeaderIntegrity`) and the request fails if the container dropped
  `Secure`, `HttpOnly` or `Path`, or emitted a header containing a control character. A container that
  silently ignores an attribute would otherwise hand out a cookie that looks set but is readable by
  script or replayable over http.

Session fixation is handled the same way it must be: login discards any session the request arrived
with and mints a *new* identifier, so a value an attacker fixed earlier never names an authenticated
session.

## Layout

```
src/main/java/com/example/auth/
  SessionCookieIssuer.java     builds the cookie, adds it to the response, verifies the header  <-- the core
  SessionCookieConfig.java     immutable attribute set, validated invariants, context-param wiring
  SessionIdentifier.java       validated opaque token; minting, constant-time compare, redaction
  InMemorySessionStore.java    identifier -> authenticated state, with absolute expiry
  AuthenticatedSession.java    SessionUser + minted-at + expires-at
  AuthContextListener.java     creates store/issuer/config once, publishes them on ServletContext
  LoginServlet.java            POST /api/login  - authenticates, sets the cookie
  WhoAmIServlet.java           GET  /api/whoami - proves the cookie alone maintains the session
  LogoutServlet.java           POST /api/logout - removes the session, overwrites the cookie
  AuthenticatedSessionServlet.java  shared cookie-reading and JSON plumbing
  SecurityHeadersFilter.java   no-store / Vary: Cookie / CSP / Referrer-Policy / HSTS-on-TLS
  EnvironmentCredentialVerifier.java  PLACEHOLDER credential check - replace for production
  CredentialVerifier.java      the seam to replace
  Json.java                    response escaping
src/main/webapp/
  WEB-INF/web.xml              registration + cookie context-params + container session hardening
  index.html, app.js, app.css  minimal form to exercise it in a browser
src/test/java/com/example/auth/TestHarness.java   116 assertions, no test framework needed
build.sh  run-tests.sh  smoke-test.sh
```

Servlets, the filter and the listener are registered in `WEB-INF/web.xml` rather than by annotation,
so the cookie settings and the container-side hardening sit together in one file that can be reviewed
and diffed.

## Compile and run

Requires JDK 17+ and any Jakarta Servlet 6.0 API jar (Tomcat 10.1+ or Jetty 11+ supplies one at
runtime; the API jar is only needed to compile). No Maven or Gradle is involved.

```bash
./build.sh          # compile and package build/session-cookie.war
./run-tests.sh      # 116 assertions against Proxy doubles of the Servlet API
./run-tests.sh --verbose
```

`build.sh` searches for the API jar (`jakarta.servlet-api-*.jar` or Tomcat's `lib/servlet-api.jar`,
checking inside the jar that it is the `jakarta.*` namespace and not `javax.*`). Point it explicitly
with `SERVLET_API_JAR=/path/to/jakarta.servlet-api-6.0.0.jar ./build.sh`, or drop the jar in `lib/`.
If you need to download it:

```bash
mkdir -p lib && curl -fLso lib/jakarta.servlet-api-6.0.0.jar \
  https://repo1.maven.org/maven2/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar
```

Equivalent manual commands, with nothing assumed about the platform default charset (a box without
`LANG`/`LC_ALL` defaults to US-ASCII, which is why `-encoding` is always explicit):

```bash
javac -Xlint:all -Werror -encoding UTF-8 -cp lib/jakarta.servlet-api-6.0.0.jar \
      -d build/classes $(find src/main/java -name '*.java')
mkdir -p build/war/WEB-INF/classes
cp -r build/classes/. build/war/WEB-INF/classes/
cp -r src/main/webapp/. build/war/
( cd build/war && jar --create --file ../session-cookie.war . )
```

### Deploy

Copy the war into the container and start it. As `ROOT` the context path is `/`, which is what
`cookiePath=/` in `web.xml` assumes; deploy it under a sub-path and set `cookiePath` to match, or the
browser stops sending the cookie back.

```bash
# Tomcat 10.1+ / Jetty 11+
cp build/session-cookie.war "$CATALINA_HOME/webapps/ROOT.war"
"$CATALINA_HOME/bin/catalina.sh" run
```

The demo verifier reads `demo.username` / `demo.password` system properties, or `DEMO_USERNAME` /
`DEMO_PASSWORD` environment variables. Without them login deliberately returns
`500 not_configured` rather than a plausible-looking `401` that would hide a broken deployment:

```bash
CATALINA_OPTS="-Ddemo.username=alice '-Ddemo.password=correct horse battery staple'" \
  "$CATALINA_HOME/bin/catalina.sh" run
```

Then open `http://localhost:8080/` and watch the Network tab, or:

```bash
curl -i -X POST --data-urlencode username=alice \
        --data-urlencode 'password=correct horse battery staple' \
        http://localhost:8080/api/login

curl -i -b 'APPSESSION=<value from Set-Cookie>' http://localhost:8080/api/whoami

curl -i -X POST -b 'APPSESSION=<value>' http://localhost:8080/api/logout
```

`./smoke-test.sh` does all of that against a throwaway Tomcat instance (its own `CATALINA_BASE` under
`build/`, its own ports, stopped on exit) and asserts on the headers that come off the wire. It exits
77 with a `SKIP` when no Tomcat 10.1+ install is present or the port is busy. Override with
`TOMCAT_HOME=/opt/tomcat PORT=8099 ./smoke-test.sh`.

### Endpoints

| Method | Path | Behaviour |
| --- | --- | --- |
| `POST` | `/api/login` | `username`/`password` form params. `200` + `Set-Cookie` on success, `401` with no cookie on failure, `500` if the verifier is unconfigured. `405` for `GET`. |
| `GET` | `/api/whoami` | `200` with the principal when the cookie names a live session, else `401`. |
| `POST` | `/api/logout` | `204` always. Removes the session server side and overwrites the cookie (`Max-Age=0`, same name and `Path`). `405` for `GET`, so a stray link cannot log anyone out. |

## Configuration

All `context-param` values in `WEB-INF/web.xml`, read once by `AuthContextListener`:

| Parameter | Default | Notes |
| --- | --- | --- |
| `cookieName` | `APPSESSION` | Must be an RFC 6265 token. |
| `cookiePath` | `/` | Must be absolute; set to the deployment's context path. |
| `secureCookie` | `true` | Set to `false` only to debug over plain http on localhost. |
| `httpOnlyCookie` | `true` | Turning this off makes the cookie readable by any script on the origin. |
| `sameSite` | `Lax` | `Strict`, `Lax`, `None`. `None` without `Secure` throws at start-up. |
| `maxAgeSeconds` | `-1` | `-1` browser session, `0` delete-now (used by logout), positive for a persistent cookie. |
| `sessionTtlMinutes` | `30` | Server-side deadline, independent of the cookie's lifetime. Keep at or below the `session-config` timeout. |

`SessionCookieConfig`'s constructor rejects a relative path, a cookie name containing a separator or
whitespace, `SameSite=None` without `Secure`, and a nonsensical negative lifetime - so a
misconfiguration surfaces as a failed start-up, not as a weak cookie served silently.

## What this is not, and what to change before production

- **`EnvironmentCredentialVerifier` is a placeholder.** One credential from a system property, no
  user store, no salted password hash, no lockout or rate limiting. Replace it by publishing a
  different `CredentialVerifier` in `AuthContextListener`; nothing else needs to change. Comparisons
  are constant-time (`MessageDigest.isEqual`) so the placeholder is at least not a password oracle.
- **`InMemorySessionStore` is single-JVM and non-durable.** Restarting logs everyone out; it will not
  survive a second node. Swap in a shared store (Redis, a database table) behind the same surface, and
  keep the constant-time comparison and the absolute deadline.
- **No CSRF token.** `SameSite=Lax` blocks the cross-site POST case, which is why the state-changing
  endpoints are POST-only. A login form is not CSRF-protected here, so adding an explicit
  synchroniser token (or `fetch` with a custom header) is the next step.
- **No HTTPS configuration.** `Secure` is emitted on the cookie, but TLS, the redirect from http, and
  HSTS preload belong to the deployment. HSTS is only sent when `request.isSecure()` is true.
- **The store keys on the identifier.** A store that instead looked up a *user* by an identifier would
  need the constant-time comparison on the lookup path; `SessionIdentifier#matches` exists so that
  call site has something correct to use.
- Session identifiers are never logged in full (`describe()` redacts to a 4/4-character fingerprint)
  and never echoed in a response body - login returns a SHA-256 fingerprint instead, since anything
  that can read the body can also be script on the origin, which is what `HttpOnly` is there to stop.

## How this was verified

- `./run-tests.sh` - 116 assertions over `java.lang.reflect.Proxy` doubles of the Servlet API. The
  response double renders `addCookie` the way an RFC 6265 cookie processor does, so checks assert on
  emitted header text. Covers the attribute set, header integrity (including a simulated container
  that drops `Secure` or emits a CRLF), identifier rejection of 14 crafted payloads
  (`abc; Domain=attacker.example`, `abc\r\nSet-Cookie: admin=y`, NUL, U+0085, oversize, ...),
  uniqueness across 2000 minted values, the store lifecycle, fixation, and every endpoint's
  success/anon/tampered/crafted/duplicate/expired paths.
- `./smoke-test.sh` - the same properties against real Tomcat 10.1.59, asserting on `curl -D -`
  output: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`, no `Max-Age`, no second
  `JSESSIONID`, 43-character identifier, cookie-only re-authentication, tamper/craft rejection,
  logout clearing, replay-after-logout rejection, and `WEB-INF` not reachable over HTTP.
- Both compile clean under `javac -Xlint:all -Werror`.
- Mutation-checked: 11 deliberate defects (drop `HttpOnly`, drop `Secure`, allow `SameSite=None`
  without `Secure`, unpin `Path`, remove identifier validation, shorten minted identifiers, keep the
  pre-authentication identifier, never attach the cookie, first-duplicate-wins, ignore the expiry
  deadline, remove the header assertion) were each applied to a throwaway copy of the tree; all 11
  were caught by a failing check, and removing `addCookie` additionally trips the fail-closed
  assertion.

Compiling against the real `jakarta.servlet-api` jar and then running the war on Tomcat matters here
for one specific reason: `SameSite` is only reachable through `Cookie#setAttribute("SameSite", ...)`,
a Servlet 6.0 API, and whether it reaches the wire depends on the container's cookie processor. The
`Set-Cookie` header above is Tomcat's own output.
