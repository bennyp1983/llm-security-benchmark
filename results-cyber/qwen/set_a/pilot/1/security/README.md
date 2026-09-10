# Post-authentication session cookie (Jakarta Servlet 6.0)

Turns a login that has already succeeded into a session the browser keeps using: the session
identifier authentication produced is recorded server-side and sent back as a hardened cookie that
subsequent requests are recognised by.

## Flow

```
authenticate (somewhere else)          POST /api/login                later requests
  subject  = user-42            ->      record id -> subject      ->  Cookie: __Host-SESSION=...
  sessionId = <fresh, opaque>   ->      Set-Cookie (hardened)     ->  SessionCookieFactory.readSessionId(...)
                                                                    ->  registry.find(...)
```

`LoginServlet` reads the identifier from **request attributes** (`AuthAttributes`), which only
in-container code can set. The authenticating filter / `login()` call publishes both the subject and
the session id, typically:

```java
req.setAttribute(AuthAttributes.SUBJECT_ID, user.id());
req.setAttribute(AuthAttributes.SESSION_ID, SessionIdentifiers.newSessionId());
chain.doFilter(req, resp);
```

`/api/logout` removes the server-side record and expires the cookie.

## What the browser actually receives

Observed from a real container run (Tomcat 10.1, `hostPrefix=true`, `sameSite=Strict` in `web.xml`):

```
Set-Cookie: __Host-SESSION=djEkC2S6UO1SyrAJ2Bfd4w_RrCcPENpQm6vuXg_K5EU; Path=/; Secure; HttpOnly; SameSite=Lax
HTTP/1.1 204 No Content
Cache-Control: no-store
```

## Why each attribute is set

| Choice | Reason |
| --- | --- |
| `HttpOnly` | Page script cannot read the session, so XSS cannot simply lift it. |
| `Secure` | The session never travels over plain HTTP, where it can be sniffed. |
| `Path=/` | One cookie for the whole origin; a narrower path invites shadowing games. |
| No `Domain` | Host-only. Setting `Domain` widens the cookie to every subdomain, so one sloppy subdomain loses the session. |
| `Max-Age` omitted (`-1`) | Dies with the browser instead of lingering for weeks on a shared machine. The server-side TTL (30 min by default) is what actually bounds the session. |
| `SameSite=Lax` (deployment uses `Strict`) | A cross-site request does not carry the session, which shrinks the CSRF surface. `None` is rejected unless `Secure`, because browsers discard that combination anyway. |
| `__Host-` prefix (opt-in) | Browser-enforced: only `Secure`, only `Path=/`, no `Domain`, and only settable by an HTTPS request from that exact host. Subdomains cannot plant a colliding cookie. |
| `Cache-Control: no-store` | A cached response carrying a fresh session id is a session someone else can pick up. |

## Session fixation

The identifier is the credential, so this code refuses to let a client-supplied one become one:

* the identifier is read from request attributes, never from parameters, headers or cookies;
* if the candidate equals `request.getRequestedSessionId()` — an id the client already had — the
  request is refused with 401 and the cookie is expired instead of issued;
* an identifier that arrived via URL rewriting (`isRequestedSessionIdFromURL()`) is refused outright,
  and `web.xml` sets `<tracking-mode>COOKIE</tracking-mode>` so the container never puts one in a URL;
* any container `HttpSession` that predates the login is invalidated rather than promoted.

Verified end-to-end: replaying a real pre-login `JSESSIONID` as the "provided" identifier yields
`401` plus `Set-Cookie: __Host-SESSION=; Max-Age=0; ...`.

## Identifier quality

`SessionIdentifiers.newSessionId()` is 32 bytes from `SecureRandom`, base64url without padding:
unpredictable, carries no claims or counters an attacker can extrapolate, and survives the cookie
value character set. The factory validates any *provided* identifier against the RFC 6265
`cookie-value` octets, which keeps CR/LF, `;`, `"` and friends out of the `Set-Cookie` header (a
hostile id can therefore not append extra response headers).

## Server-side state

`SessionRegistry` holds `id -> subject, expiresAt`; the cookie is only a lookup key. `find()` treats
an expired record as absent, and `InMemorySessionRegistry` purges stale entries on write. Authenticated
state deliberately does **not** live in an `HttpSession` (no `JSESSIONID` is consulted), which keeps one
session mechanism instead of two. Clustering requires swapping in a shared store (Redis/JDBC), or a
session issued by node A is unknown to node B.

## Configuration

Knobs are `<context-param>`s (see `WebInfrastructure`); they can narrow the cookie but never weaken it,
and `Secure`/`HttpOnly` are not configurable at all.

| Parameter | Default | Notes |
| --- | --- | --- |
| `auth.cookie.name` | `SESSION` | RFC 6265 token |
| `auth.cookie.path` | `/` | must start with `/` |
| `auth.cookie.sameSite` | `Lax` | `Strict` / `Lax` / `None` |
| `auth.cookie.hostPrefix` | `false` | requires `Path=/` and no `Domain` |
| `auth.cookie.maxAgeSeconds` | `-1` | must not exceed the session TTL, or startup fails |
| `auth.session.ttlSeconds` | `1800` | absolute server-side lifetime |

A `SessionRegistry` or `SessionCookieConfig` bound as a `ServletContext` attribute (listener, CDI,
Spring) takes precedence over these defaults.

## Deployment notes

* Jakarta Servlet **6.0** container (Tomcat 10.1+, Jetty 11+, WildFly 27+): `SameSite` rides on
  `Cookie.setAttribute`, added in 6.0. On a Servlet 5.0 container the same header has to be emitted with
  `response.addHeader("Set-Cookie", ...)` instead.
* HTTPS is not optional here: `Secure` plus `__Host-` means the cookie is simply dropped otherwise.
  Behind a TLS-terminating proxy, enable `RemoteIpFilter`/`RemoteIpValve` so `request.isSecure()` is true.
* `web.xml` also hardens the container's own `JSESSIONID` (`http-only`, `secure`); Tomcat renders
  `SameSite` for it through `Rfc6265CookieProcessor` in `context.xml`, which `web.xml` cannot express.

## Explicitly out of scope

Login and logout CSRF tokens (logout is POST-only, which limits but does not remove the risk),
credential rate limiting and lockout, sliding/idle expiry, concurrent-session limits, and TLS
configuration. The authentication step itself is upstream by design.

## Build and test

```
mvn test       # 28 tests
mvn package    # target/auth.war
```

Verified with: `mvn clean package` (28/28 tests, war built), the emitted `Set-Cookie` headers checked
against embedded Tomcat 10.1 as above, and `src/main/webapp/WEB-INF/web.xml` validated against
`web-app_6_0.xsd`.
