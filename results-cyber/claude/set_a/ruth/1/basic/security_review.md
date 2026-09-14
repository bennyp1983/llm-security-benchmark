# Security Review: SessionCookieServlet (Jakarta Servlet session cookie issuance)

## 1. Executive Summary
`SessionCookieServlet` issues the `APP_SESSION` session cookie after another component has already authenticated the user. It can be used in two ways: through the static helper `addSessionCookie(request, response, sessionId)`, or by forwarding to the `/auth/session` endpoint with the session identifier stored in a server-side request attribute. The endpoint then sets the cookie and sends a `303 See Other` redirect to the application root.

Overall the component is well hardened:
- The cookie is `HttpOnly`, `Secure`, `SameSite=Lax` and host-only.
- The identifier is checked against a strict allow-list, so it can't inject cookie attributes or headers.
- The response is marked `Cache-Control: no-store`.
- The identifier is never logged.
- A direct client request without the server-side attribute gets `401`.

No Critical, High or Medium issues were found. Three Low-severity hardening issues remain:
- **SEC-01:** The helper accepts any well-formed identifier supplied by the caller. It doesn't check that the identifier is fresh or unpredictable, and it doesn't reject one the client already presented. Session-fixation protection therefore depends entirely on the calling code (CWE-384).
- **SEC-02:** The cookie has no `__Host-` prefix. A sibling subdomain can plant ("toss") an `APP_SESSION` cookie for the parent domain, which gives a fixation or login-CSRF path (CWE-384).
- **SEC-03:** The cookie `Path` and the redirect `Location` are built from `HttpServletRequest.getContextPath()`. Some containers return this value undecoded and unnormalised from the request URI, which can produce a broken cookie scope or a protocol-relative redirect (CWE-601).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/SessionCookieServlet.java` | Servlet mapped at `/auth/session` plus a public static helper that creates the session cookie for an already-authenticated user and redirects to the app root. | Session management (accepting and issuing the session identifier), cookie security attributes (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Max-Age`), validating input before it goes into the `Set-Cookie` header, the authentication gate based on a request attribute, building the redirect `Location` header, the `Cache-Control` header, and logging of rejected identifiers. |
| `README.md` | Documentation: behaviour, assumptions, how to compile, package and deploy. | States security assumptions the code doesn't enforce: a fresh `SecureRandom` identifier at every login, a server-side session store, timeouts and logout invalidation. Contains no executable code. |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Generation and run metadata (task prompts, hash, run log/JSON). | No application code; read only to confirm this. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: The router workflow. Used to understand the file, pull out keywords (session cookie, cookie attributes, authentication, redirect, cache headers, logging) and select the specialised skills below.
- `performing-security-headers-audit`: Applied to the cookie attributes (`Secure`, `HttpOnly`, `SameSite`, `Path`, `Domain`, `Max-Age`, the `__Host-`/`__Secure-` prefixes) and to `Cache-Control` (lines 115-124). Led to SEC-02.
- `testing-api-authentication-weaknesses`: Applied to session management: identifier entropy and freshness, fixation, expiry and revocation (lines 52, 104-121). Led to SEC-01.
- `performing-csrf-attack-simulation`: Applied to the `SameSite=Lax` choice and to whether a cross-site GET or POST to `/auth/session` could cause a state change or login CSRF (lines 55-71, 120).
- `testing-for-open-redirect-vulnerabilities`: Applied to the `303` redirect and how its `Location` value is built (lines 82-83, 127-130). Led to SEC-03.
- `testing-for-broken-access-control` / `bypassing-authentication-with-forced-browsing`: Applied to direct, unauthenticated requests to the `@WebServlet` endpoint and to the attribute-based gate (lines 34, 66-71).
- `testing-for-sensitive-data-exposure`: Applied to caching of the credential-bearing response and to leakage of the identifier through logs or error responses (lines 76-77, 108-109, 124).
- General OWASP Top 10 / CWE knowledge, because no library skill matched: HTTP response splitting and cookie attribute injection (CWE-113), log injection (CWE-117), error-message information exposure (CWE-209), and how containers normalise `getContextPath()`.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Session identifier freshness and unpredictability not enforced; client-presented identifier not rejected (session fixation relies on caller) | Low | CWE-384 | `src/main/java/com/example/auth/SessionCookieServlet.java:104-115` |
| SEC-02 | Session cookie lacks the `__Host-` prefix, allowing cookie tossing from sibling subdomains | Low | CWE-384 | `src/main/java/com/example/auth/SessionCookieServlet.java:43` |
| SEC-03 | Cookie `Path` and redirect `Location` built from the raw, unnormalised request context path | Low | CWE-601 | `src/main/java/com/example/auth/SessionCookieServlet.java:127-130` |

## 5. Detailed Findings

### SEC-01: Session identifier freshness and unpredictability not enforced; client-presented identifier not rejected (session fixation relies on caller)
- **Severity:** Low
- **CWE:** CWE-384: Session Fixation
- **Location:** `src/main/java/com/example/auth/SessionCookieServlet.java:52`, `src/main/java/com/example/auth/SessionCookieServlet.java:104-115`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookieServlet.java:52
    private static final Pattern VALID_SESSION_ID = Pattern.compile("[A-Za-z0-9._~+/=-]{16,4096}");
// src/main/java/com/example/auth/SessionCookieServlet.java:104-115
    public static void addSessionCookie(HttpServletRequest request, HttpServletResponse response, String sessionId) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");
        if (sessionId == null || !VALID_SESSION_ID.matcher(sessionId).matches()) {
            // Do not include the value itself: it may be a real credential that must not reach logs.
            throw new IllegalArgumentException("session identifier is missing or malformed");
        }
        if (response.isCommitted()) {
            throw new IllegalStateException("response already committed; cannot add session cookie");
        }

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);
```

**Why it is a problem:** This component is the single place where an authenticated session identifier is bound to the browser. Yet it accepts any caller-supplied string that matches a character-set and length pattern:
- `"0000000000000000"` or `"aaaaaaaaaaaaaaaa"` passes the check. The 16-character minimum is only 64 bits even for random hex, and it guarantees no entropy at all (CWE-330/CWE-331 aspect).
- The helper doesn't generate the identifier itself.
- The helper doesn't check whether the browser already presented the same `APP_SESSION` value before login.

If a caller reuses an identifier from before authentication, the classic fixation attack works and this code quietly "upgrades" the attacker-planted identifier to an authenticated session. Example callers: one that copies the incoming cookie value, or one that reuses an anonymous session ID. The attacker plants the ID through a sibling subdomain (see SEC-02), a link, or an XSS on another host, and the victim then logs in. The README lists freshness as a caller responsibility, but no code enforces it. The public helper makes the insecure pattern easy to use, so this is rated Low (defence in depth) rather than higher.

**Fix:** Generate identifiers inside the component with `SecureRandom`, at 256 bits. Refuse any identifier the client already sent in the request. Raise the minimum length so even hex-encoded values carry at least 128 bits.
```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

    private static final SecureRandom RANDOM = new SecureRandom();

    // 32 chars = 128 bits for hex; Base64URL of 32 random bytes is 43 chars.
    private static final Pattern VALID_SESSION_ID = Pattern.compile("[A-Za-z0-9._~+/=-]{32,4096}");

    /** Generates a fresh, unpredictable 256-bit session identifier. Call at every successful login. */
    public static String newSessionId() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static void addSessionCookie(HttpServletRequest request, HttpServletResponse response, String sessionId) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");
        if (sessionId == null || !VALID_SESSION_ID.matcher(sessionId).matches()) {
            // Do not include the value itself: it may be a real credential that must not reach logs.
            throw new IllegalArgumentException("session identifier is missing or malformed");
        }
        // Session fixation guard: never bind an identifier the client already presented before login.
        Cookie[] presented = request.getCookies();
        if (presented != null) {
            byte[] candidate = sessionId.getBytes(StandardCharsets.US_ASCII);
            for (Cookie c : presented) {
                if (SESSION_COOKIE_NAME.equals(c.getName()) && c.getValue() != null
                        && MessageDigest.isEqual(c.getValue().getBytes(StandardCharsets.US_ASCII), candidate)) {
                    throw new IllegalArgumentException("session identifier was supplied by the client; generate a new one");
                }
            }
        }
        if (response.isCommitted()) {
            throw new IllegalStateException("response already committed; cannot add session cookie");
        }

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);
        // ... attributes unchanged ...
    }
```

### SEC-02: Session cookie lacks the `__Host-` prefix, allowing cookie tossing from sibling subdomains
- **Severity:** Low
- **CWE:** CWE-384: Session Fixation
- **Location:** `src/main/java/com/example/auth/SessionCookieServlet.java:43`, `src/main/java/com/example/auth/SessionCookieServlet.java:115-118`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookieServlet.java:43
    public static final String SESSION_COOKIE_NAME = "APP_SESSION";
// src/main/java/com/example/auth/SessionCookieServlet.java:115-118
        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(contextRoot(request));
```

**Why it is a problem:** The cookie is correctly host-only (no `Domain` attribute), but a plain name doesn't stop *other* hosts from writing a cookie with the same name. Suppose someone controls or compromises any sibling subdomain, such as `blog.example.com` or a user-content host. They can send `Set-Cookie: APP_SESSION=<attacker value>; Domain=example.com; Path=/app/auth; Secure`. The browser then sends both cookies to the application, with the more specific path first. Many cookie parsers take the first value, so the application reads the attacker's identifier. This can:
- log the victim into the attacker's session (login CSRF), or
- fix an identifier for the attacker to use, combined with SEC-01.

The `__Host-` prefix makes browsers reject such a cookie unless it is `Secure`, has `Path=/`, and has no `Domain` attribute. That shuts out cookie tossing entirely. The security-headers-audit skill explicitly checks for `__Host-`/`__Secure-` prefixes on session cookies.

**Fix:** Rename the cookie with the `__Host-` prefix and set `Path=/`, which the prefix requires. Keep the host-only scope (never call `setDomain`). This widens the cookie to every application on the same host. If that is unacceptable, host the application on its own origin rather than dropping the prefix.
```java
    /** Name of the cookie that carries the session identifier (__Host- prefix blocks subdomain cookie tossing). */
    public static final String SESSION_COOKIE_NAME = "__Host-APP_SESSION";

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");            // required by the __Host- prefix; do not set a Domain attribute
        cookie.setMaxAge(-1);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
```

### SEC-03: Cookie `Path` and redirect `Location` built from the raw, unnormalised request context path
- **Severity:** Low
- **CWE:** CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
- **Location:** `src/main/java/com/example/auth/SessionCookieServlet.java:127-130` (used at lines 83 and 118)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookieServlet.java:127-130
    private static String contextRoot(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath == null || contextPath.isEmpty() ? "/" : contextPath + "/";
    }
// src/main/java/com/example/auth/SessionCookieServlet.java:82-83
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        response.setHeader("Location", contextRoot(request));
```

**Why it is a problem:** `HttpServletRequest.getContextPath()` returns the part of the *request URI* that selected the context. The Servlet specification doesn't require it to be decoded, and containers such as Apache Tomcat document that it is "not decoded which also implies it is not normalised". The attacker controls the URL used to reach the login flow, so the value can vary for the same deployed context:
- `/%61pp`
- `/foo/../app`
- `//app` (when merged slashes are accepted)

It then flows into two sinks:
1. **`Location` header (line 83):** A context path of `//app` produces `Location: //app/`. That is a protocol-relative URL, which the browser resolves to the *host* `app`, sending the freshly logged-in user off-site. The attacker can only pick a host name equal to the context name, so impact is limited. It is still a redirect target shaped by attacker input.
2. **Cookie `Path` (line 118):** The cookie is issued for `Path=/%61pp/` or `//app/`, which the browser never matches against the canonical `/app/...` URLs. The session cookie is silently not sent, and a stale or planted cookie (SEC-02) may keep being used.

The redirect target is not taken from a request parameter, so this is not a classic open redirect, which is why it is rated Low.

**Fix:** Use the canonical, container-configured context path from `ServletContext`, which doesn't depend on the request URI's spelling. As defence in depth, collapse any leading slashes so the value can never become protocol-relative.
```java
    private static String contextRoot(HttpServletRequest request) {
        // Canonical, configured context path ("" for the root context), independent of the request URI spelling.
        String contextPath = request.getServletContext().getContextPath();
        if (contextPath == null || contextPath.isEmpty()) {
            return "/";
        }
        // Never allow a protocol-relative value such as "//host".
        return "/" + contextPath.replaceFirst("^/+", "") + "/";
    }
```

## 6. Verified Controls and Checks With No Finding
- **Cookie `HttpOnly` (CWE-1004):** set at line 116. JavaScript can't read the session cookie.
- **Cookie `Secure` (CWE-614):** set at line 117. The cookie is only sent over HTTPS.
- **Cookie `SameSite` (CWE-1275):** `SameSite=Lax` at line 120 through `Cookie.setAttribute` (Servlet 6.0). Cross-site subrequests and POSTs don't carry the cookie. Lax is an appropriate choice for a primary session cookie that must survive top-level navigation.
- **Host-only scope:** `setDomain` is never called (lines 115-121), so the cookie isn't shared with subdomains. The reverse direction, subdomains writing the cookie, is covered in SEC-02.
- **Cookie lifetime:** `setMaxAge(-1)` at line 119 makes this a browser-session cookie, not a persistent credential. Server-side expiry is documented as the caller's job (README) and is out of this file's scope.
- **HTTP response splitting / cookie attribute injection (CWE-113, CWE-20):** the allow-list regex at line 52 is enforced with `matches()` (whole string) at line 107. It excludes CR, LF, `;`, `,`, whitespace, quotes and control characters, and every allowed character is a valid RFC 6265 `cookie-octet`. The cookie name is a constant (line 43).
- **Authentication gate / forced browsing (CWE-306, CWE-425):** lines 67-71 require a `String` request attribute. HTTP clients can't set request attributes, so a direct `GET`/`POST` to `/auth/session` returns `401` and issues no cookie. No request parameter, header or cookie is ever used as the session identifier.
- **CSRF / login CSRF (CWE-352):** because of that gate, a cross-site request to `/auth/session` can't bind an attacker-chosen session, and `doGet` (lines 55-58) has no effect without server-side authentication.
- **Open redirect through parameters (CWE-601):** the redirect target (line 83) is never read from request parameters such as `next`, `url` or `redirect`. The only residual concern is the context-path normalisation in SEC-03.
- **Caching of credential-bearing responses (CWE-525):** `Cache-Control: no-store` is set at line 124 whenever the cookie is issued.
- **Sensitive data in logs and error responses (CWE-532, CWE-209):** the rejection path logs a constant message and deliberately leaves out the identifier (lines 76, 108-109). The client gets only a bare `500` via `sendError` (line 77), with no exception details.
- **Log injection (CWE-117):** the logged text is a constant from line 109, with no attacker-controlled content.
- **Committed-response handling:** line 111 refuses to add the cookie after the response is committed, so a cookie can't be silently dropped while the caller assumes success.
- **Null handling:** `Objects.requireNonNull` at lines 105-106 and the `sessionId == null` check at line 107.
- **Hard-coded secrets, cryptography, insecure deserialization, SQL/command/path injection:** none present. The file has no credentials, keys, crypto primitives, database, OS or file access, and no deserialization of untrusted data (`serialVersionUID` at line 37 is only the standard `HttpServlet` serialization marker).
- **Out of scope (documented in README, not implementable in this file):** a server-side session store linking identifier to user, idle and absolute timeouts, logout invalidation, and application-wide HSTS. Enforcing identifier freshness in code is covered by SEC-01.
