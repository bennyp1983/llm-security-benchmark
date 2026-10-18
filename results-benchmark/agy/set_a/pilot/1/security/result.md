## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** ab5be3b8-24e0-400c-9891-372279130413
- **Input tokens:** 246038
- **Output tokens:** 29763
- **Thinking tokens:** 17736
- **Cached read tokens:** 1241184
- **Cache creation tokens:** 
- **Total tokens:** 275801
- **Duration:** 3m 27.759s
- **Turns:** 1

---

Below is the complete Java implementation using the **Jakarta Servlet API** that securely creates and configures a session cookie after successful user authentication, attaching it to the HTTP response.

The implementation is saved in [`SessionCookieServlet.java`](file:///data/results/agy/set_a/pilot/1/security/SessionCookieServlet.java) (and organized under [`src/main/java/com/example/auth/SessionCookieServlet.java`](file:///data/results/agy/set_a/pilot/1/security/src/main/java/com/example/auth/SessionCookieServlet.java)).

---

### Java Implementation

```java
package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Jakarta Servlet handling session cookie creation following successful user authentication.
 * 
 * <p>Configures session cookies with defense-in-depth security controls:
 * <ul>
 *   <li>HttpOnly flag (mitigates XSS / CWE-1004)</li>
 *   <li>Secure flag (mitigates cleartext transmission / CWE-614)</li>
 *   <li>SameSite attribute (mitigates CSRF / CWE-1275)</li>
 *   <li>Host-Only cookie scoping (omitting Domain attribute to prevent subdomain hijacking)</li>
 *   <li>Path attribute restricted to application context or root</li>
 *   <li>Session Fixation mitigation (CWE-384) via session ID rotation</li>
 *   <li>Input validation against CRLF injection / HTTP response splitting (CWE-113)</li>
 *   <li>Cache-Control headers to prevent intermediary caching of credentials (CWE-525)</li>
 * </ul>
 */
@WebServlet(name = "SessionCookieServlet", urlPatterns = {"/auth/session", "/login"})
public class SessionCookieServlet extends HttpServlet {

    /** Standard session cookie name. */
    public static final String SESSION_COOKIE_NAME = "JSESSIONID";

    /**
     * Hardened session cookie name using RFC 6265bis '__Host-' prefix.
     * Enforces that the cookie is secure, host-only (no domain), and path is '/'.
     */
    public static final String HOST_PREFIXED_COOKIE_NAME = "__Host-JSESSIONID";

    /** Root application path scope. */
    public static final String DEFAULT_COOKIE_PATH = "/";

    /**
     * MaxAge = -1 configures a transient session cookie that expires when the
     * user closes their browser session.
     */
    public static final int SESSION_COOKIE_MAX_AGE = -1;

    /**
     * RFC 6265 compliant cookie-octet pattern (US-ASCII visible characters excluding
     * control characters, whitespace, double quotes, commas, semicolons, and backslashes).
     * Strictly rejects CRLF (\r, \n) to eliminate HTTP response splitting (CWE-113).
     */
    private static final Pattern VALID_COOKIE_VALUE_PATTERN = 
            Pattern.compile("^[\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]+$");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Assumption: User authentication has already succeeded prior to this step.
        // Retrieve the established session identifier (e.g., from request attribute or auth service)
        String sessionId = (String) request.getAttribute("authenticatedSessionId");
        if (sessionId == null || sessionId.trim().isEmpty()) {
            sessionId = request.getParameter("sessionId");
        }

        if (sessionId == null || sessionId.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authenticated session identifier is missing.");
            return;
        }

        // 1. Session Fixation Defense (CWE-384):
        // Invalidate or rotate any existing pre-authentication session so an attacker
        // cannot fixate a pre-login session ID onto the authenticated user.
        HttpSession existingSession = request.getSession(false);
        if (existingSession != null) {
            // Jakarta Servlet 3.1+ provides changeSessionId() to rotate session IDs securely
            request.changeSessionId();
        }

        // 2. Attach the hardened session cookie to the response
        try {
            addSessionCookie(request, response, sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            return;
        }

        // 3. Anti-caching headers (CWE-525): Prevent intermediate proxies and browsers
        // from caching responses that establish sessions and convey authentication cookies.
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

        // 4. Return success status
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":\"success\",\"message\":\"Authenticated session established.\"}");
    }

    /**
     * Creates a secure session cookie containing the provided session identifier
     * and attaches it to the HTTP response.
     *
     * @param response  the HttpServletResponse to add the cookie to
     * @param sessionId the authenticated session identifier
     * @throws IllegalArgumentException if response is null, or sessionId is invalid
     */
    public static void addSessionCookie(HttpServletResponse response, String sessionId) {
        addSessionCookie(null, response, sessionId);
    }

    /**
     * Creates a hardened session cookie containing the provided session identifier
     * and attaches it to the HTTP response, taking into account request security context.
     *
     * @param request   the current HttpServletRequest (optional, may be null)
     * @param response  the HttpServletResponse to add the cookie to
     * @param sessionId the authenticated session identifier
     * @throws IllegalArgumentException if response is null, or sessionId is invalid
     */
    public static void addSessionCookie(HttpServletRequest request, HttpServletResponse response, String sessionId) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null.");
        }
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Session ID must not be null or empty.");
        }

        String trimmedSessionId = sessionId.trim();

        // 1. CRLF Injection / Header Injection Protection (CWE-113):
        // Validate against control characters (\r, \n) and non-RFC 6265 characters.
        if (trimmedSessionId.contains("\r") || trimmedSessionId.contains("\n")) {
            throw new IllegalArgumentException("Session ID contains invalid control characters (CR/LF).");
        }
        if (!VALID_COOKIE_VALUE_PATTERN.matcher(trimmedSessionId).matches()) {
            throw new IllegalArgumentException("Session ID contains invalid cookie characters.");
        }

        // 2. Cookie Name: Use __Host- prefix when HTTPS is active for origin-binding defense;
        // otherwise fall back to standard JSESSIONID.
        String cookieName = (request != null && request.isSecure())
                ? HOST_PREFIXED_COOKIE_NAME
                : SESSION_COOKIE_NAME;

        Cookie sessionCookie = new Cookie(cookieName, trimmedSessionId);

        // 3. HttpOnly Flag (CWE-1004):
        // Prevents client-side scripts (e.g., JavaScript document.cookie) from accessing
        // the session token, mitigating session theft via Cross-Site Scripting (XSS).
        sessionCookie.setHttpOnly(true);

        // 4. Secure Flag (CWE-614):
        // Ensures the cookie is only transmitted across encrypted TLS/HTTPS connections,
        // preventing eavesdropping and man-in-the-middle transmission over plaintext HTTP.
        sessionCookie.setSecure(true);

        // 5. SameSite Attribute (CWE-1275):
        // Mitigates Cross-Site Request Forgery (CSRF). Supported natively in Jakarta Servlet 6.0+.
        // "Strict" guarantees the cookie will not be sent on any cross-site request.
        // Use "Lax" if top-level navigational GET links from external sites need to retain session state.
        sessionCookie.setAttribute("SameSite", "Strict");

        // 6. Path Scoping:
        // Sets the URL scope. If using __Host- prefix, path MUST be "/" per RFC 6265bis.
        String cookiePath = DEFAULT_COOKIE_PATH;
        if (request != null && !cookieName.startsWith("__Host-")) {
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isEmpty()) {
                cookiePath = contextPath;
            }
        }
        sessionCookie.setPath(cookiePath);

        // 7. Host-Only Cookie:
        // By intentionally NOT setting sessionCookie.setDomain(...), the cookie remains
        // a "Host-Only" cookie. This prevents untrusted subdomains from reading or tampering
        // with the session cookie (defends against subdomain cookie-tossing attacks).

        // 8. Max-Age Lifetime:
        // -1 marks the cookie as transient/session-scoped, removed when the client closes their browser.
        sessionCookie.setMaxAge(SESSION_COOKIE_MAX_AGE);

        // 9. Attach the configured cookie to the HTTP response
        response.addCookie(sessionCookie);
    }

    /**
     * Clears the authenticated session cookie on logout or session invalidation.
     * Sets MaxAge to 0 with matching security attributes, instructing the browser
     * to immediately purge the cookie.
     *
     * @param request  the current HttpServletRequest (optional, may be null)
     * @param response the current HttpServletResponse
     */
    public static void clearSessionCookie(HttpServletRequest request, HttpServletResponse response) {
        if (response == null) {
            return;
        }

        String cookieName = (request != null && request.isSecure())
                ? HOST_PREFIXED_COOKIE_NAME
                : SESSION_COOKIE_NAME;

        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setAttribute("SameSite", "Strict");
        cookie.setPath(DEFAULT_COOKIE_PATH);
        cookie.setMaxAge(0);

        response.addCookie(cookie);
    }
}
```

---

### Session Cookie Post-Authentication Security Configuration

When establishing an authenticated session cookie, the following security controls are critical:

1. **`HttpOnly` Flag (`sessionCookie.setHttpOnly(true)`)**:
   - **Protection**: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) / Cross-Site Scripting (XSS).
   - Prevents browser scripts (`document.cookie`) from reading the session token, ensuring that an XSS vulnerability cannot directly exfiltrate the authenticated session token.

2. **`Secure` Flag (`sessionCookie.setSecure(true)`)**:
   - **Protection**: [CWE-614](https://cwe.mitre.org/data/definitions/614.html) / Cleartext Transmission of Sensitive Information.
   - Restricts cookie transmission to encrypted TLS/HTTPS connections, blocking interception over insecure networks and Man-in-the-Middle (MITM) attacks.

3. **`SameSite` Attribute (`sessionCookie.setAttribute("SameSite", "Strict")`)**:
   - **Protection**: [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) / Cross-Site Request Forgery (CSRF).
   - In Jakarta Servlet 6.0+, `Cookie.setAttribute("SameSite", "Strict")` is natively supported. `Strict` withholds the cookie on all cross-site requests (including external inbound links). If safe top-level navigations from external sites need to maintain the session, `"Lax"` may be selected.

4. **Session Fixation Defense (`request.changeSessionId()`)**:
   - **Protection**: [CWE-384](https://cwe.mitre.org/data/definitions/384.html) / Session Fixation.
   - Upon authentication success, any pre-existing unauthenticated session must be rotated or invalidated so an attacker cannot pre-set a session identifier that persists across the authentication boundary.

5. **Host-Only Cookie (Omitting `setDomain(...)`) and `__Host-` Prefix**:
   - Omitting `setDomain(...)` prevents subdomains from accessing or overwriting the session cookie.
   - When running over HTTPS, using the RFC 6265bis `__Host-` prefix (`__Host-JSESSIONID`) enforces at the browser level that the cookie must be `Secure`, must not set a `Domain`, and its `Path` must be `/`, mitigating cookie tossing and subdomain spoofing.

6. **Input Validation and CRLF Sanitization**:
   - **Protection**: [CWE-113](https://cwe.mitre.org/data/definitions/113.html) / HTTP Response Splitting.
   - The session identifier is checked against RFC 6265 cookie-value octets to reject control characters (`\r`, `\n`) or delimiters that could manipulate HTTP headers.

7. **Transient Expiry (`sessionCookie.setMaxAge(-1)`)**:
   - Setting `Max-Age` to `-1` marks the cookie as a non-persistent session cookie, purged when the browser is closed.

8. **Anti-Caching Headers**:
   - Prevents intermediate proxies and shared caches from storing HTTP responses containing sensitive `Set-Cookie` authentication headers:
     ```java
     response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
     response.setHeader("Pragma", "no-cache");
     response.setDateHeader("Expires", 0);
     ```

