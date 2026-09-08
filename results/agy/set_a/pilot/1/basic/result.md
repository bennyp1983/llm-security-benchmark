## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** 6316a34f-e180-4ed1-9fe5-7f8b06d22533
- **Input tokens:** 179241
- **Output tokens:** 17201
- **Thinking tokens:** 8702
- **Cached read tokens:** 748366
- **Cache creation tokens:** 
- **Total tokens:** 196442
- **Duration:** 2m 6.98s
- **Turns:** 1

---

Below is the complete Java implementation using the **Jakarta Servlet API** to create and attach a secure session cookie to the HTTP response after successful authentication.

The implementation is saved in [`SessionCookieServlet.java`](file:///data/results/agy/set_a/pilot/1/basic/SessionCookieServlet.java).

---

### Implementation

```java
package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Servlet handling user session cookie creation following successful authentication.
 */
@WebServlet(name = "SessionCookieServlet", urlPatterns = {"/auth/session", "/login"})
public class SessionCookieServlet extends HttpServlet {

    public static final String SESSION_COOKIE_NAME = "JSESSIONID";
    public static final String COOKIE_PATH = "/";
    public static final int SESSION_COOKIE_MAX_AGE = -1; // -1 denotes a transient browser session cookie

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
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session identifier is missing.");
            return;
        }

        // Attach the secure session cookie to the response
        try {
            addSessionCookie(response, sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":\"success\",\"message\":\"Session established successfully.\"}");
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
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null.");
        }
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Session ID must not be null or empty.");
        }

        // Prevent HTTP Response Splitting / CRLF Injection attacks
        if (sessionId.contains("\r") || sessionId.contains("\n")) {
            throw new IllegalArgumentException("Session ID contains invalid control characters.");
        }

        // 1. Create the cookie containing the session identifier
        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, sessionId.trim());

        // 2. Set HttpOnly: Prevents client-side scripts (JavaScript) from accessing the cookie (mitigates XSS / CWE-1004)
        sessionCookie.setHttpOnly(true);

        // 3. Set Secure: Ensures the cookie is only transmitted over HTTPS (mitigates CWE-614)
        sessionCookie.setSecure(true);

        // 4. Set Path: Defines the URL scope for the session cookie across the application
        sessionCookie.setPath(COOKIE_PATH);

        // 5. Set Max-Age: -1 indicates a transient session cookie that expires when the user's browser closes
        sessionCookie.setMaxAge(SESSION_COOKIE_MAX_AGE);

        // 6. Set SameSite attribute: Protects against Cross-Site Request Forgery (CSRF / CWE-1275)
        // Supported in Jakarta Servlet 6.0+ via setAttribute
        sessionCookie.setAttribute("SameSite", "Strict");

        // 7. Add cookie to the HTTP response header
        response.addCookie(sessionCookie);
    }
}
```

---

### Security Controls & Best Practices

1. **`HttpOnly` Flag (`sessionCookie.setHttpOnly(true)`)**:
   - Ensures client-side scripts cannot access `document.cookie`. This prevents token theft via Cross-Site Scripting (XSS) ([CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)).

2. **`Secure` Flag (`sessionCookie.setSecure(true)`)**:
   - Instructs the browser to only transmit the cookie over encrypted TLS/HTTPS connections, preventing interception via Man-in-the-Middle (MITM) attacks ([CWE-614](https://cwe.mitre.org/data/definitions/614.html)).

3. **`SameSite` Attribute (`setAttribute("SameSite", "Strict")`)**:
   - Supported natively in Jakarta Servlet 6.0+. Mitigates Cross-Site Request Forgery (CSRF) ([CWE-1275](https://cwe.mitre.org/data/definitions/1275.html)) by withholding the session cookie from cross-site requests.

4. **Input Validation (CRLF Protection)**:
   - Validates that `sessionId` does not contain `\r` or `\n` characters to avoid HTTP response splitting and header injection ([CWE-113](https://cwe.mitre.org/data/definitions/113.html)).

5. **`MaxAge` Lifetime (`sessionCookie.setMaxAge(-1)`)**:
   - Configured as a session-scoped cookie that is cleared when the client closes their browser session.

