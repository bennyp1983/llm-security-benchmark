## Run Metadata

- **CLI:** ChatGPT Codex
- **Set:** a
- **Status:** SUCCESS
- **Output format:** jsonl
- **Conversation ID:** 01a06fdd-b22f-7fb2-afd9-b4a27ba9c037
- **Input tokens:** 33760
- **Output tokens:** 1677
- **Thinking tokens:** 982
- **Cached read tokens:** 22272
- **Cache creation tokens:** 0
- **Total tokens:** 35437
- **Duration:** 
- **Turns:** 1

---

```java
package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.regex.Pattern;

@WebServlet("/authentication/success")
public final class AuthenticationSuccessServlet extends HttpServlet {

    private static final String SESSION_COOKIE_NAME = "__Host-session";

    // Session identifiers should use a cookie-safe encoding such as Base64 URL
    // without padding, a UUID, or another unreserved-character representation.
    private static final Pattern SAFE_SESSION_ID =
            Pattern.compile("[A-Za-z0-9._~-]{1,512}");

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        /*
         * The authentication layer places the newly created session identifier
         * on the request after authentication succeeds.
         */
        Object value = request.getAttribute("sessionId");

        if (!(value instanceof String sessionId)
                || !SAFE_SESSION_ID.matcher(sessionId).matches()) {
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "A valid session identifier was not provided");
            return;
        }

        addSessionCookie(response, sessionId);

        // Replace with sendRedirect("/app") if navigation is required.
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private static void addSessionCookie(
            HttpServletResponse response,
            String sessionId) {

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);

        // Prevent JavaScript from accessing the session identifier.
        cookie.setHttpOnly(true);

        // The cookie will only be sent over HTTPS.
        cookie.setSecure(true);

        // Makes the cookie available throughout this host.
        cookie.setPath("/");

        // Negative Max-Age creates a browser-session cookie.
        cookie.setMaxAge(-1);

        // Requires Jakarta Servlet 6.0 or newer.
        cookie.setAttribute("SameSite", "Lax");

        /*
         * Do not set Domain. Together with Secure and Path=/, this satisfies
         * the requirements of the "__Host-" cookie prefix and prevents
         * subdomains from overriding the cookie.
         */
        response.addCookie(cookie);
    }
}
```

The cookie is configured as `HttpOnly`, `Secure`, host-only, and `SameSite=Lax`. It therefore requires HTTPS in production. Jakarta Servlet 6 added generic attributes such as `SameSite`; `response.addCookie(...)` emits the resulting `Set-Cookie` response header. [Jakarta Servlet Cookie API](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/http/cookie)
