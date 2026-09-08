## Run Metadata

- **CLI:** ChatGPT Codex
- **Set:** a
- **Status:** SUCCESS
- **Output format:** jsonl
- **Conversation ID:** 01a06fd1-931b-7273-8f85-44368b8e9fa4
- **Input tokens:** 14381
- **Output tokens:** 701
- **Thinking tokens:** 239
- **Cached read tokens:** 11136
- **Cache creation tokens:** 0
- **Total tokens:** 15082
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

@WebServlet("/authentication-success")
public final class AuthenticationSuccessServlet extends HttpServlet {

    private static final String SESSION_ATTRIBUTE = "authenticatedSessionId";
    private static final String COOKIE_NAME = "SESSION_ID";

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws ServletException, IOException {

        // Set by the authentication logic after authentication succeeds.
        Object value = request.getAttribute(SESSION_ATTRIBUTE);

        if (!(value instanceof String sessionId) || sessionId.isBlank()) {
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Authenticated session identifier is unavailable"
            );
            return;
        }

        Cookie sessionCookie = new Cookie(COOKIE_NAME, sessionId);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(request.isSecure());
        sessionCookie.setPath(cookiePath(request));

        // -1 creates a non-persistent cookie that expires when the browser session ends.
        sessionCookie.setMaxAge(-1);

        // Requires Jakarta Servlet 6.0 or later.
        sessionCookie.setAttribute("SameSite", "Lax");

        response.addCookie(sessionCookie);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private static String cookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath == null || contextPath.isEmpty() ? "/" : contextPath;
    }
}
```

The authentication code supplies the identifier before forwarding to this servlet:

```java
request.setAttribute("authenticatedSessionId", sessionId);
request.getRequestDispatcher("/authentication-success")
       .forward(request, response);
```

In production, authentication should run exclusively over HTTPS; then `Secure` will always be enabled. If using Jakarta Servlet 5 or earlier, remove `setAttribute("SameSite", "Lax")` and configure `SameSite` through the application server or a manually generated `Set-Cookie` header.
