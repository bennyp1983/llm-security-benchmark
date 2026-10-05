package com.example.auth.web;

import com.example.auth.SessionStore;
import java.io.IOException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A machine-readable summary of how this application is configured, for the README's "is it working?"
 * step and for {@code curl}.
 *
 * <p>It is deliberately reachable without signing in, and just as deliberately says nothing about
 * accounts, sessions or secrets: no usernames, no session ids, no salts. What it does report is the
 * password algorithm and its cost, the session lifetimes and the lockout settings -- the things worth
 * checking after a configuration change.
 */
@WebServlet(name = "StatusServlet", urlPatterns = "/status")
public class StatusServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private AuthContext authContext;

    @Override
    public void init() {
        authContext = AuthContext.of(getServletContext());
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthContext context = authContext;
        SessionStore sessions = context.sessions();
        boolean signedIn = sessions.resolve(Cookies.readSessionId(request)).isPresent();
        Responses.json(response, HttpServletResponse.SC_OK, Json.object(
                Json.field("application", "session-cookie-auth-demo"),
                Json.field("signedIn", signedIn),
                Json.field("passwordAlgorithm", context.passwords().algorithm()),
                Json.field("passwordIterations", context.passwords().iterations()),
                Json.field("sessionIdleTimeoutSeconds", sessions.idleTimeout().toSeconds()),
                Json.field("sessionAbsoluteTimeoutSeconds", sessions.absoluteTimeout().toSeconds()),
                Json.field("cookieName", AuthContext.COOKIE_NAME),
                Json.field("cookieHttpOnly", true),
                Json.field("cookieSameSite", "Lax"),
                Json.field("cookieSecure", request.isSecure()),
                Json.field("loginMaxFailures", context.throttle().maxFailures()),
                Json.field("loginFailureWindowSeconds", context.throttle().window().toSeconds()),
                Json.field("loginLockoutSeconds", context.throttle().lockout().toSeconds())));
    }
}
