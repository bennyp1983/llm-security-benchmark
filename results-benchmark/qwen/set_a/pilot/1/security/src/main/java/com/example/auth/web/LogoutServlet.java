package com.example.auth.web;

import com.example.auth.session.SessionCookieConfig;
import com.example.auth.session.SessionCookieFactory;
import com.example.auth.session.SessionRegistry;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * Ends the session behind the cookie.
 *
 * <p>The server-side record goes away first: expiring the cookie alone leaves the identifier live, so
 * a copy of it taken before logout would still work.
 */
@WebServlet(name = "logoutServlet", urlPatterns = "/api/logout")
public class LogoutServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private SessionRegistry sessions;
    private SessionCookieConfig cookieConfig;

    public LogoutServlet() {
    }

    public LogoutServlet(SessionRegistry sessions, SessionCookieConfig cookieConfig) {
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.cookieConfig = Objects.requireNonNull(cookieConfig, "cookieConfig");
    }

    @Override
    public void init() {
        if (cookieConfig == null) {
            this.sessions = WebInfrastructure.sessionRegistry(getServletContext());
            this.cookieConfig = WebInfrastructure.sessionCookieConfig(getServletContext());
        }
    }

    /**
     * Logout changes server state, so it is POST-only; a GET logout can be triggered by an
     * {@code <img>} tag, which turns logout into a harassment and denial-of-service primitive.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.setHeader("Allow", "POST");
        AuthResponses.noStore(response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String identifier = SessionCookieFactory.readSessionId(request, cookieConfig);
        if (identifier != null) {
            sessions.remove(identifier);
        }
        AuthResponses.discardPreAuthSession(request);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        AuthResponses.noStore(response);
        SessionCookieFactory.clear(response, cookieConfig);
    }
}
