package com.example.auth.web;

import com.example.auth.AuthenticatedUser;
import com.example.auth.SessionStore;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The page the whole exercise is about: it only renders when the session cookie the browser sent
 * names a live session record on the server. {@link AuthFilter} already turned a missing or expired
 * cookie into a redirect to the sign-in page, so anything that reaches here is signed in.
 *
 * <p>Each request that arrives slides the session's idle deadline, and a "keep me signed in" session
 * gets its remaining lifetime refreshed in the cookie so the browser-side expiry matches the server.
 */
@WebServlet(name = "AccountServlet", urlPatterns = "/account")
public class AccountServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private AuthContext authContext;

    @Override
    public void init() {
        authContext = AuthContext.of(getServletContext());
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthContext context = authContext;
        String sessionId = Cookies.readSessionId(request);
        // touch() both validates the cookie against the store and slides the idle deadline, so a
        // single lookup answers "is this still a live session?" without a second read to race with.
        Optional<SessionStore.Session> session = context.sessions().touch(sessionId);
        if (session.isEmpty()) {
            // Only reachable when the filter was bypassed by a direct forward; refuse rather than
            // render an empty page.
            Responses.html(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "<h1>Not signed in</h1>\n<p>No live session behind this request.</p>\n");
            return;
        }
        SessionStore.Session live = session.get();
        if (live.persistent()) {
            Cookies.writeSessionId(response, live.id(), live.cookieMaxAge(Instant.now()),
                    request.isSecure(), Cookies.cookiePath(request));
        }
        Responses.html(response, HttpServletResponse.SC_OK, accountHtml(live, request));
    }

    static String accountHtml(SessionStore.Session session, HttpServletRequest request) {
        AuthenticatedUser user = new AuthenticatedUser(session.username(), session.roles());
        String prefix = request.getContextPath() == null ? "" : request.getContextPath();
        StringBuilder body = new StringBuilder();
        body.append("<h1>Signed in</h1>\n");
        body.append("<p class=\"lead\">This page is behind the session cookie. The browser sent the "
                + "cookie, the server found a live record for it, and the page rendered.</p>\n");
        body.append("<ul>\n");
        body.append("<li><strong>Username</strong>: ").append(Html.escape(user.username())).append("</li>\n");
        body.append("<li><strong>Roles</strong>: ")
                // A set has no inherent order; sorting keeps the page identical on every render.
                .append(Html.escape(user.roles().isEmpty() ? "(none)"
                        : user.roles().stream().sorted().collect(java.util.stream.Collectors.joining(", "))))
                .append("</li>\n");
        body.append("<li><strong>Session expires</strong>: ")
                .append(Html.escape(session.expiresAt().toString())).append("</li>\n");
        body.append("<li><strong>Cookie name</strong>: <code>")
                .append(AuthContext.COOKIE_NAME).append("</code> (HttpOnly, SameSite=Lax")
                .append(request.isSecure() ? ", Secure" : "").append(")</li>\n");
        body.append("</ul>\n");
        body.append("<p>Note that the page never shows the session id: the cookie is marked HttpOnly, "
                + "so page script cannot read it, and there is no reason to print it here.</p>\n");
        body.append("<form method=\"post\" action=\"").append(Html.attribute(prefix)).append("/logout\">\n");
        body.append("<p><input type=\"submit\" value=\"Sign out\"></p>\n");
        body.append("</form>\n");
        return body.toString();
    }
}
