package com.example.auth.web;

import java.io.IOException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Ends the session: the server-side record is deleted and the browser is told to drop the cookie.
 *
 * <p>{@code POST} only, because logging out is a state change -- a link on some other site must not
 * be able to sign the user out. A request without a session cookie is not an error; there is nothing
 * to end, and the answer is the same page either way.
 */
@WebServlet(name = "LogoutServlet", urlPatterns = "/logout")
public class LogoutServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private AuthContext authContext;

    @Override
    public void init() {
        authContext = AuthContext.of(getServletContext());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthContext context = authContext;
        // Delete the record whatever the cookie says: an unrecognised value is told to go away too,
        // so a stray cookie cannot linger in the browser and be replayed later.
        context.sessions().invalidate(Cookies.readSessionId(request));
        Cookies.clearSessionId(response, request.isSecure(), Cookies.cookiePath(request));
        Responses.html(response, HttpServletResponse.SC_OK, logoutHtml(request));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 405 with an Allow header, so a browser link or an image tag cannot sign anyone out.
        Responses.doNotCache(response);
        response.setHeader("Allow", "POST");
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Sign out requires POST");
    }

    static String logoutHtml(HttpServletRequest request) {
        String prefix = request.getContextPath() == null ? "" : request.getContextPath();
        return "<h1>Signed out</h1>\n"
                + "<p>The session record was deleted and the session cookie was cleared. Nobody can use "
                + "that cookie again, even if it was copied somewhere.</p>\n"
                + "<p><a href=\"" + Html.attribute(prefix) + "/login\">Sign in again</a> or "
                + "<a href=\"" + Html.attribute(prefix) + "/status\">check the server status</a>.</p>\n";
    }
}
