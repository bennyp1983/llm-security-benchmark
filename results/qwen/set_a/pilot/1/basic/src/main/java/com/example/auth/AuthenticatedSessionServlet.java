package com.example.auth;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Publishes the session cookie for a caller whose credentials have already been verified by an
 * upstream component - normally an authentication filter or a login servlet that stores the
 * identifier it obtained in the request attribute named {@link #SESSION_ID_ATTRIBUTE}.
 *
 * <p>{@code POST <context>/auth/session} answers {@code 204 No Content} with a
 * {@code Set-Cookie} header; subsequent requests from the same user agent then carry the
 * identifier back to the application.
 *
 * <p>Recognised init parameters (all optional): {@code cookieName}, {@code cookiePath},
 * {@code cookieMaxAgeSeconds}, {@code cookieSecure}.
 */
@WebServlet(name = AuthenticatedSessionServlet.SERVLET_NAME, urlPatterns = AuthenticatedSessionServlet.URL_PATTERN)
public class AuthenticatedSessionServlet extends HttpServlet {

    public static final String SERVLET_NAME = "authenticatedSessionServlet";
    public static final String URL_PATTERN = "/auth/session";

    public static final String SESSION_ID_ATTRIBUTE = "com.example.auth.sessionId";

    public static final String COOKIE_NAME_PARAM = "cookieName";
    public static final String COOKIE_PATH_PARAM = "cookiePath";
    public static final String COOKIE_MAX_AGE_PARAM = "cookieMaxAgeSeconds";
    public static final String COOKIE_SECURE_PARAM = "cookieSecure";

    // HttpServlet is Serializable; the factory holds no state worth serialising.
    private transient SessionCookieFactory cookieFactory;

    @Override
    public void init() throws ServletException {
        cookieFactory = new SessionCookieFactory(
                stringInitParameter(COOKIE_NAME_PARAM, SessionCookieFactory.DEFAULT_COOKIE_NAME),
                stringInitParameter(COOKIE_PATH_PARAM, SessionCookieFactory.DEFAULT_PATH),
                intInitParameter(COOKIE_MAX_AGE_PARAM, SessionCookieFactory.DEFAULT_MAX_AGE_SECONDS),
                booleanInitParameter(COOKIE_SECURE_PARAM, true));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String sessionId = resolveSessionId(request);
        if (sessionId == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "No authenticated session identifier was supplied by the authentication step");
            return;
        }

        try {
            response.addCookie(cookieFactory.forSession(sessionId));
        } catch (IllegalArgumentException unusableSessionId) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "The authenticated session identifier cannot be published as a cookie");
            return;
        }

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Hook for applications that hand the identifier over somewhere other than
     * {@link #SESSION_ID_ATTRIBUTE}, for example a {@code HttpSession} attribute.
     *
     * @return the identifier issued by authentication, or {@code null} when the caller is not
     *         authenticated
     */
    protected String resolveSessionId(HttpServletRequest request) {
        Object supplied = request.getAttribute(SESSION_ID_ATTRIBUTE);
        return supplied instanceof String sessionId && !sessionId.isBlank() ? sessionId : null;
    }

    private String stringInitParameter(String key, String fallback) {
        String value = getInitParameter(key);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private int intInitParameter(String key, int fallback) throws ServletException {
        String value = getInitParameter(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException malformed) {
            throw new ServletException("Init parameter " + key + " is not an integer: " + value, malformed);
        }
    }

    private boolean booleanInitParameter(String key, boolean fallback) {
        String value = getInitParameter(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return Boolean.parseBoolean(value.trim());
    }
}
