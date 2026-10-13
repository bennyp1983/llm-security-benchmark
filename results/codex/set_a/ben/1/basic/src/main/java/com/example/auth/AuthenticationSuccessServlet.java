package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Handles the successful-authentication step by issuing a session cookie.
 *
 * <p>The authentication component that forwards to this servlet must put the
 * newly created session identifier in the request attribute named by
 * {@link #SESSION_ID_ATTRIBUTE}.</p>
 */
@WebServlet(name = "authenticationSuccessServlet", urlPatterns = "/auth/success")
public final class AuthenticationSuccessServlet extends HttpServlet {

    public static final String SESSION_ID_ATTRIBUTE = "sessionIdentifier";
    public static final String SESSION_COOKIE_NAME = "SESSION_ID";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Object value = request.getAttribute(SESSION_ID_ATTRIBUTE);
        if (!(value instanceof String sessionIdentifier) || sessionIdentifier.isBlank()) {
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "An authenticated session identifier was not supplied");
            return;
        }

        try {
            addSessionCookie(response, request.getContextPath(), sessionIdentifier);
        } catch (IllegalArgumentException exception) {
            throw new ServletException("The supplied session identifier is not cookie-safe", exception);
        }

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Adds an HTTP-only, HTTPS-only session cookie to the response.
     * No Max-Age or Expires value is set, so the browser treats it as a
     * session cookie.
     */
    public static void addSessionCookie(
            HttpServletResponse response, String contextPath, String sessionIdentifier) {
        if (response == null) {
            throw new IllegalArgumentException("response must not be null");
        }
        validateSessionIdentifier(sessionIdentifier);

        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, sessionIdentifier);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(true);
        sessionCookie.setPath(normalizeCookiePath(contextPath));
        sessionCookie.setAttribute("SameSite", "Lax");

        response.addCookie(sessionCookie);
    }

    private static String normalizeCookiePath(String contextPath) {
        return contextPath == null || contextPath.isBlank() ? "/" : contextPath;
    }

    private static void validateSessionIdentifier(String sessionIdentifier) {
        if (sessionIdentifier == null || sessionIdentifier.isBlank()) {
            throw new IllegalArgumentException("sessionIdentifier must not be blank");
        }

        // RFC 6265 cookie-octet characters. Session IDs should normally be
        // generated as hex or Base64 URL without padding, both of which pass.
        byte[] bytes = sessionIdentifier.getBytes(StandardCharsets.US_ASCII);
        if (bytes.length != sessionIdentifier.length()) {
            throw new IllegalArgumentException("sessionIdentifier must contain ASCII characters only");
        }
        for (byte value : bytes) {
            int character = Byte.toUnsignedInt(value);
            boolean allowed = character == 0x21
                    || (character >= 0x23 && character <= 0x2B)
                    || (character >= 0x2D && character <= 0x3A)
                    || (character >= 0x3C && character <= 0x5B)
                    || (character >= 0x5D && character <= 0x7E);
            if (!allowed) {
                throw new IllegalArgumentException("sessionIdentifier contains an invalid cookie character");
            }
        }
    }
}
