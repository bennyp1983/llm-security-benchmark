package com.example.auth.web;

import com.example.auth.AuthenticatedUser;
import com.example.auth.PasswordService;
import com.example.auth.SessionStore;
import com.example.auth.web.LoginThrottle.Verdict;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Signs a user in and hands the browser the session cookie.
 *
 * <p>{@code GET /login} shows the form and gives the visitor an anonymous session record holding a
 * one-use token. {@code POST /login} checks that token, checks the credentials, and on success
 * throws the anonymous record away, mints a brand-new session id and sets the cookie. The id that
 * existed before the credentials were proven never survives the login: that is what keeps a
 * session-fixation attempt from succeeding.
 *
 * <p>A wrong password and an unknown username produce the same answer, the same 401 page and roughly
 * the same delay, so the endpoint cannot be used to find out which accounts exist.
 */
@WebServlet(name = "LoginServlet", urlPatterns = "/login")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Accounts are names, not essays: a bounded, boring character set, checked before anything else. */
    private static final java.util.regex.Pattern USERNAME =
            java.util.regex.Pattern.compile("[A-Za-z0-9][A-Za-z0-9._@-]{0,63}");
    private static final int MAX_PASSWORD_CHARS = 1_024;
    private static final String GENERIC_FAILURE = "Invalid username or password.";
    private static final String EXPIRED_FORM = "That sign-in page has expired. Please try again.";
    private static final String THROTTLED = "Too many failed sign-in attempts. Try again later.";
    /** 429 is not a constant in Servlet 6.0 ({@code SC_TOO_MANY_REQUESTS} arrived in 6.1). */
    private static final int SC_TOO_MANY_REQUESTS = 429;

    private static final Logger LOG = Logger.getLogger(LoginServlet.class.getName());

    private AuthContext authContext;

    @Override
    public void init() {
        authContext = AuthContext.of(getServletContext());
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        request.setCharacterEncoding("UTF-8");
        AuthContext context = authContext;
        String incoming = Cookies.readSessionId(request);
        if (context.sessions().resolve(incoming).isPresent()) {
            // Already signed in: nothing to ask. Slide the idle clock and move on.
            context.sessions().touch(incoming);
            response.sendRedirect(prefix(request) + "/account");
            return;
        }
        showForm(request, response, null, "", false, HttpServletResponse.SC_OK);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        request.setCharacterEncoding("UTF-8");
        AuthContext context = authContext;
        String formSessionId = Cookies.readSessionId(request);
        String username = trimToEmpty(request.getParameter("username"));
        char[] password = passwordChars(request.getParameter("password"));
        boolean remember = "on".equals(request.getParameter("remember"));
        String throttleKey = LoginThrottle.keyFor(request.getRemoteAddr(), username);

        try {
            if (context.throttle().verdictFor(throttleKey, Instant.now()) == Verdict.THROTTLED) {
                LOG.log(Level.WARNING, "Sign-in attempts throttled for {0}", request.getRemoteAddr());
                // Set before the body is written: once the response is committed the container drops
                // the header, and a 429 without Retry-After leaves the caller guessing.
                response.setIntHeader("Retry-After", (int) context.throttle().lockout().toSeconds());
                showForm(request, response, THROTTLED, "", false, SC_TOO_MANY_REQUESTS);
                return;
            }

            // The form token is single-use and is burned here whatever the outcome, so one served
            // page cannot be posted twice.
            String token = request.getParameter(AuthContext.CSRF_FIELD);
            if (!context.sessions().consumeCsrfToken(formSessionId, token)) {
                showForm(request, response, EXPIRED_FORM, username, remember,
                        HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            Optional<PasswordService.StoredPassword> stored = usernameValid(username)
                    ? context.users().findPassword(username)
                    : Optional.empty();
            boolean credentialsOk = false;
            if (!PasswordService.isUsableCandidate(password)) {
                // A candidate that cannot be verified unambiguously still costs a full stretch, so
                // refusing it is not a fast lane through the endpoint.
                context.passwords().chargeRefusedAttempt(password);
            } else if (stored.isEmpty()) {
                // Same here: "no such user" must not come back instantly.
                context.passwords().chargeRefusedAttempt(password);
            } else {
                credentialsOk = context.passwords().verify(password, stored.get());
            }

            if (!credentialsOk) {
                context.throttle().recordFailure(throttleKey, Instant.now());
                LOG.log(Level.FINE, "Rejected sign-in for user ''{0}'' from {1}",
                        new Object[] {username, request.getRemoteAddr()});
                showForm(request, response, GENERIC_FAILURE, username, remember,
                        HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            finishLogin(request, response, context, username, remember, formSessionId);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private void finishLogin(HttpServletRequest request, HttpServletResponse response,
                             AuthContext context, String username, boolean remember, String formSessionId)
            throws IOException {
        AuthenticatedUser user = new AuthenticatedUser(username, context.users().rolesOf(username));
        // Burn the pre-login record and its id before the new one exists.
        context.sessions().invalidate(formSessionId);
        String sessionId = context.sessions().newSessionId();
        SessionStore.Session session = remember
                ? context.sessions().create(sessionId, user)
                : context.sessions().createBrowserSession(sessionId, user);
        Cookies.writeSessionId(response, sessionId,
                remember ? session.cookieMaxAge(Instant.now()) : null, request.isSecure(),
                Cookies.cookiePath(request));
        context.throttle().recordSuccess(LoginThrottle.keyFor(request.getRemoteAddr(), username));
        response.sendRedirect(prefix(request) + "/account");
    }

    /**
     * Serves the form with a cookie for a brand-new anonymous record. The record the previous attempt
     * used is already burned, so the browser needs a live one before it can post again.
     */
    private void showForm(HttpServletRequest request, HttpServletResponse response, String message,
                          String username, boolean remember, int status) throws IOException {
        AuthContext context = authContext;
        String sessionId = context.sessions().newSessionId();
        String token = context.sessions().createFormToken(sessionId);
        Cookies.writeSessionId(response, sessionId, null, request.isSecure(), Cookies.cookiePath(request));
        Responses.html(response, status, formHtml(message, username, remember, token, prefix(request)));
    }

    static String formHtml(String message, String username, boolean remember, String token, String prefix) {
        StringBuilder body = new StringBuilder();
        body.append("<h1>Sign in</h1>\n");
        body.append("<p class=\"lead\">Enter your credentials. A successful sign-in sets a session cookie "
                + "that the browser then sends with every request.</p>\n");
        if (message != null) {
            body.append("<p class=\"error\" role=\"alert\">").append(Html.escape(message)).append("</p>\n");
        }
        body.append("<form method=\"post\" action=\"").append(Html.attribute(prefix)).append("/login\" "
                + "accept-charset=\"UTF-8\">\n");
        body.append("<input type=\"hidden\" name=\"").append(AuthContext.CSRF_FIELD).append("\" value=\"")
                .append(Html.attribute(token)).append("\">\n");
        body.append("<label for=\"username\">Username</label>\n");
        body.append("<input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" "
                + "autocapitalize=\"none\" required maxlength=\"64\" value=\"")
                .append(Html.attribute(username == null ? "" : username)).append("\">\n");
        body.append("<label for=\"password\">Password</label>\n");
        body.append("<input type=\"password\" id=\"password\" name=\"password\" "
                + "autocomplete=\"current-password\" required maxlength=\"1024\">\n");
        body.append("<label class=\"field\"><input type=\"checkbox\" id=\"remember\" name=\"remember\"")
                .append(remember ? " checked" : "").append("> Keep me signed in</label>\n");
        body.append("<p><input type=\"submit\" value=\"Sign in\"></p>\n");
        body.append("</form>\n");
        return body.toString();
    }

    private static boolean usernameValid(String username) {
        return USERNAME.matcher(username).matches();
    }

    private static String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static char[] passwordChars(String value) {
        if (value == null || value.isEmpty()) {
            // A stand-in of the right shape keeps this path's stretching cost equal to the others.
            return new char[] {'\0'};
        }
        String capped = value.length() > MAX_PASSWORD_CHARS ? value.substring(0, MAX_PASSWORD_CHARS) : value;
        return capped.toCharArray();
    }

    private static String prefix(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath == null ? "" : contextPath;
    }
}
