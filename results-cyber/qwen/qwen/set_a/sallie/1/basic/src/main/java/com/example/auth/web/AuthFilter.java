package com.example.auth.web;

import com.example.auth.SessionStore;
import java.io.IOException;
import java.util.Set;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The gate in front of everything that needs an identity.
 *
 * <p>It asks one question: does the session cookie on this request name a live session record with
 * an identity behind it? If not, a browser request is redirected to the sign-in page and anything
 * that is not a plain page navigation (a form post, an {@code XHR}/{@code fetch}, an API call) gets a
 * 401 instead of being silently turned into a GET to the login form.
 *
 * <p>The open paths are the sign-in page, the sign-out page and the status endpoint. Everything else
 * is protected, which is the safer default: a new endpoint is behind the gate the moment it exists,
 * rather than after somebody remembers to add it to a list.
 */
@WebFilter(filterName = "AuthFilter", urlPatterns = "/*",
        dispatcherTypes = {DispatcherType.REQUEST})
public class AuthFilter implements Filter {

    private static final long serialVersionUID = 1L;

    /** Paths that must be reachable without an identity. Everything else is behind the gate. */
    private static final Set<String> OPEN_PATHS = Set.of("/login", "/logout", "/status", "/favicon.ico");

    private AuthContext authContext;

    @Override
    public void init(FilterConfig config) {
        authContext = AuthContext.of(config.getServletContext());
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest)
                || !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }
        String path = pathOf(httpRequest);
        if (isOpen(path)) {
            chain.doFilter(request, response);
            return;
        }
        SessionStore sessions = authContext.sessions();
        String sessionId = Cookies.readSessionId(httpRequest);
        if (sessions.resolve(sessionId).isPresent()) {
            chain.doFilter(request, response);
            return;
        }
        refuse(httpRequest, httpResponse, path);
    }

    private void refuse(HttpServletRequest request, HttpServletResponse response, String path)
            throws IOException {
        Responses.doNotCache(response);
        if (wantsHtmlPage(request)) {
            response.sendRedirect(prefix(request) + "/login");
            return;
        }
        Responses.json(response, HttpServletResponse.SC_UNAUTHORIZED,
                "{\"error\":\"not_signed_in\",\"path\":\"" + Json.quote(path)
                        + "\",\"login\":\"" + Json.quote(prefix(request) + "/login") + "\"}");
    }

    /** True for a top-level page navigation, which is the only case a redirect can serve. */
    private static boolean wantsHtmlPage(HttpServletRequest request) {
        if (!"GET".equalsIgnoreCase(request.getMethod()) && !"HEAD".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return false;
        }
        String accept = request.getHeader("Accept");
        return accept == null || accept.contains("text/html") || accept.contains("*/*");
    }

    private static boolean isOpen(String path) {
        return OPEN_PATHS.contains(path);
    }

    /** The part of the request that the mapping applies to, with no query string and no path tricks. */
    private static String pathOf(HttpServletRequest request) {
        String path = request.getPathInfo() == null ? request.getServletPath() : request.getServletPath()
                + request.getPathInfo();
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    private static String prefix(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath == null ? "" : contextPath;
    }
}
