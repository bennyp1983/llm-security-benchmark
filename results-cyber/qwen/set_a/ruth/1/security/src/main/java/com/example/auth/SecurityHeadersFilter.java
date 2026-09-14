package com.example.auth;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Response headers that bound what a leaked identifier or a cached response can do. Registered in
 * {@code WEB-INF/web.xml} ahead of the servlets, so the cookie always travels with them.
 *
 * <ul>
 *   <li>{@code Vary: Cookie} and {@code Cache-Control: no-store} - a response that carries
 *       {@code Set-Cookie} must not be served from a cache to the next visitor.</li>
 *   <li>{@code Referrer-Policy: no-referrer} - keeps a URL, and anything a URL rewrite put in it,
 *       out of the {@code Referer} header a third-party page receives.</li>
 *   <li>{@code Content-Security-Policy} with {@code default-src 'self'} and no {@code unsafe-inline}
 *       - the cookie is HttpOnly, which only pays off if script injection is also hard; a XSS that
 *       cannot read the cookie can still act as the user, so this is the second line of defence.</li>
 * </ul>
 */
public final class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse http) {
            http.setHeader("Cache-Control", "no-store");
            http.setHeader("Vary", "Cookie");
            http.setHeader("Referrer-Policy", "no-referrer");
            http.setHeader("X-Content-Type-Options", "nosniff");
            http.setHeader("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'");
            // Only worth sending over TLS, and harmless otherwise: browsers ignore it on http.
            if (request instanceof HttpServletRequest servletRequest && servletRequest.isSecure()) {
                http.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            }
        }
        chain.doFilter(request, response);
    }
}
