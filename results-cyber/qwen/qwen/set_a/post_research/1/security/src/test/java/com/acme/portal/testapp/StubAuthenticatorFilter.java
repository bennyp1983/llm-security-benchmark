package com.acme.portal.testapp;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

/**
 * TEST SCAFFOLDING ONLY. Stands in for the trusted authenticator that this component is documented
 * to sit behind.
 *
 * <p>It reads a request header, which production code must never do to establish identity. That is
 * acceptable here for one reason: the header only names a <i>ticket</i>. The session identifier is
 * created by {@link StubSessionStore} with its own CSPRNG and recorded server side, so a client
 * still cannot choose or learn the value the component will eventually issue. The scaffolding lets a
 * {@code curl} script produce a legitimate handoff; the security assertions then check that no
 * client-supplied string is ever echoed back as a session value.
 *
 * <p>Usage in the end-to-end script:
 * <ul>
 *   <li>{@code X-Stub-Login: <ticket>} performs a sign-in, creating a session for that ticket.</li>
 *   <li>{@code X-Stub-Ticket: <ticket>} asserts the session that ticket owns, which is what drives a
 *       granted handoff.</li>
 *   <li>{@code X-Stub-Assert: <value>} asserts an arbitrary value, which is how the script
 *       reproduces the most dangerous integration mistake: a trusted component naming an identifier
 *       the session store has never heard of. Whether that becomes a cookie is decided by the
 *       component's verifier gate, and that gate is the single most important thing to test over real
 *       HTTP.</li>
 * </ul>
 * The attribute name matches the component's default assertion attribute.
 */
public final class StubAuthenticatorFilter implements Filter {

    /** Same default the component reads; kept in sync deliberately. */
    public static final String ASSERTION_ATTRIBUTE = "com.acme.portal.session.assertedId";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest http = (HttpServletRequest) request;
            String loginTicket = http.getHeader("X-Stub-Login");
            if (loginTicket != null && !loginTicket.isEmpty()) {
                StubSessionStore.loginAndCreateSession(loginTicket);
            }
            String ticket = http.getHeader("X-Stub-Ticket");
            if (ticket != null && !ticket.isEmpty()) {
                String sessionId = StubSessionStore.sessionForTicket(ticket);
                if (sessionId != null) {
                    http.setAttribute(ASSERTION_ATTRIBUTE, sessionId);
                }
            }
            String asserted = http.getHeader("X-Stub-Assert");
            if (asserted != null) {
                http.setAttribute(ASSERTION_ATTRIBUTE, asserted);
            }
        }
        chain.doFilter(request, response);
    }
}
