package com.example.security.session;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * POST-only internal handoff endpoint installed after the trusted authentication component.
 *
 * <p>The upstream component transfers the existing identifier in the request attribute named by
 * {@link SessionCookiePolicy#REQUEST_ATTRIBUTE}; this endpoint deliberately never reads a request
 * parameter, header, URL, or request cookie as the candidate session identifier.</p>
 */
public final class SessionCookieEndpoint extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final byte[] FAILURE_BODY =
            "Authentication handoff failed.\n".getBytes(StandardCharsets.UTF_8);

    private final SessionHandoffStore store;
    private final System.Logger logger;

    public SessionCookieEndpoint(SessionHandoffStore store) {
        this(store, System.getLogger(SessionCookieEndpoint.class.getName()));
    }

    SessionCookieEndpoint(SessionHandoffStore store, System.Logger logger) {
        this.store = Objects.requireNonNull(store, "store");
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");

        // This endpoint owns an uncommitted response. Reset prevents an upstream stale Set-Cookie.
        if (response.isCommitted()) {
            logger.log(System.Logger.Level.ERROR, "session handoff called after response commit");
            return; // the container can no longer produce a safe generic response
        }
        response.reset();
        addNonCacheableHeaders(response);

        Object supplied = request.getAttribute(SessionCookiePolicy.REQUEST_ATTRIBUTE);
        String candidate = supplied instanceof String string ? string : null;
        String remoteAddress = request.getRemoteAddr();

        boolean validCandidate = SessionCookiePolicy.isValidSessionId(candidate);
        boolean validSource = SessionCookiePolicy.isValidSourceKey(remoteAddress);
        boolean secureTransport = request.isSecure();

        // Include every local prerequisite in the flag passed to the atomic consume operation.
        // Otherwise an HTTP request could burn a valid one-time handoff and then be denied here.
        boolean locallyEligible = validCandidate && validSource && secureTransport;
        String lookupId = locallyEligible ? candidate : SessionCookiePolicy.DUMMY_SESSION_ID;
        String sourceKey = validSource ? remoteAddress : SessionCookiePolicy.DUMMY_SOURCE_KEY;

        SessionHandoffStore.Decision decision = SessionHandoffStore.Decision.DENY;
        try {
            SessionHandoffStore.Decision returned =
                    store.authorizeAndConsume(lookupId, locallyEligible, sourceKey);
            if (returned != null) {
                decision = returned;
            }
        } catch (RuntimeException failure) {
            // Exception messages may contain secrets supplied by a backing store; never log them.
            logger.log(System.Logger.Level.ERROR, "session handoff store failure");
        }

        if (locallyEligible
                && decision == SessionHandoffStore.Decision.AUTHORIZE) {
            response.addCookie(SessionCookiePolicy.sessionCookie(candidate));
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }

        // Remove any pre-existing session to prevent a failed login from retaining another user.
        response.addCookie(SessionCookiePolicy.deletionCookie());
        writeGenericFailure(response);
    }

    private static void addNonCacheableHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }

    private static void writeGenericFailure(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentLength(FAILURE_BODY.length);
        response.getOutputStream().write(FAILURE_BODY);
    }
}
