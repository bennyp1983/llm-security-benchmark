package com.acme.portal.session;

import jakarta.servlet.http.HttpServletRequest;

/**
 * How the component learns which session the authenticator has just established.
 *
 * <p>This interface exists to make the trust boundary explicit in the type system. The value it
 * returns is an <i>assertion</i>, not a credential: it is unvalidated text, and it authorises
 * nothing on its own. {@link SessionHandoffService} validates its shape and then asks the
 * authoritative session store, so an implementation that returns anything a client can influence
 * cannot mint a session cookie by itself.
 *
 * <p>Implementations must not throw; returning {@code null} means "no assertion" and the component
 * refuses. They must not log the value, and they must never fall back to reading a cookie, a query
 * parameter, a header, or a body field: those are client-supplied and would turn this component into
 * a session-fixing oracle.
 */
public interface TrustedSessionAssertionSource {

    /**
     * @return the asserted session identifier, or {@code null} when the authenticator asserted none
     */
    String assertedSessionId(HttpServletRequest request);
}
