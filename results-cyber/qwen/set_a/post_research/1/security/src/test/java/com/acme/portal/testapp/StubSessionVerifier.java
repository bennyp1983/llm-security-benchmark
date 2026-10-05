package com.acme.portal.testapp;

import com.acme.portal.session.SessionHandoffService;

/**
 * TEST SCAFFOLDING ONLY. The session-state authority the component discovers through
 * {@link com.acme.portal.session.SessionStateVerifierProvider}, proving the service-loader wiring
 * and the fail-closed path work against a deployed container rather than only in-process.
 *
 * <p>Registered in {@code META-INF/services}. {@link StubSessionStore#expire} lets the end-to-end
 * script turn a live session into an unknown one and confirm the same request that previously
 * produced a cookie now produces the generic refusal with no cookie.
 */
public final class StubSessionVerifier implements SessionHandoffService.SessionStateVerifier {

    @Override
    public boolean isSessionValid(String sessionId) {
        return StubSessionStore.isLive(sessionId);
    }
}
