package com.acme.portal.testapp;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * TEST SCAFFOLDING ONLY, and it is shipped in nothing but the end-to-end test war.
 *
 * <p>Gives the end-to-end script the one thing it cannot do from outside a JVM: turn a live session
 * into an unknown one, so the "the session store no longer confirms this identifier" path can be
 * observed over real HTTP rather than only in-process.
 *
 * <p>Deliberately minimal: it takes no identifier as a parameter (so a client cannot name a session
 * to expire, which would be a session-invalidation oracle), it exposes only a count and a status
 * word, and it never prints an identifier. {@link StubSessionStore#expireOldest()} picks the session
 * to drop.
 */
public final class StubControlServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        respond(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        respond(request, response);
    }

    private void respond(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getPathInfo() == null ? "" : request.getPathInfo();
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("text/plain;charset=UTF-8");
        PrintWriter out = response.getWriter();
        if ("/expire-oldest".equals(action)) {
            out.println(StubSessionStore.expireOldest() ? "EXPIRED" : "NONE");
        } else if ("/live".equals(action)) {
            out.println(Integer.toString(StubSessionStore.liveCount()));
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            out.println("UNKNOWN");
        }
        out.flush();
    }
}
