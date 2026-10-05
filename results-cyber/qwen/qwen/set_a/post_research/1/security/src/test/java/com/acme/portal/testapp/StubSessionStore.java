package com.acme.portal.testapp;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The server-side half of the end-to-end test: stands in for the trusted session owner this
 * component is documented to integrate with.
 *
 * <p>It owns two things and nothing else: the set of identifiers that currently exist, and the
 * mapping from a login ticket to the identifier created for it.
 *
 * <p>Identifiers are minted here, by this stand-in component, with its own {@link SecureRandom} and
 * its own base64url encoding. That is deliberate twice over: the real trusted owner would hold its
 * own generator, and {@code SessionId#value()} is package private in the component under test, so
 * this scaffolding proves from the outside that the sealed accessor really is unobtainable. It also
 * proves the component accepts an identifier produced by an independent generator, which is the
 * integration it documents.
 *
 * <p>A client can neither choose nor predict one of these values. The end-to-end assertions
 * deliberately try to.
 */
public final class StubSessionStore {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, Boolean> LIVE = new ConcurrentHashMap<String, Boolean>();
    private static final Map<String, String> TICKETS = new ConcurrentHashMap<String, String>();

    /** Insertion order, guarded by the class lock. Only {@link #expireOldest()} reads it. */
    private static final List<String> CREATION_ORDER = new ArrayList<String>();

    private StubSessionStore() {
    }

    /** Simulates a successful sign-in: mints an identifier and records it as live. */
    public static synchronized String loginAndCreateSession(String ticket) {
        byte[] material = new byte[32];
        RANDOM.nextBytes(material);
        String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(material);
        LIVE.put(sessionId, Boolean.TRUE);
        CREATION_ORDER.add(sessionId);
        if (ticket != null && !ticket.isEmpty()) {
            TICKETS.put(ticket, sessionId);
        }
        return sessionId;
    }

    /** Redeems a ticket for its session, leaving the ticket valid; a real one would be consumed. */
    public static String sessionForTicket(String ticket) {
        return ticket == null ? null : TICKETS.get(ticket);
    }

    public static boolean isLive(String sessionId) {
        return sessionId != null && Boolean.TRUE.equals(LIVE.get(sessionId));
    }

    /** Test-only: makes an identifier unknown, to exercise the "store does not confirm" path. */
    public static void expire(String sessionId) {
        if (sessionId != null) {
            LIVE.remove(sessionId);
        }
    }

    /**
     * Expires the oldest session that is still live and reports whether one was dropped. The
     * end-to-end script uses this to re-run an identical request and watch a grant turn into a
     * refusal, and "oldest still live" is the one session the script can name without an identifier:
     * it signs in with it before anything else does, and a previous call to this method has already
     * removed it from the live set, so the selector cannot be turned into a session-invalidation
     * oracle for a session the caller picked.
     */
    public static synchronized boolean expireOldest() {
        for (int i = 0; i < CREATION_ORDER.size(); i++) {
            String candidate = CREATION_ORDER.get(i);
            if (Boolean.TRUE.equals(LIVE.get(candidate))) {
                LIVE.remove(candidate);
                return true;
            }
        }
        return false;
    }

    public static int liveCount() {
        return LIVE.size();
    }
}
