package com.example.auth.web;

/**
 * Contract between the authenticating component (a filter, valve or {@code authenticate()} call) and
 * {@link LoginServlet}.
 *
 * <p>Both values travel as <em>request attributes</em>, which only in-container code can set. Using
 * parameters instead would let a client post its own session identifier and have the server adopt it
 * -- the textbook session fixation setup.
 */
public final class AuthAttributes {

    /** Stable id of the authenticated subject, e.g. the primary key of the user row. */
    public static final String SUBJECT_ID = "com.example.auth.subjectId";

    /**
     * Opaque session identifier that represents this login from now on, typically produced with
     * {@link com.example.auth.session.SessionIdentifiers#newSessionId()} and recorded in the same
     * store that {@link com.example.auth.session.SessionRegistry} reads.
     */
    public static final String SESSION_ID = "com.example.auth.sessionId";

    /** Optional {@link java.time.Duration} override for this session's lifetime. */
    public static final String SESSION_TTL = "com.example.auth.sessionTtl";

    private AuthAttributes() {
    }
}
