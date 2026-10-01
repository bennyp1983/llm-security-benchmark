package com.example.portal.auth;

import java.util.Optional;

/**
 * The outcome of an authentication attempt, as the caller is allowed to see it.
 *
 * <p>Deliberately coarse. There is no field saying <em>why</em> an attempt failed: an unknown
 * account, a wrong password, an account under restriction and a source under restriction all produce
 * the same {@code granted=false} and the same {@link #message()}. The distinction exists only in the
 * audit log. A front end cannot leak what it was never given.
 */
public final class AuthResult {

    /**
     * The single message shown for every unsuccessful outcome. Identical text in every case, so the
     * response cannot be used to confirm that an account exists or that it is locked.
     */
    public static final String GENERIC_FAILURE_MESSAGE =
            "Access denied. Check your credentials and try again later; "
                    + "contact the IT service desk if the problem continues.";

    private static final String SUCCESS_MESSAGE = "Access granted.";

    private final boolean granted;
    private final String message;
    private final Session session;
    private final String token;

    private AuthResult(boolean granted, String message, Session session, String token) {
        this.granted = granted;
        this.message = message;
        this.session = session;
        this.token = token;
    }

    static AuthResult granted(SessionManager.Issued issued) {
        return new AuthResult(true, SUCCESS_MESSAGE, issued.session(), issued.token());
    }

    static AuthResult denied() {
        return new AuthResult(false, GENERIC_FAILURE_MESSAGE, null, null);
    }

    /** Whether access is granted. The only authorisation signal a caller should branch on. */
    public boolean granted() {
        return granted;
    }

    /** The message to show the user, generic on every failure. */
    public String message() {
        return message;
    }

    /** The server-side session, present only on success. */
    public Optional<Session> session() {
        return Optional.ofNullable(session);
    }

    /**
     * The session token, present only on success.
     *
     * <p>A bearer credential: hand it to the client over a confidential channel -- see
     * {@link SessionCookie} for the web path -- and do not log, print or persist it.
     */
    public Optional<String> sessionToken() {
        return Optional.ofNullable(token);
    }

    /** Never renders the token. */
    @Override
    public String toString() {
        return "AuthResult[granted=" + granted + ", session=" + session + ", token=<redacted>]";
    }
}
