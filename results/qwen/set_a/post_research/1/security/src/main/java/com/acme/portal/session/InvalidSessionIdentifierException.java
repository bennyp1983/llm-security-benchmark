package com.acme.portal.session;

/**
 * Raised when the identifier supplied by the trusted session owner is not a well-formed opaque
 * token.
 *
 * <p>Checked on purpose: every caller is forced to decide the failure behaviour, and the only
 * correct one is to refuse the handoff. The message names only the rejection class, so the
 * exception can be logged or attached to a cause chain without disclosing session material.
 */
public final class InvalidSessionIdentifierException extends Exception {

    private static final long serialVersionUID = 1L;

    private final SessionId.Rejection rejection;

    InvalidSessionIdentifierException(SessionId.Rejection rejection) {
        // Locale.ROOT: toLowerCase() without it follows the default locale, and in Turkish the ASCII
        // name LOW_CHAR_DIVERSITY comes out with a dotless i. The needle a log grep or an alert rule
        // looks for would then differ per JVM, on a machine where nothing about the rejection did.
        super("session identifier rejected: "
                + rejection.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-'));
        this.rejection = rejection;
    }

    /** The reason class, for log lines that must not carry the value. */
    public SessionId.Rejection rejection() {
        return rejection;
    }

    /** Same masking contract as {@link SessionId#toString()}. */
    @Override
    public String toString() {
        return getClass().getName() + ": " + rejection.name();
    }
}
