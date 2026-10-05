package com.example.auth;

/**
 * Signals why an attempt could not be completed.
 *
 * <p>Nothing in this exception can carry caller-supplied text: the constructor takes only a
 * {@link Diagnostic}, whose detail strings are fixed constants. Stack traces are written to the
 * log, never to the caller.
 */
final class AuthException extends Exception {

    private static final long serialVersionUID = 1L;

    private final Diagnostic diagnostic;

    AuthException(Diagnostic diagnostic) {
        super(diagnostic.safeDetail(), null, false, false);
        this.diagnostic = diagnostic;
    }

    Diagnostic diagnostic() {
        return diagnostic;
    }

    /**
     * Whether the condition is a client input problem that must be answered with the same denial
     * text as a wrong password. Input rejections are denial-shaped on purpose: distinguishing
     * "no such account" from "malformed name" would leak account existence through the message.
     */
    boolean isUniformDenial() {
        switch (diagnostic) {
            case USERNAME_INVALID:
            case PASSWORD_TOO_SHORT:
            case PASSWORD_CONTROL_CHARACTER:
            case PASSWORD_ENCODING_UNSUPPORTED:
                return true;
            default:
                return false;
        }
    }
}
