package com.example.auth;

/**
 * Raised when an event could not be persisted.
 *
 * <p>The caller must treat authentication as failed. An event that is not durable is an
 * authentication decision that cannot be reviewed later, which is exactly the condition the log
 * exists to prevent, so the attempt is refused rather than allowed.
 *
 * <p>Like {@link AuthException}, this carries only a {@link Diagnostic} category. The suppressed
 * cause is deliberate: the underlying {@code IOException} message contains the log path, which must
 * not reach a caller.
 */
final class AuditPersistenceException extends Exception {

    private static final long serialVersionUID = 1L;

    private final Diagnostic diagnostic;
    private final AuthEvent event;

    AuditPersistenceException(Diagnostic diagnostic) {
        this(diagnostic, null);
    }

    /**
     * @param event the event that could not be written, when the failure was about one specific
     *     event. It is never rendered into this exception's message: only fields that are already
     *     safe to record are offered back, so the alert replacing the event can keep the attribution
     *     the event carried instead of reporting an unattributed error.
     */
    AuditPersistenceException(Diagnostic diagnostic, AuthEvent event) {
        super(diagnostic.safeDetail(), null, false, false);
        this.diagnostic = diagnostic;
        this.event = event;
    }

    Diagnostic diagnostic() {
        return diagnostic;
    }

    /** The unsaved event, or {@code null} when the failure was not about one specific event. */
    AuthEvent unsavedEvent() {
        return event;
    }
}
