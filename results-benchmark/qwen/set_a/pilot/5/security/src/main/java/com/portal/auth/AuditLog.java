package com.portal.auth;

/**
 * Sink for authentication audit records.
 *
 * <p>An audit failure must never be what stops someone from logging in, and it must never be what
 * leaks a secret: implementations are expected to swallow their own I/O errors and to accept only
 * {@link AuditEvent}, which cannot carry a password.
 */
public interface AuditLog {

    void record(AuditEvent event);

    /** Discards everything; useful where the host application has its own audit pipeline. */
    static AuditLog none() {
        return event -> {};
    }
}
