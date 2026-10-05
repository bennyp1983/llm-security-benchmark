package com.example.identity;

/**
 * Security-relevant events that are not the outcome of a caller's request.
 *
 * <p>Kept separate from {@link Reason} because a {@code Reason} carries a user-visible message and
 * these events have no business being shown to anyone. The point of the enum is that
 * {@link AuditLog} accepts <em>no</em> free-text field at all: the set of things this program can
 * record is closed at compile time, which is what makes "the log never contains caller data" a
 * property of the types rather than a property of my discipline.
 *
 * <p>The names deliberately describe no identifier, address, or credential.
 */
enum AuditEvent {

    /** Process started with a validated configuration. */
    STARTED,
    /** Database opened and schema accepted. */
    STORE_OPENED,
    /** Sessions left by a previous run were deleted at startup. */
    SESSIONS_INVALIDATED_ON_START,
    /** A credential was re-derived at today's cost parameters during a successful sign-in. */
    CREDENTIAL_REENCODED,
    /** A rate-limit penalty engaged. Counters only; no identifier is recorded. */
    THROTTLE_ENGAGED,
    /** An account's administrative status changed. */
    STATUS_CHANGED,
    /** The audit log itself hit its size cap and stopped recording. */
    AUDIT_LOG_STOPPED,
    /** Database file permissions could not be set to owner-only. */
    DATABASE_FILE_NOT_PRIVATE,
    /** A row failed strict re-validation and was treated as absent. */
    ROW_REJECTED_AS_ABSENT;

    /** Fixed, secret-free description written into the line. */
    String describe() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
