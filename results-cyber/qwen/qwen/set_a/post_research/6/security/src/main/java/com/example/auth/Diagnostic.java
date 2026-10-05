package com.example.auth;

/**
 * Internal reason categories. Each carries a fixed, operator-facing explanation that is safe to
 * write to the log; none of them can contain a username, a password, an address or a token.
 */
enum Diagnostic {

    CREDENTIAL_MISMATCH("supplied password does not match the stored verifier"),
    SOURCE_ADDRESS_MISSING("no valid source address was supplied for the attempt"),
    USERNAME_INVALID("username failed validation before any store lookup"),
    SESSION_STORE_LIMIT("in-memory session capacity is exhausted"),
    WORK_UNAVAILABLE("the credential check could not be performed within the work budget"),
    PASSWORD_ENCODING_UNSUPPORTED("password contains code points that cannot be encoded exactly"),
    PASSWORD_TOO_SHORT("password failed the length policy"),
    PASSWORD_CONTROL_CHARACTER("password contains a control character"),
    STORE_UNAVAILABLE("credential store could not be read"),
    LOG_WRITE_FAILED("event could not be persisted to the log file"),
    LOG_STORAGE_FULL("the event log file system is below the configured free-space floor"),
    LOG_FILE_LIMIT("the event log file reached the accepted size limit and must be rotated"),
    LOG_PARTIAL_RECORD("a partial record at the end of the event log was discarded"),
    LOG_LINE_REJECTED("a log line failed the safety checks before it could be written"),
    AUDIT_UNAVAILABLE("the audit logger is closed or was never built"),
    INTERNAL("unexpected internal failure");

    private final String safeDetail;

    Diagnostic(String safeDetail) {
        this.safeDetail = safeDetail;
    }

    /** Fixed operator-facing text; contains no caller- or store-supplied content. */
    String safeDetail() {
        return safeDetail;
    }
}
