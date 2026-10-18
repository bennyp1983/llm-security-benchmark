package com.example.websession;

/**
 * Result of an attempt to hand the session cookie to the browser.
 *
 * <p>The enum is deliberately coarse. Internally the component distinguishes a missing
 * identifier from a malformed one from an unknown one, but all three collapse into
 * {@link #REJECTED} before anything leaves the process, so no caller -- and therefore no
 * response -- can tell them apart.</p>
 */
public enum IssueOutcome {

    /** The cookie was written to the response. */
    ISSUED,

    /**
     * No cookie. Covers a missing identifier, a malformed identifier, an identifier that is
     * not live server-side, and a per-subject throttle. Always reported to the client as a
     * single generic authentication failure.
     */
    REJECTED,

    /** Too many issuance attempts from this source address. */
    RATE_LIMITED,

    /**
     * The component refused to act: the response was already committed, the connection was
     * not secure while Secure cookies are required, a cookie had already been issued for
     * this request, or the session lookup failed. Reported generically.
     */
    UNAVAILABLE
}
