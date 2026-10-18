package com.portal.auth;

import java.time.Duration;
import java.util.Objects;

/**
 * Thresholds that decide when consecutive failed logins stop being tolerated.
 *
 * <p>The defaults follow the NIST SP 800-63B guidance for a small internal portal: throttle rather
 * than forbid, keep the throttle short enough that a legitimate user locked out by a fat finger is
 * back in a few minutes, and escalate to a hard lock only when a single account keeps absorbing
 * attempts after repeated throttling.
 */
public record LoginPolicy(
        int maxFailedAttempts,
        Duration failureWindow,
        Duration lockDuration,
        int permanentLockAfterLocks) {

    /** 5 wrong passwords inside 15 minutes locks the account for 15 minutes. */
    public static final LoginPolicy DEFAULT = new LoginPolicy(
            5, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);

    public LoginPolicy {
        Objects.requireNonNull(failureWindow, "failureWindow");
        Objects.requireNonNull(lockDuration, "lockDuration");
        if (maxFailedAttempts < 1) {
            throw new IllegalArgumentException("maxFailedAttempts must be at least 1");
        }
        if (failureWindow.isNegative() || failureWindow.isZero()) {
            throw new IllegalArgumentException("failureWindow must be positive");
        }
        if (lockDuration.isNegative() || lockDuration.isZero()) {
            throw new IllegalArgumentException("lockDuration must be positive");
        }
        if (permanentLockAfterLocks < 0) {
            throw new IllegalArgumentException("permanentLockAfterLocks must be 0 (never) or greater");
        }
    }
}
