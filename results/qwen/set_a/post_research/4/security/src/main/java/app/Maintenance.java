package app;

import java.sql.SQLException;

/**
 * Bounds the state that the feature itself creates.
 *
 * <p>Every failed sign-in, every distinct source and every issued session writes a row. Without a
 * sweep the store only grows, and unbounded growth in a security table is its own problem: it
 * slows the very lookups that decide access and eventually exhausts the disk, which the audit
 * trail turns into a denial. So the state that can no longer affect a decision is deleted -
 * expired or revoked sessions, elapsed throttle windows, and guard rows for accounts that are both
 * outside the recent window <em>and</em> hold no live state.
 *
 * <p>A sweep never weakens a control that is still in force. A source bucket is eligible only once
 * its whole window has elapsed, which is the moment its next attempt would refill it anyway, so
 * deleting rows cannot be used to reset a denial that is currently blocking somebody. A guard row is
 * kept for the same reason even when its account has aged out of retention: if its lockout has not
 * expired, or its failure window is still running, deleting it would hand a rate limit or a lockout
 * back to whoever triggered the sweep.
 *
 * <p>Failure to sweep is reported and ignored, never fatal and never a denial: this is a
 * housekeeping task, and refusing a sign-in because old rows were not deleted would be a denial of
 * service caused by maintenance rather than by an attack.
 */
public final class Maintenance {

    /** Guard rows are kept for this many of the most recently created accounts. */
    static final int RECENT_ACCOUNTS_TO_KEEP = 10_000;

    private final SessionStore sessions;
    private final Throttle throttle;
    private final Gate gate;

    public Maintenance(SessionStore sessions, Throttle throttle, Gate gate) {
        this.sessions = sessions;
        this.throttle = throttle;
        this.gate = gate;
    }

    /** Runs one sweep; returns the number of rows removed, which is zero when the sweep failed. */
    public int run() {
        int sessionsRemoved;
        int throttleRemoved;
        try {
            sessionsRemoved = sessions.purgeExpired();
            throttleRemoved = throttle.purgeStaleState(RECENT_ACCOUNTS_TO_KEEP);
        } catch (SQLException | AuditLog.AuditException sweepFailed) {
            System.err.println("NOTE the maintenance sweep could not complete;"
                + " the operation that triggered it is unaffected");
            return 0;
        }
        int removed = sessionsRemoved + throttleRemoved;
        // Only a sweep that changed state is recorded. This runs on every invocation, so a record per
        // no-op would make the trail grow in proportion to how often the program is started - the one
        // resource the audit budget exists to bound.
        if (removed == 0) {
            return 0;
        }
        try {
            gate.record(AuditLog.Event.MAINTENANCE_RUN,
                "sessions", Integer.toString(sessionsRemoved),
                "throttle", Integer.toString(throttleRemoved));
        } catch (AuditLog.AuditException auditUnwritable) {
            // Nothing was denied by this record, so an unwritable trail must not undo a sweep that
            // already committed. The state below is already smaller; reporting is all that failed.
            System.err.println("NOTE the maintenance sweep could not be recorded");
        }
        return removed;
    }
}
