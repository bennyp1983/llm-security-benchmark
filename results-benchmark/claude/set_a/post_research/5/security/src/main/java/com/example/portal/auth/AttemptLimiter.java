package com.example.portal.auth;

import java.time.Duration;

/**
 * Tracks failed authentication attempts and applies a temporary restriction once the permitted
 * number is exceeded.
 *
 * <p>Two independent budgets are enforced, because either alone is exploitable:
 *
 * <ul>
 *   <li><b>Per account.</b> Stops an attacker guessing many passwords against one employee.</li>
 *   <li><b>Per source.</b> Stops an attacker spreading a few guesses each across the whole employee
 *       directory -- password spraying, which a per-account limit never notices.</li>
 * </ul>
 *
 * <p>Both restrictions expire. A permanent account lock would mean anyone who knows an employee's
 * username can take that employee offline at will: the limit itself becomes the denial of service.
 * A restriction that lifts after a fixed interval caps guessing throughput without handing anyone
 * that lever.
 *
 * <p>Implementations must consume the attempt slot <em>before</em> the password is verified, and must
 * make the read-decide-update sequence atomic with respect to other attempts. Verifying first and
 * counting afterwards lets concurrent requests all observe "one attempt left" and proceed together.
 */
public interface AttemptLimiter {

    /** Why an attempt was refused, or that it was permitted. */
    enum Decision {
        /** A slot was consumed; the caller may verify the credential. */
        PERMITTED,
        /** The account has exceeded its budget and is under restriction. */
        ACCOUNT_RESTRICTED,
        /** The source has exceeded its budget and is under restriction. */
        SOURCE_RESTRICTED,
        /** Tracking capacity is exhausted; the attempt is refused rather than left untracked. */
        CAPACITY_EXHAUSTED,
        /** The tracker itself could not be consulted; the attempt is refused. */
        UNAVAILABLE
    }

    /**
     * Tunable budgets.
     *
     * @param maxAccountAttempts non-successful attempts permitted per account within the window
     * @param accountWindow      interval over which account attempts accumulate
     * @param accountRestriction how long an account stays restricted once its budget is exceeded
     * @param maxSourceAttempts  non-successful attempts permitted per source within the window
     * @param sourceWindow       interval over which source attempts accumulate
     * @param sourceRestriction  how long a source stays restricted once its budget is exceeded
     * @param maxTrackedKeys     upper bound on tracked keys per budget, so an attacker inventing
     *                           usernames cannot grow the tracker without limit
     */
    record Limits(int maxAccountAttempts,
                  Duration accountWindow,
                  Duration accountRestriction,
                  int maxSourceAttempts,
                  Duration sourceWindow,
                  Duration sourceRestriction,
                  int maxTrackedKeys) {

        public Limits {
            if (maxAccountAttempts < 1 || maxSourceAttempts < 1) {
                throw new IllegalArgumentException("attempt budgets must be positive");
            }
            if (maxTrackedKeys < 1) {
                throw new IllegalArgumentException("tracking capacity must be positive");
            }
            requirePositive(accountWindow, "accountWindow");
            requirePositive(accountRestriction, "accountRestriction");
            requirePositive(sourceWindow, "sourceWindow");
            requirePositive(sourceRestriction, "sourceRestriction");
        }

        private static void requirePositive(Duration d, String name) {
            if (d == null || d.isZero() || d.isNegative()) {
                throw new IllegalArgumentException(name + " must be a positive duration");
            }
        }

        /**
         * The portal's defaults: five attempts per account and fifty per source, each counted over
         * 15 minutes, each restricted for 15 minutes once exceeded.
         *
         * <p>The source budget is ten times the account budget so that a shared office address or
         * NAT gateway does not trip it during ordinary use, while a spraying run across dozens of
         * accounts still does.
         */
        public static Limits defaults() {
            return new Limits(5, Duration.ofMinutes(15), Duration.ofMinutes(15),
                    50, Duration.ofMinutes(15), Duration.ofMinutes(15),
                    100_000);
        }
    }

    /** A reserved attempt slot, or the reason one was refused. */
    record Reservation(Decision decision, String account, String source) {
        public boolean permitted() {
            return decision == Decision.PERMITTED;
        }
    }

    /**
     * Atomically consumes one attempt slot for {@code source} and then one for {@code account}.
     *
     * <p>Both arguments must already have passed {@link InputPolicy} validation.
     */
    Reservation tryReserve(String account, String source);

    /** Returns the slots consumed by a reservation that ended in a successful authentication. */
    void recordSuccess(Reservation reservation);

    /**
     * Confirms that a reserved attempt failed.
     *
     * <p>The slot was consumed at reservation time, so implementations apply no further increment;
     * this keeps the accounting explicit at the call site without making the effective budget depend
     * on which call sites remembered to call it.
     */
    void recordFailure(Reservation reservation);
}
