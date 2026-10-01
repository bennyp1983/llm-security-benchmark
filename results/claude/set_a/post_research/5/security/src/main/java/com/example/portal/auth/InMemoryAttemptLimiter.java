package com.example.portal.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * An {@link AttemptLimiter} holding its counters in memory.
 *
 * <p>Suitable for a long-lived process -- the portal's web front end, where one JVM serves every
 * attempt. Not suitable for a short-lived command: when the process exits the counters go with it,
 * so an attacker who can start the program repeatedly gets a fresh budget each time. The console
 * front end uses {@link FileAttemptLimiter} for that reason.
 *
 * <p>A single {@link ReentrantLock} guards both counter maps. Serialising counter updates is
 * deliberate: it is what makes "check the budget, then spend from it" one indivisible step. The lock
 * is held only for the bookkeeping, never across the password derivation, so the expensive work
 * still proceeds in parallel.
 */
public final class InMemoryAttemptLimiter implements AttemptLimiter {

    private final Map<String, AttemptCounters.State> accounts = new HashMap<>();
    private final Map<String, AttemptCounters.State> sources = new HashMap<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Limits limits;
    private final LongSupplier clockMillis;

    public InMemoryAttemptLimiter(Limits limits) {
        this(limits, System::currentTimeMillis);
    }

    /** Takes an injectable epoch-millisecond clock so the self-test can advance time. */
    public InMemoryAttemptLimiter(Limits limits, LongSupplier clockMillis) {
        this.limits = limits;
        this.clockMillis = clockMillis;
    }

    @Override
    public Reservation tryReserve(String account, String source) {
        lock.lock();
        try {
            long now = clockMillis.getAsLong();
            // The source budget is evaluated first on purpose: if the account budget were spent
            // first, attempts the source restriction was going to refuse anyway would still count
            // against the employee, letting a blocked attacker keep a real user locked out.
            AttemptCounters.Slot sourceSlot = AttemptCounters.consume(sources, source,
                    limits.maxSourceAttempts(), limits.sourceWindow().toMillis(),
                    limits.sourceRestriction().toMillis(), now, limits.maxTrackedKeys());
            if (sourceSlot != AttemptCounters.Slot.PERMITTED) {
                return new Reservation(map(sourceSlot, Decision.SOURCE_RESTRICTED), account, source);
            }
            // A refused account reservation leaves the source slot spent, so hammering a restricted
            // account draws down the attacker's own source budget.
            AttemptCounters.Slot accountSlot = AttemptCounters.consume(accounts, account,
                    limits.maxAccountAttempts(), limits.accountWindow().toMillis(),
                    limits.accountRestriction().toMillis(), now, limits.maxTrackedKeys());
            if (accountSlot != AttemptCounters.Slot.PERMITTED) {
                return new Reservation(map(accountSlot, Decision.ACCOUNT_RESTRICTED), account, source);
            }
            return new Reservation(Decision.PERMITTED, account, source);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void recordSuccess(Reservation reservation) {
        if (!reservation.permitted()) {
            return;
        }
        lock.lock();
        try {
            AttemptCounters.clear(accounts, reservation.account());
            AttemptCounters.giveBack(sources, reservation.source());
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void recordFailure(Reservation reservation) {
        // Already counted by tryReserve().
    }

    private static Decision map(AttemptCounters.Slot slot, Decision restricted) {
        return slot == AttemptCounters.Slot.CAPACITY_EXHAUSTED ? Decision.CAPACITY_EXHAUSTED : restricted;
    }
}
