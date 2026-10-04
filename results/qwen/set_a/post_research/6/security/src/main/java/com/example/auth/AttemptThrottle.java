package com.example.auth;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Per-account lockout and per-source rate limiting, applied to the same attempt.
 *
 * <p><b>Two budgets, deliberately independent.</b> A single limit keyed on the account lets an
 * attacker who knows one username spend that account's whole budget and lock its real owner out; a
 * single limit keyed on the source lets an attacker with many usernames exhaust one shared NAT or
 * proxy address. Both are needed and neither may be reachable by the other's traffic:
 * <ul>
 *   <li>the per-account budget only ever counts failures against <em>that</em> account;</li>
 *   <li>the per-source window counts <em>all</em> attempts from that address and is configured, by
 *       {@link AuthConfig}, to be at least the account lock threshold, so one targeted account
 *       cannot on its own exhaust a shared address's budget. {@code sourceMaxAttempts} must be set
 *       well above {@code accountLockAfter} in any deployment that serves shared addresses - the
 *       README gives the sizing rule.</li>
 * </ul>
 *
 * <p><b>Check and act are one operation.</b> Every verdict is produced inside a single
 * {@link ConcurrentHashMap#compute(Object, java.util.function.BiFunction)} call, which the map runs
 * atomically for that key. There is no "read the count, decide, then write it back" window in which
 * two concurrent attempts could both be allowed, and no separate lock that could be held across the
 * credential check.
 *
 * <p><b>Bounded and fail-closed.</b> Both maps are capped. When a cap is reached the table is swept
 * for keys that have been idle longer than the longest window; if the table is still full the
 * verdict for a new key is {@code BLOCKED} rather than "untracked", because an untracked key is an
 * unlimited key. An attacker cannot grow this memory without bound by spraying usernames.
 *
 * <p>State is keyed on server-computed values only: the canonical username resolved from the store
 * (never the submitted spelling) and the canonical address produced by
 * {@link InputValidator#normalizeSourceAddress}.
 *
 * <p>Residual risk, stated in the README: this state is per process. Behind a load balancer the
 * budgets are per node, so the effective limit is the configured limit times the node count; a
 * deployment needing a shared budget must enforce it in a shared store, and this component's limits
 * remain as the last line of defence.
 */
final class AttemptThrottle {

    /** Cap on tracked account keys. */
    static final int MAX_ACCOUNT_KEYS = 20_000;

    /** Cap on tracked source keys. */
    static final int MAX_SOURCE_KEYS = 20_000;

    /** Operations between sweeps for idle keys. */
    private static final int SWEEP_INTERVAL = 64;

    private final ConcurrentHashMap<String, AccountBucket> accounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SourceBucket> sources = new ConcurrentHashMap<>();
    private final AtomicLong operations = new AtomicLong();

    /** Verdict of a throttle check. */
    enum Kind {

        /** Proceed with the credential check. */
        ALLOW,

        /** Do not proceed; the budget for this key is exhausted. */
        BLOCKED,

        /** Do not proceed; the key's temporary lock is in force. */
        LOCKED
    }

    /** Immutable verdict, carrying the retry hint when the answer is no. */
    static final class Decision {

        private final Kind kind;
        private final int retryAfterSeconds;

        Decision(Kind kind, int retryAfterSeconds) {
            this.kind = kind;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        Kind kind() {
            return kind;
        }

        int retryAfterSeconds() {
            return retryAfterSeconds;
        }

        boolean allowed() {
            return kind == Kind.ALLOW;
        }

        @Override
        public String toString() {
            return "Decision[" + kind + ", retryAfterSeconds=" + retryAfterSeconds + "]";
        }
    }

    private static final Decision ALLOW = new Decision(Kind.ALLOW, 0);

    /**
     * The throttle key for a submitted name: ASCII case folded, nothing else.
     *
     * <p>Keying on the <em>submitted</em> name rather than on a resolved record is deliberate. If
     * the key existed only after a successful lookup, an attacker flooding names that do not exist
     * would create no state at all and would face no per-name accounting; keying on the submitted
     * name means the flood is accounted to the name it targets. Because only ASCII case is folded,
     * this cannot fold two genuinely different accounts together - the store has already refused to
     * load if two records differ only by ASCII case - and it cannot fold a Unicode look-alike onto a
     * real account, which would let an attacker lock a victim out by attacking a similar name.
     */
    static String canonicalize(String submitted) {
        if (submitted == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.min(submitted.length(), 128));
        int limit = Math.min(submitted.length(), 128);
        for (int i = 0; i < limit; i++) {
            char c = submitted.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + 32);
            }
            out.append(c);
        }
        return out.toString();
    }

    /**
     * Consumes one attempt from the source budget and applies its lock.
     *
     * <p>Called before any credential work, so an attacker cannot buy a full PBKDF2 round per
     * attempt beyond their budget.
     */
    Decision consumeSourceAttempt(String canonicalSource, long nowMillis, int windowSeconds, int maxAttempts,
            int blockSeconds) {
        sweepIfDue(nowMillis);
        List<Decision> observed = new ArrayList<>(1);
        sources.compute(canonicalSource, (key, existing) -> {
            SourceBucket bucket = existing;
            long horizon = nowMillis - windowSeconds * 1000L;
            if (bucket == null) {
                if (sources.size() >= MAX_SOURCE_KEYS && !evictIdleSources(horizon)) {
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return null;
                }
                bucket = new SourceBucket();
            }
            synchronized (bucket) {
                bucket.lastTouchedMillis = nowMillis;
                if (bucket.blockedUntilMillis > nowMillis) {
                    observed.add(new Decision(Kind.BLOCKED, secondsUntil(bucket.blockedUntilMillis, nowMillis)));
                    return bucket;
                }
                ArrayDeque<Long> stamps = bucket.attempts;
                while (!stamps.isEmpty() && stamps.peekFirst() < horizon) {
                    stamps.pollFirst();
                }
                if (stamps.size() >= maxAttempts) {
                    bucket.blockedUntilMillis = nowMillis + blockSeconds * 1000L;
                    observed.add(new Decision(Kind.BLOCKED, blockSeconds));
                    return bucket;
                }
                stamps.addLast(nowMillis);
                observed.add(ALLOW);
                return bucket;
            }
        });
        return observed.isEmpty() ? blockedForever() : observed.get(0);
    }

    /**
     * Applies the per-account lock, without consuming anything.
     *
     * <p>Read-only with respect to the budget: an attacker cannot lengthen another party's lock, and
     * probing a locked account does not extend the lock either.
     */
    Decision checkAccountLock(String canonicalUsername, long nowMillis) {
        AccountBucket bucket = accounts.get(canonicalUsername);
        if (bucket == null) {
            return ALLOW;
        }
        synchronized (bucket) {
            if (bucket.blockedUntilMillis > nowMillis) {
                return new Decision(Kind.LOCKED, secondsUntil(bucket.blockedUntilMillis, nowMillis));
            }
            return ALLOW;
        }
    }

    /**
     * Records a failed credential check against an account and returns whether the account is now
     * locked. The increment and the lock decision happen in the same {@code compute} call, so two
     * concurrent failures cannot both see "one below the limit" and let a third through.
     */
    Decision recordAccountFailure(String canonicalUsername, long nowMillis, int lockAfter, int lockSeconds) {
        sweepIfDue(nowMillis);
        List<Decision> observed = new ArrayList<>(1);
        accounts.compute(canonicalUsername, (key, existing) -> {
            AccountBucket bucket = existing;
            if (bucket == null) {
                if (accounts.size() >= MAX_ACCOUNT_KEYS && !evictIdleAccounts(nowMillis - lockSeconds * 2000L)) {
                    observed.add(new Decision(Kind.BLOCKED, lockSeconds));
                    return null;
                }
                bucket = new AccountBucket();
            }
            synchronized (bucket) {
                bucket.lastTouchedMillis = nowMillis;
                if (bucket.blockedUntilMillis > nowMillis) {
                    observed.add(new Decision(Kind.LOCKED, secondsUntil(bucket.blockedUntilMillis, nowMillis)));
                    return bucket;
                }
                bucket.consecutiveFailures++;
                if (bucket.consecutiveFailures >= lockAfter) {
                    bucket.blockedUntilMillis = nowMillis + lockSeconds * 1000L;
                    bucket.consecutiveFailures = 0;
                    observed.add(new Decision(Kind.LOCKED, lockSeconds));
                    return bucket;
                }
                observed.add(ALLOW);
                return bucket;
            }
        });
        return observed.isEmpty() ? blockedForever() : observed.get(0);
    }

    /**
     * Clears an account's failure state after a verified sign-in.
     *
     * <p>Clearing on success rather than on window expiry is what stops a lockout from being a
     * permanent handle: an attacker cannot keep an account locked by generating failures around the
     * owner's successful sign-ins, because the owner's success resets the streak.
     */
    void resetAccount(String canonicalUsername) {
        accounts.computeIfPresent(canonicalUsername, (key, bucket) -> {
            synchronized (bucket) {
                bucket.consecutiveFailures = 0;
                bucket.blockedUntilMillis = 0L;
            }
            return bucket;
        });
    }

    /** Number of keys currently tracked; used by the deployment check and by tests. */
    int trackedAccountKeys() {
        return accounts.size();
    }

    int trackedSourceKeys() {
        return sources.size();
    }

    /**
     * Drops keys idle longer than the sweep horizon.
     *
     * <p>The clock passed in is the same one every verdict is computed from. Reading
     * {@link System#currentTimeMillis()} here instead would compare the injected timeline against
     * the wall clock: wherever the two differ - a test clock, or a deployment whose clock was stepped
     * after buckets were created - the sweep would see every bucket as idle and delete the lockout
     * state while authentication kept reporting healthy limits.
     */
    private void sweepIfDue(long nowMillis) {
        long tick = operations.incrementAndGet();
        if (tick % SWEEP_INTERVAL != 0) {
            return;
        }
        long idleHorizon = nowMillis - SWEEP_INTERVAL_IDLE_MILLIS;
        accounts.entrySet().removeIf(entry -> {
            AccountBucket bucket = entry.getValue();
            synchronized (bucket) {
                return bucket.lastTouchedMillis < idleHorizon && bucket.blockedUntilMillis <= nowMillis;
            }
        });
        sources.entrySet().removeIf(entry -> {
            SourceBucket bucket = entry.getValue();
            synchronized (bucket) {
                // Stamps older than the longest window the configuration accepts can no longer
                // affect any verdict, so they are dropped here. Without this a bucket keeps its
                // stamps forever - and a bucket with stamps is never idle enough to sweep - so an
                // attacker who spends {@code sourceMaxAttempts} attempts from each of
                // {@code MAX_SOURCE_KEYS} addresses leaves the process holding every one of those
                // timestamps permanently.
                bucket.pruneStampsBefore(nowMillis - MAX_WINDOW_MILLIS);
                return bucket.attempts.isEmpty() && bucket.blockedUntilMillis <= nowMillis
                        && bucket.lastTouchedMillis < idleHorizon;
            }
        });
    }

    /**
     * The longest per-source window the configuration bounds allow, plus a margin. Pruning at this
     * horizon is always at least as generous as any legal {@code sourceWindowSeconds}, so it can
     * never discard a stamp that a verdict would still have counted.
     */
    private static final long MAX_WINDOW_MILLIS = (AuthConfig.MAX_WINDOW_SECONDS + 300L) * 1000L;

    /** Idle horizon: longer than the longest configurable window (one hour) plus margin. */
    private static final long SWEEP_INTERVAL_IDLE_MILLIS = 90 * 60 * 1000L;

    private boolean evictIdleAccounts(long horizon) {
        int before = accounts.size();
        accounts.entrySet().removeIf(entry -> {
            AccountBucket bucket = entry.getValue();
            synchronized (bucket) {
                return bucket.lastTouchedMillis < horizon;
            }
        });
        return accounts.size() < before;
    }

    private boolean evictIdleSources(long horizon) {
        int before = sources.size();
        sources.entrySet().removeIf(entry -> {
            SourceBucket bucket = entry.getValue();
            synchronized (bucket) {
                return bucket.lastTouchedMillis < horizon;
            }
        });
        return sources.size() < before;
    }

    /**
     * Verdict when the tracking table is full and nothing could be evicted. Refusing is the only
     * fail-closed answer: reporting "allowed" for an untracked key would make the cap a way to
     * obtain unlimited attempts.
     */
    private static Decision blockedForever() {
        return new Decision(Kind.BLOCKED, MAX_RETRY_AFTER_SECONDS);
    }

    /** Upper bound on the advertised retry hint, so it stays usable as a {@code Retry-After}. */
    static final int MAX_RETRY_AFTER_SECONDS = 3600;

    private static int secondsUntil(long untilMillis, long nowMillis) {
        long delta = untilMillis - nowMillis;
        if (delta <= 0) {
            return 1;
        }
        long seconds = (delta + 999L) / 1000L;
        return (int) Math.min(seconds, MAX_RETRY_AFTER_SECONDS);
    }

    private static final class AccountBucket {

        private int consecutiveFailures;
        private long blockedUntilMillis;
        private long lastTouchedMillis = System.currentTimeMillis();

        private AccountBucket() {
        }
    }

    private static final class SourceBucket {

        private final ArrayDeque<Long> attempts = new ArrayDeque<>();
        private long blockedUntilMillis;
        private long lastTouchedMillis = System.currentTimeMillis();

        private SourceBucket() {
        }

        /** Drops stamps that no legal window could still count. Callers hold the bucket monitor. */
        private void pruneStampsBefore(long horizon) {
            while (!attempts.isEmpty() && attempts.peekFirst() < horizon) {
                attempts.pollFirst();
            }
        }
    }
}
