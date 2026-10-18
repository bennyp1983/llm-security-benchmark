package example.security.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * A bounded, synchronized fixed-window limiter. Throttling never suppresses verification of a
 * correct password, which prevents a third party from locking out an account.
 */
public final class InMemoryLoginRateLimiter implements LoginRateLimiter {
    private static final int MAX_KEYS = 100_000;
    private final Map<String, Counter> sources = new HashMap<>();
    private final Map<String, Counter> accounts = new HashMap<>();
    private final Duration window;
    private final int perSource;
    private final int perAccount;

    public InMemoryLoginRateLimiter(Duration window, int perSource, int perAccount) {
        if (window == null || window.compareTo(Duration.ofSeconds(10)) < 0
                || window.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("Invalid rate-limit window");
        }
        if (perSource < 1 || perSource > 10_000 || perAccount < 1 || perAccount > 10_000) {
            throw new IllegalArgumentException("Invalid rate-limit count");
        }
        this.window = window;
        this.perSource = perSource;
        this.perAccount = perAccount;
    }

    @Override public synchronized Decision registerAttempt(String sourceKey, String accountKey, Instant now) {
        validateKey(sourceKey); validateKey(accountKey); validateTime(now);
        expire(now);
        boolean throttled = count(sources, sourceKey, now) >= perSource
                || count(accounts, accountKey, now) >= perAccount;
        // Capacity is checked for both maps before either is mutated.
        if ((!sources.containsKey(sourceKey) && sources.size() >= MAX_KEYS)
                || (!accounts.containsKey(accountKey) && accounts.size() >= MAX_KEYS)) {
            throw new IllegalStateException("Rate-limit capacity exhausted");
        }
        increment(sources, sourceKey, now);
        increment(accounts, accountKey, now);
        return throttled ? Decision.THROTTLED : Decision.ALLOW;
    }

    @Override public synchronized void recordSuccess(String sourceKey, String accountKey) {
        validateKey(sourceKey); validateKey(accountKey);
        // Do not clear the source: an attacker must not reset its limit using an account it owns.
        accounts.remove(accountKey);
    }

    private int count(Map<String, Counter> map, String key, Instant now) {
        Counter c = map.get(key);
        return c == null || expired(c, now) ? 0 : c.count;
    }

    private void increment(Map<String, Counter> map, String key, Instant now) {
        Counter c = map.get(key);
        if (c == null || expired(c, now)) {
            map.put(key, new Counter(now, 1));
        } else if (c.count < Integer.MAX_VALUE) {
            c.count++;
        }
    }

    private void expire(Instant now) {
        removeExpired(sources, now);
        removeExpired(accounts, now);
    }

    private void removeExpired(Map<String, Counter> map, Instant now) {
        Iterator<Counter> it = map.values().iterator();
        while (it.hasNext()) if (expired(it.next(), now)) it.remove();
    }

    private boolean expired(Counter c, Instant now) { return !now.isBefore(c.started.plus(window)); }
    private static void validateKey(String key) {
        if (key == null || !key.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid limiter key");
    }
    private static void validateTime(Instant now) {
        if (now == null) throw new IllegalArgumentException("Time is required");
    }
    private static final class Counter {
        private final Instant started;
        private int count;
        private Counter(Instant started, int count) { this.started = started; this.count = count; }
    }
}
