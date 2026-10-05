package com.example.websession;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A bounded, thread-safe fixed-window counter.
 *
 * <p>Read-then-write on a shared counter is the classic check-then-act race: two concurrent
 * requests both read "9 of 10 used" and both proceed. Here the read, the window roll, and
 * the increment happen inside a single {@link ConcurrentHashMap#compute} call, which the
 * map performs atomically per key, and the decision is made from the value that call
 * returned -- never from a second lookup.</p>
 *
 * <p>The key space is bounded. An attacker who can vary the key (a spoofed source address,
 * say) would otherwise be able to exhaust heap through the limiter meant to protect the
 * service. When the map is full, expired windows are purged; if it is still full, new keys
 * are refused, which fails closed.</p>
 */
final class FixedWindowRateLimiter {

    private record Window(long startMillis, int count) {
    }

    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();
    private final int permitsPerWindow;
    private final long windowMillis;
    private final int maxTrackedKeys;

    FixedWindowRateLimiter(int permitsPerWindow, long windowMillis, int maxTrackedKeys) {
        if (permitsPerWindow < 1 || windowMillis < 1 || maxTrackedKeys < 1) {
            throw new IllegalArgumentException("rate limiter parameters must be positive");
        }
        this.permitsPerWindow = permitsPerWindow;
        this.windowMillis = windowMillis;
        this.maxTrackedKeys = maxTrackedKeys;
    }

    /**
     * Consumes one permit for {@code key}.
     *
     * @return {@code true} if the request is within the limit
     */
    boolean tryAcquire(String key, long nowMillis) {
        if (key == null) {
            return false;
        }
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                return false;
            }
        }
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || nowMillis - existing.startMillis() >= windowMillis) {
                return new Window(nowMillis, 1);
            }
            // Saturate rather than overflow into a negative count, which would reopen the gate.
            int next = existing.count() == Integer.MAX_VALUE ? existing.count() : existing.count() + 1;
            return new Window(existing.startMillis(), next);
        });
        return updated.count() <= permitsPerWindow;
    }

    private void purgeExpired(long nowMillis) {
        for (Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Window> entry = it.next();
            if (nowMillis - entry.getValue().startMillis() >= windowMillis) {
                it.remove();
            }
        }
    }

    int trackedKeys() {
        return windows.size();
    }
}
