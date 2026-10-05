package example.security.auth;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded single-process session store. Use an atomic shared implementation in a cluster. */
public final class InMemorySessionStore implements SessionStore {
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final int maximum;
    private final Clock clock;

    public InMemorySessionStore(int maximum, Clock clock) {
        if (maximum < 1 || maximum > 1_000_000) throw new IllegalArgumentException("Invalid session capacity");
        this.maximum = maximum;
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
    }

    @Override public synchronized boolean create(byte[] digest, String accountId, Instant expiresAt) {
        validateDigest(digest);
        if (accountId == null || !accountId.matches("[A-Za-z0-9_-]{1,64}")) return false;
        Instant now = clock.instant();
        sessions.values().removeIf(s -> !s.expiresAt.isAfter(now));
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plusSeconds(86_400)) || sessions.size() >= maximum) {
            return false;
        }
        String key = Base64.getEncoder().encodeToString(digest);
        return sessions.putIfAbsent(key, new Session(accountId, expiresAt)) == null;
    }

    @Override public void revoke(byte[] digest) {
        validateDigest(digest);
        sessions.remove(Base64.getEncoder().encodeToString(digest));
    }

    private static void validateDigest(byte[] digest) {
        if (digest == null || digest.length != 32) throw new IllegalArgumentException("Invalid session digest");
    }
    private record Session(String accountId, Instant expiresAt) {}
}
