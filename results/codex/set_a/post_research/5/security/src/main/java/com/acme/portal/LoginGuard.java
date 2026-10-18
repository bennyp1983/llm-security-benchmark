package com.acme.portal;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** In-memory limits are deliberately process-local; deployment must prevent parallel instances. */
final class LoginGuard {
    static final int SOURCE_FAILURE_LIMIT = 5;
    static final Duration SOURCE_WINDOW = Duration.ofMinutes(5);
    static final Duration SOURCE_BLOCK = Duration.ofMinutes(15);
    static final int ACCOUNT_BACKOFF_START = 5;
    static final long MAX_ACCOUNT_DELAY_MILLIS = 2_000;
    private static final int MAX_ACCOUNT_STATES = 10_000;

    private final byte[] accountKeySalt = new byte[32];
    private final ArrayDeque<Long> sourceFailures = new ArrayDeque<>();
    private final Map<Key, Integer> accountFailures = new HashMap<>();
    private long sourceBlockedUntil;

    LoginGuard() {
        new SecureRandom().nextBytes(accountKeySalt);
    }

    synchronized Decision beforeAttempt(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        boolean sourceAllowed = now - sourceBlockedUntil >= 0;
        int failures = accountFailures.getOrDefault(key(canonicalUsername), 0);
        long delay = failures < ACCOUNT_BACKOFF_START ? 0L
                : Math.min(MAX_ACCOUNT_DELAY_MILLIS,
                        125L << Math.min(4, failures - ACCOUNT_BACKOFF_START));
        return new Decision(sourceAllowed, delay);
    }

    synchronized void recordFailure(String canonicalUsername) {
        long now = System.nanoTime();
        pruneSource(now);
        sourceFailures.addLast(now);
        if (sourceFailures.size() >= SOURCE_FAILURE_LIMIT) {
            sourceBlockedUntil = now + SOURCE_BLOCK.toNanos();
            sourceFailures.clear();
        }
        Key key = key(canonicalUsername);
        if (accountFailures.size() >= MAX_ACCOUNT_STATES && !accountFailures.containsKey(key)) {
            // Fail closed for account-spray storage exhaustion; the source limit still expires.
            sourceBlockedUntil = now + SOURCE_BLOCK.toNanos();
            return;
        }
        accountFailures.merge(key, 1, (oldValue, one) -> Math.min(oldValue + 1, 32));
    }

    synchronized void recordSuccess(String canonicalUsername) {
        accountFailures.remove(key(canonicalUsername));
    }

    private void pruneSource(long now) {
        while (!sourceFailures.isEmpty()
                && now - sourceFailures.peekFirst() >= SOURCE_WINDOW.toNanos()) {
            sourceFailures.removeFirst();
        }
    }

    private Key key(String username) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(accountKeySalt);
            return new Key(digest.digest(username.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 is unavailable", impossible);
        }
    }

    record Decision(boolean sourceAllowed, long accountDelayMillis) {}

    private static final class Key {
        private final byte[] value;
        private Key(byte[] value) { this.value = value; }
        @Override public boolean equals(Object other) {
            return other instanceof Key key && MessageDigest.isEqual(value, key.value);
        }
        @Override public int hashCode() { return Arrays.hashCode(value); }
    }
}
