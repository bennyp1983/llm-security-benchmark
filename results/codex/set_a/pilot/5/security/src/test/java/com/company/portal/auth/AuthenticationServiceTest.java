package com.company.portal.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

/** Dependency-free test runner; execute with assertions enabled (-ea). */
public final class AuthenticationServiceTest {
    public static void main(String[] args) {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        PasswordHasher hasher = new PasswordHasher();
        InMemoryEmployeeRecordStore store = new InMemoryEmployeeRecordStore();
        PasswordHasher.PasswordData data = hasher.hash("correct horse".toCharArray());
        store.add(new EmployeeRecord("Alice", data.salt(), data.hash()));
        store.add(new EmployeeRecord("Bob", data.salt(), data.hash()));

        AuthenticationService service = new AuthenticationService(
                store, hasher, Clock.fixed(now, ZoneOffset.UTC), 3, Duration.ofMinutes(10));

        assert service.authenticate("alice", "wrong-1".toCharArray()) == AuthenticationResult.INVALID_CREDENTIALS;
        assert service.authenticate("ALICE", "wrong-2".toCharArray()) == AuthenticationResult.INVALID_CREDENTIALS;
        assert service.authenticate("alice", "wrong-3".toCharArray()) == AuthenticationResult.ACCOUNT_LOCKED;
        assert service.authenticate("alice", "correct horse".toCharArray()) == AuthenticationResult.ACCOUNT_LOCKED;
        assert store.findForTesting("alice").consecutiveFailures() == 3;

        AuthenticationService afterExpiry = new AuthenticationService(
                store, hasher, Clock.fixed(now.plus(Duration.ofMinutes(11)), ZoneOffset.UTC),
                3, Duration.ofMinutes(10));
        assert afterExpiry.authenticate("alice", "correct horse".toCharArray()) == AuthenticationResult.AUTHENTICATED;
        assert store.findForTesting("alice").consecutiveFailures() == 0;

        // An expired lock starts a fresh sequence rather than immediately re-locking.
        AuthenticationService initialClock = new AuthenticationService(
                store, hasher, Clock.fixed(now, ZoneOffset.UTC), 3, Duration.ofMinutes(10));
        assert initialClock.authenticate("bob", "bad".toCharArray()) == AuthenticationResult.INVALID_CREDENTIALS;
        assert initialClock.authenticate("bob", "bad".toCharArray()) == AuthenticationResult.INVALID_CREDENTIALS;
        assert initialClock.authenticate("bob", "bad".toCharArray()) == AuthenticationResult.ACCOUNT_LOCKED;
        assert afterExpiry.authenticate("bob", "bad".toCharArray()) == AuthenticationResult.INVALID_CREDENTIALS;
        assert store.findForTesting("bob").consecutiveFailures() == 1;

        assert afterExpiry.authenticate("missing", "anything".toCharArray()) == AuthenticationResult.INVALID_CREDENTIALS;
        System.out.println("All authentication tests passed.");
    }
}
