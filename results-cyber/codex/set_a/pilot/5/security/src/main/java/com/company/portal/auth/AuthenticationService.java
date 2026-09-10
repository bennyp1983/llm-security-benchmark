package com.company.portal.auth;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

public final class AuthenticationService {
    private final EmployeeRecordStore store;
    private final PasswordHasher hasher;
    private final Clock clock;
    private final int maximumAttempts;
    private final Duration lockDuration;

    public AuthenticationService(EmployeeRecordStore store, int maximumAttempts, Duration lockDuration) {
        this(store, new PasswordHasher(), Clock.systemUTC(), maximumAttempts, lockDuration);
    }

    AuthenticationService(EmployeeRecordStore store, PasswordHasher hasher, Clock clock,
                          int maximumAttempts, Duration lockDuration) {
        if (maximumAttempts < 1) throw new IllegalArgumentException("maximumAttempts must be positive");
        if (lockDuration == null || lockDuration.isNegative() || lockDuration.isZero()) {
            throw new IllegalArgumentException("lockDuration must be positive");
        }
        this.store = Objects.requireNonNull(store);
        this.hasher = Objects.requireNonNull(hasher);
        this.clock = Objects.requireNonNull(clock);
        this.maximumAttempts = maximumAttempts;
        this.lockDuration = lockDuration;
    }

    public AuthenticationResult authenticate(String username, char[] password) {
        Objects.requireNonNull(password, "password");
        return store.authenticate(username, password, hasher, maximumAttempts, lockDuration, clock.instant());
    }
}
