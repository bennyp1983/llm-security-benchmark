package com.security.auth.repository;

import com.security.auth.model.UserRecord;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory thread-safe implementation of UserCredentialRepository.
 * Enforces bounded storage size to prevent memory exhaustion (Rule 5).
 */
public final class InMemoryUserCredentialRepository implements UserCredentialRepository {

    private static final int DEFAULT_MAX_USERS = 10_000;

    private final int maxUsers;
    private final ConcurrentHashMap<String, UserRecord> store;

    public InMemoryUserCredentialRepository() {
        this(DEFAULT_MAX_USERS);
    }

    public InMemoryUserCredentialRepository(int maxUsers) {
        if (maxUsers <= 0) {
            throw new IllegalArgumentException("Max users must be positive.");
        }
        this.maxUsers = maxUsers;
        this.store = new ConcurrentHashMap<>(16);
    }

    /**
     * Stores a validated UserRecord into server-side state.
     *
     * @param record user record to store
     */
    public void putUser(UserRecord record) {
        Objects.requireNonNull(record, "UserRecord cannot be null.");
        if (store.size() >= maxUsers && !store.containsKey(record.getUsername())) {
            throw new IllegalStateException("User repository capacity reached (" + maxUsers + ").");
        }
        store.put(record.getUsername(), record);
    }

    @Override
    public Optional<UserRecord> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(store.get(username));
    }

    public int size() {
        return store.size();
    }
}
