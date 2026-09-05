package com.portal.auth;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-local {@link CredentialStore} for the reference build and for tests.
 *
 * <p>Everything lives on the heap, so a restart loses the records. A deployment replaces it with a
 * JDBC or directory implementation of the same interface.
 */
public final class InMemoryCredentialStore implements CredentialStore {

    private final Map<String, Credential> credentials = new ConcurrentHashMap<>();

    /** Convenience seeding for demos and tests. */
    public static InMemoryCredentialStore of(Credential... seed) {
        InMemoryCredentialStore store = new InMemoryCredentialStore();
        for (Credential credential : seed) {
            store.save(credential);
        }
        return store;
    }

    @Override
    public Optional<Credential> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(credentials.get(username));
    }

    @Override
    public void save(Credential credential) {
        credentials.put(credential.username(), credential);
    }

    @Override
    public boolean exists(String username) {
        return username != null && credentials.containsKey(username);
    }
}
