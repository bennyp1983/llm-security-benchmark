package com.example.auth;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link CredentialStore} held in memory, for tests and for embedding where the
 * verifiers are loaded at start-up from configuration the deployment owns.
 *
 * <p>It contains no credentials of its own: nothing is pre-seeded, so running this
 * code grants nobody access. Records must be supplied at runtime by the caller.</p>
 */
public final class InMemoryCredentialStore implements CredentialStore {

    private final Map<String, CredentialRecord> records = new ConcurrentHashMap<>();

    /**
     * Registers a verifier for a username.
     *
     * @throws IllegalArgumentException if the username does not meet {@link InputPolicy}
     */
    public void put(String username, CredentialRecord record) {
        String canonical = InputPolicy.canonicalUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("username rejected by policy"));
        records.put(canonical, record);
    }

    @Override
    public Optional<CredentialRecord> find(String canonicalUsername) {
        return Optional.ofNullable(records.get(canonicalUsername));
    }
}
