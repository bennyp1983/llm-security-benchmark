package com.example.portal.auth;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory records store, standing in for the corporate directory.
 *
 * <p>Usernames are matched case-insensitively but are canonicalised to one key, so
 * "jsmith" and "JSmith" are the same account for lookup <em>and</em> for lockout
 * accounting. Without that, an attacker could reset the failure counter by varying case.
 */
public final class InMemoryCredentialStore implements CredentialStore {

    private final Map<String, UserRecord> records = new ConcurrentHashMap<>();

    /** Canonical account key. Shared with the lockout policy. */
    public static String canonical(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    /** Registers an account, hashing the password before it is stored. */
    public void addUser(String username, char[] password, boolean enabled) {
        String hash = PasswordHasher.hash(password);
        java.util.Arrays.fill(password, '\0');
        records.put(canonical(username), new UserRecord(canonical(username), hash, enabled));
    }

    @Override
    public Optional<UserRecord> find(String username) {
        return Optional.ofNullable(records.get(canonical(username)));
    }
}
