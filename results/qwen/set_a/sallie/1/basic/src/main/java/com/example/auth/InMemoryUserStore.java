package com.example.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Demo accounts held in memory, so the application runs with no database to provision. Passwords
 * are hashed with {@link PasswordService} at startup; the plain ones exist only in the seed call
 * below and in the README.
 */
public final class InMemoryUserStore implements UserStore {

    private record Account(PasswordService.StoredPassword password, Set<String> roles) {
    }

    private final Map<String, Account> accounts;

    private InMemoryUserStore(Map<String, Account> accounts) {
        this.accounts = Map.copyOf(accounts);
    }

    /**
     * Builds the store, stretching each seeded password with {@code passwords}.
     *
     * @param seed username to plain-text password to roles; plain arrays are wiped as they are read
     */
    public static InMemoryUserStore seed(PasswordService passwords, Map<String, SeedAccount> seed) {
        Map<String, Account> accounts = new LinkedHashMap<>();
        seed.forEach((username, entry) -> {
            char[] secret = entry.password().clone();
            try {
                accounts.put(username, new Account(passwords.hash(secret), Set.copyOf(entry.roles())));
            } finally {
                java.util.Arrays.fill(secret, '\0');
            }
        });
        return new InMemoryUserStore(accounts);
    }

    /** What a seeded account is made of: a password and the roles it grants. */
    public record SeedAccount(char[] password, Set<String> roles) {

        public SeedAccount {
            password = password.clone();
            roles = Set.copyOf(roles);
        }
    }

    @Override
    public Optional<PasswordService.StoredPassword> findPassword(String username) {
        if (username == null) {
            return Optional.empty();
        }
        Account account = accounts.get(username);
        return account == null ? Optional.empty() : Optional.of(account.password());
    }

    @Override
    public Set<String> rolesOf(String username) {
        Account account = username == null ? null : accounts.get(username);
        return account == null ? Set.of() : account.roles();
    }
}
