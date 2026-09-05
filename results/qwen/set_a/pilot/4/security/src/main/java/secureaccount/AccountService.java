package secureaccount;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * Registration and authentication against an {@link AccountStore}.
 *
 * <p>This is the only place that ever sees the password, and it holds on to it for as little
 * time as the {@code char[]} it was handed allows. The store is written exclusively through
 * {@link PasswordHasher#hash(char[])}, so no code path can persist a password.
 */
public final class AccountService {

    /**
     * Returned for every failed login, whether the username is unknown or the password is
     * merely wrong. Distinguishing the two turns the login form into an account-enumeration
     * oracle, which is enough on its own to harvest a user list.
     */
    public static final String BAD_CREDENTIALS = "authentication failed";

    private final AccountStore store;
    private final PasswordHasher hasher;
    private final Clock clock;

    public AccountService(AccountStore store, PasswordHasher hasher) {
        this(store, hasher, Clock.systemUTC());
    }

    public AccountService(AccountStore store, PasswordHasher hasher, Clock clock) {
        this.store = store;
        this.hasher = hasher;
        this.clock = clock;
    }

    /**
     * Creates an account for {@code username} protected by {@code password}.
     *
     * @param username 3-32 characters of {@code a-z 0-9 . _ -}, matched case-insensitively
     * @return the created account, whose {@link Account#passwordHash()} is the verifier
     * @throws IllegalArgumentException  for an unusable username or password
     * @throws UsernameAlreadyTakenException when the name is registered
     */
    public Account register(String username, char[] password) throws IOException {
        String canonical = Account.canonicalUsername(username);
        if (canonical == null) {
            throw new IllegalArgumentException(
                    "username must be 3-32 characters using a-z, 0-9, '.', '_' or '-'");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        if (password.length > PasswordHasher.MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException(
                    "password must be at most " + PasswordHasher.MAX_PASSWORD_CHARS + " characters");
        }
        return underLock(accounts -> {
            if (accounts.containsKey(canonical)) {
                throw new UsernameAlreadyTakenException(canonical);
            }
            String hash = hasher.hash(password);
            Account account = new Account(canonical, hash, Instant.now(clock));
            accounts.put(canonical, account);
            store.saveAll(accounts);
            return account;
        });
    }

    /**
     * Checks a password against the stored verifier and, on success, transparently rehashes it
     * if the stored parameters are weaker than the current policy.
     *
     * <p>Rehashing at login is what keeps a password database from ageing badly: the
     * iteration count can be raised whenever hardware gets faster and accounts migrate on their
     * own, without a password reset.
     *
     * @return {@code true} when the credentials are valid
     * @throws AuthenticationFailedException with {@link #BAD_CREDENTIALS} otherwise
     */
    public boolean authenticate(String username, char[] password) throws IOException {
        String canonical = Account.canonicalUsername(username);
        if (canonical == null) {
            // Same shape and cost as the "unknown user" answer below, so an invalid name is
            // not a cheap way to tell malformed input apart from a real account.
            hasher.burnTime(dummySecret());
            throw new AuthenticationFailedException(BAD_CREDENTIALS);
        }
        Account account = underLock(accounts -> accounts.get(canonical));
        if (account == null) {
            // Derive a throwaway verifier so that "unknown user" and "wrong password" cost the
            // same wall-clock time and a timing difference cannot enumerate accounts either.
            hasher.burnTime(dummySecret());
            throw new AuthenticationFailedException(BAD_CREDENTIALS);
        }
        if (password == null || password.length == 0) {
            throw new AuthenticationFailedException(BAD_CREDENTIALS);
        }
        if (!hasher.matches(password, account.passwordHash())) {
            throw new AuthenticationFailedException(BAD_CREDENTIALS);
        }
        if (hasher.needsUpgrade(account.passwordHash())) {
            underLock(accounts -> {
                Account current = accounts.get(canonical);
                // Re-check under the lock: another login may have upgraded it already, in which
                // case re-writing would only churn the file.
                if (current != null && hasher.needsUpgrade(current.passwordHash())) {
                    accounts.put(canonical, current.withPasswordHash(hasher.hash(password)));
                    store.saveAll(accounts);
                }
                return Boolean.TRUE;
            });
        }
        return true;
    }

    /** Runs {@code body} against the freshly loaded store while holding the exclusive lock. */
    private <T> T underLock(StoreOp<T> body) throws IOException {
        AccountStore.LockHandle handle = store.lock();
        try {
            return body.apply(store.loadAll());
        } finally {
            handle.close();
        }
    }

    @FunctionalInterface
    private interface StoreOp<T> {
        T apply(Map<String, Account> accounts) throws IOException;
    }

    /**
     * Whether {@code username} has an account.
     *
     * <p>Deliberately not reachable from {@link #authenticate}: this is for the CLI's own
     * pre-flight, and a login failure stays uniform.
     */
    public boolean exists(String username) throws IOException {
        String canonical = Account.canonicalUsername(username);
        if (canonical == null) {
            return false;
        }
        return store.loadAll().containsKey(canonical);
    }

    /** An immutable view of registered usernames and when they were created. */
    public Map<String, Instant> listAccounts() throws IOException {
        Map<String, Account> accounts = store.loadAll();
        Map<String, Instant> out = new TreeMap<>();
        accounts.forEach((name, account) -> out.put(name, account.createdAt()));
        return Collections.unmodifiableMap(out);
    }

    /** Where credentials live, for display by the CLI. */
    public Path storePath() {
        return store.file();
    }

    /** A fixed secret used only to consume the same CPU as a genuine derivation. */
    private static char[] dummySecret() {
        return "timing-equaliser-not-a-secret-0123456789".toCharArray();
    }

    /** Thrown by {@link AccountService#register} when the name is taken. */
    public static final class UsernameAlreadyTakenException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String username;

        UsernameAlreadyTakenException(String username) {
            super("username '" + username + "' is already registered");
            this.username = username;
        }

        public String username() {
            return username;
        }
    }

    /** Thrown by {@link AccountService#authenticate} for any rejection. */
    public static final class AuthenticationFailedException extends IOException {
        private static final long serialVersionUID = 1L;

        AuthenticationFailedException(String message) {
            super(message);
        }
    }
}
