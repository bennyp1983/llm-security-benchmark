package account;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Registration and authentication, expressed as one operation per call.
 *
 * <p>An instance holds the store open (and therefore the store lock), so a test or
 * a command-line run should use try-with-resources.</p>
 */
final class AccountService implements AutoCloseable {

    enum Result {
        REGISTERED,
        USERNAME_TAKEN,
        AUTHENTICATED,
        INVALID_CREDENTIALS,
        UNKNOWN_USER
    }

    static final int MIN_USERNAME_CHARS = 3;
    static final int MAX_USERNAME_CHARS = 32;

    private final AccountStore store;

    AccountService(Path storeFile) {
        this.store = new AccountStore(storeFile);
        this.store.load();
    }

    Path storeFile() {
        return store.storeFile();
    }

    int accountCount() {
        return store.size();
    }

    /**
     * Prepares a username for storage and lookup.
     *
     * <p>Only spaces at the ends are removed, deliberately: {@code String.trim()}
     * also deletes tabs, newlines and NUL characters, which would let
     * {@code "alice"} followed by an invisible character resolve to the real
     * {@code alice} account. Anything that cannot be displayed is refused instead
     * of being cleaned away.</p>
     *
     * @throws IllegalArgumentException with a user-safe reason
     */
    static String normalizeUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username is missing");
        }
        String trimmed = trimSpacesOnly(username);
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (trimmed.length() > MAX_USERNAME_CHARS) {
            throw new IllegalArgumentException("username must be at most " + MAX_USERNAME_CHARS + " characters");
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (!allowed) {
                throw new IllegalArgumentException(
                        "username may only contain letters, digits, dot, underscore and hyphen");
            }
        }
        if (trimmed.length() < MIN_USERNAME_CHARS) {
            throw new IllegalArgumentException("username must be at least " + MIN_USERNAME_CHARS + " characters");
        }
        return trimmed;
    }

    /**
     * Registers an account.
     *
     * @throws IllegalArgumentException if the username or password is unacceptable
     */
    Result register(String username, char[] password) {
        String name = normalizeUsername(username);
        PasswordHasher.validatePassword(password);
        if (!store.add(AccountStore.newUser(name, PasswordHasher.hash(password)))) {
            return Result.USERNAME_TAKEN;
        }
        return Result.REGISTERED;
    }

    /**
     * Checks a candidate password for a username.
     *
     * <p>Both failure paths cost a key derivation: an unknown username derives
     * against a fixed salt so that response time cannot be used to find out which
     * accounts exist.</p>
     *
     * @throws IllegalArgumentException if the username itself is malformed
     */
    Result authenticate(String username, char[] password) {
        String name = normalizeUsername(username);
        try {
            PasswordHasher.validatePassword(password);
        } catch (IllegalArgumentException e) {
            return Result.INVALID_CREDENTIALS;
        }
        Optional<User> user = store.find(name);
        if (user.isEmpty()) {
            PasswordHasher.burnEquivalentWork();
            return Result.UNKNOWN_USER;
        }
        return PasswordHasher.matches(password, user.get().passwordEncoding())
                ? Result.AUTHENTICATED
                : Result.INVALID_CREDENTIALS;
    }

    @Override
    public void close() {
        store.close();
    }

    private static String trimSpacesOnly(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) == ' ') {
            start++;
        }
        while (end > start && value.charAt(end - 1) == ' ') {
            end--;
        }
        return value.substring(start, end);
    }
}
