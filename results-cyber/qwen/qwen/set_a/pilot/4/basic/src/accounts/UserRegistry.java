package accounts;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Registration and authentication against a {@link UserStore}.
 *
 * <p>Behaviour worth knowing about:
 * <ul>
 *   <li>Registration is atomic: the record is written to disk before it becomes
 *       visible in memory, so a failed write never leaves a half-registered account.</li>
 *   <li>Authentication answers an unknown username with the same message, exit status
 *       and (approximately) the same wall-clock time as a wrong password, by running a
 *       throwaway key derivation for identities that do not exist.</li>
 *   <li>Passwords are taken as {@code char[]} and cloned only where the store's
 *       contract requires it; nothing here builds a {@code String} copy.</li>
 * </ul>
 */
public final class UserRegistry {

    /** Rejected by {@link #register} for a username or password that fails policy. */
    public static final class ValidationException extends Exception {
        private static final long serialVersionUID = 1L;

        ValidationException(String message) {
            super(message);
        }
    }

    /** What callers outside this package may see about an account: identity and cost, never secrets. */
    public static final class AccountInfo {
        private final String username;
        private final String algorithm;
        private final int iterations;

        private AccountInfo(CredentialRecord record) {
            this.username = record.username();
            this.algorithm = record.algorithm();
            this.iterations = record.iterations();
        }

        public String username() {
            return username;
        }

        public String algorithm() {
            return algorithm;
        }

        public int iterations() {
            return iterations;
        }
    }

    public enum Status {
        /** Account created. */
        REGISTERED,
        /** Username already taken. */
        USERNAME_TAKEN,
        /** Unknown username, or the password did not match: the two are intentionally identical. */
        AUTHENTICATION_FAILED,
        /** Authenticated. */
        AUTHENTICATED
    }

    public static final class Result {
        private final Status status;
        private final String message;

        private Result(Status status, String message) {
            this.status = status;
            this.message = message;
        }

        public Status status() {
            return status;
        }

        public String message() {
            return message;
        }

        public boolean isSuccess() {
            return status == Status.REGISTERED || status == Status.AUTHENTICATED;
        }

        @Override
        public String toString() {
            return status + ": " + message;
        }
    }

    /** ASCII-only, no separators stacked together, to keep names comparable and loggable. */
    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?", Pattern.CASE_INSENSITIVE);

    static final int PASSWORD_MIN_LENGTH = 10;
    static final int PASSWORD_MAX_LENGTH = 1024;

    private static final String GENERIC_FAILURE =
            "authentication failed: unknown username or incorrect password";

    private final UserStore store;
    private final PasswordHasher hasher;

    /**
     * Material for the timing equalizer. Built on first failed login rather than at
     * construction, so a process that only registers or lists accounts never pays for a
     * throwaway derivation. Guarded by the same monitor as {@link #authenticate}.
     */
    private CredentialRecord dummyCredential;

    private final Map<String, CredentialRecord> byUsername = new LinkedHashMap<>();
    private final List<String> loadWarnings = new ArrayList<>();

    public UserRegistry(UserStore store) throws IOException {
        this(store, new PasswordHasher());
    }

    /** Package-private so tests can pass a cheap hasher and still exercise the real logic. */
    UserRegistry(UserStore store, PasswordHasher hasher) throws IOException {
        if (store == null) {
            throw new IllegalArgumentException("store is required");
        }
        this.store = store;
        this.hasher = hasher;
        reload();
    }

    /**
     * Refreshes the in-memory view from disk. Records are indexed by their canonical
     * username so a hand-edited store that stores "Alice" is still reachable as "alice";
     * a record whose canonical name is already taken is skipped rather than allowed to
     * shadow the first one.
     *
     * @return the number of store lines that were unreadable or shadowed
     */
    public synchronized int reload() throws IOException {
        Map<String, CredentialRecord> loaded = store.load();
        loadWarnings.clear();
        Map<String, CredentialRecord> indexed = new LinkedHashMap<>();
        int shadowed = 0;
        for (CredentialRecord record : loaded.values()) {
            if (indexed.putIfAbsent(canonical(record.username()), record) != null) {
                shadowed++;
            }
        }
        byUsername.clear();
        byUsername.putAll(indexed);
        int rejected = store.lastRejectedLines() + shadowed;
        if (rejected > 0) {
            loadWarnings.add(rejected + " record(s) in " + store.file()
                    + " were ignored as malformed or duplicate");
        }
        return rejected;
    }

    public synchronized List<String> loadWarnings() {
        return Collections.unmodifiableList(new ArrayList<>(loadWarnings));
    }

    public synchronized int accountCount() {
        return byUsername.size();
    }

    public synchronized boolean accountExists(String username) {
        return username != null && byUsername.containsKey(canonical(username));
    }

    /** Accounts in store order, with the salt and hash left out. */
    public synchronized List<AccountInfo> accountInfos() {
        List<AccountInfo> infos = new ArrayList<>(byUsername.size());
        for (CredentialRecord record : byUsername.values()) {
            infos.add(new AccountInfo(record));
        }
        return infos;
    }

    public Path storeFile() {
        return store.file();
    }

    /**
     * Creates an account.
     *
     * @return {@link Status#REGISTERED}, or {@link Status#USERNAME_TAKEN} if the name is
     *         already registered (case-insensitively)
     * @throws ValidationException if the username or password fails policy
     * @throws IOException if the credential file could not be rewritten
     */
    public synchronized Result register(String username, char[] password)
            throws ValidationException, IOException {
        validateUsername(username);
        validatePassword(username, password);

        String key = canonical(username);
        if (byUsername.containsKey(key)) {
            return new Result(Status.USERNAME_TAKEN, "username '" + key + "' is already registered");
        }

        CredentialRecord record = hasher.createCredential(key, password);
        Map<String, CredentialRecord> updated = new LinkedHashMap<>(byUsername);
        updated.put(key, record);
        store.replaceAll(updated.values());
        // Only after the write lands: a failed replaceAll leaves memory as it was.
        byUsername.clear();
        byUsername.putAll(updated);
        return new Result(Status.REGISTERED, "account '" + key + "' created in " + store.file());
    }

    /**
     * Checks credentials against the store. Never writes, and never reveals through the
     * message, the timing, or the exception type whether the username exists.
     */
    public synchronized Result authenticate(String username, char[] password) {
        if (username == null || username.isEmpty() || password == null || password.length == 0) {
            // Same derivation cost as the unknown-user branch, so an empty field does not
            // answer faster than a wrong guess.
            hasher.verify("not-a-guess".toCharArray(), timingEqualizerCredential());
            return new Result(Status.AUTHENTICATION_FAILED, GENERIC_FAILURE);
        }
        CredentialRecord stored = byUsername.get(canonical(username));
        if (stored == null) {
            hasher.verify(password, timingEqualizerCredential());
            return new Result(Status.AUTHENTICATION_FAILED, GENERIC_FAILURE);
        }
        boolean matched = hasher.verify(password, stored);
        if (!matched) {
            return new Result(Status.AUTHENTICATION_FAILED, GENERIC_FAILURE);
        }
        return new Result(Status.AUTHENTICATED, "account '" + stored.username() + "' authenticated");
    }

    /** A credential nothing can ever match, so a failed lookup still costs one derivation. */
    private CredentialRecord timingEqualizerCredential() {
        if (dummyCredential == null) {
            dummyCredential = hasher.createCredential("timing-equalizer-probe",
                    "probe-password-1".toCharArray());
        }
        return dummyCredential;
    }

    /** @throws ValidationException if {@code username} is outside the accepted shape */
    private static void validateUsername(String username) throws ValidationException {
        if (username == null || username.trim().isEmpty()) {
            throw new ValidationException("username is required");
        }
        if (!username.equals(username.trim())) {
            throw new ValidationException("username must not start or end with whitespace");
        }
        if (username.indexOf('\0') >= 0) {
            throw new ValidationException("username must not contain a NUL character");
        }
        if (username.indexOf(':') >= 0) {
            throw new ValidationException("username must not contain ':'");
        }
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new ValidationException("username must be 3-32 characters of a-z, A-Z, 0-9, '.', '_' or '-'"
                    + ", starting and ending with a letter or digit");
        }
    }

    /** @throws ValidationException if {@code password} is too short, too long, or too weak */
    private static void validatePassword(String username, char[] password) throws ValidationException {
        if (password == null || password.length == 0) {
            throw new ValidationException("password is required");
        }
        if (password.length < PASSWORD_MIN_LENGTH) {
            throw new ValidationException("password must be at least " + PASSWORD_MIN_LENGTH
                    + " characters, found " + password.length);
        }
        if (password.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException("password must be at most " + PASSWORD_MAX_LENGTH
                    + " characters, found " + password.length);
        }
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (char c : password) {
            if (c < 0x21 || c > 0x7E) {
                // Non-ASCII and space are refused here to keep the stored form and the
                // terminal round-trip unambiguous; the hasher itself is UTF-8 clean.
                throw new ValidationException("password must use printable ASCII characters");
            }
            hasLetter |= Character.isLetter(c);
            hasDigit |= Character.isDigit(c);
        }
        if (!hasLetter || !hasDigit) {
            throw new ValidationException("password must contain at least one letter and one digit");
        }
        String lowered = new String(password).toLowerCase(Locale.ROOT);
        if (lowered.contains(username.toLowerCase(Locale.ROOT))) {
            throw new ValidationException("password must not contain the username");
        }
    }

    /**
     * Usernames are matched case-insensitively, so "Alice" and "alice" are one account
     * rather than two identities an attacker can collide.
     */
    private static String canonical(String username) {
        return username.toLowerCase(Locale.ROOT);
    }
}
