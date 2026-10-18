import java.util.Optional;

/**
 * Registering accounts and authenticating them against what the store holds.
 *
 * <p>{@link #login(String, char[])} spends exactly one PBKDF2 derivation whatever the
 * outcome, including the branches that never touch a stored record, so response time
 * does not tell a caller whether the account exists.
 */
public final class UserAccountService {

    public enum Status {
        OK,
        INVALID_USERNAME,
        INVALID_PASSWORD,
        ACCOUNT_EXISTS,
        REJECTED
    }

    public record Outcome(Status status) {
        public boolean succeeded() {
            return status == Status.OK;
        }
    }

    private final AccountStore store;
    private final PasswordHasher hasher;

    public UserAccountService(AccountStore store, PasswordHasher hasher) {
        this.store = store;
        this.hasher = hasher;
    }

    public Outcome register(String rawUsername, char[] password) {
        String username = Usernames.normalize(rawUsername);
        if (username == null) {
            return new Outcome(Status.INVALID_USERNAME);
        }
        if (!Passwords.isHashable(password)) {
            return new Outcome(Status.INVALID_PASSWORD);
        }
        if (!Passwords.strongEnough(password)) {
            return new Outcome(Status.INVALID_PASSWORD);
        }
        if (store.contains(username)) {
            return new Outcome(Status.ACCOUNT_EXISTS);
        }
        String verifier = hasher.hash(password);
        if (!store.add(username, verifier)) {
            return new Outcome(Status.ACCOUNT_EXISTS);
        }
        return new Outcome(Status.OK);
    }

    /**
     * Checks a candidate password. Every refusal is {@link Status#REJECTED} and costs one
     * derivation: bad username shape, unusable password shape, unknown account, damaged
     * record and wrong password all do the same amount of work.
     */
    public Outcome login(String rawUsername, char[] candidate) {
        String username = Usernames.normalize(rawUsername);
        if (username == null || !Passwords.withinLength(candidate)) {
            hasher.burnWork();
            return new Outcome(username == null ? Status.INVALID_USERNAME : Status.INVALID_PASSWORD);
        }
        if (!Passwords.isHashable(candidate)) {
            hasher.burnWork();
            return new Outcome(Status.REJECTED);
        }
        Optional<String> stored = store.verifierFor(username);
        if (stored.isEmpty()) {
            hasher.burnWork();
            return new Outcome(Status.REJECTED);
        }
        boolean matched = hasher.verify(candidate, stored.get());
        return new Outcome(matched ? Status.OK : Status.REJECTED);
    }

    public boolean accountExists(String rawUsername) {
        String username = Usernames.normalize(rawUsername);
        return username != null && store.contains(username);
    }

    public int accountCount() {
        return store.size();
    }

    /** Verifier string as stored, for tests and for the inspect command. */
    public Optional<String> storedVerifier(String rawUsername) {
        String username = Usernames.normalize(rawUsername);
        return username == null ? Optional.empty() : store.verifierFor(username);
    }
}
