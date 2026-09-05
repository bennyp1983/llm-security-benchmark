package portal.admin;

import java.util.Objects;

/**
 * Immutable record of one administrator. The password exists here only as a salted,
 * iterated digest; there is no field, getter or {@code toString()} path that can reveal
 * or leak the plaintext.
 */
public final class AdminAccount {

    private final String username;
    private final String passwordDigest;
    private final AdminRole role;
    private final AccountState state;
    private final int consecutiveFailures;
    private final long lockedUntilMillis;
    private final long updatedAtMillis;

    public AdminAccount(String username, String passwordDigest, AdminRole role, AccountState state,
                        int consecutiveFailures, long lockedUntilMillis, long updatedAtMillis) {
        this.username = Objects.requireNonNull(username, "username");
        this.passwordDigest = Objects.requireNonNull(passwordDigest, "passwordDigest");
        this.role = Objects.requireNonNull(role, "role");
        this.state = Objects.requireNonNull(state, "state");
        this.consecutiveFailures = Math.max(0, consecutiveFailures);
        this.lockedUntilMillis = lockedUntilMillis;
        this.updatedAtMillis = updatedAtMillis;
    }

    public AdminAccount(String username, String passwordDigest, AdminRole role) {
        this(username, passwordDigest, role, AccountState.ACTIVE, 0, 0L, System.currentTimeMillis());
    }

    public String username() {
        return username;
    }

    /** The stored PBKDF2 digest, never a password. */
    public String passwordDigest() {
        return passwordDigest;
    }

    public AdminRole role() {
        return role;
    }

    public AccountState state() {
        return state;
    }

    public int consecutiveFailures() {
        return consecutiveFailures;
    }

    public long lockedUntilMillis() {
        return lockedUntilMillis;
    }

    public long updatedAtMillis() {
        return updatedAtMillis;
    }

    public AdminAccount withDigest(String newDigest, long nowMillis) {
        return new AdminAccount(username, newDigest, role, state, 0, 0L, nowMillis);
    }

    public AdminAccount withRole(AdminRole newRole, long nowMillis) {
        return new AdminAccount(username, passwordDigest, newRole, state, consecutiveFailures,
                lockedUntilMillis, nowMillis);
    }

    public AdminAccount withState(AccountState newState, long nowMillis) {
        return new AdminAccount(username, passwordDigest, role, newState,
                newState == AccountState.ACTIVE ? 0 : consecutiveFailures,
                newState == AccountState.ACTIVE ? 0L : lockedUntilMillis,
                nowMillis);
    }

    public AdminAccount withFailedAttempt(int failures, long lockedUntil, long nowMillis) {
        AccountState next = lockedUntil > 0 ? AccountState.LOCKED : state;
        return new AdminAccount(username, passwordDigest, role, next, failures, lockedUntil, nowMillis);
    }

    public AdminAccount withSuccessfulAttempt(long nowMillis) {
        return new AdminAccount(username, passwordDigest, role, AccountState.ACTIVE, 0, 0L, nowMillis);
    }

    /** Masks the digest so an accidental log or exception cannot expose it. */
    @Override
    public String toString() {
        return "AdminAccount{username=" + username + ", role=" + role + ", state=" + state
                + ", digest=[masked]}";
    }
}
