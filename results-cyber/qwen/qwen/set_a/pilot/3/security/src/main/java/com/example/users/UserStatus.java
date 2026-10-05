package com.example.users;

/** Lifecycle state of an account, as stored in {@code user_accounts.status}. */
public enum UserStatus {

    ACTIVE,
    DISABLED;

    /**
     * Maps the stored column value.
     *
     * <p>An unrecognised or missing value is rejected instead of defaulted to a constant: if an
     * unknown status fell through to {@code ACTIVE}, a migration mistake or a hand-edited row
     * would silently turn into a privilege grant. The offending value is not echoed into the
     * message - the column is attacker-writable by way of registration flows, and the message
     * may be logged or surfaced later.
     *
     * @throws IllegalStateException if {@code stored} is not a known status
     */
    static UserStatus fromStorage(String stored) {
        if (stored != null) {
            String candidate = stored.trim();
            for (UserStatus status : values()) {
                if (status.name().equalsIgnoreCase(candidate)) {
                    return status;
                }
            }
        }
        throw new IllegalStateException("user_accounts.status holds an unrecognised value");
    }
}
