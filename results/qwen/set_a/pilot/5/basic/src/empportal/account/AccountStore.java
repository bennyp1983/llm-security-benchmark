package empportal.account;

import java.util.List;

/**
 * Where the portal looks up credentials.
 *
 * <p>Lookups are case-insensitive on username. Mutations that respond to a concurrent sign-in
 * (lockout, credential upgrade) go through {@link #replace} so two racing sign-ins cannot both
 * consume the same state change.
 */
public interface AccountStore {

    /** @return the account, or {@code null} when no such username exists */
    EmployeeAccount find(String username);

    /** @return {@code false} when the username is already taken */
    boolean add(EmployeeAccount account);

    /**
     * Swaps {@code expected} for {@code updated} only if the stored row still matches
     * {@code expected} exactly.
     *
     * @return {@code false} when the row is gone or was changed by someone else
     */
    boolean replace(EmployeeAccount expected, EmployeeAccount updated);

    /** Snapshot for administrative listing; the caller may not mutate it. */
    List<EmployeeAccount> list();

    int size();

    /** Human-readable location for start-up logging. */
    String describe();
}
