package portal.auth;

/**
 * Where employee records live: a database table, an LDAP directory, a file, a test fixture.
 *
 * <p>Lookups are keyed by the canonical username produced by
 * {@link CredentialValidator#canonicalUsername(String)}.
 */
public interface CredentialStore {

    /**
     * @return the row for {@code canonicalUsername}, or null when no such employee exists
     */
    EmployeeRecord find(String canonicalUsername);

    /** A store that the portal may also write to (used by the {@code add} command). */
    interface Mutable extends CredentialStore {

        /** Stores {@code record}, replacing any row with the same username. */
        void save(EmployeeRecord record);

        /**
         * Hashes {@code password} and stores the row. The caller keeps ownership of the array.
         *
         * @throws IllegalArgumentException if the username or password cannot be used
         */
        EmployeeRecord addEmployee(String username, String displayName, char[] password);

        /** Number of employee rows held. */
        int size();
    }
}
