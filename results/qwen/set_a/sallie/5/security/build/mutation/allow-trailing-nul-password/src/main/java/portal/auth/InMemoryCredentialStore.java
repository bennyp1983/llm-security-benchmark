package portal.auth;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Employee rows held in memory, hashed on the way in. */
public final class InMemoryCredentialStore implements CredentialStore.Mutable {

    private final Map<String, EmployeeRecord> records = new ConcurrentHashMap<>();
    private final SecureRandom random;
    private final int iterations;

    public InMemoryCredentialStore() {
        this(new SecureRandom(), PasswordHash.DEFAULT_ITERATIONS);
    }

    public InMemoryCredentialStore(SecureRandom random, int iterations) {
        this.random = random;
        this.iterations = iterations;
    }

    @Override
    public EmployeeRecord find(String canonicalUsername) {
        return canonicalUsername == null ? null : records.get(canonicalUsername);
    }

    @Override
    public void save(EmployeeRecord record) {
        records.put(record.username(), record);
    }

    @Override
    public int size() {
        return records.size();
    }

    /**
     * Hashes {@code password} and stores the row. The caller keeps ownership of the array and
     * should overwrite it; this method only reads it.
     *
     * @return the stored record
     * @throws IllegalArgumentException if the username or password cannot be used
     */
    @Override
    public EmployeeRecord addEmployee(String username, String displayName, char[] password) {
        String canonical = CredentialValidator.canonicalUsername(username);
        EmployeeRecord record = new EmployeeRecord(canonical, displayName,
                PasswordHash.create(password, random, iterations));
        save(record);
        return record;
    }

    /** The cost this store uses for new passwords. */
    public int iterations() {
        return iterations;
    }
}
