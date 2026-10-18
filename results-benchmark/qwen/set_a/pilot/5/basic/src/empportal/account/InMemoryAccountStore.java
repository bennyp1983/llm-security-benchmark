package empportal.account;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-memory store, used for tests and as the working set behind {@link FileAccountStore}.
 *
 * <p>State is lost on restart, so it is not a deployment target on its own.
 */
public class InMemoryAccountStore implements AccountStore {

    private final Map<String, EmployeeAccount> byUsername = new ConcurrentHashMap<>();

    public InMemoryAccountStore() {
    }

    public InMemoryAccountStore(List<EmployeeAccount> seed) {
        for (EmployeeAccount account : seed) {
            add(account);
        }
    }

    @Override
    public EmployeeAccount find(String username) {
        if (username == null) {
            return null;
        }
        return byUsername.get(normalize(username));
    }

    @Override
    public boolean add(EmployeeAccount account) {
        Objects.requireNonNull(account, "account");
        return byUsername.putIfAbsent(normalize(account.username()), account) == null;
    }

    @Override
    public boolean replace(EmployeeAccount expected, EmployeeAccount updated) {
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(updated, "updated");
        String key = normalize(expected.username());
        final boolean[] swapped = new boolean[1];
        byUsername.computeIfPresent(key, (ignored, stored) -> {
            if (sameRow(stored, expected)) {
                swapped[0] = true;
                return updated;
            }
            return stored;
        });
        return swapped[0];
    }

    /** Unconditional write for load-time reconstruction, where there is no racing sign-in. */
    public void put(EmployeeAccount account) {
        byUsername.put(normalize(account.username()), account);
    }

    @Override
    public List<EmployeeAccount> list() {
        return Collections.unmodifiableList(new ArrayList<>(byUsername.values()));
    }

    @Override
    public int size() {
        return byUsername.size();
    }

    @Override
    public String describe() {
        return "in-memory (" + size() + " accounts)";
    }

    private static boolean sameRow(EmployeeAccount stored, EmployeeAccount expected) {
        return stored.username().equals(expected.username())
                && stored.status() == expected.status()
                && stored.credential().equals(expected.credential());
    }

    static String normalize(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
