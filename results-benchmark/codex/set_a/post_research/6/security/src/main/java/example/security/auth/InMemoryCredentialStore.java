package example.security.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.security.SecureRandom;
import java.util.Arrays;

/** Immutable, thread-safe store suitable for one process; entries are server configuration. */
public final class InMemoryCredentialStore implements CredentialStore {
    public record Entry(AuthenticatedPrincipal principal, PasswordRecord password) {
        public Entry {
            Objects.requireNonNull(principal, "principal");
            Objects.requireNonNull(password, "password");
        }
    }

    private final Map<String, Entry> entries;
    private final PasswordRecord dummyRecord;

    public InMemoryCredentialStore(Map<String, Entry> serverEntries) {
        Objects.requireNonNull(serverEntries, "serverEntries");
        if (serverEntries.size() > 100_000) throw new IllegalArgumentException("Too many accounts");
        Map<String, Entry> copy = new LinkedHashMap<>();
        serverEntries.forEach((name, entry) -> {
            String canonical = AuthenticationService.canonicalUsername(name);
            if (!canonical.equals(name) || copy.put(canonical, Objects.requireNonNull(entry)) != null) {
                throw new IllegalArgumentException("Invalid or duplicate canonical username");
            }
        });
        this.entries = Map.copyOf(copy);
        char[] dummy = new char[32];
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < dummy.length; i++) dummy[i] = (char) ('!' + random.nextInt(90));
        try {
            this.dummyRecord = PasswordVerifier.hashForStorage(dummy, random);
        } finally {
            Arrays.fill(dummy, '\0');
        }
    }

    @Override public Optional<AuthenticatedPrincipal> verify(String canonicalUsername, char[] password) {
        Entry entry = entries.get(canonicalUsername);
        if (entry == null) {
            PasswordVerifier.verify(password, dummyRecord);
            return Optional.empty();
        }
        return PasswordVerifier.verify(password, entry.password())
                ? Optional.of(entry.principal()) : Optional.empty();
    }
}
