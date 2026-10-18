package portal.auth;

import java.util.Objects;

/**
 * One employee row in the records store.
 *
 * <p>Every field is immutable, and the password is held only as a {@link PasswordHash}, so a row
 * can be handed out freely without exposing anything an attacker can replay.
 */
public record EmployeeRecord(String username, String displayName, PasswordHash passwordHash) {

    public EmployeeRecord {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(passwordHash, "passwordHash");
        if (!username.equals(CredentialValidator.canonicalUsername(username))) {
            throw new IllegalArgumentException("username must already be canonical: " + username);
        }
        displayName = displayName == null || displayName.isBlank() ? username : displayName.trim();
    }
}
