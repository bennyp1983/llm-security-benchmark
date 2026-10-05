package example.security.auth;

import java.util.Optional;

/**
 * Server-side authentication state. Persistent adapters must obtain the account and active state
 * in one consistent transaction; they must never accept either value from the client.
 */
public interface CredentialStore {
    /**
     * Must perform one equivalent password derivation for unknown and known accounts and expose
     * an identity only after an atomic check of the current server-side credential/active state.
     */
    Optional<AuthenticatedPrincipal> verify(String canonicalUsername, char[] password);

    record AuthenticatedPrincipal(String accountId) {
        public AuthenticatedPrincipal {
            if (accountId == null || !accountId.matches("[A-Za-z0-9_-]{1,64}")) {
                throw new IllegalArgumentException("Invalid server-side account identifier");
            }
        }
    }
}
