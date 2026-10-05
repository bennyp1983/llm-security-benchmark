package com.example.auth;

import java.util.Optional;

/**
 * Read-only view of the server-side credential state that authentication decides
 * against. Implementations are expected to be safe for concurrent use.
 *
 * <p>Intentionally read-only: creating, changing or disabling accounts is account
 * management and outside this component.</p>
 */
public interface CredentialStore {

    /**
     * @param canonicalUsername a username already accepted by
     *                          {@link InputPolicy#canonicalUsername}
     * @return the stored verifier, or empty when no such account exists
     * @throws CredentialStoreException if the backing store cannot be consulted;
     *                                  the caller fails the attempt closed
     */
    Optional<CredentialRecord> find(String canonicalUsername) throws CredentialStoreException;

    /** Signals that the store was unavailable or returned an unusable record. */
    class CredentialStoreException extends Exception {

        private static final long serialVersionUID = 1L;

        public CredentialStoreException(String message, Throwable cause) {
            super(message, cause);
        }

        public CredentialStoreException(String message) {
            super(message);
        }
    }
}
