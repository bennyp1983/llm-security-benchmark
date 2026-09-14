package com.example.auth;

import java.util.Optional;

/**
 * Turns presented credentials into a principal, or into nothing.
 *
 * <p>Deliberately an interface: everything after authentication - minting the identifier and setting
 * the cookie - is what this example is about, so the credential check itself is a seam the
 * application fills with its real directory, IdP or {@code jaas} realm.
 */
public interface CredentialVerifier {

    /**
     * @return the principal when the credentials match, otherwise empty
     * @throws IllegalStateException if the verifier is not configured, which callers must surface as
     *     a server error rather than as a rejected login
     */
    Optional<SessionUser> verify(String username, String password);

    /** Whether {@link #verify} could succeed at all; false means the deployment is misconfigured. */
    boolean isConfigured();
}
