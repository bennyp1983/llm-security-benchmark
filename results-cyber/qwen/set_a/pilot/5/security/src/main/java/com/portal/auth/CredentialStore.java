package com.portal.auth;

import java.util.Optional;

/**
 * The credential records store the authenticator checks against.
 *
 * <p>Deliberately an interface: the same authentication logic runs against the in-memory store used
 * by the tests and against a JDBC or directory-backed implementation, without the authenticator
 * needing to know which.
 */
public interface CredentialStore {

    /**
     * Looks up a username.
     *
     * <p>Usernames are matched exactly (case-sensitive); callers normalise before storing and
     * looking up so the two sides agree.
     */
    Optional<Credential> findByUsername(String username);

    /** Inserts or replaces a record. */
    void save(Credential credential);

    /** @return true if a record exists, whatever its status. */
    boolean exists(String username);
}
