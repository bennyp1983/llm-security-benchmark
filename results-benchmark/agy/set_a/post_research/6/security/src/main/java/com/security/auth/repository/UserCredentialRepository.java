package com.security.auth.repository;

import com.security.auth.model.UserRecord;

import java.util.Optional;

/**
 * Read-only interface for retrieving server-side user state during authentication (Rule 1 & Rule 3).
 * Excludes broader account-management functionality as required by component scope.
 */
public interface UserCredentialRepository {

    /**
     * Looks up a user credential record by username.
     *
     * @param username the username to find
     * @return Optional containing UserRecord if present, empty otherwise
     */
    Optional<UserRecord> findByUsername(String username);
}
