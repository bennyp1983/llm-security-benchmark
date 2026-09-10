package com.example.portal.auth;

import java.util.Optional;

/** Read/write access to employee credential records. */
public interface CredentialStore {

    /** Looks up a record by username, matching case-insensitively. */
    Optional<EmployeeRecord> find(String username);

    /** Inserts a new record, or replaces the existing one with the same username. */
    void save(EmployeeRecord record);

    /** Number of records held. */
    int size();
}
