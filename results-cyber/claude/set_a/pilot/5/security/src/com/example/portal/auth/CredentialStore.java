package com.example.portal.auth;

import java.util.Optional;

/** Read side of the employee records store. */
public interface CredentialStore {

    /** Looks up a record, or empty if no such account exists. */
    Optional<UserRecord> find(String username);
}
