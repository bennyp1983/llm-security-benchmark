package com.example.auth;

import java.util.Optional;

/**
 * Where the accounts live. The servlets only ask this for a stored password, so swapping the
 * in-memory demo for a JDBC or LDAP back end does not touch the request handling.
 */
public interface UserStore {

    /** The stored password for {@code username}, or empty when no such account exists. */
    Optional<PasswordService.StoredPassword> findPassword(String username);

    /** The roles granted to {@code username}. Empty when the account does not exist. */
    default java.util.Set<String> rolesOf(String username) {
        return java.util.Set.of();
    }
}
