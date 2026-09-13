package com.example.auth;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The identity that a successful login proved, plus the roles carried into the session.
 */
public record AuthenticatedUser(String username, Set<String> roles) {

    public AuthenticatedUser {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        roles = Collections.unmodifiableSet(new LinkedHashSet<>(roles));
    }
}
