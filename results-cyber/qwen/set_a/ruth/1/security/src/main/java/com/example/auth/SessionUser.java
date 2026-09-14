package com.example.auth;

import java.time.Instant;

/** A principal that completed authentication. */
public record SessionUser(String username) {

    public SessionUser {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username is blank");
        }
    }
}
