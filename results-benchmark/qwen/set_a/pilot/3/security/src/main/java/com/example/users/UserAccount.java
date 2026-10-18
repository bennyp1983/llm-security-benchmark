package com.example.users;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable account record returned by {@link UserAccountRepository}.
 *
 * <p>Deliberately carries no credential material: there is no password hash, no token, no
 * salt. The repository never selects those columns either, so a caller that only needed to
 * look an account up cannot forward, serialise or log a password hash by accident. Code that
 * genuinely has to verify a credential needs its own, narrower read path.
 *
 * <p>{@code email} is nullable and is kept out of {@link #toString()} on purpose: account
 * objects end up in log lines and error messages far more often than they are shown to a
 * person.
 */
public record UserAccount(long id,
                          String userName,
                          String email,
                          UserStatus status,
                          Instant createdAt) {

    public UserAccount {
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(createdAt, "createdAt");
    }

    @Override
    public String toString() {
        return "UserAccount{id=" + id + ", userName='" + userName + "', status=" + status + "}";
    }
}
