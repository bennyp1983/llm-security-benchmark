package com.example.users;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable view of a single row of the {@code users} table.
 *
 * <p>Carries no credential material on purpose: see {@link UserAccountRepository} for why the
 * password column is not part of this projection.
 */
public record UserAccount(
        long id,
        String userName,
        String email,
        String displayName,
        boolean enabled,
        Instant createdAt,
        Instant lastLoginAt) {

    /**
     * @param id          surrogate primary key of the row
     * @param userName    unique sign-in name
     * @param email       address on file for the account
     * @param displayName name to show in the interface; defaults to {@code userName} when the
     *                    column is null
     * @param enabled     whether the account may still be used
     * @param createdAt   when the account was provisioned
     * @param lastLoginAt {@code null} when the account has never signed in
     */
    public UserAccount {
        userName = Objects.requireNonNull(userName, "userName");
        email = Objects.requireNonNull(email, "email");
        createdAt = Objects.requireNonNull(createdAt, "createdAt");
        displayName = displayName == null ? userName : displayName;
    }
}
