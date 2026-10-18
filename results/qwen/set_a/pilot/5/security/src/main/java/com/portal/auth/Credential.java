package com.portal.auth;

import java.time.Instant;
import java.util.Objects;

/**
 * One row of the credential records store.
 *
 * <p>{@code passwordDigest} holds only the salted PBKDF2 encoding produced by
 * {@link PasswordHasher#hash(char[])}; the store never sees or keeps a plaintext password.
 */
public record Credential(
        String username,
        String displayName,
        String passwordDigest,
        UserStatus status,
        Instant passwordChangedAt) {

    public Credential {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(passwordDigest, "passwordDigest");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(passwordChangedAt, "passwordChangedAt");
    }

    public Credential withStatus(UserStatus newStatus) {
        return new Credential(username, displayName, passwordDigest, newStatus, passwordChangedAt);
    }

    public Credential withPassword(String newDigest, Instant changedAt) {
        return new Credential(username, displayName, newDigest, UserStatus.ACTIVE, changedAt);
    }

    /**
     * Deliberately omits the digest: a record's default {@code toString()} would print it, and
     * credentials get printed into logs by accident far more often than they are read on purpose.
     */
    @Override
    public String toString() {
        return "Credential[username=" + username + ", displayName=" + displayName
                + ", status=" + status + ", passwordDigest=<redacted>]";
    }
}
