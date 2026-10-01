package com.example.portal.auth;

import java.util.Optional;

/**
 * Read access to the employee credential records that authentication decisions are checked against.
 *
 * <p>Implementations are the authoritative, server-side source of truth. Nothing a client sends may
 * stand in for a lookup here.
 */
public interface CredentialStore {

    /**
     * Returns the stored hash enrolled for {@code canonicalUsername}, or empty if there is no such
     * account.
     *
     * <p>The argument must already have passed {@link InputPolicy#requireValidUsername}.
     */
    Optional<PasswordHasher.StoredHash> find(String canonicalUsername);

    /** Number of enrolled accounts; used for operational logging only. */
    int size();
}
