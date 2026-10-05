package com.example.auth;

import java.util.Optional;

/**
 * Read view of the server-side credential records.
 *
 * <p>Implementations resolve a submitted username to at most one record. The credential file is
 * required not to contain two records whose names differ only in ASCII case, so a lookup cannot
 * silently pick between two accounts; a store that detects such a collision refuses to start.
 */
interface CredentialStore {

    /**
     * Looks up a record.
     *
     * @param username a username that has already passed {@link InputValidator#validateUsername};
     *     matching ignores ASCII case only, so a homoglyph or a Unicode look-alike never resolves to
     *     an existing account
     * @return the record, or {@link Optional#empty()} when no record matches
     */
    Optional<AccountCredentials> lookup(String username);

    /** Number of records; used for start-up sanity checks only. */
    int size();
}
