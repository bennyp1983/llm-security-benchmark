package example.security.auth;

import java.time.Instant;

/** Server-side session storage; the value is a SHA-256 token digest, never the bearer token. */
public interface SessionStore {
    boolean create(byte[] tokenDigest, String accountId, Instant expiresAt);
    void revoke(byte[] tokenDigest);
}
