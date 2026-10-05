package com.example.auth;

/**
 * One credential record as held in the store.
 *
 * <p>Immutable, and it deliberately holds no password: only the salt, the iteration count that was
 * used, and the resulting digest. The digest is treated as secret - it is never logged and never
 * returned to a caller of the service.
 */
final class AccountCredentials {

    private final String username;
    private final byte[] salt;
    private final int iterations;
    private final byte[] digest;

    AccountCredentials(String username, byte[] salt, int iterations, byte[] digest) {
        this.username = username;
        this.salt = salt;
        this.iterations = iterations;
        this.digest = digest;
    }

    String username() {
        return username;
    }

    byte[] salt() {
        return salt.clone();
    }

    int iterations() {
        return iterations;
    }

    byte[] digest() {
        return digest.clone();
    }

    /**
     * Deliberately no serialiser. Rendering a credential line is provisioning, which is account
     * creation, and this component is scoped to authentication and event logging: a shipped writer
     * would be a production path that turns a record back into a file, and one more place where a
     * digest could be written somewhere its owner did not approve. The test tree builds its own
     * lines. {@link #toString()} likewise omits both secret fields, so an accidental log or exception
     * message containing a record cannot publish a crackable verifier.
     */
    @Override
    public String toString() {
        return "AccountCredentials[" + username + ", iterations=" + iterations + "]";
    }
}
