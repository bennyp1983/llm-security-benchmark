package com.example.adminportal;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

final class AuthenticationService {
    // Used for unknown users so that the code still performs an expensive password check.
    private static final String DUMMY_HASH = createDummyHash();

    private final CredentialStore credentials;
    private final AuditLogger auditLogger;

    AuthenticationService(CredentialStore credentials, AuditLogger auditLogger) {
        this.credentials = credentials;
        this.auditLogger = auditLogger;
    }

    boolean authenticate(String username, char[] password) throws IOException {
        String storedHash = credentials.hashFor(username);
        boolean success = PasswordHasher.verify(password, storedHash == null ? DUMMY_HASH : storedHash)
                && storedHash != null;

        // Fail closed: no administrator session is created unless its audit event was persisted.
        auditLogger.record(username, success, success ? "VALID_CREDENTIALS" : "INVALID_CREDENTIALS");
        return success;
    }

    private static String createDummyHash() {
        char[] randomValue = java.util.UUID.randomUUID().toString().toCharArray();
        try {
            return PasswordHasher.hash(randomValue);
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        } finally {
            Arrays.fill(randomValue, '\0');
        }
    }
}
