package com.acme.portal;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Locale;

final class Authenticator {
    static final int MAX_PASSWORD_CHARS = 128;
    private static final char[] DUMMY_PASSWORD = "fixed-work-placeholder".toCharArray();

    private final LoginGuard guard;
    private final CredentialStore.Record dummyRecord;

    Authenticator() throws GeneralSecurityException {
        this.guard = new LoginGuard();
        byte[] salt = PasswordHasher.newSalt();
        byte[] hash = PasswordHasher.hash(DUMMY_PASSWORD, salt);
        this.dummyRecord = new CredentialStore.Record(salt, hash);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(hash, (byte) 0);
    }

    /** Serializing the full decision prevents concurrent check-then-grant races. */
    synchronized boolean authenticate(CredentialStore store, String suppliedUsername,
            char[] suppliedPassword)
            throws GeneralSecurityException, InterruptedException {
        String canonical = canonicalUsername(suppliedUsername);
        boolean usernameValid = canonical != null;
        boolean passwordValid = suppliedPassword != null
                && suppliedPassword.length >= 1
                && suppliedPassword.length <= MAX_PASSWORD_CHARS;
        String guardName = usernameValid ? canonical : "invalid-input";
        LoginGuard.Decision decision = guard.beforeAttempt(guardName);
        if (decision.accountDelayMillis() > 0) {
            Thread.sleep(decision.accountDelayMillis());
        }

        CredentialStore.Record actual = usernameValid ? store.find(canonical) : null;
        CredentialStore.Record checked = actual == null ? dummyRecord : actual;
        char[] checkedPassword = passwordValid ? suppliedPassword : DUMMY_PASSWORD;
        boolean passwordMatches = PasswordHasher.verify(checkedPassword, checked);
        boolean allowed = decision.sourceAllowed() && usernameValid && passwordValid
                && actual != null && passwordMatches;
        if (allowed) {
            guard.recordSuccess(canonical);
        } else {
            guard.recordFailure(guardName);
        }
        return allowed;
    }

    static String canonicalUsername(String input) {
        if (input == null || input.length() < 3 || input.length() > 64) {
            return null;
        }
        String canonical = input.toLowerCase(Locale.ROOT);
        return CredentialStore.USERNAME.matcher(canonical).matches() ? canonical : null;
    }
}
