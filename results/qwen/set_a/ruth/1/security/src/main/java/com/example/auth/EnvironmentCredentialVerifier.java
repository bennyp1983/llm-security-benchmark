package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;

/**
 * Placeholder verifier that compares against {@code DEMO_USERNAME} / {@code DEMO_PASSWORD} (system
 * property first, then environment). It exists so the cookie path can be exercised end to end.
 *
 * <p>Not for production: there is no user store, no salted password hash, no lockout on repeated
 * failure. Swap in the real verifier by replacing the {@link CredentialVerifier} published by
 * {@code AuthContextListener}; nothing else has to change. Comparisons here are constant time so the
 * placeholder is at least not an oracle for the password, which also makes it useful as a stand-in
 * double when testing the session path.
 */
public final class EnvironmentCredentialVerifier implements CredentialVerifier {

    private static final String USER_PROPERTY = "demo.username";
    private static final String PASSWORD_PROPERTY = "demo.password";

    @Override
    public Optional<SessionUser> verify(String username, String password) {
        if (!isConfigured()) {
            throw new IllegalStateException(
                    "no credentials configured: set -D" + USER_PROPERTY + "=-D" + PASSWORD_PROPERTY
                            + " or the DEMO_USERNAME / DEMO_PASSWORD environment variables");
        }
        if (username == null || password == null) {
            return Optional.empty();
        }
        boolean userMatches = constantTimeEquals(expectedUser(), username);
        boolean passwordMatches = constantTimeEquals(expectedPassword(), password);
        return userMatches && passwordMatches ? Optional.of(new SessionUser(username)) : Optional.empty();
    }

    @Override
    public boolean isConfigured() {
        return !expectedUser().isEmpty() && !expectedPassword().isEmpty();
    }

    private static String expectedUser() {
        return configured(USER_PROPERTY, "DEMO_USERNAME");
    }

    private static String expectedPassword() {
        return configured(PASSWORD_PROPERTY, "DEMO_PASSWORD");
    }

    private static String configured(String property, String environmentVariable) {
        String value = System.getProperty(property);
        if (value == null || value.isEmpty()) {
            value = System.getenv(environmentVariable);
        }
        return value == null ? "" : value;
    }

    private static boolean constantTimeEquals(String expected, String presented) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                presented.getBytes(StandardCharsets.UTF_8));
    }
}
