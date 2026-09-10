package com.example.portal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

public final class AuthenticationService {
    public enum Result { GRANTED, DENIED }

    private static final byte[] DUMMY_SALT =
            "unknown-user-salt".getBytes(StandardCharsets.UTF_8);
    private final CredentialStore store;
    private final PasswordHasher hasher;

    public AuthenticationService(CredentialStore store, PasswordHasher hasher) {
        this.store = store;
        this.hasher = hasher;
    }

    public Result authenticate(String suppliedUsername, char[] password) throws IOException {
        String username = normalizeUsername(suppliedUsername);
        try {
            Optional<EmployeeRecord> found = store.findByUsername(username);
            if (found.isEmpty()) {
                // Do comparable work for unknown users to reduce username timing leaks.
                byte[] ignored = hasher.hash(password, DUMMY_SALT,
                        PasswordHasher.DEFAULT_ITERATIONS);
                Arrays.fill(ignored, (byte) 0);
                return Result.DENIED;
            }
            EmployeeRecord employee = found.get();
            boolean matches = hasher.matches(password, employee);
            return matches && employee.enabled() ? Result.GRANTED : Result.DENIED;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public static String normalizeUsername(String username) {
        if (username == null) return "";
        return username.strip().toLowerCase(Locale.ROOT);
    }

    public static boolean isValidUsername(String username) {
        return username.matches("[a-z0-9][a-z0-9._-]{2,63}");
    }
}
