package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds credential files for the suites. This lives in the test tree on purpose.
 *
 * <p>Turning a password into a stored record is account creation, and the component under test is
 * scoped to authentication and authentication-event logging. If the serializer shipped in
 * {@code src/main} - even package-private, even named after tests - it would be a production code
 * path that hashes a caller-supplied password, which is exactly what the scope limit forbids and what
 * a reviewer would report. Nothing in the shipped service can produce a record.
 *
 * <p>It reuses the production {@link PasswordHasher} and the production record format rather than
 * reimplementing PBKDF2 here, so a fixture file is a genuine input to
 * {@link FileCredentialStore}: a digest this class got wrong is a suite that fails, not a suite that
 * agrees with a broken loader.
 */
final class FixtureProvisioner {

    private FixtureProvisioner() {
    }

    /**
     * Renders one credential-file line per {@code namePasswordPairs} entry, hashing with
     * {@code pepper} at {@code iterations}.
     *
     * @param saltProvider supplies the 16-byte salt for each record, so a caller can reuse one salt to
     *     probe the store's duplicate handling
     */
    static List<String> records(char[] pepper, int iterations, String[][] namePasswordPairs,
            SaltProvider saltProvider) throws AuthException {
        SecureRandom unusedButRequired = new SecureRandom();
        PasswordHasher hasher = new PasswordHasher(pepper, iterations, unusedButRequired);
        List<String> out = new ArrayList<>(namePasswordPairs.length);
        for (String[] pair : namePasswordPairs) {
            char[] password = pair[1].toCharArray();
            byte[] salt = saltProvider.nextSalt();
            byte[] passwordBytes;
            byte[] digest;
            try {
                passwordBytes = InputValidator.encodePassword(password);
                digest = hasher.derive(passwordBytes, salt, iterations);
            } finally {
                Arrays.fill(password, (char) 0);
            }
            Arrays.fill(passwordBytes, (byte) 0);
            // The line is rendered here rather than by a shipped serialiser, so that nothing in
            // src/main can write a credential record at all. The joining and the Base64 spelling are
            // the fixture's own; the shipped decoder is what has to accept the result, so a record
            // this class mis-renders is a suite that fails, not a fixture that agrees with a broken
            // loader.
            out.add(pair[0] + ":" + base64(salt) + ":" + iterations + ":" + base64(digest));
            Arrays.fill(digest, (byte) 0);
        }
        return out;
    }

    /** Renders records with a fresh random salt each, the ordinary case. */
    static List<String> records(char[] pepper, int iterations, String[][] namePasswordPairs) throws AuthException {
        return records(pepper, iterations, namePasswordPairs, RandomSalt.INSTANCE);
    }

    /**
     * The Base64 spelling the shipped decoder accepts. The encoder lives here rather than in
     * {@code src/main} because the component under test only ever reads credential records.
     */
    static String base64(byte[] value) {
        return java.util.Base64.getEncoder().encodeToString(value);
    }

    /** Supplies the salt for each record in turn. */
    interface SaltProvider {

        byte[] nextSalt();
    }

    private enum RandomSalt implements SaltProvider {

        INSTANCE;

        private final SecureRandom random = new SecureRandom();

        @Override
        public byte[] nextSalt() {
            byte[] salt = new byte[PasswordHasher.SALT_BYTES];
            random.nextBytes(salt);
            return salt;
        }
    }

    /** Reuses one salt for every record, for the duplicate-salt cases. */
    static SaltProvider saltedWith(final byte[] salt) {
        return new SaltProvider() {

            @Override
            public byte[] nextSalt() {
                return salt.clone();
            }
        };
    }
}
