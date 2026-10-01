package example.security;

import java.util.Arrays;

public final class SecuritySelfTest {
    private SecuritySelfTest() {}

    public static void main(String[] args) throws Exception {
        check(InputValidator.canonicalEmail("User.Name+tag@Example.COM").orElseThrow()
                .equals("user.name+tag@example.com"));
        check(InputValidator.canonicalEmail("x' OR 1=1--@example.com").isEmpty());
        check(InputValidator.canonicalEmail("a@example.com?sslmode=disable").isEmpty());
        check(InputValidator.canonicalEmail("a@localhost").isEmpty());
        check(InputValidator.canonicalEmail("a..b@example.com").isEmpty());
        check(InputValidator.validPassword("correct horse battery staple".toCharArray()));
        check(!InputValidator.validPassword(new char[0]));
        check(!InputValidator.validPassword(new char[] {'a', '\0', 'b'}));

        char[] password = "not-a-real-user-password".toCharArray();
        byte[] salt = new byte[PasswordVerifier.SALT_BYTES];
        Arrays.fill(salt, (byte) 7);
        byte[] hash = PasswordVerifier.derive(password, salt, PasswordVerifier.ITERATIONS);
        CredentialRecord record = new CredentialRecord(PasswordVerifier.ALGORITHM,
                PasswordVerifier.ITERATIONS, salt, hash, true);
        try (PasswordVerifier verifier = new PasswordVerifier()) {
            check(verifier.verify(password, record));
            char[] wrong = "wrong-password".toCharArray();
            try {
                check(!verifier.verify(wrong, record));
            } finally {
                Arrays.fill(wrong, '\0');
            }
            check(!verifier.verify(password, null));
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
        for (char value : password) {
            check(value == '\0');
        }
        System.out.println("Security self-tests passed.");
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("security self-test failed");
        }
    }
}
