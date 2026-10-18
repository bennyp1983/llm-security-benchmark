import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class UserAccountAppTest {
    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("account-test-");
        Path file = directory.resolve("credentials.db");
        CredentialStore firstProcess = new CredentialStore(file);

        char[] password = "correct horse battery staple".toCharArray();
        firstProcess.register("alice@example.com", password);

        // A fresh store instance demonstrates that authentication uses persisted data.
        CredentialStore laterProcess = new CredentialStore(file);
        check(laterProcess.authenticate("alice@example.com", password), "correct password rejected");
        check(!laterProcess.authenticate("alice@example.com", "wrong".toCharArray()), "wrong password accepted");
        check(!laterProcess.authenticate("unknown", password), "unknown user accepted");

        String stored = Files.readString(file, StandardCharsets.UTF_8);
        check(!stored.contains(new String(password)), "plaintext password was stored");
        check(stored.startsWith("v1:"), "versioned verifier record missing");

        boolean duplicateRejected = false;
        try {
            firstProcess.register("alice@example.com", "different".toCharArray());
        } catch (IllegalArgumentException expected) {
            duplicateRejected = true;
        }
        check(duplicateRejected, "duplicate username accepted");
        Arrays.fill(password, '\0');
        System.out.println("All tests passed.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
