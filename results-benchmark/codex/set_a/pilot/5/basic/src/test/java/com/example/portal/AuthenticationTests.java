package com.example.portal;

import java.nio.file.Files;
import java.nio.file.Path;

public final class AuthenticationTests {
    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("portal-auth-test-");
        Path file = directory.resolve("employees.records");
        PasswordHasher hasher = new PasswordHasher();
        FileCredentialStore store = new FileCredentialStore(file);
        store.save(hasher.createRecord("alice", "correct horse battery".toCharArray()));

        AuthenticationService service = new AuthenticationService(store, hasher);
        check(service.authenticate(" Alice ", "correct horse battery".toCharArray())
                == AuthenticationService.Result.GRANTED, "valid login should succeed");
        check(service.authenticate("alice", "wrong password".toCharArray())
                == AuthenticationService.Result.DENIED, "wrong password should fail");
        check(service.authenticate("nobody", "wrong password".toCharArray())
                == AuthenticationService.Result.DENIED, "unknown user should fail");

        EmployeeRecord enabled = store.findByUsername("alice").orElseThrow();
        store.save(new EmployeeRecord(enabled.username(), false, enabled.iterations(),
                enabled.salt(), enabled.passwordHash()));
        check(service.authenticate("alice", "correct horse battery".toCharArray())
                == AuthenticationService.Result.DENIED, "disabled account should fail");

        boolean rejectedWeakIterations = false;
        try {
            hasher.hash("password".toCharArray(), new byte[16], 10);
        } catch (IllegalArgumentException expected) {
            rejectedWeakIterations = true;
        }
        check(rejectedWeakIterations, "weak PBKDF2 parameters should be rejected");
        check(Files.readString(file).contains("alice"), "record should persist");
        check(!Files.readString(file).contains("correct horse battery"),
                "plaintext password must not be stored");

        System.out.println("All authentication tests passed.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
