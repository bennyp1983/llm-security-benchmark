package com.example.adminportal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/** Minimal dependency-free test runner. */
public final class AdminPortalTest {
    private AdminPortalTest() { }

    public static void main(String[] args) throws Exception {
        Path temp = Files.createTempDirectory("admin-portal-test-");
        try {
            char[] correct = "a-secure-test-password".toCharArray();
            String encoded = PasswordHasher.hash(correct);
            require(PasswordHasher.verify(correct, encoded), "correct password should verify");
            require(!PasswordHasher.verify("incorrect-password".toCharArray(), encoded),
                    "incorrect password should not verify");

            Path credentialsFile = temp.resolve("credentials.properties");
            Files.writeString(credentialsFile, "administrator=" + encoded + "\n",
                    StandardCharsets.UTF_8);
            Path auditFile = temp.resolve("audit.jsonl");
            AuthenticationService service = new AuthenticationService(
                    CredentialStore.load(credentialsFile), new AuditLogger(auditFile));

            require(service.authenticate("administrator", correct), "valid login should succeed");
            require(!service.authenticate("administrator", "wrong-password".toCharArray()),
                    "invalid login should fail");
            require(!service.authenticate("unknown\nuser", correct), "unknown user should fail");

            String audit = Files.readString(auditFile, StandardCharsets.UTF_8);
            require(audit.lines().count() == 3, "every attempt should create one audit line");
            require(audit.contains("AUTHENTICATION_SUCCESS"), "success should be audited");
            require(audit.contains("AUTHENTICATION_FAILURE"), "failure should be audited");
            require(audit.contains("unknown\\nuser"), "log control characters should be escaped");
            require(!audit.contains("a-secure-test-password"), "password must not be logged");

            Path invalidAuditTarget = temp.resolve("audit-directory");
            Files.createDirectories(invalidAuditTarget);
            AuthenticationService failClosedService = new AuthenticationService(
                    CredentialStore.load(credentialsFile), new AuditLogger(invalidAuditTarget));
            boolean auditFailureRaised = false;
            try {
                failClosedService.authenticate("administrator", correct);
            } catch (java.io.IOException expected) {
                auditFailureRaised = true;
            }
            require(auditFailureRaised, "audit failure must prevent authentication");
            System.out.println("All tests passed.");
        } finally {
            try (var paths = Files.walk(temp)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
