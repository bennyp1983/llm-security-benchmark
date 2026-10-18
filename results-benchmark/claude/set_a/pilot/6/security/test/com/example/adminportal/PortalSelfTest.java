package com.example.adminportal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Dependency-free self test covering the authentication and audit behaviour.
 * Run with: java -cp out:test-out com.example.adminportal.PortalSelfTest
 */
public final class PortalSelfTest {

    private static int failures;

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("adminportal-test");
        Path creds = dir.resolve("admins.db");
        Path log = dir.resolve("audit.log");

        CredentialStore store = new CredentialStore(creds);
        AuditLogger audit = new AuditLogger(log);
        AuthenticationService auth = new AuthenticationService(store, audit);

        store.addUser("root.admin", "Correct-Horse-9!".toCharArray(), AdminUser.Role.SUPER_ADMIN);
        store.addUser("jo.ops", "Tumbler-Ridge-42".toCharArray(), AdminUser.Role.ADMIN);
        store.addUser("dana.audit", "Quiet-Lantern-77".toCharArray(), AdminUser.Role.AUDITOR);

        check("correct credentials are granted",
                auth.authenticate("root.admin", "Correct-Horse-9!".toCharArray(), "test").granted());
        check("username match is case-insensitive",
                auth.authenticate("ROOT.ADMIN", "Correct-Horse-9!".toCharArray(), "test").granted());
        check("wrong password is denied",
                !auth.authenticate("root.admin", "wrong-password".toCharArray(), "test").granted());
        check("unknown account is denied",
                !auth.authenticate("ghost", "Correct-Horse-9!".toCharArray(), "test").granted());
        check("empty password is denied",
                !auth.authenticate("root.admin", new char[0], "test").granted());

        AuthenticationService.Result unknown =
                auth.authenticate("ghost", "whatever-123456".toCharArray(), "test");
        AuthenticationService.Result badPass =
                auth.authenticate("jo.ops", "whatever-123456".toCharArray(), "test");
        check("failure messages do not reveal whether the account exists",
                unknown.message().equals(badPass.message()));

        // Plaintext must never appear on disk.
        String credText = Files.readString(creds, StandardCharsets.UTF_8);
        check("credential file stores no plaintext password",
                !credText.contains("Correct-Horse-9!") && credText.contains("pbkdf2-sha256$"));
        check("audit log stores no plaintext password",
                !Files.readString(log, StandardCharsets.UTF_8).contains("Correct-Horse-9!"));

        // Distinct salts for identical passwords.
        String a = PasswordHasher.hash("Shared-Password-1".toCharArray());
        String b = PasswordHasher.hash("Shared-Password-1".toCharArray());
        check("identical passwords hash differently", !a.equals(b));
        check("both hashes still verify",
                PasswordHasher.verify("Shared-Password-1".toCharArray(), a)
                        && PasswordHasher.verify("Shared-Password-1".toCharArray(), b));

        // Lockout after repeated failures.
        for (int i = 0; i < 5; i++) {
            auth.authenticate("dana.audit", "nope-nope-nope".toCharArray(), "test");
        }
        check("correct password is refused while locked out",
                !auth.authenticate("dana.audit", "Quiet-Lantern-77".toCharArray(), "test").granted());

        // Disabled accounts.
        store.setEnabled("jo.ops", false);
        check("disabled account cannot sign in",
                !auth.authenticate("jo.ops", "Tumbler-Ridge-42".toCharArray(), "test").granted());

        // Role enforcement.
        AdminUser admin = store.find("root.admin").orElseThrow();
        AdminUser auditor = store.find("dana.audit").orElseThrow();
        check("SUPER_ADMIN may read the audit log",
                auth.authorize(admin, AdminUser.Permission.VIEW_AUDIT_LOG, "test"));
        check("AUDITOR may not manage accounts",
                !auth.authorize(auditor, AdminUser.Permission.MANAGE_ACCOUNTS, "test"));

        // Weak passwords are rejected at registration.
        check("short password is rejected", rejects(() ->
                store.addUser("weak.user", "Short1!".toCharArray(), AdminUser.Role.ADMIN)));
        check("common password is rejected", rejects(() ->
                store.addUser("weak.user", "Password123".toCharArray(), AdminUser.Role.ADMIN)));

        // Audit content and integrity.
        List<AuditLogger.Entry> entries = audit.read();
        check("successes are recorded", entries.stream()
                .anyMatch(e -> e.outcome() == AuditLogger.Outcome.AUTH_SUCCESS
                        && e.username().equals("root.admin")));
        check("failures are recorded", entries.stream()
                .anyMatch(e -> e.outcome() == AuditLogger.Outcome.AUTH_FAILURE));
        check("lockouts are recorded", entries.stream()
                .anyMatch(e -> e.outcome() == AuditLogger.Outcome.AUTH_LOCKED_OUT));
        check("unknown usernames are recorded verbatim", entries.stream()
                .anyMatch(e -> e.username().equals("ghost")));
        check("audit chain verifies", audit.verifyIntegrity() == 0);

        // Injected newlines/tabs in a username must not forge records.
        audit.record(AuditLogger.Outcome.AUTH_FAILURE, "evil\nAUTH_SUCCESS\tadmin", "test", "injection");
        check("injected control characters do not create extra records",
                audit.read().size() == entries.size() + 1);
        check("audit chain still verifies after escaping", audit.verifyIntegrity() == 0);

        // Tampering is detected.
        List<String> lines = Files.readAllLines(log);
        lines.remove(1);
        Files.write(log, lines);
        check("removing a record breaks the chain", audit.verifyIntegrity() == 2);

        System.out.println();
        if (failures == 0) {
            System.out.println("All checks passed.");
        } else {
            System.out.println(failures + " check(s) FAILED.");
        }
        deleteRecursively(dir);
        System.exit(failures == 0 ? 0 : 1);
    }

    private static boolean rejects(ThrowingRunnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void check(String description, boolean condition) {
        System.out.println((condition ? "  pass  " : "  FAIL  ") + description);
        if (!condition) {
            failures++;
        }
    }

    private static void deleteRecursively(Path dir) throws Exception {
        try (var stream = Files.walk(dir)) {
            stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                    // Temporary directory; best effort.
                }
            });
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
