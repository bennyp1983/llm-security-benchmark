package accounts;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Minimal self-check: run with {@code java accounts.UserStoreTest}. */
public final class UserStoreTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("accounts-test");
        Path file = dir.resolve("accounts.db");
        UserStore store = new UserStore(file);

        store.register("Alice", "correct horse battery".toCharArray());
        check("correct password authenticates",
                store.authenticate("alice", "correct horse battery".toCharArray()));
        check("username is case-insensitive",
                store.authenticate("ALICE", "correct horse battery".toCharArray()));
        check("wrong password is rejected",
                !store.authenticate("alice", "correct horse batteru".toCharArray()));
        check("unknown user is rejected",
                !store.authenticate("mallory", "correct horse battery".toCharArray()));

        String contents = Files.readString(file, StandardCharsets.UTF_8);
        check("password is absent from storage", !contents.contains("correct horse battery"));
        check("stored record is a PBKDF2 hash", contents.contains("pbkdf2_sha256$210000$"));

        store.register("bob", "correct horse battery".toCharArray());
        String[] lines = contents.isEmpty() ? new String[0]
                : Files.readString(file, StandardCharsets.UTF_8).strip().split("\n");
        check("identical passwords hash differently (per-user salt)",
                !lines[0].split("\t")[1].equals(lines[1].split("\t")[1]));

        check("duplicate registration is refused", throwsOn(
                () -> store.register("alice", "another long password".toCharArray())));
        check("short password is refused", throwsOn(
                () -> store.register("carol", "short".toCharArray())));
        check("invalid username is refused", throwsOn(
                () -> store.register("a b!", "another long password".toCharArray())));

        check("credentials survive a reload",
                new UserStore(file).authenticate("alice", "correct horse battery".toCharArray()));

        check("password change takes effect", store.changePassword(
                "alice", "correct horse battery".toCharArray(), "a brand new secret".toCharArray()));
        check("old password no longer works",
                !store.authenticate("alice", "correct horse battery".toCharArray()));
        check("new password works",
                store.authenticate("alice", "a brand new secret".toCharArray()));

        System.out.println(failures == 0 ? "\nAll checks passed." : "\n" + failures + " check(s) FAILED.");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static boolean throwsOn(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException | IllegalStateException e) {
            return true;
        }
    }

    private static void check(String description, boolean condition) {
        if (!condition) {
            failures++;
        }
        System.out.println((condition ? "ok   " : "FAIL ") + description);
    }

    private UserStoreTest() {
    }
}
