package accounts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Minimal dependency-free test harness: {@code java accounts.AccountStoreTest}. */
public final class AccountStoreTest {

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws IOException {
        Path dir = Files.createTempDirectory("accounts-test");
        Path file = dir.resolve("accounts.db");

        AccountStore store = new AccountStore(file);
        store.register("alice", "correct-horse".toCharArray());

        check("registration is persisted", Files.exists(file));
        check("correct password authenticates",
                store.authenticate("alice", "correct-horse".toCharArray()).isPresent());
        check("wrong password is rejected",
                store.authenticate("alice", "correct-horsf".toCharArray()).isEmpty());
        check("unknown user is rejected",
                store.authenticate("mallory", "correct-horse".toCharArray()).isEmpty());
        check("login is case-insensitive",
                store.authenticate("ALICE", "correct-horse".toCharArray()).isPresent());

        // Credentials survive a restart of the process.
        AccountStore reloaded = new AccountStore(file);
        check("credentials reload from disk",
                reloaded.authenticate("alice", "correct-horse".toCharArray()).isPresent());
        check("reloaded store keeps one account", reloaded.size() == 1);

        check("duplicate username is refused",
                throwsFrom(() -> reloaded.register("Alice", "another-password".toCharArray())));
        check("short password is refused",
                throwsFrom(() -> reloaded.register("bob", "short".toCharArray())));
        check("illegal username is refused",
                throwsFrom(() -> reloaded.register("bad:name", "long-enough-pw".toCharArray())));
        check("password equal to username is refused",
                throwsFrom(() -> reloaded.register("charlie12", "charlie12".toCharArray())));

        String stored = Files.readString(file);
        check("plaintext password is never written", !stored.contains("correct-horse"));

        // Two accounts with the same password get different salts, so different hashes.
        reloaded.register("bob", "correct-horse".toCharArray());
        String[] records = Files.readString(file).strip().split("\n");
        check("identical passwords hash differently",
                !records[0].split(":")[3].equals(records[1].split(":")[3]));

        deleteRecursively(dir);
        System.out.printf("%n%d passed, %d failed%n", passed, failed);
        System.exit(failed == 0 ? 0 : 1);
    }

    private static boolean throwsFrom(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException | IllegalStateException e) {
            return true;
        }
    }

    private static void check(String description, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  PASS  " + description);
        } else {
            failed++;
            System.out.println("  FAIL  " + description);
        }
    }

    private static void deleteRecursively(Path dir) throws IOException {
        try (var paths = Files.walk(dir)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // Temp directory cleanup is best effort.
                }
            });
        }
    }
}
