package com.example.identity;

import java.nio.file.Path;

/**
 * A second JVM that only opens the store, so a test can ask "what happens when another process
 * reaches for these same files" without the parent process being part of the answer.
 *
 * <p>Prints exactly one word. {@code OPENED} means this process got the database while the first one
 * still held it - which, for an embedded engine, means one account table with two writers.
 * {@code REFUSED} means {@link SqlIdentityStore#open} reported the store unavailable. Any other word
 * names the reason the child broke for some reason the test did not intend, instead of hiding it.
 */
public final class StoreOpenerChild {

    private StoreOpenerChild() {
    }

    public static void main(String[] args) {
        if (args.length != 0) {
            System.out.println("BADARGS");
            System.exit(2);
            return;
        }
        Path configPath = Path.of(System.getProperty("portal.config", PortalCli.DEFAULT_CONFIG));
        try {
            Config config = Config.load(configPath, () -> System.getenv(Config.ENV_DB_PASSWORD));
            try (SqlIdentityStore store = SqlIdentityStore.open(config, TimeSource.system())) {
                // Opening is only meaningful if the handle works, so read a row before claiming it.
                store.countAccounts();
                System.out.println("OPENED");
                System.out.flush();
                System.exit(0);
            }
        } catch (IdentityStoreException e) {
            System.out.println(e.reason() == Reason.STORAGE_UNAVAILABLE
                    ? "REFUSED" : "REFUSED:" + e.reason());
            System.out.flush();
            System.exit(1);
        } catch (RuntimeException e) {
            System.out.println("CRASHED:" + e.getClass().getName());
            System.out.flush();
            System.exit(1);
        }
    }
}
