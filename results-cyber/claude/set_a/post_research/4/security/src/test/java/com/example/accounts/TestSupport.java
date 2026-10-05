package com.example.accounts;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/** Shared fixture helpers. */
final class TestSupport {

    private TestSupport() {
    }

    /** A config rooted at {@code dir} with the lowest Argon2 cost the policy still allows. */
    static Config config(Path dir, Map<String, String> overrides) {
        Map<String, String> env = new HashMap<>();
        env.put("ACCOUNTS_DATA_DIR", dir.toAbsolutePath().toString());
        env.put("ACCOUNTS_ARGON2_MEMORY_KIB", "19456");
        env.put("ACCOUNTS_ARGON2_ITERATIONS", "2");
        env.put("ACCOUNTS_ARGON2_PARALLELISM", "1");
        env.put("ACCOUNTS_LOG_TO_FILE", "false");
        env.putAll(overrides);
        return Config.fromEnvironment(env);
    }

    static Config config(Path dir) {
        return config(dir, Map.of());
    }

    static Logger silentLogger() {
        Logger logger = Logger.getLogger("com.example.accounts.test");
        logger.setUseParentHandlers(false);
        return logger;
    }
}
