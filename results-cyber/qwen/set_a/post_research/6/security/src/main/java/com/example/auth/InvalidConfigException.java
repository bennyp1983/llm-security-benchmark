package com.example.auth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Raised at start-up when configuration is missing, malformed, out of range, or points at a file
 * whose permissions would expose credential material to other users.
 *
 * <p>Start-up must fail rather than degrade: a permissive default for a limit, an unwritable log,
 * or a group-readable keystore are all conditions under which authentication cannot be trusted.
 *
 * <p>Problem strings name configuration keys and fixed reasons. They never contain a configured
 * value, so the keystore password cannot reach a log or a terminal through this path. The
 * suppressed cause is deliberate: this exception is constructed around keystore failures whose JDK
 * messages quote the keystore path.
 */
public final class InvalidConfigException extends Exception {

    private static final long serialVersionUID = 1L;

    private final List<String> problems;

    InvalidConfigException(List<String> problems) {
        super(describe(problems), null, false, false);
        this.problems = Collections.unmodifiableList(new ArrayList<>(problems));
    }

    /** Every problem found, in the order detected. Safe to log; contains no configured values. */
    public List<String> problems() {
        return problems;
    }

    private static String describe(List<String> problems) {
        if (problems.isEmpty()) {
            return "configuration is invalid";
        }
        if (problems.size() == 1) {
            return "configuration is invalid: " + problems.get(0);
        }
        return "configuration is invalid (" + problems.size() + " problems): " + String.join("; ", problems);
    }

    /**
     * Renders a configuration key name defensively. Keys come from the environment and are
     * attacker-chosen when the operator copies a template, so anything outside
     * {@code A-Z0-9_} is dropped rather than printed - a key name must not become a log-injection
     * or terminal-control vector.
     */
    static String describeKey(String key) {
        if (key == null || key.isEmpty() || key.length() > 64) {
            return "an unsupported configuration key";
        }
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            boolean allowed = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
            if (!allowed) {
                return "an unsupported configuration key";
            }
        }
        return key;
    }
}
