package com.example.auth;

/**
 * Makes values safe to place in a log line.
 *
 * <p>Two separate jobs. First, neutralising syntax: newlines, carriage returns,
 * control characters and quoting are removed or escaped, so an attacker who picks
 * their own username cannot forge a log record or break a downstream parser.
 * Second, masking: identifying values are reduced so that the log, which is read
 * by more people than the credential store is, does not become a directory of
 * accounts and addresses.</p>
 */
public final class LogSanitizer {

    /** Hard cap on any single field, so a log record has a bounded size. */
    static final int MAX_FIELD_LENGTH = 64;

    private LogSanitizer() {
    }

    /**
     * Escapes a value for inclusion in a quoted log field and truncates it.
     * Characters outside printable ASCII become {@code .} - including every
     * newline, so one record can never become two.
     */
    public static String escape(String value) {
        if (value == null) {
            return "-";
        }
        int limit = Math.min(value.length(), MAX_FIELD_LENGTH);
        StringBuilder out = new StringBuilder(limit + 8);
        for (int i = 0; i < limit; i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c > 0x7e) {
                out.append('.');
            } else {
                out.append(c);
            }
        }
        if (value.length() > limit) {
            out.append("...");
        }
        return out.toString();
    }

    /**
     * Masks a username, keeping just enough for an operator to recognise an
     * account they already know while not disclosing the account list.
     */
    public static String maskUsername(String username) {
        if (username == null || username.isEmpty()) {
            return "-";
        }
        String safe = escape(username);
        if (safe.length() <= 2) {
            return "*".repeat(safe.length());
        }
        return safe.charAt(0) + "*".repeat(Math.min(safe.length() - 2, 8)) + safe.charAt(safe.length() - 1);
    }

    /**
     * Masks a source address: the last IPv4 octet, or everything below the IPv6
     * /48 prefix, is dropped. Enough to spot a hostile network, not enough to
     * single out a person.
     */
    public static String maskSource(String source) {
        if (source == null || source.isEmpty()) {
            return "-";
        }
        String safe = escape(source);
        if (safe.indexOf(':') >= 0) {
            String[] groups = safe.split(":", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < 3 && i < groups.length; i++) {
                out.append(groups[i]).append(':');
            }
            return out.append(":/48").toString();
        }
        int lastDot = safe.lastIndexOf('.');
        return lastDot < 0 ? "***" : safe.substring(0, lastDot) + ".0/24";
    }
}
