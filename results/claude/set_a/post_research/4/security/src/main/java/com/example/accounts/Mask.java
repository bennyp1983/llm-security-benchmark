package com.example.accounts;

/**
 * Masking helpers for anything that reaches a log, console or exception message.
 *
 * <p>Rule 5 (sensitive data): identifiers are reduced to the minimum needed to correlate records.
 * Passwords and session tokens have no masking helper on purpose -- they are never logged at all,
 * so there is no "safe" rendering of them to reach for.
 */
final class Mask {

    private Mask() {
    }

    /** {@code alice@example.com} -> {@code a***@example.com}; shape-preserving, not reversible. */
    static String email(String email) {
        if (email == null || email.isEmpty()) {
            return "<none>";
        }
        int at = email.lastIndexOf('@');
        if (at <= 0) {
            return "<malformed>";
        }
        String local = email.substring(0, at);
        String domain = email.substring(at); // includes '@'
        char first = local.charAt(0);
        return first + "***" + domain;
    }

    /** Keeps the first character only, so support can match a report to a log line. */
    static String username(String username) {
        if (username == null || username.isEmpty()) {
            return "<none>";
        }
        return username.charAt(0) + "***(" + username.length() + ")";
    }

    /** Strips any userinfo/query from a JDBC URL, which may carry credentials. */
    static String jdbcUrl(String url) {
        if (url == null) {
            return "<none>";
        }
        int cut = url.length();
        for (char c : new char[] {'?', ';'}) {
            int i = url.indexOf(c);
            if (i >= 0 && i < cut) {
                cut = i;
            }
        }
        String base = url.substring(0, cut);
        int at = base.indexOf('@');
        if (at >= 0) {
            int schemeEnd = base.indexOf("//");
            if (schemeEnd >= 0 && at > schemeEnd) {
                base = base.substring(0, schemeEnd + 2) + "***" + base.substring(at);
            }
        }
        return base;
    }
}
