package com.portal.auth;

import java.time.Instant;

/**
 * One audit record describing something that happened to an account.
 *
 * <p>Notably absent: the password. No field of this record may ever hold a candidate or stored
 * secret, and {@link #safe(String)} is applied to usernames so a crafted name cannot forge extra log
 * lines.
 */
public record AuditEvent(Instant at, Type type, String username, String detail) {

    public enum Type {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        /** A credential check was refused because the account is throttled. */
        LOGIN_REFUSED_LOCKED,
        /** A credential check was refused because the record is LOCKED or DISABLED. */
        LOGIN_REFUSED_STATUS,
        /** A count of failures crossed the policy threshold. */
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        ACCOUNT_STATUS_CHANGED,
        ACCOUNT_CREATED,
        PASSWORD_RESET
    }

    public static AuditEvent of(Type type, String username, String detail) {
        return new AuditEvent(Instant.now(), type, safe(username), detail);
    }

    /**
     * Strips control characters (CR/LF among them, the log-forging vector) from attacker-supplied
     * text, escapes the two characters that would break the quoting in {@link #toString()}, and caps
     * the length, so a 10&nbsp;MB username cannot become a 10&nbsp;MB log line.
     */
    public static String safe(String raw) {
        if (raw == null) {
            return "<null>";
        }
        int limit = Math.min(raw.length(), 64);
        StringBuilder out = new StringBuilder(limit);
        for (int i = 0; i < limit; i++) {
            char c = raw.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                out.append('?');
            } else if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else {
                out.append(c);
            }
        }
        if (raw.length() > limit) {
            out.append("...[truncated]");
        }
        return out.toString();
    }

    /**
     * The username is quoted so an attacker-chosen name cannot blur the boundary between field and
     * value. Quoting plus control-character stripping is what guarantees one {@code AuditEvent}
     * renders to exactly one line, which is the property downstream log shippers rely on.
     */
    @Override
    public String toString() {
        return at + " type=" + type + " user=\"" + username + "\""
                + (detail == null || detail.isEmpty() ? "" : " " + detail);
    }
}
