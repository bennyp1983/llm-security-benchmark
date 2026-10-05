package com.portal.auth;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Security-relevant event log.
 *
 * <p>What may be recorded: a timestamp, an event name, a SHA-256 reference of an
 * identity, a source reference, and booleans/counts. What may never appear: a password,
 * a full username, a session id, a CSRF token, a keystore password, or an exception
 * message that could contain any of those (see {@link #systemFailure}).
 *
 * <p>The file is append-only {@code 0600}. A bounded in-memory ring is kept as well so
 * the operator can inspect recent events without reading the file.
 */
public final class AuditLog {

    public static final int MAX_KEPT = 200_000;

    /** Bounded so a log-flood attempt cannot grow the heap without limit. */
    private final Deque<String> recent = new ArrayDeque<>();
    private final Path file;
    private final boolean enabled;
    private long written;
    private long failedWrites;

    public AuditLog(Path file) {
        this.file = file;
        this.enabled = file != null;
    }

    public static AuditLog discarding() {
        return new AuditLog(null);
    }

    /**
     * @param identityRef {@link Crypto#idRef} of the identity, never the identity itself
     * @param outcome     short machine token, e.g. {@code denied}
     * @param detail      short machine token, e.g. {@code bad-credentials}; free text is
     *                    not permitted because it is attacker-influenced in places
     */
    public synchronized void event(String name, String identityRef, String sourceRef,
                                   String outcome, String detail) {
        String line = "ts=" + AuditClock.now()
                + " event=" + token(name, 40)
                + " subject=" + ref(identityRef)
                + " src=" + ref(sourceRef)
                + " outcome=" + token(outcome, 32)
                + " detail=" + token(detail, 48);
        append(line);
    }

    /**
     * A system failure detail. The exception is reduced to its class name only: a
     * {@code JDBC} or {@code IOException} message can echo a path, a URL with
     * credentials, or a value we would rather not persist.
     */
    public synchronized void systemFailure(String name, String identityRef, String sourceRef,
                                           Throwable failure) {
        event(name, identityRef, sourceRef, "error",
                "type=" + failure.getClass().getSimpleName());
    }

    private void append(String line) {
        recent.addLast(line);
        while (recent.size() > MAX_KEPT) {
            recent.removeFirst();
        }
        if (!enabled) {
            return;
        }
        try {
            PrivateFiles.appendPrivateLine(file, line);
            written++;
        } catch (RuntimeException cannotWrite) {
            // Never let logging availability change an authentication decision, and never
            // let the log's own error text (which may name a path) reach the caller.
            failedWrites++;
        }
    }

    public synchronized String lastEventForTesting() {
        return recent.peekLast();
    }

    public synchronized java.util.List<String> recentForTesting(int max) {
        java.util.List<String> out = new java.util.ArrayList<>(recent.size());
        int skip = Math.max(0, recent.size() - max);
        int i = 0;
        for (String s : recent) {
            if (i++ >= skip) {
                out.add(s);
            }
        }
        return out;
    }

    public synchronized long writtenCount() {
        return written;
    }

    public synchronized long failedWriteCount() {
        return failedWrites;
    }

    /** Restricts a field to the audit alphabet; anything else becomes a fixed token. */
    private static String token(String value, int maxLen) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        if (value.length() > maxLen) {
            return "truncated";
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '=' || c == ':';
            if (!ok) {
                return "rejected";
            }
        }
        return value;
    }

    /**
     * The identity and source fields carry <em>references</em>, never identities. Their
     * width is pinned to {@link Ledger#SUBJECT_HEX} because the same value doubles as a
     * throttle-bucket key, and the only non-digest tokens accepted are the two internal
     * labels below. A permissive character-class check would not do: a username is a short
     * lower-case word, so one would pass straight through and the log would name accounts.
     */
    private static String ref(String value) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        if (value.length() == Ledger.SUBJECT_HEX && isLowerHex(value)) {
            return value;
        }
        if (value.equals("-") || value.equals(Authenticator.INVALID_REF)) {
            return value;
        }
        return "rejected";
    }

    private static boolean isLowerHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
