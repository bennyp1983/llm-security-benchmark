package com.example.auth;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Append-only audit log.
 *
 * <p>Guarantees enforced here rather than trusted to callers:
 * <ul>
 *   <li>Message text comes only from {@link Event} constants plus a redacted account field, so
 *       attacker-controlled text cannot enter a line except through {@link #maskEmail(String)},
 *       which rebuilds its output from an allowlisted character set.</li>
 *   <li>Every rendered line is re-checked against that same allowlist, which excludes CR and LF,
 *       before it reaches the file. A line that fails is replaced by a fixed token, so log
 *       injection through any field is impossible.</li>
 *   <li>No method here accepts a password, a password hash, a salt, or a session token. There is no
 *       code path by which one can be written.</li>
 *   <li>The file is created owner-only (0600). An existing file that is a symlink, not owned by the
 *       current user, or group/world accessible stops the program at startup.</li>
 *   <li>Total bytes written are capped, so a request flood cannot be turned into disk exhaustion.</li>
 * </ul>
 */
final class LogWriter implements AutoCloseable {

    enum Event {
        BOOT_OK("boot_ok"),
        BOOT_FAIL("boot_fail"),
        LOGIN_SUCCESS("login_success"),
        LOGIN_DENIED("login_denied"),
        LOGIN_THROTTLED("login_throttled"),
        LOGIN_INVALID_INPUT("login_invalid_input"),
        LOGIN_INTERNAL("login_internal"),
        DB_UNAVAILABLE("db_unavailable"),
        DB_ROW_REJECTED("db_row_rejected"),
        SESSION_ISSUED("session_issued"),
        SESSION_REVOKED("session_revoked"),
        SESSION_NOT_FOUND("session_not_found"),
        SEED_OK("seed_ok"),
        SEED_EXISTS("seed_exists"),
        SEED_REJECTED("seed_rejected"),
        COUNTER_REFUNDED("counter_refunded"),
        AUDIT_CAP_REACHED("audit_cap_reached");

        private final String text;

        Event(String text) {
            this.text = text;
        }

        String text() {
            return text;
        }
    }

    private static final int MAX_LINE_CHARS = 320;
    private static final int MAX_TOTAL_BYTES = 4 * 1024 * 1024;
    private static final String FIXED_REJECT_LINE = "log_line_rejected";

    private final Path file;
    private final Writer out;
    private long written;
    private boolean capNotified;

    private LogWriter(Path file, Writer out) {
        this.file = file;
        this.out = out;
    }

    /**
     * Opens (creating if absent) the audit file. The parent directory must already have been
     * verified private; it is verified again here so this method is safe on its own.
     */
    static LogWriter open(Path file) throws IOException {
        Path parent = file.getParent();
        if (parent == null) {
            throw new IOException("audit_parent_missing");
        }
        DbPathGuard.requirePrivateDirectory(parent);
        if (Files.isSymbolicLink(file)) {
            throw new IOException("audit_file_is_symlink");
        }
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            DbFiles.newPrivateFile(file).close();
        }
        DbPathGuard.requirePrivateRegularFile(file);
        return new LogWriter(file, Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND));
    }

    /** Writes one event with a redacted account field and a non-negative counter. */
    synchronized void log(Event event, String maskedEmail, long count) {
        write("ev=" + event.text() + " acct=" + maskedEmail + " n=" + Math.max(0, count));
    }

    /**
     * Writes one event with a machine-readable reason code. The code must be one of this program's
     * own fixed tokens - a code containing anything else is dropped rather than written, so a
     * future caller cannot route attacker text into the log through this parameter.
     */
    synchronized void log(Event event, String maskedEmail, String code) {
        if (code == null || !FIXED_TOKEN.matcher(code).matches()) {
            code = "code_unavailable";
        }
        write("ev=" + event.text() + " acct=" + maskedEmail + " reason=" + code);
    }

    private static final java.util.regex.Pattern FIXED_TOKEN =
            java.util.regex.Pattern.compile("[a-z0-9_]{1,40}");

    synchronized void log(Event event) {
        write("ev=" + event.text());
    }

    private void write(String candidate) {
        String line = sanitize(candidate);
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        if (written + bytes.length > MAX_TOTAL_BYTES) {
            if (capNotified) {
                return;
            }
            capNotified = true;
            bytes = ("ev=" + Event.AUDIT_CAP_REACHED.text() + "\n").getBytes(StandardCharsets.UTF_8);
            if (written + bytes.length > MAX_TOTAL_BYTES) {
                return;
            }
            emit(bytes);
            return;
        }
        emit(bytes);
    }

    private void emit(byte[] bytes) {
        try {
            out.write(new String(bytes, StandardCharsets.UTF_8));
            out.flush();
            written += bytes.length;
        } catch (IOException e) {
            // Failing to audit must not take down authentication, and must not echo content.
            System.err.println("audit_write_failed");
        }
    }

    /**
     * Rejects (never escapes) any line that leaves the allowlisted charset, is empty, is over-long,
     * or would span more than one line.
     */
    static String sanitize(String candidate) {
        if (candidate == null || candidate.isEmpty() || candidate.length() > MAX_LINE_CHARS) {
            return FIXED_REJECT_LINE;
        }
        for (int i = 0; i < candidate.length(); i++) {
            if (!allowed(candidate.charAt(i))) {
                return FIXED_REJECT_LINE;
            }
        }
        return candidate;
    }

    private static boolean allowed(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == ' ' || c == '=' || c == ':' || c == '.' || c == '-' || c == '_'
                || c == '@' || c == '*' || c == '+' || c == '/' || c == '(' || c == ')'
                || c == ',';
    }

    /**
     * Redacts an account identifier: keeps the first local-part character and the domain (enough to
     * correlate a support case), never the rest of the mailbox name. A value that is not a clean
     * lowercase validated address collapses to a fixed token rather than being echoed.
     */
    static String maskEmail(String email) {
        if (email == null) {
            return "*";
        }
        int at = email.indexOf('@');
        if (at <= 0 || at != email.lastIndexOf('@') || at == email.length() - 1) {
            return "*";
        }
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);
        if (local.length() > 64 || domain.length() > 253) {
            return "*";
        }
        char first = local.charAt(0);
        if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9'))) {
            return "*";
        }
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!ok) {
                return "*";
            }
        }
        return first + "***@" + domain;
    }

    /** Shape-only summary for input that never became a valid address. */
    static String lengthOnly(String raw) {
        return "len=" + (raw == null ? 0 : raw.length());
    }

    Path path() {
        return file;
    }

    long bytesWritten() {
        return written;
    }

    @Override
    public void close() {
        try {
            out.close();
        } catch (IOException ignored) {
            // Closing an append-only sink cannot affect an authentication decision.
        }
    }
}
