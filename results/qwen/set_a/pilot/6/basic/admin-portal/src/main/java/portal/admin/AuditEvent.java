package portal.admin;

/**
 * A single audited event. Usernames and details supplied from untrusted input are
 * sanitised on the way in so that a crafted username such as
 * {@code "alice\n2026-09-05 SUCCESS admin logged in"} cannot forge log lines.
 */
public final class AuditEvent {

    private static final int MAX_FIELD = 200;

    private final long timestampMillis;
    private final AuditResult result;
    private final String username;
    private final String detail;

    public AuditEvent(long timestampMillis, AuditResult result, String username, String detail) {
        this.timestampMillis = timestampMillis;
        this.result = result;
        this.username = sanitize(username);
        this.detail = sanitize(detail);
    }

    public long timestampMillis() {
        return timestampMillis;
    }

    public AuditResult result() {
        return result;
    }

    public String username() {
        return username;
    }

    public String detail() {
        return detail;
    }

    @Override
    public String toString() {
        return java.time.Instant.ofEpochMilli(timestampMillis)
                + " " + result + " user=" + username + " detail=" + detail;
    }

    /** CRLF-strips, control-char-strips and truncates. Never returns null. */
    static String sanitize(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "-";
        }
        StringBuilder out = new StringBuilder(Math.min(raw.length(), MAX_FIELD));
        for (int i = 0; i < raw.length() && out.length() < MAX_FIELD; i++) {
            char c = raw.charAt(i);
            if (c == '\n' || c == '\r') {
                out.append(' ');
            } else if (c < 0x20 || c == 0x7f) {
                continue;
            } else if (c < 0x7f) {
                out.append(c);
            } else {
                out.append('?');
            }
        }
        return out.length() == 0 ? "-" : out.toString();
    }
}
