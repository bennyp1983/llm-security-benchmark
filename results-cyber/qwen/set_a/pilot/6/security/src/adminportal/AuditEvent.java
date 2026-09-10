package adminportal;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One immutable audit record. Serialised as a single JSON object per line so the log stays
 * machine-readable (jq, python -c json) while remaining append-only text.
 *
 * Field values are always passed through {@link #sanitize(String)} before they are stored, which
 * is what stops a crafted username or argument from injecting forged log lines.
 *
 * @param seq       strictly increasing sequence number, 1-based, no gaps
 * @param timestamp ISO-8601 UTC instant
 * @param keyId     identifier of the HMAC key that sealed this record (supports key rotation)
 * @param prevHash  hash of the previous record, or the GENESIS sentinel for the first record
 * @param hash      HMAC over {@link #canonicalPayload()} sealed with {@code keyId}
 */
public record AuditEvent(long seq, String timestamp, String event, String outcome, String actor,
                         String username, String detail, String keyId, String prevHash, String hash) {

    public enum Outcome {
        SUCCESS, FAILURE, INFO
    }

    public static final String GENESIS = "GENESIS";
    public static final int MAX_FIELD_LEN = 200;

    /**
     * Neutralises log-injection: no CR/LF (line forgery), no other control characters, no
     * non-printable bytes, bounded length. Values that could imitate an account-store record are
     * flattened too.
     */
    public static String sanitize(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(Math.min(raw.length(), MAX_FIELD_LEN));
        for (int i = 0; i < raw.length() && sb.length() < MAX_FIELD_LEN; i++) {
            char c = raw.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') {
                sb.append(' ');
            } else if (c < 0x20 || c == 0x7F || c > 0x7E) {
                sb.append('?');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Canonical rendering used as the HMAC input. Excludes the record's own hash. */
    public String canonicalPayload() {
        return "seq=" + seq
                + "\u001Fts=" + timestamp
                + "\u001Fevent=" + event
                + "\u001Foutcome=" + outcome
                + "\u001Factor=" + actor
                + "\u001Fusername=" + username
                + "\u001Fdetail=" + detail
                + "\u001Fprev=" + prevHash
                + "\u001Fkey=" + keyId;
    }

    public String toJsonLine() {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        appendField(sb, "seq", String.valueOf(seq), true);
        appendField(sb, "ts", timestamp, false);
        appendField(sb, "event", event, false);
        appendField(sb, "outcome", outcome, false);
        appendField(sb, "actor", actor, false);
        appendField(sb, "username", username, false);
        appendField(sb, "detail", detail, false);
        appendField(sb, "prev", prevHash, false);
        appendField(sb, "key", keyId, false);
        appendField(sb, "hash", hash, false);
        sb.append('}');
        return sb.toString();
    }

    private static void appendField(StringBuilder sb, String name, String value, boolean first) {
        if (!first) {
            sb.append(',');
        }
        sb.append('"').append(name).append("\":\"").append(escape(value)).append('"');
    }

    static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    /** Parses one JSON line written by {@link #toJsonLine()}. Returns null when structurally bad. */
    static AuditEvent fromJsonLine(String line) {
        if (line == null) {
            return null;
        }
        String s = line.strip();
        if (s.length() < 2 || !s.startsWith("{") || !s.endsWith("}")) {
            return null;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        int i = 1;
        int end = s.length() - 1;
        while (i < end) {
            int nameStart = s.indexOf('"', i);
            if (nameStart < 0 || nameStart >= end) {
                return null;
            }
            int nameEnd = s.indexOf('"', nameStart + 1);
            if (nameEnd < 0 || nameEnd >= end) {
                return null;
            }
            String name = s.substring(nameStart + 1, nameEnd);
            int colon = s.indexOf(':', nameEnd + 1);
            if (colon < 0 || colon > end) {
                return null;
            }
            int valueStart = s.indexOf('"', colon + 1);
            if (valueStart < 0 || valueStart > end) {
                return null;
            }
            StringBuilder value = new StringBuilder();
            int j = valueStart + 1;
            while (j < end) {
                char c = s.charAt(j);
                if (c == '"') {
                    break;
                }
                if (c == '\\' && j + 1 < end) {
                    char next = s.charAt(j + 1);
                    switch (next) {
                        case 'n' -> value.append('\n');
                        case 'r' -> value.append('\r');
                        case 't' -> value.append('\t');
                        case '"' -> value.append('"');
                        case '\\' -> value.append('\\');
                        case 'u' -> {
                            if (j + 5 >= end) {
                                return null;
                            }
                            value.append((char) Integer.parseInt(s.substring(j + 2, j + 6), 16));
                            j += 4;
                        }
                        default -> value.append(next);
                    }
                    j += 2;
                } else {
                    value.append(c);
                    j++;
                }
            }
            if (j >= end) {
                return null;
            }
            if (fields.put(name, value.toString()) != null) {
                // Duplicate key: two records ran together on one line, or a hand-edited payload.
                return null;
            }
            i = j + 1;
        }
        String seq = fields.get("seq");
        if (seq == null) {
            return null;
        }
        try {
            return new AuditEvent(Long.parseLong(seq), fields.getOrDefault("ts", ""),
                    fields.getOrDefault("event", ""), fields.getOrDefault("outcome", ""),
                    fields.getOrDefault("actor", ""), fields.getOrDefault("username", ""),
                    fields.getOrDefault("detail", ""), fields.getOrDefault("key", ""),
                    fields.getOrDefault("prev", ""), fields.getOrDefault("hash", ""));
        } catch (NumberFormatException | IndexOutOfBoundsException e) {
            return null;
        }
    }

    @Override
    public String toString() {
        return String.format("%s seq=%-4d %-7s %-26s actor=%-10s user=%-16s %s", timestamp, seq,
                outcome, event, actor, username.isEmpty() ? "-" : username, detail);
    }
}
