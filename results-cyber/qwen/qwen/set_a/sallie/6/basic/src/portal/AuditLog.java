package portal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Append-only trail of authentication and administration events.
 *
 * <p>Recording failures are surfaced to the caller as {@link IOException} and the
 * portal treats them as fatal for the operation in progress: an attempt that
 * cannot be written down is an attempt that is not honoured.
 */
public final class AuditLog {

    static final int MAX_FIELD_CHARS = 96;
    private static final int TAIL_LIMIT = 5_000;

    private final Path path;
    private long sequence;

    public AuditLog(Path path) {
        this.path = path;
        this.sequence = lastSequenceOnDisk();
    }

    public Path path() {
        return path;
    }

    /**
     * @throws IOException if the record could not be persisted
     */
    public synchronized void record(String event, String subject, String detail) throws IOException {
        StringBuilder line = new StringBuilder(160);
        line.append(++sequence)
                .append('\t').append(Instant.now())
                .append('\t').append(clean(event))
                .append('\t').append(clean(subject))
                .append('\t').append(clean(detail));
        byte[] bytes = (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
        Files.write(path, bytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
    }

    /** Best-effort read of the last {@code n} records; never throws. */
    public List<String> tail(int n) {
        int limit = Math.max(1, Math.min(n, TAIL_LIMIT));
        List<String> out = new ArrayList<>();
        try {
            if (!Files.isRegularFile(path)) {
                return out;
            }
            List<String> all = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (int i = Math.max(0, all.size() - limit); i < all.size(); i++) {
                out.add(all.get(i));
            }
        } catch (IOException unreadable) {
            out.add("(the audit log at " + clean(path.toString()) + " could not be read)");
        }
        return out;
    }

    /** Keeps hostile input from forging extra records or control sequences. */
    static String clean(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "-";
        }
        String value = raw.length() > MAX_FIELD_CHARS ? raw.substring(0, MAX_FIELD_CHARS) : raw;
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            sb.append(c >= 0x20 && c < 0x7F ? c : '?');
        }
        return sb.length() == 0 ? "?" : sb.toString();
    }

    private long lastSequenceOnDisk() {
        try {
            if (!Files.isRegularFile(path)) {
                return 0L;
            }
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (int i = lines.size() - 1; i >= 0; i--) {
                String line = lines.get(i);
                int tab = line.indexOf('\t');
                if (tab <= 0) {
                    continue;
                }
                try {
                    return Long.parseLong(line.substring(0, tab).trim());
                } catch (NumberFormatException notUs) {
                    return 0L;
                }
            }
        } catch (IOException unreadable) {
            return 0L;
        }
        return 0L;
    }
}
