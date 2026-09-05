package empportal.security;

import java.io.PrintStream;
import java.time.Instant;
import java.util.function.LongSupplier;

/**
 * Line-oriented audit sink.
 *
 * <p>Defaults to {@code System.err} so audit lines stay separated from portal output and can be
 * redirected to the host log collector independently.
 */
public final class ConsoleAuditLog implements AuditLog {

    private final PrintStream out;
    private final LongSupplier clock;

    public ConsoleAuditLog(PrintStream out, LongSupplier clock) {
        this.out = out;
        this.clock = clock;
    }

    public static ConsoleAuditLog system() {
        return new ConsoleAuditLog(System.err, System::currentTimeMillis);
    }

    @Override
    public void record(AuditEvent event, String username, String outcome, String detail) {
        StringBuilder line = new StringBuilder(96);
        line.append(Instant.ofEpochMilli(clock.getAsLong()))
                .append(" auth event=").append(event)
                .append(" user=").append(sanitize(username))
                .append(" outcome=").append(outcome);
        if (detail != null && !detail.isEmpty()) {
            line.append(" detail=").append(sanitize(detail));
        }
        out.println(line);
    }

    /** Keeps one record per line and strips control characters that could forge a log entry. */
    private static String sanitize(String value) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        StringBuilder clean = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t' || Character.isISOControl(c)) {
                clean.append(' ');
            } else {
                clean.append(c);
            }
        }
        return clean.toString();
    }
}
