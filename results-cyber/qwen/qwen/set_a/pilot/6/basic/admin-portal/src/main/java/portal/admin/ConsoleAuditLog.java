package portal.admin;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

/** Writes one sanitised line per event, and optionally keeps them for inspection. */
public final class ConsoleAuditLog implements AuditLog {

    private final PrintStream out;
    private final boolean retain;
    private final List<AuditEvent> events = new ArrayList<>();

    public ConsoleAuditLog(PrintStream out) {
        this(out, false);
    }

    public ConsoleAuditLog(PrintStream out, boolean retain) {
        this.out = out;
        this.retain = retain;
    }

    @Override
    public synchronized void record(AuditEvent event) {
        if (retain) {
            events.add(event);
        }
        out.println("AUDIT " + event);
        out.flush();
    }

    public synchronized List<AuditEvent> events() {
        return new ArrayList<>(events);
    }

    @Override
    public synchronized List<AuditEvent> recent(int limit) {
        if (limit <= 0 || limit >= events.size()) {
            return new ArrayList<>(events);
        }
        return new ArrayList<>(events.subList(events.size() - limit, events.size()));
    }

    /** Convenience for tests and assertions. */
    public synchronized int count(AuditResult result) {
        int total = 0;
        for (AuditEvent event : events) {
            if (event.result() == result) {
                total++;
            }
        }
        return total;
    }
}
