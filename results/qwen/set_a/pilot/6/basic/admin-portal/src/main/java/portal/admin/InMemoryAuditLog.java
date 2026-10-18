package portal.admin;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Keeps the most recent events in memory on top of a delegate sink, so an auditor signed
 * into the console can review them without a log file being tailed. Bounded and
 * synchronized; it is a convenience view, not the system of record.
 */
public final class InMemoryAuditLog implements AuditLog {

    public static final int DEFAULT_CAPACITY = 500;

    private final Deque<AuditEvent> events = new ArrayDeque<>();
    private final AuditLog delegate;
    private final int capacity;

    public InMemoryAuditLog() {
        this(null, DEFAULT_CAPACITY);
    }

    public InMemoryAuditLog(AuditLog delegate, int capacity) {
        this.delegate = delegate;
        this.capacity = capacity < 10 ? 10 : capacity;
    }

    @Override
    public synchronized void record(AuditEvent event) {
        if (events.size() >= capacity) {
            events.pollFirst();
        }
        events.addLast(event);
        if (delegate != null) {
            delegate.record(event);
        }
    }

    @Override
    public synchronized List<AuditEvent> recent(int limit) {
        List<AuditEvent> all = new ArrayList<>(events);
        if (limit <= 0 || limit >= all.size()) {
            return all;
        }
        return all.subList(all.size() - limit, all.size());
    }

    public synchronized List<AuditEvent> all() {
        return new ArrayList<>(events);
    }

    public synchronized int count(AuditResult result) {
        int total = 0;
        for (AuditEvent event : events) {
            if (event.result() == result) {
                total++;
            }
        }
        return total;
    }

    public synchronized int size() {
        return events.size();
    }

    public synchronized void clear() {
        events.clear();
    }
}
