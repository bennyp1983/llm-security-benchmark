package portal.admin;

/**
 * Append-only sink for security-relevant events. Deliberately an interface: the console
 * implementation is for operators, tests capture events in memory, and a deployment can
 * route them to a real SIEM without touching the authentication code.
 */
public interface AuditLog {

    void record(AuditEvent event);

    default void record(AuditResult result, String username, String detail) {
        record(new AuditEvent(System.currentTimeMillis(), result, username, detail));
    }

    /**
     * Most recent events, oldest first, capped at {@code limit}. Sinks that do not retain
     * history (a plain SIEM forwarder, for instance) return an empty list, and callers
     * must not treat that as "nothing happened".
     */
    default java.util.List<AuditEvent> recent(int limit) {
        return java.util.Collections.emptyList();
    }
}

