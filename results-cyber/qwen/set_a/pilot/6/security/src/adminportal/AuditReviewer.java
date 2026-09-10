package adminportal;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Read-side of the audit trail: filtering, human-readable tables, summaries, and export. */
public final class AuditReviewer {

    /** Filter criteria for a review. Null / empty fields are unconstrained. */
    public static final class Filter {
        public String username = "";
        public String outcome = "";
        public String event = "";
        public int limit = 0;

        public boolean matches(AuditEvent e) {
            if (!username.isEmpty()
                    && !e.username().toLowerCase(Locale.ROOT).contains(username.toLowerCase(Locale.ROOT))) {
                return false;
            }
            if (!outcome.isEmpty()
                    && !e.outcome().equalsIgnoreCase(outcome)) {
                return false;
            }
            if (!event.isEmpty()
                    && !e.event().toLowerCase(Locale.ROOT).contains(event.toLowerCase(Locale.ROOT))) {
                return false;
            }
            return true;
        }
    }

    private final AuditLog log;

    public AuditReviewer(AuditLog log) {
        this.log = log;
    }

    public List<AuditEvent> select(Filter filter) throws IOException {
        List<AuditEvent> all = log.readAll();
        List<AuditEvent> out = new ArrayList<>();
        for (AuditEvent event : all) {
            if (filter.matches(event)) {
                out.add(event);
            }
        }
        if (filter.limit > 0 && out.size() > filter.limit) {
            out = new ArrayList<>(out.subList(out.size() - filter.limit, out.size()));
        }
        return out;
    }

    public void printTable(List<AuditEvent> events, PrintStream out) {
        if (events.isEmpty()) {
            out.println("(no audit records match the filter)");
            return;
        }
        out.printf("%-4s %-26s %-8s %-24s %-10s %-16s %s%n", "seq", "timestamp", "outcome", "event",
                "actor", "username", "detail");
        out.println("-".repeat(120));
        for (AuditEvent event : events) {
            out.printf("%-4d %-26s %-8s %-24s %-10s %-16s %s%n", event.seq(), event.timestamp(),
                    event.outcome(), truncate(event.event(), 24), truncate(event.actor(), 10),
                    truncate(event.username().isEmpty() ? "-" : event.username(), 16),
                    event.detail());
        }
    }

    /** Aggregate view an operator scans first: totals, failure reasons, locked accounts. */
    public void printSummary(List<AuditEvent> events, AuthenticationService service, PrintStream out)
            throws IOException {
        Map<String, Integer> byEvent = new LinkedHashMap<>();
        Map<String, Integer> byOutcome = new LinkedHashMap<>();
        Map<String, Integer> failuresByUser = new LinkedHashMap<>();
        Map<String, Integer> reasonCounts = new LinkedHashMap<>();
        for (AuditEvent e : events) {
            byEvent.merge(e.event(), 1, Integer::sum);
            byOutcome.merge(e.outcome(), 1, Integer::sum);
            if (AuditEvent.Outcome.FAILURE.name().equals(e.outcome())) {
                if (!e.username().isEmpty()) {
                    failuresByUser.merge(e.username(), 1, Integer::sum);
                }
                String reason = e.detail().contains(":")
                        ? e.detail().substring(0, e.detail().indexOf(':')) : e.detail();
                reasonCounts.merge(reason.trim(), 1, Integer::sum);
            }
        }
        out.println("=== audit summary (" + events.size() + " record(s) shown) ===");
        byOutcome.forEach((k, v) -> out.printf("  outcome %-8s %d%n", k, v));
        out.println("  --- by event ---");
        byEvent.forEach((k, v) -> out.printf("    %-28s %d%n", k, v));
        if (!reasonCounts.isEmpty()) {
            out.println("  --- failure reasons ---");
            reasonCounts.entrySet().stream()
                    .sorted((x, y) -> Integer.compare(y.getValue(), x.getValue()))
                    .forEach(en -> out.printf("    %-24s %d%n", en.getKey(), en.getValue()));
        }
        if (!failuresByUser.isEmpty()) {
            out.println("  --- accounts with failures ---");
            failuresByUser.entrySet().stream()
                    .sorted((x, y) -> Integer.compare(y.getValue(), x.getValue())).limit(10)
                    .forEach(en -> out.printf("    %-20s %d failure(s)%s%n", en.getKey(),
                            en.getValue(),
                            service != null && service.isLockedOut(en.getKey()) ? " [LOCKED]" : ""));
        }
    }

    public AuditLog.Verification verifyChain() throws IOException {
        return log.verify();
    }

    public void printVerification(AuditLog.Verification v, PrintStream out) {
        out.println("audit log: " + log.location());
        out.println("signing key: " + log.keyLocation() + " (id " + log.keyId() + ")");
        out.println("records verified: " + v.records());
        if (v.isValid()) {
            out.println("RESULT: INTACT -- every seal and every chain link recomputes.");
        } else {
            out.println("RESULT: TAMPERING DETECTED -- " + v.problems().size() + " problem(s):");
            for (String problem : v.problems()) {
                out.println("  ! " + problem);
            }
        }
    }

    /** Raw JSONL export, for shipping to a SIEM or archiving. */
    public void exportJson(List<AuditEvent> events, PrintStream out) {
        for (AuditEvent event : events) {
            out.println(event.toJsonLine());
        }
    }

    private static String truncate(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max - 1) + "~";
    }
}
