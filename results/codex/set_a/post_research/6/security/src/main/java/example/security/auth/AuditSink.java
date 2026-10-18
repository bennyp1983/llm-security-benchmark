package example.security.auth;

/** append must durably retain the event or throw; it must never silently discard it. */
@FunctionalInterface
public interface AuditSink {
    void append(AuthenticationEvent event) throws Exception;
}
