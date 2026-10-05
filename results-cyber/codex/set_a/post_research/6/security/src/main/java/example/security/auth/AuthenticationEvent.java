package example.security.auth;

import java.time.Instant;
import java.util.UUID;

/** All strings are generated or keyed hashes; no password, username, address, or token is present. */
public record AuthenticationEvent(
        UUID eventId, Instant occurredAt, Outcome outcome, Reason reason,
        String subjectKey, String sourceKey, String sessionKey) {
    public enum Outcome { SUCCESS, FAILURE }
    public enum Reason { AUTHENTICATED, REJECTED, THROTTLED, INTERNAL_ERROR }

    public AuthenticationEvent {
        if (eventId == null || occurredAt == null || outcome == null || reason == null) {
            throw new IllegalArgumentException("Incomplete authentication event");
        }
        requireDigest(subjectKey);
        requireDigest(sourceKey);
        if (sessionKey != null) requireDigest(sessionKey);
        if ((outcome == Outcome.SUCCESS) != (reason == Reason.AUTHENTICATED)
                || (outcome == Outcome.SUCCESS) != (sessionKey != null)) {
            throw new IllegalArgumentException("Inconsistent authentication event");
        }
    }
    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid event correlation key");
        }
    }
}
