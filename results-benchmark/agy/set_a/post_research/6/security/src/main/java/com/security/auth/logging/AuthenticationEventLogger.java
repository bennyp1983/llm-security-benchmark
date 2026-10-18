package com.security.auth.logging;

import java.util.List;

/**
 * Interface for logging authentication activity and retaining events for audit review.
 */
public interface AuthenticationEventLogger extends AutoCloseable {

    /**
     * Records an authentication event in the application audit log.
     *
     * @param event authentication event to log
     */
    void logEvent(AuthenticationEvent event);

    /**
     * Retrieves retained authentication events for security review.
     *
     * @param limit maximum number of recent events to return
     * @return list of recent authentication events in chronological order
     */
    List<AuthenticationEvent> getRecentEvents(int limit);

    @Override
    default void close() {
        // Default no-op
    }
}
