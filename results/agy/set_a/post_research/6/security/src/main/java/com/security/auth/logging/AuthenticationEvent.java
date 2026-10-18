package com.security.auth.logging;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable audit event capturing authentication activity for later review (Rule 1, 2, 5, 6).
 * Secrets (passwords, raw tokens) are never accepted or retained in event state.
 */
public final class AuthenticationEvent {

    private static final int MAX_DETAIL_LENGTH = 256;
    private static final int MAX_USERNAME_LENGTH = 64;
    private static final int MAX_IP_LENGTH = 45;

    private final Instant timestamp;
    private final AuthenticationEventType eventType;
    private final boolean success;
    private final String username;
    private final String clientIp;
    private final String tokenFingerprint;
    private final String details;

    public AuthenticationEvent(Instant timestamp,
                               AuthenticationEventType eventType,
                               boolean success,
                               String username,
                               String clientIp,
                               String tokenFingerprint,
                               String details) {
        this.timestamp = Objects.requireNonNull(timestamp, "Timestamp cannot be null.");
        this.eventType = Objects.requireNonNull(eventType, "EventType cannot be null.");
        this.success = success;
        this.username = sanitizeAndBound(username, MAX_USERNAME_LENGTH, "[ANONYMOUS]");
        this.clientIp = sanitizeAndBound(clientIp, MAX_IP_LENGTH, "[UNKNOWN_IP]");
        this.tokenFingerprint = sanitizeAndBound(tokenFingerprint, 32, "");
        this.details = sanitizeAndBound(details, MAX_DETAIL_LENGTH, "");
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public AuthenticationEventType getEventType() {
        return eventType;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getUsername() {
        return username;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getTokenFingerprint() {
        return tokenFingerprint;
    }

    public String getDetails() {
        return details;
    }

    /**
     * Sanitizes input to neutralize CRLF injection (CWE-117) and bounds string length (Rule 5).
     */
    private static String sanitizeAndBound(String input, int maxLength, String fallback) {
        if (input == null || input.isBlank()) {
            return fallback;
        }
        // Neutralize carriage returns, newlines, and tabs to prevent log forging
        String sanitized = input.replace('\r', '_')
                .replace('\n', '_')
                .replace('\t', ' ')
                .replaceAll("[\\p{Cntrl}]", "");

        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength);
        }
        return sanitized;
    }

    /**
     * Formats the event as a structured log line.
     */
    public String toLogLine() {
        return String.format("%s | outcome=%s | event=%s | user=%s | ip=%s | token_fp=%s | details=\"%s\"",
                timestamp.toString(),
                success ? "SUCCESS" : "FAILURE",
                eventType.name(),
                username,
                clientIp,
                tokenFingerprint.isEmpty() ? "none" : tokenFingerprint,
                details);
    }

    @Override
    public String toString() {
        return toLogLine();
    }
}
