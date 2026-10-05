package com.example.auth;

import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Audit and security logger.
 * Enforces:
 * - Rule 2: Passwords and secrets are never printed or logged.
 * - Rule 5: Masking of sensitive identifiers (emails masked, tokens truncated).
 * - Rule 6: Internal detailed failure reasons logged securely without exposing them to users.
 * - CWE-117 mitigation: Neutralization of Carriage Return and Line Feed (CRLF) characters to prevent log forging.
 */
public final class SecurityLogger {

    private static final Logger LOGGER = Logger.getLogger(SecurityLogger.class.getName());

    static {
        LOGGER.setUseParentHandlers(false);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                return String.format("[%1$tF %1$tT.%1$tL] [%2$s] %3$s%n",
                        record.getMillis(),
                        record.getLevel().getName(),
                        record.getMessage());
            }
        });
        LOGGER.addHandler(handler);
    }

    private SecurityLogger() {
        // Utility class
    }

    /**
     * Masks an email address for safe logging.
     * Example: "alice.smith@domain.com" -> "a***h@d***n.com"
     */
    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return "[EMPTY_EMAIL]";
        }
        int atIndex = email.indexOf('@');
        if (atIndex <= 0 || atIndex == email.length() - 1) {
            return "[MALFORMED_EMAIL]";
        }

        String localPart = email.substring(0, atIndex);
        String domainPart = email.substring(atIndex + 1);

        int dotIndex = domainPart.lastIndexOf('.');
        String maskedDomain;
        if (dotIndex > 0) {
            String domainName = domainPart.substring(0, dotIndex);
            String tld = domainPart.substring(dotIndex);
            maskedDomain = maskSegment(domainName) + tld;
        } else {
            maskedDomain = maskSegment(domainPart);
        }

        String maskedLocal = maskSegment(localPart);
        return sanitizeCrlf(maskedLocal + "@" + maskedDomain);
    }

    /**
     * Truncates and masks a session token for safe logging.
     */
    public static String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "[EMPTY_TOKEN]";
        }
        if (token.length() <= 8) {
            return "***";
        }
        return sanitizeCrlf(token.substring(0, 4) + "..." + token.substring(token.length() - 4));
    }

    /**
     * Sanitizes inputs to prevent CRLF injection / log forging (CWE-117).
     */
    public static String sanitizeCrlf(String input) {
        if (input == null) {
            return "";
        }
        return input.replace('\r', '_').replace('\n', '_');
    }

    public static void logAuthSuccess(String email, String sourceId) {
        LOGGER.info(String.format("AUDIT [AUTH_SUCCESS] User=%s Source=%s",
                maskEmail(email), sanitizeCrlf(sourceId)));
    }

    public static void logAuthFailure(String email, String sourceId, String internalReason) {
        LOGGER.warning(String.format("AUDIT [AUTH_FAILURE] User=%s Source=%s Reason=%s",
                maskEmail(email), sanitizeCrlf(sourceId), sanitizeCrlf(internalReason)));
    }

    public static void logRateLimitExceeded(String email, String sourceId, String limitType) {
        LOGGER.warning(String.format("AUDIT [RATE_LIMIT_BLOCKED] User=%s Source=%s LimitType=%s",
                maskEmail(email), sanitizeCrlf(sourceId), sanitizeCrlf(limitType)));
    }

    public static void logSystemError(String operation, Throwable throwable) {
        LOGGER.log(Level.SEVERE, "SECURITY [SYSTEM_ERROR] Operation=" + sanitizeCrlf(operation), throwable);
    }

    private static String maskSegment(String segment) {
        if (segment == null || segment.isEmpty()) {
            return "*";
        }
        if (segment.length() <= 2) {
            return segment.charAt(0) + "***";
        }
        return segment.charAt(0) + "***" + segment.charAt(segment.length() - 1);
    }
}
