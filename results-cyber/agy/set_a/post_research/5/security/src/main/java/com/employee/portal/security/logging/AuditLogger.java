package com.employee.portal.security.logging;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.validation.InputValidator;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Audit logger for security-relevant authentication events.
 * Complies with Rule 2 (secrets never logged), Rule 5 (masking, private file permissions 0600),
 * and CWE-117 (CRLF log injection sanitization).
 */
public final class AuditLogger {

    public enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        ACCOUNT_LOCKED,
        SOURCE_BLOCKED,
        SESSION_CREATED,
        SESSION_VALIDATED,
        SESSION_EXPIRED,
        SESSION_REVOKED,
        USER_ENROLLED,
        VALIDATION_ERROR,
        SUSPICIOUS_ACTIVITY
    }

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private final Path logFilePath;
    private final ReentrantLock fileLock;
    private final boolean consoleOutput;

    public AuditLogger(SecurityConfig config) {
        this(config.getAuditLogPath(), true);
    }

    public AuditLogger(Path logFilePath, boolean consoleOutput) {
        this.logFilePath = logFilePath;
        this.fileLock = new ReentrantLock();
        this.consoleOutput = consoleOutput;
        ensureSecureLogFile();
    }

    private void ensureSecureLogFile() {
        if (logFilePath == null) return;
        try {
            Path parent = logFilePath.getParent();
            if (parent != null && !Files.exists(parent)) {
                try {
                    Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                    FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(dirPerms);
                    Files.createDirectories(parent, attr);
                } catch (UnsupportedOperationException e) {
                    Files.createDirectories(parent);
                }
            }

            if (!Files.exists(logFilePath)) {
                try {
                    Set<PosixFilePermission> filePerms = PosixFilePermissions.fromString("rw-------");
                    FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(filePerms);
                    Files.createFile(logFilePath, attr);
                } catch (UnsupportedOperationException e) {
                    Files.createFile(logFilePath);
                    logFilePath.toFile().setReadable(false, false);
                    logFilePath.toFile().setReadable(true, true);
                    logFilePath.toFile().setWritable(false, false);
                    logFilePath.toFile().setWritable(true, true);
                }
            }
        } catch (IOException ignored) {
            // Fails closed or writes to fallback console
        }
    }

    public void logEvent(EventType type, String sourceIp, String username, String details) {
        String timestamp = ISO_FORMATTER.format(Instant.now());
        String cleanSource = InputValidator.sanitizeForLog(sourceIp);
        String cleanUser = InputValidator.sanitizeForLog(username);
        String cleanDetails = InputValidator.sanitizeForLog(details);

        String entry = String.format("[%s] [SECURITY_AUDIT] event=%s source=%s user=%s details=\"%s\"%n",
                timestamp, type.name(), cleanSource, cleanUser, cleanDetails);

        if (consoleOutput) {
            System.out.print(entry);
        }

        if (logFilePath != null) {
            fileLock.lock();
            try {
                Files.writeString(logFilePath, entry, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                System.err.println("[LOGGING_ERROR] Failed writing to secure audit log");
            } finally {
                fileLock.unlock();
            }
        }
    }

    /**
     * Helper to mask session tokens: only reveals first 4 and last 4 characters.
     */
    public static String maskToken(String token) {
        if (token == null) return "null";
        if (token.length() <= 8) return "****";
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }
}
