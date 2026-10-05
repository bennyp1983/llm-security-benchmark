package com.security.auth.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Secure event logger that writes to a restricted file and retains events for review (Rule 2 & 5).
 * Enforces:
 * - Private file permissions (0600 for log file, 0700 for directory).
 * - Thread-safe atomic writes (Rule 7).
 * - Bounded in-memory event retention (Rule 5).
 * - Protection against CRLF log injection (CWE-117).
 */
public final class SecureFileEventLogger implements AuthenticationEventLogger {

    private static final Logger SLF4J_LOGGER = LoggerFactory.getLogger(SecureFileEventLogger.class);

    private static final Set<PosixFilePermission> POSIX_FILE_PERMS = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> POSIX_DIR_PERMS = PosixFilePermissions.fromString("rwx------");
    private static final int DEFAULT_MAX_RETAINED_EVENTS = 1_000;

    public static final long DEFAULT_MAX_LOG_FILE_SIZE_BYTES = 50 * 1024 * 1024L; // 50 MB

    private final Path logFilePath;
    private final int maxRetainedEvents;
    private final long maxLogFileSizeBytes;
    private final ArrayDeque<AuthenticationEvent> retainedEvents;
    private BufferedWriter writer;
    private boolean closed = false;

    public SecureFileEventLogger(Path logFilePath) throws IOException {
        this(logFilePath, DEFAULT_MAX_RETAINED_EVENTS, DEFAULT_MAX_LOG_FILE_SIZE_BYTES);
    }

    public SecureFileEventLogger(Path logFilePath, int maxRetainedEvents) throws IOException {
        this(logFilePath, maxRetainedEvents, DEFAULT_MAX_LOG_FILE_SIZE_BYTES);
    }

    public SecureFileEventLogger(Path logFilePath, int maxRetainedEvents, long maxLogFileSizeBytes) throws IOException {
        this.logFilePath = Objects.requireNonNull(logFilePath, "Log file path cannot be null.").toAbsolutePath().normalize();
        if (maxRetainedEvents <= 0) {
            throw new IllegalArgumentException("Max retained events must be positive.");
        }
        if (maxLogFileSizeBytes <= 0) {
            throw new IllegalArgumentException("Max log file size must be positive.");
        }
        this.maxRetainedEvents = maxRetainedEvents;
        this.maxLogFileSizeBytes = maxLogFileSizeBytes;
        this.retainedEvents = new ArrayDeque<>(Math.min(maxRetainedEvents, 128));

        initializeSecureLogFile();
    }

    private void initializeSecureLogFile() throws IOException {
        // Prevent symlink attacks (CWE-59)
        if (Files.isSymbolicLink(logFilePath)) {
            throw new SecurityException("Log file path cannot be a symbolic link: " + logFilePath);
        }

        Path parent = logFilePath.getParent();
        if (parent != null) {
            if (Files.isSymbolicLink(parent)) {
                throw new SecurityException("Log directory cannot be a symbolic link: " + parent);
            }
            if (Files.exists(parent)) {
                try {
                    Set<PosixFilePermission> parentPerms = Files.getPosixFilePermissions(parent);
                    if (parentPerms.contains(PosixFilePermission.OTHERS_WRITE)) {
                        throw new SecurityException("Log directory cannot be world-writable: " + parent);
                    }
                } catch (UnsupportedOperationException ignored) {
                    // Non-POSIX fallback
                }
            } else {
                try {
                    FileAttribute<Set<PosixFilePermission>> dirAttr = PosixFilePermissions.asFileAttribute(POSIX_DIR_PERMS);
                    Files.createDirectories(parent, dirAttr);
                } catch (UnsupportedOperationException e) {
                    Files.createDirectories(parent);
                    restrictFilePermissionsFallback(parent.toFile(), true);
                }
            }
        }

        if (!Files.exists(logFilePath)) {
            try {
                FileAttribute<Set<PosixFilePermission>> fileAttr = PosixFilePermissions.asFileAttribute(POSIX_FILE_PERMS);
                Files.createFile(logFilePath, fileAttr);
            } catch (UnsupportedOperationException e) {
                Files.createFile(logFilePath);
                restrictFilePermissionsFallback(logFilePath.toFile(), false);
            }
        } else {
            // Ensure existing file has private permissions
            try {
                Files.setPosixFilePermissions(logFilePath, POSIX_FILE_PERMS);
            } catch (UnsupportedOperationException e) {
                restrictFilePermissionsFallback(logFilePath.toFile(), false);
            }
        }

        this.writer = Files.newBufferedWriter(
                logFilePath,
                StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND,
                java.nio.file.LinkOption.NOFOLLOW_LINKS
        );
    }

    private static void restrictFilePermissionsFallback(File file, boolean isDir) {
        file.setReadable(false, false);
        file.setReadable(true, true); // Owner readable only
        file.setWritable(false, false);
        file.setWritable(true, true); // Owner writable only
        if (isDir) {
            file.setExecutable(false, false);
            file.setExecutable(true, true); // Owner executable only
        } else {
            file.setExecutable(false, false);
        }
    }

    @Override
    public synchronized void logEvent(AuthenticationEvent event) {
        if (closed || event == null) {
            return;
        }

        // 1. Maintain bounded in-memory retention buffer (Rule 5)
        if (retainedEvents.size() >= maxRetainedEvents) {
            retainedEvents.pollFirst();
        }
        retainedEvents.addLast(event);

        // 2. Write to secure log file with atomic write semantics and bounded size (Rule 5 & Rule 7)
        String logLine = event.toLogLine();
        try {
            if (Files.exists(logFilePath) && Files.size(logFilePath) >= maxLogFileSizeBytes) {
                SLF4J_LOGGER.warn("Authentication log file exceeded maximum size of {} bytes. Write omitted to bound storage.", maxLogFileSizeBytes);
            } else {
                writer.write(logLine);
                writer.newLine();
                writer.flush();
            }
        } catch (IOException e) {
            SLF4J_LOGGER.error("Failed to write authentication event to log file", e);
        }

        // Also emit via standard platform logger for central logging integrations
        if (event.isSuccess()) {
            SLF4J_LOGGER.info("Authentication Event: {}", logLine);
        } else {
            SLF4J_LOGGER.warn("Authentication Event: {}", logLine);
        }
    }

    @Override
    public synchronized List<AuthenticationEvent> getRecentEvents(int limit) {
        if (limit <= 0) {
            return Collections.emptyList();
        }
        int count = Math.min(limit, retainedEvents.size());
        List<AuthenticationEvent> result = new ArrayList<>(count);
        int skip = retainedEvents.size() - count;
        int i = 0;
        for (AuthenticationEvent event : retainedEvents) {
            if (i >= skip) {
                result.add(event);
            }
            i++;
        }
        return Collections.unmodifiableList(result);
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            closed = true;
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    SLF4J_LOGGER.warn("Error closing log writer", e);
                }
            }
        }
    }

    public Path getLogFilePath() {
        return logFilePath;
    }
}
