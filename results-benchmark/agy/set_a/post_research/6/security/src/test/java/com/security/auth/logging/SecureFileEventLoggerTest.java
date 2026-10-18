package com.security.auth.logging;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SecureFileEventLogger Tests (Rule 2 & Rule 5)")
class SecureFileEventLoggerTest {

    @Test
    @DisplayName("Should create log file with private owner permissions (0600) on POSIX filesystems")
    void testLogFilePermissions(@TempDir Path tempDir) throws IOException {
        Path logFile = tempDir.resolve("logs/auth_events.log");

        try (SecureFileEventLogger logger = new SecureFileEventLogger(logFile)) {
            logger.logEvent(new AuthenticationEvent(Instant.now(),
                    AuthenticationEventType.LOGIN_SUCCESS,
                    true, "alice", "127.0.0.1", "a1b2c3d4", "Login test"));
        }

        assertTrue(Files.exists(logFile));

        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(logFile);
            assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
            assertTrue(perms.contains(PosixFilePermission.OWNER_WRITE));
            assertFalse(perms.contains(PosixFilePermission.OTHERS_READ), "Log file must not be readable by others (Rule 2 & 5)");
            assertFalse(perms.contains(PosixFilePermission.OTHERS_WRITE), "Log file must not be writable by others");
            assertFalse(perms.contains(PosixFilePermission.GROUP_READ), "Log file must not be group-readable");
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX system (e.g. Windows)
        }
    }

    @Test
    @DisplayName("CRLF Injection Defense: Injected newlines must be sanitized to prevent log forging (CWE-117)")
    void testCrlfInjectionNeutralized(@TempDir Path tempDir) throws IOException {
        Path logFile = tempDir.resolve("crlf_test.log");

        try (SecureFileEventLogger logger = new SecureFileEventLogger(logFile)) {
            // Attacker attempts to forge a fake login event via CRLF in username
            String maliciousUsername = "admin\r\n2026-10-01T00:00:00Z | outcome=SUCCESS | event=LOGIN_SUCCESS | user=hacked";
            String maliciousDetails = "some details\nForged line 2\rForged line 3";

            logger.logEvent(new AuthenticationEvent(Instant.now(),
                    AuthenticationEventType.LOGIN_FAILURE_INVALID_INPUT,
                    false,
                    maliciousUsername,
                    "192.168.1.1",
                    "",
                    maliciousDetails));
        }

        List<String> lines = Files.readAllLines(logFile);
        // CRITICAL CHECK: Exactly ONE line must exist in the file, proving no log injection / line forging occurred
        assertEquals(1, lines.size(), "CRLF characters must not create additional log lines!");
        assertFalse(lines.get(0).contains("\n"));
        assertFalse(lines.get(0).contains("\r"));
    }

    @Test
    @DisplayName("Should retain recent events in memory bounded by limit")
    void testEventRetention(@TempDir Path tempDir) throws IOException {
        Path logFile = tempDir.resolve("retention_test.log");

        try (SecureFileEventLogger logger = new SecureFileEventLogger(logFile, 5)) {
            for (int i = 1; i <= 10; i++) {
                logger.logEvent(new AuthenticationEvent(Instant.now(),
                        AuthenticationEventType.LOGIN_FAILURE_INVALID_CREDENTIALS,
                        false, "user" + i, "10.0.0." + i, "", "Attempt " + i));
            }

            // In-memory buffer bounded to 5
            List<AuthenticationEvent> recent = logger.getRecentEvents(10);
            assertEquals(5, recent.size());
            assertEquals("user6", recent.get(0).getUsername());
            assertEquals("user10", recent.get(4).getUsername());
        }
    }

    @Test
    @DisplayName("Symlink Defense: Log file pointing to symbolic link must be rejected (CWE-59)")
    void testRejectsSymbolicLink(@TempDir Path tempDir) throws IOException {
        Path targetFile = tempDir.resolve("target_file.log");
        Files.createFile(targetFile);
        Path symlink = tempDir.resolve("symlink.log");

        try {
            Files.createSymbolicLink(symlink, targetFile);
            assertThrows(SecurityException.class, () -> new SecureFileEventLogger(symlink));
        } catch (UnsupportedOperationException ignored) {
            // OS may restrict symlink creation
        }
    }

    @Test
    @DisplayName("Storage Bounds: Log writes must be bounded when maximum file size is reached (Rule 5)")
    void testBoundedLogFileSize(@TempDir Path tempDir) throws IOException {
        Path logFile = tempDir.resolve("bounded.log");
        long maxSizeBytes = 200; // Very small limit for testing

        try (SecureFileEventLogger logger = new SecureFileEventLogger(logFile, 10, maxSizeBytes)) {
            // First event: fits within limit
            logger.logEvent(new AuthenticationEvent(Instant.now(),
                    AuthenticationEventType.LOGIN_SUCCESS, true, "u1", "127.0.0.1", "", "msg1"));

            long sizeAfterFirst = Files.size(logFile);
            assertTrue(sizeAfterFirst > 0);

            // Attempting to write more events after limit exceeded should not grow file indefinitely
            for (int i = 0; i < 10; i++) {
                logger.logEvent(new AuthenticationEvent(Instant.now(),
                        AuthenticationEventType.LOGIN_SUCCESS, true, "u2", "127.0.0.1", "", "long message to exceed size bound"));
            }

            long finalSize = Files.size(logFile);
            assertTrue(finalSize <= maxSizeBytes + 200, "Log file size must remain bounded");
        }
    }
}
