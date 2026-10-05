package example.security.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class PrivateRollingFileAuditSinkTest {
    @TempDir Path directory;

    @Test void writesOnlyBoundedPseudonymousDataToOwnerPrivateFile() throws Exception {
        Files.setPosixFilePermissions(directory, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        var sink = new PrivateRollingFileAuditSink(directory, 65_536, 2);
        String digest = "a".repeat(64);
        sink.append(new AuthenticationEvent(UUID.fromString("01234567-89ab-4def-8123-456789abcdef"),
                Instant.parse("2026-10-01T12:00:00Z"), AuthenticationEvent.Outcome.FAILURE,
                AuthenticationEvent.Reason.REJECTED, digest, digest, null));

        Path log = directory.resolve("authentication-events.log");
        assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(log));
        String content = Files.readString(log);
        assertTrue(content.contains("event=authentication outcome=FAILURE reason=REJECTED"));
        assertFalse(content.contains("password"));
        assertTrue(Files.size(log) < 1024);
    }
}
