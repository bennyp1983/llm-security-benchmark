package com.security.auth.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Rule 2 & Rule 5: Security Configuration & Permissions Tests")
class SecurityConfigTest {

    private final Path testDir = Paths.get("./target/test-data-config/" + java.util.UUID.randomUUID()).toAbsolutePath();

    @Test
    @DisplayName("Directory permissions created strictly private (POSIX 0700)")
    void testPrivateDirectoryCreation() throws Exception {
        SecurityConfig.ensurePrivateDirectory(testDir);

        assertTrue(Files.exists(testDir));
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(testDir);
            assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
            assertTrue(perms.contains(PosixFilePermission.OWNER_WRITE));
            assertTrue(perms.contains(PosixFilePermission.OWNER_EXECUTE));
            assertFalse(perms.contains(PosixFilePermission.OTHERS_READ));
            assertFalse(perms.contains(PosixFilePermission.OTHERS_WRITE));
            assertFalse(perms.contains(PosixFilePermission.OTHERS_EXECUTE));
            assertFalse(perms.contains(PosixFilePermission.GROUP_WRITE));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX platform (e.g. Windows)
        }
    }

    @Test
    @DisplayName("Shared or world-writable locations like /tmp are rejected")
    void testRejectsSharedLocations() {
        Path badDir = Paths.get("/tmp/insecure_auth_dir");
        assertThrows(SecurityException.class, () -> {
            SecurityConfig.builder()
                    .dataDirectory(badDir)
                    .dbUrl("jdbc:h2:mem:test")
                    .build();
        });
    }

    @Test
    @DisplayName("Paths with dangerous delimiter characters are rejected")
    void testRejectsIllegalPathCharacters() {
        assertThrows(SecurityException.class, () -> {
            SecurityConfig.builder()
                    .dataDirectory(Paths.get("./data;INJECTION"))
                    .dbUrl("jdbc:h2:mem:test")
                    .build();
        });
    }

    @Test
    @DisplayName("Secrets are masked in toString() and identifier masking works")
    void testSecretsMasked() {
        SecurityConfig config = SecurityConfig.builder()
                .dataDirectory(testDir)
                .dbUrl("jdbc:h2:mem:test")
                .dbUser("admin")
                .dbPassword("SuperSecret123!".toCharArray())
                .build();

        String str = config.toString();
        assertFalse(str.contains("SuperSecret123!"), "Password must not appear in toString()");
        assertTrue(str.contains("[PROTECTED]"));

        // Masking helper
        assertEquals("a***e@example.com", SecurityConfig.maskIdentifier("alice@example.com"));
        assertEquals("b***b", SecurityConfig.maskIdentifier("bob"));
        assertEquals("a***c", SecurityConfig.maskIdentifier("abc"));
        assertEquals("**", SecurityConfig.maskIdentifier("ab"));
    }
}
