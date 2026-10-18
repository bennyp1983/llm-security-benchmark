package com.employee.portal.security;

import com.employee.portal.security.crypto.PasswordHasher;
import com.employee.portal.security.model.EmployeeRecord;
import com.employee.portal.security.model.UserStatus;
import com.employee.portal.security.repository.FileEmployeeRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Rule 1, 2 & 5: File Storage, Schema Validation, and Private Permissions Tests")
class FileEmployeeRepositoryTest {

    @TempDir
    Path tempDir;

    private Path dbFile;
    private FileEmployeeRepository repository;
    private PasswordHasher hasher;

    @BeforeEach
    void setUp() {
        dbFile = tempDir.resolve("employees.db");
        repository = new FileEmployeeRepository(dbFile);
        hasher = new PasswordHasher(100000, 32, 256);
    }

    @Test
    void testFilePermissionsAreOwnerOnly() throws IOException {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dbFile);
            assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
            assertTrue(perms.contains(PosixFilePermission.OWNER_WRITE));
            assertFalse(perms.contains(PosixFilePermission.GROUP_READ), "Group read must be denied");
            assertFalse(perms.contains(PosixFilePermission.OTHERS_READ), "Others read must be denied");
            assertFalse(perms.contains(PosixFilePermission.OTHERS_WRITE), "Others write must be denied");
        } catch (UnsupportedOperationException ignored) {
            // Not a POSIX filesystem
        }
    }

    @Test
    void testSaveAndFindRecord() {
        char[] password = "InitialPassword#2026".toCharArray();
        byte[] salt = hasher.generateSalt();
        byte[] hash = hasher.hashPassword(password, salt);

        EmployeeRecord record = new EmployeeRecord("alice", salt, hash, 100000, UserStatus.ACTIVE, "ADMIN");
        boolean saved = repository.save(record);
        assertTrue(saved);

        Optional<EmployeeRecord> found = repository.findByUsername("alice");
        assertTrue(found.isPresent());
        assertEquals("alice", found.get().getUsername());
        assertEquals(UserStatus.ACTIVE, found.get().getStatus());
        assertEquals("ADMIN", found.get().getRole());
        assertArrayEquals(salt, found.get().getSalt());
        assertArrayEquals(hash, found.get().getPasswordHash());
    }

    @Test
    void testDefensiveCopyingPreservesIntegrity() {
        byte[] salt = hasher.generateSalt();
        byte[] hash = hasher.hashPassword("SafePassword#2026".toCharArray(), salt);
        EmployeeRecord record = new EmployeeRecord("bob", salt, hash, 100000, UserStatus.ACTIVE, "EMPLOYEE");
        repository.save(record);

        // Mutate array returned from getter
        byte[] extractedSalt = record.getSalt();
        extractedSalt[0] ^= (byte) 0xFF;

        // Verify stored salt was not corrupted
        assertFalse(java.util.Arrays.equals(extractedSalt, record.getSalt()));
    }

    @Test
    void testCorruptedLinesIgnoredSafely() throws IOException {
        // Append malformed lines directly to file
        String corruptedContent =
                "valid.user:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:100000:ACTIVE:EMPLOYEE\n" +
                "corrupted_line_with_missing_fields\n" +
                "evil/user:00:00:100:ACTIVE:ADMIN\n" + // invalid username & short hash
                "bad_hex:NOT_HEX:NOT_HEX:100000:ACTIVE:EMPLOYEE\n";

        Files.writeString(dbFile, corruptedContent);
        repository.reload();

        // Valid record loaded
        assertTrue(repository.exists("valid.user"));
        // Invalid lines skipped safely
        assertFalse(repository.exists("corrupted_line_with_missing_fields"));
        assertFalse(repository.exists("evil/user"));
        assertFalse(repository.exists("bad_hex"));
    }
}
