package com.security.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests enforcing filesystem trust boundaries, private file permissions,
 * and secure KeyStore loading from files (Rules 1, 2, 5, 8).
 */
public class FileSecurityTest {

    private static final boolean IS_POSIX =
            FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    @Test
    @DisplayName("Create private file sets owner-only permissions (0600 on POSIX)")
    public void testCreatePrivateFile(@TempDir Path tempDir) throws Exception {
        Path target = tempDir.resolve("private_secret.dat");
        Path created = FileSecurityUtil.createPrivateFile(target);

        assertTrue(Files.exists(created));
        if (IS_POSIX) {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(created);
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms);
        }

        // Validate succeeds on private file
        Path validated = FileSecurityUtil.validatePrivateFile(created);
        assertNotNull(validated);
    }

    @Test
    @DisplayName("Reject file accessible to group or other users")
    public void testRejectOverlyPermissiveFile(@TempDir Path tempDir) throws Exception {
        if (!IS_POSIX) {
            return; // Skip on non-POSIX systems
        }

        Path target = tempDir.resolve("insecure_secret.dat");
        Files.createFile(target);

        // Make file world-readable
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-r--r--"));

        CryptoException ex = assertThrows(CryptoException.class,
                () -> FileSecurityUtil.validatePrivateFile(target));
        assertTrue(ex.getMessage().contains("Key file permissions are too open"));
    }

    @Test
    @DisplayName("Reject non-existent file or directory path")
    public void testRejectNonExistentPath(@TempDir Path tempDir) {
        Path nonExistent = tempDir.resolve("does_not_exist.p12");
        assertThrows(CryptoException.class, () -> FileSecurityUtil.validatePrivateFile(nonExistent));

        // Directory path instead of regular file
        assertThrows(CryptoException.class, () -> FileSecurityUtil.validatePrivateFile(tempDir));
    }

    @Test
    @DisplayName("Load KeyStore from secure file and reject when file permissions are insecure")
    public void testKeyStoreFromFileSecurity(@TempDir Path tempDir) throws Exception {
        Path keystoreFile = tempDir.resolve("keystore.p12");
        FileSecurityUtil.createPrivateFile(keystoreFile);

        String alias = "prod_aes_key";
        SecretKey appKey = KeyGeneratorUtil.generateAes256Key();
        char[] password = "StrongKeystorePassword123!".toCharArray();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setEntry(alias,
                new KeyStore.SecretKeyEntry(appKey),
                new KeyStore.PasswordProtection(password));

        try (OutputStream out = Files.newOutputStream(keystoreFile)) {
            ks.store(out, password);
        }

        // 1. Should succeed with private permissions
        KeyStoreKeyProvider provider = KeyStoreKeyProvider.fromFile(keystoreFile, password.clone(), alias);
        assertNotNull(provider);
        assertEquals(alias, provider.getActiveKeyId());
        provider.close();

        // 2. Modify permissions to world-readable; must fail immediately
        if (IS_POSIX) {
            Files.setPosixFilePermissions(keystoreFile, PosixFilePermissions.fromString("rw-rw-rw-"));
            assertThrows(CryptoException.class,
                    () -> KeyStoreKeyProvider.fromFile(keystoreFile, password.clone(), alias));
        }
    }
}
