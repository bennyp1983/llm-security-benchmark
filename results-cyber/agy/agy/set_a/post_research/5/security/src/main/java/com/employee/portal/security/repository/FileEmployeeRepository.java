package com.employee.portal.security.repository;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.model.EmployeeRecord;
import com.employee.portal.security.model.UserStatus;
import com.employee.portal.security.validation.InputValidator;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * File-backed repository for employee credentials.
 * Implements Rule 1 (strict schema validation of stored records),
 * Rule 2 & 5 (files created private to owner 0600, atomic replacement),
 * and Rule 7 (thread-safe concurrency control).
 */
public final class FileEmployeeRepository implements EmployeeRepository {

    private final Path dbFile;
    private final Map<String, EmployeeRecord> cache;
    private final ReentrantReadWriteLock rwLock;
    private final HexFormat hexFormat;

    public FileEmployeeRepository(SecurityConfig config) {
        this(config.getEmployeeDbPath());
    }

    public FileEmployeeRepository(Path dbFile) {
        this.dbFile = Objects.requireNonNull(dbFile).normalize().toAbsolutePath();
        this.cache = new HashMap<>();
        this.rwLock = new ReentrantReadWriteLock();
        this.hexFormat = HexFormat.of();
        ensureSecureFileExists();
        loadRecords();
    }

    private void ensureSecureFileExists() {
        try {
            Path parent = dbFile.getParent();
            if (parent != null && !Files.exists(parent)) {
                try {
                    Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                    FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(dirPerms);
                    Files.createDirectories(parent, attr);
                } catch (UnsupportedOperationException e) {
                    Files.createDirectories(parent);
                }
            }

            if (!Files.exists(dbFile)) {
                try {
                    Set<PosixFilePermission> filePerms = PosixFilePermissions.fromString("rw-------");
                    FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(filePerms);
                    Files.createFile(dbFile, attr);
                } catch (UnsupportedOperationException e) {
                    Files.createFile(dbFile);
                    dbFile.toFile().setReadable(false, false);
                    dbFile.toFile().setReadable(true, true);
                    dbFile.toFile().setWritable(false, false);
                    dbFile.toFile().setWritable(true, true);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize secure storage at " + dbFile, e);
        }
    }

    private void loadRecords() {
        rwLock.writeLock().lock();
        try {
            cache.clear();
            if (!Files.exists(dbFile)) {
                return;
            }
            try (BufferedReader reader = Files.newBufferedReader(dbFile, StandardCharsets.UTF_8)) {
                String line;
                int lineNum = 0;
                while ((line = reader.readLine()) != null) {
                    lineNum++;
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    String[] parts = line.split(":", -1);
                    if (parts.length < 6) {
                        // Malformed record ignored
                        continue;
                    }

                    String username = parts[0].trim();
                    String saltHex = parts[1].trim();
                    String hashHex = parts[2].trim();
                    String iterStr = parts[3].trim();
                    String statusStr = parts[4].trim();
                    String role = parts[5].trim();

                    if (!InputValidator.isValidUsername(username)) {
                        continue;
                    }

                    try {
                        byte[] salt = hexFormat.parseHex(saltHex);
                        byte[] hash = hexFormat.parseHex(hashHex);
                        int iterations = Integer.parseInt(iterStr);
                        UserStatus status = UserStatus.valueOf(statusStr.toUpperCase());

                        EmployeeRecord record = new EmployeeRecord(username, salt, hash, iterations, status, role);
                        cache.put(username.toLowerCase(), record);
                    } catch (Exception e) {
                        // Skip corrupted record to fail safe
                    }
                }
            } catch (IOException e) {
                // If database read fails, fail closed
            }
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    @Override
    public Optional<EmployeeRecord> findByUsername(String username) {
        if (!InputValidator.isValidUsername(username)) {
            return Optional.empty();
        }
        rwLock.readLock().lock();
        try {
            return Optional.ofNullable(cache.get(username.toLowerCase()));
        } finally {
            rwLock.readLock().unlock();
        }
    }

    @Override
    public boolean exists(String username) {
        if (!InputValidator.isValidUsername(username)) {
            return false;
        }
        rwLock.readLock().lock();
        try {
            return cache.containsKey(username.toLowerCase());
        } finally {
            rwLock.readLock().unlock();
        }
    }

    @Override
    public boolean save(EmployeeRecord record) {
        Objects.requireNonNull(record, "record cannot be null");
        rwLock.writeLock().lock();
        try {
            cache.put(record.getUsername().toLowerCase(), record);
            return persistToDisk();
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    @Override
    public int count() {
        rwLock.readLock().lock();
        try {
            return cache.size();
        } finally {
            rwLock.readLock().unlock();
        }
    }

    @Override
    public void reload() {
        loadRecords();
    }

    /**
     * Atomically writes records to a temporary file and replaces the target file.
     * Preserves private permissions (0600) and ensures atomic state commits (Rule 7).
     */
    private boolean persistToDisk() {
        Path tempFile = null;
        try {
            Path parent = dbFile.getParent();
            try {
                Set<PosixFilePermission> filePerms = PosixFilePermissions.fromString("rw-------");
                FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(filePerms);
                tempFile = Files.createTempFile(parent, "emp_db_", ".tmp", attr);
            } catch (UnsupportedOperationException e) {
                tempFile = Files.createTempFile(parent, "emp_db_", ".tmp");
                tempFile.toFile().setReadable(false, false);
                tempFile.toFile().setReadable(true, true);
                tempFile.toFile().setWritable(false, false);
                tempFile.toFile().setWritable(true, true);
            }

            try (BufferedWriter writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
                for (EmployeeRecord rec : cache.values()) {
                    String line = String.format("%s:%s:%s:%d:%s:%s%n",
                            rec.getUsername(),
                            hexFormat.formatHex(rec.getSalt()),
                            hexFormat.formatHex(rec.getPasswordHash()),
                            rec.getIterations(),
                            rec.getStatus().name(),
                            rec.getRole());
                    writer.write(line);
                }
            }

            // Atomic move replaces target file atomically
            Files.move(tempFile, dbFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException e) {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {}
            }
            return false;
        }
    }
}
