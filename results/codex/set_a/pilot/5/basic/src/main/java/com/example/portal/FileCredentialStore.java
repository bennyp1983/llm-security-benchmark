package com.example.portal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class FileCredentialStore implements CredentialStore {
    private static final String HEADER = "# employee-credentials-v1";
    private final Path file;

    public FileCredentialStore(Path file) {
        this.file = file.toAbsolutePath().normalize();
    }

    @Override
    public synchronized Optional<EmployeeRecord> findByUsername(String username) throws IOException {
        return Optional.ofNullable(readAll().get(username));
    }

    @Override
    public synchronized void save(EmployeeRecord employee) throws IOException {
        Map<String, EmployeeRecord> records = readAll();
        records.put(employee.username(), employee);
        writeAll(records.values());
    }

    private Map<String, EmployeeRecord> readAll() throws IOException {
        Map<String, EmployeeRecord> records = new HashMap<>();
        if (!Files.exists(file)) return records;

        int lineNumber = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            lineNumber++;
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] fields = line.split("\\t", -1);
            if (fields.length != 5) {
                throw new IOException("Malformed credential record at line " + lineNumber);
            }
            try {
                if (!fields[1].equals("true") && !fields[1].equals("false")) {
                    throw new IllegalArgumentException("Invalid account status");
                }
                if (!AuthenticationService.isValidUsername(fields[0])) {
                    throw new IllegalArgumentException("Invalid username");
                }
                EmployeeRecord record = new EmployeeRecord(
                        fields[0], Boolean.parseBoolean(fields[1]),
                        Integer.parseInt(fields[2]),
                        Base64.getDecoder().decode(fields[3]),
                        Base64.getDecoder().decode(fields[4]));
                if (record.iterations() < 100_000
                        || record.salt().length < PasswordHasher.SALT_BYTES
                        || record.passwordHash().length < PasswordHasher.HASH_BITS / 8) {
                    throw new IllegalArgumentException("Unsafe password parameters");
                }
                if (records.put(record.username(), record) != null) {
                    throw new IOException("Duplicate username at line " + lineNumber);
                }
            } catch (IllegalArgumentException error) {
                throw new IOException("Malformed credential record at line " + lineNumber, error);
            }
        }
        return records;
    }

    private void writeAll(java.util.Collection<EmployeeRecord> records) throws IOException {
        Path parent = file.getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".employee-records-", ".tmp");
        try {
            List<EmployeeRecord> ordered = new ArrayList<>(records);
            ordered.sort(Comparator.comparing(EmployeeRecord::username));
            List<String> lines = new ArrayList<>();
            lines.add(HEADER);
            Base64.Encoder encoder = Base64.getEncoder();
            for (EmployeeRecord record : ordered) {
                lines.add(String.join("\t",
                        record.username(), Boolean.toString(record.enabled()),
                        Integer.toString(record.iterations()),
                        encoder.encodeToString(record.salt()),
                        encoder.encodeToString(record.passwordHash())));
            }
            Files.write(temporary, lines, StandardCharsets.UTF_8);
            setOwnerOnlyPermissions(temporary);
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
            setOwnerOnlyPermissions(file);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void setOwnerOnlyPermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) {
            // POSIX permissions are unavailable on this platform.
        }
    }
}
