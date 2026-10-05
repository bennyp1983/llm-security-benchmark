package com.acme.portal;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

final class CredentialStore {
    static final String HEADER = "EMPLOYEE_AUTH_STORE_V1";
    static final int MAX_USERS = 10_000;
    static final long MAX_FILE_BYTES = 2_000_000;
    static final Pattern USERNAME = Pattern.compile("[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?");
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> UNSAFE_DIRECTORY_PERMISSIONS = EnumSet.of(
            PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE);

    record Record(byte[] salt, byte[] passwordHash) {
        Record {
            salt = salt.clone();
            passwordHash = passwordHash.clone();
        }

        @Override public byte[] salt() { return salt.clone(); }
        @Override public byte[] passwordHash() { return passwordHash.clone(); }
    }

    private final Map<String, Record> records;

    private CredentialStore(Map<String, Record> records) {
        this.records = Collections.unmodifiableMap(records);
    }

    Record find(String canonicalUsername) {
        return records.get(canonicalUsername);
    }

    Map<String, Record> copyRecords() {
        return new HashMap<>(records);
    }

    static UpdateLock lockForUpdate(Path storePath) throws IOException {
        validateParent(storePath);
        Path lockPath = storePath.resolveSibling(storePath.getFileName() + ".lock");
        try {
            Files.createFile(lockPath, PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS));
        } catch (java.nio.file.FileAlreadyExistsException expected) {
            // The stable lock file is intentionally retained between invocations.
        }
        if (Files.isSymbolicLink(lockPath)
                || !Files.isRegularFile(lockPath, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(lockPath, LinkOption.NOFOLLOW_LINKS)
                        .equals(FILE_PERMISSIONS)) {
            throw new IOException("credential update lock is unsafe");
        }
        FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS);
        try {
            return new UpdateLock(channel, channel.lock());
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
    }

    static final class UpdateLock implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;

        private UpdateLock(FileChannel channel, FileLock lock) {
            this.channel = channel;
            this.lock = lock;
        }

        void requireHeld() throws IOException {
            if (!lock.isValid()) {
                throw new IOException("credential update lock was lost");
            }
        }

        @Override public void close() throws IOException {
            try {
                lock.release();
            } finally {
                channel.close();
            }
        }
    }

    static CredentialStore load(Path path) throws IOException {
        validateParent(path);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(path)) {
            throw new IOException("credential store is not a regular, non-symbolic file");
        }
        if (!Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(FILE_PERMISSIONS)) {
            throw new IOException("credential store permissions must be 0600");
        }
        long size = Files.size(path);
        if (size <= 0 || size > MAX_FILE_BYTES) {
            throw new IOException("credential store size is invalid");
        }

        Map<String, Record> parsed = new HashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII)) {
            if (!HEADER.equals(reader.readLine())) {
                throw new IOException("credential store header is invalid");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                if (parsed.size() >= MAX_USERS || line.length() > 256 || line.isBlank()) {
                    throw new IOException("credential store record bounds are invalid");
                }
                String[] fields = line.split(":", -1);
                if (fields.length != 3 || !USERNAME.matcher(fields[0]).matches()) {
                    throw new IOException("credential store record is invalid");
                }
                byte[] salt;
                byte[] hash;
                try {
                    salt = Base64.getDecoder().decode(fields[1]);
                    hash = Base64.getDecoder().decode(fields[2]);
                } catch (IllegalArgumentException e) {
                    throw new IOException("credential store encoding is invalid", e);
                }
                if (salt.length != PasswordHasher.SALT_BYTES
                        || hash.length != PasswordHasher.HASH_BYTES
                        || parsed.putIfAbsent(fields[0], new Record(salt, hash)) != null) {
                    throw new IOException("credential store record is invalid");
                }
            }
        }
        if (parsed.isEmpty()) {
            throw new IOException("credential store contains no employees");
        }
        return new CredentialStore(parsed);
    }

    static void write(Path path, Map<String, Record> records) throws IOException {
        validateParent(path);
        if (records.isEmpty() || records.size() > MAX_USERS) {
            throw new IOException("credential record count is invalid");
        }
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(path)
                    || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
                            .equals(FILE_PERMISSIONS)) {
                throw new IOException("existing credential store is unsafe");
            }
        }

        Path temp = Files.createTempFile(path.getParent(), ".credentials-", ".tmp",
                PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS));
        boolean moved = false;
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(temp, StandardCharsets.US_ASCII,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write(HEADER);
                writer.newLine();
                List<Map.Entry<String, Record>> ordered = new ArrayList<>(records.entrySet());
                ordered.sort(Comparator.comparing(Map.Entry::getKey));
                for (Map.Entry<String, Record> entry : ordered) {
                    if (!USERNAME.matcher(entry.getKey()).matches()) {
                        throw new IOException("invalid username in credential records");
                    }
                    writer.write(entry.getKey());
                    writer.write(':');
                    writer.write(Base64.getEncoder().encodeToString(entry.getValue().salt()));
                    writer.write(':');
                    writer.write(Base64.getEncoder().encodeToString(entry.getValue().passwordHash()));
                    writer.newLine();
                }
            }
            if (Files.size(temp) > MAX_FILE_BYTES) {
                throw new IOException("credential store would exceed maximum size");
            }
            Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            moved = true;
        } finally {
            if (!moved) {
                Files.deleteIfExists(temp);
            }
        }
    }

    private static void validateParent(Path path) throws IOException {
        if (!path.isAbsolute() || !path.equals(path.normalize()) || path.getParent() == null) {
            throw new IOException("credential store path is invalid");
        }
        Path parent = path.getParent();
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(parent)) {
            throw new IOException("credential store directory is unsafe");
        }
        Set<PosixFilePermission> permissions =
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS);
        if (!Collections.disjoint(permissions, UNSAFE_DIRECTORY_PERMISSIONS)) {
            throw new IOException("credential store directory is writable by other users");
        }
    }
}
