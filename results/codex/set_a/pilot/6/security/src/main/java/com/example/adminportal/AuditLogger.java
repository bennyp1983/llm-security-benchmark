package com.example.adminportal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/** Append-only JSON Lines audit log. Passwords and password hashes are never logged. */
final class AuditLogger {
    private static final Set<OpenOption> OPEN_OPTIONS = Set.of(
            StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND,
            LinkOption.NOFOLLOW_LINKS);
    private final Path path;
    private final Clock clock;

    AuditLogger(Path path) throws IOException {
        this(path, Clock.systemUTC());
    }

    AuditLogger(Path path, Clock clock) throws IOException {
        this.path = path.toAbsolutePath().normalize();
        this.clock = clock;
        Path parent = this.path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        if (Files.exists(this.path, LinkOption.NOFOLLOW_LINKS)
                && Files.isSymbolicLink(this.path)) {
            throw new IOException("Audit log must not be a symbolic link");
        }
        createWithRestrictedPermissionsIfMissing();
    }

    synchronized void record(String username, boolean success, String reason) throws IOException {
        String event = success ? "AUTHENTICATION_SUCCESS" : "AUTHENTICATION_FAILURE";
        String line = "{\"timestamp\":\"" + Instant.now(clock) + "\","
                + "\"eventId\":\"" + UUID.randomUUID() + "\","
                + "\"event\":\"" + event + "\","
                + "\"username\":\"" + jsonEscape(username) + "\","
                + "\"reason\":\"" + jsonEscape(reason) + "\"}\n";
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);

        try (FileChannel channel = FileChannel.open(path, OPEN_OPTIONS);
             FileLock lock = channel.lock()) {
            if (!lock.isValid()) {
                throw new IOException("Could not lock audit log");
            }
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        restrictPermissionsIfSupported();
    }

    private void restrictPermissionsIfSupported() throws IOException {
        try {
            Files.setPosixFilePermissions(path,
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) {
            // ACLs are platform-specific. The host administrator must restrict the file on non-POSIX systems.
        }
    }

    private void createWithRestrictedPermissionsIfMissing() throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
        } catch (UnsupportedOperationException e) {
            try {
                Files.createFile(path);
            } catch (FileAlreadyExistsException ignored) {
                // Another process created it; the no-follow open below still validates the target.
            }
        } catch (FileAlreadyExistsException ignored) {
            // Another process created it; the no-follow open below still validates the target.
        }
        if (Files.isSymbolicLink(path)) {
            throw new IOException("Audit log must not be a symbolic link");
        }
    }

    private static String jsonEscape(String value) {
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) c));
                    } else {
                        escaped.append(c);
                    }
                }
            }
        }
        return escaped.toString();
    }
}
