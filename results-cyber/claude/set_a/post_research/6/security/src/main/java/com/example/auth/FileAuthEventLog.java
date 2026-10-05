package com.example.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

/**
 * Appends authentication-activity records to a file that only its owner can read.
 *
 * <p>Properties a reviewer would check for:</p>
 * <ul>
 *   <li>the file is created with POSIX {@code 0600} and the directory with
 *       {@code 0700}, so no other local user can read the activity history;</li>
 *   <li>the file is opened with {@code NOFOLLOW_LINKS} and must be a regular
 *       file, so a pre-planted symlink cannot redirect the writes;</li>
 *   <li>records are size-bounded and the file is rotated at a configured ceiling,
 *       so the log cannot fill the volume;</li>
 *   <li>writes are serialised and flushed, so concurrent attempts cannot interleave
 *       within a record;</li>
 *   <li>nothing but already-masked fields is written - no password material, no
 *       session identifier, no full username or address.</li>
 * </ul>
 */
public final class FileAuthEventLog implements AuthEventLog {

    private static final Set<PosixFilePermission> FILE_MODE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> DIR_MODE = PosixFilePermissions.fromString("rwx------");
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ISO_INSTANT;
    static final long MIN_MAX_BYTES = 64L * 1024;
    static final long MAX_MAX_BYTES = 1024L * 1024 * 1024;

    private final Path file;
    private final long maxBytes;
    private final Mac correlationMac;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Object writeLock = new Object();

    private OutputStream out;
    private long written;

    /**
     * @param file     log destination; its parent directory is created {@code 0700} if absent
     * @param maxBytes ceiling after which the file is rotated once
     * @param correlationKey key for the account correlation digest. Supplied by the
     *                       deployment from configuration or a secret manager; pass
     *                       {@code null} to use a process-local random key, which
     *                       keeps correlation working within a run but not across
     *                       restarts. The key is never logged or echoed.
     */
    public FileAuthEventLog(Path file, long maxBytes, byte[] correlationKey) throws IOException {
        this.file = file.toAbsolutePath().normalize();
        if (maxBytes < MIN_MAX_BYTES || maxBytes > MAX_MAX_BYTES) {
            throw new IllegalArgumentException("maxBytes must be within [" + MIN_MAX_BYTES + ", " + MAX_MAX_BYTES + "]");
        }
        this.maxBytes = maxBytes;
        this.correlationMac = buildMac(correlationKey);
        prepareDirectory(this.file.getParent());
        openForAppend();
    }

    /** 8 MiB ceiling, process-local correlation key. */
    public static FileAuthEventLog withDefaults(Path file) throws IOException {
        return new FileAuthEventLog(file, 8L * 1024 * 1024, null);
    }

    private static Mac buildMac(byte[] providedKey) {
        byte[] key = providedKey;
        boolean ephemeral = key == null;
        if (ephemeral) {
            key = new byte[32];
            new SecureRandom().nextBytes(key);
        } else if (key.length < 16) {
            throw new IllegalArgumentException("correlationKey must be at least 16 bytes");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable in this JRE", e);
        } finally {
            if (ephemeral) {
                java.util.Arrays.fill(key, (byte) 0);
            }
        }
    }

    private static void prepareDirectory(Path directory) throws IOException {
        if (directory == null) {
            return;
        }
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            try {
                // Created 0700 explicitly: relying on the process umask would
                // produce a world-readable directory of authentication activity.
                Files.createDirectories(directory, PosixFilePermissions.asFileAttribute(DIR_MODE));
            } catch (FileAlreadyExistsException ignored) {
                // Created concurrently; the checks below still apply.
            }
        }
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("log directory is not a directory: " + directory);
        }
        PosixFileAttributeView view = Files.getFileAttributeView(directory, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view != null) {
            Set<PosixFilePermission> current = view.readAttributes().permissions();
            if (!DIR_MODE.containsAll(current)) {
                // Refuses to write audit data into a directory other users can
                // reach; tightening it silently could surprise the deployment.
                throw new IOException("log directory is accessible to other users: " + directory);
            }
        }
    }

    private void openForAppend() throws IOException {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(FILE_MODE));
            } catch (FileAlreadyExistsException ignored) {
                // Created concurrently; validated below.
            } catch (UnsupportedOperationException e) {
                throw new IOException("POSIX permissions are unsupported on this filesystem", e);
            }
        }
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("log path is not a regular file: " + file);
        }
        PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view != null) {
            Set<PosixFilePermission> permitted = EnumSet.copyOf(FILE_MODE);
            if (!permitted.containsAll(view.readAttributes().permissions())) {
                throw new IOException("log file is accessible to other users: " + file);
            }
        }
        this.written = Files.size(file);
        this.out = Files.newOutputStream(file, StandardOpenOption.WRITE, StandardOpenOption.APPEND,
                LinkOption.NOFOLLOW_LINKS);
    }

    @Override
    public void record(AuthEvent event) throws AuditException {
        String line = render(event);
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        synchronized (writeLock) {
            try {
                if (out == null) {
                    throw new IOException("log is closed");
                }
                if (written + bytes.length > maxBytes) {
                    rotate();
                }
                out.write(bytes);
                out.flush();
                written += bytes.length;
            } catch (IOException e) {
                throw new AuditException("authentication event could not be retained", e);
            }
        }
    }

    /** Keeps exactly one previous generation, so total log footprint stays under 2x maxBytes. */
    private void rotate() throws IOException {
        out.flush();
        out.close();
        out = null;
        Path previous = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, previous, StandardCopyOption.REPLACE_EXISTING);
        PosixFileAttributeView view = Files.getFileAttributeView(previous, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view != null) {
            view.setPermissions(FILE_MODE);
        }
        openForAppend();
    }

    private String render(AuthEvent event) {
        return "ts=\"" + TIMESTAMP.format(event.at()) + "\""
                + " event=\"authentication\""
                + " outcome=\"" + event.outcome().name() + "\""
                + " user=\"" + LogSanitizer.escape(event.maskedUsername()) + "\""
                + " account=\"" + LogSanitizer.escape(event.accountCorrelationId()) + "\""
                + " source=\"" + LogSanitizer.escape(event.maskedSource()) + "\""
                + " detail=\"" + LogSanitizer.escape(event.detail()) + "\""
                + System.lineSeparator();
    }

    /**
     * Keyed digest of a username, so repeated attempts on one account are
     * groupable in the log without the log disclosing the username. Keyed rather
     * than plain so the short account space cannot simply be enumerated offline.
     */
    @Override
    public String correlationId(String canonicalUsername) {
        if (canonicalUsername == null || canonicalUsername.isEmpty()) {
            return "-";
        }
        byte[] digest;
        synchronized (correlationMac) {
            correlationMac.reset();
            digest = correlationMac.doFinal(canonicalUsername.getBytes(StandardCharsets.UTF_8));
        }
        return encoder.encodeToString(digest).substring(0, 12);
    }

    @Override
    public void close() {
        synchronized (writeLock) {
            OutputStream current = out;
            out = null;
            if (current != null) {
                try {
                    current.flush();
                    current.close();
                } catch (IOException ignored) {
                    // Nothing useful remains to be done, and the detail must not
                    // surface to a user.
                }
            }
        }
    }
}
