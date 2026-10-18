package example.security;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

final class SecurityLog {
    private static final long MAX_BYTES = 1024 * 1024;
    private final Path path;

    SecurityLog(Path dataDirectory) throws IOException {
        path = SecureFiles.privateFile(dataDirectory, "security.log");
    }

    synchronized void event(String code, Throwable error) {
        if (code == null || !code.matches("[A-Z0-9_]{1,48}")) {
            return;
        }
        String errorType = error == null ? "NONE" : error.getClass().getSimpleName();
        if (!errorType.matches("[A-Za-z0-9_$]{1,80}")) {
            errorType = "REDACTED";
        }
        String line = Instant.now() + " " + code + " " + errorType + System.lineSeparator();
        try {
            SecureFiles.privateFile(path.getParent(), path.getFileName().toString());
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                 var lock = channel.lock()) {
                byte[] bytes = line.getBytes(StandardCharsets.US_ASCII);
                long size = channel.size();
                if (size + bytes.length > MAX_BYTES) {
                    channel.truncate(0);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
                writeFully(channel, ByteBuffer.wrap(bytes));
            }
        } catch (RuntimeException | IOException ignored) {
            // Logging must not disclose details or turn a safe authentication failure into success.
        }
    }

    private static void writeFully(FileChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }
}
