package com.example.accounts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Configures the single application logger.
 *
 * <p>Rule 5 (sensitive data): the log file is created before the handler opens it so its mode can
 * be set to {@code 0600} -- the audit trail of who logged in from where is not readable by other
 * local users. Rule 6 (failure behaviour): stack traces and the specific reason a login failed go
 * here and only here; the user-facing channel gets a generic sentence.
 */
public final class Logging {

    private static final String LOGGER_NAME = "com.example.accounts";
    private static boolean configured;

    private Logging() {
    }

    public static synchronized Logger configure(Config config) {
        Logger logger = Logger.getLogger(LOGGER_NAME);
        if (configured) {
            return logger;
        }
        logger.setUseParentHandlers(false);
        for (Handler existing : logger.getHandlers()) {
            logger.removeHandler(existing);
        }
        logger.setLevel(Level.INFO);

        Handler handler = null;
        if (config.logToFile()) {
            try {
                handler = openPrivateFileHandler(config.logFile());
            } catch (IOException e) {
                // Fail loudly about the *log* but keep the service usable: fall through to stderr.
                System.err.println("warning: cannot open log file; logging to stderr");
            }
        }
        if (handler == null) {
            handler = new ConsoleHandler();
        }
        handler.setLevel(Level.INFO);
        handler.setFormatter(new PlainFormatter());
        logger.addHandler(handler);
        configured = true;
        return logger;
    }

    private static FileHandler openPrivateFileHandler(Path logFile) throws IOException {
        if (!Files.exists(logFile)) {
            if (logFile.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(logFile,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } else {
                Files.createFile(logFile);
            }
        } else if (Files.isSymbolicLink(logFile)) {
            throw new IOException("log path is a symbolic link");
        } else if (logFile.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(logFile, PosixFilePermissions.fromString("rw-------"));
        }
        // One bounded file (1 MiB, wraps in place). A count above 1 would make FileHandler create
        // its own "accounts.log.N" files under the process umask -- i.e. world-readable -- which
        // would defeat the permissions set just above.
        return new FileHandler(logFile.toString(), 1024 * 1024, 1, true);
    }

    public static Logger logger() {
        return Logger.getLogger(LOGGER_NAME);
    }

    private static final class PlainFormatter extends Formatter {
        private static final DateTimeFormatter TS =
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

        @Override
        public String format(LogRecord record) {
            StringBuilder sb = new StringBuilder(160);
            sb.append(TS.format(Instant.ofEpochMilli(record.getMillis())))
                    .append(' ').append(record.getLevel().getName())
                    .append(' ').append(oneLine(formatMessage(record)))
                    .append(System.lineSeparator());
            Throwable t = record.getThrown();
            if (t != null) {
                sb.append("    caused by: ").append(oneLine(String.valueOf(t)))
                        .append(System.lineSeparator());
            }
            return sb.toString();
        }

        /** Keeps one event on one line so injected newlines cannot forge log entries. */
        private static String oneLine(String s) {
            return s.replaceAll("[\\r\\n\\u0085\\u2028\\u2029]", "\\\\n");
        }
    }
}
