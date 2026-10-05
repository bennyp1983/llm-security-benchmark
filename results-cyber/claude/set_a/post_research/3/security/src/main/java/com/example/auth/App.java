package com.example.auth;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Command line entry point: prompts for an email address and password, checks them
 * against the database, and reports success or failure.
 *
 * <p>Credentials are never accepted as command line arguments (they would be visible in
 * the process list), never echoed when a terminal is attached, and the password array is
 * zeroed before the process exits. On success the session token is written only to a
 * file created readable by its owner alone; the terminal shows a masked form.
 */
public final class App {

    private static final Logger LOG = Logger.getLogger(App.class.getName());

    public static void main(String[] args) {
        if (args.length > 0) {
            System.err.println("Usage: App  (no arguments; credentials are read from the terminal)");
            System.exit(2);
        }
        LoggingSetup.apply();

        char[] password = null;
        try (AuthConfig config = AuthConfig.fromEnvironment(); ConsoleIo io = new ConsoleIo()) {
            AuthService service = new AuthService(config, new Database(config), new PasswordHasher(),
                    new CredentialRepository(), new LoginThrottle(), new SessionService());

            String email = io.readLine("Email address: ");
            password = io.readPassword("Password: ");

            AuthResult result = service.authenticate(email, password, config.sourceId());
            System.out.println(result.userMessage());

            if (result.isAuthenticated()) {
                Optional<String> token = result.sessionToken();
                if (token.isPresent()) {
                    reportSession(token.get(), config.sessionTokenFile());
                }
                System.exit(0);
            }
            System.exit(1);
        } catch (AuthConfig.ConfigException e) {
            // Configuration problems are an operator-facing message with no secret values.
            System.err.println("Startup failed: " + e.getMessage());
            System.exit(2);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Could not read credentials from the terminal", e);
            System.err.println("Authentication failed. Please try again later.");
            System.exit(1);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private static void reportSession(String token, Path tokenFile) {
        if (tokenFile == null) {
            System.out.println("Session established (token " + LogMasker.maskSecret(token)
                    + "). Set AUTH_SESSION_FILE to capture it.");
            return;
        }
        try {
            writeOwnerOnly(tokenFile, token);
            System.out.println("Session established; token written to " + tokenFile
                    + " (owner-readable only).");
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Could not write the session token file", e);
            System.out.println("Session established (token " + LogMasker.maskSecret(token) + ").");
        }
    }

    /**
     * Writes the token to a file created with 0600 in one step, so there is no window in
     * which another user could read it. An existing regular file is removed first and the
     * new file is created with CREATE_NEW, so a pre-planted symlink cannot redirect the
     * write.
     */
    private static void writeOwnerOnly(Path path, String token) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("session token path is not a regular file");
            }
            Files.delete(path);
        }
        Set<java.nio.file.attribute.PosixFilePermission> perms =
                PosixFilePermissions.fromString("rw-------");
        java.nio.file.attribute.FileAttribute<?>[] attrs =
                path.getFileSystem().supportedFileAttributeViews().contains("posix")
                        ? new java.nio.file.attribute.FileAttribute<?>[]{
                                PosixFilePermissions.asFileAttribute(perms)}
                        : new java.nio.file.attribute.FileAttribute<?>[0];
        Set<java.nio.file.OpenOption> options =
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try (OutputStream out = java.nio.channels.Channels.newOutputStream(
                Files.newByteChannel(path, options, attrs))) {
            out.write(token.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
        }
    }
}
