package com.acme.portal;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class Main {
    static final Path STORE_PATH = Path.of("/var/lib/internal-employee-portal/credentials.v1");
    private static final Logger LOG = Logger.getLogger(Main.class.getName());

    private Main() {}

    public static void main(String[] args) {
        int status = run(args, System.console());
        if (status != 0) {
            System.exit(status);
        }
    }

    static int run(String[] args, Console console) {
        if (args.length != 1 || console == null) {
            System.err.println("Unable to process the request securely.");
            return 2;
        }
        try {
            return switch (args[0]) {
                case "login" -> login(console);
                case "provision" -> provision(console);
                default -> {
                    System.err.println("Unable to process the request securely.");
                    yield 2;
                }
            };
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.log(Level.WARNING, "Authentication operation interrupted");
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // No paths, usernames, credentials, or exception text are emitted.
            LOG.log(Level.SEVERE, "Authentication operation failed internally");
        }
        System.err.println("Unable to process the request securely.");
        return 2;
    }

    private static int login(Console console)
            throws IOException, GeneralSecurityException, InterruptedException {
        // Validate at startup, then reload under the stable lock for every decision so
        // credential changes cannot race a grant or remain stale in memory.
        CredentialStore.load(STORE_PATH);
        Authenticator authenticator = new Authenticator();
        // This is a long-lived verifier. Failed attempts must not restart the process and
        // thereby reset its source/account throttles.
        while (true) {
            String username = console.readLine("Username: ");
            if (username == null) {
                return 1;
            }
            char[] password = console.readPassword("Password: ");
            if (password == null) {
                password = new char[0];
            }
            boolean allowed;
            try {
                try (CredentialStore.UpdateLock updateLock =
                        CredentialStore.lockForUpdate(STORE_PATH)) {
                    updateLock.requireHeld();
                    allowed = authenticator.authenticate(
                            CredentialStore.load(STORE_PATH), username, password);
                }
            } finally {
                Arrays.fill(password, '\0');
            }
            // All authentication failures, including throttling, have one response.
            System.out.println(allowed ? "Access granted." : "Access denied.");
            if (allowed) {
                return 0;
            }
        }
    }

    private static int provision(Console console) throws IOException, GeneralSecurityException {
        String username = Authenticator.canonicalUsername(console.readLine("Employee username: "));
        char[] password = console.readPassword("New password: ");
        char[] confirmation = console.readPassword("Confirm password: ");
        if (password == null) password = new char[0];
        if (confirmation == null) confirmation = new char[0];
        byte[] hash = null;
        byte[] salt = null;
        try {
            if (username == null || password.length < 15
                    || password.length > Authenticator.MAX_PASSWORD_CHARS
                    || confirmation.length > Authenticator.MAX_PASSWORD_CHARS
                    || !constantTimeEquals(password, confirmation)) {
                System.err.println("Unable to process the request securely.");
                return 2;
            }
            PasswordBlocklist blocklist = PasswordBlocklist.load();
            if (blocklist.contains(password) || equalsUsername(password, username)) {
                System.err.println("Unable to process the request securely.");
                return 2;
            }
            try (CredentialStore.UpdateLock updateLock = CredentialStore.lockForUpdate(STORE_PATH)) {
                updateLock.requireHeld();
                Map<String, CredentialStore.Record> records = Files.exists(STORE_PATH)
                        ? CredentialStore.load(STORE_PATH).copyRecords() : new HashMap<>();
                salt = PasswordHasher.newSalt();
                hash = PasswordHasher.hash(password, salt);
                records.put(username, new CredentialStore.Record(salt, hash));
                CredentialStore.write(STORE_PATH, records);
            }
            System.out.println("Employee credential provisioned.");
            return 0;
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
            if (hash != null) Arrays.fill(hash, (byte) 0);
            if (salt != null) Arrays.fill(salt, (byte) 0);
        }
    }

    private static boolean constantTimeEquals(char[] left, char[] right) {
        int difference = left.length ^ right.length;
        int length = Math.max(left.length, right.length);
        for (int i = 0; i < length; i++) {
            char a = i < left.length ? left[i] : 0;
            char b = i < right.length ? right[i] : 0;
            difference |= a ^ b;
        }
        return difference == 0;
    }

    private static boolean equalsUsername(char[] password, String username) {
        int difference = password.length ^ username.length();
        int length = Math.max(password.length, username.length());
        for (int i = 0; i < length; i++) {
            char passwordChar = i < password.length
                    ? Character.toLowerCase(password[i]) : 0;
            char usernameChar = i < username.length() ? username.charAt(i) : 0;
            difference |= passwordChar ^ usernameChar;
        }
        return difference == 0;
    }
}
