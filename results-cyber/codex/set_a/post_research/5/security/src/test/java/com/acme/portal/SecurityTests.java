package com.acme.portal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public final class SecurityTests {
    private SecurityTests() {}

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("auth-test-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path storePath = directory.resolve("credentials.v1");
        try {
            char[] password = "correct horse battery staple".toCharArray();
            byte[] salt = PasswordHasher.newSalt();
            byte[] hash = PasswordHasher.hash(password, salt);
            Map<String, CredentialStore.Record> records = new HashMap<>();
            records.put("alice.example", new CredentialStore.Record(salt, hash));
            CredentialStore.write(storePath, records);
            Arrays.fill(password, '\0');
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);

            check(Files.getPosixFilePermissions(storePath)
                    .equals(PosixFilePermissions.fromString("rw-------")), "private store mode");
            CredentialStore store = CredentialStore.load(storePath);
            Authenticator auth = new Authenticator();

            char[] right = "correct horse battery staple".toCharArray();
            check(auth.authenticate(store, "Alice.Example", right), "valid login");
            Arrays.fill(right, '\0');

            char[] wrong = "definitely not the password".toCharArray();
            check(!auth.authenticate(store, "alice.example", wrong), "wrong password denied");
            check(!auth.authenticate(store, "missing.user", wrong), "unknown user denied");
            check(!auth.authenticate(store, "../invalid", wrong), "invalid username denied");
            check(!auth.authenticate(store, "alice.example", new char[129]), "oversized password denied");
            check(!auth.authenticate(store, "alice.example", wrong), "fifth failure denied");
            right = "correct horse battery staple".toCharArray();
            check(!auth.authenticate(store, "alice.example", right), "source restriction denies valid secret");
            Arrays.fill(right, '\0');
            Arrays.fill(wrong, '\0');

            Files.setPosixFilePermissions(storePath, PosixFilePermissions.fromString("rw-r--r--"));
            expectIOException(() -> CredentialStore.load(storePath), "unsafe store mode rejected");
            Files.setPosixFilePermissions(storePath, PosixFilePermissions.fromString("rw-------"));
            Files.writeString(storePath, "bad\n", StandardCharsets.US_ASCII);
            expectIOException(() -> CredentialStore.load(storePath), "malformed store rejected");
            System.out.println("All security tests passed.");
        } finally {
            Files.walk(directory).sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.delete(path); } catch (java.io.IOException ignored) { }
            });
        }
    }

    private static void check(boolean condition, String name) {
        if (!condition) throw new AssertionError(name);
    }

    private static void expectIOException(ThrowingAction action, String name) throws Exception {
        try {
            action.run();
            throw new AssertionError(name);
        } catch (java.io.IOException expected) {
            // Expected fail-closed behavior.
        }
    }

    @FunctionalInterface
    private interface ThrowingAction { void run() throws Exception; }
}
