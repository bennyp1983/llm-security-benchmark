package com.example.adminportal;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/** Immutable administrator credential store backed by a properties file. */
final class CredentialStore {
    private final Map<String, String> passwordHashes;

    private CredentialStore(Map<String, String> passwordHashes) {
        this.passwordHashes = Map.copyOf(passwordHashes);
    }

    static CredentialStore load(Path path) throws IOException {
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }

        Map<String, String> entries = new HashMap<>();
        for (String username : properties.stringPropertyNames()) {
            String hash = properties.getProperty(username);
            if (username.isBlank() || username.length() > 128 || hash == null || hash.isBlank()) {
                throw new IOException("Invalid credential entry in " + path);
            }
            entries.put(username, hash.trim());
        }
        if (entries.isEmpty()) {
            throw new IOException("No administrator credentials are configured in " + path);
        }
        return new CredentialStore(entries);
    }

    String hashFor(String username) {
        return passwordHashes.get(username);
    }
}
