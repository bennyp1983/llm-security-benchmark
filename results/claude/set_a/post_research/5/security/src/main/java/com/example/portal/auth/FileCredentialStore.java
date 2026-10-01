package com.example.portal.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link CredentialStore} backed by a line-oriented file of {@code username:stored-hash} records.
 *
 * <p>The file is loaded once into an immutable map, so a lookup during authentication does no I/O
 * and cannot be influenced by a concurrent write. The file is treated as untrusted input:
 *
 * <ul>
 *   <li>It must be a regular file, not a symlink or a device, so it cannot be pointed at something
 *       else after an administrator has reviewed it.</li>
 *   <li>It must be owned by the process user and readable only by its owner. A credential file that
 *       another local account can read is already compromised; one another account can <em>write</em>
 *       lets that account enrol itself as any employee, so loading continues only when the
 *       permission bits are a subset of owner read/write.</li>
 *   <li>Its directory must not be world-writable, since that would let another account replace the
 *       file wholesale.</li>
 *   <li>Its size and record count are bounded, so a file that has grown without limit cannot
 *       exhaust heap on startup.</li>
 *   <li>Every field of every record is validated. A malformed record is dropped, not guessed at,
 *       and the account it names simply does not exist.</li>
 * </ul>
 */
public final class FileCredentialStore implements CredentialStore {

    /** Largest credential file this loader will read, in bytes. */
    public static final long MAX_FILE_BYTES = 8L * 1024 * 1024;
    /** Largest number of records this loader will hold. */
    public static final int MAX_RECORDS = 50_000;
    /** Largest single record, in characters. */
    public static final int MAX_LINE_LENGTH = 512;

    private final Map<String, PasswordHasher.StoredHash> records;

    private FileCredentialStore(Map<String, PasswordHasher.StoredHash> records) {
        this.records = Collections.unmodifiableMap(records);
    }

    /**
     * Loads and validates the credential file at {@code path}.
     *
     * @param audit receives one entry per rejected record; rejected records are never echoed
     *              verbatim, only counted by line number
     * @throws IOException         if the file cannot be read
     * @throws ValidationException if the file's type, ownership, permissions or size make it unsafe
     *                             to trust
     */
    public static FileCredentialStore load(Path path, AuditLog audit) throws IOException, ValidationException {
        Path resolved = path.toAbsolutePath().normalize();
        PrivateFiles.requireOwnerOnly(resolved, "credential file");

        long size = Files.size(resolved);
        if (size > MAX_FILE_BYTES) {
            throw new ValidationException("credential file exceeds the maximum accepted size");
        }

        List<String> lines = Files.readAllLines(resolved, StandardCharsets.UTF_8);
        Map<String, PasswordHasher.StoredHash> parsed = new HashMap<>();
        int rejected = 0;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int lineNumber = i + 1;
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            if (parsed.size() >= MAX_RECORDS) {
                throw new ValidationException("credential file exceeds the maximum accepted record count");
            }
            if (line.length() > MAX_LINE_LENGTH) {
                audit.warn("credential record rejected: over-long line", "line=" + lineNumber);
                rejected++;
                continue;
            }
            int separator = line.indexOf(':');
            if (separator <= 0 || separator == line.length() - 1) {
                audit.warn("credential record rejected: missing field separator", "line=" + lineNumber);
                rejected++;
                continue;
            }
            try {
                String username = InputPolicy.requireValidUsername(line.substring(0, separator));
                PasswordHasher.StoredHash hash = PasswordHasher.parse(line.substring(separator + 1));
                if (parsed.putIfAbsent(username, hash) != null) {
                    // Two records for one account would make the effective credential depend on
                    // load order. Refuse rather than pick one.
                    throw new ValidationException("duplicate account record");
                }
            } catch (ValidationException e) {
                audit.warn("credential record rejected: " + e.getMessage(), "line=" + lineNumber);
                rejected++;
            }
        }

        audit.info("credential store loaded", "accounts=" + parsed.size() + " rejected=" + rejected);
        return new FileCredentialStore(parsed);
    }

    /**
     * Creates the credential file with owner-only permissions if it does not exist yet, so there is
     * never a window in which it is world-readable.
     */
    public static void createIfAbsent(Path path) throws IOException {
        PrivateFiles.createPrivateIfAbsent(path.toAbsolutePath().normalize());
    }

    @Override
    public Optional<PasswordHasher.StoredHash> find(String canonicalUsername) {
        return Optional.ofNullable(records.get(canonicalUsername));
    }

    @Override
    public int size() {
        return records.size();
    }
}
