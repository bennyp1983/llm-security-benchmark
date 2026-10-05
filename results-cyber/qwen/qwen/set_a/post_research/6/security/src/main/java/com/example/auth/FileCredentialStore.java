package com.example.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Credential records loaded from the configured file.
 *
 * <p>The file is operator-supplied and therefore attacker-controlled: anyone with write access to it
 * can try to shape a security outcome, so every field is validated on load and any problem is fatal
 * at start-up rather than tolerated. No URL, ZIP or remote URI scheme is accepted anywhere; the path
 * must be an absolute local path, checked for {@code NOFOLLOW_LINKS} regular-file status before it
 * is read.
 *
 * <p>Record format, one record per line, UTF-8:
 * <pre>username : base64(16-byte salt) : iteration-count : base64(32-byte digest)</pre>
 * A valid username cannot contain {@code :}, so the split is unambiguous. Rejected outright, each
 * with a start-up problem that names only the line number and never the offending content:
 * <ul>
 *   <li>a username that fails {@link InputValidator};</li>
 *   <li>Base64 that is not canonical, or of the wrong length;</li>
 *   <li>an iteration count below the configured minimum or above the hard maximum;</li>
 *   <li>duplicate usernames, and usernames that collide with another record ignoring ASCII case -
 *       either would let one spelling name two different records, so the store refuses to load;</li>
 *   <li>more records than {@link #MAX_RECORDS}, so the file cannot be used to exhaust memory.</li>
 * </ul>
 */
final class FileCredentialStore implements CredentialStore {

    static final int MAX_RECORDS = 20_000;
    private static final int MAX_FILE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_LINE_CHARS = 512;

    private final Map<String, AccountCredentials> byExactName;
    private final Map<String, String> canonicalByLowerName;

    private FileCredentialStore(Map<String, AccountCredentials> byExactName, Map<String, String> canonicalByLowerName) {
        this.byExactName = Collections.unmodifiableMap(byExactName);
        this.canonicalByLowerName = Collections.unmodifiableMap(canonicalByLowerName);
    }

    /**
     * Loads and validates the credential file.
     *
     * @param problems start-up problems are appended here; nothing is thrown so that the caller can
     *     report every problem found across configuration and store together
     */
    static FileCredentialStore load(Path file, AuthConfig config, List<String> problems) {
        Map<String, AccountCredentials> byExactName = new LinkedHashMap<>();
        Map<String, String> canonicalByLowerName = new LinkedHashMap<>();
        if (file == null) {
            problems.add("credential file is missing");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            problems.add("credential file is not a regular file");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        final long size;
        try {
            size = Files.size(file);
        } catch (IOException e) {
            problems.add("credential file size could not be determined");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        if (size > MAX_FILE_BYTES) {
            problems.add("credential file is larger than the accepted size");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        final List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            problems.add("credential file could not be read as UTF-8 text");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }
        if (lines.size() > MAX_RECORDS) {
            problems.add("credential file has more records than the accepted maximum");
            return new FileCredentialStore(byExactName, canonicalByLowerName);
        }

        int lineNumber = 0;
        for (String line : lines) {
            lineNumber++;
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.length() > MAX_LINE_CHARS) {
                problems.add("credential file line " + lineNumber + " is too long");
                continue;
            }
            AccountCredentials record = parseLine(line, lineNumber, config, problems);
            if (record == null) {
                continue;
            }
            String exact = record.username();
            if (byExactName.containsKey(exact)) {
                problems.add("credential file line " + lineNumber + " repeats a username");
                continue;
            }
            String lower = lowerAscii(exact);
            if (canonicalByLowerName.containsKey(lower)) {
                problems.add("credential file line " + lineNumber + " collides with an earlier username ignoring case");
                continue;
            }
            byExactName.put(exact, record);
            canonicalByLowerName.put(lower, exact);
        }
        if (!problems.isEmpty()) {
            // Fail closed: a store we cannot fully trust is not loaded at all. The caller refuses
            // to start the service once the collected problems are reported.
            return new FileCredentialStore(new LinkedHashMap<>(), new LinkedHashMap<>());
        }
        return new FileCredentialStore(byExactName, canonicalByLowerName);
    }

    private static AccountCredentials parseLine(String line, int lineNumber, AuthConfig config, List<String> problems) {
        String[] parts = line.split(":", -1);
        if (parts.length != 4) {
            problems.add("credential file line " + lineNumber + " does not have four fields");
            return null;
        }
        String username = InputValidator.validateUsername(parts[0]);
        if (username == null) {
            problems.add("credential file line " + lineNumber + " has an invalid username");
            return null;
        }
        byte[] salt = PasswordHasher.decodeBytes(parts[1], PasswordHasher.SALT_BYTES);
        if (salt == null) {
            problems.add("credential file line " + lineNumber + " has an invalid salt");
            return null;
        }
        int iterations = parseIterations(parts[2]);
        // The upper bound is the configured count, not the parser's ceiling. A record may not order
        // this deployment to do more work per sign-in than its own policy costs every other account:
        // PasswordHasher enforces the same bound at derivation time, and refusing here turns it into
        // a named start-up problem instead of a per-attempt store failure.
        if (iterations < config.minAcceptedIterations() || iterations > config.pbkdf2Iterations()) {
            problems.add("credential file line " + lineNumber + " has an unacceptable iteration count");
            return null;
        }
        byte[] digest = PasswordHasher.decodeBytes(parts[3], PasswordHasher.MAX_DIGEST_BYTES);
        if (digest == null) {
            problems.add("credential file line " + lineNumber + " has an invalid digest");
            return null;
        }
        return new AccountCredentials(username, salt, iterations, digest);
    }

    private static int parseIterations(String field) {
        if (field.isEmpty() || field.length() > 9) {
            return -1;
        }
        for (int i = 0; i < field.length(); i++) {
            if (field.charAt(i) < '0' || field.charAt(i) > '9') {
                return -1;
            }
        }
        if (field.length() > 1 && field.charAt(0) == '0') {
            return -1;
        }
        try {
            return Integer.parseInt(field);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    @Override
    public Optional<AccountCredentials> lookup(String username) {
        if (username == null) {
            return Optional.empty();
        }
        String canonical = resolve(username);
        if (canonical == null) {
            return Optional.empty();
        }
        AccountCredentials record = byExactName.get(canonical);
        return record == null ? Optional.empty() : Optional.of(record);
    }

    /**
     * Canonical name that {@code username} names, or {@code null}. ASCII case is the only thing
     * folded, and load-time validation guarantees at most one record per folded name.
     */
    String resolve(String username) {
        if (username == null) {
            return null;
        }
        return canonicalByLowerName.get(lowerAscii(username));
    }

    @Override
    public int size() {
        return byExactName.size();
    }

    /**
     * ASCII-only case folding. It is used solely to detect two records whose names differ only in
     * case and to let one record be named by either spelling. The stored name is never rewritten, so
     * this cannot merge two records and cannot make a non-ASCII look-alike resolve to an account.
     */
    private static String lowerAscii(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + 32);
            }
            out.append(c);
        }
        return out.toString();
    }
}
