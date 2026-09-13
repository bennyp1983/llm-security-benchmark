package portal.auth;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only records store loaded from a tab-separated text file.
 *
 * <p>Line format (blank lines and lines whose first non-blank character is {@code #} ignored):
 *
 * <pre>
 *   alice.jones&lt;TAB&gt;Alice Jones&lt;TAB&gt;pbkdf2-sha256$100000$Zm9v...$QmFy...
 * </pre>
 *
 * <p>A file that cannot be understood is rejected as a whole at start-up - the portal never runs
 * with a half-loaded employee list, and never honours a record whose stored cost is below
 * {@code minStoredIterations}.
 */
public final class TextFileCredentialStore implements CredentialStore {

    private final Map<String, EmployeeRecord> records;

    public TextFileCredentialStore(Path file) throws IOException {
        this(file, PasswordHash.MIN_STORED_ITERATIONS);
    }

    public TextFileCredentialStore(Path file, int minStoredIterations) throws IOException {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException("cannot read records file " + file + ": " + e.getMessage(), e);
        }
        this.records = parse(lines, minStoredIterations);
    }

    /** Reads the same line format from memory; used by tests that do not want a temp file. */
    public static TextFileCredentialStore fromLines(List<String> lines, int minStoredIterations) {
        try {
            return new TextFileCredentialStore(parse(lines, minStoredIterations));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public EmployeeRecord find(String canonicalUsername) {
        return canonicalUsername == null ? null : records.get(canonicalUsername);
    }

    public int size() {
        return records.size();
    }

    /** Usernames in the file, sorted; handy for start-up logging. */
    public List<String> usernames() {
        List<String> names = new ArrayList<>(records.keySet());
        names.sort(String::compareTo);
        return names;
    }

    private TextFileCredentialStore(Map<String, EmployeeRecord> records) {
        this.records = records;
    }

    private static Map<String, EmployeeRecord> parse(List<String> lines, int minStoredIterations)
            throws IOException {
        Map<String, EmployeeRecord> loaded = new HashMap<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int lineNumber = i + 1;
            if (line.isBlank() || line.stripLeading().startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\t", -1);
            if (fields.length != 3) {
                throw new IOException("line " + lineNumber
                        + ": expected 3 tab-separated fields, found " + fields.length);
            }
            try {
                String username = CredentialValidator.canonicalUsername(fields[0]);
                EmployeeRecord record = new EmployeeRecord(username, fields[1],
                        PasswordHash.parse(fields[2], minStoredIterations));
                if (loaded.putIfAbsent(username, record) != null) {
                    throw new IOException("line " + lineNumber + ": duplicate username " + username);
                }
            } catch (IllegalArgumentException e) {
                throw new IOException("line " + lineNumber + ": " + e.getMessage(), e);
            }
        }
        return Map.copyOf(loaded);
    }
}
