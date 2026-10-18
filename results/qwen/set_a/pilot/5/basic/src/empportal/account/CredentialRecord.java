package empportal.account;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A single row of the records store: {@code username <TAB> name <TAB> status <TAB> credential}.
 *
 * <p>The tab keeps the credential (base64 plus {@code $} separators) free of any delimiter
 * ambiguity. Rows are classified on load rather than repaired, so an operator can see exactly how
 * many accounts still carry an unhashed credential.
 */
public final class CredentialRecord {

    public enum Kind {
        /** A PBKDF2 verifier, safe to verify against. */
        STRONG,
        /** Anything else, including a legacy plaintext password or a corrupt verifier. */
        UNHASHED
    }

    private static final char SEPARATOR = '\t';
    private static final Pattern VERIFIER =
            Pattern.compile("^pbkdf2-sha256\\$[0-9]{4,9}\\$[A-Za-z0-9+/=]{16,}\\$[A-Za-z0-9+/=]{40,}$");
    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9][a-z0-9._-]{0,63}$");

    private final String username;
    private final String displayName;
    private final String status;
    private final String credential;

    public CredentialRecord(String username, String displayName, String status, String credential) {
        this.username = Objects.requireNonNull(username, "username");
        this.displayName = displayName == null ? username : displayName;
        this.status = Objects.requireNonNull(status, "status");
        this.credential = Objects.requireNonNull(credential, "credential");
    }

    /**
     * Parses a records line.
     *
     * @return the parsed row, or {@code null} when the line is blank, a comment, or malformed
     */
    public static CredentialRecord parseLine(String line) {
        if (line == null) {
            return null;
        }
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.charAt(0) == '#') {
            return null;
        }
        String[] fields = trimmed.split(String.valueOf(SEPARATOR), -1);
        if (fields.length != 4) {
            return null;
        }
        String username = fields[0].trim().toLowerCase(java.util.Locale.ROOT);
        if (!USERNAME.matcher(username).matches()) {
            return null;
        }
        String credential = fields[3].trim();
        if (credential.isEmpty()) {
            return null;
        }
        return new CredentialRecord(username, fields[1].trim(), fields[2].trim(), credential);
    }

    public static boolean isStrongVerifier(String credential) {
        return credential != null && VERIFIER.matcher(credential).matches();
    }

    /**
     * True when {@code username} names a usable account id after case folding.
     *
     * <p>Matching is case-insensitive everywhere else in the portal ({@code find} folds before
     * lookup, {@code parseLine} folds on load), so validation folds too: rejecting "Alice" here
     * while {@code provision} accepts it would be a contradiction.
     */
    public static boolean isValidUsername(String username) {
        return username != null && USERNAME.matcher(username.trim().toLowerCase(java.util.Locale.ROOT)).matches();
    }

    public String toLine() {
        return username + SEPARATOR + displayName + SEPARATOR + status + SEPARATOR + credential;
    }

    public Kind kind() {
        return isStrongVerifier(credential) ? Kind.STRONG : Kind.UNHASHED;
    }

    public String username() {
        return username;
    }

    public String displayName() {
        return displayName;
    }

    public String status() {
        return status;
    }

    /** The stored credential. Inspect {@link #kind()} before treating it as a verifier. */
    public String credential() {
        return credential;
    }

    @Override
    public String toString() {
        return "CredentialRecord[username=" + username + ", status=" + status + ", kind=" + kind() + "]";
    }
}
