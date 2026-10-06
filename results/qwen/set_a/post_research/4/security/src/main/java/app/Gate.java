package app;

/**
 * Wraps {@link AuditLog} so that a security decision cannot be returned before its record was
 * written. Every method throws {@link AuditLog.AuditException} on a write failure, and callers
 * translate that into a refusal - the trail cannot be silently lost by an attacker who fills the
 * disk, replaces the log with a directory, or widens its permissions.
 *
 * <p>Field values passed through here are always code-supplied constants or non-reversible
 * digests; see {@link AuditLog}.
 */
public final class Gate {

    /** Per-process salt so correlation tags do not survive as stable row identifiers. */
    private final String processSalt = java.util.UUID.randomUUID().toString();

    private final AuditLog audit;

    public Gate(AuditLog audit) {
        this.audit = audit;
    }

    /** Records the event or throws; there is no variant that swallows a failure. */
    public void record(AuditLog.Event event, String... fields) throws AuditLog.AuditException {
        audit.record(event, fields);
    }

    /**
     * Non-reversible correlation tag for an account: the primary key hashed with a per-process
     * random salt, so records can be joined without writing a row identifier that maps directly
     * onto the database.
     */
    public String accountTag(long accountId) {
        return tag("account", Long.toString(accountId));
    }

    /** Non-reversible tag for a source identifier. */
    public String sourceTag(String sourceId) {
        if (sourceId == null) {
            return "unknown";
        }
        return tag("src", sourceId);
    }

    /**
     * Tags for identifying data. Because a username or an email address is low-entropy, these are
     * salted per process: records can be joined within one run of the program, but the trail cannot
     * be joined back to database rows, and two runs of the program produce unrelated tags. See the
     * README for exactly what that does and does not protect.
     */
    public String emailTag(String canonicalEmail) {
        return tag("email", canonicalEmail);
    }

    public String usernameTag(String username) {
        return tag("username", username);
    }

    /**
     * Tag for a session token. A token is a bearer credential, so neither the token nor its
     * unstored SHA-256 may appear in the trail: a trail reader could otherwise sign in with
     * whatever they can read. This digest is additionally salted per process, so it cannot be
     * matched against the {@code sessions} table either.
     */
    public String sessionTag(String token) {
        if (token == null) {
            return "absent";
        }
        return tag("session", token);
    }

    private String tag(String kind, String value) {
        return Digests.sha256Hex((processSalt + ':' + kind + ':' + value)
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII)).substring(0, 16);
    }

    public AuditLog log() {
        return audit;
    }
}
