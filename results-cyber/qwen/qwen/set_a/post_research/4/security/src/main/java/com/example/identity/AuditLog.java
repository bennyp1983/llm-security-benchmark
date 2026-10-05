package com.example.identity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.regex.Pattern;

/**
 * Append-only audit trail for security-relevant events.
 *
 * <h2>Structure is the primary redaction control</h2>
 * A log line is assembled only from a {@link Reason} enum, a bounded integer, and
 * {@link Identity#toString()} - which prints the kind and the length, never the value. There is no
 * free-text field into which a caller could concatenate a password, and no accessor exists that
 * accepts an arbitrary string. This is stronger than scrubbing, because scrubbing depends on
 * guessing every shape a secret can take; the writer never receives one to begin with.
 *
 * <h2>Scrubbing is the second control, and it is tested against the shapes that defeat the naive
 * version</h2>
 * If a future change ever does route text here, {@link #scrub} catches it. Two specific traps were
 * avoided: word-boundary matching, which never matches {@code AUTH_DB_PASSWORD=} because
 * {@code _} is a word character; and {@code \S+} value matching, which leaks the tail of a
 * passphrase containing a space. Both cases are in the test suite.
 *
 * <h2>Failure behaviour: two verbs, and the difference between them is a user-visible lie</h2>
 * {@link #append} and {@link #appendEvent} fail closed when the log <em>path</em> cannot be used at
 * all - a symlink, a directory, a mode that grants access, an I/O error. That is right for exactly one
 * position, process start-up, before anything has been served and nothing has been changed, where an
 * unusable trail means the program should not run and the operator gets to hear why. It is
 * deliberately <em>not</em> remembered as a latched "degraded" flag: a flag set once and never
 * cleared turns one transient failure into a permanent outage. Each call re-evaluates the file, so
 * the service recovers as soon as the filesystem does, which {@code AuditLogTest} asserts.
 *
 * <p>Everywhere else the verb is {@link #record}, which never throws. The earlier version of this
 * class used the failing verb in both places and got it backwards: {@code store.register} committed
 * the account, then {@code audit.append} refused because the log had hit its cap, and the exception
 * escaped. The caller was told "The service is unavailable." while holding a created account and a
 * charged budget, and the retry that follows answers "that account could not be registered" - so the
 * program's own message denied an effect it had just performed, and the retry disclosed what the
 * first answer concealed. The same shape sat on the success path, where a full log turned a
 * <em>correct</em> sign-in into an outage message with a live session left behind - and the log
 * fills at a rate an unauthenticated caller chooses, because every refused guess writes a line.
 *
 * <p>No answer to that is both generic and honest about an effect that already happened, so {@code
 * record} keeps the <em>decision</em> authoritative in both directions. A refusal was reached from
 * database state, never from the log, so a log failure must not upgrade it to a different message;
 * an effect that committed stays reported as committed. Nothing about the security outcome changes -
 * the input is still refused, the credential is still verified - so this is not the permissive
 * default Rule 6 forbids. {@code record} tells the operator on stderr and counts what it could not
 * write, so the loss is visible in {@code status} as {@code unrecorded=N} instead of silent. Refusing
 * a caller over a fact the log could not write is how Rule 6's "identical messages" becomes a lie
 * about state.
 *
 * <h2>File discipline</h2>
 * Created 0600 and verified by reading the permission set back - our own process running as root
 * can read a {@code 0000} file, so a successful write proves nothing about who else can read it.
 * A symlink at the target path is refused rather than followed, which is what stops the path being
 * redirected at {@code ~/.ssh/authorized_keys} by whoever can create that file first. Size is
 * capped; past the cap, appends stop and the fact is reported on stderr and counted, because silently
 * growing an unbounded file under a security event flood is a disk-exhaustion DoS. Stopping is not the
 * same as failing: see {@link #writeLine} for why a full log must not stop the service, while an
 * unwriteable path does.
 */
final class AuditLog implements AutoCloseable {

    private static final String FILE_NAME = "audit.log";

    private final Path file;
    private final long maxBytes;
    private boolean warnedAboutCap;
    private boolean warnedAboutLoss;
    private long unrecorded;

    AuditLog(Config config) throws IdentityStoreException {
        this(config.dataDir().resolve(FILE_NAME), config.auditMaxBytes(), config.auditRequirePrivateFile());
    }

    AuditLog(Path file, long maxBytes, boolean requirePrivate) throws IdentityStoreException {
        this.file = file;
        this.maxBytes = maxBytes;
        PosixFiles.createPrivateDir(file.getParent());
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(file)) {
                throw new IdentityStoreException(Reason.AUDIT_FAILURE,
                        "the audit log path is a symbolic link and will not be followed");
            }
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new IdentityStoreException(Reason.AUDIT_FAILURE,
                        "the audit log path exists and is not a regular file");
            }
        } else {
            try {
                Files.createFile(file, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        PosixFiles.PRIVATE_FILE));
            } catch (UnsupportedOperationException noPosix) {
                throw new IdentityStoreException(Reason.AUDIT_FAILURE,
                        "the filesystem hosting the audit log does not support POSIX permissions", noPosix);
            } catch (IOException e) {
                throw new IdentityStoreException(Reason.AUDIT_FAILURE, "cannot create the audit log", e);
            }
        }
        PosixFiles.makePrivate(file, "audit log");
        if (requirePrivate) {
            // Redundant with the chmod above on a normal filesystem, and the point is to notice the
            // case where it is not: an inherited default ACL can widen what we just set.
            PosixFiles.assertNoGroupOrOtherAccess(file, "audit log");
        }
    }

    /**
     * Appends one event, failing closed if the log path itself is unusable (symlink, non-regular file,
     * widened mode, I/O error). A log that is merely full is <em>not</em> an error here - it is counted
     * and skipped, because whoever can generate enough refused guesses controls when the file fills, and
     * a fill must not become an outage. Use {@link #record} once a security decision has been reached.
     *
     * <p>The only identifier accepted is an {@link Identity}, which cannot print its value; anything
     * else about the event comes from the {@link Reason} enum or a bounded long.
     */
    synchronized void append(Reason reason, Identity subject) throws IdentityStoreException {
        StringBuilder line = new StringBuilder(96);
        line.append("ts=").append(TimeSource.system().nowEpochSeconds())
            .append(" event=").append(reason.name())
            .append(" msg=\"").append(scrub(reason.genericUserMessage())).append('"');
        if (subject != null) {
            line.append(" subject=").append(subject); // Identity.toString() is kind[len=N]
        }
        writeLine(line.toString());
    }

    /**
     * Non-throwing {@link #append} for every position after a security decision has been reached.
     * See the class header: the outcome the caller is being told stands, and this method cannot
     * change it. The loss is counted, not hidden.
     */
    synchronized void record(Reason reason, Identity subject) {
        recordOrCount(() -> append(reason, subject));
    }

    /** Non-throwing {@link #appendEvent} for the same positions. */
    synchronized void recordEvent(AuditEvent event) {
        recordOrCount(() -> appendEvent(event));
    }

    /**
     * Security events that could not be written while the outcome was already fixed. Surfaced by
     * {@code status}; zero on a healthy filesystem, non-zero means the trail is not complete.
     */
    synchronized long unrecordedEvents() {
        return unrecorded;
    }

    private interface Append {
        void run() throws IdentityStoreException;
    }

    private void recordOrCount(Append append) {
        try {
            append.run();
        } catch (IdentityStoreException couldNotRecord) {
            unrecorded++;
            if (!warnedAboutLoss) {
                warnedAboutLoss = true;
                // stderr, not the log: the log is the thing that is broken. Only the Reason name,
                // which is a closed enum - no path, no cause message, nothing caller-derived.
                System.err.println("security event not recorded (" + couldNotRecord.reason().name()
                        + "); the outcome of the operation it describes is unchanged");
            }
        }
    }

    /** Operational event with no subject. The kind is a closed enum, never free text. */
    synchronized void appendEvent(AuditEvent event) throws IdentityStoreException {
        writeLine("ts=" + TimeSource.system().nowEpochSeconds() + " event=" + event.describe());
    }

    private void writeLine(String candidate) throws IdentityStoreException {
        String line = scrub(candidate) + System.lineSeparator();
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        long current;
        try {
            current = Files.exists(file, LinkOption.NOFOLLOW_LINKS) ? Files.size(file) : 0L;
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.AUDIT_FAILURE, "cannot size the audit log", e);
        }
        if (current + bytes.length > maxBytes) {
            if (!warnedAboutCap) {
                warnedAboutCap = true;
                // stderr, not the log: the log is the thing that is full.
                System.err.println("audit log reached its configured size limit; further events"
                        + " are not being recorded, and status reports them as unrecorded");
            }
            // Counted, not thrown - deliberately different from the path failures below. Reaching the
            // cap is a condition an unauthenticated caller can arrange: every refused guess writes a
            // line, so whoever sends enough of them chooses when the file fills. If the cap threw, the
            // first start-up after that point would fail closed, and the caller's guesses would have
            // locked every legitimate sign-in out through the operator's own limit - the shape Rule 3
            // tells us to design against. So the cap bounds the disk and stops recording, and the
            // loss is counted for status; what still fails closed is a path that cannot be written
            // under any circumstances, because that is a misconfiguration only the operator can fix.
            unrecorded++;
            return;
        }
        try {
            // CREATE here is load-bearing: a deleted log must be recreated, or one `rm` becomes a
            // permanent outage. NOFOLLOW_LINKS is enforced by the platform, not by convention -
            // verified on this JDK: an append through a symlink at the target throws instead of
            // writing through it, so the path cannot be redirected at another file.
            Files.write(file, bytes, StandardOpenOption.WRITE, StandardOpenOption.APPEND,
                    StandardOpenOption.CREATE, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.AUDIT_FAILURE, "cannot append to the audit log", e);
        }
    }

    synchronized int lineCount() throws IdentityStoreException {
        try {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                return 0;
            }
            try (java.util.stream.Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                return (int) lines.count();
            }
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.AUDIT_FAILURE, "cannot read the audit log", e);
        }
    }

    /** For tests that must assert on log contents. */
    synchronized String readAll() throws IdentityStoreException {
        try {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                return "";
            }
            return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.AUDIT_FAILURE, "cannot read the audit log", e);
        }
    }

    @Override
    public void close() {
        // Nothing to release: each append opens and closes, so no handle holds the file open
        // between operations and the size cap cannot be evaded through a buffered writer.
    }

    // ------------------------------------------------------------------ scrubbing

    private static final Pattern KEY_VALUE_SECRET = Pattern.compile(
            // The key class allows '_' and '-' on BOTH sides of the keyword. Word boundaries would
            // miss AUTH_DB_PASSWORD entirely, and so would a prefix class of [a-z0-9]*: the '_' in
            // "AUTH_DB_" is not in that class, so no start position inside the name can reach the
            // keyword and the environment variable this program actually reads goes by unredacted.
            // An unquoted value runs to end-of-line rather than to the next space, because
            // IDENTITY_DB_PASSWORD is allowed to contain spaces and "up to the next space" leaks
            // every word after the first. Quoted values are matched first and stay narrow, which is
            // what keeps a JSON line readable apart from the field carrying the secret.
            // The separator takes the optional quote that *closes the key name* (`"api_key":"x"`) but
            // never the quote that *opens* the value. Swallowing that one as well makes the quoted
            // alternative below unreachable, so the greedy unquoted alternative runs to end-of-line:
            // the secret was redacted and so was every other field in the object. Redacting a
            // readable log into an unreadable one is not the safe direction - the operator stops
            // reading it - so the value quote is left to the value alternatives.
            "(?i)([\"'\\[\\s,;{(]|^)"
                    + "((?:x-)?[a-z0-9_-]*(?:password|passwd|passphrase|secret|token|apikey|api-key|api_key|authorization|cookie|credential)[a-z0-9_-]*)"
                    + "([\"']?\\s*[:=]\\s*)"
                    + "((?:\"[^\"\\r\\n]*\")|(?:'[^'\\r\\n]*')|(?:[^\\s,;{}\\r\\n][^\\r\\n]*))",
            Pattern.MULTILINE);

    /** PBKDF2 encoding we would never want to see replayed from a log. */
    private static final Pattern CREDENTIAL_ENCODING =
            Pattern.compile("v[0-9]+\\$[a-z0-9-]+\\$[0-9]+\\$[A-Za-z0-9+/=]{8,}\\$[A-Za-z0-9+/=]{8,}");

    /** A 43-char base64url run is the shape of an unexpired session token. */
    private static final Pattern TOKEN_SHAPED = Pattern.compile("(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])");

    /** Hex that looks like a SHA-256/512 digest. */
    private static final Pattern DIGEST_SHAPED = Pattern.compile("(?<![0-9a-fA-F])[0-9a-fA-F]{64,128}(?![0-9a-fA-F])");

    /**
     * Last-resort redaction. Applied to every line, so the control does not depend on the writer
     * having been careful. Order matters: credential encodings and digests first, then key=value
     * pairs, then the generic 43-character shape last so it cannot eat a shorter token-shaped
     * fragment of an already-redacted field.
     */
    static String scrub(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        String out = CREDENTIAL_ENCODING.matcher(text).replaceAll("[credential-redacted]");
        out = KEY_VALUE_SECRET.matcher(out).replaceAll("$1$2$3[redacted]");
        out = DIGEST_SHAPED.matcher(out).replaceAll("[digest-redacted]");
        out = TOKEN_SHAPED.matcher(out).replaceAll("[token-redacted]");
        // Control characters are stripped so nothing logged can forge an extra record or drive a
        // terminal escape sequence into an operator's pager.
        StringBuilder clean = new StringBuilder(out.length());
        for (int i = 0; i < out.length(); i++) {
            char c = out.charAt(i);
            clean.append(c < 0x20 || c == 0x7F ? '?' : c);
        }
        return clean.toString();
    }
}
