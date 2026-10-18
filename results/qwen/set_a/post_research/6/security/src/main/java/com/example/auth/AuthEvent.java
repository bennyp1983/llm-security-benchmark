package com.example.auth;

import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.regex.Pattern;

/**
 * One authentication event, as retained for later review.
 *
 * <p>Immutable and constructed only from values that have already been validated, each rendered into
 * a fixed set of {@code key=value} fields. There is no free-text field and no exception message is
 * ever placed here, so no attacker-controlled string can contribute a newline, a forged field or a
 * terminal control sequence to a log line.
 *
 * <p>Deliberately absent: the password (in any form), the credential digest, the salt, the pepper,
 * the whole session identifier, and the username itself (see {@link AccountField}).
 */
final class AuthEvent {

    /** Longest rendered line the logger will accept, enforced again by {@link AuditLogger}. */
    static final int MAX_LINE_CHARS = 320;

    private static final Pattern SOURCE_PATTERN = Pattern.compile(
            "^(?:[0-9]{1,3}(?:\\.[0-9]{1,3}){3}|[0-9A-Fa-f:]{2,45})$");

    private static final DateTimeFormatter TIMESTAMP = new DateTimeFormatterBuilder()
            .appendInstant(6)
            .toFormatter(java.util.Locale.ROOT);

    private final long timestampMillis;
    private final EventType type;
    private final String outcome;
    private final String accountField;
    private final String source;
    private final String reason;
    private final long latencyMicros;
    private final int retryAfterSeconds;
    private final String sessionSuffix;
    private final boolean sessionSuffixRejected;

    private AuthEvent(Builder b) {
        this.timestampMillis = b.timestampMillis;
        this.type = b.type;
        this.outcome = b.outcome;
        this.accountField = b.accountField;
        this.source = b.source;
        this.reason = b.reason;
        this.latencyMicros = b.latencyMicros;
        this.retryAfterSeconds = b.retryAfterSeconds;
        this.sessionSuffix = b.sessionSuffix;
        this.sessionSuffixRejected = b.sessionSuffixRejected;
    }

    static Builder builder() {
        return new Builder();
    }

    EventType type() {
        return type;
    }

    String accountField() {
        return accountField;
    }

    long timestampMillis() {
        return timestampMillis;
    }

    /**
     * The source only if it is a form this component would have written in the first place. Used when
     * re-reporting a rejected event as an alert: the alert must not reintroduce the value that caused
     * the rejection.
     */
    String sourceIfSafe() {
        if (source == null) {
            return null;
        }
        if (!SOURCE_PATTERN.matcher(source).matches()) {
            return null;
        }
        return source.equals(InputValidator.normalizeSourceAddress(source)) ? source : null;
    }

    /** The latency, or zero when it is outside the range this class would have rendered. */
    long latencyMicrosIfSafe() {
        return latencyMicros >= 0 && latencyMicros <= 3_600_000_000L ? latencyMicros : 0L;
    }

    /** The retry hint, or zero when it is outside the range this class would have rendered. */
    int retryAfterSecondsIfSafe() {
        return retryAfterSeconds >= 0 && retryAfterSeconds <= 86_400 ? retryAfterSeconds : 0;
    }

    /**
     * Renders the canonical single-line form. The sequence number is supplied by the logger, which
     * owns the counter, so two concurrent attempts cannot both claim the same number.
     */
    String render(long sequence) {
        StringBuilder out = new StringBuilder(192);
        out.append("seq=").append(sequence)
                .append(" ts=").append(TIMESTAMP.format(java.time.Instant.ofEpochMilli(timestampMillis)))
                .append(" type=").append(type.token())
                .append(" ").append(accountField)
                .append(" outcome=").append(outcome);
        if (source != null) {
            out.append(" source=").append(source);
        }
        if (reason != null) {
            out.append(" reason=").append(reason);
        }
        out.append(" latency_us=").append(latencyMicros);
        if (retryAfterSeconds > 0) {
            out.append(" retry_after=").append(retryAfterSeconds);
        }
        if (sessionSuffix != null) {
            out.append(" session=").append(sessionSuffix);
        }
        return out.toString();
    }

    /**
     * Returns the rendered line, or {@code null} when it would not be safe to write: an over-long
     * line, a missing account field, or a source that is not the canonical form produced by
     * {@link InputValidator#normalizeSourceAddress}.
     */
    String renderOrReject(long sequence) {
        if (type == null || outcome == null) {
            return null;
        }
        if (accountField == null || !accountField.startsWith("account_id=")) {
            return null;
        }
        if (source != null && !SOURCE_PATTERN.matcher(source).matches()) {
            return null;
        }
        if (source != null && !source.equals(InputValidator.normalizeSourceAddress(source))) {
            return null;
        }
        if (sessionSuffixRejected) {
            // The caller attached a session identifier this component cannot vouch for. Dropping the
            // field and writing the line would record a success whose evidence was thrown away, so
            // the whole event is refused and the caller raises an alert instead.
            return null;
        }
        if (sessionSuffix != null && !sessionSuffix.matches("[0-9a-f]{6}")) {
            return null;
        }
        if (latencyMicros < 0 || latencyMicros > 3_600_000_000L) {
            return null;
        }
        if (retryAfterSeconds < 0 || retryAfterSeconds > 86_400) {
            return null;
        }
        if (sequence < 1) {
            return null;
        }
        String line = render(sequence);
        if (line.length() > MAX_LINE_CHARS || line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0) {
            return null;
        }
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            // Space (0x20) is the field separator and must be allowed; every other character below
            // it (tab, NUL, CR, LF, the rest of C0) and DEL are refused, which is what stops a
            // forged second record or a terminal escape sequence.
            if (c < 0x20 || c == 0x7f) {
                return null;
            }
        }
        return line;
    }

    @Override
    public String toString() {
        // Sequence 0 is never a valid number, so this can only ever render the redacted shape and
        // never a line that would otherwise be rejected.
        return "AuthEvent[type=" + (type == null ? "none" : type.token()) + "]";
    }

    static final class Builder {

        private long timestampMillis;
        private EventType type;
        private String outcome = "none";
        private String accountField;
        private String source;
        private String reason;
        private long latencyMicros;
        private int retryAfterSeconds;
        private String sessionSuffix;
        private boolean sessionSuffixRejected;

        private Builder() {
        }

        Builder timestampMillis(long value) {
            this.timestampMillis = value;
            return this;
        }

        Builder type(EventType value) {
            this.type = value;
            return this;
        }

        Builder outcome(String value) {
            if (!"success".equals(value) && !"failure".equals(value) && !"none".equals(value)
                    && !"blocked".equals(value) && !"error".equals(value)) {
                throw new IllegalArgumentException("outcome");
            }
            this.outcome = value;
            return this;
        }

        Builder account(String submittedUsername, boolean present) {
            this.accountField = AccountField.render(submittedUsername, present);
            return this;
        }

        /**
         * Reuses an account field the component already computed, for re-reporting a rejected event
         * as an alert. The hash is derived from the name by this code, so carrying it over cannot
         * introduce attacker-controlled text; recomputing it would be pointless work on a path that
         * exists only because something already went wrong.
         */
        Builder accountFieldOf(String rendered) {
            this.accountField = rendered;
            return this;
        }

        Builder source(String canonicalAddress) {
            this.source = canonicalAddress;
            return this;
        }

        /** Only a {@link Diagnostic} category may be recorded as a reason. */
        Builder reason(Diagnostic diagnostic) {
            this.reason = diagnostic == null ? null : diagnostic.name().toLowerCase(java.util.Locale.ROOT);
            return this;
        }

        Builder latencyMicros(long value) {
            this.latencyMicros = value;
            return this;
        }

        Builder retryAfterSeconds(int value) {
            this.retryAfterSeconds = value;
            return this;
        }

        /** Records the first six hex characters of a session identifier, for correlating events. */
        Builder sessionSuffix(String sessionId) {
            this.sessionSuffix = null;
            this.sessionSuffixRejected = false;
            if (sessionId == null) {
                return this;
            }
            if (sessionId.length() < 6) {
                this.sessionSuffixRejected = true;
                return this;
            }
            String candidate = sessionId.substring(0, 6);
            if (!candidate.matches("[0-9a-f]{6}")) {
                this.sessionSuffixRejected = true;
                return this;
            }
            this.sessionSuffix = candidate;
            return this;
        }

        AuthEvent build() {
            return new AuthEvent(this);
        }
    }
}
