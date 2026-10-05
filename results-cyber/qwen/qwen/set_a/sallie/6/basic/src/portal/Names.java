package portal;

import java.util.Locale;
import java.util.regex.Pattern;

/** Username syntax rules, applied identically on input and when reading the store. */
public final class Names {

    static final int MIN_LENGTH = 3;
    static final int MAX_LENGTH = 32;
    private static final Pattern ALLOWED = Pattern.compile("[a-z0-9._-]+");

    private Names() {
    }

    /**
     * Usernames are lower-cased so that {@code Alice} and {@code alice} cannot
     * become two different accounts, and restricted to a small character set so
     * that they are safe to embed in the store file and the audit log.
     *
     * <p>Leading and trailing whitespace is refused rather than trimmed. Trimming
     * would let {@code alice} followed by a tab or a newline reach the same account
     * as {@code alice}, which turns a mistyped or crafted name into a valid login.
     *
     * @throws IllegalArgumentException with a caller-safe message
     */
    public static String normalize(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("username must be given");
        }
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("username must be given");
        }
        char first = raw.charAt(0);
        char last = raw.charAt(raw.length() - 1);
        if (first <= ' ' || last <= ' ') {
            throw new IllegalArgumentException("username may not start or end with a space or a control character");
        }
        if (raw.length() < MIN_LENGTH || raw.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "username must be " + MIN_LENGTH + "-" + MAX_LENGTH + " characters");
        }
        String lowered = raw.toLowerCase(Locale.ROOT);
        if (!ALLOWED.matcher(lowered).matches()) {
            throw new IllegalArgumentException(
                    "username may only use a-z, 0-9, dot, underscore and hyphen");
        }
        if (lowered.startsWith(".") || lowered.endsWith(".")
                || lowered.startsWith("-") || lowered.endsWith("-")) {
            throw new IllegalArgumentException("username may not start or end with . or -");
        }
        if (lowered.contains("..")) {
            throw new IllegalArgumentException("username may not contain two dots in a row");
        }
        if ("admin-portal".equals(lowered) || "credentials".equals(lowered)) {
            throw new IllegalArgumentException("username is reserved");
        }
        return lowered;
    }

    static void validate(String normalized) {
        if (normalized.length() < MIN_LENGTH || normalized.length() > MAX_LENGTH
                || !ALLOWED.matcher(normalized).matches()) {
            throw new IllegalArgumentException("stored username is not valid");
        }
    }
}
