package com.example.auth;

import java.util.Locale;
import java.util.Optional;

/**
 * Validation of every value that crosses the trust boundary into this component.
 *
 * <p>Every input is treated as attacker-controlled: username, password, source
 * identifier and session identifier arrive from a client; credential records and
 * configuration arrive from a store or file that this process does not own.
 * Nothing is normalised into a permissive default - invalid input is rejected.</p>
 */
public final class InputPolicy {

    /** Upper bound on a username, in UTF-16 code units. */
    public static final int USERNAME_MAX_LENGTH = 64;
    /** Lower bound on a username. */
    public static final int USERNAME_MIN_LENGTH = 1;
    /** Lower bound on a password. Short secrets are rejected, never "upgraded". */
    public static final int PASSWORD_MIN_LENGTH = 12;
    /**
     * Upper bound on a password. A bound is required because the key-derivation
     * cost grows with input length, which an unbounded password turns into a
     * cheap denial-of-service vector.
     */
    public static final int PASSWORD_MAX_LENGTH = 256;
    /** Upper bound on a source identifier (IP literal, possibly with a zone id). */
    public static final int SOURCE_MAX_LENGTH = 45;
    /** Exact length of a session identifier emitted by {@link SessionRegistry}. */
    public static final int SESSION_ID_LENGTH = 43;

    private InputPolicy() {
    }

    /**
     * Validates and canonicalises a username.
     *
     * <p>Allowed characters are ASCII letters, digits and the separators
     * {@code . _ - @ +}; the value must start and end with a letter or digit.
     * This is an allow-list, so control characters, newlines (log forging),
     * Unicode confusables and wildcard characters used by directory or SQL
     * back ends can never reach the credential store or the log.</p>
     *
     * @return the lower-cased username, or empty if the input is not acceptable
     */
    public static Optional<String> canonicalUsername(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        int length = raw.length();
        if (length < USERNAME_MIN_LENGTH || length > USERNAME_MAX_LENGTH) {
            return Optional.empty();
        }
        for (int i = 0; i < length; i++) {
            char c = raw.charAt(i);
            boolean alphanumeric = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            boolean separator = c == '.' || c == '_' || c == '-' || c == '@' || c == '+';
            if (!alphanumeric && !separator) {
                return Optional.empty();
            }
            if (!alphanumeric && (i == 0 || i == length - 1)) {
                return Optional.empty();
            }
        }
        // Locale.ROOT: a locale-sensitive fold would map distinct usernames
        // together (e.g. Turkish dotless i) and let one account answer for another.
        return Optional.of(raw.toLowerCase(Locale.ROOT));
    }

    /**
     * Checks a password candidate for length only. Content rules belong to
     * registration, which is outside this component's scope.
     */
    public static boolean isAcceptablePassword(char[] password) {
        return password != null
                && password.length >= PASSWORD_MIN_LENGTH
                && password.length <= PASSWORD_MAX_LENGTH;
    }

    /**
     * Validates a source identifier - the remote address the attempt came from.
     *
     * <p>The caller is responsible for taking this from the transport layer (the
     * socket peer, or a proxy header only where the proxy is trusted and
     * stripping client-supplied copies). It is validated here as an IPv4 or IPv6
     * literal so that a forged value cannot inject log syntax or grow the
     * throttle's key space with arbitrary strings.</p>
     *
     * @return the identifier unchanged, or empty if it is not a valid IP literal
     */
    public static Optional<String> canonicalSource(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > SOURCE_MAX_LENGTH) {
            return Optional.empty();
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != '.' && c != ':') {
                return Optional.empty();
            }
        }
        boolean v6 = raw.indexOf(':') >= 0;
        boolean v4 = raw.indexOf('.') >= 0;
        if (v6 == v4) {
            return Optional.empty();
        }
        return (v4 ? isIpv4(raw) : isIpv6(raw)) ? Optional.of(raw) : Optional.empty();
    }

    private static boolean isIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
                octet = octet * 10 + (c - '0');
            }
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6(String value) {
        if (value.contains(":::") || value.startsWith(":") && !value.startsWith("::")
                || value.endsWith(":") && !value.endsWith("::")) {
            return false;
        }
        int compressions = 0;
        for (int i = 0; i + 1 < value.length(); i++) {
            if (value.charAt(i) == ':' && value.charAt(i + 1) == ':') {
                compressions++;
            }
        }
        if (compressions > 1) {
            return false;
        }
        String[] groups = value.split(":", -1);
        int present = 0;
        for (String group : groups) {
            if (group.isEmpty()) {
                continue;
            }
            if (group.length() > 4) {
                return false;
            }
            present++;
        }
        if (compressions == 0) {
            return present == 8 && groups.length == 8;
        }
        return present <= 7;
    }

    /**
     * Validates the shape of a session identifier presented by a client.
     *
     * <p>Shape alone proves nothing: the identifier only grants anything after
     * {@link SessionRegistry#validate} finds it in server-side state. This check
     * exists to keep malformed values out of the lookup path and the log.</p>
     */
    public static boolean isWellFormedSessionId(String candidate) {
        if (candidate == null || candidate.length() != SESSION_ID_LENGTH) {
            return false;
        }
        for (int i = 0; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            boolean base64Url = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!base64Url) {
                return false;
            }
        }
        return true;
    }

    /** Range check for a configured integer. Out-of-range configuration is rejected, not clamped. */
    public static int requireInRange(String name, int value, int minInclusive, int maxInclusive) {
        if (value < minInclusive || value > maxInclusive) {
            throw new IllegalArgumentException(
                    name + " must be within [" + minInclusive + ", " + maxInclusive + "]");
        }
        return value;
    }
}
