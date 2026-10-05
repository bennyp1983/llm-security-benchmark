package com.example.websession;

/**
 * Syntactic validation of an externally supplied session identifier.
 *
 * <p>The identifier is produced by the trusted session component, not by this code, so
 * this class cannot vouch for its entropy. It enforces the properties this component
 * <em>can</em> enforce: a bounded length and a character set that is safe to place in a
 * {@code Set-Cookie} header without any escaping. Anything else is rejected outright --
 * there is no sanitising, trimming, or permissive fallback, because silently repairing a
 * malformed identifier would turn a bug in the caller into an injected header here.</p>
 *
 * <p>The allowed alphabet is base64url ({@code A-Z a-z 0-9 - _}), which is a strict subset
 * of RFC 6265 {@code cookie-octet}. By construction the accepted value can contain no CR,
 * LF, NUL, space, quote, comma, semicolon, or backslash, so response splitting and cookie
 * attribute injection are impossible rather than merely filtered.</p>
 */
public final class SessionIdValidator {

    /**
     * 22 base64url characters carry ~131 bits, the smallest value that could plausibly be a
     * well-generated session identifier. Shorter values are rejected as a defence-in-depth
     * check against a caller that downgraded its generator.
     */
    public static final int MIN_LENGTH = 22;

    /** Upper bound so a hostile caller cannot push an oversized header into the response. */
    public static final int MAX_LENGTH = 128;

    private SessionIdValidator() {
    }

    /**
     * @return {@code true} only if {@code candidate} is non-null, within length bounds, and
     *         composed entirely of base64url characters.
     */
    public static boolean isValid(String candidate) {
        if (candidate == null) {
            return false;
        }
        int length = candidate.length();
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (!isAllowed(candidate.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAllowed(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-'
                || c == '_';
    }
}
