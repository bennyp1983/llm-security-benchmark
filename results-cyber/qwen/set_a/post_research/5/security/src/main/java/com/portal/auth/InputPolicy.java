package com.portal.auth;

/**
 * The single trust boundary for attacker-supplied text.
 *
 * <p>Rules baked in here (see docs/THREAT_MODEL.md section 1):
 * <ul>
 *   <li>No value is trimmed. {@code String.trim()}/{@code strip()} delete characters
 *       {@code <= U+0020} including NUL and TAB, so a trim would silently fold
 *       {@code "alice\t"} onto the real account {@code "alice"}. Rejection is the only
 *       acceptable response to an invisible character.</li>
 *   <li>Usernames are printable-ASCII-only from a fixed character class, so case
 *       folding, Unicode normalisation (NFKC) and confusable/similar-codepoint
 *       folding cannot produce a different identity from the same bytes. The accepted
 *       set is already normalised: every accepted username is NFKC-invariant.</li>
 *   <li>Passwords are printable-ASCII-only for the same reason, and because
 *       {@link javax.crypto.spec.PBEKeySpec} is not injective over {@code char[]}
 *       (it drops trailing NULs and maps unpaired surrogates to {@code '?'}), which
 *       would otherwise make two different passwords verify identically.</li>
 *   <li>Every rejection carries a machine-readable code and never the rejected value,
 *       so a rejection cannot leak into a log or a response.</li>
 * </ul>
 */
public final class InputPolicy {

    /** Hard ceilings. Anything larger is refused before it is copied or hashed. */
    public static final int USERNAME_MIN = 3;
    public static final int USERNAME_MAX = 32;
    public static final int PASSWORD_MIN = 12;
    public static final int PASSWORD_MAX = 128;
    /** A line read from a file/pipe is refused above this, before any parsing. */
    public static final int LINE_MAX = 1024;
    /** Opaque token shapes: 32 random bytes => 43 base64url chars, 24 => 32 chars. */
    public static final int SESSION_TOKEN_BYTES = 32;
    public static final int CSRF_TOKEN_BYTES = 24;

    private InputPolicy() {
    }

    /**
     * Accepted usernames: {@code [a-z0-9._-]{3,32}} whose first and last characters are
     * alphanumeric. Lower-case only on purpose: an upper-case-accepting scheme must
     * case-fold to look the account up, and case-folding is exactly the step where
     * identity-folding bugs (and Turkish-i style surprises) live.
     */
    public static boolean isUsername(String candidate) {
        if (candidate == null) {
            return false;
        }
        return isUsername(candidate.toCharArray());
    }

    public static boolean isUsername(char[] c) {
        if (c == null || c.length < USERNAME_MIN || c.length > USERNAME_MAX) {
            return false;
        }
        if (!isAlnum(c[0]) || !isAlnum(c[c.length - 1])) {
            return false;
        }
        for (char ch : c) {
            if (!isAlnum(ch) && ch != '.' && ch != '_' && ch != '-') {
                return false;
            }
        }
        // Refuse the dot-leading/trailing and ".." shapes that confuse path and
        // normalisation handling downstream, even though they cannot be a valid name.
        String s = new String(c);
        return !s.contains("..");
    }

    /**
     * Structural validation of a password candidate: printable ASCII only, correct
     * length, no leading/trailing space (a copy-paste artefact that is impossible to
     * see), no NUL/control characters, no surrogates.
     */
    public static boolean isWellFormedSecret(char[] secret) {
        if (secret == null || secret.length < PASSWORD_MIN || secret.length > PASSWORD_MAX) {
            return false;
        }
        if (secret[0] == ' ' || secret[secret.length - 1] == ' ') {
            return false;
        }
        for (char c : secret) {
            if (c < 0x21 || c > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /**
     * Enrolment-time strength rules. Deliberately NOT applied at login time: a login
     * that answers "your password is too weak" is a second distinguishable failure
     * reason and hands an attacker an enumeration channel.
     */
    public static String strengthFailure(char[] secret, char[] username) {
        if (!isWellFormedSecret(secret)) {
            return "Password must be " + PASSWORD_MIN + "-" + PASSWORD_MAX
                    + " printable ASCII characters with no leading or trailing space.";
        }
        int lower = 0;
        int upper = 0;
        int digit = 0;
        int other = 0;
        for (char c : secret) {
            if (c >= 'a' && c <= 'z') {
                lower++;
            } else if (c >= 'A' && c <= 'Z') {
                upper++;
            } else if (c >= '0' && c <= '9') {
                digit++;
            } else {
                other++;
            }
        }
        if (lower + upper + digit + other != secret.length) {
            return "Password contains a character that is not permitted.";
        }
        if (lower == 0 || upper == 0 || digit == 0 || other == 0) {
            return "Password must contain a lower-case letter, an upper-case letter, "
                    + "a digit and a non-alphanumeric character.";
        }
        if (containsIgnoreCase(secret, username)) {
            return "Password must not contain the username.";
        }
        String common = commonShapeFailure(secret);
        if (common != null) {
            return common;
        }
        return null;
    }

    /**
     * Rejects shapes that pass the class rules but are on every breach list.
     *
     * <p>Two things worth stating explicitly, because the first drafts of both rules were
     * unreachable and therefore worth nothing:
     * <ul>
     *   <li>a "no single repeated character" rule that only fires when <em>every</em>
     *       character is the same can never fire at all -- such a password always fails the
     *       four-class rule above first. The usable rule is a share bound.</li>
     *   <li>an ascending-run rule alone leaves {@code dcba9876} (a descending keyboard
     *       walk) perfectly acceptable. Both directions are checked.</li>
     * </ul>
     * Each rule below is exercised by a fixture that passes every <em>other</em> rule, so a
     * regression that makes one unreachable shows up as a failure rather than as green.
     */
    private static String commonShapeFailure(char[] s) {
        int[] count = new int[128];
        for (char c : s) {
            count[c]++;
        }
        int most = 0;
        for (int n : count) {
            most = Math.max(most, n);
        }
        if (most * 2 > s.length) {
            return "Password must not be built mostly from one character.";
        }
        int run = 1;
        for (int i = 1; i < s.length; i++) {
            int delta = s[i] - s[i - 1];
            if (delta == 1 || delta == -1) {
                run++;
                if (run >= 5) {
                    return "Password must not contain a long ascending or descending sequence.";
                }
            } else {
                run = 1;
            }
        }
        return null;
    }

    private static boolean containsIgnoreCase(char[] haystack, char[] needle) {
        if (needle == null || needle.length == 0 || needle.length > haystack.length) {
            return false;
        }
        char[] n = new char[needle.length];
        for (int i = 0; i < needle.length; i++) {
            n[i] = lowerAscii(needle[i]);
        }
        try {
            outer:
            for (int i = 0; i + n.length <= haystack.length; i++) {
                for (int j = 0; j < n.length; j++) {
                    if (lowerAscii(haystack[i + j]) != n[j]) {
                        continue outer;
                    }
                }
                return true;
            }
            return false;
        } finally {
            Crypto.wipe(n);
        }
    }

    private static char lowerAscii(char c) {
        return (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
    }

    /**
     * Validates a session id or CSRF token that arrived from a client. Only the shape
     * is checked here; possession is only ever <em>proved</em> by a hash lookup against
     * server-side state in {@link SessionManager}.
     */
    public static boolean isOpaqueToken(String candidate, int expectedBytes) {
        if (candidate == null) {
            return false;
        }
        try {
            Crypto.base64UrlStrictExpectedLen(candidate, expectedBytes);
            return true;
        } catch (IllegalArgumentException expected) {
            return false;
        }
    }

    public static boolean isSessionToken(String candidate) {
        return isOpaqueToken(candidate, SESSION_TOKEN_BYTES);
    }

    public static boolean isCsrfToken(String candidate) {
        return isOpaqueToken(candidate, CSRF_TOKEN_BYTES);
    }

    /** Case-insensitive ASCII case fold for the fixed username alphabet (locale-free). */
    public static char[] lowerCopy(char[] in) {
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = lowerAscii(in[i]);
        }
        return out;
    }

    private static boolean isAlnum(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }
}
